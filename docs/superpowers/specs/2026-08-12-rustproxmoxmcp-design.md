# rustproxmoxmcp — design

**Date:** 2026-08-12
**Status:** approved, ready for implementation planning

One Rust MCP server holding an inventory of Proxmox VE clusters, replacing a
deployment that runs one process per endpoint. Third member of the mechub
per-vendor family after `rustjunosmcp` and `rustpanosmcp`, and the first target
that is not a network device.

---

## 1. Why now

The repository README blocked this work on `mecmcp`, the shared crate family
underneath the vendor servers. That blocker is gone. `mecmcp` is at **0.8.8**
with all four extraction milestones landed — `mecmcp-server`, the bearer
boundary, HTTP transport assembly, and the generic `ToolScopePreflight` — plus
four crates a REST vendor needs that a NETCONF vendor never did:

| Crate | What it gives Proxmox |
|---|---|
| `mecmcp-http` | HTTPS-only outbound, no redirects, no proxy, bounded concurrency, whole-request deadline, sensitive headers, streaming response cap |
| `mecmcp-job` | Immediate first probe, capped backoff, cancellation, whole-operation deadline — for UPID task polling |
| `mecmcp-secret` | Zeroizing outbound credential, hardened 0600 env/file loader |
| `mecmcp-openapi` | Path-template expansion that rejects rather than sanitizes |

Eleven of the fourteen crates apply. `mecmcp-device` and `mecmcp-scp` do not
(no SSH). `mecmcp-policy` arrives in 0.5 with `execute_vm_command`.

### `mecmcp` is read-only

This project consumes `mecmcp` at a pinned exact version and does not modify it.
Gaps become issues on `fastrevmd-lab/mecmcp` and are designed around in the
consumer meanwhile. `mecmcp` is the foundation under four servers; a change made
to suit Proxmox lands in all of them, and the extraction programme existed
precisely to stop each repo being the private reference implementation for
something the others lack.

Open issue candidates are listed in §12.

---

## 2. What makes Proxmox different

Junos and PAN-OS are config-text devices: a candidate configuration exists, can
be diffed, fingerprinted, approved, and committed atomically. `mecmcp-changeset`
is built for exactly that shape.

**Proxmox has no candidate configuration.** Every mutation is an imperative REST
call that returns a UPID and begins immediately. There is nothing to diff and
nothing to commit. And unlike a bad firewall rule, `DELETE /nodes/pve2/qemu/905`
is not undone by `rollback 1`.

Two consequences drive the whole design:

1. Change control must key on **what the call will do**, not on a text diff.
2. The **identity of the target** must be bound at approval time, because a
   VMID is a mutable pointer to a guest rather than a stable name.

---

## 3. Crate layout

```
crates/rust-proxmoxmcp-core/    vendor logic; no MCP, no transport
  catalog.rs     read tools as data: method, path template, target fields, tier
  request.rs     generic executor over mecmcp-http + mecmcp-openapi::path
  resolve.rs     (cluster, vmid) -> ResolvedGuest -> AuthorizedGuest
  protect.rs     protection resolution and waiver evaluation
  tier.rs        action-class classification
  fingerprint.rs Proxmox fingerprint and preview rendering
  task.rs        UPID parse, task status probe, mecmcp-job polling
  lifecycle.rs   typed: start, stop, shutdown, reset, reboot
  guests.rs      typed: create, clone, destroy, restore, resize
  storage.rs     typed: snapshot, backup, ISO mutations
  inventory.rs   Cluster / ClusterPolicy types over mecmcp-inventory
  error.rs       typed Proxmox error mapping

crates/rust-proxmoxmcp/         binary
  main.rs        CLI via mecmcp-runtime, TLS bootstrap, signals, shutdown
  http_transport.rs  boundary assembly, ToolScopePreflight configuration
  server/        MCP tool handlers, one module per domain
```

Matches `rustsdcmcp` and `rustmistmcp`. Repo name `rustproxmoxmcp` (mechub
naming rule); binary and crates take dashes as `rust-proxmoxmcp`.

### Read/write split

The core is deliberately two-natured, split on the same line the action tiers
draw:

- **Reads are data.** Proxmox's read surface is large and extremely uniform
  (`/nodes/{node}/qemu/{vmid}/status/current`). A catalog entry declares method,
  path template, target fields and tier; one generic executor serves all of
  them. `mecmcp-openapi::path` expands the template, rejecting any value that
  would break a segment, start a query, navigate the hierarchy, collapse a
  segment, or carry a control byte.
- **Writes are code.** Every mutating tool is a typed request/response struct
  with an explicit schema. Each needs preconditions a catalog entry cannot
  express: protection check, tier classification, UPID handoff, change-set
  binding.

Adding a read tool is a data change. Adding a destructive tool is a deliberate
code change that cannot skip the guardrail.

---

## 4. The safety spine

### 4.1 Protection resolution

One function, fail-closed, consulted before every mutating call:

```
protected(cluster, vmid) :=
      live_tag_contains("protected")        // from /cluster/resources
    ∨ inventory.protected(cluster, vmid)    // clusters.json
    ∨ tag_read_failed                       // fail closed
    ∨ vmid_absent_from_cluster_resources    // fail closed
```

The union is the point. A live Proxmox tag keeps the list current and lets
operators manage it where they already work — but the server's own API token can
clear that tag, so a tag alone means an attacker or a confused agent can
unprotect-then-destroy in two calls. The inventory half cannot be edited through
the Proxmox API at all. Neither half is sufficient; the union is.

An unknown VMID resolves as protected. This makes a destroy of a guest missing
from `/cluster/resources` a refusal. Accepted knowingly: it will occasionally
surprise someone cleaning up after a failed create, and that is the correct
trade against acting on a target the server cannot see.

### 4.2 Override

For the destructive tier only:

```
allowed := ¬protected
         ∨ waiver_matches(cluster, vmid, now)   // waivers.json, time-boxed
         ∨ lab_mode                              // process-start flag
```

Neither override is a tool argument. A `force: true` parameter is not a
guardrail — a sufficiently confident model sets it. The override must originate
where the calling agent cannot reach.

**Production path:** an operator writes a time-boxed waiver to
`/etc/proxmoxmcp/waivers.json`, loaded through the same hardened loader
`mecmcp-auth` and `mecmcp-inventory` use (mode 0600, regular file, owned by the
service user) and hot-reloaded on SIGHUP.

```jsonc
{ "version": 1, "waivers": [
  { "cluster": "pve3", "vmid": 905,
    "until": "2026-08-13T02:00:00Z",
    "reason": "decommission", "ticket": "CHG-4471" }
]}
```

An expired waiver is not a waiver. Expiry is evaluated at apply time, not at
load time, so a waiver cannot outlive its window by sitting in memory.

**Lab path:** `--lab-mode` at process start allows a caller to waive with a
mandatory reason.

Both paths produce a waiver record, so the audit event and the change-set record
distinguish a waived approval from a genuine two-principal one by construction.

**Updated 2026-08-15 — mecmcp now carries this vocabulary natively.** §12's
blocker shipped as mecmcp#275 in 0.10.0, so the two paths map onto the library
instead of a private record:

| This design | mecmcp 0.10.0 |
|---|---|
| operator waiver from `waivers.json` | `WaiverKind::OperatorFile` |
| `--lab-mode` waiver | `WaiverKind::LabMode` |
| `until` | `WaiverRecord::expires_at_unix` |
| `ticket` | `WaiverRecord::ticket` |
| `reason` | `WaiverRecord::reason` |

All four fields are digest-bound by `compute_waiver_digest_v3`, so an expiry or
ticket edited after the fact invalidates the record rather than silently
widening it. Use `waive_approval_operator` for the file path and
`waive_approval` for lab mode; do **not** hand-build a `WaiverRecord` or its
digest, or the record fails validation on the next state load.

Two consequences worth stating, both learned from deploying #275:

- **`waive_approval_operator` refuses an expiry already in the past**, so a
  waiver that is dead on arrival is a configuration error at grant time rather
  than a waiver that silently never applies. §4.2's apply-time evaluation still
  stands — both checks exist.
- mecmcp enforces expiry at **both** apply gates, before and after the device
  guard is taken. A waiver that lapses while the apply waits on the guard is
  refused with a distinct error naming which gate rejected it.

`/etc/proxmoxmcp/` is read-only *to the service process* under
`ProtectSystem=strict`. That is not a limitation to work around — it is what
makes granting a waiver a root operation rather than a tool call. There is
deliberately **no `grant_waiver` tool and no `add_cluster` tool.**

### 4.3 Action tiers

Tier is a property of the tool, declared once, and selects the code path. It is
never a value a caller passes.

| Tier | Tools | Gate |
|---|---|---|
| `read` | `get_cluster_status`, `get_nodes`, `get_node_status`, `get_vms`, `get_containers`, `get_vm_config`, `get_container_config`, `get_container_ip`, `get_guest_status`, `get_storage`, `list_snapshots`, `list_backups`, `list_isos`, `list_templates`, `list_tasks`, `get_task_status` | scope + audit |
| `low` | `start_vm`, `stop_vm`, `shutdown_vm`, `reset_vm`, `start_container`, `stop_container`, `restart_container`, `create_snapshot`, `create_backup`, `create_vm`, `create_container`, `clone_vm`, `download_iso`, `update_container_resources`, `resize_disk` (grow) | scope + protection reported + audit |
| `destructive` | `delete_vm`, `delete_container`, `restore_backup`, `rollback_snapshot`, `delete_snapshot`, `delete_backup`, `delete_iso`, `resize_disk` (shrink) | change set: plan → fingerprint → approve → apply |

> **Not implemented as designed.** Shrinking is refused outright rather than
> routed through a change set: the only destructive plan tool is
> `plan_proxmox_destroy`, which destroys the whole guest, so sending a shrink
> "through the change-set flow" would have meant destroying the VM. Callers are
> refused outright: Proxmox itself rejects a reduction, so there is no path to
> steer callers toward. The rest of this section describes
> the original design.

`resize_disk` is the single tier-split-on-argument case: grow is `low`, shrink is
`destructive`. A shrink destroys data and a grow does not, and splitting them
into two tools would let a caller reach the destructive path through the benign
tool's name.

`stop_vm` is `low`, not `destructive`: it is disruptive but reversible. The tier
boundary is data loss, not disruption.

### 4.4 The Proxmox fingerprint

`mecmcp-changeset` binds a `Fingerprint` at plan time and re-verifies it at
apply. With no candidate config, the fingerprint is **the identity and state of
the target**, hashed per guest:

```
sha256(cluster, vmid, name, type, node, status,
       sorted(tags), config_digest, sorted(disk_id, size_bytes))
```

`config_digest` is Proxmox's own `digest` field, returned by
`GET /nodes/{node}/{qemu,lxc}/{vmid}/config` for optimistic locking. Using the
vendor's digest rather than hashing the config body means the fingerprint moves
exactly when Proxmox considers the config to have moved.

If any component changed between approval and apply, apply is refused rather
than proceeding against a guest that is no longer the one described.

**Verified live 2026-08-15** against pve2, read-only apart from one reverted
description edit on the disposable LXC 617:

- `digest` is present on **both** `/nodes/{node}/lxc/{vmid}/config` and
  `/nodes/{node}/qemu/{vmid}/config`.
- It is **stable across repeated reads**, so it will not invalidate approvals
  spuriously.
- It **moves on a config change** (`e94e30c4…` → `53804039…` on setting a
  description) and returns to the prior value when the change is reverted.
- Every `/cluster/resources` field the fingerprint hashes — `name`, `type`,
  `node`, `status`, `tags` — is present.

The revert behaviour is worth naming: `digest` is derived from config content,
not a monotonic counter, so the fingerprint detects **current divergence from
what was approved**, not *any* intervening edit. A config changed and changed
back still matches. That is the correct semantic for "is this still the guest
the approver saw?" — but it means the fingerprint is not an edit audit trail,
and nothing should read it as one.

This is not theoretical. On 2026-08-12 most of the fleet was renumbered across
three waves — `103→905`, `604→970`, `611→800`, `114→907` and `900→908` moving
node as well. A change set approved to destroy `604` before that window and
applied after would have addressed a different guest entirely. The fingerprint
makes that a refusal instead of an incident.

### 4.5 The preview is generated by the server

The existing guardrail is a ritual: *print the guest's name, node, and config
first, confirm it is not tagged `protected`, and state why the evidence supports
this specific action.* An agent performs that ritual and could skip or fabricate
it.

As a `PreviewRecord` it becomes the server's own output, digest-bound into the
approval via `preview_digest`:

```
DESTROY  pve3 / 907 vsrx-ci  (qemu, running)
  tags       ci, protected          ← PROTECTED
  node       pve2
  disks      scsi0 64G, scsi1 8G    (purge: yes)
  snapshots  3   latest: proven-0.19.0  (2026-08-11)
  backups    last: 2026-08-09 (3d ago), 2 retained
  waiver     none
  verdict    REFUSED — protected, no waiver
```

Backup age is reported, not enforced. Enforcing a backup precondition would
imply the backup restores, and this estate has a documented counter-example:
`ssdf-clickhouse` (LXC 104) produced 178 K of 4,628,855 rows with 59 parts
`broken-on-start` from both a cold copy and a snapshot. Report the evidence; let
the approver weigh it.

---

## 5. Scope model

Two-level targets. A token declares which clusters it may reach and, within
each, a selector over the guests it may touch.

```jsonc
{ "name": "ci-runner",
  "clusters": ["pve3"],
  "guests":   ["vmid:600-699"],
  "tools":    ["get_*", "create_container", "delete_container", "start_*", "stop_*"] }

{ "name": "readonly-dash",
  "clusters": ["*"], "guests": ["*"], "tools": ["get_*", "list_*"] }
```

Selector terms: `vmid:<n>`, `vmid:<lo>-<hi>`, `tag:<name>`, `pool:<name>`,
`node:<name>`, `type:qemu|lxc`, `*`. A guest matches if any term matches.

This makes the existing VMID band scheme — 900–999 operational, 800–899 personal,
700–799 project stacks, 600–699 disposable — enforced rather than remembered. A
CI token becomes structurally incapable of touching anything outside 600–699.
That is ROADMAP §1's multi-tenant scoping, delivered in the first release.

### Two-stage authorization

Not every selector term can be evaluated in the preflight, and pretending
otherwise is how a scope silently stops being enforced. `ToolScopePreflight`
runs inside the bearer boundary, before dispatch and before any I/O; it has
request arguments and nothing else. Tags and pools are properties of the live
cluster, not of the request.

- **Stage 1 — preflight, zero I/O.** Tool scope and cluster scope, both
  derivable from raw arguments. Rejects the bulk of abuse before a packet leaves
  for Proxmox, and preserves the boundary's ordering: `IP rate limit →
  authenticate → token rate limit → token concurrency → body limit → preflight →
  target concurrency → handler`.
- **Stage 2 — after resolution, in `core`.** The whole guest selector —
  every term, `vmid:` included — evaluated against the resolved guest, followed
  by the protection check.

**Where each half is stored.** The device `ScopeSet` carries **cluster names
only**, which `ToolScopePreflight` matches unchanged with
`TargetField::scalar("cluster")`. The guest selector lives in the token's
**grant**, `mecmcp-auth`'s documented vendor seam.

That split is forced rather than chosen. `CallerScopes` exposes only
`token_name`, `devices` and `tools` — all opaque name sets — and
`TargetValueShape` is `Scalar | NonEmptyArray` with no numeric-range form. A
`vmid:600-699` term is therefore unevaluable before dispatch, and putting it in
the device scope would leave a restriction the operator believes is enforced
sitting unread. Moving it into the grant makes it enforced, at the cost of one
cached `/cluster/resources` read before an out-of-scope vmid is refused — behind
authentication, the tool scope, the cluster scope, and the rate limiter.

### `AuthorizedGuest`

Stage 2 lives past the boundary, and handler code can forget. So it is not
optional by construction:

```rust
/// A guest that has passed stage-2 scope evaluation and the protection check.
/// No public constructor. Produced only by `resolve::authorize`.
pub struct AuthorizedGuest { /* private */ }
```

Every mutating API in `core` takes `AuthorizedGuest`, never a bare `vmid`. A
handler that skips authorization does not compile. This is the same move
`mecmcp` 0.8.1 made for audit — audited because it went through the transport,
not because someone remembered.

---

## 6. Cluster inventory and outbound transport

`clusters.json`, loaded through `mecmcp-inventory`'s `Inventory<Cluster,
ClusterPolicy>` trait with the hardened loader, hot-reloaded on SIGHUP:

```jsonc
{ "version": 1, "clusters": {
  "pve3": {
    "endpoint": "https://pve3.example.org:8006",
    "token_id": "root@pam!mcp",
    "token_secret_env": "PVE_PVE3_TOKEN",
    "ca_pem_path": "/etc/proxmoxmcp/ca/pve3.pem",
    "protected_vmids": [905, 906, 907, 908, 910, 920, 950, 951, 952,
                        960, 970, 980, 990, 991],
    "protected_tags": ["protected"]
  }
}}
```

Credentials never sit in the inventory file. `mecmcp-secret::OutboundSecret`
loads from env or a separate 0600 file, is zeroized on drop, and implements
neither `Debug`, `Display`, nor `Serialize`.

Proxmox's scheme is not Bearer, so the header is attached with
`secret_header("Authorization", "PVEAPIToken=<id>=<secret>")`, which sets
reqwest's sensitive flag.

**TLS trust is settled by the crate.** `mecmcp-http` exposes
`extra_root_certificates` and offers no insecure-skip-verify at any layer, so
per-cluster CA pinning is the only available path and `verify=false` is
structurally unavailable.

One `HttpClient` per cluster. Per-cluster isolation then comes for free:
`max_concurrent_requests` and `max_queued_requests` are per client, so a wedged
cluster returns `QueueFull` immediately instead of consuming a shared pool. That
covers most of ROADMAP §9's circuit-breaker requirement by construction.

---

## 7. Target resolution

Every guest-addressed tool takes `(cluster, vmid)`. **The caller never names a
node.** The server resolves it from `/api2/json/cluster/resources?type=vm` on
every call, behind a short TTL cache:

```
resolve(cluster, vmid) -> ResolvedGuest {
    vmid, name, r#type, node, status, tags, pool, maxdisk
}
```

Guests migrate. Two of the 2026-08-12 renumbers were cross-node moves
(`114→907`, `900→908`, both pve3→pve2). A caller-supplied node is an
opportunity to act on a stale assumption and to address the wrong guest.

---

## 8. Tasks

Most mutations answer with a UPID and begin work. `core/task.rs` parses
`UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:` and polls
`GET /nodes/{node}/tasks/{upid}/status` through `mecmcp_job::poll_until_ready`:

- `status == "running"` → `Probe::Pending`
- `status == "stopped"` → `Probe::Ready(exitstatus)`

`mecmcp-job` is explicit that terminal-state vocabulary belongs to the consumer,
so interpreting `exitstatus` — `"OK"` against Proxmox's several non-OK spellings
— stays in `core`. `PollError`'s three-way split (cancelled / deadline / probe
failed) surfaces as three distinct MCP errors; "job polling failed" tells an
operator nothing about which of the three happened.

### Indeterminate recovery

The UPID is persisted into the `OperationRecord` before the call returns. After
a crash or restart, `resolve_persisted_operation` re-probes that exact task and
learns the real outcome from Proxmox.

This is materially better than the firewall case. The operation whose result was
never observed is the hardest state in this domain, and here it is genuinely
recoverable rather than merely detectable — a dropped NETCONF commit leaves no
server-side handle to re-probe.

---

## 9. Errors, audit, observability

Proxmox returns a JSON `errors` map plus an HTTP status; `core/error.rs` maps
these to a typed enum rather than passing strings through. `mecmcp-http` already
bounds peer-chosen error text and strips control characters before it can reach
a log.

Two audit events per mutating call, correlated by request id:

- the transport's by-construction event for every `tools/call`;
- the handler's enriched event: cluster, resolved node, vmid, guest name, tier,
  protection verdict, waiver kind if any, UPID, outcome.

Metrics via `mecmcp-transport`'s Prometheus exporter, plus per-cluster API error
rate and task duration.

### Known gap: no on-device attribution

ROADMAP §2 wants attribution landing on the device itself — the Junos `commit
comment`, the PAN-OS commit description — because that is what an incident
responder reads when they do not trust the MCP server.

**Proxmox has no equivalent.** The task log records the API token identity,
which is the server, not the principal behind it. The nearest available echo is
appending a change-set id to the guest `description` field, which means the
server silently editing guest metadata as a side effect of unrelated calls.

Decision: accept the gap, document it, let the audit sink be the record. Flagged
here rather than discovered during an audit.

---

## 10. Testing

**Unit — the protection truth table.** Every combination of `{tag present,
absent, unreadable} × {inventory pinned, not} × {vmid known, unknown} × {waiver
valid, expired, absent} × {lab_mode on, off} × {tier}`. Exhaustive and cheap.
This is the function that decides whether a VM survives.

**Property — an adversarial suite.** The interesting failure is not a wrong
truth-table row, it is a path that reaches a destroy without consulting it.
Assertions: no mutating `core` API accepts a bare `vmid`; a fingerprint mismatch
always refuses; an expired waiver never unlocks; a scope-rejected call never
reaches Proxmox. Fuzz UPID parsing and path-parameter expansion, both of which
take values from a request.

**Integration — mock cluster, real boundary.** `mecmcp_transport::test_client::
McpClient` against a `wiremock` Proxmox serving recorded `/cluster/resources`,
task-status and error responses. This exercises the *assembled* router
deliberately: `mecmcp` 0.8.3's headline bug was a middleware that passed every
unit test and was never wired up by the assembly. Tests that build components by
hand prove the component; only an end-to-end client proves the server.

**Lab — disposable guests only.** Destroy-path validation runs against `600`
(`rust-junosmcp-600`), `601` (`rust-panosmcp-601`) and `606` (`rustsdcmcp-606`),
all tagged `disposable`, and nowhere else. Guests in the 900 band appear only as
refusal fixtures: a test proving `907 vsrx-ci` cannot be destroyed is exactly as
valuable as one proving `600` can be, and costs nothing.

---

## 11. Packaging and deployment

Per `mecmcp/docs/PACKAGING.md`: Debian 13 LXC, release tarball plus
`packaging/lxc/install.sh`, systemd unit with `ProtectSystem=strict` and
`ReadWritePaths` limited to the state directory.

```
/etc/proxmoxmcp/            read-only to the service, root-writable
  clusters.json   0600      inventory + protected_vmids
  tokens.json     0600      mecmcp-auth minted tokens
  waivers.json    0600      time-boxed overrides
  ca/*.pem                  per-cluster trust anchors
/var/lib/proxmoxmcp/        the only ReadWritePath
  changesets.json           mecmcp-changeset persistence
  audit.jsonl
```

The read-only `/etc` is deliberate and comes from a known lesson:
`rust-junosmcp`'s `add_device` tool fails with `Read-only file system` under the
same sandbox, and the documented preference is to keep the sandbox narrow rather
than widen it around the token file. Here that constraint is the feature.

A remote listener must supply `--allowed-host`; `mecmcp-transport`'s
`HostOriginPolicy` has only an `Enforced` variant, and the allowlist must track
the address clients actually dial.

Deployment target is a new LXC in the 900 band on pve2 or pve3, running
alongside the three existing python endpoints until cutover. VMID chosen at
deploy time — `970` is the incumbent `proxmox-mcp` and is tagged `protected`.

Rollback follows the sibling rule: snapshot the container before installing any
release. `clusters.json`, `tokens.json` and `waivers.json` stay compatible
across releases, so a snapshot restore is a complete revert.

---

## 12. `mecmcp` issue candidates

One candidate, and it does not block implementation.

1. ~~**`WaiverRecord` cannot express an operator waiver.**~~ **SHIPPED** as
   mecmcp#275 in **0.10.0** (2026-08-15). `WaiverRecord` gained a digest-bound
   `kind` — `LabMode` | `OperatorFile` | `OperatorTool`, one variant more than
   proposed, because a waiver granted by editing a root-owned file is a
   different claim from one granted by a second principal calling a tool — plus
   digest-bound `expires_at_unix` and `ticket`, a new
   `waive_approval_operator`, schema v3, and expiry enforced at both apply
   gates.

   **The fallback in this section is withdrawn.** `core` does *not* keep its own
   waiver record: hand-building a `WaiverRecord` or its digest produces evidence
   that fails validation on the next state load. Call the library. See the
   updated §4.2 for the field mapping.

A second candidate — a numeric-range `TargetValueShape` for `vmid:600-699` — was
withdrawn after reading the real API. `CallerScopes` exposes only opaque name
sets, so even a range shape would not have carried the guest selector into the
preflight. Moving the selector into the grant solves it entirely within the
consumer, as §5 now records.

---

## 13. Phasing

Each phase is independently shippable and independently useful.

| Release | Scope | What it proves |
|---|---|---|
| **0.1** | Read surface, multi-cluster inventory, bearer boundary, stage-1 and stage-2 scopes, `AuthorizedGuest`, audit, per-cluster CA pinning | The spine, at near-zero blast radius. Deployable as a read-only endpoint immediately. |
| **0.2** | `low` tier: lifecycle, snapshot create, backup create, create/clone, ISO download. UPID → `mecmcp-job`. | Task polling and the mutation path, with everything reversible. |
| **0.3** | `destructive` tier: change sets, Proxmox fingerprint, server-generated preview, waiver file, `--lab-mode`. | The thesis. |
| **0.4** | Remaining parity, indeterminate recovery across restart, metrics, packaging, **cutover** — the three python endpoints retire. | One binary, one token store, one place the guardrails live. |
| **0.5** | `execute_vm_command` behind `mecmcp-policy`, its own scope, destructive tier. | The capability deliberately withheld from v1. |

0.1 should be deployed to the lab and left running while 0.2 is built, rather
than holding everything for cutover.

**Status 2026-08-15.** 0.1 shipped as 0.1.2 and is deployed twice: LXC 616
`test-twoperson-proxmox` and LXC 971 `prod-proxmoxmcp`, the latter over TLS as
`prod-proxmoxmcp.mechub.org:30031`. Sixteen tools, all `read`. **0.2 is not
built** — there is no mutation path, no UPID handling, and no `mecmcp-job`
integration yet.

**0.3 shipped 2026-08-15.** Destructive tier under change-set control: plan →
approve → apply, with server-generated preview, Proxmox fingerprint binding,
`--lab-mode`, and `--waivers-file`. **Only `delete_container` is implemented**
of the eight destructive tools; the remaining seven are mechanical follow-ons.
The `low` tier remains unbuilt. LXC 617 `test-labmode-proxmox` (192.168.1.237)
can now be enabled.

**0.3's implementation plan absorbs 0.2's mutation spine as its opening tasks.**
The phasing above still describes the right order of *capability*, but the
`low` tier and the `destructive` tier share one substrate — issuing a write to
Proxmox and following its UPID to completion — and building that substrate twice
is worse than building it once under the harder requirement. The plan sequences
it as: task/UPID spine → one `low` tool proving the spine end to end → change
sets, fingerprint, preview → waiver file and `--lab-mode` → the remaining
`destructive` tools. A reversible tool still proves the mutation path first;
it simply does so inside 0.3's plan rather than a separate release.

---

## 14. Ruled out

**No `mecmcp-intent` analogue.** ROADMAP §11 is about rendering vendor-neutral
firewall policy to native config. There is no cross-vendor "VM intent" worth
abstracting, and pretending otherwise produces a layer with one implementation.

**No drift detection in v1.** ROADMAP §6 assumes an intended state to compare
against. Proxmox guest configuration is not declaratively authored here; a
desired-state store is a separate project, not a feature of this one.

**No `execute_vm_command` in v1.** Arbitrary command execution inside every
guest is remote code execution as a tool call. It is not required for cutover,
and it ships only once the boring tools are proven and `mecmcp-policy` is
compiling an allow/deny rule set over the command subject.

**No `add_cluster`, no `grant_waiver`.** Both would move an operator control
into the tool surface the calling agent drives. Root plus SIGHUP is the
interface.
