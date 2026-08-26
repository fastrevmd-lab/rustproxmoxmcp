<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rustproxmoxmcp</h1>

<p align="center"><strong>One Rust MCP server for many Proxmox VE clusters</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This is an independent community project and does not claim affiliation with or endorsement by Proxmox Server Solutions GmbH. Product names and trademarks are used only to identify the systems with which the software interoperates.

---

## Status: 0.8.0 — the tool surface is complete but for two gaps

**36 callable tools**: 17 read, 18 `low`, and `apply_proxmox_change_set` as the
single `destructive` entry point. Seven further names --- `delete_vm`,
`delete_container`, `delete_snapshot`, `delete_backup`, `delete_iso`,
`restore_backup`, `rollback_snapshot` --- are **authorization scopes, not
tools**: a token grants them by name and reaches them through
`plan_proxmox_destroy`. `KNOWN_TOOLS` therefore holds 43 entries.

### What is still missing

- **`execute_vm_command`.** Deliberate. The design spec makes it conditional on
  `mecmcp-policy` compiling an allow/deny rule set over the command subject, and
  that is not wired. Arbitrary command execution inside every guest is remote
  code execution as a tool call; it ships with a policy engine or not at all.
- **Restore to a *new* VMID.** `restore_backup` exists but is not equivalent to
  the third-party server's: the plan resolves an **existing** guest and the
  apply passes `force=true`, so a same-shaped call overwrites rather than
  creates. This is the gap most likely to be missed, because the tool exists and
  the call succeeds.

Both are tracked in #57. Everything else the third-party `proxmox-mcp` offers
has an equivalent here --- see `docs/MIGRATING-FROM-PROXMOX-MCP.md`, which also
lists the arguments that changed shape.

### Change control

Destructive work goes through plan → approve → apply. The plan renders a
server-generated preview and records the action; the approval binds the plan
digest over `(owner, device, expected fingerprint, actions)`; the apply
re-checks the guest's fingerprint and refuses one that moved.

Two things worth stating plainly, because both are easy to assume wrongly:

- **The preview is not hashed into the digest.** It is stored with its own hash,
  so the text an approver read cannot be edited afterwards without the store
  refusing it --- but what an approver commits to is the operation and its
  parameters, not the prose describing them (#56).
- **`--lab-mode` is the *protection* override, not a blanket waiver.** It
  supplies the override a protected guest needs, so on a lab-mode server a
  **protected** guest is approved on creation with no second principal, while an
  **ordinary** guest still requires one and self-approval is refused. That
  inversion surprises people.

`--waivers-file` (default `/etc/proxmoxmcp/waivers.json`, mode 0600,
service-owned) carries time-boxed operator waivers. Both overrides originate
outside the tool call: **there is deliberately no `grant_waiver` tool and no
`force` argument**, because an override a caller can pass is not an override.

### What's implemented

- **Multi-cluster inventory:** One server, many clusters. Each cluster gets its own API token and protection policy.
- **Two-stage authorization:**
  1. **Stage 1** (before the catalog call): Bearer token validation, tool and cluster scope checks.
  2. **Stage 2** (guest-addressed tools only): Guest resolution, grant evaluation (VMID range, tag, pool selectors), and fail-closed protection.
- **Protection union:** A guest is protected if it appears in `protected_vmids` **or** carries a tag from `protected_tags`. A protected guest is refused by every destructive and service-interrupting tool unless a waiver or lab mode supplies an override. (Read tools see protected guests normally.)
- **The node is never accepted from the caller.** It is resolved on every call, and again at apply, because guests migrate. The one exception is `create_vm`/`create_container`, where there is no existing guest to resolve --- so the caller names the node, and it is the one place a caller can address the wrong host.
- **Catalog-driven dispatch:** Every read tool's HTTP method, path template, query flag, and type filter is declared once in `catalog.rs`.
- **In-flight recovery:** A change set left `Applying` with a task handle is re-probed at startup, so an apply interrupted by a restart resolves rather than staying unresolved forever.
- **SIGHUP reload:** `systemctl reload` reloads `clusters.json` in place without dropping in-flight calls. A failed reload logs and retains the previous snapshot.
- **Per-cluster CA pinning:** Each cluster can name a `ca_pem_path`. There is **no insecure-skip-verify at any layer**, so a cluster with a private CA needs its CA installed and must be addressed by a name its certificate covers.
- **Audit logging:** JSON-structured logs with optional PII redaction (HMAC-keyed or drop). Every tool call logs cluster, guest, tier, and protection status.

### The 17 read tools

| Tool | Scope | Description |
|------|-------|-------------|
| `get_cluster_status` | cluster | Quorum and node membership |
| `get_nodes` | cluster | All nodes with status and resource totals |
| `get_node_status` | node | Detailed status for one node |
| `get_vms` | cluster | All QEMU guests with node, status, tags |
| `get_containers` | cluster | All LXC guests with node, status, tags |
| `get_vm_config` | guest (QEMU only) | Configuration including Proxmox digest |
| `get_container_config` | guest (LXC only) | Configuration including Proxmox digest |
| `get_container_ip` | guest (LXC only) | Network interfaces and addresses |
| `get_guest_status` | guest | Current runtime status |
| `list_snapshots` | guest | Snapshots of one guest |
| `get_storage` | node | Storage backends visible to one node |
| `list_backups` | storage | Backup archives on one storage backend |
| `list_isos` | storage | ISO images on one storage backend |
| `list_templates` | storage | Container templates on one storage backend |
| `list_tasks` | node | Recent tasks on one node |
| `get_task_status` | task | Status of one task by UPID |
| `get_proxmox_change_set` | change set | One change set's state and preview |

The three type-specific reads refuse the other guest type by name rather than
addressing an endpoint that cannot exist.

### The 18 low tools

Lifecycle: `start_vm`, `stop_vm`\*, `shutdown_vm`\*, `reset_vm`\*,
`start_container`, `stop_container`\*, `restart_container`\*.

Provisioning: `create_vm`, `create_container`, `clone_vm`, `download_iso`,
`resize_disk`, `create_snapshot`, `create_backup`,
`update_container_resources`\*.

Tasks and change sets: `stop_task`\*, `plan_proxmox_destroy`,
`approve_proxmox_change_set`.

\* interrupts a running guest. That axis is tracked separately from the tier: a
tool can be `low` and still take a service down, and the protection gate applies
to both.

Notes that catch people out:

- `create_container` defaults to `unprivileged=1`. Proxmox reads an omitted
  field as privileged, so silence must not select the dangerous option.
- Config keys that reach the hypervisor are refused: `hookscript`, `args`, `mpN`
  host mounts, `hostpciN`/`usbN`/`devN`/`serialN`/`parallelN` passthrough, raw
  `lxc.*`, and any value carrying an absolute host path. A create is a `low`
  operation and must not become code execution on the node.
- A create refuses a VMID that already exists. Proxmox restores a backup by
  POSTing to the same endpoint, so without that check a `low` create could
  overwrite a live guest.
- `resize_disk` grows only. Shrinking is unsupported here **and in Proxmox** ---
  `qm resize` and `pct resize` reject a reduction.
- Container stops are immediate. There is no graceful LXC path: `shutdown_vm` is
  QEMU-only.

## Changing a token's scopes

`token set-scopes` changes a token's device, tool, guest, and action scopes
**without reissuing its secret**, so no client is reconfigured:

```
rust-proxmoxmcp token set-scopes --tokens-file <PATH> --name <NAME> \
  [--devices <CSV|*>] [--tools <CSV|*>] \
  [--guests <SELECTORS|*>] [--actions read,low,destructive] [--yes]
```

An omitted `--devices`/`--tools` leaves that scope unchanged. `--guests` and
`--actions` replace the grant **wholesale** rather than merging — a guest grant
is a scope where "I meant to replace it" must not silently mean "I added to
it" — and `--actions` alone is refused, because a grant carries both halves and
inventing the other would grant reach nobody named.

Widening is a privilege escalation and is confirmed interactively unless
`--yes` is passed; narrowing is not, because reducing a scope cannot grant
anything.

**`--tools '*'` does not reach a mutating tool.** `WRITE_TOOLS` is deliberately
excluded from the tool wildcard, so `start_vm` and its peers must be named
explicitly or the preflight refuses with `403 insufficient_scope`.

## Authorization model

### Stage 1: Bearer token and scope

Every streamable-HTTP call carries a bearer token. The token store (`tokens.json`) binds the token to:
- A **tool scope** (`tools: ["*"]` or `tools: ["get_nodes", "get_vms"]`)
- A **device scope** (`devices: ["*"]` or `devices: ["pve3"]`)
- A **grant** (see stage 2)

Stage 1 refuses:
- An invalid or missing bearer token (unless `--allow-no-auth` on loopback)
- A tool not in the token's `tools` list
- A cluster not in the token's `devices` list
- Any tool in `WRITE_TOOLS` that a wildcard scope tried to reach. `tools: ["*"]` deliberately excludes that registry, so a wildcard token reaches no mutating tool: each must be named explicitly.

Tokens with no `grant` key are **refused for guest-addressed tools**. This is fail-closed: a token that declares no guest selector must not become a wildcard.

### Stage 2: Guest resolution and protection

Guest-addressed tools resolve the VMID to a `GuestFacts` record (name, node, type, tags, pool) and evaluate the token's **grant**:

```json
{
  "guests": ["vmid:600-699", "tag:disposable", "pool:test-vms"],
  "actions": ["read"]
}
```

A guest is in scope when **any** selector term matches. The server then checks the **protection union**:

- A guest is protected if it appears in the cluster's `protected_vmids` **or** carries a tag from `protected_tags` (default: `["protected"]`).
- A protected guest **cannot be addressed by any mutating tool**, even with `"guests": ["*"]`.
- Read tools see protected guests normally.

If the guest is out of scope or the action tier (`read`/`low`/`destructive`) is not in the token's grant, the server refuses with a non-leaking error: "authorization failed" with no guest details.

## Configuration

### Cluster inventory: `clusters.json`

```json
{
  "version": 1,
  "devices": {
    "pve3": {
      "endpoint": "https://pve3.example.org:8006",
      "token_id": "root@pam!mcp",
      "token_secret_env": "PVE_PVE3_TOKEN",
      "protected_vmids": [905, 906, 907],
      "protected_tags": ["protected"]
    }
  },
  "policy": {
    "resource_cache_ttl_secs": 10
  }
}
```

**Note:** The top-level key is `devices`, not `clusters` — this is the canonical envelope from `mecmcp-inventory`, and the server reads each entry as a cluster.

**Credentials never appear in this file.** Each cluster references its API token secret through one of two mechanisms:

- **`token_secret_file`** (default): Points to a separate file like `/etc/proxmoxmcp/secrets/<cluster>.token`. This is the stronger option — the file is read through the same hardened loader as `clusters.json` and `tokens.json` (0600, regular file, owned by the service user, `O_NOFOLLOW`), and the credential never enters the process environment where it could surface in crash dumps or `/proc/<pid>/environ`.
- **`token_secret_env`**: Names an environment variable. Supported via `EnvironmentFile=-/etc/proxmoxmcp/secrets.env` in the systemd unit (the `-` prefix makes a missing file non-fatal). The environment-variable path is weaker because the credential becomes readable from the process environment.

Both are loaded through `mecmcp-secret` into an `OutboundSecret` that is zeroized on drop and implements neither `Debug` nor `Serialize`.

### Token store: `tokens.json`

```json
{
  "version": 1,
  "tokens": {
    "demo-reader": {
      "hash": "$argon2id$v=19$m=...",
      "grant": {
        "guests": ["vmid:600-699"],
        "actions": ["read"]
      },
      "tools": ["*"],
      "devices": ["pve3"]
    }
  }
}
```

Mint a token with `rust-proxmoxmcp token add <name>`. The plaintext token is printed once and never recoverable.

**IMPORTANT:** A token without a `grant` key is refused for guest-addressed tools. To grant read access to all guests:

```json
"grant": {
  "guests": ["*"],
  "actions": ["read"]
}
```

## CLI flags

`rust-proxmoxmcp` inherits every flag from `mecmcp_runtime::cli::Cli` (transport, bind, TLS, allowed hosts/origins, audit) and adds exactly one:

- `--clusters-file <path>` — Cluster inventory (default: `/etc/proxmoxmcp/clusters.json`)

For streamable-HTTP, either `--tokens-file` or `--allow-no-auth` is required. The latter permits unauthenticated read requests on loopback only; write tools remain denied.

Run `rust-proxmoxmcp --help` for the complete list.

## Installation

See `packaging/lxc/install.sh` for a POSIX installer targeting Debian 13 LXC. The installer:
- Creates the `proxmoxmcp` system user
- Installs the binary to `/usr/local/bin/rust-proxmoxmcp`
- Installs example config files to `/etc/proxmoxmcp` (mode 0600, owned by `proxmoxmcp`) **only if absent**
- Installs the hardened systemd unit with `ProtectSystem=strict` and `ReadWritePaths=/var/lib/proxmoxmcp`
- Prints next steps and a reminder to snapshot the container before upgrading

**Before upgrading:** Snapshot the container in Proxmox. A failed upgrade can be reverted by rolling back to the snapshot.

## Development notes

### Crate structure

- `rust-proxmoxmcp-core`: Domain logic (inventory, resolution, authorization, catalog). No server or transport.
- `rust-proxmoxmcp`: The binary. Assembles the transport, loads the inventory, and serves the catalog.

### The `testing` feature

The core crate has a non-default `testing` feature that pulls in `rcgen`, `rustls`, `tokio-rustls`, and `tempfile` to build mock HTTPS servers for the test suite. This machinery is **not** compiled into the release binary.

## Sibling servers

| | [rustjunosmcp](https://github.com/fastrevmd-lab/rustjunosmcp) | [rustpanosmcp](https://github.com/fastrevmd-lab/rustpanosmcp) | rustproxmoxmcp |
|---|---|---|---|
| Vendor | Juniper Junos / SRX | Palo Alto PAN-OS | Proxmox VE |
| Transport | NETCONF over SSH | HTTPS XML-API | HTTPS REST |
| Status | shipping | shipping | shipping, 0.8.0 |

All three consume `mecmcp` — the shared Rust crate family underneath mechub's per-vendor MCP servers.

## Audit forwarding to the event store

The audit trail does not stay on this host. This server follows the family
standard — [AUDIT-FORWARDING-STANDARD.md](https://github.com/fastrevmd-lab/mecmcp/blob/main/docs/AUDIT-FORWARDING-STANDARD.md).

An audit record that only exists on the machine that produced it is not an audit
trail: it is a log file on a box whose operator is the party the record is about.

### Emission (in effect now)

```
--audit-format json \
--audit-log-file /var/lib/proxmoxmcp/audit.jsonl
```

JSON is mandatory. The `text` format is for reading in a terminal and is not a
parse target. The file is the operator-facing artifact and must be rotated — the
server never truncates it.

### Transport (specified, not yet implemented)

Records are written directly into SSDF's `ssdf.audit` as **hash-chained** rows,
per SSDF's merged evidence contract, so that deleting or editing a row is
detectable. Tracked in [mecmcp#292](https://github.com/fastrevmd-lab/mecmcp/issues/292).

A cheaper syslog path was designed and rejected: it works, but the records are
unchained, and every other link here is tamper-evident by construction — plan
digests bind approvals, approvals name a distinct principal, and
`token_verified_fields` separates vouched-for provenance from asserted. An
unchained final hop would discard that guarantee exactly where an auditor needs
it. The reasoning is recorded in the standard.

### Reading the result

`token_verified_fields` names the provenance fields the **token** vouched for.
The rest of that group — `client_name`, `model_id`, `session_id` — is
client-asserted and authenticated by nothing. Do not read them as equivalent.

`request_id` correlates the transport event, the handler event, and (on Junos)
the device commit comment.

## License

## Operations and Security

### Egress filtering

The packaged unit declares `IPAddressDeny` and `IPAddressAllow` to control
egress. However, **systemd cannot enforce these directives in an unprivileged
LXC** — every guest in this fleet is one. systemd implements them with cgroup
BPF and fails open when it cannot load the program, so the unit can declare a
full egress policy while enforcing none of it. `systemd-analyze security` reads
the declaration and cannot tell the difference.

The installer probes actual enforcement and prints one of four verdicts:

- `egress filter: ENFORCED` — the host attaches the BPF program *and* the
  installed unit declares a policy
- `egress filter: NOT ENFORCED` — the host cannot attach it; guidance follows
- `egress filter: NO POLICY` — the host could enforce, but the installed unit
  declares no `IPAddressDeny` (a preserved customized unit overrides the
  packaged one; re-install to restore it)
- `egress filter: UNKNOWN` — the probe could not run; nothing is claimed

Both conditions matter. A host-capability check alone would report success over
a service filtering nothing.

The probe uses IP accounting, which rides the same BPF attachment, so a
populated counter proves the filter attached. Check it any time:

```console
systemctl show rust-proxmoxmcp.service -p IPEgressBytes --value
```

`[no data]` means the egress directives are doing nothing. Set
`PROXMOXMCP_REQUIRE_EGRESS_FILTER=1` to make the installer refuse anything short
of `ENFORCED` — including `UNKNOWN`, since an unmeasurable host is exactly as
unguaranteed as a non-enforcing one.

#### Enforcing it where systemd cannot

Any result other than `ENFORCED` means the unit directives are **unproven**, and
the control should move outward — to whatever layer actually sees this
workload's packets. `NOT ENFORCED` and `NO POLICY` mean they are demonstrably
doing nothing; `UNKNOWN` means nothing was measured and they may well be
working. Do not treat the last as the first.

The policy does not change with the runtime (though the unit allows RFC 1918 to
reach Proxmox API endpoints):

1. deny `169.254.0.0/16` and `fd00:ec2::254` — cloud metadata, the route from a
   compromised HTTP client to a stolen credential
2. deny link-local (`fe80::/10`) — not used by any supported target
3. deny the local subnet **except** your DNS resolver — blocks lateral movement
   while keeping name resolution working (not currently declared in this
   server's unit; add via drop-in if needed)

The mechanism does. Configure it with your platform's own documentation rather
than a recipe here — these are the layers, not instructions:

| Runtime | Layer that sees this workload's packets |
|---|---|
| Proxmox LXC / VM | per-guest interface firewall |
| libvirt / KVM | `nwfilter` on the guest interface |
| Kubernetes | `NetworkPolicy` egress, on a CNI that implements it |
| Cloud instance | in-guest packet filter for **both** metadata addresses, plus security groups for everything else |
| Bare metal, VM with working systemd | the unit directives; this section does not apply |

Two properties are worth checking whatever you choose, because both are common
and both produce a control that reads as present and is not:

- **Some layers accept egress policy without enforcing it.** Container network
  attachment and some CNI implementations are the usual cases.
- **Cloud metadata often bypasses the cloud firewall.** On EC2, IMDS traffic is
  handled below the security group and NACL layer, so an egress rule there does
  not block it. This applies to the IPv6 endpoint too — `fd00:ec2::254` is ULA
  rather than link-local, so it is easy to file mentally under "ordinary routed
  traffic the firewall sees", and it is not. The control has to be in-guest, or
  IMDS disabled outright. Consult your provider's current metadata-hardening
  guidance; it changes, and getting it wrong is silent.

Whichever you pick, a rule that has not been exercised from inside the workload
is an assumption. Verify it, and re-verify after a reboot — in-kernel firewall
rules are not persistent unless you made them so.


Licensed under [MIT](LICENSE).
