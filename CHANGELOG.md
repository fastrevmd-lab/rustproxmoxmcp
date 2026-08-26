# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-08-26

Completes the destructive tier. 0.3 built the change-set machinery and wired
**one** of the eight destructive tools through it; the remaining six now go
through the same plan -> approve -> apply path rather than beside it.

### Added

- **`plan_proxmox_destroy` takes an `op`** — `destroy_guest` (the default),
  `delete_snapshot`, `rollback_snapshot`, `delete_backup`, `delete_iso`,
  `restore_backup` — with the parameters each needs. Required at **plan** time,
  because the action is what the digest covers: anything left undecided then is
  something the approver cannot review.
- `destroy_vm`, `delete_snapshot`, `rollback_snapshot`, `delete_volume` and
  `restore_backup` primitives.

### Security

- **Each operation authorises against its own tool name.** A token allowlisted
  for `plan_proxmox_destroy` and `apply_proxmox_change_set` could previously
  select any operation, which made `WRITE_TOOLS` naming each destructive tool
  separately meaningless. Checked at plan **and** at apply, because a scope can
  be narrowed between the two and the apply is the call that acts.
- **The preview describes the operation that will run.** It previously rendered
  a guest destroy for every operation, so an approver reviewing a rollback,
  restore or volume deletion was shown `DESTROY <guest>`. The two that *replace*
  state now say so: a rollback and a restore both warn that everything written
  since the snapshot is lost.
- **A volume is addressed on its own node.** `local` is node-local storage, so
  `local:backup/x` on two nodes names two different volumes; the node is now
  part of the action rather than derived from whichever guest the vmid names.

### Fixed

- **A synchronous deletion no longer fails after succeeding.** Some storage
  types delete without a task and return no handle; parsing that as a UPID
  reported failure for a volume already gone, wrote no receipt, and left the
  record retryable against something that no longer existed.

### What the approval actually binds

Stated plainly, because the 0.3 README overstated it. The plan digest covers
`(owner, device, expected fingerprint, actions)` and the approval binds that
digest. **The preview is not hashed into it.** It is stored with its own digest,
so the text an approver read cannot be edited afterwards without the store
refusing it — but what an approver commits to is the operation and its
parameters, not the prose describing them.

### Backward compatibility

`op` defaults to `destroy_guest`, so a caller written against 0.5 keeps working.
A change set planned under 0.3 recorded `op: "destroy"`, and that spelling still
dispatches: a plan made then must not become unexecutable because the name
changed.

## [0.5.0] - 2026-08-25

The daily driver. **`KNOWN_TOOLS` goes 20 -> 29**, and change-set state is
persisted for the first time.

Issue #46 calls this milestone "0.4"; the crate was already at 0.4.0 when that
issue was written, so it ships as 0.5.0. The milestone numbering in #47-#49
is one behind the version for the same reason.

### Added

- **Seven lifecycle tools** — `start_vm`, `stop_vm`, `shutdown_vm`,
  `reset_vm`, `start_container`, `stop_container`, `restart_container`.
- **`create_snapshot` and `create_backup`.** `create_backup` defaults to
  vzdump `mode=snapshot`, the only mode that does not interrupt the guest.
- **`--state-file`**, the spelling `mecmcp/docs/PACKAGING.md` standardises.
  The packaged unit passes `${STATE_DIRECTORY}/changeset-state.json`.
- **Startup recovery.** An apply that was in flight when the process stopped
  is re-probed before serving, closing the "detectable but not recoverable"
  limitation 0.3 documented.
- **`token set-scopes`** changes a token's device, tool, guest and action
  scopes **without reissuing its secret**, so no client is reconfigured. The
  alternatives all mint a new one: `rotate` preserves scopes and changes the
  secret, `revoke`+`add` does the same, and hand-editing `tokens.json` skips
  every validation.

  Widening is a privilege escalation and is confirmed interactively unless
  `--yes` is passed; narrowing is not, because reducing a scope cannot grant
  anything. Every change is written to the audit trail through a sink that
  `RUST_LOG` cannot silence — a target-specific filter previously suppressed
  it while the widening still applied.

  Note that `--tools '*'` does **not** reach a mutating tool: `WRITE_TOOLS` is
  excluded from the wildcard, so the nine tools above must be named explicitly
  in a token scope.

### Fixed

- **Change-set state is persisted at all.** `new_with_default_coordinator`
  passed `None` as the state path, so the coordinator kept everything in
  memory: every approval, preview and operation record was lost on restart,
  and had been since 0.1. `StateDirectory=proxmoxmcp` had been provisioning a
  0700 directory all along with nothing writing to it.

### Changed — protection now covers interrupting calls

The protection gate keyed on `tier == Destructive`, which was
indistinguishable from "everything disruptive" while destructive tools were
the only mutating tools. Adding `stop_vm` made the difference real: a
protected guest would have been stoppable by a routine low-tier call.

The axis is **service interruption, not mutation**, and it is deliberately
orthogonal to `Tier` — the tier answers "does this destroy data", interruption
answers "does this take the guest down".

| on a protected guest | |
|---|---|
| `stop_vm` `shutdown_vm` `reset_vm` `stop_container` `restart_container` | **refused** without a waiver or `--lab-mode` |
| `start_vm` `start_container` `create_snapshot` `create_backup` | allowed |

The second row is the point: all five guests upgraded on 2026-08-25 are
`protected`, and snapshotting them beforehand is the most common operation in
this lab.

### Upgrade note

`mecmcp` 0.19.0 -> 0.20.0.

**Rolling back during an apply needs the state file restored alongside the
binary** — the Proxmox snapshot path the fleet already uses.

The reason is the field, not the envelope version. `ChangeSetRecord` is
`deny_unknown_fields`, so a binary predating 0.20.0 rejects the **whole state
file** — not the one record — the moment any change set carries `task_id`.
`task_id` raises the file's minimum to version 2, but an in-flight apply is by
definition an approved change set, and a real approval already forces version 4
(or 3 with a waiver), so the file such a rollback meets is normally well past
version 2 anyway.

A deployment that never applies keeps writing files the older binary reads.

## [0.4.0] - 2026-08-25

### Added

- **SSDF evidence pipeline** (mecmcp#292). Mutating operations now emit
  execution evidence, including around the destroy path, and the evidence is
  flushed even when serving ends in an error. Receipts name the executor.

### Security

- **Tier-2 hardening.** `tokens.json` moves to `/var/lib`, the systemd unit is
  sandboxed, the audit HMAC key is guarded, and stale secrets are scanned for.
- **The legacy token store is no longer shadowed by an empty one.** An upgrade
  that found an empty primary could previously mask a populated legacy store,
  which reads as "every credential was rejected" rather than as a packaging
  fault.
- **Token paths compare byte-for-byte**, not by `Path` equality, and the legacy
  fallback is restricted to the canonical path only.
- Packaging now probes real egress enforcement rather than implying it.

### Changed

- **`mecmcp` 0.11.0 -> 0.19.0.** That is the jump from the v0.3.2 baseline;
  0.17.0 was an intermediate untagged step.

### Upgrade note — rolling back needs the state file, not just the binary

`mecmcp-changeset` state carries a schema version. v0.3.2 links 0.11.0, whose
reader accepts **v1-v3 only**. 0.4.0 links 0.19.0, which accepts v1-v4 and
**stamps v4 on any write to a store holding a real approval**.

Once this release has written such a store, reinstalling the 0.3.2 binary alone
will not start — it rejects the state file with `unsupported changeset state
version 4`. **Roll back with the Proxmox snapshot**, which restores `/var/lib`
along with the binary. A binary-only downgrade is not a rollback path.
- `rmcp` 3.1.2 -> 3.1.4.
- Pinned toolchain moved to 1.98.0, alongside the builder image, with a CI
  toolchain-pin guard and a Docker build in CI.
- Dependabot now watches the Dockerfile. `reqwest` 0.12 -> 0.13, `rcgen` 0.13 ->
  0.14.

### Note on the version

Minor rather than patch: this release adds the evidence pipeline, which is a
feature, not a fix.

## [0.3.2] - 2026-08-19

### Added

- **`--lab-mode` now announces itself at startup.** The flag was applied
  silently, so the only way to tell a lab-mode server from a two-person one was
  to read its unit file or `/proc/<pid>/cmdline`. Every sibling server in the
  family prints this banner; auditing the fleet at a glance depends on it.

## [0.3.1] - 2026-08-18

### Fixed

- **`tools/list` now carries the cache descriptor** (`ttlMs`, `cacheScope`) a
  2026-07-28 client validates. Because this server overrides `list_tools` to
  filter by token scope, it did not inherit the fields rmcp's generated handler
  supplies, and a client on the new protocol rejected the reply outright —
  reported as "tools fetch failed" against a healthy server.
- Took h2 0.4.17 for RUSTSEC-2026-0258.

### Documentation

- Documented audit forwarding and where the trail goes.

## [0.3.0] - 2026-08-15

### Added

- **Destructive operations are under change-set control.** `delete_container`
  and its siblings go through create/approve/apply rather than executing on
  call, following the Proxmox UPID task to completion.
- **`--lab-mode` and `--waivers-file`**, matching the rest of the family:
  single-operator mode waives the distinct-approver rule, and waivers are
  recorded rather than implied.

### Fixed

- **`--allow-insecure-bind` was parsed and never wired into the transport**, so
  the server could not bind plaintext off-loopback at all. It hid because every
  deployed server uses TLS. Now covered by a test that binds `0.0.0.0:0`.

## [0.1.2] - 2026-08-14

### Changed

- Converged on mecmcp v0.9.1 (from v0.8.8).

### Added

- CI and security workflows: gitleaks with default rules loaded, `cargo-deny`
  with a `[sources]` section, and fixtures marked exempt from secret scanning.

### Fixed

- Hardened the `testing` feature guard against fail-open.

## [0.1.1] - 2026-08-13

### Fixed

Five defects found by installing and running release 0.1.0 against a live Proxmox VE cluster:

- **Blocker:** A fresh install could not mint its first token. The installer seeded `tokens.json` with a JSON object (`{"version": 1, "tokens": {}}`) where the loader requires an array (`{"version": 1, "tokens": []}`). Fixed by changing the installer to write the correct envelope.
- **Blocker:** `token add` had no way to set a token's guest grant, so no mintable token could call guest-addressed tools. Added `--guests <selector>` and `--actions <tier>` flags to `rust-proxmoxmcp token add`.
- SIGHUP reloaded the cluster inventory but not the token store, so minting a token and reloading the service appeared to do nothing until a full restart. Fixed by adding `TokenStore` to the `ReloadableState` struct.
- A missing credential file or unreadable CA certificate reported "malformed proxmox response", pointing operators at their Proxmox cluster instead of their filesystem. Fixed by surfacing the underlying I/O error as a configuration error in the reload handler.
- The example inventory (`clusters.example.json`) named a `ca_pem_path` the installer never creates, breaking startup for any cluster with a publicly-trusted certificate. Fixed by removing the key from the example; `ca_pem_path` is now documented as optional and only needed for private CAs.

## [0.1.0] - 2026-08-12

### Added

- **Multi-cluster inventory:** One server process serves many Proxmox VE clusters from a single `clusters.json` file. Each cluster entry specifies its endpoint, API token reference, optional per-cluster CA certificate, and protection policy.
- **Complete read-only catalog:** 16 tools covering cluster status, nodes, guests (QEMU and LXC), storage, backups, ISO images, templates, snapshots, and tasks.
  - Cluster-scoped: `get_cluster_status`, `get_nodes`, `get_vms`, `get_containers`
  - Node-scoped: `get_node_status`, `get_storage`, `list_tasks`
  - Guest-scoped: `get_vm_config`, `get_container_config`, `get_container_ip` (LXC only), `get_guest_status`, `list_snapshots`
  - Storage-scoped: `list_backups`, `list_isos`, `list_templates`
  - Task-scoped: `get_task_status`
- **Two-stage authorization:**
  - Stage 1: Bearer token validation, tool and cluster scope checks (via `mecmcp-auth::authorize_call`)
  - Stage 2 (guest tools only): Guest resolution, grant evaluation (`GuestFacts` against `ProxmoxGrant`), and fail-closed protection enforcement
- **Protection union:** A guest is protected if it appears in `protected_vmids` **or** carries a tag from `protected_tags`. Protected guests cannot be addressed by mutating tools (when implemented), even with wildcard grants.
- **`AuthorizedGuest`:** A type-level authorization proof that a guest passed stage-2 checks. Constructors are `pub(crate)` so guest-addressed catalog calls cannot bypass authorization.
- **Complete `WRITE_TOOLS` registry:** The full mutating catalog is declared in `tier::WRITE_TOOLS` (23 tools across `low` and `destructive` tiers). None are implemented in this release; the registry exists so `authorize_call` refuses them before any catalog lookup.
- **Catalog-driven dispatch:** Every tool's HTTP method, path template, query flag, and type filter is declared once in `catalog.rs`. The runtime resolves `{node}` and `{vmid}` path parameters without per-tool client code.
- **Per-cluster CA pinning:** Each cluster can specify `ca_pem_path` to trust a private CA. No `--insecure` flag exists.
- **SIGHUP reload:** `systemctl reload rust-proxmoxmcp` (or `kill -HUP <pid>`) reloads `clusters.json` in place, invalidates the guest index cache, and logs the result. A failed reload retains the previous snapshot and does not stop the server.
- **Hardened systemd unit:** `ProtectSystem=strict` with `ReadWritePaths=/var/lib/proxmoxmcp` only. `/etc/proxmoxmcp` is read-only to the service process, making inventory edits a root operation.
- **LXC packaging:** `packaging/lxc/install.sh` — a POSIX installer for Debian 13 that creates the service user, installs the binary, writes example configs (only if absent), and installs the systemd unit.
- **Audit logging:** JSON-structured logs with optional PII redaction. Every tool call logs cluster, guest, tier, and protection status.
- **Comprehensive test suite:** 78 tests including:
  - Client retry, bearer token assembly, catalog integrity
  - Authorization stage 1 and stage 2, including out-of-scope and protected-guest refusals
  - Guest resolution, type filtering, protection union
  - Adversarial cases: a token with no grant is refused; `get_container_ip` refuses QEMU guests; protected guests cannot be reached by mutating tools
  - Compile-fail tests ensuring `AuthorizedGuest::new` is not public

### Not Included

- **No mutating tools.** Every destructive operation (`delete_vm`, `delete_container`, `delete_snapshot`, `delete_backup`, `restore_backup`, `rollback_snapshot`) and low-tier operation (`clone_vm`, `create_snapshot`, `create_backup`, start/stop/reset lifecycle) is registered in `WRITE_TOOLS` but unimplemented. Deferred to release 0.2.
- **No override or lab mode.** `--lab-mode`, `--waivers-file`, and the `lab_unrestricted` token flag belong to release 0.3's change-control surface and are deliberately absent.
- **No task streaming or UPID polling.** Task lifecycle (wait-for-completion, progress streaming) is deferred to release 0.2.
- **No lab validation against a real Proxmox cluster.** All 78 tests pass against mock HTTPS servers; the code has not been run against a live Proxmox VE cluster.

### Notes

- The existing deployment (three Python MCP servers, one per cluster endpoint) **remains in service**. This release does not replace it.
- The cluster inventory file uses the top-level key `devices` (the canonical envelope from `mecmcp-inventory`), not `clusters`. Each entry is read as a cluster.
- A bearer token with no `grant` key is refused for guest-addressed tools. This is fail-closed: a grantless token must not become a wildcard.
- The `rust-proxmoxmcp-core` crate has a non-default `testing` feature that pulls in mock-server machinery (`rcgen`, `rustls`, `tokio-rustls`, `tempfile`). This is **not** compiled into the release binary.

[0.1.1]: https://github.com/fastrevmd-lab/rustproxmoxmcp/releases/tag/v0.1.1
[0.1.0]: https://github.com/fastrevmd-lab/rustproxmoxmcp/releases/tag/v0.1.0
