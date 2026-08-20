# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
