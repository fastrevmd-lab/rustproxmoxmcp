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

## Status: 0.1 — read surface

Release 0.1 delivers the complete read-only catalog: 16 tools covering cluster status, nodes, guests (QEMU VMs and LXC containers), storage, backups, ISO images, templates, snapshots, and tasks. **No mutating tools exist yet** — every destructive operation (`delete_vm`, `clone_vm`, snapshot/backup lifecycle, etc.) is deferred to release 0.2.

**Testing status:** All 78 tests pass, including an adversarial suite covering the authorization spine and the protection union. The test suite exercises the code against **mock Proxmox servers only** — release 0.1 has not been run against a real Proxmox cluster.

### What's implemented

- **Multi-cluster inventory:** One server, many clusters. Each cluster gets its own API token, TLS trust anchor, and protection policy.
- **Two-stage authorization:**
  1. **Stage 1** (before the catalog call): Bearer token validation, tool and cluster scope checks.
  2. **Stage 2** (guest-addressed tools only): Guest resolution, grant evaluation (VMID range, tag, pool selectors), and fail-closed protection.
- **Protection union:** A guest is protected if it appears in `protected_vmids` **or** carries a tag from `protected_tags`. A protected guest cannot be addressed by any mutating tool, even with a wildcard token. (Read tools see protected guests normally.)
- **Catalog-driven dispatch:** Every tool's HTTP method, path template, query flag, and type filter is declared once in `catalog.rs`. The runtime resolves `{node}` and `{vmid}` parameters and assembles the outbound call without hand-written per-tool client code.
- **SIGHUP reload:** `systemctl reload` (or `kill -HUP`) reloads `clusters.json` in place without dropping in-flight calls. A failed reload logs and retains the previous snapshot.
- **Per-cluster CA pinning:** Each cluster in the inventory can name a `ca_pem_path`. No `--insecure` flag exists at any layer.
- **Audit logging:** JSON-structured logs with optional PII redaction (HMAC-keyed or drop). Every tool call logs cluster, guest, tier, and protection status.

### What's deliberately absent

- **Every mutating tool.** The complete destructive tier (`delete_vm`, `delete_container`, `delete_snapshot`, `delete_backup`, `restore_backup`, `rollback_snapshot`) and the low tier (`clone_vm`, `create_snapshot`, `create_backup`, `start_vm`, `stop_vm`, etc.) are registered in `WRITE_TOOLS` but unimplemented. A token with `"tools": ["*"]` cannot call them because they are unregistered; the catalog refuses the call before authorization runs.
- **Override and lab mode** (release 0.3): `--lab-mode`, `--waivers-file`, and the `lab_unrestricted` token flag. These belong to release 0.3's change-control surface and are deliberately omitted so a flag that is present but ignored cannot confuse an operator.

### The 16 read tools

| Tool | Scope | Description |
|------|-------|-------------|
| `get_cluster_status` | cluster | Quorum and node membership |
| `get_nodes` | cluster | All nodes with status and resource totals |
| `get_node_status` | node | Detailed status for one node |
| `get_vms` | cluster | All QEMU guests with node, status, tags |
| `get_containers` | cluster | All LXC guests with node, status, tags |
| `get_vm_config` | guest (QEMU) | Configuration including Proxmox digest |
| `get_container_config` | guest (LXC) | Configuration including Proxmox digest |
| `get_container_ip` | guest (LXC only) | Network interfaces and addresses |
| `get_guest_status` | guest | Current runtime status |
| `list_snapshots` | guest | Snapshots of one guest |
| `get_storage` | node | Storage backends visible to one node |
| `list_backups` | storage | Backup archives on one storage backend |
| `list_isos` | storage | ISO images on one storage backend |
| `list_templates` | storage | Container templates on one storage backend |
| `list_tasks` | node | Recent tasks on one node |
| `get_task_status` | task | Status of one task by UPID |

Guest-addressed tools (`get_vm_config`, `get_container_config`, `get_container_ip`, `get_guest_status`, `list_snapshots`) take `(cluster, vmid)` only. The server resolves the guest's current node on every call — accepting a node from the caller is how a request addresses the wrong guest after a migration.

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
- Any tool in `WRITE_TOOLS` (the complete mutating catalog is registered but unimplemented)

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
      "ca_pem_path": "/etc/proxmoxmcp/ca/pve3.pem",
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
| Status | shipping | shipping | 0.1, read surface |

All three consume `mecmcp` — the shared Rust crate family underneath mechub's per-vendor MCP servers.

## License

Licensed under [MIT](LICENSE).
