# Migrating from the third-party `proxmox-mcp`

For operators moving off the third-party server (LXC 970, tagged
`notmechub;protected`) to `rust-proxmoxmcp`.

Retirement here means **ceasing to depend on 970**, not acting on the guest.
It is not ours to modify.

## The behavioural difference that matters

The third-party server **deletes on a single call**. This one makes destruction
a governed change set:

```
plan_proxmox_destroy → approve_proxmox_change_set → apply_proxmox_change_set
```

The plan renders a server-generated preview and records the operation; the
approval binds the **plan digest**, which covers `(owner, device, expected
fingerprint, actions)`; and applying re-checks the guest's fingerprint.
**A guest that changed after approval is refused rather than acted on.**

`--lab-mode` waives the second principal for a single-operator lab, and
`--waivers-file` carries time-boxed operator waivers — both originate outside
the tool call, because an override a caller can pass is not an override.

Be precise about what the approval covers, because an earlier draft of this
guide was not. **The preview is not part of the digest.** It is stored with its
own hash, so the text an approver read cannot be edited afterwards without the
store refusing it — but the approval binds the *action*, and the preview is
rendered from that action rather than hashed into it. What an approver is
cryptographically committing to is the operation and its parameters, not the
prose describing them.

That is the reason to migrate. Everything below is the mechanics.

## Tool mapping

### Same name, same meaning

`get_cluster_status` · `get_nodes` · `get_node_status` · `get_vms` ·
`get_containers` · `get_vm_config` · `get_container_config` ·
`get_container_ip` · `get_storage` · `list_backups` · `list_isos` ·
`list_snapshots` · `list_templates` · `start_vm` · `stop_vm` ·
`shutdown_vm` · `reset_vm` · `start_container` · `stop_container` ·
`restart_container` · `create_snapshot` · `create_backup` · `clone_vm` ·
`resize_disk`

Guest-addressed tools take `(cluster, vmid)` only. **The node is never
accepted from the caller** — it is resolved on every call, because accepting a
node is how a request addresses the wrong guest after a migration.

### Reached through the change-set flow instead of directly

| third-party | here |
|---|---|
| `delete_vm` | `plan_proxmox_destroy` with `op: "destroy_guest"` |
| `delete_container` | `plan_proxmox_destroy` with `op: "destroy_guest"` |
| `delete_snapshot` | `op: "delete_snapshot"`, `snapname` |
| `rollback_snapshot` | `op: "rollback_snapshot"`, `snapname` |
| `delete_backup` | `op: "delete_backup"`, `storage` + `volid` |
| `delete_iso` | `op: "delete_iso"`, `storage` + `volid` |
| `restore_backup` | `op: "restore_backup"`, `volid` |
| `execute_vm_command` | `op: "guest_exec"`, `command` |

Then `approve_proxmox_change_set` and `apply_proxmox_change_set`.

`delete_backup` and `delete_iso` also require `storage_node`: `local` is
node-local storage, so the same volid on two nodes names two different volumes.

Each operation additionally authorises against **its own tool name** — a token
allowlisted for `plan_proxmox_destroy` and `apply_proxmox_change_set` but not
`delete_backup` cannot select `op: "delete_backup"`. Name the operations you
need in the token scope, not just the two handlers.

### No equivalent, by decision

| third-party | why |
|---|---|
| `get_job` | use `get_task_status` with the UPID |
| `list_jobs` | use `list_tasks` for a node |
| `poll_job` | applies follow their UPID to completion within the call; a crashed apply is re-probed at startup |
| `cancel_job` | **none.** Proxmox tasks are not cancellable through this surface |
| `retry_job` | **none.** A failed apply needs a fresh plan — the change set is terminal, and retrying one whose receipt is already written would carry an empty digest and principal |

The last two are genuine gaps, not oversights. A caller that depends on them
has to change rather than be shimmed.

### Here but not there

`get_guest_status` · `get_task_status` · `list_tasks` ·
`plan_proxmox_destroy` · `get_proxmox_change_set` ·
`approve_proxmox_change_set` · `apply_proxmox_change_set`

## Before you cut over

1. **Name every tool in the token scope.** `tools: ["*"]` deliberately
   **excludes** `WRITE_TOOLS`, so a wildcard token reaches no mutating tool.
   Use `token set-scopes --name N --tools ...` — it changes scopes without
   reissuing the secret.
2. **Grant the action tiers you need.** `read`, `low`, `destructive`. A grant
   carrying only `read` cannot call `start_vm` however its tool scope reads.
3. **Pass `--state-file`.** Without it, change sets live in memory and every
   approval is lost on restart. The packaged unit passes
   `${STATE_DIRECTORY}/changeset-state.json`.
4. **Check `protected_vmids` and `protected_tags`.** A protected guest refuses
   anything that would interrupt or destroy it without a waiver — including
   `stop_vm`. Snapshots and backups still work, which is deliberate.

## Two behaviours that will surprise a 970 caller

- **`stop_vm` on a protected guest is refused.** The third-party server has no
  such concept. Snapshotting and starting a protected guest are still allowed:
  protection means "do not take this down", not "do not back it up".
- **A shrinking `resize_disk` is refused, and there is no supported
  alternative here.** Only the `+N` form is accepted, because an absolute size
  may be smaller than the current disk and this server cannot know the current
  size.

  Shrink from the Proxmox UI or CLI. Do **not** reach for
  `plan_proxmox_destroy` — it takes only a cluster and a vmid and deletes the
  whole guest. An earlier draft of this guide suggested it, which would have
  turned a disk-shrink request into a VM deletion for anyone following the
  text literally.
