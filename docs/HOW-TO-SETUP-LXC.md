# How to set up a rust-proxmoxmcp LXC from scratch

Builds one Proxmox LXC running `rust-proxmoxmcp`, in either **lab mode** or
**two-person** mode. Written from a rebuild performed on 2026-09-07, not from
memory: every command here was run, and the two failures that occurred are in
[Troubleshooting](#troubleshooting) with their exact error text.

Two rigs are normally built as a pair, because they test different things:

| mode | approvals | use it for |
|---|---|---|
| **lab mode** (`--lab-mode`) | waived on creation for protected guests only; ordinary guests still require a second principal | lab work on protected guests, single-operator change sets |
| **two-person** (no flag) | a second principal must approve before apply, for all guests | anything that must prove the approval gate holds |

Never point a lab-mode server at production clusters. `--lab-mode` is the
*protection* override, not a blanket waiver: on a lab-mode server a
**protected** guest is approved on creation with no second principal, while an
**ordinary** guest still requires one and self-approval is refused. That
inversion surprises people.

## 0. Before you start

You need:

- A Proxmox node, a container template, and a free VMID and IP.
- **The credentials the server will use.** Four files: `clusters.json`,
  `tokens.json`, `mcp-rig.secret`, and a per-cluster token file in
  `secrets/<cluster>.token`. Building the container is the easy part; these are
  the part you cannot regenerate. If you are rebuilding an existing rig, back
  them up first — see [Rebuilding](#rebuilding-an-existing-rig).

Check the template is present:

```bash
pveam list local | grep debian-13
# local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst
```

## 1. Get a binary that will actually run

**Do not `cargo build --release` on your workstation and copy the binary in.**
glibc is forward-incompatible: a binary linked against a newer glibc will not
start on an older one, and it fails at service start with a loader error *after*
the old binary has been replaced — an outage, not a build failure.

Take the binary from the release image, which CI builds against the right glibc:

```bash
docker create --name px ghcr.io/fastrevmd-lab/rust-proxmoxmcp:0.9.1
docker cp px:/usr/local/bin/rust-proxmoxmcp ./rust-proxmoxmcp
docker rm px
```

No docker? On the Proxmox host, `skopeo` is available:

```bash
skopeo copy docker://ghcr.io/fastrevmd-lab/rust-proxmoxmcp:0.9.1 dir:/tmp/img
```

Then find the layer containing `usr/local/bin/rust-proxmoxmcp` and untar it.

## 2. Assemble the install package

**This repo has NO package-building script**, unlike its sibling servers. The
package is hand-assembled. Note the unusual layout: the binary goes at the
package **root**, not in `bin/`:

```
rust-proxmoxmcp                                   (binary, at root)
packaging/systemd/rust-proxmoxmcp.service
packaging/systemd/rust-proxmoxmcp.sysusers
packaging/systemd/rust-proxmoxmcp.tmpfiles
packaging/examples/clusters.example.json
packaging/lxc/install.sh
```

Assemble it:

```bash
cd /path/to/rustproxmoxmcp
tar czf pkg.tar.gz rust-proxmoxmcp packaging/
```

> **Gap:** `rustjunosmcp` ships `scripts/package-lxc.sh` with
> `JMCP_PACKAGE_SKIP_BUILD=1`; this repo has no equivalent. The package must be
> hand-assembled as shown above.

The installer is `#!/bin/sh`, not bash. Invoke it as `bash ./packaging/lxc/install.sh`
(or `sh`) since it may not be executable in the archive.

## 3. Create the container

`nesting=1` is **required**. systemd 257 degrades badly in an unprivileged LXC
without it.

```bash
pct create 616 local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
    --hostname test-twoperson-proxmox \
    --cores 1 --memory 512 --swap 512 \
    --rootfs local-lvm:4 \
    --unprivileged 1 --features nesting=1 \
    --net0 name=eth0,bridge=vmbr0,firewall=1,gw=192.0.2.1,ip=192.0.2.10/24,type=veth \
    --onboot 0 --ostype debian \
    --tags "disposable;test;twoperson"

pct start 616
```

For the lab-mode pair, substitute `617`, `test-labmode-proxmox`, `192.0.2.11`,
and the tag `labmode`.

512 MB and one core is enough. The tags matter: `disposable` is what marks a
guest as safe to destroy, and the fleet's own safety rules key on it.

## 4. Install

```bash
pct push 616 pkg.tar.gz /tmp/pkg.tar.gz
pct exec 616 -- bash -lc 'cd /tmp && tar xzf pkg.tar.gz && bash ./packaging/lxc/install.sh'
```

`install.sh` creates the `proxmoxmcp` service user, installs the binary and the
unit, and stops there. **The service will not start yet** — it has no
configuration, and it says so.

## 5. Configuration and credentials

**This server needs FOUR files**, and a missing one costs a restart each:

```
/etc/proxmoxmcp/clusters.json
/etc/proxmoxmcp/tokens.json
/etc/proxmoxmcp/mcp-rig.secret
/etc/proxmoxmcp/secrets/<cluster>.token
```

Two real failures happened here during the rebuild this document is written from:

1. `configuration error: file /etc/proxmoxmcp/mcp-rig.secret: No such file or directory`
   — that file was not restored.
2. `token file /etc/proxmoxmcp/tokens.json: No such file or directory` even
   though `tokens.json` existed at `/var/lib/proxmoxmcp/tokens.json` — because
   the drop-in's `--tokens-file` points at `/etc/proxmoxmcp/`.

**Read the drop-in first to learn where it expects each file**, rather than
assuming a default location. Restore everything before the first start.

Place the credentials:

```bash
pct push 616 clusters.json        /etc/proxmoxmcp/clusters.json
pct push 616 tokens.json          /etc/proxmoxmcp/tokens.json
pct push 616 mcp-rig.secret       /etc/proxmoxmcp/mcp-rig.secret
pct push 616 pve3.token           /etc/proxmoxmcp/secrets/pve3.token
```

Then fix ownership and modes. **Do this for every credential file at once.** The
server refuses to start on any file that is group- or world-readable, and it
checks them one at a time — so getting this wrong costs you one restart per file:

```bash
pct exec 616 -- bash -lc '
    install -d -o proxmoxmcp -g proxmoxmcp -m 0700 /etc/proxmoxmcp/secrets
    chown -R proxmoxmcp:proxmoxmcp /etc/proxmoxmcp
    for f in clusters.json tokens.json mcp-rig.secret secrets/*.token; do
        [ -f "/etc/proxmoxmcp/$f" ] && chmod 0600 "/etc/proxmoxmcp/$f"
    done
'
```

All four files must be 0600 and owned by `proxmoxmcp`.

## 6. The site drop-in

The shipped unit binds `127.0.0.1` and is deliberately conservative. Site
configuration goes in a drop-in, which keeps the shipped unit replaceable.

**Why a drop-in matters:** The shipped unit carries the seccomp posture
(`SystemCallFilter`, `SystemCallErrorNumber`). Replacing it wholesale silently
loses that hardening.

**`install.sh` does NOT create `/etc/systemd/system/rust-proxmoxmcp.service.d/`**;
create it first:

```bash
pct exec 616 -- mkdir -p /etc/systemd/system/rust-proxmoxmcp.service.d
```

`/etc/systemd/system/rust-proxmoxmcp.service.d/override.conf`:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/rust-proxmoxmcp \
    --clusters-file /etc/proxmoxmcp/clusters.json \
    --tokens-file /var/lib/proxmoxmcp/tokens.json \
    --mcp-rig-secret-file /etc/proxmoxmcp/mcp-rig.secret \
    --waivers-file /etc/proxmoxmcp/waivers.json \
    --transport streamable-http \
    --host 0.0.0.0 \
    --port 30031 \
    --allow-insecure-bind \
    --allowed-host 192.0.2.10 \
    --allowed-origin http://192.0.2.10:30031 \
    --allowed-host test-twoperson-proxmox:30031 \
    --allowed-origin http://test-twoperson-proxmox:30031 \
    --audit-format json \
    --audit-log-file /var/lib/proxmoxmcp/audit.jsonl \
    --audit-journald
```

The empty `ExecStart=` is required: it clears the shipped one before setting a
new one.

**For lab mode, add `--lab-mode` to the `ExecStart` line.** That single flag is
the whole difference between the two rigs.

Point `--allowed-host` and `--allowed-origin` at that rig's own address — both
must move in lockstep, and an off-loopback listener requires both or the service
refuses to start. They must track whatever clients actually dial, or requests
are refused with 421.

Then:

```bash
pct exec 616 -- bash -lc 'systemctl daemon-reload && systemctl enable --now rust-proxmoxmcp.service'
```

## 7. Verify

Check the four things that actually matter:

```bash
# 1. it is running the version you think
pct exec 616 -- /usr/local/bin/rust-proxmoxmcp --version

# 2. the seccomp posture comes from the SHIPPED unit, not a local patch
pct exec 616 -- systemctl show rust-proxmoxmcp.service -p SystemCallErrorNumber --value   # 1 (EPERM)
pct exec 616 -- grep -l SystemCallErrorNumber /etc/systemd/system/rust-proxmoxmcp.service

# 3. the filter is actually installed, read from the kernel rather than systemd
pid=$(pct exec 616 -- systemctl show -p MainPID --value rust-proxmoxmcp.service)
pct exec 616 -- grep -E '^Seccomp' /proc/$pid/status                                      # Seccomp: 2

# 4. it is serving, and refusing unauthenticated callers
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://192.0.2.10:30031/mcp \
     -H 'content-type: application/json' -d '{}'                                          # 401
```

`401` is the success case here: the transport is up and authentication is being
enforced. A `000` means nothing is listening on that address or port.

### Why the `SystemCallErrorNumber` check matters for this server

**Before v0.9.1, this server shipped NO `SystemCallErrorNumber` directive**, so a
denied syscall raised SIGSYS and killed the process mid-request instead of
returning `EPERM`. v0.9.1 is the release that fixes it, and reading it back from
the unit is how you prove the fix is present.

Checking it matters for every mecmcp-family server, but for `rust-proxmoxmcp`
this check is also how you know you are running 0.9.1 or later.

The installer reports `egress filter: NOT ENFORCED` in unprivileged LXC. That is
expected and true — systemd cannot enforce `IPAddressDeny` in an unprivileged
container, and the installer says so. It is not a fault.

## 8. Final step: stop the rig

Test rigs are stopped by default. They are started only when needed, and stopped
again at completion. Use `pct shutdown` rather than `pct stop` — a hard stop can
interrupt a state write and leave an operation unreconciled.

```bash
pct shutdown 616
```

## Rebuilding an existing rig

Back the credentials out **before** destroying anything. `pct mount` reads a
stopped container's filesystem without starting it:

```bash
pct mount 616
cp -a /var/lib/lxc/616/rootfs/etc/proxmoxmcp        /root/backup-616/
cp -a /var/lib/lxc/616/rootfs/etc/systemd/system/rust-proxmoxmcp.service.d /root/backup-616/
pct config 616 > /root/backup-616/pct-config.txt
pct unmount 616
```

`pct-config.txt` is worth keeping: it is the network, resources and tags you will
want to reproduce.

Restoring `tokens.json` rather than minting fresh tokens keeps existing clients
working — the secrets are hashed and cannot be recovered, so re-minting means
reconfiguring every client that talks to this rig.

## Troubleshooting

Both of these were hit during the rebuild this document is written from.

**`configuration error: file /etc/proxmoxmcp/mcp-rig.secret: No such file or directory`**  
That file was not restored. Step 5 names all four required files. Missing even
one prevents startup.

**`token file /etc/proxmoxmcp/tokens.json: No such file or directory`**  
Even though `tokens.json` existed at `/var/lib/proxmoxmcp/tokens.json`, the
drop-in's `--tokens-file` points at `/etc/proxmoxmcp/`. Read the drop-in first
to learn where each file is expected, rather than assuming a default location.

**`non-loopback bind '0.0.0.0' requires at least one --allowed-origin`**  
An off-loopback listener must supply both `--allowed-host` and `--allowed-origin`.
Add an `--allowed-origin` line for each `--allowed-host`, using the full URL
including scheme and port (e.g., `http://192.0.2.10:30031`). The service refuses
to start without it.

**Service active but every call returns 421**  
`--allowed-host` does not match the address clients dial. Add the exact host and
port they use.
