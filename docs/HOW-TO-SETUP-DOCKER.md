# How to run rust-proxmoxmcp in Docker

Runs the server as a container in either **lab mode** or **two-person** mode.
Written from a working setup built on 2026-09-07: every command here was run,
and the two failures that occurred are in [Troubleshooting](#troubleshooting)
with their exact error text.

| mode | approvals | use it for |
|---|---|---|
| **lab mode** (`--lab-mode`) | waived on creation, recorded as `approval_waiver=lab-mode` | ordinary tool work, reads, single-operator change sets |
| **two-person** (no flag) | a second principal must approve before apply | anything that must prove the approval gate holds |

The server announces lab mode at startup, as a `WARN`:

```
lab mode enabled: change sets are approved on creation with no second principal.
Records carry approval_waiver=lab-mode. Do not run this against production clusters.
```

If you see that line and did not intend it, stop and fix the flag.

## The ENTRYPOINT problem

The image's `ENTRYPOINT` already passes six arguments:

```
--clusters-file /etc/proxmoxmcp/clusters.json
--tokens-file   /var/lib/proxmoxmcp/tokens.json
--transport     streamable-http
--host          127.0.0.1
--port          30031
```

The Dockerfile comment says *"Override `--host` to expose the port."* **That is
impossible.** Docker appends your arguments to `ENTRYPOINT`, and clap rejects
duplicates:

```
error: the argument '--host <HOST>' cannot be used multiple times
```

The same applies to `--transport`. So as shipped, the container cannot be
exposed beyond loopback at all through the documented route.

This is filed as issue #85 in this repo. The working route is to replace the
entrypoint, which then obliges you to re-specify every preset flag. The examples
below do this.

## The tokens.json path inconsistency

The image presets `--tokens-file /var/lib/proxmoxmcp/tokens.json`, but this
repo's **LXC drop-in expects `/etc/proxmoxmcp/tokens.json`**. One repo, two
answers to where the token store lives. During the 2026-09-07 rig rebuild that
mismatch cost a wasted restart with `token file /etc/proxmoxmcp/tokens.json: No
such file or directory`.

Check which path your deployment uses rather than assuming. The LXC setup is
tracked in fastrevmd-lab/mecmcp#356. This document uses
`/var/lib/proxmoxmcp/tokens.json` to match the image default.

## 1. Prepare host paths

```bash
mkdir -p proxmox-docker/secrets
cd proxmox-docker
```

`clusters.json` — follows `packaging/examples/clusters.example.json`. Note it
references a **separate secret file** per cluster via `token_secret_file`:

```json
{
  "version": 1,
  "devices": {
    "pve-demo": {
      "endpoint": "https://192.0.2.10:8006",
      "token_id": "root@pam!mcp",
      "token_secret_file": "/etc/proxmoxmcp/secrets/pve-demo.token",
      "protected_vmids": [100, 101],
      "protected_tags": ["protected"]
    }
  },
  "policy": {
    "resource_cache_ttl_secs": 10
  }
}
```

**`token_secret_file` must be the in-container path**, not the host path. The
file lives at `secrets/pve-demo.token` on the host and is mounted to
`/etc/proxmoxmcp/secrets`.

Create the Proxmox API token secret file:

```bash
echo -n "your-proxmox-api-token-secret" > secrets/pve-demo.token
```

Mint a bearer token for MCP clients. The binary can do this on the host:

```bash
rust-proxmoxmcp token add --tokens-file ./tokens.json \
    --name my-client --devices '*' --tools '*'
```

The secret prints **once** and is stored hashed. Note the CLI's hint: a token
minted without `--guests` cannot use guest-addressed tools. Grant that with
`--guests '*'` or a selector (`vmid:X`, `tag:Y`, `pool:Z`).

Then lock the modes down:

```bash
chmod 0600 clusters.json tokens.json secrets/*.token
```

## 2. Ownership: two options

The container process is UID 65532 and must read the config and write the state
directory.

**For a real deployment**, give it ownership:

```bash
sudo chown -R 65532:65532 clusters.json tokens.json secrets
```

**For local testing without root**, run the container as yourself instead. The
files stay owned by you and nothing needs `sudo`:

```bash
--user "$(id -u):$(id -g)"
```

Both are shown below. The second is what the examples here were verified with.

## 3. Run it — two-person mode

Pin the image by **immutable digest**, not mutable tag. If the tag is republished,
the same documented command runs different bytes with no visible change. Obtain
the digest:

```bash
docker inspect ghcr.io/fastrevmd-lab/rust-proxmoxmcp:0.9.1 --format '{{index .RepoDigests 0}}'
# ghcr.io/fastrevmd-lab/rust-proxmoxmcp@sha256:abcd1234...
```

Then use the digest in the run command, with the version tag as a comment:

```bash
docker run -d --name proxmox-twoperson \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30033:30031 \
  --entrypoint /usr/local/bin/rust-proxmoxmcp \
  -v "$PWD/clusters.json:/etc/proxmoxmcp/clusters.json:ro" \
  -v "$PWD/tokens.json:/var/lib/proxmoxmcp/tokens.json:ro" \
  -v "$PWD/secrets:/etc/proxmoxmcp/secrets:ro" \
  ghcr.io/fastrevmd-lab/rust-proxmoxmcp@sha256:abcd1234... `# 0.9.1` \
  --clusters-file /etc/proxmoxmcp/clusters.json \
  --tokens-file /var/lib/proxmoxmcp/tokens.json \
  --transport streamable-http --host 0.0.0.0 --port 30031 \
  --allow-insecure-bind \
  --allowed-host 127.0.0.1:30033 --allowed-host localhost:30033 \
  --allowed-origin http://127.0.0.1:30033 --allowed-origin http://localhost:30033
```

The `-p 127.0.0.1:30033:30031` publish binds only to loopback on the host.
Reaching this server from another host requires TLS, not a wider publish — Host
and Origin header validation is not a network boundary.

Configuration files are mounted read-only. No state directory is mounted because
this server persists change-set state only — there are no leases or staged
transfers like the Junos server has.

## 4. Run it — lab mode

Identical but for `--lab-mode`, and a different published port so both can run
side by side. Use the same digest you obtained above:

```bash
docker run -d --name proxmox-labmode \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30043:30031 \
  --entrypoint /usr/local/bin/rust-proxmoxmcp \
  -v "$PWD/clusters.json:/etc/proxmoxmcp/clusters.json:ro" \
  -v "$PWD/tokens.json:/var/lib/proxmoxmcp/tokens.json:ro" \
  -v "$PWD/secrets:/etc/proxmoxmcp/secrets:ro" \
  ghcr.io/fastrevmd-lab/rust-proxmoxmcp@sha256:abcd1234... `# 0.9.1` \
  --clusters-file /etc/proxmoxmcp/clusters.json \
  --tokens-file /var/lib/proxmoxmcp/tokens.json \
  --transport streamable-http --host 0.0.0.0 --port 30031 \
  --allow-insecure-bind \
  --allowed-host 127.0.0.1:30043 --allowed-host localhost:30043 \
  --allowed-origin http://127.0.0.1:30043 --allowed-origin http://localhost:30043 \
  --lab-mode
```

**Note the port asymmetry, because it catches people.** The server always
listens on `30031` *inside* the container; `-p 30043:30031` publishes it as
30043 on the host. But `--allowed-host` and `--allowed-origin` are matched
against the `Host` and `Origin` headers the **client** sends, and the client is
talking to 30043. So those flags carry the *published* port, not the internal
one. Get this wrong and the server starts cleanly and then refuses every request
with `421`.

Lab mode waives approval on creation and records `approval_waiver=lab-mode`.
Never point it at a production cluster.

## 5. Verify

```bash
docker ps --filter name=proxmox- --format '{{.Names}} {{.Status}}'

curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30033/mcp \
     -H 'content-type: application/json' -d '{}'    # 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30043/mcp \
     -H 'content-type: application/json' -d '{}'    # 401
```

**`401` is the success case**: the transport is up and authentication is being
enforced. `000` means nothing is listening — check `docker logs`. A `421` means
the allow-lists do not match the address the client used.

Confirm the mode is what you intended:

```bash
docker logs proxmox-labmode 2>&1 | grep -i 'lab mode'
```

## 6. Stop

```bash
docker stop proxmox-twoperson proxmox-labmode
docker rm proxmox-twoperson proxmox-labmode
```

`docker stop` sends SIGTERM and waits, which lets the server finish in-flight
work and flush its state. Avoid `docker kill` for anything holding change-set
state: a process killed mid-write leaves an operation non-terminal, and the next
caller finds the guest blocked.

## Troubleshooting

All of these were hit while writing this document or during the 2026-09-07 rig
rebuild.

**`error: the argument '--host <HOST>' cannot be used multiple times`**
You tried to pass `--host` or `--transport` to the container without replacing
the `ENTRYPOINT`. The image presets both flags, and clap rejects duplicates.
Add `--entrypoint /usr/local/bin/rust-proxmoxmcp` before the image name and
re-specify all six preset arguments as shown above.

**`token file /etc/proxmoxmcp/tokens.json: No such file or directory`**
The tokens file is mounted to the wrong path. The image expects
`/var/lib/proxmoxmcp/tokens.json` by default, but some deployments use
`/etc/proxmoxmcp/tokens.json`. Check which path your `--tokens-file` flag
points to and mount the file there. This inconsistency is tracked in
fastrevmd-lab/mecmcp#356.

**`421` on every request after the server starts cleanly**
The `--allowed-host` and `--allowed-origin` values do not match the address
the client is using. These flags match against the headers the **client**
sends, not the internal listen address. If the container publishes
`-p 30043:30031`, the client talks to 30043 on the host, so the allow-lists
must carry 30043. Check `docker logs` for the exact header values the server
received.

**Permission denied reading the inventory or writing state** — the container
process is UID 65532 and does not own your files. Either `chown -R 65532:65532`
them, or run with `--user "$(id -u):$(id -g)"` as shown above.

**Container exits immediately with no log output** — check `docker logs` on the
stopped container: `docker ps -a --filter name=proxmox-`. Startup validation
failures print and exit before the transport is up, so the container is gone by
the time you look for it with plain `docker ps`.
