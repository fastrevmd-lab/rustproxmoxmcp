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
  "clusters": [
    {
      "name": "homelab",
      "api_host": "pve3.mechub.org",
      "port": 8006,
      "verify_tls": true,
      "token_name": "rust-proxmoxmcp@pve!ci",
      "token_secret_file": "/etc/proxmoxmcp/secrets/homelab.token"
    }
  ]
}
```

`tokens.json` — initially empty. Tokens are minted with `rust-proxmoxmcp token
add` once the server is running:

```json
{"version":1,"tokens":[]}
```

`secrets/homelab.token` — the API token secret for the cluster (plain text):

```
12345678-1234-1234-1234-123456789abc
```

## 2. Build or pull the image

Pull a published release:

```bash
docker pull ghcr.io/fastrevmd-lab/rust-proxmoxmcp:0.9.1
```

Or build from the working tree:

```bash
docker build -t rust-proxmoxmcp:local .
```

## 3. Run it — two-person mode

The image's `ENTRYPOINT` presets `--clusters-file` and `--tokens-file` so they
cannot be lost on override. The `CMD` carries the defaults for `--transport`,
`--host`, and `--port` — operators replace `CMD` to expose the container, add
TLS, or change the mode. Docker replaces `CMD` wholesale when you pass
arguments, so just supply the flags you want; do not re-pass `--clusters-file`
or `--tokens-file` unless you need different paths.

When building your own deployment command from these examples, it is safer to
specify the image by digest rather than tag. Resolve it once with:

```bash
image=$(docker inspect ghcr.io/fastrevmd-lab/rust-proxmoxmcp:0.9.1 \
    --format '{{index .RepoDigests 0}}')
```

The resolved digest should be recorded wherever the deployment is tracked, since
that value identifies the exact bytes. On subsequent runs, use the recorded
digest directly (`image=ghcr.io/...@sha256:<recorded digest>`) or compare the
freshly resolved one against it and stop on mismatch — re-resolving the tag runs
whatever that tag points at today, which may be different bytes.

```bash
docker run -d --name proxmox-twoperson \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30033:30031 \
  -v "$PWD/clusters.json:/etc/proxmoxmcp/clusters.json:ro" \
  -v "$PWD/tokens.json:/var/lib/proxmoxmcp/tokens.json:ro" \
  -v "$PWD/secrets:/etc/proxmoxmcp/secrets:ro" \
  "$image" \
  --transport streamable-http --host 0.0.0.0 --port 30031 \
  --allow-insecure-bind \
  --allowed-host 127.0.0.1:30033 --allowed-host localhost:30033 \
  --allowed-origin http://127.0.0.1:30033 --allowed-origin http://localhost:30033
```

The `-p 127.0.0.1:30033:30031` publish binds only to loopback on the host.
Reaching this server from another host requires BOTH a non-loopback publish
(`-p 30033:30031` or `-p 0.0.0.0:30033:30031`) AND TLS with the allow-lists
updated to the externally dialled authority, or a TLS-terminating reverse proxy
in front of the loopback endpoint — Host and Origin header validation is not a
network boundary.

Configuration files are mounted read-only. No state directory is mounted because
this server persists change-set state only — there are no leases or staged
transfers like the Junos server has.

## 4. Run it — lab mode

Identical but for `--lab-mode`, and a different published port so both can run
side by side. Use the same `$image` variable captured above:

```bash
docker run -d --name proxmox-labmode \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30043:30031 \
  -v "$PWD/clusters.json:/etc/proxmoxmcp/clusters.json:ro" \
  -v "$PWD/tokens.json:/var/lib/proxmoxmcp/tokens.json:ro" \
  -v "$PWD/secrets:/etc/proxmoxmcp/secrets:ro" \
  "$image" \
  --transport streamable-http --host 0.0.0.0 --port 30031 \
  --allow-insecure-bind \
  --allowed-host 127.0.0.1:30043 --allowed-host localhost:30043 \
  --allowed-origin http://127.0.0.1:30043 --allowed-origin http://localhost:30043 \
  --lab-mode
```

## 5. Mint a token

Run `token add` inside the container to create an MCP bearer token:

```bash
docker exec proxmox-twoperson rust-proxmoxmcp token add \
  --tokens-file /var/lib/proxmoxmcp/tokens.json \
  --scopes tools=all,devices=all \
  my-session
```

The token is printed once and cannot be recovered. Record it in your MCP client
config immediately. The tool cannot overwrite the tokens file by default because
the server is hardened with `ProtectSystem=strict`, so the mounted
`tokens.json` must be writable by the container user (UID 65532 or your own
UID if you passed `--user`).

Alternatively, run the `token add` command on the host with a copy of the
tokens file, merge the result back, and restart the container. This is the safer
path when the container is already serving.

## 6. Register the MCP server

Add the server to your MCP client (Claude Desktop, Zed, etc.) with the
streamable-http transport:

```json
{
  "mcpServers": {
    "proxmox": {
      "transport": {
        "type": "streamable-http",
        "url": "http://127.0.0.1:30033/mcp",
        "headers": {
          "Authorization": "Bearer <token-from-step-5>"
        }
      }
    }
  }
}
```

Restart the client to load the server. The tools list appears under
`mcp__prod-labmode-proxmox__*`.

## 7. Verify it responds

```bash
curl -H "Authorization: Bearer <your-token>" \
  http://127.0.0.1:30033/health
```

Expected response: `{"status":"ok"}`. If this returns 421, the `--allowed-host`
value does not match the Host header your client sends — see
[Troubleshooting](#troubleshooting) below.

## 8. Stop and remove containers

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

**`token file /etc/proxmoxmcp/tokens.json: No such file or directory`**
The tokens file is mounted to the wrong path. The current canonical location
since #22 is `/var/lib/proxmoxmcp/tokens.json`, which is what the image presets
via `ENTRYPOINT` and what the systemd unit uses. Some older deployments or
documentation may reference `/etc/proxmoxmcp/tokens.json`. The install script
handles migration from the old path with a fallback and warning. Check your
mount and either update it to `/var/lib/proxmoxmcp/tokens.json` or pass
`--tokens-file /etc/proxmoxmcp/tokens.json` explicitly if you need the old path.

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

**`Error: loading /etc/proxmoxmcp/clusters.json` with `No such file or directory`**
The mount path does not match where the binary expects to read from. The image
presets `--clusters-file /etc/proxmoxmcp/clusters.json`, so mount your
`clusters.json` there with `-v $PWD/clusters.json:/etc/proxmoxmcp/clusters.json:ro`,
or pass a different `--clusters-file` flag and mount to that path instead.
