#!/bin/sh
# POSIX shell installer for rust-proxmoxmcp on Debian 13 LXC.
set -eu

# Refuse if not root
if [ "$(id -u)" -ne 0 ]; then
    echo "error: this installer must run as root" >&2
    exit 1
fi

# Refuse if not Debian 13
if [ ! -f /etc/os-release ]; then
    echo "error: /etc/os-release not found; cannot verify OS" >&2
    exit 1
fi

# shellcheck disable=SC1091
. /etc/os-release

if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "13" ]; then
    echo "error: this installer requires Debian 13 (detected: ${ID:-unknown} ${VERSION_ID:-unknown})" >&2
    exit 1
fi

echo "==> Installing rust-proxmoxmcp"

# Install runtime dependencies
echo "    Installing runtime dependencies..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates
apt-get clean
rm -rf /var/lib/apt/lists/*

# Create service user and directories via systemd
if [ ! -f packaging/systemd/rust-proxmoxmcp.sysusers ]; then
    echo "error: packaging/systemd/rust-proxmoxmcp.sysusers not found" >&2
    exit 1
fi
if [ ! -f packaging/systemd/rust-proxmoxmcp.tmpfiles ]; then
    echo "error: packaging/systemd/rust-proxmoxmcp.tmpfiles not found" >&2
    exit 1
fi

echo "    Creating proxmoxmcp system user..."
systemd-sysusers packaging/systemd/rust-proxmoxmcp.sysusers

echo "    Creating directories..."
systemd-tmpfiles --create packaging/systemd/rust-proxmoxmcp.tmpfiles

# Install the binary
if [ ! -f rust-proxmoxmcp ]; then
    echo "error: rust-proxmoxmcp binary not found in current directory" >&2
    exit 1
fi
echo "    Installing binary to /usr/local/bin/rust-proxmoxmcp..."
install -m 0755 -o root -g root rust-proxmoxmcp /usr/local/bin/rust-proxmoxmcp

# /etc/proxmoxmcp and secrets directory already created by tmpfiles

# Install example config files only if absent
if [ ! -f /etc/proxmoxmcp/clusters.json ]; then
    echo "    Installing example clusters.json..."
    if [ -f packaging/examples/clusters.example.json ]; then
        install -m 0600 -o proxmoxmcp -g proxmoxmcp packaging/examples/clusters.example.json /etc/proxmoxmcp/clusters.json
    else
        echo "    warning: packaging/examples/clusters.example.json not found; skipping" >&2
    fi
else
    echo "    /etc/proxmoxmcp/clusters.json exists; not overwriting"
fi

if [ ! -f /var/lib/proxmoxmcp/tokens.json ]; then
    echo "    Creating empty tokens.json..."
    printf '{"version":1,"tokens":[]}\n' > /var/lib/proxmoxmcp/tokens.json
    chown proxmoxmcp:proxmoxmcp /var/lib/proxmoxmcp/tokens.json
    chmod 0600 /var/lib/proxmoxmcp/tokens.json
else
    echo "    /var/lib/proxmoxmcp/tokens.json exists; not overwriting"
fi

# Generate audit HMAC key if absent. Never regenerate — a new key breaks
# verification of every prior audit record.
if [ ! -f /etc/proxmoxmcp/audit-hmac.key ]; then
    echo "    Generating audit HMAC key..."
    umask 077
    head -c 32 /dev/urandom > /etc/proxmoxmcp/audit-hmac.key
    chown proxmoxmcp:proxmoxmcp /etc/proxmoxmcp/audit-hmac.key
    chmod 0600 /etc/proxmoxmcp/audit-hmac.key
else
    echo "    /etc/proxmoxmcp/audit-hmac.key exists; preserving (never regenerate)"
fi

# Install systemd unit
if [ -f packaging/systemd/rust-proxmoxmcp.service ]; then
    echo "    Installing systemd unit..."
    install -m 0644 -o root -g root packaging/systemd/rust-proxmoxmcp.service /etc/systemd/system/rust-proxmoxmcp.service
    systemctl daemon-reload
else
    echo "    warning: packaging/systemd/rust-proxmoxmcp.service not found; skipping unit install" >&2
fi

echo ""
echo "==> Installation complete"
echo ""
echo "Next steps:"
echo "  1. Edit /etc/proxmoxmcp/clusters.json with your cluster details"
echo "  2. Write each cluster's API token secret to /etc/proxmoxmcp/secrets/<cluster>.token"
echo "     (mode 0600, owned by proxmoxmcp). Alternatively, use token_secret_env and"
echo "     create /etc/proxmoxmcp/secrets.env with KEY=value lines."
echo "  3. Mint a token, e.g.:"
echo "       rust-proxmoxmcp token add --tokens-file /var/lib/proxmoxmcp/tokens.json \\"
echo "           --name reader --devices '*' --tools '*' --guests '*' --actions read"
echo "     Omit --guests only for a token that will call cluster-scoped tools alone;"
echo "     without it the token cannot address individual guests."
echo "  4. (Optional) Configure TLS certificates at /etc/proxmoxmcp/tls/{fullchain,privkey}.pem"
echo "  5. Start the service: systemctl start rust-proxmoxmcp"
echo "  6. Enable on boot: systemctl enable rust-proxmoxmcp"
echo ""
echo "IMPORTANT: Before upgrading, snapshot this container in Proxmox."
echo "           A failed upgrade can be reverted by rolling back to the snapshot."
echo ""
