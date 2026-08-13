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

# Create service user if absent
if ! id proxmoxmcp >/dev/null 2>&1; then
    echo "    Creating proxmoxmcp system user..."
    useradd --system --home-dir /var/lib/proxmoxmcp --create-home --shell /usr/sbin/nologin proxmoxmcp
else
    echo "    User proxmoxmcp already exists"
fi

# Ensure /var/lib/proxmoxmcp exists and has correct ownership
if [ ! -d /var/lib/proxmoxmcp ]; then
    mkdir -p /var/lib/proxmoxmcp
fi
chown proxmoxmcp:proxmoxmcp /var/lib/proxmoxmcp
chmod 750 /var/lib/proxmoxmcp

# Install the binary
if [ ! -f rust-proxmoxmcp ]; then
    echo "error: rust-proxmoxmcp binary not found in current directory" >&2
    exit 1
fi
echo "    Installing binary to /usr/local/bin/rust-proxmoxmcp..."
install -m 0755 -o root -g root rust-proxmoxmcp /usr/local/bin/rust-proxmoxmcp

# Create /etc/proxmoxmcp and secrets directory
mkdir -p /etc/proxmoxmcp
if [ ! -d /etc/proxmoxmcp/secrets ]; then
    echo "    Creating /etc/proxmoxmcp/secrets/..."
    mkdir -p /etc/proxmoxmcp/secrets
    chown proxmoxmcp:proxmoxmcp /etc/proxmoxmcp/secrets
    chmod 0700 /etc/proxmoxmcp/secrets
else
    echo "    /etc/proxmoxmcp/secrets/ exists"
fi

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

if [ ! -f /etc/proxmoxmcp/tokens.json ]; then
    echo "    Creating empty tokens.json..."
    printf '{"version":1,"tokens":{}}\n' > /etc/proxmoxmcp/tokens.json
    chown proxmoxmcp:proxmoxmcp /etc/proxmoxmcp/tokens.json
    chmod 0600 /etc/proxmoxmcp/tokens.json
else
    echo "    /etc/proxmoxmcp/tokens.json exists; not overwriting"
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
echo "  3. Mint a token with: rust-proxmoxmcp token add <name>"
echo "  4. (Optional) Configure TLS certificates at /etc/proxmoxmcp/tls/{fullchain,privkey}.pem"
echo "  5. Start the service: systemctl start rust-proxmoxmcp"
echo "  6. Enable on boot: systemctl enable rust-proxmoxmcp"
echo ""
echo "IMPORTANT: Before upgrading, snapshot this container in Proxmox."
echo "           A failed upgrade can be reverted by rolling back to the snapshot."
echo ""
