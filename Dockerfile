# syntax=docker/dockerfile:1.6
# linux/amd64 manifests pinned on 2026-08-24. The published image is currently
# amd64-only; update both digests deliberately when refreshing either base.
#
# Builder version is taken from rust-toolchain.toml (currently 1.98.0). The two
# must stay in sync.
FROM rust:1.98-slim-bookworm@sha256:1469a27c125cb5a3aebfa4f4e4665d935b02fb72cc093b2c974b3d740e43f157 AS builder
WORKDIR /src

COPY . .
RUN cargo build --release --bin rust-proxmoxmcp

# Create the directory tree with the right modes and ownership, since distroless
# has no shell and cannot run groupadd/useradd/install. The distroless :nonroot
# variant already ships uid 65532, so we create the tree with explicit modes and
# then COPY it.
#
# COPY preserves source modes: 0750 for config dirs, 0700 for state.
RUN install -d -m 0750 -o 65532 -g 65532 /stage-etc/proxmoxmcp \
    && install -d -m 0700 -o 65532 -g 65532 /stage-etc/proxmoxmcp/secrets \
    && install -d -m 0700 -o 65532 -g 65532 /stage-var/lib/proxmoxmcp

# Runtime base: distroless. Possible because this server has zero Command::new
# call sites in production code (grep confirms tests-only). The server makes
# outbound HTTPS calls but does not shell out, so it needs no shell or utilities.
#
# glibc rule: builder generation must be <= runtime generation. The builder is
# bookworm (glibc 2.36) and this is debian13 (glibc 2.41), so the direction is
# safe. Moving the builder forward would require moving this first.
#
# Digest resolved on 2026-08-24 from gcr.io/distroless/cc-debian13:nonroot.
# This is newer than the 2026-08-07 digest junos/mist share; they should be
# updated to this digest to avoid drift.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:a77defd6fedbb3392b175ba8ea3d1c22be963c1597c248c3ba987ddd80bfb512
LABEL org.opencontainers.image.source="https://github.com/fastrevmd-lab/rustproxmoxmcp"
LABEL org.opencontainers.image.licenses="MIT"

# CA certificates are shipped in gcr.io/distroless/cc-* at /etc/ssl/certs. The
# binary makes outbound TLS calls (HTTPS to Proxmox API and SSDF endpoint), and
# rustls uses the system CA bundle via rustls-native-certs.
COPY --from=builder --chown=65532:65532 \
    /src/target/release/rust-proxmoxmcp /usr/local/bin/rust-proxmoxmcp
COPY --from=builder --chown=65532:65532 /stage-etc/proxmoxmcp /etc/proxmoxmcp
COPY --from=builder --chown=65532:65532 /stage-var/lib/proxmoxmcp /var/lib/proxmoxmcp

ENV RUST_LOG=info
VOLUME ["/var/lib/proxmoxmcp"]
USER 65532:65532

# HEALTHCHECK removed: distroless has no shell and no `kill` utility. Container
# orchestrators (Compose healthcheck, Kubernetes liveness probes) supervise the
# process directly via the container runtime rather than shelling out.

# Note: The shipped unit currently binds 0.0.0.0 by default, but this Dockerfile
# follows the junos model of binding 127.0.0.1. Override --host to expose the port.
ENTRYPOINT ["/usr/local/bin/rust-proxmoxmcp", \
    "--clusters-file", "/etc/proxmoxmcp/clusters.json", \
    "--tokens-file", "/var/lib/proxmoxmcp/tokens.json", \
    "--transport", "streamable-http", \
    "--host", "127.0.0.1", \
    "--port", "30031"]
