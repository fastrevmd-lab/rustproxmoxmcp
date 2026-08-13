# rustproxmoxmcp 0.1 — Read Spine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single Rust MCP server that serves the Proxmox VE read surface across many clusters, behind bearer auth with per-token cluster and guest scoping, with the protection guardrail and `AuthorizedGuest` authorization spine already in place and enforced.

**Architecture:** Two crates — `rust-proxmoxmcp-core` (vendor logic, no MCP) and `rust-proxmoxmcp` (binary, MCP handlers, transport). Reads are declared as catalog data and served by one generic executor over `mecmcp-http`; the authorization spine that 0.2–0.5 depend on is built in full now, so the mutating tiers land later as code that cannot bypass it. Two-stage authorization: cluster and tool in the preflight (zero I/O), guest selector and protection after resolution behind an unconstructable `AuthorizedGuest`.

**Tech Stack:** Rust 1.97 toolchain / MSRV 1.88 / edition 2024, `rmcp` 3, `axum` 0.8, `tokio`, `reqwest` 0.13 via `mecmcp-http`, `wiremock` for tests, `mecmcp` 0.8.8 crates from git.

**Spec:** `docs/superpowers/specs/2026-08-12-rustproxmoxmcp-design.md`

## Global Constraints

- **`mecmcp` is read-only.** Consume at pinned `version = "0.8.8"` with `tag = "v0.8.8"`. Never edit `~/Projects/mecmcp`. A genuine gap becomes an issue on `fastrevmd-lab/mecmcp` and is designed around in the consumer.
- **Edition 2024, `rust-version = "1.88"`, toolchain `1.97.0`** — matches the rest of the family.
- **`unsafe_code = "forbid"`, `missing_docs = "warn"`, `clippy::all = "warn"`, `dbg_macro = "deny"`, `todo = "deny"`, `unwrap_used = "warn"`** in `[workspace.lints]`. `unwrap` and `expect` are forbidden in non-test code.
- **Repo name `rustproxmoxmcp`; crate and binary names take dashes** — `rust-proxmoxmcp`, `rust-proxmoxmcp-core`.
- **No flag that does nothing.** `--lab-mode` and `--waivers-file` belong to 0.3 and must not appear in 0.1. A flag present but ignored is worse than one absent, because the operator cannot tell.
- **No `add_cluster` tool, no `grant_waiver` tool, ever.** Inventory and waivers are root-plus-SIGHUP operations.
- **`WRITE_TOOLS` is declared complete in 0.1**, listing every `low` and `destructive` tool from spec §4.3 even though none are registered yet. `ScopeSet::allows_tool` excludes `write_tools` from the tool wildcard, so the registry is the only thing standing between a `"tools": ["*"]` token and write authority the day 0.2 lands.
- **Unix-only.** `mecmcp-secret` refuses to compile elsewhere by design.
- Every task ends with a passing `cargo test --workspace` and `cargo clippy --all-targets -- -D warnings`.

---

## File Structure

```
Cargo.toml                                    workspace, pinned mecmcp deps
rust-toolchain.toml                           1.97.0
deny.toml                                     cargo-deny config
crates/rust-proxmoxmcp-core/
  src/lib.rs                                  re-exports, crate docs
  src/error.rs                                ProxmoxError, HTTP+API error mapping
  src/inventory.rs                            Cluster, ClusterPolicy, ClusterInventory
  src/client.rs                               ProxmoxClient: one per cluster, over mecmcp-http
  src/resolve.rs                              ResolvedGuest, GuestIndex TTL cache, authorize()
  src/selector.rs                             Selector parse + match against ResolvedGuest
  src/grant.rs                                ProxmoxGrant (impl mecmcp_auth::Grant), ProxmoxAction
  src/protect.rs                              protection resolution, Protection verdict
  src/tier.rs                                 Tier, tier_of(tool)
  src/catalog.rs                              read tool catalog: name, method, path, targets, tier
  src/authorized.rs                           AuthorizedGuest (no public constructor)
crates/rust-proxmoxmcp/
  src/main.rs                                 CLI, wiring, SIGHUP reload, serve
  src/cli.rs                                  ProxmoxCli flattening mecmcp_runtime::cli::Cli
  src/http_transport.rs                       boundary assembly, preflight configuration
  src/server/mod.rs                           ServerHandler, KNOWN_TOOLS, WRITE_TOOLS, tool_router
  src/server/cluster.rs                       cluster/node-scoped read tools
  src/server/guest.rs                         guest-scoped read tools
  tests/common/mod.rs                          wiremock Proxmox fixture builder
  tests/read_surface.rs                       end-to-end via mecmcp_transport::test_client
  tests/authorization.rs                       adversarial suite
packaging/lxc/install.sh                      Debian 13 installer
packaging/systemd/rust-proxmoxmcp.service     hardened unit
```

Files that change together live together: the authorization spine (`selector`, `grant`, `protect`, `resolve`, `authorized`) is five small focused files rather than one `auth.rs`, because each has a distinct test surface and the protection truth table alone justifies its own module.

---

### Task 1: Workspace scaffold

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `deny.toml`
- Create: `crates/rust-proxmoxmcp-core/Cargo.toml`, `crates/rust-proxmoxmcp-core/src/lib.rs`
- Create: `crates/rust-proxmoxmcp/Cargo.toml`, `crates/rust-proxmoxmcp/src/main.rs`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: a two-crate workspace that compiles; crate names `rust-proxmoxmcp-core` and `rust-proxmoxmcp`.

- [ ] **Step 1: Write the workspace manifest**

`Cargo.toml`:

```toml
[workspace]
members  = ["crates/rust-proxmoxmcp-core", "crates/rust-proxmoxmcp"]
resolver = "2"

[workspace.package]
version      = "0.1.0"
edition      = "2024"
rust-version = "1.88"
license      = "MIT"
repository   = "https://github.com/fastrevmd-lab/rustproxmoxmcp"
authors      = ["fastrevmd-lab"]

[workspace.lints.rust]
missing_docs = "warn"
unsafe_code  = "forbid"

[workspace.lints.clippy]
all         = { level = "warn", priority = -1 }
dbg_macro   = "deny"
todo        = "deny"
unwrap_used = "warn"

[workspace.dependencies]
anyhow      = "1"
async-trait = "0.1"
axum        = "0.8"
axum-server = { version = "0.8", default-features = false, features = ["tls-rustls-no-provider"] }
chrono      = { version = "0.4", default-features = false, features = ["serde", "clock"] }
clap        = { version = "4", features = ["derive"] }
http        = "1"
rmcp        = { version = "3", features = ["server", "transport-io", "transport-streamable-http-server", "transport-streamable-http-server-session"] }
rustls      = { version = "0.23", default-features = false, features = ["aws-lc-rs", "std", "tls12", "logging"] }
schemars    = "1"
serde       = { version = "1", features = ["derive"] }
serde_json  = "1"
sha2        = "0.11"
thiserror   = "2"
tokio       = { version = "1", features = ["macros", "rt-multi-thread", "signal", "sync", "time"] }
tokio-util  = { version = "0.7", default-features = false, features = ["rt"] }
tracing     = "0.1"
url         = "2"

# Test-only
wiremock    = "0.6"

# mecmcp is consumed read-only at an exact pinned version. Do not relax the tag.
mecmcp-audit     = { version = "0.8.8", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.8.8" }
mecmcp-auth      = { version = "0.8.8", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.8.8" }
mecmcp-http      = { version = "0.8.8", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.8.8" }
mecmcp-inventory = { version = "0.8.8", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.8.8" }
mecmcp-openapi   = { version = "0.8.8", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.8.8" }
mecmcp-runtime   = { version = "0.8.8", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.8.8" }
mecmcp-secret    = { version = "0.8.8", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.8.8" }
mecmcp-server    = { version = "0.8.8", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.8.8" }
mecmcp-transport = { version = "0.8.8", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "v0.8.8" }
```

`rust-toolchain.toml`:

```toml
# Match the toolchain the rest of the mechub Rust MCP family builds with.
# MSRV is declared separately in Cargo.toml; this is the build toolchain.
[toolchain]
channel    = "1.97.0"
profile    = "minimal"
components = ["rustfmt", "clippy"]
```

`deny.toml`:

```toml
[advisories]
version = 2
yanked  = "deny"

[licenses]
version = 2
allow   = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-3.0", "Zlib", "MPL-2.0"]

[bans]
multiple-versions = "warn"
wildcards         = "deny"
```

- [ ] **Step 2: Write the core crate manifest and lib root**

`crates/rust-proxmoxmcp-core/Cargo.toml`:

```toml
[package]
name         = "rust-proxmoxmcp-core"
version.workspace      = true
edition.workspace      = true
rust-version.workspace = true
license.workspace      = true
repository.workspace   = true
authors.workspace      = true
description  = "Proxmox VE domain logic for rust-proxmoxmcp: inventory, resolution, authorization, catalog."

[dependencies]
chrono           = { workspace = true }
mecmcp-auth      = { workspace = true }
mecmcp-http      = { workspace = true }
mecmcp-inventory = { workspace = true }
mecmcp-openapi   = { workspace = true }
mecmcp-secret    = { workspace = true }
serde            = { workspace = true }
serde_json       = { workspace = true }
sha2             = { workspace = true }
thiserror        = { workspace = true }
tokio            = { workspace = true }
tracing          = { workspace = true }

[dev-dependencies]
tokio    = { workspace = true, features = ["macros", "rt-multi-thread", "time", "test-util"] }
wiremock = { workspace = true }

[lints]
workspace = true
```

`crates/rust-proxmoxmcp-core/src/lib.rs`:

```rust
//! Proxmox VE domain logic for `rust-proxmoxmcp`.
//!
//! This crate holds everything vendor-shaped and nothing MCP-shaped: cluster
//! inventory, guest resolution, the authorization spine, and the read catalog.
//! The binary crate owns transport, tool registration, and CLI.
//!
//! # The authorization spine
//!
//! Proxmox has no candidate configuration, so change control keys on the
//! identity of the target rather than on a config diff. Every mutating API in
//! this crate takes an [`AuthorizedGuest`], a type with no public constructor
//! produced only by [`resolve::authorize`]. A caller that skips authorization
//! does not compile.

pub mod authorized;
pub mod catalog;
pub mod client;
pub mod error;
pub mod grant;
pub mod inventory;
pub mod protect;
pub mod resolve;
pub mod selector;
pub mod tier;

pub use authorized::AuthorizedGuest;
pub use error::ProxmoxError;
pub use grant::{ProxmoxAction, ProxmoxGrant};
pub use inventory::{Cluster, ClusterInventory, ClusterPolicy};
pub use resolve::ResolvedGuest;
pub use selector::Selector;
pub use tier::Tier;
```

Create each listed module as an empty file with a `//!` doc line so the crate compiles; later tasks fill them.

- [ ] **Step 3: Write the binary crate manifest and a placeholder main**

`crates/rust-proxmoxmcp/Cargo.toml`:

```toml
[package]
name         = "rust-proxmoxmcp"
version.workspace      = true
edition.workspace      = true
rust-version.workspace = true
license.workspace      = true
repository.workspace   = true
authors.workspace      = true
description  = "One MCP server for many Proxmox VE clusters."

[[bin]]
name = "rust-proxmoxmcp"
path = "src/main.rs"

[dependencies]
anyhow           = { workspace = true }
axum             = { workspace = true }
axum-server      = { workspace = true }
clap             = { workspace = true }
http             = { workspace = true }
mecmcp-audit     = { workspace = true }
mecmcp-auth      = { workspace = true }
mecmcp-runtime   = { workspace = true }
mecmcp-server    = { workspace = true }
mecmcp-transport = { workspace = true }
rmcp             = { workspace = true }
rust-proxmoxmcp-core = { path = "../rust-proxmoxmcp-core" }
rustls           = { workspace = true }
schemars         = { workspace = true }
serde            = { workspace = true }
serde_json       = { workspace = true }
thiserror        = { workspace = true }
tokio            = { workspace = true }
tokio-util       = { workspace = true }
tracing          = { workspace = true }

[dev-dependencies]
mecmcp-transport = { workspace = true }
tokio            = { workspace = true, features = ["macros", "rt-multi-thread", "time"] }
wiremock         = { workspace = true }

[lints]
workspace = true
```

`crates/rust-proxmoxmcp/src/main.rs`:

```rust
//! One MCP server for many Proxmox VE clusters.

fn main() {
    eprintln!("rust-proxmoxmcp: not yet wired; see docs/superpowers/plans/");
}
```

- [ ] **Step 4: Verify the workspace builds**

Run: `cargo build --workspace`
Expected: success. The `mecmcp` git dependencies resolve at tag `v0.8.8`.

Run: `cargo clippy --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 5: Add build artefacts to .gitignore**

Append to `.gitignore`:

```
/target
**/*.rs.bk
Cargo.lock
```

Note: `Cargo.lock` is gitignored to match the family. This is why `mecmcp` deps pin an exact `tag` rather than a caret range — a lockfile cannot protect this repo's consumers.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml rust-toolchain.toml deny.toml crates .gitignore
git commit -m "feat: two-crate workspace pinned to mecmcp v0.8.8"
```

---

### Task 2: Typed Proxmox errors

**Files:**
- Create: `crates/rust-proxmoxmcp-core/src/error.rs`
- Test: inline `#[cfg(test)]` module in the same file

**Interfaces:**
- Consumes: `mecmcp_http::HttpError`.
- Produces: `ProxmoxError` enum with variants `Http(HttpError)`, `Api { status: u16, message: String }`, `Unauthorized`, `NotFound { what: String }`, `Malformed(String)`, `UnknownCluster(String)`; `ProxmoxError::from_response(status: u16, body: &[u8]) -> ProxmoxError`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_proxmox_error_map_to_api_variant() {
        let body = br#"{"data":null,"errors":{"vmid":"invalid format"}}"#;
        let error = ProxmoxError::from_response(400, body);
        match error {
            ProxmoxError::Api { status, message } => {
                assert_eq!(status, 400);
                assert!(message.contains("vmid"), "message was {message}");
                assert!(message.contains("invalid format"), "message was {message}");
            }
            other => panic!("expected Api, got {other:?}"),
        }
    }

    #[test]
    fn maps_401_to_unauthorized_without_echoing_body() {
        let error = ProxmoxError::from_response(401, b"authentication failure: token 'secret'");
        assert!(matches!(error, ProxmoxError::Unauthorized));
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn bounds_and_sanitises_unstructured_error_text() {
        let body = format!("x\u{0007}{}", "y".repeat(4096));
        let error = ProxmoxError::from_response(500, body.as_bytes());
        let rendered = error.to_string();
        assert!(rendered.len() <= 640, "rendered {} bytes", rendered.len());
        assert!(!rendered.contains('\u{0007}'), "control byte survived");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rust-proxmoxmcp-core error::tests`
Expected: FAIL — `cannot find type ProxmoxError`.

- [ ] **Step 3: Write the implementation**

```rust
//! Typed Proxmox VE API errors.
//!
//! Proxmox answers a failure with an HTTP status and, usually, a JSON body
//! carrying an `errors` map. Both halves are peer-controlled, so neither is
//! passed through verbatim: the text is bounded and stripped of control
//! characters before it can reach a log or an MCP error message.

use mecmcp_http::HttpError;

/// Longest error detail retained from a peer-supplied body.
const MAX_DETAIL_BYTES: usize = 512;

/// A failure talking to a Proxmox VE cluster.
#[derive(Debug, thiserror::Error)]
pub enum ProxmoxError {
    /// The outbound HTTP layer refused or failed the request.
    #[error("http: {0}")]
    Http(#[from] HttpError),
    /// The cluster answered with an error status.
    #[error("proxmox api error (status {status}): {message}")]
    Api {
        /// HTTP status returned by the cluster.
        status: u16,
        /// Bounded, control-stripped detail.
        message: String,
    },
    /// The cluster rejected our credentials.
    ///
    /// Carries no body: a 401 body has been observed to echo the presented
    /// credential back, and this error is rendered into logs and MCP results.
    #[error("proxmox api rejected the configured credentials")]
    Unauthorized,
    /// The cluster has no such object.
    #[error("not found: {what}")]
    NotFound {
        /// What was looked up, in the server's own vocabulary.
        what: String,
    },
    /// A response did not have the shape the API documents.
    #[error("malformed proxmox response: {0}")]
    Malformed(String),
    /// The request named a cluster absent from the inventory.
    #[error("unknown cluster: {0}")]
    UnknownCluster(String),
}

impl ProxmoxError {
    /// Classify a non-success response.
    ///
    /// A 401 is deliberately reduced to [`ProxmoxError::Unauthorized`] with the
    /// body discarded.
    #[must_use]
    pub fn from_response(status: u16, body: &[u8]) -> Self {
        if status == 401 || status == 403 {
            return Self::Unauthorized;
        }
        Self::Api {
            status,
            message: extract_detail(body),
        }
    }
}

/// Render a peer-supplied body into bounded, inert detail.
fn extract_detail(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let detail = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|value| {
            let errors = value.get("errors")?.as_object()?;
            let mut parts: Vec<String> = errors
                .iter()
                .map(|(field, reason)| match reason.as_str() {
                    Some(reason) => format!("{field}: {reason}"),
                    None => format!("{field}: {reason}"),
                })
                .collect();
            parts.sort();
            Some(parts.join("; "))
        })
        .unwrap_or_else(|| text.into_owned());

    sanitise(&detail)
}

/// Truncate on a character boundary and drop control characters.
fn sanitise(input: &str) -> String {
    let cleaned: String = input
        .chars()
        .filter(|character| !character.is_control() || *character == ' ')
        .collect();
    let mut end = MAX_DETAIL_BYTES.min(cleaned.len());
    while end > 0 && !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    cleaned[..end].to_owned()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rust-proxmoxmcp-core error::tests`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/rust-proxmoxmcp-core/src/error.rs
git commit -m "feat(core): typed Proxmox errors with bounded, inert detail"
```

---

### Task 3: Cluster inventory

**Files:**
- Create: `crates/rust-proxmoxmcp-core/src/inventory.rs`
- Test: inline `#[cfg(test)]` module plus a fixture written to `tempfile`

**Interfaces:**
- Consumes: `mecmcp_inventory::{FileInventory, Inventory, InventoryError}`, `mecmcp_secret::{OutboundSecret, SecretLimits, load_from_env, load_from_file}`.
- Produces:
  - `struct Cluster { endpoint: String, token_id: String, token_secret_env: Option<String>, token_secret_file: Option<PathBuf>, ca_pem_path: Option<PathBuf>, protected_vmids: Vec<u32>, protected_tags: Vec<String> }` — `Clone`, `Deserialize`, `#[serde(deny_unknown_fields)]`.
  - `struct ClusterPolicy { resource_cache_ttl_secs: u64 }` with `Default` (`ttl = 10`).
  - `struct ClusterInventory` wrapping `FileInventory<Cluster, ClusterPolicy>` with `load(path) -> Result<Self, InventoryError>`, `reload(&self) -> Result<usize, InventoryError>`, `names(&self) -> Vec<String>`, `get(&self, name: &str) -> Result<Cluster, ProxmoxError>`, `policy(&self) -> ClusterPolicy`.
  - `Cluster::load_secret(&self) -> Result<OutboundSecret, ProxmoxError>`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_fixture(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(contents.as_bytes()).expect("write");
        // The hardened loader requires 0600.
        std::fs::set_permissions(file.path(), std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("chmod");
        file
    }

    const FIXTURE: &str = r#"{
      "version": 1,
      "devices": {
        "pve3": {
          "endpoint": "https://pve3.example.org:8006",
          "token_id": "root@pam!mcp",
          "token_secret_env": "PVE_PVE3_TOKEN",
          "protected_vmids": [905, 907],
          "protected_tags": ["protected"]
        }
      }
    }"#;

    #[test]
    fn loads_clusters_and_exposes_names() {
        let file = write_fixture(FIXTURE);
        let inventory = ClusterInventory::load(file.path()).expect("load");
        assert_eq!(inventory.names(), vec!["pve3".to_owned()]);
    }

    #[test]
    fn resolves_a_cluster_by_name() {
        let file = write_fixture(FIXTURE);
        let inventory = ClusterInventory::load(file.path()).expect("load");
        let cluster = inventory.get("pve3").expect("cluster");
        assert_eq!(cluster.endpoint, "https://pve3.example.org:8006");
        assert_eq!(cluster.protected_vmids, vec![905, 907]);
    }

    #[test]
    fn unknown_cluster_is_a_typed_error_not_a_panic() {
        let file = write_fixture(FIXTURE);
        let inventory = ClusterInventory::load(file.path()).expect("load");
        let error = inventory.get("pve9").expect_err("should not resolve");
        assert!(matches!(error, ProxmoxError::UnknownCluster(name) if name == "pve9"));
    }

    #[test]
    fn rejects_an_unknown_field_rather_than_dropping_it() {
        let file = write_fixture(
            r#"{"version":1,"devices":{"pve3":{"endpoint":"https://a:8006",
                "token_id":"root@pam!mcp","token_secret_env":"X","verify_tls":false}}}"#,
        );
        assert!(ClusterInventory::load(file.path()).is_err());
    }

    #[test]
    fn defaults_the_resource_cache_ttl() {
        let file = write_fixture(FIXTURE);
        let inventory = ClusterInventory::load(file.path()).expect("load");
        assert_eq!(inventory.policy().resource_cache_ttl_secs, 10);
    }
}
```

Add `tempfile = "3"` to the core crate's `[dev-dependencies]`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rust-proxmoxmcp-core inventory::tests`
Expected: FAIL — `cannot find type ClusterInventory`.

- [ ] **Step 3: Write the implementation**

```rust
//! Multi-cluster inventory.
//!
//! `clusters.json` is read through `mecmcp-inventory`'s hardened loader, which
//! requires mode 0600, a regular file, and ownership by the service user. The
//! canonical envelope uses the key `devices` — the shared loader's vocabulary —
//! and this crate reads it as clusters.
//!
//! Credentials never appear in this file. Each cluster names an environment
//! variable or a separate 0600 file, loaded through `mecmcp-secret` into an
//! [`OutboundSecret`] that is zeroized on drop and implements neither `Debug`
//! nor `Serialize`.

use crate::error::ProxmoxError;
use mecmcp_inventory::{FileInventory, InventoryError};
use mecmcp_secret::{OutboundSecret, SecretLimits, load_from_env, load_from_file};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// One Proxmox VE cluster.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cluster {
    /// Base URL including scheme and port, e.g. `https://pve3.example.org:8006`.
    pub endpoint: String,
    /// API token identity in `user@realm!tokenid` form.
    pub token_id: String,
    /// Environment variable holding the token secret.
    #[serde(default)]
    pub token_secret_env: Option<String>,
    /// File holding the token secret. Mutually exclusive with the env form.
    #[serde(default)]
    pub token_secret_file: Option<PathBuf>,
    /// PEM trust anchor for this cluster's API certificate.
    ///
    /// `mecmcp-http` offers no insecure-skip-verify at any layer, so this is
    /// the only way to reach a cluster with a private CA.
    #[serde(default)]
    pub ca_pem_path: Option<PathBuf>,
    /// VMIDs protected regardless of their live tags.
    ///
    /// The durable half of the protection union: a holder of the server's own
    /// API token can clear a Proxmox tag, and cannot touch this list.
    #[serde(default)]
    pub protected_vmids: Vec<u32>,
    /// Tag names that mark a guest protected. Defaults to `["protected"]`.
    #[serde(default = "default_protected_tags")]
    pub protected_tags: Vec<String>,
}

fn default_protected_tags() -> Vec<String> {
    vec!["protected".to_owned()]
}

/// Inventory-wide settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterPolicy {
    /// How long a `/cluster/resources` snapshot may be reused.
    #[serde(default = "default_ttl")]
    pub resource_cache_ttl_secs: u64,
}

fn default_ttl() -> u64 {
    10
}

impl Default for ClusterPolicy {
    fn default() -> Self {
        Self {
            resource_cache_ttl_secs: default_ttl(),
        }
    }
}

impl Cluster {
    /// Load this cluster's API token secret.
    ///
    /// # Errors
    /// Returns [`ProxmoxError::Malformed`] when neither or both sources are
    /// configured, or when the hardened loader refuses the source.
    pub fn load_secret(&self) -> Result<OutboundSecret, ProxmoxError> {
        let limits = SecretLimits::default();
        match (&self.token_secret_env, &self.token_secret_file) {
            (Some(variable), None) => load_from_env(variable, limits)
                .map_err(|error| ProxmoxError::Malformed(error.to_string())),
            (None, Some(path)) => load_from_file(path, limits)
                .map_err(|error| ProxmoxError::Malformed(error.to_string())),
            (Some(_), Some(_)) => Err(ProxmoxError::Malformed(
                "exactly one of token_secret_env or token_secret_file must be set, not both".into(),
            )),
            (None, None) => Err(ProxmoxError::Malformed(
                "one of token_secret_env or token_secret_file must be set".into(),
            )),
        }
    }

    /// The `Authorization` header value for this cluster.
    ///
    /// Proxmox uses `PVEAPIToken=<id>=<secret>`, which is not the Bearer
    /// scheme, so this is attached with `secret_header` rather than
    /// `bearer_auth`.
    #[must_use]
    pub fn authorization_value(&self, secret: &OutboundSecret) -> String {
        format!("PVEAPIToken={}={}", self.token_id, secret.expose())
    }
}

/// The loaded cluster inventory, hot-reloadable on SIGHUP.
pub struct ClusterInventory {
    inner: FileInventory<Cluster, ClusterPolicy>,
}

impl ClusterInventory {
    /// Load `clusters.json` through the hardened loader.
    ///
    /// # Errors
    /// Returns [`InventoryError`] when the file is missing, wrongly permissioned,
    /// not a regular file, or structurally invalid.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, InventoryError> {
        Ok(Self {
            inner: FileInventory::load(path)?,
        })
    }

    /// Re-read the file in place, returning the number of clusters loaded.
    ///
    /// # Errors
    /// Returns [`InventoryError`] on any load failure. The previous contents
    /// remain in effect when a reload fails.
    pub fn reload(&self) -> Result<usize, InventoryError> {
        self.inner.reload()
    }

    /// All cluster names, in stable order.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.inner.names()
    }

    /// Resolve one cluster by exact name.
    ///
    /// # Errors
    /// Returns [`ProxmoxError::UnknownCluster`] when the name is absent.
    pub fn get(&self, name: &str) -> Result<Cluster, ProxmoxError> {
        self.inner
            .get_device(name)
            .map_err(|_| ProxmoxError::UnknownCluster(name.to_owned()))
    }

    /// Inventory-wide policy, or defaults when the file omits it.
    #[must_use]
    pub fn policy(&self) -> ClusterPolicy {
        self.inner.get_policy().unwrap_or_default()
    }
}
```

Note for the implementer: `FileInventory::names` comes from the `Inventory` trait; import `mecmcp_inventory::Inventory` if the inherent method is not present, and adjust `get_device`/`get_policy` to whichever of the inherent or trait methods the crate exposes at v0.8.8. Confirm with `cargo doc -p mecmcp-inventory --open` before writing the body; the trait doc explicitly warns that an earlier revision had inert trait methods.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rust-proxmoxmcp-core inventory::tests`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/rust-proxmoxmcp-core/src/inventory.rs crates/rust-proxmoxmcp-core/Cargo.toml
git commit -m "feat(core): cluster inventory with hardened load and separated credentials"
```

---

### Task 4: Guest selector language

**Files:**
- Create: `crates/rust-proxmoxmcp-core/src/selector.rs`
- Test: inline `#[cfg(test)]` module

**Interfaces:**
- Consumes: `crate::resolve::ResolvedGuest` — but to avoid a circular dependency during implementation, `Selector::matches` takes the fields it needs via a small `GuestFacts` borrow defined in this module and implemented for `ResolvedGuest` in Task 6.
- Produces:
  - `enum Selector { Any, Vmid(u32), VmidRange { low: u32, high: u32 }, Tag(String), Pool(String), Node(String), Type(GuestType) }`
  - `enum GuestType { Qemu, Lxc }` — `Copy`, `Eq`, `Deserialize`, `Serialize`.
  - `struct GuestFacts<'a> { vmid: u32, r#type: GuestType, node: &'a str, pool: Option<&'a str>, tags: &'a [String] }`
  - `Selector::parse(&str) -> Result<Selector, SelectorError>`
  - `Selector::matches(&self, facts: GuestFacts<'_>) -> bool`
  - `enum SelectorError { Unknown(String), BadRange(String), BadVmid(String) }`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn facts<'a>(vmid: u32, tags: &'a [String], pool: Option<&'a str>) -> GuestFacts<'a> {
        GuestFacts {
            vmid,
            r#type: GuestType::Qemu,
            node: "pve2",
            pool,
            tags,
        }
    }

    #[test]
    fn parses_every_documented_term() {
        assert_eq!(Selector::parse("*").expect("parse"), Selector::Any);
        assert_eq!(Selector::parse("vmid:905").expect("parse"), Selector::Vmid(905));
        assert_eq!(
            Selector::parse("vmid:600-699").expect("parse"),
            Selector::VmidRange { low: 600, high: 699 }
        );
        assert_eq!(
            Selector::parse("tag:ci").expect("parse"),
            Selector::Tag("ci".to_owned())
        );
        assert_eq!(
            Selector::parse("pool:lab").expect("parse"),
            Selector::Pool("lab".to_owned())
        );
        assert_eq!(
            Selector::parse("node:pve2").expect("parse"),
            Selector::Node("pve2".to_owned())
        );
        assert_eq!(
            Selector::parse("type:lxc").expect("parse"),
            Selector::Type(GuestType::Lxc)
        );
    }

    #[test]
    fn rejects_an_unknown_term_rather_than_ignoring_it() {
        let error = Selector::parse("site:emea").expect_err("should reject");
        assert!(matches!(error, SelectorError::Unknown(term) if term == "site"));
    }

    #[test]
    fn rejects_an_inverted_range() {
        assert!(matches!(
            Selector::parse("vmid:699-600"),
            Err(SelectorError::BadRange(_))
        ));
    }

    #[test]
    fn range_is_inclusive_at_both_ends() {
        let selector = Selector::parse("vmid:600-699").expect("parse");
        assert!(selector.matches(facts(600, &[], None)));
        assert!(selector.matches(facts(699, &[], None)));
        assert!(!selector.matches(facts(599, &[], None)));
        assert!(!selector.matches(facts(700, &[], None)));
    }

    #[test]
    fn tag_match_is_exact_not_substring() {
        let selector = Selector::parse("tag:ci").expect("parse");
        let protected = vec!["ci-runner".to_owned()];
        assert!(!selector.matches(facts(600, &protected, None)));
        let exact = vec!["ci".to_owned()];
        assert!(selector.matches(facts(600, &exact, None)));
    }

    #[test]
    fn a_guest_with_no_pool_never_matches_a_pool_selector() {
        let selector = Selector::parse("pool:lab").expect("parse");
        assert!(!selector.matches(facts(600, &[], None)));
        assert!(selector.matches(facts(600, &[], Some("lab"))));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rust-proxmoxmcp-core selector::tests`
Expected: FAIL — `cannot find type Selector`.

- [ ] **Step 3: Write the implementation**

```rust
//! The guest selector language used by per-token grants.
//!
//! A selector names a set of guests within a cluster. A token's grant carries a
//! list of them, and a guest is in scope when any selector matches — union, not
//! intersection, so `["vmid:600-699", "tag:ci"]` reads as "the disposable band
//! or anything tagged ci".
//!
//! Parsing rejects an unrecognised term rather than ignoring it. A selector the
//! server does not understand is a restriction the operator believes is in
//! force, so silently dropping it widens the token.

use serde::{Deserialize, Serialize};

/// Whether a guest is a virtual machine or a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuestType {
    /// A QEMU virtual machine.
    Qemu,
    /// An LXC container.
    Lxc,
}

impl GuestType {
    /// The path segment Proxmox uses for this guest type.
    #[must_use]
    pub const fn path_segment(self) -> &'static str {
        match self {
            Self::Qemu => "qemu",
            Self::Lxc => "lxc",
        }
    }
}

/// The facts a selector needs about a guest.
///
/// A borrow rather than the whole resolved guest, so this module has no
/// dependency on resolution and can be tested on its own.
#[derive(Debug, Clone, Copy)]
pub struct GuestFacts<'a> {
    /// Numeric guest id, cluster-unique.
    pub vmid: u32,
    /// VM or container.
    pub r#type: GuestType,
    /// Node the guest currently runs on.
    pub node: &'a str,
    /// Proxmox pool, when the guest is in one.
    pub pool: Option<&'a str>,
    /// Live tags.
    pub tags: &'a [String],
}

/// A malformed selector.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SelectorError {
    /// The term prefix is not one this server understands.
    #[error("unknown selector term '{0}'")]
    Unknown(String),
    /// A range was inverted, empty, or unparseable.
    #[error("invalid vmid range: {0}")]
    BadRange(String),
    /// A vmid was not a number.
    #[error("invalid vmid: {0}")]
    BadVmid(String),
}

/// One term of a guest selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// Every guest in the cluster.
    Any,
    /// Exactly this vmid.
    Vmid(u32),
    /// An inclusive vmid range.
    VmidRange {
        /// Lowest vmid in scope.
        low: u32,
        /// Highest vmid in scope.
        high: u32,
    },
    /// Any guest carrying this exact tag.
    Tag(String),
    /// Any guest in this Proxmox pool.
    Pool(String),
    /// Any guest currently on this node.
    Node(String),
    /// Any guest of this type.
    Type(GuestType),
}

impl Selector {
    /// Parse one selector term.
    ///
    /// # Errors
    /// Returns [`SelectorError`] for an unknown prefix or a malformed value.
    pub fn parse(input: &str) -> Result<Self, SelectorError> {
        if input == "*" {
            return Ok(Self::Any);
        }
        let Some((prefix, value)) = input.split_once(':') else {
            return Err(SelectorError::Unknown(input.to_owned()));
        };
        match prefix {
            "vmid" => parse_vmid_term(value),
            "tag" => Ok(Self::Tag(value.to_owned())),
            "pool" => Ok(Self::Pool(value.to_owned())),
            "node" => Ok(Self::Node(value.to_owned())),
            "type" => match value {
                "qemu" => Ok(Self::Type(GuestType::Qemu)),
                "lxc" => Ok(Self::Type(GuestType::Lxc)),
                other => Err(SelectorError::Unknown(format!("type:{other}"))),
            },
            other => Err(SelectorError::Unknown(other.to_owned())),
        }
    }

    /// Whether this selector admits the described guest.
    #[must_use]
    pub fn matches(&self, facts: GuestFacts<'_>) -> bool {
        match self {
            Self::Any => true,
            Self::Vmid(vmid) => facts.vmid == *vmid,
            Self::VmidRange { low, high } => facts.vmid >= *low && facts.vmid <= *high,
            Self::Tag(tag) => facts.tags.iter().any(|candidate| candidate == tag),
            Self::Pool(pool) => facts.pool == Some(pool.as_str()),
            Self::Node(node) => facts.node == node,
            Self::Type(kind) => facts.r#type == *kind,
        }
    }
}

/// Parse the value half of a `vmid:` term.
fn parse_vmid_term(value: &str) -> Result<Selector, SelectorError> {
    if let Some((low, high)) = value.split_once('-') {
        let low: u32 = low
            .parse()
            .map_err(|_| SelectorError::BadRange(value.to_owned()))?;
        let high: u32 = high
            .parse()
            .map_err(|_| SelectorError::BadRange(value.to_owned()))?;
        if low > high {
            return Err(SelectorError::BadRange(value.to_owned()));
        }
        return Ok(Selector::VmidRange { low, high });
    }
    value
        .parse()
        .map(Selector::Vmid)
        .map_err(|_| SelectorError::BadVmid(value.to_owned()))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rust-proxmoxmcp-core selector::tests`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/rust-proxmoxmcp-core/src/selector.rs
git commit -m "feat(core): guest selector language that rejects unknown terms"
```

---

### Task 5: `ProxmoxGrant` — the per-token vendor seam

**Files:**
- Create: `crates/rust-proxmoxmcp-core/src/grant.rs`
- Test: inline `#[cfg(test)]` module

**Interfaces:**
- Consumes: `mecmcp_auth::{Grant, GrantError}`, `crate::selector::{GuestFacts, Selector, SelectorError}`, `crate::tier::Tier` (Task 7 — declare `Tier` first if executing out of order; it is a three-variant `Copy` enum).
- Produces:
  - `enum ProxmoxAction { Read, Low, Destructive }` — `Copy`, `Eq`.
  - `struct ProxmoxGrant { guests: Vec<String>, actions: Vec<ProxmoxAction> }` — `Clone`, `Debug`, `Serialize`, `Deserialize`, `#[serde(deny_unknown_fields)]`, `impl Grant`.
  - `ProxmoxGrant::allows_guest(&self, facts: GuestFacts<'_>) -> bool` — the inherent rich check used by stage 2.
  - `ProxmoxGrant::read_only() -> Self`.

**Why the grant and not the device scope:** `CallerScopes` exposes only `devices` and `tools`, and `TargetValueShape` is `Scalar | NonEmptyArray`, so a `vmid:600-699` term cannot be evaluated in the preflight at all. `devices` therefore carries cluster names only — which `ToolScopePreflight` handles unchanged — and the guest selector lives in the grant, `mecmcp-auth`'s documented vendor seam. Guest scoping is consequently a stage-2 concern, enforced behind `AuthorizedGuest`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::selector::GuestType;
    use mecmcp_auth::Grant;

    fn facts(vmid: u32) -> GuestFacts<'static> {
        GuestFacts {
            vmid,
            r#type: GuestType::Qemu,
            node: "pve2",
            pool: None,
            tags: &[],
        }
    }

    #[test]
    fn a_band_scoped_grant_admits_only_its_band() {
        let grant = ProxmoxGrant {
            guests: vec!["vmid:600-699".to_owned()],
            actions: vec![ProxmoxAction::Read],
        };
        assert!(grant.allows_guest(facts(606)));
        assert!(!grant.allows_guest(facts(905)));
    }

    #[test]
    fn selectors_union_rather_than_intersect() {
        let grant = ProxmoxGrant {
            guests: vec!["vmid:600-699".to_owned(), "vmid:800".to_owned()],
            actions: vec![ProxmoxAction::Read],
        };
        assert!(grant.allows_guest(facts(606)));
        assert!(grant.allows_guest(facts(800)));
        assert!(!grant.allows_guest(facts(905)));
    }

    #[test]
    fn an_empty_guest_list_admits_nothing() {
        let grant = ProxmoxGrant {
            guests: Vec::new(),
            actions: vec![ProxmoxAction::Read],
        };
        assert!(!grant.allows_guest(facts(606)));
    }

    #[test]
    fn an_unparseable_selector_admits_nothing_and_fails_validation() {
        let grant = ProxmoxGrant {
            guests: vec!["site:emea".to_owned()],
            actions: vec![ProxmoxAction::Read],
        };
        assert!(!grant.allows_guest(facts(606)));
        assert!(grant.validate().is_err());
    }

    #[test]
    fn read_only_grant_permits_no_mutating_action() {
        let grant = ProxmoxGrant::read_only();
        assert!(grant.allows_action(ProxmoxAction::Read));
        assert!(!grant.allows_action(ProxmoxAction::Low));
        assert!(!grant.allows_action(ProxmoxAction::Destructive));
    }

    #[test]
    fn rejects_an_unknown_field_so_a_rewrite_cannot_silently_drop_it() {
        let error = serde_json::from_str::<ProxmoxGrant>(
            r#"{"guests":["*"],"actions":["read"],"max_targets":3}"#,
        );
        assert!(error.is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rust-proxmoxmcp-core grant::tests`
Expected: FAIL — `cannot find type ProxmoxGrant`.

- [ ] **Step 3: Write the implementation**

```rust
//! Per-token write authority and guest scope.
//!
//! `mecmcp-auth` calls this the vendor seam: the shared crate stores the grant
//! and never interprets it. Two things live here that the shared scope model
//! cannot express — the guest selector, because `CallerScopes` carries only
//! opaque name sets and has no numeric-range shape, and the action tier.
//!
//! An unparseable selector admits nothing. A restriction the server cannot
//! understand must not become an absence of restriction.

use crate::selector::{GuestFacts, Selector};
use mecmcp_auth::{Grant, GrantError};
use serde::{Deserialize, Serialize};

/// The mutating action tiers this server distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxmoxAction {
    /// Observation only.
    Read,
    /// Disruptive but reversible: lifecycle, snapshot create, backup create.
    Low,
    /// Irreversible: destroy, restore-over, rollback, shrink, delete.
    Destructive,
}

/// A token's guest scope and action authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxmoxGrant {
    /// Selector terms; a guest is in scope when any term matches.
    pub guests: Vec<String>,
    /// Action tiers this token may invoke.
    pub actions: Vec<ProxmoxAction>,
}

impl ProxmoxGrant {
    /// A grant that sees everything and may change nothing.
    #[must_use]
    pub fn read_only() -> Self {
        Self {
            guests: vec!["*".to_owned()],
            actions: vec![ProxmoxAction::Read],
        }
    }

    /// Whether this grant admits the described guest.
    ///
    /// A term that does not parse contributes no match, so a malformed grant
    /// admits nothing rather than everything. `validate` reports the same
    /// malformation at token-store load time, which is where an operator sees it.
    #[must_use]
    pub fn allows_guest(&self, facts: GuestFacts<'_>) -> bool {
        self.guests.iter().any(|term| {
            Selector::parse(term)
                .map(|selector| selector.matches(facts))
                .unwrap_or(false)
        })
    }
}

impl Grant for ProxmoxGrant {
    type Action = ProxmoxAction;

    fn allows_action(&self, action: Self::Action) -> bool {
        self.actions.contains(&action)
    }

    fn allows_subject(&self, subject: &str) -> bool {
        // A subject here is a cluster-qualified guest address, `cluster/vmid`.
        // The rich check is `allows_guest`, which sees tags and pools; this
        // exists so the shared token store can validate and display a grant.
        subject
            .split_once('/')
            .and_then(|(_, vmid)| vmid.parse::<u32>().ok())
            .is_some_and(|vmid| {
                self.guests.iter().any(|term| {
                    matches!(
                        Selector::parse(term),
                        Ok(Selector::Any)
                            | Ok(Selector::Vmid(_))
                            | Ok(Selector::VmidRange { .. })
                    ) && Selector::parse(term).is_ok_and(|selector| {
                        matches!(selector, Selector::Any)
                            || matches!(selector, Selector::Vmid(other) if other == vmid)
                            || matches!(
                                selector,
                                Selector::VmidRange { low, high } if vmid >= low && vmid <= high
                            )
                    })
                })
            })
    }

    fn validate(&self) -> Result<(), GrantError> {
        for term in &self.guests {
            Selector::parse(term).map_err(|error| GrantError::Invalid(error.to_string()))?;
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rust-proxmoxmcp-core grant::tests`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/rust-proxmoxmcp-core/src/grant.rs
git commit -m "feat(core): ProxmoxGrant carrying guest selectors and action tiers"
```

---

### Task 6: Tier classification and the read catalog

**Files:**
- Create: `crates/rust-proxmoxmcp-core/src/tier.rs`
- Create: `crates/rust-proxmoxmcp-core/src/catalog.rs`
- Test: inline `#[cfg(test)]` modules in both

**Interfaces:**
- Consumes: `crate::grant::ProxmoxAction`.
- Produces:
  - `enum Tier { Read, Low, Destructive }` with `Tier::action(self) -> ProxmoxAction`.
  - `const WRITE_TOOLS: &[&str]` — every `low` and `destructive` tool name from spec §4.3, complete.
  - `fn tier_of(tool: &str) -> Option<Tier>`.
  - `struct ReadTool { name: &'static str, method: Method, path: &'static str, needs_guest: bool, description: &'static str }`
  - `const READ_TOOLS: &[ReadTool]`, `fn read_tool(name: &str) -> Option<&'static ReadTool>`.

- [ ] **Step 1: Write the failing tests**

`tier.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_read_tool_classifies_as_read() {
        for tool in crate::catalog::READ_TOOLS {
            assert_eq!(tier_of(tool.name), Some(Tier::Read), "tool {}", tool.name);
        }
    }

    #[test]
    fn every_write_tool_classifies_as_low_or_destructive() {
        for tool in WRITE_TOOLS {
            let tier = tier_of(tool).unwrap_or_else(|| panic!("unclassified tool {tool}"));
            assert_ne!(tier, Tier::Read, "tool {tool} classified as read");
        }
    }

    #[test]
    fn destroy_and_restore_are_destructive() {
        assert_eq!(tier_of("delete_vm"), Some(Tier::Destructive));
        assert_eq!(tier_of("delete_container"), Some(Tier::Destructive));
        assert_eq!(tier_of("restore_backup"), Some(Tier::Destructive));
        assert_eq!(tier_of("rollback_snapshot"), Some(Tier::Destructive));
    }

    #[test]
    fn stop_is_low_because_the_tier_boundary_is_data_loss_not_disruption() {
        assert_eq!(tier_of("stop_vm"), Some(Tier::Low));
    }

    #[test]
    fn no_read_tool_appears_in_the_write_registry() {
        for tool in crate::catalog::READ_TOOLS {
            assert!(
                !WRITE_TOOLS.contains(&tool.name),
                "read tool {} is in WRITE_TOOLS",
                tool.name
            );
        }
    }

    #[test]
    fn an_unknown_tool_is_unclassified_rather_than_defaulting_to_read() {
        assert_eq!(tier_of("wipe_everything"), None);
    }
}
```

`catalog.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_names_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for tool in READ_TOOLS {
            assert!(seen.insert(tool.name), "duplicate tool {}", tool.name);
        }
    }

    #[test]
    fn guest_scoped_tools_template_both_node_and_vmid() {
        for tool in READ_TOOLS.iter().filter(|tool| tool.needs_guest) {
            assert!(tool.path.contains("{node}"), "{} lacks node", tool.name);
            assert!(tool.path.contains("{vmid}"), "{} lacks vmid", tool.name);
        }
    }

    #[test]
    fn no_path_is_absolute_against_a_different_api_root() {
        for tool in READ_TOOLS {
            assert!(tool.path.starts_with("/api2/json/"), "{} path {}", tool.name, tool.path);
        }
    }

    #[test]
    fn looks_up_by_name() {
        assert!(read_tool("get_vms").is_some());
        assert!(read_tool("not_a_tool").is_none());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p rust-proxmoxmcp-core tier:: catalog::`
Expected: FAIL — `cannot find type Tier`, `cannot find value READ_TOOLS`.

- [ ] **Step 3: Write `tier.rs`**

```rust
//! Action-class tiering.
//!
//! Tier is a property of the tool, declared once here, and it selects the code
//! path. It is never a value a caller passes: a `force: true` argument is not a
//! guardrail, because a sufficiently confident caller sets it.
//!
//! `WRITE_TOOLS` is complete from release 0.1 even though releases 0.2 and 0.3
//! register the tools it names. `ScopeSet::allows_tool` excludes this registry
//! from the tool wildcard, so it is the only thing standing between a
//! `"tools": ["*"]` token and write authority the day those tools appear.

use crate::grant::ProxmoxAction;

/// Action class of a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Observation only.
    Read,
    /// Disruptive but reversible.
    Low,
    /// Irreversible.
    Destructive,
}

impl Tier {
    /// The grant action this tier requires.
    #[must_use]
    pub const fn action(self) -> ProxmoxAction {
        match self {
            Self::Read => ProxmoxAction::Read,
            Self::Low => ProxmoxAction::Low,
            Self::Destructive => ProxmoxAction::Destructive,
        }
    }
}

/// Tools excluded from a wildcard tool scope. Complete as of spec §4.3.
pub const WRITE_TOOLS: &[&str] = &[
    // low
    "clone_vm",
    "create_backup",
    "create_container",
    "create_snapshot",
    "create_vm",
    "download_iso",
    "reset_vm",
    "restart_container",
    "shutdown_vm",
    "start_container",
    "start_vm",
    "stop_container",
    "stop_vm",
    "update_container_resources",
    // low or destructive depending on direction; classified at call time
    "resize_disk",
    // destructive
    "delete_backup",
    "delete_container",
    "delete_iso",
    "delete_snapshot",
    "delete_vm",
    "restore_backup",
    "rollback_snapshot",
    // deferred to 0.5, registered here so a wildcard never reaches it
    "execute_vm_command",
];

/// Tools whose tier is `Destructive`.
const DESTRUCTIVE_TOOLS: &[&str] = &[
    "delete_backup",
    "delete_container",
    "delete_iso",
    "delete_snapshot",
    "delete_vm",
    "execute_vm_command",
    "restore_backup",
    "rollback_snapshot",
];

/// Classify a tool.
///
/// Returns `None` for a name this server does not register. An unknown tool is
/// unclassified rather than defaulted to [`Tier::Read`]; defaulting would make
/// a future tool readable by omission.
///
/// `resize_disk` reports [`Tier::Low`] here and is re-classified at call time
/// from the sign of its size argument — a shrink destroys data and a grow does
/// not. See `crate::catalog` for where that happens in release 0.2.
#[must_use]
pub fn tier_of(tool: &str) -> Option<Tier> {
    if DESTRUCTIVE_TOOLS.contains(&tool) {
        return Some(Tier::Destructive);
    }
    if WRITE_TOOLS.contains(&tool) {
        return Some(Tier::Low);
    }
    crate::catalog::read_tool(tool).map(|_| Tier::Read)
}
```

- [ ] **Step 4: Write `catalog.rs`**

```rust
//! The read surface, declared as data.
//!
//! Proxmox's read API is large and uniform, so a read tool is a catalog entry
//! rather than a function: name, HTTP method, path template, and whether it
//! addresses a specific guest. One generic executor in `crate::client` serves
//! all of them, expanding the template through `mecmcp-openapi`, which rejects
//! a parameter that would break a segment rather than sanitising it.
//!
//! Mutating tools are deliberately *not* here. Each needs preconditions a
//! catalog entry cannot express, so each is written as code that takes an
//! [`crate::AuthorizedGuest`].

use mecmcp_http::Method;

/// One read tool.
#[derive(Debug, Clone, Copy)]
pub struct ReadTool {
    /// MCP tool name.
    pub name: &'static str,
    /// HTTP method.
    pub method: Method,
    /// Path template with `{node}` and `{vmid}` placeholders.
    pub path: &'static str,
    /// Whether the tool addresses one guest and therefore needs resolution.
    pub needs_guest: bool,
    /// One-line MCP description.
    pub description: &'static str,
}

/// The complete 0.1 read surface.
pub const READ_TOOLS: &[ReadTool] = &[
    ReadTool {
        name: "get_cluster_status",
        method: Method::Get,
        path: "/api2/json/cluster/status",
        needs_guest: false,
        description: "Cluster quorum and node membership.",
    },
    ReadTool {
        name: "get_nodes",
        method: Method::Get,
        path: "/api2/json/nodes",
        needs_guest: false,
        description: "All nodes in the cluster with status and resource totals.",
    },
    ReadTool {
        name: "get_node_status",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/status",
        needs_guest: false,
        description: "Detailed status for one node.",
    },
    ReadTool {
        name: "get_vms",
        method: Method::Get,
        path: "/api2/json/cluster/resources",
        needs_guest: false,
        description: "All QEMU guests across the cluster, with node, status and tags.",
    },
    ReadTool {
        name: "get_containers",
        method: Method::Get,
        path: "/api2/json/cluster/resources",
        needs_guest: false,
        description: "All LXC guests across the cluster, with node, status and tags.",
    },
    ReadTool {
        name: "get_vm_config",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/qemu/{vmid}/config",
        needs_guest: true,
        description: "Configuration of one QEMU guest, including its Proxmox digest.",
    },
    ReadTool {
        name: "get_container_config",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/lxc/{vmid}/config",
        needs_guest: true,
        description: "Configuration of one LXC guest, including its Proxmox digest.",
    },
    ReadTool {
        name: "get_guest_status",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/{kind}/{vmid}/status/current",
        needs_guest: true,
        description: "Current runtime status of one guest.",
    },
    ReadTool {
        name: "list_snapshots",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/{kind}/{vmid}/snapshot",
        needs_guest: true,
        description: "Snapshots of one guest.",
    },
    ReadTool {
        name: "get_storage",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/storage",
        needs_guest: false,
        description: "Storage backends visible to one node, with usage.",
    },
    ReadTool {
        name: "list_backups",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/storage/{storage}/content",
        needs_guest: false,
        description: "Backup archives on one storage backend.",
    },
    ReadTool {
        name: "list_isos",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/storage/{storage}/content",
        needs_guest: false,
        description: "ISO images on one storage backend.",
    },
    ReadTool {
        name: "list_templates",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/storage/{storage}/content",
        needs_guest: false,
        description: "Container templates on one storage backend.",
    },
    ReadTool {
        name: "list_tasks",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/tasks",
        needs_guest: false,
        description: "Recent tasks on one node.",
    },
    ReadTool {
        name: "get_task_status",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/tasks/{upid}/status",
        needs_guest: false,
        description: "Status of one task by UPID.",
    },
];

/// Look up a read tool by MCP name.
#[must_use]
pub fn read_tool(name: &str) -> Option<&'static ReadTool> {
    READ_TOOLS.iter().find(|tool| tool.name == name)
}
```

Note for the implementer: confirm `mecmcp_http::Method`'s variant spelling (`Method::Get` vs `Method::GET`) with `cargo doc -p mecmcp-http` before writing, and match it.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p rust-proxmoxmcp-core tier:: catalog::`
Expected: 10 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/rust-proxmoxmcp-core/src/tier.rs crates/rust-proxmoxmcp-core/src/catalog.rs
git commit -m "feat(core): action tiers with a complete write registry, and the read catalog"
```

---

### Task 7: The Proxmox HTTP client

**Files:**
- Create: `crates/rust-proxmoxmcp-core/src/client.rs`
- Test: `crates/rust-proxmoxmcp-core/tests/client.rs` (integration, uses `wiremock`)

**Interfaces:**
- Consumes: `mecmcp_http::{HttpClient, HttpClientConfig, HttpRequest, Method}`, `mecmcp_openapi::path`, `crate::inventory::Cluster`, `crate::error::ProxmoxError`.
- Produces:
  - `struct ProxmoxClient { cluster: Cluster, http: HttpClient, authorization: String }`
  - `ProxmoxClient::new(cluster: Cluster) -> Result<Self, ProxmoxError>`
  - `ProxmoxClient::get_json(&self, path_template: &str, params: &[(&str, &str)]) -> Result<serde_json::Value, ProxmoxError>` — expands the template, sends, unwraps Proxmox's `{"data": …}` envelope.

- [ ] **Step 1: Write the failing test**

`crates/rust-proxmoxmcp-core/tests/client.rs`:

```rust
//! Integration tests for the Proxmox HTTP client against a mock cluster.

use rust_proxmoxmcp_core::{client::ProxmoxClient, error::ProxmoxError, inventory::Cluster};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A cluster pointed at the mock server.
///
/// `mecmcp-http` is HTTPS-only, so these tests run against an `https` mock via
/// `extra_root_certificates`. `MockServer::start_tls` is not available; instead
/// the test harness generates a self-signed pair with `rcgen` and serves it.
fn cluster_for(endpoint: &str, ca_pem: &std::path::Path) -> Cluster {
    Cluster {
        endpoint: endpoint.to_owned(),
        token_id: "root@pam!mcp".to_owned(),
        token_secret_env: Some("PVE_TEST_TOKEN".to_owned()),
        token_secret_file: None,
        ca_pem_path: Some(ca_pem.to_owned()),
        protected_vmids: vec![905],
        protected_tags: vec!["protected".to_owned()],
    }
}

#[tokio::test]
async fn unwraps_the_data_envelope() {
    // SAFETY OF TEST ENV: single-threaded test, variable removed at the end.
    unsafe { std::env::set_var("PVE_TEST_TOKEN", "not-a-real-secret-0123456789abcdef") };
    let (server, ca_pem) = common::tls_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api2/json/nodes"))
        .and(header("Authorization", "PVEAPIToken=root@pam!mcp=not-a-real-secret-0123456789abcdef"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            br#"{"data":[{"node":"pve2","status":"online"}]}"#.to_vec(),
            "application/json",
        ))
        .mount(&server)
        .await;

    let client = ProxmoxClient::new(cluster_for(&server.uri(), ca_pem.path())).expect("client");
    let value = client.get_json("/api2/json/nodes", &[]).await.expect("get");

    assert_eq!(value[0]["node"], "pve2");
}

#[tokio::test]
async fn expands_a_path_template_and_percent_encodes_the_value() {
    unsafe { std::env::set_var("PVE_TEST_TOKEN", "not-a-real-secret-0123456789abcdef") };
    let (server, ca_pem) = common::tls_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve2/qemu/905/config"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            br#"{"data":{"digest":"abc123","name":"vsrx-prod"}}"#.to_vec(),
            "application/json",
        ))
        .mount(&server)
        .await;

    let client = ProxmoxClient::new(cluster_for(&server.uri(), ca_pem.path())).expect("client");
    let value = client
        .get_json(
            "/api2/json/nodes/{node}/qemu/{vmid}/config",
            &[("node", "pve2"), ("vmid", "905")],
        )
        .await
        .expect("get");

    assert_eq!(value["digest"], "abc123");
}

#[tokio::test]
async fn a_path_parameter_cannot_escape_its_segment() {
    unsafe { std::env::set_var("PVE_TEST_TOKEN", "not-a-real-secret-0123456789abcdef") };
    let (server, ca_pem) = common::tls_mock_server().await;
    let client = ProxmoxClient::new(cluster_for(&server.uri(), ca_pem.path())).expect("client");

    let error = client
        .get_json(
            "/api2/json/nodes/{node}/status",
            &[("node", "pve2/../../access/users")],
        )
        .await
        .expect_err("segment break must be refused");

    assert!(matches!(error, ProxmoxError::Malformed(_)));
}

#[tokio::test]
async fn a_401_becomes_unauthorized_without_echoing_the_body() {
    unsafe { std::env::set_var("PVE_TEST_TOKEN", "not-a-real-secret-0123456789abcdef") };
    let (server, ca_pem) = common::tls_mock_server().await;

    Mock::given(method("GET"))
        .and(path("/api2/json/nodes"))
        .respond_with(ResponseTemplate::new(401).set_body_raw(
            b"authentication failure: token not-a-real-secret-0123456789abcdef".to_vec(),
            "text/plain",
        ))
        .mount(&server)
        .await;

    let client = ProxmoxClient::new(cluster_for(&server.uri(), ca_pem.path())).expect("client");
    let error = client.get_json("/api2/json/nodes", &[]).await.expect_err("401");

    assert!(matches!(error, ProxmoxError::Unauthorized));
    assert!(!error.to_string().contains("not-a-real-secret-0123456789abcdef"));
}

#[tokio::test]
async fn a_plaintext_endpoint_is_refused_at_construction() {
    unsafe { std::env::set_var("PVE_TEST_TOKEN", "not-a-real-secret-0123456789abcdef") };
    let (_, ca_pem) = common::tls_mock_server().await;
    let mut cluster = cluster_for("http://pve3.example.org:8006", ca_pem.path());
    cluster.ca_pem_path = None;

    assert!(ProxmoxClient::new(cluster).is_err());
}

mod common;
```

- [ ] **Step 2: Write the TLS mock-server helper**

`crates/rust-proxmoxmcp-core/tests/common/mod.rs`:

```rust
//! Shared test fixtures.
//!
//! `mecmcp-http` rejects a plaintext URL at construction, so every client test
//! needs an HTTPS peer. `wiremock` serves plain HTTP, so this wraps it in a
//! TLS-terminating `axum-server` listener using a self-signed pair generated
//! per test, and hands back the CA PEM for `extra_root_certificates`.

use std::io::Write;
use wiremock::MockServer;

/// Start a mock server reachable over HTTPS, returning it with its CA PEM file.
pub async fn tls_mock_server() -> (MockServer, tempfile::NamedTempFile) {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate self-signed certificate");
    let cert_pem = certificate.cert.pem();
    let key_pem = certificate.signing_key.serialize_pem();

    let mut ca_file = tempfile::NamedTempFile::new().expect("temp ca file");
    ca_file
        .write_all(cert_pem.as_bytes())
        .expect("write ca pem");
    ca_file.flush().expect("flush ca pem");

    let server = MockServer::start_with_tls(cert_pem, key_pem).await;
    (server, ca_file)
}
```

If `wiremock` 0.6 has no `start_with_tls`, replace this helper with a
`hyper`-based stub server: bind a `tokio::net::TcpListener` on `127.0.0.1:0`,
wrap it with `tokio_rustls::TlsAcceptor` built from the generated pair, and
serve a fixed response per registered path. The tests above depend only on
`server.uri()` and path/header matching, so either implementation satisfies them.

Add to `[dev-dependencies]` of the core crate: `rcgen = "0.13"`, `tempfile = "3"`.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p rust-proxmoxmcp-core --test client`
Expected: FAIL — `cannot find type ProxmoxClient`.

- [ ] **Step 4: Write the implementation**

```rust
//! One hardened HTTP client per Proxmox cluster.
//!
//! Isolation between clusters is structural rather than scheduled: each cluster
//! gets its own [`HttpClient`], so `max_concurrent_requests` and
//! `max_queued_requests` bound that cluster alone and a wedged endpoint returns
//! `QueueFull` immediately instead of consuming a pool shared with healthy ones.

use crate::error::ProxmoxError;
use crate::inventory::Cluster;
use mecmcp_http::{HttpClient, HttpClientConfig, HttpRequest, Method};
use mecmcp_secret::OutboundSecret;
use std::time::Duration;

/// Requests in flight to one cluster.
const MAX_CONCURRENT: usize = 8;
/// Callers permitted to wait behind those.
const MAX_QUEUED: usize = 32;
/// Whole-request deadline, covering permit acquisition and send.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest response body accepted, enforced as it streams.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// A client bound to one cluster.
pub struct ProxmoxClient {
    cluster: Cluster,
    http: HttpClient,
    authorization: String,
}

impl ProxmoxClient {
    /// Build a client for one cluster, loading its credential.
    ///
    /// # Errors
    /// Returns [`ProxmoxError`] when the credential cannot be loaded, the CA
    /// PEM is unreadable, or the endpoint is not HTTPS.
    pub fn new(cluster: Cluster) -> Result<Self, ProxmoxError> {
        let secret: OutboundSecret = cluster.load_secret()?;
        let authorization = cluster.authorization_value(&secret);

        let mut extra_root_certificates = Vec::new();
        if let Some(path) = &cluster.ca_pem_path {
            let pem = std::fs::read_to_string(path)
                .map_err(|error| ProxmoxError::Malformed(format!("ca_pem_path: {error}")))?;
            extra_root_certificates.push(pem);
        }

        let config = HttpClientConfig {
            request_timeout: REQUEST_TIMEOUT,
            max_concurrent_requests: MAX_CONCURRENT,
            max_queued_requests: MAX_QUEUED,
            max_response_bytes: MAX_RESPONSE_BYTES,
            user_agent: concat!("rust-proxmoxmcp/", env!("CARGO_PKG_VERSION")).to_owned(),
            extra_root_certificates,
            ..HttpClientConfig::default()
        };

        let http = HttpClient::new(config)?;
        Ok(Self {
            cluster,
            http,
            authorization,
        })
    }

    /// Issue a GET against a path template and return the unwrapped `data`.
    ///
    /// The template is expanded by `mecmcp-openapi`, which rejects a parameter
    /// that would span a segment, start a query, navigate the hierarchy,
    /// collapse a segment, or carry a control byte. Nothing is sanitised: a
    /// rewritten value is a value the caller did not send.
    ///
    /// # Errors
    /// Returns [`ProxmoxError::Malformed`] for a rejected parameter or a body
    /// without a `data` member, [`ProxmoxError::Unauthorized`] for 401/403, and
    /// [`ProxmoxError::Api`] for any other error status.
    pub async fn get_json(
        &self,
        path_template: &str,
        params: &[(&str, &str)],
    ) -> Result<serde_json::Value, ProxmoxError> {
        let expanded = mecmcp_openapi::expand_path(path_template, params)
            .map_err(|error| ProxmoxError::Malformed(error.to_string()))?;
        let url = format!("{}{expanded}", self.cluster.endpoint.trim_end_matches('/'));

        let request = HttpRequest::new(Method::Get, &url)?
            .header("Accept", "application/json")?
            .header_bytes("Authorization", self.authorization.as_bytes())?;

        let response = self.http.send(request).await?;
        if response.status() >= 400 {
            return Err(ProxmoxError::from_response(response.status(), response.body()));
        }

        let parsed: serde_json::Value = serde_json::from_slice(response.body())
            .map_err(|error| ProxmoxError::Malformed(error.to_string()))?;
        parsed
            .get("data")
            .cloned()
            .ok_or_else(|| ProxmoxError::Malformed("response has no 'data' member".into()))
    }

    /// The cluster this client is bound to.
    #[must_use]
    pub fn cluster(&self) -> &Cluster {
        &self.cluster
    }
}
```

Notes for the implementer:
- `mecmcp_openapi`'s path-expansion entry point may be named `path::expand` rather than `expand_path`; check `cargo doc -p mecmcp-openapi` and use the real name.
- `HttpRequest::header_bytes` is used for `Authorization` so the value can be marked sensitive; if `secret_header` is available taking an `&OutboundSecret`, prefer it and keep the `OutboundSecret` on the struct instead of a `String`. That is the better form — take it if the signature allows building the full `PVEAPIToken=` value as a secret.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p rust-proxmoxmcp-core --test client`
Expected: 5 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/rust-proxmoxmcp-core/src/client.rs crates/rust-proxmoxmcp-core/tests crates/rust-proxmoxmcp-core/Cargo.toml
git commit -m "feat(core): per-cluster hardened client with rejecting path expansion"
```

---

### Task 8: Guest resolution with a TTL cache

**Files:**
- Create: `crates/rust-proxmoxmcp-core/src/resolve.rs`
- Test: `crates/rust-proxmoxmcp-core/tests/resolve.rs`

**Interfaces:**
- Consumes: `ProxmoxClient::get_json`, `crate::selector::{GuestFacts, GuestType}`.
- Produces:
  - `struct ResolvedGuest { cluster: String, vmid: u32, name: String, r#type: GuestType, node: String, status: String, tags: Vec<String>, pool: Option<String> }` with `ResolvedGuest::facts(&self) -> GuestFacts<'_>`.
  - `struct GuestIndex` — `GuestIndex::new(ttl: Duration)`, `GuestIndex::resolve(&self, client: &ProxmoxClient, cluster: &str, vmid: u32) -> Result<ResolvedGuest, ProxmoxError>`, `GuestIndex::invalidate(&self)`.
  - `ProxmoxError::NotFound` for an absent vmid.

- [ ] **Step 1: Write the failing test**

```rust
//! Resolution turns (cluster, vmid) into a live guest. The caller never names
//! a node: guests migrate, and two of the 2026-08-12 renumbers moved node.

use rust_proxmoxmcp_core::{
    client::ProxmoxClient, error::ProxmoxError, resolve::GuestIndex, selector::GuestType,
};
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;

const RESOURCES: &[u8] = br#"{"data":[
  {"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2",
   "status":"running","tags":"protected","pool":"ops"},
  {"id":"lxc/606","type":"lxc","vmid":606,"name":"rustsdcmcp-606","node":"pve3",
   "status":"running","tags":"disposable;lab"}
]}"#;

async fn index_and_client() -> (GuestIndex, ProxmoxClient, MockServer, tempfile::NamedTempFile) {
    unsafe { std::env::set_var("PVE_TEST_TOKEN", "not-a-real-secret-0123456789abcdef") };
    let (server, ca) = common::tls_mock_server().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/cluster/resources"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(RESOURCES.to_vec(), "application/json"))
        .mount(&server)
        .await;
    let client = ProxmoxClient::new(common::cluster_for(&server.uri(), ca.path())).expect("client");
    (GuestIndex::new(Duration::from_secs(10)), client, server, ca)
}

#[tokio::test]
async fn resolves_a_guest_to_its_current_node() {
    let (index, client, _server, _ca) = index_and_client().await;
    let guest = index.resolve(&client, "pve3", 905).await.expect("resolve");
    assert_eq!(guest.node, "pve2");
    assert_eq!(guest.name, "vsrx-prod");
    assert_eq!(guest.r#type, GuestType::Qemu);
}

#[tokio::test]
async fn splits_semicolon_separated_tags() {
    let (index, client, _server, _ca) = index_and_client().await;
    let guest = index.resolve(&client, "pve3", 606).await.expect("resolve");
    assert_eq!(guest.tags, vec!["disposable".to_owned(), "lab".to_owned()]);
}

#[tokio::test]
async fn an_absent_vmid_is_not_found_rather_than_a_default() {
    let (index, client, _server, _ca) = index_and_client().await;
    let error = index.resolve(&client, "pve3", 4242).await.expect_err("absent");
    assert!(matches!(error, ProxmoxError::NotFound { .. }));
}

#[tokio::test]
async fn a_guest_with_no_pool_resolves_with_none() {
    let (index, client, _server, _ca) = index_and_client().await;
    let guest = index.resolve(&client, "pve3", 606).await.expect("resolve");
    assert_eq!(guest.pool, None);
}

#[tokio::test]
async fn a_second_resolve_within_the_ttl_issues_no_second_request() {
    let (index, client, server, _ca) = index_and_client().await;
    index.resolve(&client, "pve3", 905).await.expect("first");
    index.resolve(&client, "pve3", 606).await.expect("second");
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
}
```

Move `cluster_for` from `tests/client.rs` into `tests/common/mod.rs` as `pub fn cluster_for` so both integration tests share it.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p rust-proxmoxmcp-core --test resolve`
Expected: FAIL — `cannot find type GuestIndex`.

- [ ] **Step 3: Write the implementation**

```rust
//! Guest resolution.
//!
//! Every guest-addressed tool takes `(cluster, vmid)` and never a node. Guests
//! migrate; a caller-supplied node is an opportunity to act on a stale
//! assumption, and after a migration it addresses the wrong place entirely.
//!
//! Resolution reads `/cluster/resources` once per TTL window rather than once
//! per call, because the same snapshot answers node, name, status, tags and
//! pool for every guest at once.

use crate::client::ProxmoxClient;
use crate::error::ProxmoxError;
use crate::selector::{GuestFacts, GuestType};
use std::collections::BTreeMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// A guest as the cluster currently reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGuest {
    /// Inventory name of the cluster this guest lives in.
    pub cluster: String,
    /// Numeric guest id.
    pub vmid: u32,
    /// Display name.
    pub name: String,
    /// VM or container.
    pub r#type: GuestType,
    /// Node the guest is on right now.
    pub node: String,
    /// Runtime status, e.g. `running` or `stopped`.
    pub status: String,
    /// Live tags, split from Proxmox's semicolon-separated field.
    pub tags: Vec<String>,
    /// Proxmox pool, when the guest is in one.
    pub pool: Option<String>,
}

impl ResolvedGuest {
    /// Borrow the facts a selector needs.
    #[must_use]
    pub fn facts(&self) -> GuestFacts<'_> {
        GuestFacts {
            vmid: self.vmid,
            r#type: self.r#type,
            node: &self.node,
            pool: self.pool.as_deref(),
            tags: &self.tags,
        }
    }
}

/// One cached `/cluster/resources` snapshot.
struct Snapshot {
    taken: Instant,
    guests: BTreeMap<u32, ResolvedGuest>,
}

/// A TTL-bounded index of every guest in every cluster.
pub struct GuestIndex {
    ttl: Duration,
    snapshots: RwLock<BTreeMap<String, Snapshot>>,
}

impl GuestIndex {
    /// Build an index whose snapshots expire after `ttl`.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            snapshots: RwLock::new(BTreeMap::new()),
        }
    }

    /// Resolve one guest, refreshing the cluster snapshot when it has expired.
    ///
    /// # Errors
    /// Returns [`ProxmoxError::NotFound`] when the cluster does not report the
    /// vmid, and propagates any client error from refreshing the snapshot.
    pub async fn resolve(
        &self,
        client: &ProxmoxClient,
        cluster: &str,
        vmid: u32,
    ) -> Result<ResolvedGuest, ProxmoxError> {
        if let Some(guest) = self.lookup_fresh(cluster, vmid) {
            return Ok(guest);
        }
        let guests = fetch_guests(client, cluster).await?;
        let found = guests.get(&vmid).cloned();
        if let Ok(mut snapshots) = self.snapshots.write() {
            snapshots.insert(
                cluster.to_owned(),
                Snapshot {
                    taken: Instant::now(),
                    guests,
                },
            );
        }
        found.ok_or_else(|| ProxmoxError::NotFound {
            what: format!("guest {vmid} in cluster {cluster}"),
        })
    }

    /// Drop every cached snapshot, e.g. after a mutation.
    pub fn invalidate(&self) {
        if let Ok(mut snapshots) = self.snapshots.write() {
            snapshots.clear();
        }
    }

    /// Read one guest out of a snapshot that has not expired.
    fn lookup_fresh(&self, cluster: &str, vmid: u32) -> Option<ResolvedGuest> {
        let snapshots = self.snapshots.read().ok()?;
        let snapshot = snapshots.get(cluster)?;
        if snapshot.taken.elapsed() > self.ttl {
            return None;
        }
        snapshot.guests.get(&vmid).cloned()
    }
}

/// Read and parse `/cluster/resources` for one cluster.
async fn fetch_guests(
    client: &ProxmoxClient,
    cluster: &str,
) -> Result<BTreeMap<u32, ResolvedGuest>, ProxmoxError> {
    let value = client
        .get_json("/api2/json/cluster/resources", &[])
        .await?;
    let entries = value
        .as_array()
        .ok_or_else(|| ProxmoxError::Malformed("cluster/resources is not an array".into()))?;

    let mut guests = BTreeMap::new();
    for entry in entries {
        let Some(kind) = entry.get("type").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let r#type = match kind {
            "qemu" => GuestType::Qemu,
            "lxc" => GuestType::Lxc,
            _ => continue,
        };
        let Some(vmid) = entry.get("vmid").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let vmid = u32::try_from(vmid)
            .map_err(|_| ProxmoxError::Malformed(format!("vmid {vmid} out of range")))?;
        let node = entry
            .get("node")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ProxmoxError::Malformed(format!("guest {vmid} has no node")))?;

        guests.insert(
            vmid,
            ResolvedGuest {
                cluster: cluster.to_owned(),
                vmid,
                name: entry
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                r#type,
                node: node.to_owned(),
                status: entry
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                tags: parse_tags(entry.get("tags").and_then(serde_json::Value::as_str)),
                pool: entry
                    .get("pool")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
            },
        );
    }
    Ok(guests)
}

/// Split Proxmox's semicolon-separated tag string.
fn parse_tags(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .split(';')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_owned)
        .collect()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rust-proxmoxmcp-core --test resolve`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/rust-proxmoxmcp-core/src/resolve.rs crates/rust-proxmoxmcp-core/tests
git commit -m "feat(core): resolve (cluster,vmid) to the guest's current node"
```

---

### Task 9: Protection resolution — the truth table

**Files:**
- Create: `crates/rust-proxmoxmcp-core/src/protect.rs`
- Test: inline `#[cfg(test)]` module

**Interfaces:**
- Consumes: `crate::inventory::Cluster`, `crate::resolve::ResolvedGuest`, `crate::tier::Tier`.
- Produces:
  - `enum Protection { Unprotected, Protected { reasons: Vec<ProtectionReason> } }`
  - `enum ProtectionReason { LiveTag(String), InventoryPin, ResolutionFailed, UnknownGuest }`
  - `fn protection_of(cluster: &Cluster, guest: Option<&ResolvedGuest>, resolution_failed: bool) -> Protection`
  - `Protection::is_protected(&self) -> bool`, `Protection::summary(&self) -> String`

Release 0.1 has no destructive tier, so nothing consumes the verdict to refuse a
call yet. It is still built and enforced-on-read now, because 0.3 must not be
the release that both introduces destroys and introduces the guardrail.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::selector::GuestType;

    fn cluster(protected_vmids: Vec<u32>) -> Cluster {
        Cluster {
            endpoint: "https://pve3.example.org:8006".to_owned(),
            token_id: "root@pam!mcp".to_owned(),
            token_secret_env: Some("X".to_owned()),
            token_secret_file: None,
            ca_pem_path: None,
            protected_vmids,
            protected_tags: vec!["protected".to_owned()],
        }
    }

    fn guest(vmid: u32, tags: &[&str]) -> ResolvedGuest {
        ResolvedGuest {
            cluster: "pve3".to_owned(),
            vmid,
            name: format!("guest-{vmid}"),
            r#type: GuestType::Qemu,
            node: "pve2".to_owned(),
            status: "running".to_owned(),
            tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
            pool: None,
        }
    }

    #[test]
    fn a_live_tag_alone_protects() {
        let verdict = protection_of(&cluster(vec![]), Some(&guest(905, &["protected"])), false);
        assert!(verdict.is_protected());
    }

    #[test]
    fn an_inventory_pin_alone_protects() {
        let verdict = protection_of(&cluster(vec![905]), Some(&guest(905, &[])), false);
        assert!(verdict.is_protected());
    }

    #[test]
    fn clearing_the_tag_does_not_clear_the_pin() {
        // The attack the union exists to stop: the server's own token can edit
        // tags, so a tag-only policy is unprotect-then-destroy in two calls.
        let verdict = protection_of(&cluster(vec![905]), Some(&guest(905, &["ci"])), false);
        assert!(verdict.is_protected());
    }

    #[test]
    fn a_failed_resolution_is_protected() {
        let verdict = protection_of(&cluster(vec![]), None, true);
        assert!(verdict.is_protected());
        assert!(matches!(
            verdict,
            Protection::Protected { ref reasons } if reasons.contains(&ProtectionReason::ResolutionFailed)
        ));
    }

    #[test]
    fn an_unknown_guest_is_protected() {
        let verdict = protection_of(&cluster(vec![]), None, false);
        assert!(verdict.is_protected());
        assert!(matches!(
            verdict,
            Protection::Protected { ref reasons } if reasons.contains(&ProtectionReason::UnknownGuest)
        ));
    }

    #[test]
    fn an_untagged_unpinned_known_guest_is_unprotected() {
        let verdict = protection_of(&cluster(vec![905]), Some(&guest(606, &["disposable"])), false);
        assert!(!verdict.is_protected());
    }

    #[test]
    fn a_custom_protected_tag_is_honoured() {
        let mut cluster = cluster(vec![]);
        cluster.protected_tags = vec!["do-not-touch".to_owned()];
        let verdict = protection_of(&cluster, Some(&guest(606, &["do-not-touch"])), false);
        assert!(verdict.is_protected());
    }

    #[test]
    fn every_applicable_reason_is_reported_not_just_the_first() {
        let verdict = protection_of(&cluster(vec![905]), Some(&guest(905, &["protected"])), false);
        let Protection::Protected { reasons } = verdict else {
            panic!("expected protected");
        };
        assert_eq!(reasons.len(), 2, "reasons were {reasons:?}");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p rust-proxmoxmcp-core protect::tests`
Expected: FAIL — `cannot find function protection_of`.

- [ ] **Step 3: Write the implementation**

```rust
//! Protection resolution: the function that decides whether a guest survives.
//!
//! Protection is the union of a live Proxmox tag and a server-side pin, and it
//! fails closed on both an unreadable answer and an unknown guest.
//!
//! The union is the whole point. A live tag keeps the list current and lets
//! operators manage it where they already work — but the server's own API token
//! can clear that tag, so a tag-only policy is unprotect-then-destroy in two
//! calls. The pin in `clusters.json` cannot be edited through the Proxmox API
//! at all. Neither half is sufficient alone.
//!
//! Every applicable reason is reported rather than the first one found, because
//! the preview an approver reads should say *why* — a guest protected twice
//! over is a different situation from one protected by a tag someone may
//! reasonably remove.

use crate::inventory::Cluster;
use crate::resolve::ResolvedGuest;

/// Why a guest is protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionReason {
    /// The guest carries a tag the cluster policy marks protective.
    LiveTag(String),
    /// The guest's vmid is pinned in `clusters.json`.
    InventoryPin,
    /// The cluster could not be read, so protection cannot be ruled out.
    ResolutionFailed,
    /// The cluster does not report this guest at all.
    UnknownGuest,
}

/// The protection verdict for one guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protection {
    /// No protective signal applies.
    Unprotected,
    /// At least one protective signal applies.
    Protected {
        /// Every applicable reason, in a stable order.
        reasons: Vec<ProtectionReason>,
    },
}

impl Protection {
    /// Whether any protective signal applies.
    #[must_use]
    pub fn is_protected(&self) -> bool {
        matches!(self, Self::Protected { .. })
    }

    /// A one-line rendering for audit metadata and previews.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Unprotected => "unprotected".to_owned(),
            Self::Protected { reasons } => reasons
                .iter()
                .map(|reason| match reason {
                    ProtectionReason::LiveTag(tag) => format!("tag:{tag}"),
                    ProtectionReason::InventoryPin => "inventory-pin".to_owned(),
                    ProtectionReason::ResolutionFailed => "resolution-failed".to_owned(),
                    ProtectionReason::UnknownGuest => "unknown-guest".to_owned(),
                })
                .collect::<Vec<_>>()
                .join(","),
        }
    }
}

/// Resolve protection for one guest.
///
/// `guest` is `None` when the cluster does not report the vmid. `resolution_failed`
/// is `true` when the cluster could not be read at all — distinguished from an
/// absent guest because they are different operational situations, and both are
/// protective.
#[must_use]
pub fn protection_of(
    cluster: &Cluster,
    guest: Option<&ResolvedGuest>,
    resolution_failed: bool,
) -> Protection {
    let mut reasons = Vec::new();

    if resolution_failed {
        reasons.push(ProtectionReason::ResolutionFailed);
    }

    match guest {
        None if !resolution_failed => reasons.push(ProtectionReason::UnknownGuest),
        None => {}
        Some(guest) => {
            for tag in &guest.tags {
                if cluster.protected_tags.contains(tag) {
                    reasons.push(ProtectionReason::LiveTag(tag.clone()));
                }
            }
            if cluster.protected_vmids.contains(&guest.vmid) {
                reasons.push(ProtectionReason::InventoryPin);
            }
        }
    }

    if reasons.is_empty() {
        Protection::Unprotected
    } else {
        Protection::Protected { reasons }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rust-proxmoxmcp-core protect::tests`
Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/rust-proxmoxmcp-core/src/protect.rs
git commit -m "feat(core): fail-closed protection as the union of live tag and inventory pin"
```

---

### Task 10: `AuthorizedGuest` and stage-2 authorization

**Files:**
- Create: `crates/rust-proxmoxmcp-core/src/authorized.rs`
- Modify: `crates/rust-proxmoxmcp-core/src/resolve.rs` (add `authorize`)
- Test: `crates/rust-proxmoxmcp-core/tests/authorize.rs`

**Interfaces:**
- Consumes: `GuestIndex::resolve`, `ProxmoxGrant::allows_guest`, `protection_of`, `Tier`.
- Produces:
  - `struct AuthorizedGuest` — fields private; accessors `guest(&self) -> &ResolvedGuest`, `protection(&self) -> &Protection`, `tier(&self) -> Tier`. **No public constructor.**
  - `enum AuthorizationDenied { OutOfScope { vmid: u32 }, ActionNotGranted { tier: Tier }, Protected { summary: String } }`
  - `GuestIndex::authorize(&self, client, cluster, vmid, grant: &ProxmoxGrant, tier: Tier) -> Result<AuthorizedGuest, ProxmoxError>`

- [ ] **Step 1: Write the failing test**

```rust
//! Stage-2 authorization. Stage 1 (tool + cluster) runs in the preflight with
//! no I/O; everything that needs a resolved guest happens here, behind a type
//! that cannot be constructed any other way.

use rust_proxmoxmcp_core::{
    client::ProxmoxClient, error::ProxmoxError, grant::{ProxmoxAction, ProxmoxGrant},
    resolve::GuestIndex, tier::Tier,
};
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;

const RESOURCES: &[u8] = br#"{"data":[
  {"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2",
   "status":"running","tags":"protected"},
  {"id":"lxc/606","type":"lxc","vmid":606,"name":"rustsdcmcp-606","node":"pve3",
   "status":"running","tags":"disposable"}
]}"#;

async fn fixture() -> (GuestIndex, ProxmoxClient, MockServer, tempfile::NamedTempFile) {
    unsafe { std::env::set_var("PVE_TEST_TOKEN", "not-a-real-secret-0123456789abcdef") };
    let (server, ca) = common::tls_mock_server().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/cluster/resources"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(RESOURCES.to_vec(), "application/json"))
        .mount(&server)
        .await;
    let mut cluster = common::cluster_for(&server.uri(), ca.path());
    cluster.protected_vmids = vec![905];
    let client = ProxmoxClient::new(cluster).expect("client");
    (GuestIndex::new(Duration::from_secs(10)), client, server, ca)
}

fn band_grant() -> ProxmoxGrant {
    ProxmoxGrant {
        guests: vec!["vmid:600-699".to_owned()],
        actions: vec![ProxmoxAction::Read],
    }
}

#[tokio::test]
async fn authorizes_an_in_scope_guest_for_a_granted_tier() {
    let (index, client, _server, _ca) = fixture().await;
    let authorized = index
        .authorize(&client, "pve3", 606, &band_grant(), Tier::Read)
        .await
        .expect("authorize");
    assert_eq!(authorized.guest().vmid, 606);
    assert_eq!(authorized.tier(), Tier::Read);
    assert!(!authorized.protection().is_protected());
}

#[tokio::test]
async fn refuses_a_guest_outside_the_grant_selector() {
    let (index, client, _server, _ca) = fixture().await;
    let error = index
        .authorize(&client, "pve3", 905, &band_grant(), Tier::Read)
        .await
        .expect_err("905 is outside 600-699");
    assert!(error.to_string().contains("905"));
}

#[tokio::test]
async fn refuses_a_tier_the_grant_does_not_carry() {
    let (index, client, _server, _ca) = fixture().await;
    let error = index
        .authorize(&client, "pve3", 606, &band_grant(), Tier::Destructive)
        .await
        .expect_err("grant carries read only");
    assert!(error.to_string().contains("destructive") || error.to_string().contains("Destructive"));
}

#[tokio::test]
async fn a_protected_guest_still_authorizes_for_read_and_reports_protection() {
    // Protection gates the destructive tier, not observation. A read of a
    // protected guest is exactly how an operator checks that it is protected.
    let (index, client, _server, _ca) = fixture().await;
    let grant = ProxmoxGrant::read_only();
    let authorized = index
        .authorize(&client, "pve3", 905, &grant, Tier::Read)
        .await
        .expect("read of a protected guest is allowed");
    assert!(authorized.protection().is_protected());
    assert!(authorized.protection().summary().contains("inventory-pin"));
    assert!(authorized.protection().summary().contains("tag:protected"));
}

#[tokio::test]
async fn an_unknown_guest_is_not_found_and_never_yields_an_authorized_guest() {
    let (index, client, _server, _ca) = fixture().await;
    let error = index
        .authorize(&client, "pve3", 4242, &ProxmoxGrant::read_only(), Tier::Read)
        .await
        .expect_err("absent");
    assert!(matches!(error, ProxmoxError::NotFound { .. }));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p rust-proxmoxmcp-core --test authorize`
Expected: FAIL — `no method named authorize`.

- [ ] **Step 3: Write `authorized.rs`**

```rust
//! The type that makes stage-2 authorization unskippable.
//!
//! Stage 1 — tool and cluster scope — runs in the bearer boundary before any
//! I/O. Stage 2 needs a resolved guest, so it necessarily runs past the
//! boundary, in code a handler could forget to call.
//!
//! It therefore is not optional by construction. [`AuthorizedGuest`] has no
//! public constructor and no public fields; the only way to obtain one is
//! `crate::resolve::GuestIndex::authorize`, which runs the grant selector, the
//! action check and the protection resolution. Every mutating API in this crate
//! takes one. A handler that skips authorization does not compile.
//!
//! This is the same move `mecmcp` 0.8.1 made for audit: audited because it went
//! through the transport, not because someone remembered.

use crate::protect::Protection;
use crate::resolve::ResolvedGuest;
use crate::tier::Tier;

/// A guest that has passed stage-2 authorization for a specific tier.
#[derive(Debug, Clone)]
pub struct AuthorizedGuest {
    guest: ResolvedGuest,
    protection: Protection,
    tier: Tier,
}

impl AuthorizedGuest {
    /// Construct an authorized guest.
    ///
    /// Deliberately `pub(crate)`: `crate::resolve::GuestIndex::authorize` is the
    /// only caller, and it is the only place the checks live.
    pub(crate) fn new(guest: ResolvedGuest, protection: Protection, tier: Tier) -> Self {
        Self {
            guest,
            protection,
            tier,
        }
    }

    /// The resolved guest.
    #[must_use]
    pub fn guest(&self) -> &ResolvedGuest {
        &self.guest
    }

    /// The protection verdict observed at authorization time.
    #[must_use]
    pub fn protection(&self) -> &Protection {
        &self.protection
    }

    /// The tier this authorization was granted for.
    #[must_use]
    pub fn tier(&self) -> Tier {
        self.tier
    }
}
```

- [ ] **Step 4: Add `authorize` to `resolve.rs`**

```rust
use crate::authorized::AuthorizedGuest;
use crate::grant::ProxmoxGrant;
use crate::protect::protection_of;
use crate::tier::Tier;

impl GuestIndex {
    /// Resolve a guest and run stage-2 authorization for `tier`.
    ///
    /// Order matters. The guest is resolved first, because the grant selector
    /// and the protection check both need live facts. The scope check runs
    /// before the protection check so an out-of-scope caller learns nothing
    /// about whether the guest is protected.
    ///
    /// Protection does not gate [`Tier::Read`]: observing a protected guest is
    /// how an operator confirms it is protected. It is carried on the returned
    /// value so the audit event and, from 0.3, the change-set preview can
    /// report it.
    ///
    /// # Errors
    /// Returns [`ProxmoxError::NotFound`] for an absent guest, and
    /// [`ProxmoxError::Malformed`] carrying a caller-safe reason when the grant
    /// does not admit the guest, does not carry the tier, or when the tier is
    /// gated by protection.
    pub async fn authorize(
        &self,
        client: &ProxmoxClient,
        cluster: &str,
        vmid: u32,
        grant: &ProxmoxGrant,
        tier: Tier,
    ) -> Result<AuthorizedGuest, ProxmoxError> {
        let guest = self.resolve(client, cluster, vmid).await?;

        if !grant.allows_guest(guest.facts()) {
            return Err(ProxmoxError::Malformed(format!(
                "token scope does not admit guest {vmid} in cluster {cluster}"
            )));
        }

        if !mecmcp_auth::Grant::allows_action(grant, tier.action()) {
            return Err(ProxmoxError::Malformed(format!(
                "token grant does not carry the {tier:?} action tier"
            )));
        }

        let protection = protection_of(client.cluster(), Some(&guest), false);

        if tier == Tier::Destructive && protection.is_protected() {
            return Err(ProxmoxError::Malformed(format!(
                "guest {vmid} is protected ({}); a destructive call needs a waiver",
                protection.summary()
            )));
        }

        Ok(AuthorizedGuest::new(guest, protection, tier))
    }
}
```

Add `mecmcp-auth` to the core crate's dependencies if Task 5 has not already.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p rust-proxmoxmcp-core --test authorize`
Expected: 5 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/rust-proxmoxmcp-core/src/authorized.rs crates/rust-proxmoxmcp-core/src/resolve.rs crates/rust-proxmoxmcp-core/tests/authorize.rs
git commit -m "feat(core): AuthorizedGuest makes stage-2 authorization unskippable"
```

---

### Task 11: MCP server handler and tool registration

**Files:**
- Create: `crates/rust-proxmoxmcp/src/server/mod.rs`
- Create: `crates/rust-proxmoxmcp/src/lib.rs`
- Modify: `crates/rust-proxmoxmcp/src/main.rs` (declare `mod server;` via the lib)

**Interfaces:**
- Consumes: everything from `rust-proxmoxmcp-core`; `mecmcp_server::{tool_result, tool_error, authorize_call, caller_from_extensions, filter_tools_for_scope, audit_scope, ResultFormat, ResultLimits}`; `rmcp::{tool, tool_router, tool_handler, ServerHandler}`.
- Produces:
  - `const KNOWN_TOOLS: &[&str]` — every registered 0.1 tool name.
  - `struct ProxmoxServer { clusters: Arc<ClusterInventory>, clients: Arc<BTreeMap<String, ProxmoxClient>>, index: Arc<GuestIndex>, tool_router: ToolRouter<Self> }`
  - `ProxmoxServer::new(...) -> Self`, `impl ServerHandler for ProxmoxServer`.

- [ ] **Step 1: Write the failing test**

Inline in `server/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tools_matches_the_read_catalog_exactly() {
        let mut catalog: Vec<&str> = rust_proxmoxmcp_core::catalog::READ_TOOLS
            .iter()
            .map(|tool| tool.name)
            .collect();
        catalog.sort_unstable();
        let mut known: Vec<&str> = KNOWN_TOOLS.to_vec();
        known.sort_unstable();
        assert_eq!(known, catalog, "KNOWN_TOOLS has drifted from the catalog");
    }

    #[test]
    fn no_write_tool_is_registered_in_this_release() {
        for tool in rust_proxmoxmcp_core::tier::WRITE_TOOLS {
            assert!(
                !KNOWN_TOOLS.contains(tool),
                "write tool {tool} registered in a read-only release"
            );
        }
    }

    #[test]
    fn known_tools_is_sorted_so_review_diffs_stay_readable() {
        let mut sorted = KNOWN_TOOLS.to_vec();
        sorted.sort_unstable();
        assert_eq!(KNOWN_TOOLS, sorted.as_slice());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rust-proxmoxmcp server::tests`
Expected: FAIL — `cannot find value KNOWN_TOOLS`.

- [ ] **Step 3: Write the handler**

```rust
//! The MCP tool surface for release 0.1: reads only.

use mecmcp_auth::CallerCtx;
use mecmcp_server::{
    ResultFormat, ResultLimits, audit_scope, authorize_call, caller_from_extensions, tool_error,
    tool_result,
};
use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Implementation, ServerCapabilities, ServerInfo},
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use rust_proxmoxmcp_core::{
    ProxmoxGrant, Tier,
    catalog::read_tool,
    client::ProxmoxClient,
    inventory::ClusterInventory,
    resolve::GuestIndex,
};
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Every tool registered by this release. Kept sorted; asserted against the
/// catalog by a test so the two cannot drift.
pub const KNOWN_TOOLS: &[&str] = &[
    "get_cluster_status",
    "get_container_config",
    "get_containers",
    "get_guest_status",
    "get_node_status",
    "get_nodes",
    "get_storage",
    "get_task_status",
    "get_vm_config",
    "get_vms",
    "list_backups",
    "list_isos",
    "list_snapshots",
    "list_tasks",
    "list_templates",
];

/// Arguments for a cluster-scoped read.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClusterArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
}

/// Arguments for a node-scoped read.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct NodeArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node name as reported by `get_nodes`.
    pub node: String,
}

/// Arguments for a guest-scoped read.
///
/// There is deliberately no `node` field. Guests migrate between nodes, and the
/// server resolves the current one on every call; accepting a node from the
/// caller is how a request addresses the wrong guest after a migration.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GuestArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id, unique within the cluster.
    pub vmid: u32,
}

/// The MCP server.
#[derive(Clone)]
pub struct ProxmoxServer {
    clusters: Arc<ClusterInventory>,
    clients: Arc<BTreeMap<String, ProxmoxClient>>,
    index: Arc<GuestIndex>,
    tool_router: ToolRouter<Self>,
}

impl ProxmoxServer {
    /// Build the server over a loaded inventory and its per-cluster clients.
    #[must_use]
    pub fn new(
        clusters: Arc<ClusterInventory>,
        clients: Arc<BTreeMap<String, ProxmoxClient>>,
        index: Arc<GuestIndex>,
    ) -> Self {
        Self {
            clusters,
            clients,
            index,
            tool_router: Self::proxmox_tool_router(),
        }
    }

    /// Recover the caller's context, or `None` on the stdio path.
    fn caller(context: &RequestContext<RoleServer>) -> Option<CallerCtx<ProxmoxGrant>> {
        caller_from_extensions::<ProxmoxGrant>(&context.extensions).cloned()
    }

    /// Look up the client for a cluster the caller is entitled to reach.
    fn client_for(&self, cluster: &str) -> Result<&ProxmoxClient, CallToolResult> {
        self.clients
            .get(cluster)
            .ok_or_else(|| tool_error(format!("unknown cluster: {cluster}")))
    }
}

#[tool_router(router = proxmox_tool_router, vis = "pub(crate)")]
impl ProxmoxServer {
    #[tool(name = "get_nodes", description = "All nodes in the cluster with status and resource totals.")]
    async fn get_nodes(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read("get_nodes", &args.cluster, &[], None, &context)
            .await
    }

    #[tool(name = "get_node_status", description = "Detailed status for one node.")]
    async fn get_node_status(
        &self,
        Parameters(args): Parameters<NodeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_node_status",
            &args.cluster,
            &[("node", args.node.as_str())],
            None,
            &context,
        )
        .await
    }

    #[tool(name = "get_vm_config", description = "Configuration of one QEMU guest, including its Proxmox digest.")]
    async fn get_vm_config(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read("get_vm_config", &args.cluster, &[], Some(args.vmid), &context)
            .await
    }

    // ... one #[tool] per entry in KNOWN_TOOLS, each delegating to serve_read
    // with the same shape. Write them out in full; do not collapse into a macro,
    // because the tool name, description and argument type are what an MCP
    // client sees and each must be reviewable on its own.
}

impl ProxmoxServer {
    /// Execute one catalog-declared read.
    ///
    /// Guest-scoped tools resolve the guest and run stage-2 authorization,
    /// yielding an `AuthorizedGuest` whose node fills the `{node}` parameter.
    /// Cluster- and node-scoped tools take their parameters from the request.
    async fn serve_read(
        &self,
        tool: &'static str,
        cluster: &str,
        extra_params: &[(&str, &str)],
        vmid: Option<u32>,
        context: &RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(context);
        if let Err(error) = authorize_call(caller.as_ref(), tool, &[cluster]) {
            return tool_error(error);
        }

        let Some(entry) = read_tool(tool) else {
            return tool_error(format!("unregistered tool: {tool}"));
        };
        let client = match self.client_for(cluster) {
            Ok(client) => client,
            Err(result) => return result,
        };

        let mut params: Vec<(&str, String)> = extra_params
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned()))
            .collect();

        if let Some(vmid) = vmid {
            let grant = caller
                .as_ref()
                .and_then(|caller| caller.grant.clone())
                .unwrap_or_else(ProxmoxGrant::read_only);
            let authorized = match self
                .index
                .authorize(client, cluster, vmid, &grant, Tier::Read)
                .await
            {
                Ok(authorized) => authorized,
                Err(error) => return tool_error(error),
            };
            let guest = authorized.guest();
            params.push(("node", guest.node.clone()));
            params.push(("vmid", guest.vmid.to_string()));
            params.push(("kind", guest.r#type.path_segment().to_owned()));
            tracing::info!(
                tool,
                cluster,
                vmid = guest.vmid,
                node = %guest.node,
                guest_name = %guest.name,
                tier = "read",
                protection = %authorized.protection().summary(),
                scope = %audit_scope(caller.as_ref()),
                "proxmox read authorized"
            );
        }

        let borrowed: Vec<(&str, &str)> = params
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();

        match client.get_json(entry.path, &borrowed).await {
            Ok(value) => tool_result(&value, ResultFormat::Json, ResultLimits::default()),
            Err(error) => tool_error(error),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ProxmoxServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            server_info: Implementation {
                name: "rust-proxmoxmcp".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                ..Implementation::default()
            },
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(
                "Proxmox VE MCP server. Guest-addressed tools take (cluster, vmid); \
                 the server resolves the node itself because guests migrate."
                    .to_owned(),
            ),
            ..ServerInfo::default()
        }
    }
}
```

Notes for the implementer:
- `CallerCtx`'s grant accessor may be a field named `grant` of type `Option<G>` or `G`; check `cargo doc -p mecmcp-auth` and adapt the two lines that read it.
- `filter_tools_for_scope` should be applied in `list_tools` so a caller sees only tools its scope permits. If `#[tool_handler]` generates `list_tools`, override it explicitly and call `filter_tools_for_scope` on the generated list.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rust-proxmoxmcp server::tests`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/rust-proxmoxmcp/src/server crates/rust-proxmoxmcp/src/lib.rs
git commit -m "feat: MCP read surface over the catalog with stage-2 authorization"
```

---

### Task 12: CLI and transport assembly

**Files:**
- Create: `crates/rust-proxmoxmcp/src/cli.rs`
- Create: `crates/rust-proxmoxmcp/src/http_transport.rs`
- Modify: `crates/rust-proxmoxmcp/src/main.rs`

**Interfaces:**
- Consumes: `mecmcp_runtime::cli::{Cli, parse_with_provenance}`, `mecmcp_transport::{HttpTransportConfig, HostOriginPolicy, LimitsConfig, TransportIdentity, ToolScopePreflight, TargetField, MalformedArgumentsPolicy, BoundaryAccounting, ConcurrencyState, apply_bearer_boundary, apply_ip_rate_limit, build_streamable_http_router, serve_router}`, `mecmcp_audit::init_tracing`.
- Produces:
  - `struct ProxmoxCli { common: Cli, clusters_file: PathBuf }`
  - `fn build_preflight() -> Arc<dyn ScopePreflight>`
  - `async fn run() -> anyhow::Result<()>`

- [ ] **Step 1: Write the failing test**

Inline in `http_transport.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mecmcp_auth::ScopeSet;
    use mecmcp_transport::CallerScopes;

    fn scopes<'a>(clusters: &'a ScopeSet, tools: &'a ScopeSet) -> CallerScopes<'a> {
        CallerScopes {
            token_name: "test",
            devices: clusters,
            tools,
        }
    }

    fn call(tool: &str, cluster: &str) -> Vec<u8> {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call",
                 "params":{{"name":"{tool}","arguments":{{"cluster":"{cluster}"}}}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn admits_a_call_within_both_scopes() {
        let clusters = ScopeSet::Allowlist(vec!["pve3".to_owned()]);
        let tools = ScopeSet::Allowlist(vec!["get_nodes".to_owned()]);
        assert!(build_preflight()
            .check(&call("get_nodes", "pve3"), scopes(&clusters, &tools))
            .is_ok());
    }

    #[test]
    fn refuses_a_cluster_outside_the_device_scope() {
        let clusters = ScopeSet::Allowlist(vec!["pve3".to_owned()]);
        let tools = ScopeSet::Wildcard;
        assert!(build_preflight()
            .check(&call("get_nodes", "pve2"), scopes(&clusters, &tools))
            .is_err());
    }

    #[test]
    fn a_tool_wildcard_does_not_reach_a_write_tool() {
        // The registry is complete from 0.1 precisely so this holds the day
        // release 0.2 registers delete_vm.
        let clusters = ScopeSet::Wildcard;
        let tools = ScopeSet::Wildcard;
        assert!(build_preflight()
            .check(&call("delete_vm", "pve3"), scopes(&clusters, &tools))
            .is_err());
    }

    #[test]
    fn malformed_arguments_are_refused_not_deferred() {
        let clusters = ScopeSet::Wildcard;
        let tools = ScopeSet::Wildcard;
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call",
                        "params":{"name":"get_nodes","arguments":"not-an-object"}}"#;
        assert!(build_preflight()
            .check(body, scopes(&clusters, &tools))
            .is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p rust-proxmoxmcp http_transport::tests`
Expected: FAIL — `cannot find function build_preflight`.

- [ ] **Step 3: Write `cli.rs`**

```rust
//! Command-line surface.
//!
//! `mecmcp_runtime::cli::Cli` is flattened rather than reimplemented, so every
//! shared flag — transport, bind, TLS, allowed hosts, audit — behaves exactly as
//! it does on the sibling servers.
//!
//! Release 0.1 adds exactly one flag. `--lab-mode` and `--waivers-file` belong
//! to 0.3 and are deliberately absent: a flag that is present but ignored is
//! worse than one that is absent, because the operator cannot tell.

use clap::Parser;
use mecmcp_runtime::cli::Cli;
use std::path::PathBuf;

/// `rust-proxmoxmcp` command line.
#[derive(Debug, Parser)]
#[command(name = "rust-proxmoxmcp", version)]
pub struct ProxmoxCli {
    /// Flags shared with the rest of the mechub MCP family.
    #[command(flatten)]
    pub common: Cli,

    /// Cluster inventory. Must be mode 0600 and owned by the service user.
    #[arg(long, default_value = "/etc/proxmoxmcp/clusters.json")]
    pub clusters_file: PathBuf,
}
```

- [ ] **Step 4: Write `http_transport.rs`**

```rust
//! Transport assembly.
//!
//! The bearer boundary builds everything from authentication inwards, so the
//! layer order cannot be got wrong here. Per-IP rate limiting is the one layer
//! this crate applies itself, because it must run *before* authentication: a
//! request with a missing, malformed or unknown token has no identity to
//! charge, and metering it is what stops an authentication flood.
//!
//! Axum runs the last-applied layer first, so `apply_ip_rate_limit` is applied
//! after `apply_bearer_boundary` in order to sit outside it.

use mecmcp_transport::{
    MalformedArgumentsPolicy, ScopePreflight, TargetField, ToolScopePreflight,
};
use rust_proxmoxmcp_core::tier::WRITE_TOOLS;
use std::sync::Arc;

/// Build the stage-1 preflight: tool scope and cluster scope, with no I/O.
///
/// Guest selectors are deliberately not checked here. `CallerScopes` carries
/// only opaque name sets and `TargetValueShape` has no numeric-range form, so a
/// `vmid:600-699` term cannot be evaluated before dispatch. Guest scope lives in
/// the token's grant and is enforced in stage 2, behind `AuthorizedGuest`.
#[must_use]
pub fn build_preflight() -> Arc<dyn ScopePreflight> {
    Arc::new(ToolScopePreflight::new(
        WRITE_TOOLS,
        [TargetField::scalar("cluster")],
        MalformedArgumentsPolicy::Deny,
    ))
}
```

- [ ] **Step 5: Write `main.rs`**

```rust
//! One MCP server for many Proxmox VE clusters.

mod cli;
mod http_transport;
mod server;

use anyhow::Context as _;
use cli::ProxmoxCli;
use mecmcp_transport::{
    BoundaryAccounting, ConcurrencyState, HostOriginPolicy, HttpTransportConfig, LimitsConfig,
    TransportIdentity, apply_bearer_boundary, apply_ip_rate_limit, build_streamable_http_router,
    serve_router,
};
use rust_proxmoxmcp_core::{client::ProxmoxClient, inventory::ClusterInventory, resolve::GuestIndex};
use server::ProxmoxServer;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `mecmcp-http` deliberately installs no rustls CryptoProvider: a shared
    // crate choosing one is how aws-lc-rs was once linked into a ring build.
    // The binary installs it, once, before any client is constructed.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("a rustls crypto provider was already installed"))?;

    let parsed = mecmcp_runtime::cli::parse_with_provenance::<ProxmoxCli>(
        "rust-proxmoxmcp",
        env!("CARGO_PKG_VERSION"),
    );
    let arguments = parsed.cli;

    mecmcp_audit::init_tracing(&mecmcp_audit::AuditConfig::default())
        .context("initialise audit logging")?;

    let clusters = Arc::new(
        ClusterInventory::load(&arguments.clusters_file)
            .with_context(|| format!("load {}", arguments.clusters_file.display()))?,
    );

    let mut clients = BTreeMap::new();
    for name in clusters.names() {
        let cluster = clusters.get(&name)?;
        clients.insert(
            name.clone(),
            ProxmoxClient::new(cluster).with_context(|| format!("build client for {name}"))?,
        );
    }
    let clients = Arc::new(clients);

    let index = Arc::new(GuestIndex::new(Duration::from_secs(
        clusters.policy().resource_cache_ttl_secs,
    )));

    // SIGHUP reloads the inventory in place. A failed reload leaves the previous
    // contents in effect and logs; it must never take the server down.
    spawn_sighup_reload(Arc::clone(&clusters), Arc::clone(&index));

    serve(arguments, clusters, clients, index).await
}
```

Write `serve` to:

1. Build `TransportIdentity::new("rust-proxmoxmcp", metric_prefix, server_label, ["cluster"])`.
2. Build `LimitsConfig` from the shared flags.
3. Build `HostOriginPolicy::enforced(arguments.common.allowed_host, arguments.common.allowed_origin)`.
4. Build the token store over `ProxmoxGrant` from `--tokens-file` and construct the `BearerBoundary`.
5. Attach `build_preflight()` to the boundary.
6. `build_streamable_http_router(move || Ok(ProxmoxServer::new(...)), config)` → `(router, shutdown)`.
7. `let app = apply_bearer_boundary(router, boundary, accounting);`
8. `let app = apply_ip_rate_limit(app, &limits);` — **after**, so it sits outside.
9. `serve_router(app, address, tls, shutdown).await`.

Consult `crates/rustsdcmcp/src/main.rs` and `crates/rustmistmcp/src/main.rs` for the exact call shapes at v0.8.8 and mirror whichever is closer; do not invent parameter orders.

Write `spawn_sighup_reload` to listen on `tokio::signal::unix::SignalKind::hangup()` and, on each signal, call `clusters.reload()` and `index.invalidate()`, logging the count on success and the error on failure.

- [ ] **Step 6: Run tests and build**

Run: `cargo test -p rust-proxmoxmcp http_transport::tests`
Expected: 4 passed.

Run: `cargo build --workspace && cargo clippy --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/rust-proxmoxmcp/src
git commit -m "feat: CLI, stage-1 preflight, and bearer boundary assembly"
```

---

### Task 13: End-to-end tests through the assembled router

**Files:**
- Create: `crates/rust-proxmoxmcp/tests/common/mod.rs`
- Create: `crates/rust-proxmoxmcp/tests/read_surface.rs`

**Interfaces:**
- Consumes: `mecmcp_transport::test_client::McpClient`, the wiremock fixture from Task 7.
- Produces: nothing consumed by later tasks.

**Why this task is not optional:** `mecmcp` 0.8.3's headline bug was a middleware that passed every unit test and was never wired up by the assembly — `build_streamable_http_router` never called `with_session_tracker`, so every consumer emitted an empty client name exactly as before the feature shipped. Tests that construct components by hand prove the component. Only a client speaking to the assembled router proves the server.

- [ ] **Step 1: Write the failing test**

```rust
//! End-to-end: a real MCP client against the fully assembled router, with a
//! mock Proxmox behind it.

use mecmcp_transport::test_client::McpClient;

mod common;

#[tokio::test]
async fn lists_only_the_tools_the_token_scope_permits() {
    let harness = common::TestServer::start(common::TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec!["get_nodes".to_owned()],
        guests: vec!["*".to_owned()],
    })
    .await;

    let mut client = McpClient::connect(&harness.url, &harness.token)
        .await
        .expect("connect");
    let tools = client.list_tools().await.expect("list tools");

    let names: Vec<String> = tools.iter().map(|tool| tool.name.to_string()).collect();
    assert_eq!(names, vec!["get_nodes".to_owned()]);
}

#[tokio::test]
async fn a_permitted_read_returns_cluster_data() {
    let harness = common::TestServer::start(common::TokenSpec::full()).await;
    let mut client = McpClient::connect(&harness.url, &harness.token)
        .await
        .expect("connect");

    let result = client
        .call_tool("get_nodes", serde_json::json!({ "cluster": "pve3" }))
        .await
        .expect("call");

    assert!(result.to_string().contains("pve2"), "result was {result}");
}

#[tokio::test]
async fn a_cluster_outside_scope_is_refused_before_any_proxmox_request() {
    let harness = common::TestServer::start(common::TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec!["get_nodes".to_owned()],
        guests: vec!["*".to_owned()],
    })
    .await;
    let mut client = McpClient::connect(&harness.url, &harness.token)
        .await
        .expect("connect");

    let outcome = client
        .call_tool("get_nodes", serde_json::json!({ "cluster": "pve2" }))
        .await;

    assert!(outcome.is_err(), "expected a 403 from the preflight");
    assert_eq!(
        harness.proxmox_request_count().await,
        0,
        "the preflight must reject before any outbound request"
    );
}

#[tokio::test]
async fn a_guest_outside_the_grant_selector_is_refused_after_resolution() {
    let harness = common::TestServer::start(common::TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec!["get_vm_config".to_owned()],
        guests: vec!["vmid:600-699".to_owned()],
    })
    .await;
    let mut client = McpClient::connect(&harness.url, &harness.token)
        .await
        .expect("connect");

    let result = client
        .call_tool(
            "get_vm_config",
            serde_json::json!({ "cluster": "pve3", "vmid": 905 }),
        )
        .await
        .expect("call completes with a tool error");

    assert!(result.to_string().contains("scope"), "result was {result}");
    assert!(
        !result.to_string().contains("vsrx-prod"),
        "a refused call must not leak the guest name"
    );
}

#[tokio::test]
async fn a_missing_token_is_refused() {
    let harness = common::TestServer::start(common::TokenSpec::full()).await;
    let outcome = McpClient::connect(&harness.url, "not-a-real-token").await;
    assert!(outcome.is_err());
}
```

- [ ] **Step 2: Write the harness**

`crates/rust-proxmoxmcp/tests/common/mod.rs` must:

1. Start the TLS wiremock Proxmox from Task 7's helper, serving `/api2/json/nodes`, `/api2/json/cluster/resources`, and `/api2/json/nodes/pve2/qemu/905/config`.
2. Write a 0600 `clusters.json` naming that endpoint with its CA PEM.
3. Mint a token into a 0600 `tokens.json` via `mecmcp_auth::TokenStoreFile`, carrying a `ProxmoxGrant` built from the `TokenSpec`.
4. Build the same router `main.rs` builds — call the same `serve`-adjacent function, do not re-assemble by hand, or the test proves nothing about the assembly.
5. Bind `127.0.0.1:0`, spawn `serve_router`, and expose `url`, `token`, and `proxmox_request_count()`.

Refactor `main.rs` so router assembly lives in a `pub fn build_app(...)` the test can call. That refactor is part of this task.

- [ ] **Step 3: Run tests to verify they fail, then pass**

Run: `cargo test -p rust-proxmoxmcp --test read_surface`
Expected first: FAIL — harness does not compile. After implementation: 5 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/rust-proxmoxmcp/tests crates/rust-proxmoxmcp/src/main.rs
git commit -m "test: end-to-end read surface through the assembled router"
```

---

### Task 14: The adversarial suite

**Files:**
- Create: `crates/rust-proxmoxmcp-core/tests/adversarial.rs`

**Interfaces:**
- Consumes: everything in core.
- Produces: nothing.

The truth table in Task 9 proves the decision is right. This proves nothing reaches a destroy without asking it.

- [ ] **Step 1: Write the tests**

```rust
//! Properties that must hold regardless of how the surface grows.

use rust_proxmoxmcp_core::{catalog::READ_TOOLS, tier::{Tier, WRITE_TOOLS, tier_of}};

#[test]
fn every_catalog_path_templates_only_known_parameters() {
    const KNOWN: &[&str] = &["{node}", "{vmid}", "{kind}", "{storage}", "{upid}"];
    for tool in READ_TOOLS {
        let mut rest = tool.path;
        while let Some(open) = rest.find('{') {
            let close = rest[open..]
                .find('}')
                .unwrap_or_else(|| panic!("unterminated placeholder in {}", tool.name));
            let placeholder = &rest[open..=open + close];
            assert!(
                KNOWN.contains(&placeholder),
                "{} uses unknown placeholder {placeholder}",
                tool.name
            );
            rest = &rest[open + close + 1..];
        }
    }
}

#[test]
fn no_catalog_tool_uses_a_mutating_method() {
    for tool in READ_TOOLS {
        assert_eq!(
            format!("{:?}", tool.method).to_lowercase(),
            "get",
            "{} is not a GET",
            tool.name
        );
    }
}

#[test]
fn every_destructive_tool_is_in_the_write_registry() {
    // The registry is what excludes a tool from the wildcard scope. A
    // destructive tool missing from it is reachable by a "tools": ["*"] token.
    for tool in WRITE_TOOLS {
        assert!(matches!(tier_of(tool), Some(Tier::Low | Tier::Destructive)));
    }
}

#[test]
fn the_write_registry_is_sorted_within_its_groups() {
    // Sorted groups keep the review diff readable when 0.2 adds to it, which is
    // the moment an omission actually costs something.
    let destructive_start = WRITE_TOOLS
        .iter()
        .position(|tool| *tool == "delete_backup")
        .expect("delete_backup present");
    let destructive = &WRITE_TOOLS[destructive_start..];
    let mut sorted = destructive.to_vec();
    sorted.sort_unstable();
    assert_eq!(destructive, sorted.as_slice());
}
```

- [ ] **Step 2: Add a compile-fail check that `AuthorizedGuest` cannot be forged**

Create `crates/rust-proxmoxmcp-core/tests/compile_fail/forge_authorized_guest.rs`:

```rust
//! `AuthorizedGuest::new` is pub(crate); an external crate cannot call it.
fn main() {
    let _ = rust_proxmoxmcp_core::AuthorizedGuest::new(todo!(), todo!(), todo!());
}
```

Add `trybuild = "1"` to `[dev-dependencies]` and a driver:

```rust
#[test]
fn authorized_guest_cannot_be_constructed_outside_the_crate() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/*.rs");
}
```

- [ ] **Step 3: Run the suite**

Run: `cargo test -p rust-proxmoxmcp-core --test adversarial`
Expected: 5 passed, including the compile-fail case.

- [ ] **Step 4: Commit**

```bash
git add crates/rust-proxmoxmcp-core/tests/adversarial.rs crates/rust-proxmoxmcp-core/tests/compile_fail crates/rust-proxmoxmcp-core/Cargo.toml
git commit -m "test: adversarial properties over the catalog and the authorization type"
```

---

### Task 15: Packaging and documentation

**Files:**
- Create: `packaging/systemd/rust-proxmoxmcp.service`
- Create: `packaging/lxc/install.sh`
- Create: `packaging/examples/clusters.json`
- Modify: `README.md`
- Create: `CHANGELOG.md`

**Interfaces:**
- Consumes: the built binary.
- Produces: an installable release.

- [ ] **Step 1: Write the systemd unit**

```ini
[Unit]
Description=rust-proxmoxmcp — one MCP server for many Proxmox VE clusters
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=proxmoxmcp
Group=proxmoxmcp
ExecStart=/usr/local/bin/rust-proxmoxmcp \
    --clusters-file /etc/proxmoxmcp/clusters.json \
    --tokens-file /etc/proxmoxmcp/tokens.json \
    --transport streamable-http \
    --host 0.0.0.0 --port 30031 \
    --allowed-host proxmoxmcp.example.org \
    --tls-cert /etc/proxmoxmcp/tls/fullchain.pem \
    --tls-key /etc/proxmoxmcp/tls/privkey.pem \
    --audit-format json \
    --audit-log-file /var/lib/proxmoxmcp/audit.jsonl
Restart=on-failure
RestartSec=5
EnvironmentFile=/etc/proxmoxmcp/secrets.env

# /etc/proxmoxmcp stays read-only to the service. This is deliberate: it is what
# makes editing the inventory — and, from 0.3, granting a waiver — a root
# operation rather than a tool call. rust-junosmcp's add_device fails under the
# same sandbox, and keeping the sandbox narrow is the documented preference.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryDenyWriteExecute=yes
LockPersonality=yes
ReadWritePaths=/var/lib/proxmoxmcp
TimeoutStopSec=45

[Install]
WantedBy=multi-user.target
```

`TimeoutStopSec` must stay comfortably above the transport's `shutdown_timeout`: while any SSE stream is open, shutdown takes the full drain window.

- [ ] **Step 2: Write the installer**

`packaging/lxc/install.sh` — a POSIX shell script that:
1. Refuses to run if not root, or if `/etc/os-release` is not Debian 13.
2. Creates the `proxmoxmcp` system user and `/var/lib/proxmoxmcp` owned by it.
3. Installs the binary to `/usr/local/bin/rust-proxmoxmcp` mode 0755.
4. Installs `clusters.json`, `tokens.json` and `secrets.env` as mode 0600 owned by `proxmoxmcp` **only if absent** — never overwriting existing credentials.
5. Installs the unit, runs `systemctl daemon-reload`, and prints the next steps rather than starting the service.
6. Prints a reminder to snapshot the container before upgrading.

- [ ] **Step 3: Write the example inventory**

`packaging/examples/clusters.json`:

```json
{
  "version": 1,
  "devices": {
    "pve3": {
      "endpoint": "https://pve3.example.org:8006",
      "token_id": "root@pam!mcp",
      "token_secret_env": "PVE_PVE3_TOKEN",
      "ca_pem_path": "/etc/proxmoxmcp/ca/pve3.pem",
      "protected_vmids": [905, 906, 907, 908, 910, 920, 950, 951, 952, 960, 970, 980, 990, 991],
      "protected_tags": ["protected"]
    }
  },
  "policy": {
    "resource_cache_ttl_secs": 10
  }
}
```

- [ ] **Step 4: Rewrite the README**

Replace the "Status: design pending" section with a "Status: 0.1 — read surface" section stating: what is implemented, what is not (every mutating tool), the two-stage authorization model, the protection union, the flags, and a worked `clusters.json`. Keep the unofficial/community disclaimer and the mechub mark verbatim. Keep the sibling comparison table and update the `rustproxmoxmcp` row to `0.1, read surface`.

- [ ] **Step 5: Write the changelog**

`CHANGELOG.md` with a `## 0.1.0` entry covering: multi-cluster inventory, catalog read surface, two-stage authorization, `AuthorizedGuest`, fail-closed protection, complete `WRITE_TOOLS` registry, per-cluster CA pinning, SIGHUP reload. State plainly that no mutating tool exists yet and that the three python endpoints remain in service.

- [ ] **Step 6: Verify the whole workspace**

Run: `cargo test --workspace`
Expected: all pass.

Run: `cargo clippy --all-targets -- -D warnings`
Expected: clean.

Run: `cargo deny check`
Expected: no advisories, no license violations.

- [ ] **Step 7: Commit**

```bash
git add packaging README.md CHANGELOG.md
git commit -m "feat: LXC packaging, hardened unit, and 0.1 documentation"
```

---

## Post-plan verification

Before declaring 0.1 done, deploy to a lab LXC and confirm against the real cluster:

1. `get_nodes` against `pve3` returns both nodes.
2. `get_vm_config` for a **disposable** guest (600, 601 or 606) returns a config with a `digest`.
3. `get_vm_config` for `905` with a token scoped `vmid:600-699` is refused, and the refusal does not name the guest.
4. A token with `"tools": ["*"]` cannot call `delete_vm` — it is unregistered *and* in `WRITE_TOOLS`.
5. `systemctl reload` (SIGHUP) after editing `clusters.json` picks up a new cluster without dropping in-flight calls.
6. `systemctl restart` drains rather than dropping an in-flight call.

Record the results in the release notes. A lab check that was not run is not a lab check that passed.

---

## Self-review

**Spec coverage.** §3 crate layout → Task 1. §4.1 protection → Task 9. §4.2 override → deferred to 0.3 by design, and the plan forbids the flags appearing early. §4.3 tiers → Task 6. §4.4 fingerprint and §4.5 preview → 0.3. §5 scope model → Tasks 4, 5, 10, 12; the stage-1/stage-2 split is refined from the spec, see below. §6 inventory and transport → Tasks 3, 7. §7 resolution → Task 8. §8 tasks/UPID → 0.2. §9 errors and audit → Tasks 2, 11. §10 testing → Tasks 13, 14. §11 packaging → Task 15. §12 issue candidates → candidate 2 is resolved by the grant-based design and should be struck from the spec; candidate 1 stands and belongs to 0.3. §13 phasing → this plan is row 0.1. §14 ruled out → nothing in the plan contradicts it.

**Spec amendment required.** §5 says VMID-range terms are evaluated in stage 1. They cannot be: `TargetValueShape` is `Scalar | NonEmptyArray` and `CallerScopes` exposes only opaque name sets. The plan places cluster scope in the device `ScopeSet` and the guest selector in the token grant, making all guest scoping stage 2. Update spec §5 and delete issue candidate 2 from §12 before executing.

**Placeholder scan.** No TBDs. Three places name a verification step rather than an exact call — `mecmcp_openapi`'s expansion function name, `mecmcp_http::Method`'s variant spelling, and `CallerCtx`'s grant accessor. Each says exactly which command to run and what to do with the answer; they are checks against a pinned dependency, not undecided design.

**Type consistency.** `GuestFacts` is defined in Task 4 and consumed unchanged in Tasks 5, 8 and 10. `ResolvedGuest::facts` bridges them. `Tier` is defined in Task 6 and used in 5, 10, 11. `ProxmoxGrant::allows_guest` is inherent, `Grant::allows_action` is the trait method, and Task 10 calls the trait one through `mecmcp_auth::Grant::allows_action` explicitly. `AuthorizedGuest::new` is `pub(crate)` in Task 10 and the compile-fail test in Task 14 depends on exactly that.
