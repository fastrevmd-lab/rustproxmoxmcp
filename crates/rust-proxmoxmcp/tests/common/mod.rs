//! Test harness for end-to-end tests through the assembled router.
//!
//! Provides `TestServer` which starts:
//! - A TLS mock Proxmox serving canned routes
//! - A token store with a minted token carrying specified scopes
//! - The same HTTP router that `main.rs` uses (via `build_http_router`)
//!
//! The harness exposes the base URL, the plaintext token, and the mock's
//! request count to prove preflight rejection happens before any Proxmox request.

use mecmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use mecmcp_transport::LimitsConfig;
use rust_proxmoxmcp::http_transport::build_http_router;
use rust_proxmoxmcp::server::ProxmoxServer;
use rust_proxmoxmcp_core::testing::{Route, TlsMockServer};
use rust_proxmoxmcp_core::{
    ProxmoxAction, ProxmoxGrant,
    client::ProxmoxClient,
    inventory::{Cluster, ClusterInventory},
    resolve::GuestIndex,
};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

/// Allocate a unique test port for each TestServer instance.
static TEST_PORT_COUNTER: AtomicU16 = AtomicU16::new(19888);

/// Token specification for test scenarios.
pub struct TokenSpec {
    /// Allowed clusters.
    pub clusters: Vec<String>,
    /// Allowed tools.
    pub tools: Vec<String>,
    /// Guest selectors (e.g., `["*"]`, `["vmid:600-699"]`).
    pub guests: Vec<String>,
}

impl TokenSpec {
    /// A token with full wildcard access.
    pub fn full() -> Self {
        Self {
            clusters: vec!["*".to_owned()],
            tools: vec!["*".to_owned()],
            guests: vec!["*".to_owned()],
        }
    }
}

/// The assembled test server with a mock Proxmox behind it.
pub struct TestServer {
    /// Base URL for the MCP server (e.g., `http://127.0.0.1:xxxxx`).
    pub url: String,
    /// Plaintext bearer token for authentication.
    pub token: String,
    /// The mock Proxmox server.
    mock: TlsMockServer,
    /// Temp directory holding clusters.json and tokens.json.
    _temp_dir: tempfile::TempDir,
}

impl TestServer {
    /// Start the test server with a token carrying the given scopes.
    ///
    /// Sets up:
    /// - TLS mock Proxmox with standard routes
    /// - clusters.json and tokens.json
    /// - The same HTTP router that `main` uses
    ///
    /// The server listens on `127.0.0.1:0` and is served over plain HTTP
    /// (the HTTPS requirement is for the outbound leg to Proxmox).
    pub async fn start(spec: TokenSpec) -> Self {
        // Install crypto provider once for the test binary.
        ensure_crypto_provider();

        // Start the TLS mock Proxmox.
        let mock = TlsMockServer::start(vec![
            Route {
                path: "/api2/json/nodes",
                status: 200,
                body: br#"{"data":[{"node":"pve2","status":"online"},{"node":"pve3","status":"online"}]}"#,
            },
            Route {
                path: "/api2/json/cluster/resources",
                status: 200,
                body: br#"{"data":[
                  {"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2","status":"running","tags":"protected"},
                  {"id":"lxc/606","type":"lxc","vmid":606,"name":"rustsdcmcp-606","node":"pve3","status":"running","tags":"disposable"}
                ]}"#,
            },
            Route {
                path: "/api2/json/nodes/pve2/qemu/905/config",
                status: 200,
                body: br#"{"data":{"vmid":905,"name":"vsrx-prod","cores":2,"memory":2048}}"#,
            },
        ])
        .await;

        // Create a temp directory for clusters.json and tokens.json.
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let clusters_path = temp_dir.path().join("clusters.json");
        let tokens_path = temp_dir.path().join("tokens.json");

        // Write clusters.json.
        let cluster = Cluster {
            endpoint: mock.uri().to_owned(),
            token_id: "root@pam!mcp".to_owned(),
            token_secret_env: None,
            token_secret_file: Some(create_secret_file("mock-secret")),
            ca_pem_path: Some(mock.ca_pem_path().to_owned()),
            protected_vmids: vec![905],
            protected_tags: vec!["protected".to_owned()],
        };

        let mut clusters_map = BTreeMap::new();
        clusters_map.insert("pve3".to_owned(), cluster);

        let inventory_json = serde_json::json!({
            "version": 1,
            "devices": clusters_map,
            "policy": {
                "resource_cache_ttl_secs": 300
            }
        });

        let mut clusters_file =
            std::fs::File::create(&clusters_path).expect("create clusters.json");
        clusters_file
            .write_all(
                serde_json::to_string_pretty(&inventory_json)
                    .expect("serialize")
                    .as_bytes(),
            )
            .expect("write clusters.json");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&clusters_path, std::fs::Permissions::from_mode(0o600))
                .expect("set clusters.json permissions");
        }

        // Mint a token and write tokens.json.
        let grant = ProxmoxGrant {
            guests: spec.guests.clone(),
            actions: vec![ProxmoxAction::Read],
        };

        let tool_refs: Vec<&str> = spec.tools.iter().map(|s| s.as_str()).collect();
        let known = KnownNames {
            devices: Some(&spec.clusters),
            tools: &tool_refs,
        };

        let plaintext = TokenStoreFile::<ProxmoxGrant>::add_with_options(
            &tokens_path,
            "test-token",
            parse_scope(&spec.clusters),
            parse_scope(&spec.tools),
            None,
            Some(grant),
            None,
            None,
            None,
            None,
            &known,
        )
        .expect("mint token");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tokens_path, std::fs::Permissions::from_mode(0o600))
                .expect("set tokens.json permissions");
        }

        // Load the inventory and build clients.
        let clusters =
            Arc::new(ClusterInventory::load(&clusters_path).expect("load clusters.json"));
        let mut clients = BTreeMap::new();
        for name in clusters.names() {
            let cluster = clusters.get(&name).expect("get cluster");
            clients.insert(
                name.clone(),
                ProxmoxClient::new(cluster).expect("build client"),
            );
        }
        let clients = Arc::new(clients);

        let index = Arc::new(GuestIndex::new(Duration::from_secs(
            clusters.policy().resource_cache_ttl_secs,
        )));

        // Build the HTTP router using the same function `main` uses.
        let handler = ProxmoxServer::new(clusters, clients, index);
        let token_store_arc =
            Arc::new(TokenStoreFile::<ProxmoxGrant>::load(&tokens_path).expect("load tokens.json"));
        let shutdown = tokio_util::sync::CancellationToken::new();

        let plan = build_http_router(
            handler,
            Some(token_store_arc),
            vec![],
            vec![],
            LimitsConfig::default(),
            false,
            shutdown.clone(),
        )
        .expect("build HTTP router");

        // Allocate a unique test port for this instance to allow parallel test execution.
        use std::net::SocketAddr;
        let port = TEST_PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse test address");

        tokio::spawn(async move {
            mecmcp_transport::serve_router(plan, addr, None, Duration::from_secs(30))
                .await
                .expect("serve router");
        });

        // Give the server a moment to bind and start.
        tokio::time::sleep(Duration::from_millis(100)).await;

        Self {
            url: format!("http://{addr}"),
            token: plaintext.expose_secret().to_owned(),
            mock,
            _temp_dir: temp_dir,
        }
    }

    /// Number of requests the mock Proxmox has received.
    ///
    /// Used to prove that preflight rejection happens before any outbound request.
    pub fn proxmox_request_count(&self) -> usize {
        self.mock.request_count()
    }
}

/// Parse a scope specification into a `ScopeSet`.
fn parse_scope(items: &[String]) -> ScopeSet {
    if items.len() == 1 && items[0] == "*" {
        ScopeSet::Wildcard
    } else {
        ScopeSet::Allowlist(items.to_vec())
    }
}

/// Create a secret file with mode 0600 and return its path.
fn create_secret_file(value: &str) -> PathBuf {
    let mut file = tempfile::NamedTempFile::new().expect("create secret file");
    file.write_all(value.as_bytes())
        .expect("write secret value");
    file.flush().expect("flush secret file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("set secret file permissions");
    }

    file.into_temp_path().keep().expect("keep secret file")
}

/// Install a crypto provider once for the whole test binary.
///
/// `mecmcp-http` deliberately does not pick a provider, so tests stand in for
/// the consumer binary. `install_default` is process-global and one-shot.
fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}
