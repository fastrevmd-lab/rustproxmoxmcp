//! Test harness for end-to-end tests through the assembled router.
//!
//! Provides `TestServer` which starts:
//! - A TLS mock Proxmox serving canned routes
//! - A token store with a minted token carrying specified scopes
//! - The same HTTP router that `main.rs` uses (via `build_http_router`)
//!
//! The harness exposes the base URL, the plaintext token, and the mock's
//! request count to prove preflight rejection happens before any Proxmox request.

#![allow(dead_code)]

pub use rust_proxmoxmcp_core::testing::Route;

use mecmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use mecmcp_transport::LimitsConfig;
use mecmcp_transport::test_harness::serve_on_loopback;
use rust_proxmoxmcp::http_transport::build_http_router;
use rust_proxmoxmcp::server::ProxmoxServer;
use rust_proxmoxmcp_core::testing::TlsMockServer;
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
use std::time::Duration;

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
    /// Plaintext bearer token for authentication (first principal).
    pub token: String,
    /// Second bearer token for two-principal workflows.
    pub second_token: String,
    /// The mock Proxmox server.
    mock: TlsMockServer,
    /// Guest index for cache invalidation in tests.
    index: Arc<GuestIndex>,
    /// Temp directory holding clusters.json and tokens.json.
    _temp_dir: tempfile::TempDir,
}

impl TestServer {
    /// Start the test server with a token carrying the given scopes and custom routes.
    ///
    /// Sets up:
    /// - TLS mock Proxmox with the provided routes
    /// - clusters.json and tokens.json
    /// - The same HTTP router that `main` uses
    ///
    /// The server listens on `127.0.0.1:0` and is served over plain HTTP
    /// (the HTTPS requirement is for the outbound leg to Proxmox).
    pub async fn start_with_routes(spec: TokenSpec, routes: Vec<Route>) -> Self {
        Self::start_with_config(
            spec,
            routes,
            Arc::new(rust_proxmoxmcp_core::waiver::WaiverFile::empty()),
            false,
        )
        .await
    }

    /// Start the test server with custom waivers and lab-mode setting.
    ///
    /// This is used for testing the two-person control override system.
    pub async fn start_with_config(
        spec: TokenSpec,
        routes: Vec<Route>,
        waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
        lab_mode: bool,
    ) -> Self {
        // Install crypto provider once for the test binary.
        ensure_crypto_provider();

        // Start the TLS mock Proxmox with custom routes.
        let mock = TlsMockServer::start(routes).await;

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
            actions: vec![
                ProxmoxAction::Read,
                ProxmoxAction::Low,
                ProxmoxAction::Destructive,
            ],
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
            Some(grant.clone()),
            None,
            None,
            None,
            None,
            &known,
        )
        .expect("mint token");

        // Mint a second token for two-principal workflows.
        let second_plaintext = TokenStoreFile::<ProxmoxGrant>::add_with_options(
            &tokens_path,
            "test-token-2",
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
        .expect("mint second token");

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
        let handler = ProxmoxServer::new_with_default_coordinator(
            clusters,
            clients,
            Arc::clone(&index),
            waivers,
            lab_mode,
            None,
            None,
        )
        .expect("build server");
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
            false,
            shutdown.clone(),
        )
        .expect("build HTTP router");

        // Serve on an OS-assigned loopback port to avoid test collisions.
        let served = serve_on_loopback(plan).await;

        Self {
            url: format!("http://{}", served.address),
            token: plaintext.expose_secret().to_owned(),
            second_token: second_plaintext.expose_secret().to_owned(),
            mock,
            index,
            _temp_dir: temp_dir,
        }
    }

    /// Start the test server with default routes.
    pub async fn start(spec: TokenSpec) -> Self {
        let routes = vec![
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
        ];
        Self::start_with_routes(spec, routes).await
    }

    /// Number of requests the mock Proxmox has received.
    ///
    /// Used to prove that preflight rejection happens before any outbound request.
    pub fn proxmox_request_count(&self) -> usize {
        self.mock.request_count()
    }

    /// Script a task to complete with the given UPID and exit status.
    ///
    /// This sets up the mock to respond to task polling requests with the
    /// specified exit status. The first poll returns "running", and subsequent
    /// polls return "stopped" with the given exitstatus.
    pub fn script_task_completion(&self, upid: &str, exitstatus: &str) {
        // Parse the UPID to extract the node.
        let parts: Vec<&str> = upid.split(':').collect();
        let node = parts.get(1).expect("valid UPID with node");

        // Encode UPID for the path.
        let encoded_upid = upid.replace(':', "%3A");

        // First poll: running.
        let running_path = format!("/api2/json/nodes/{node}/tasks/{encoded_upid}/status");
        self.mock.replace_route(Route {
            path: Box::leak(running_path.into_boxed_str()),
            status: 200,
            body: Box::leak(
                format!(r#"{{"data":{{"status":"stopped","exitstatus":"{exitstatus}"}}}}"#)
                    .into_boxed_str(),
            )
            .as_bytes(),
        });
    }

    /// All requests the mock Proxmox has received.
    ///
    /// Used to assert that specific requests were issued (e.g., the DELETE).
    pub fn requests(&self) -> Vec<rust_proxmoxmcp_core::testing::RecordedRequest> {
        self.mock.requests()
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

/// Create a test handler configured with a specific guest.
///
/// # Parameters
/// - `vmid`: The guest VMID to configure
/// - `protected`: Whether the guest should be protected
pub async fn handler_with_guest(_vmid: u32, protected: bool) -> TestServer {
    let _tags = if protected { "protected" } else { "test" };
    let spec = TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_proxmox_destroy".to_owned(),
            "get_proxmox_change_set".to_owned(),
            "approve_proxmox_change_set".to_owned(),
            "apply_proxmox_change_set".to_owned(),
            // The operation's own tool, not just the generic handlers. These
            // tests planned a guest destroy while holding no `delete_vm`
            // scope, which the per-operation check now refuses — correctly:
            // that was the bypass it exists to close.
            "delete_vm".to_owned(),
            // The fixture guest is an LXC, and a guest destroy authorises
            // against its own type: delete_container, not delete_vm.
            "delete_container".to_owned(),
        ],
        guests: vec!["*".to_owned()],
    };

    // Build custom routes. Hardcode vmid 617 for simplicity.
    let routes = vec![
        Route {
            path: "/api2/json/nodes",
            status: 200,
            body:
                br#"{"data":[{"node":"pve2","status":"online"},{"node":"pve3","status":"online"}]}"#,
        },
        Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: if protected {
                br#"{"data":[{"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2","status":"running","tags":"protected"},{"id":"lxc/617","type":"lxc","vmid":617,"name":"test-guest-617","node":"pve2","status":"running","tags":"protected"}]}"#
            } else {
                br#"{"data":[{"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2","status":"running","tags":"protected"},{"id":"lxc/617","type":"lxc","vmid":617,"name":"test-guest-617","node":"pve2","status":"running","tags":"test"}]}"#
            },
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617",
            status: 200,
            body: br#"{"data":"UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:617:root@pam:"}"#,
        },
    ];

    TestServer::start_with_routes(spec, routes).await
}

/// Make an MCP tool call.
///
/// Uses McpClient with proper initialize handshake. McpClient is synchronous,
/// so we spawn_blocking to avoid deadlocking against the server on the same runtime.
///
/// # Errors
///
/// Returns an error if the tool call fails.
pub async fn call(
    server: &TestServer,
    tool: &str,
    args: serde_json::Value,
) -> Result<serde_json::Value, String> {
    call_with_token(server, &server.token, tool, args).await
}

/// Make an MCP tool call with a specific token.
///
/// # Errors
///
/// Returns an error if the tool call fails.
pub async fn call_with_token(
    server: &TestServer,
    token: &str,
    tool: &str,
    args: serde_json::Value,
) -> Result<serde_json::Value, String> {
    use mecmcp_transport::test_client::McpClient;

    let url = server.url.clone();
    let token = token.to_owned();
    let tool = tool.to_owned();

    tokio::task::spawn_blocking(move || {
        let client = McpClient::new(&url)
            .map_err(|e| format!("create client: {e}"))?
            .with_bearer(&token);
        let session_id = client
            .initialize()
            .map_err(|e| format!("initialize: {e}"))?;
        let result = client
            .tools_call(&session_id, &tool, args)
            .map_err(|e| format!("call: {e}"))?;

        eprintln!(
            "Full MCP result: {}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{result:?}"))
        );

        // Check if this is an error response
        let is_error = result
            .get("isError")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Extract the text content from the MCP response
        let text = result
            .get("content")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("text"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| format!("no result text, response: {result}"))?;

        if is_error {
            Err(text.to_owned())
        } else {
            serde_json::from_str(text).map_err(|e| format!("json parse: {e}"))
        }
    })
    .await
    .map_err(|e| format!("spawn_blocking: {e}"))?
}

/// Approve a change set as a second principal.
pub async fn approve_as_second_principal(server: &TestServer, change_set_id: &str) {
    approve_as_second_principal_for(server, change_set_id, "pve3", 617).await;
}

/// Approve a change set as a second principal for a specific cluster and vmid.
pub async fn approve_as_second_principal_for(
    server: &TestServer,
    change_set_id: &str,
    cluster: &str,
    vmid: u32,
) {
    call_with_token(
        server,
        &server.second_token,
        "approve_proxmox_change_set",
        serde_json::json!({
            "change_set_id": change_set_id,
            "cluster": cluster,
            "vmid": vmid
        }),
    )
    .await
    .expect("second principal approval should succeed");
}

impl TestServer {
    /// Simulate moving a guest to a different node (changes fingerprint).
    ///
    /// Updates the mock Proxmox's `/api2/json/cluster/resources` response to
    /// show the guest on a different node, which causes the fingerprint to change.
    /// Also invalidates the guest index cache so the next resolve sees the change.
    pub fn move_guest_to_node(&self, vmid: u32, new_node: &str) {
        // Replace the cluster/resources route with updated guest data.
        // The hardcoded guest 617 is moved to the specified node.
        let body = format!(
            r#"{{"data":[{{"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2","status":"running","tags":"protected"}},{{"id":"lxc/{}","type":"lxc","vmid":{},"name":"test-guest-{}","node":"{}","status":"running","tags":"test"}}]}}"#,
            vmid, vmid, vmid, new_node
        );

        self.mock.replace_route(Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: Box::leak(body.into_boxed_str()).as_bytes(),
        });

        // Invalidate the cache so the next resolve fetches the updated data.
        self.index.invalidate();
    }
}
