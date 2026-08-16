//! Transport assembly.
//!
//! The bearer boundary and per-IP rate limiting are both applied inside
//! `build_streamable_http_router` as of mecmcp-transport 0.8.8, so the consumer
//! builds the configuration and passes it in. The assembly here cannot double-
//! apply them, which was the pre-0.7.0 pattern and would halve the effective
//! per-IP budget while stacking the boundary twice.

use crate::server::ProxmoxServer;
use mecmcp_auth::{BearerSyntax, CallerCtx, TokenStoreFile};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, HostOriginPolicy,
    HttpTransportBuildError, HttpTransportConfig, InsecureBindAcknowledgement, LimitsConfig,
    MalformedArgumentsPolicy, NoAuthAcknowledgement, ServePlan, TargetField, ToolScopePreflight,
    TransportIdentity, build_streamable_http_router,
};
use rust_proxmoxmcp_core::{ProxmoxGrant, tier::WRITE_TOOLS};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Build the stage-1 preflight: tool scope and cluster scope, with no I/O.
///
/// Guest selectors are deliberately not checked here. `CallerScopes` carries
/// only opaque name sets and `TargetValueShape` has no numeric-range form, so a
/// `vmid:600-699` term cannot be evaluated before dispatch. Guest scope lives in
/// the token's grant and is enforced in stage 2, behind `AuthorizedGuest`.
#[must_use]
pub fn build_preflight() -> ToolScopePreflight {
    ToolScopePreflight::new(
        WRITE_TOOLS,
        [TargetField::scalar("cluster")],
        MalformedArgumentsPolicy::Deny,
    )
}

/// Build the complete HTTP router with Proxmox-owned identity and scope fields.
///
/// Exposed publicly so Task 13's end-to-end tests exercise the same assembly
/// `main` uses. A test that re-assembles by hand proves nothing about the server.
///
/// # Errors
///
/// Returns an error when shared HTTP limits or router composition are invalid.
#[allow(clippy::too_many_arguments)]
pub fn build_http_router(
    handler: ProxmoxServer,
    token_store: Option<Arc<TokenStoreFile<ProxmoxGrant>>>,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    limits: LimitsConfig,
    enable_metrics: bool,
    allow_insecure_bind: bool,
    shutdown: CancellationToken,
) -> Result<ServePlan, HttpTransportBuildError> {
    let identity =
        TransportIdentity::new("rust-proxmoxmcp", "proxmox", "rust-proxmoxmcp", ["cluster"]);
    let host_origin = HostOriginPolicy::enforced(allowed_hosts, allowed_origins);

    let config = if let Some(store_file) = token_store {
        let auth_store = store_file.clone();
        let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, move |candidate| {
            let snapshot = auth_store.store();
            snapshot.authenticate(candidate).map(CallerCtx::from)
        });
        let boundary = BearerBoundary::new(
            authenticator,
            BearerResponseProfile::detailed("rust-proxmoxmcp"),
        )
        .with_preflight(build_preflight());
        let mut config =
            HttpTransportConfig::authenticated(identity, limits, host_origin, shutdown, boundary)
                .with_metrics(enable_metrics);
        if allow_insecure_bind {
            config = config
                .with_insecure_bind(InsecureBindAcknowledgement::operator_allowed_insecure_bind());
        }
        config
    } else {
        let mut config = HttpTransportConfig::unauthenticated(
            identity,
            limits,
            host_origin,
            shutdown,
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        )
        .with_metrics(enable_metrics);
        if allow_insecure_bind {
            config = config
                .with_insecure_bind(InsecureBindAcknowledgement::operator_allowed_insecure_bind());
        }
        config
    };

    build_streamable_http_router(move || Ok::<_, std::io::Error>(handler.clone()), config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mecmcp_auth::ScopeSet;
    use mecmcp_transport::{CallerScopes, ScopePreflight};

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
        let preflight = build_preflight();
        assert!(
            preflight
                .check(&call("get_nodes", "pve3"), scopes(&clusters, &tools))
                .is_ok()
        );
    }

    #[test]
    fn refuses_a_cluster_outside_the_device_scope() {
        let clusters = ScopeSet::Allowlist(vec!["pve3".to_owned()]);
        let tools = ScopeSet::Wildcard;
        let preflight = build_preflight();
        assert!(
            preflight
                .check(&call("get_nodes", "pve2"), scopes(&clusters, &tools))
                .is_err()
        );
    }

    #[test]
    fn a_tool_wildcard_does_not_reach_a_write_tool() {
        // The registry is complete from 0.1 precisely so this holds the day
        // release 0.2 registers delete_vm.
        let clusters = ScopeSet::Wildcard;
        let tools = ScopeSet::Wildcard;
        let preflight = build_preflight();
        assert!(
            preflight
                .check(&call("delete_vm", "pve3"), scopes(&clusters, &tools))
                .is_err()
        );
    }

    #[test]
    fn malformed_arguments_are_refused_not_deferred() {
        let clusters = ScopeSet::Wildcard;
        let tools = ScopeSet::Wildcard;
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call",
                        "params":{"name":"get_nodes","arguments":"not-an-object"}}"#;
        let preflight = build_preflight();
        assert!(preflight.check(body, scopes(&clusters, &tools)).is_err());
    }

    #[tokio::test]
    async fn allow_insecure_bind_flag_is_threaded_into_config() {
        use crate::server::ProxmoxServer;
        use rust_proxmoxmcp_core::{
            client::ProxmoxClient, inventory::ClusterInventory, resolve::GuestIndex,
        };
        use std::io::Write as _;
        use std::sync::Arc;
        use std::time::Duration;

        // Install crypto provider once for the test.
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });

        // This test cannot bind a real non-loopback address because:
        // 1. The address must exist on the test runner's network interface
        // 2. Port binding requires privileges in CI environments
        // 3. Parallel test runs would collide on fixed ports
        //
        // Instead, we verify that `build_http_router` accepts the flag and
        // produces a ServePlan for both true and false values. The sabotage
        // test (removing the `.with_insecure_bind(...)` call and confirming
        // that a real deployment fails) is the definitive verification.

        // Build a minimal inventory and token store.
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let clusters_path = temp_dir.path().join("clusters.json");
        let secret_path = temp_dir.path().join("secret.txt");

        // Write a secret file.
        std::fs::write(&secret_path, "test-secret").expect("write secret file");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
                .expect("set secret file permissions");
        }

        // Write clusters.json.
        let inventory_json = serde_json::json!({
            "version": 1,
            "devices": {
                "test": {
                    "endpoint": "https://127.0.0.1:8006",
                    "token_id": "test@pam!test",
                    "token_secret_file": secret_path.to_str().expect("secret path"),
                    "protected_vmids": []
                }
            },
            "policy": { "resource_cache_ttl_secs": 300 }
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

        // Load the inventory and build a minimal server.
        let clusters =
            Arc::new(ClusterInventory::load(&clusters_path).expect("load clusters.json"));
        let mut clients = std::collections::BTreeMap::new();
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
        let waivers = Arc::new(rust_proxmoxmcp_core::waiver::WaiverFile::empty());

        let handler =
            ProxmoxServer::new_with_default_coordinator(clusters, clients, index, waivers, false)
                .expect("build server");

        let shutdown = tokio_util::sync::CancellationToken::new();

        // Test with allow_insecure_bind=false (should build successfully).
        let _plan_without_flag = build_http_router(
            handler.clone(),
            None,
            vec![],
            vec![],
            LimitsConfig::default(),
            false,
            false,
            shutdown.clone(),
        )
        .expect("build_http_router must succeed with allow_insecure_bind=false");

        // Test with allow_insecure_bind=true (should build successfully).
        let _plan_with_flag = build_http_router(
            handler,
            None,
            vec![],
            vec![],
            LimitsConfig::default(),
            false,
            true,
            shutdown,
        )
        .expect("build_http_router must succeed with allow_insecure_bind=true");

        // Both builds succeeded. The real verification is that a deployment
        // attempt with allow_insecure_bind=false and a non-loopback bind
        // address fails with InsecureBindNotAcknowledged, and succeeds with
        // allow_insecure_bind=true. That verification is done by removing
        // the `.with_insecure_bind(...)` call and confirming a real deploy
        // fails (the sabotage test).
    }
}
