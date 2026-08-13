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
    HttpShutdown, HttpTransportBuildError, HttpTransportConfig, LimitsConfig,
    MalformedArgumentsPolicy, TargetField, ToolScopePreflight,
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
    shutdown: CancellationToken,
) -> Result<(axum::Router, HttpShutdown), HttpTransportBuildError> {
    let identity = TransportIdentity::new(
        "rust-proxmoxmcp",
        "proxmox",
        "rust-proxmoxmcp",
        ["cluster"],
    );
    let mut config = HttpTransportConfig::new(
        identity,
        limits,
        HostOriginPolicy::enforced(allowed_hosts, allowed_origins),
        shutdown,
    )
    .with_metrics(enable_metrics);

    if let Some(store_file) = token_store {
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
        config = config.with_bearer(boundary);
    }

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
        assert!(preflight
            .check(&call("get_nodes", "pve3"), scopes(&clusters, &tools))
            .is_ok());
    }

    #[test]
    fn refuses_a_cluster_outside_the_device_scope() {
        let clusters = ScopeSet::Allowlist(vec!["pve3".to_owned()]);
        let tools = ScopeSet::Wildcard;
        let preflight = build_preflight();
        assert!(preflight
            .check(&call("get_nodes", "pve2"), scopes(&clusters, &tools))
            .is_err());
    }

    #[test]
    fn a_tool_wildcard_does_not_reach_a_write_tool() {
        // The registry is complete from 0.1 precisely so this holds the day
        // release 0.2 registers delete_vm.
        let clusters = ScopeSet::Wildcard;
        let tools = ScopeSet::Wildcard;
        let preflight = build_preflight();
        assert!(preflight
            .check(&call("delete_vm", "pve3"), scopes(&clusters, &tools))
            .is_err());
    }

    #[test]
    fn malformed_arguments_are_refused_not_deferred() {
        let clusters = ScopeSet::Wildcard;
        let tools = ScopeSet::Wildcard;
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call",
                        "params":{"name":"get_nodes","arguments":"not-an-object"}}"#;
        let preflight = build_preflight();
        assert!(preflight
            .check(body, scopes(&clusters, &tools))
            .is_err());
    }
}
