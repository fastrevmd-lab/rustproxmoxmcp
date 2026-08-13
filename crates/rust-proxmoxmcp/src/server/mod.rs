//! The MCP tool surface for release 0.1: reads only.

use mecmcp_auth::{CallerCtx, ScopeSet};
use mecmcp_server::{
    ResultFormat, ResultLimits, authorize_call, caller_from_extensions, filter_tools_for_scope,
    tool_error, tool_result,
};
use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Implementation, ListToolsResult, PaginatedRequestParams,
        ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use rust_proxmoxmcp_core::{
    ProxmoxGrant, Tier, catalog::read_tool, client::ProxmoxClient, inventory::ClusterInventory,
    resolve::GuestIndex, selector::GuestType, tier::WRITE_TOOLS,
};
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Result size limits for MCP tool responses.
const RESULT_LIMITS: ResultLimits = ResultLimits {
    max_text_bytes: 512 * 1024,
    max_json_bytes: 512 * 1024,
};

/// Every tool registered by this release. Kept sorted; asserted against the
/// catalog by a test so the two cannot drift.
pub const KNOWN_TOOLS: &[&str] = &[
    "get_cluster_status",
    "get_container_config",
    "get_container_ip",
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

/// Arguments for a storage-scoped read.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct StorageArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node name as reported by `get_nodes`.
    pub node: String,
    /// Storage backend name.
    pub storage: String,
}

/// Arguments for a task-scoped read.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TaskArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node name as reported by `get_nodes`.
    pub node: String,
    /// Proxmox task UPID.
    pub upid: String,
}

/// The MCP server.
#[derive(Clone)]
pub struct ProxmoxServer {
    #[allow(dead_code)]
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
            clusters: clusters.clone(),
            clients: clients.clone(),
            index: index.clone(),
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

/// Resolve the grant for a guest-addressed call.
///
/// Distinguishes two cases:
/// - `caller` is `None` (stdio path, no bearer token): returns the wildcard read-only grant
/// - `caller` is `Some` with `grant: None` (authenticated token that declared no scope): refuses
///
/// # Errors
///
/// Returns a `CallToolResult` error when an authenticated token carries no guest selector.
fn resolve_grant(caller: Option<&CallerCtx<ProxmoxGrant>>) -> Result<ProxmoxGrant, CallToolResult> {
    match caller {
        None => Ok(rust_proxmoxmcp_core::ProxmoxGrant::read_only()),
        Some(ctx) => ctx.grant.clone().ok_or_else(|| {
            tool_error(format!(
                "token '{}' carries no 'guests' selector; add one to tokens.json",
                ctx.token_name
            ))
        }),
    }
}

/// Derive a scope description from the caller's tool and device scopes.
fn scope_desc(caller: Option<&CallerCtx<ProxmoxGrant>>) -> &'static str {
    caller
        .map(|c| match (&c.tools, &c.devices) {
            (ScopeSet::Wildcard, ScopeSet::Wildcard) => "global",
            (ScopeSet::Wildcard, ScopeSet::Allowlist(_)) => "device-scoped",
            (ScopeSet::Allowlist(_), _) => "tool-scoped",
        })
        .unwrap_or("stdio")
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
        if let Err(error) = authorize_call(caller.as_ref(), tool, Some(cluster), WRITE_TOOLS) {
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
            let grant = match resolve_grant(caller.as_ref()) {
                Ok(grant) => grant,
                Err(error) => return error,
            };
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
                scope = scope_desc(caller.as_ref()),
                "proxmox read authorized"
            );
        }

        let borrowed: Vec<(&str, &str)> = params
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();

        let result = match client.get_json(entry.path, &borrowed, entry.query).await {
            Ok(mut value) => {
                // Apply type_filter if present
                if let Some(filter_type) = entry.type_filter
                    && let Some(array) = value.as_array_mut()
                {
                    array.retain(|item| {
                        item.get("type")
                            .and_then(|v| v.as_str())
                            .is_some_and(|t| t == filter_type.path_segment())
                    });
                }
                Ok(value)
            }
            Err(error) => Err(error),
        };

        match result {
            Ok(value) => tool_result(
                Ok::<_, String>(value),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }
}

#[tool_router(router = proxmox_tool_router, vis = "pub(crate)")]
impl ProxmoxServer {
    #[tool(
        name = "get_cluster_status",
        description = "Cluster quorum and node membership."
    )]
    async fn get_cluster_status(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read("get_cluster_status", &args.cluster, &[], None, &context)
            .await
    }

    #[tool(
        name = "get_nodes",
        description = "All nodes in the cluster with status and resource totals."
    )]
    async fn get_nodes(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read("get_nodes", &args.cluster, &[], None, &context)
            .await
    }

    #[tool(
        name = "get_node_status",
        description = "Detailed status for one node."
    )]
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

    #[tool(
        name = "get_vms",
        description = "All QEMU guests across the cluster, with node, status and tags."
    )]
    async fn get_vms(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read("get_vms", &args.cluster, &[], None, &context)
            .await
    }

    #[tool(
        name = "get_containers",
        description = "All LXC guests across the cluster, with node, status and tags."
    )]
    async fn get_containers(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read("get_containers", &args.cluster, &[], None, &context)
            .await
    }

    #[tool(
        name = "get_vm_config",
        description = "Configuration of one QEMU guest, including its Proxmox digest."
    )]
    async fn get_vm_config(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_vm_config",
            &args.cluster,
            &[],
            Some(args.vmid),
            &context,
        )
        .await
    }

    #[tool(
        name = "get_container_config",
        description = "Configuration of one LXC guest, including its Proxmox digest."
    )]
    async fn get_container_config(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_container_config",
            &args.cluster,
            &[],
            Some(args.vmid),
            &context,
        )
        .await
    }

    #[tool(
        name = "get_container_ip",
        description = "Network interfaces and addresses of one LXC guest."
    )]
    async fn get_container_ip(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        // This tool is LXC-only. We need to resolve the guest first to check its type.
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "get_container_ip",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return result,
        };

        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return error,
        };
        let authorized = match self
            .index
            .authorize(client, &args.cluster, args.vmid, &grant, Tier::Read)
            .await
        {
            Ok(authorized) => authorized,
            Err(error) => return tool_error(error),
        };

        let guest = authorized.guest();
        if guest.r#type != GuestType::Lxc {
            return tool_error(format!(
                "get_container_ip requires an LXC guest, but {} is a QEMU VM",
                args.vmid
            ));
        }

        let vmid_str = guest.vmid.to_string();
        let params = vec![("node", guest.node.as_str()), ("vmid", vmid_str.as_str())];

        tracing::info!(
            tool = "get_container_ip",
            cluster = args.cluster,
            vmid = guest.vmid,
            node = %guest.node,
            guest_name = %guest.name,
            tier = "read",
            protection = %authorized.protection().summary(),
            scope = scope_desc(caller.as_ref()),
            "proxmox read authorized"
        );

        let entry = read_tool("get_container_ip").expect("tool in catalog");
        match client.get_json(entry.path, &params, entry.query).await {
            Ok(value) => tool_result(
                Ok::<_, String>(value),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "get_guest_status",
        description = "Current runtime status of one guest."
    )]
    async fn get_guest_status(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_guest_status",
            &args.cluster,
            &[],
            Some(args.vmid),
            &context,
        )
        .await
    }

    #[tool(name = "list_snapshots", description = "Snapshots of one guest.")]
    async fn list_snapshots(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_snapshots",
            &args.cluster,
            &[],
            Some(args.vmid),
            &context,
        )
        .await
    }

    #[tool(
        name = "get_storage",
        description = "Storage backends visible to one node, with usage."
    )]
    async fn get_storage(
        &self,
        Parameters(args): Parameters<NodeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_storage",
            &args.cluster,
            &[("node", args.node.as_str())],
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "list_backups",
        description = "Backup archives on one storage backend."
    )]
    async fn list_backups(
        &self,
        Parameters(args): Parameters<StorageArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_backups",
            &args.cluster,
            &[
                ("node", args.node.as_str()),
                ("storage", args.storage.as_str()),
            ],
            None,
            &context,
        )
        .await
    }

    #[tool(name = "list_isos", description = "ISO images on one storage backend.")]
    async fn list_isos(
        &self,
        Parameters(args): Parameters<StorageArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_isos",
            &args.cluster,
            &[
                ("node", args.node.as_str()),
                ("storage", args.storage.as_str()),
            ],
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "list_templates",
        description = "Container templates on one storage backend."
    )]
    async fn list_templates(
        &self,
        Parameters(args): Parameters<StorageArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_templates",
            &args.cluster,
            &[
                ("node", args.node.as_str()),
                ("storage", args.storage.as_str()),
            ],
            None,
            &context,
        )
        .await
    }

    #[tool(name = "list_tasks", description = "Recent tasks on one node.")]
    async fn list_tasks(
        &self,
        Parameters(args): Parameters<NodeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_tasks",
            &args.cluster,
            &[("node", args.node.as_str())],
            None,
            &context,
        )
        .await
    }

    #[tool(name = "get_task_status", description = "Status of one task by UPID.")]
    async fn get_task_status(
        &self,
        Parameters(args): Parameters<TaskArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_task_status",
            &args.cluster,
            &[("node", args.node.as_str()), ("upid", args.upid.as_str())],
            None,
            &context,
        )
        .await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ProxmoxServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "rust-proxmoxmcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "Proxmox VE MCP server. Guest-addressed tools take (cluster, vmid); \
                 the server resolves the node itself because guests migrate.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<ProxmoxGrant>(&context.extensions);
        let all_tools = self.tool_router.list_all();
        let visible = filter_tools_for_scope(all_tools, caller, WRITE_TOOLS);
        Ok(ListToolsResult::with_all_items(visible))
    }
}

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

    #[test]
    fn every_known_tool_has_a_registered_handler() {
        // KNOWN_TOOLS is hand-maintained; the router is generated from #[tool]
        // attributes. Nothing else in the build makes them agree.
        let router = ProxmoxServer::proxmox_tool_router();
        let registered: std::collections::BTreeSet<String> = router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect();
        for name in KNOWN_TOOLS {
            assert!(
                registered.contains(*name),
                "{name} is in KNOWN_TOOLS but has no #[tool] handler"
            );
        }
        assert_eq!(
            registered.len(),
            KNOWN_TOOLS.len(),
            "router has tools absent from KNOWN_TOOLS"
        );
    }

    #[test]
    fn authenticated_token_without_grant_is_refused() {
        use mecmcp_auth::{ActorType, ScopeSet};

        // An authenticated caller (Some) with no grant (grant: None) must be refused.
        // This is the grantless-token case: a token that omits the 'grant' key in
        // tokens.json produces CallerCtx { grant: None, ... }.
        let grantless_caller = CallerCtx {
            token_name: "test-grantless-token".to_owned(),
            grant: None,
            tools: ScopeSet::Wildcard,
            devices: ScopeSet::Wildcard,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Agent,
            client_name: None,
        };

        let result = resolve_grant(Some(&grantless_caller));
        assert!(
            result.is_err(),
            "grantless authenticated token must be refused, not granted wildcard access"
        );

        // The error must name the token so the operator can find it in tokens.json.
        let error_result = result.expect_err("already checked is_err");
        let error_text = format!("{error_result:?}");
        assert!(
            error_text.contains("test-grantless-token"),
            "error message must name the token: {error_text}"
        );
        assert!(
            error_text.contains("guests"),
            "error message must mention 'guests' selector: {error_text}"
        );
    }

    #[test]
    fn stdio_path_gets_wildcard_read_grant() {
        // The stdio path (caller = None, no bearer token) gets the wildcard read grant.
        let grant = resolve_grant(None).expect("stdio path should succeed");
        assert_eq!(
            grant.guests.len(),
            1,
            "read_only grant should have one selector"
        );
        // The read_only grant is constructed as guests: ["*"], actions: [Read]
    }
}
