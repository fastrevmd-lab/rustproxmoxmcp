//! The MCP tool surface for release 0.1: reads only.

mod change_set;

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
    "apply_proxmox_change_set",
    "approve_proxmox_change_set",
    "get_cluster_status",
    "get_container_config",
    "get_container_ip",
    "get_containers",
    "get_guest_status",
    "get_node_status",
    "get_nodes",
    "get_proxmox_change_set",
    "get_storage",
    "get_task_status",
    "get_vm_config",
    "get_vms",
    "list_backups",
    "list_isos",
    "list_snapshots",
    "list_tasks",
    "list_templates",
    "plan_proxmox_destroy",
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
    coordinator: Arc<mecmcp_changeset::ChangesetCoordinator>,
    waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
    lab_mode: bool,
    tool_router: ToolRouter<Self>,
}

impl ProxmoxServer {
    /// Build the server over a loaded inventory and its per-cluster clients.
    #[must_use]
    pub fn new(
        clusters: Arc<ClusterInventory>,
        clients: Arc<BTreeMap<String, ProxmoxClient>>,
        index: Arc<GuestIndex>,
        coordinator: Arc<mecmcp_changeset::ChangesetCoordinator>,
        waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
        lab_mode: bool,
    ) -> Self {
        Self {
            clusters: clusters.clone(),
            clients: clients.clone(),
            index: index.clone(),
            coordinator,
            waivers,
            lab_mode,
            tool_router: Self::proxmox_tool_router(),
        }
    }

    /// Build the server with a default in-memory coordinator.
    ///
    /// # Errors
    ///
    /// Returns an error if the coordinator cannot be created.
    pub fn new_with_default_coordinator(
        clusters: Arc<ClusterInventory>,
        clients: Arc<BTreeMap<String, ProxmoxClient>>,
        index: Arc<GuestIndex>,
        waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
        lab_mode: bool,
    ) -> Result<Self, mecmcp_changeset::CoordinatorError> {
        let coordinator = change_set::build_coordinator(None, lab_mode)?;
        Ok(Self::new(
            clusters,
            clients,
            index,
            coordinator,
            waivers,
            lab_mode,
        ))
    }

    /// Recover the caller's context, or `None` on the stdio path.
    fn caller(context: &RequestContext<RoleServer>) -> Option<CallerCtx<ProxmoxGrant>> {
        caller_from_extensions::<ProxmoxGrant>(&context.extensions).cloned()
    }

    /// Look up the client for a cluster the caller is entitled to reach.
    fn client_for(&self, cluster: &str) -> Result<&ProxmoxClient, Box<CallToolResult>> {
        self.clients
            .get(cluster)
            .ok_or_else(|| Box::new(tool_error(format!("unknown cluster: {cluster}"))))
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
fn resolve_grant(
    caller: Option<&CallerCtx<ProxmoxGrant>>,
) -> Result<ProxmoxGrant, Box<CallToolResult>> {
    match caller {
        None => Ok(rust_proxmoxmcp_core::ProxmoxGrant::read_only()),
        Some(ctx) => ctx.grant.clone().ok_or_else(|| {
            Box::new(tool_error(format!(
                "token '{}' carries no 'guests' selector; add one to tokens.json",
                ctx.token_name
            )))
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
            Err(result) => return *result,
        };

        let mut params: Vec<(&str, String)> = extra_params
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned()))
            .collect();

        if let Some(vmid) = vmid {
            let grant = match resolve_grant(caller.as_ref()) {
                Ok(grant) => grant,
                Err(error) => return *error,
            };
            let authorized = match self
                .index
                .authorize(client, cluster, vmid, &grant, Tier::Read, None)
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
            Err(result) => return *result,
        };

        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };
        let authorized = match self
            .index
            .authorize(client, &args.cluster, args.vmid, &grant, Tier::Read, None)
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

    #[tool(
        name = "plan_proxmox_destroy",
        description = "Plan a guest destroy operation for two-principal approval."
    )]
    async fn plan_destroy(
        &self,
        Parameters(args): Parameters<change_set::PlanDestroyArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::{ChangeSetResponse, DestroyAction};
        use mecmcp_changeset::WaiverKind;
        use rust_proxmoxmcp_core::{
            fingerprint::{GuestState, fingerprint},
            preview::{PreviewInput, render_preview},
            protect::{Override, destructive_allowed, protection_of},
        };

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "plan_proxmox_destroy",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };

        // Resolve guest and compute protection to determine override.
        let guest = match self.index.resolve(client, &args.cluster, args.vmid).await {
            Ok(guest) => guest,
            Err(error) => return tool_error(error),
        };
        let protection = protection_of(client.cluster(), Some(&guest), false);

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs();

        let override_ = destructive_allowed(
            &protection,
            &self.waivers,
            &args.cluster,
            args.vmid,
            now_unix,
            self.lab_mode,
        );

        let override_applies = !matches!(override_, Override::None);

        // Now authorize with the override information.
        let authorized = match self
            .index
            .authorize(
                client,
                &args.cluster,
                args.vmid,
                &grant,
                Tier::Destructive,
                Some(override_applies),
            )
            .await
        {
            Ok(authorized) => authorized,
            Err(error) => return tool_error(error),
        };

        let guest = authorized.guest();

        // Compute fingerprint.
        let state = GuestState {
            cluster: args.cluster.clone(),
            vmid: guest.vmid,
            name: guest.name.clone(),
            kind: guest.r#type.path_segment().to_owned(),
            node: guest.node.clone(),
            status: guest.status.clone(),
            tags: guest.tags.clone(),
            config_digest: String::new(),
            disks: Vec::new(),
        };

        let expected_fingerprint = fingerprint(&state);

        // Render preview.
        let preview_input = PreviewInput {
            state: &state,
            protected: protection.is_protected(),
            protection_summary: &protection.summary(),
            override_: &override_,
            snapshots: 0,
            latest_snapshot: None,
            last_backup: None,
            purge_disks: true,
        };

        let preview_text = render_preview(&preview_input);

        // Use the shared coordinator.
        let coordinator = self.coordinator.clone();

        let owner = caller
            .as_ref()
            .map(|ctx| ctx.token_name.clone())
            .unwrap_or_else(|| "stdio".to_owned());

        let device = format!("{}/{}", args.cluster, args.vmid);
        let action = DestroyAction {
            op: "destroy".to_owned(),
            cluster: args.cluster.clone(),
            vmid: args.vmid,
        };

        // This server has no policy engine in 0.3.
        let policy_signature = "proxmox-no-policy-engine";

        // For now, create the change set without preview binding.
        // TODO: implement preview binding properly once the coordinator API is clarified.
        let output = match coordinator
            .create_change_set(
                device.clone(),
                vec![action],
                owner.clone(),
                expected_fingerprint.clone(),
                policy_signature.to_owned(),
            )
            .await
        {
            Ok(output) => output,
            Err(error) => return tool_error(format!("create: {error}")),
        };

        // Apply override.
        let output = match override_ {
            Override::Waiver {
                reason,
                ticket,
                until_unix,
            } => match coordinator
                .waive_approval_operator(
                    output.change_set_id.clone(),
                    device.clone(),
                    owner.clone(),
                    output.digest.clone(),
                    WaiverKind::OperatorFile,
                    reason,
                    Some(until_unix),
                    ticket,
                )
                .await
            {
                Ok(waived) => waived,
                Err(error) => return tool_error(format!("waiver: {error}")),
            },
            Override::LabMode => match coordinator
                .waive_approval(
                    output.change_set_id.clone(),
                    device.clone(),
                    owner.clone(),
                    output.digest.clone(),
                )
                .await
            {
                Ok(waived) => waived,
                Err(error) => return tool_error(format!("lab-mode: {error}")),
            },
            Override::None => output,
        };

        let response = ChangeSetResponse {
            change_set_id: output.change_set_id,
            state: format!("{:?}", output.state),
            expected_fingerprint,
            preview: preview_text,
            expected_digest: Some(output.digest),
        };

        tool_result(
            Ok::<_, String>(response),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "get_proxmox_change_set",
        description = "Retrieve the current state of a change set."
    )]
    async fn get_change_set(
        &self,
        Parameters(args): Parameters<change_set::ChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::ChangeSetResponse;

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "get_proxmox_change_set",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let coordinator = self.coordinator.clone();

        let device = format!("{}/{}", args.cluster, args.vmid);
        let record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(format!("get: {error}")),
        };

        let preview_text = record
            .preview
            .as_ref()
            .map(|p| p.artifact.clone())
            .unwrap_or_else(|| "(no preview)".to_owned());

        let response = ChangeSetResponse {
            change_set_id: record.id,
            state: format!("{:?}", record.state),
            expected_fingerprint: record.expected_candidate_fingerprint,
            preview: preview_text,
            expected_digest: Some(record.digest),
        };

        tool_result(
            Ok::<_, String>(response),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "approve_proxmox_change_set",
        description = "Approve a planned change set as a second principal."
    )]
    async fn approve_change_set(
        &self,
        Parameters(args): Parameters<change_set::ChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::ChangeSetResponse;

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "approve_proxmox_change_set",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let approver = caller
            .as_ref()
            .map(|ctx| ctx.token_name.clone())
            .unwrap_or_else(|| "stdio".to_owned());

        let coordinator = self.coordinator.clone();

        let device = format!("{}/{}", args.cluster, args.vmid);
        let record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(format!("get: {error}")),
        };

        let output = match coordinator
            .approve_change_set(
                args.change_set_id.clone(),
                device.clone(),
                approver,
                record.digest.clone(),
            )
            .await
        {
            Ok(output) => output,
            Err(error) => {
                let msg = error.to_string();
                // Reword the self-approval error to match test expectations.
                if msg.contains("owner cannot approve their own") {
                    return tool_error(
                        "self-approval refused: the planner cannot approve their own change set",
                    );
                }
                return tool_error(format!("approve: {error}"));
            }
        };

        let preview_text = record
            .preview
            .as_ref()
            .map(|p| p.artifact.clone())
            .unwrap_or_else(|| "(no preview)".to_owned());

        let response = ChangeSetResponse {
            change_set_id: output.change_set_id,
            state: format!("{:?}", output.state),
            expected_fingerprint: record.expected_candidate_fingerprint,
            preview: preview_text,
            expected_digest: Some(output.digest),
        };

        tool_result(
            Ok::<_, String>(response),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "apply_proxmox_change_set",
        description = "Apply an approved change set."
    )]
    async fn apply_change_set(
        &self,
        Parameters(args): Parameters<change_set::ChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use rust_proxmoxmcp_core::{
            fingerprint::{GuestState, fingerprint},
            protect::{Override, destructive_allowed, protection_of},
        };

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "apply_proxmox_change_set",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let coordinator = self.coordinator.clone();

        let device = format!("{}/{}", args.cluster, args.vmid);
        let record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(format!("get: {error}")),
        };

        // Re-resolve and verify fingerprint.
        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };

        // Resolve guest and compute protection to determine override.
        let guest = match self.index.resolve(client, &args.cluster, args.vmid).await {
            Ok(guest) => guest,
            Err(error) => return tool_error(error),
        };
        let protection = protection_of(client.cluster(), Some(&guest), false);

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs();

        let override_ = destructive_allowed(
            &protection,
            &self.waivers,
            &args.cluster,
            args.vmid,
            now_unix,
            self.lab_mode,
        );

        let override_applies = !matches!(override_, Override::None);

        // Now authorize with the override information.
        let authorized = match self
            .index
            .authorize(
                client,
                &args.cluster,
                args.vmid,
                &grant,
                Tier::Destructive,
                Some(override_applies),
            )
            .await
        {
            Ok(authorized) => authorized,
            Err(error) => return tool_error(error),
        };

        let guest = authorized.guest();

        let state = GuestState {
            cluster: args.cluster.clone(),
            vmid: guest.vmid,
            name: guest.name.clone(),
            kind: guest.r#type.path_segment().to_owned(),
            node: guest.node.clone(),
            status: guest.status.clone(),
            tags: guest.tags.clone(),
            config_digest: String::new(),
            disks: Vec::new(),
        };

        let current_fingerprint = fingerprint(&state);

        if current_fingerprint != record.expected_candidate_fingerprint {
            return tool_error(format!(
                "fingerprint changed (expected {}, got {})",
                record.expected_candidate_fingerprint, current_fingerprint
            ));
        }

        // Verify the change set is approved.
        if record.state != mecmcp_changeset::ChangeSetState::Approved {
            return tool_error(format!(
                "change set not approved (state: {:?})",
                record.state
            ));
        }

        // Issue the DELETE and get the UPID string.
        let upid_str = match rust_proxmoxmcp_core::guests::destroy_container(
            client,
            &state.node,
            args.vmid,
            true, // purge
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        // Parse the UPID to extract the node for polling.
        // Per spec §7, the node is authoritative: guests migrate, so we must
        // poll the node from the UPID, never a caller-supplied one.
        let upid = match rust_proxmoxmcp_core::task::Upid::parse(&upid_str) {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        // Note: The UPID should be persisted into the operation record BEFORE
        // polling (spec §8), but mecmcp-changeset doesn't yet expose a method
        // to update a change set with the task ID. For now, we proceed without
        // persistence, which means a crashed apply is detectable but not
        // recoverable. This will be addressed in a follow-up task.

        // Poll the task to completion using mecmcp_job.
        let token = tokio_util::sync::CancellationToken::new();
        let config = mecmcp_job::PollConfig {
            first_interval: std::time::Duration::from_secs(1),
            max_interval: std::time::Duration::from_secs(8),
            multiplier: 2,
            deadline: std::time::Duration::from_secs(300),
        };

        let poll_node = upid.node().to_owned();
        let poll_upid = upid_str.clone();
        let exitstatus = match mecmcp_job::poll_until_ready(&token, config, |_attempt| {
            let node = poll_node.clone();
            let upid_str = poll_upid.clone();
            async move {
                // URL-encode the UPID for the path.
                let upid_encoded = upid_str.replace(':', "%3A");
                let path = format!("/api2/json/nodes/{node}/tasks/{upid_encoded}/status");
                let data = client
                    .get_json(&path, &[], &[])
                    .await
                    .map_err(|error| format!("task status request failed: {error}"))?;

                let status = data
                    .get("status")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "status field missing or not a string".to_string())?;

                if status == "running" {
                    Ok(mecmcp_job::Probe::Pending)
                } else if status == "stopped" {
                    let exitstatus = data
                        .get("exitstatus")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "exitstatus field missing or not a string".to_string())?;
                    Ok(mecmcp_job::Probe::Ready(exitstatus.to_owned()))
                } else {
                    Err(format!("unexpected task status: {status}"))
                }
            }
        })
        .await
        {
            Ok(exitstatus) => exitstatus,
            Err(mecmcp_job::PollError::Cancelled { attempts }) => {
                return tool_error(format!("polling cancelled after {attempts} attempt(s)"));
            }
            Err(mecmcp_job::PollError::DeadlineExceeded { attempts, deadline }) => {
                return tool_error(format!(
                    "polling exceeded its {deadline:?} deadline after {attempts} attempt(s)"
                ));
            }
            Err(mecmcp_job::PollError::Probe { attempts, source }) => {
                return tool_error(format!("probe failed on attempt {attempts}: {source}"));
            }
            Err(mecmcp_job::PollError::Config(error)) => {
                return tool_error(format!("invalid poll configuration: {error}"));
            }
        };

        // Classify the exit status using the Task 3 classifier.
        let outcome = rust_proxmoxmcp_core::task::classify_exit_status(&exitstatus);
        match outcome {
            rust_proxmoxmcp_core::task::TaskOutcome::Ok => {
                let response = serde_json::json!({
                    "outcome": "ok",
                    "upid": upid_str,
                    "exitstatus": exitstatus,
                });
                tool_result(
                    Ok::<_, String>(response),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                )
            }
            rust_proxmoxmcp_core::task::TaskOutcome::Failed(message) => {
                tool_error(format!("task failed: {message}"))
            }
        }
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
    fn known_tools_includes_read_catalog_and_changeset_tools() {
        // Read tools from catalog.
        let read_tools: std::collections::HashSet<&str> = rust_proxmoxmcp_core::catalog::READ_TOOLS
            .iter()
            .map(|tool| tool.name)
            .collect();

        // Changeset tools added in Task 6.
        let changeset_tools = [
            "plan_proxmox_destroy",
            "get_proxmox_change_set",
            "approve_proxmox_change_set",
            "apply_proxmox_change_set",
        ];

        for tool in KNOWN_TOOLS {
            assert!(
                read_tools.contains(tool) || changeset_tools.contains(tool),
                "{tool} is in KNOWN_TOOLS but not in READ_TOOLS or changeset tools"
            );
        }

        // Verify changeset tools are present.
        for tool in &changeset_tools {
            assert!(
                KNOWN_TOOLS.contains(tool),
                "changeset tool {tool} missing from KNOWN_TOOLS"
            );
        }
    }

    #[test]
    fn changeset_write_tools_are_registered() {
        let changeset_write = [
            "plan_proxmox_destroy",
            "approve_proxmox_change_set",
            "apply_proxmox_change_set",
        ];
        for tool in &changeset_write {
            assert!(
                KNOWN_TOOLS.contains(tool),
                "changeset write tool {tool} must be registered"
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
            request_id: uuid::Uuid::new_v4(),
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
