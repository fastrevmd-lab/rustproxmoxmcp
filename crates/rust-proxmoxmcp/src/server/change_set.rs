//! Destructive change-set lifecycle for Proxmox guests.
//!
//! Provides the plan → approve → apply workflow with two-principal control,
//! fingerprint verification, and operator waiver support. The state machine,
//! persistence, and digest validation come from `mecmcp-changeset`; this module
//! handles Proxmox-specific concerns: protection evaluation, fingerprint binding,
//! preview generation, and guest resolution.

use crate::server::ProxmoxServer;
use mecmcp_changeset::{ChangesetCoordinator, CoordinatorError, OperationLimits, WaiverKind};
use mecmcp_server::{authorize_call, tool_error, tool_result, ResultFormat, ResultLimits};
use rmcp::{
    RoleServer,
    handler::server::wrapper::Parameters,
    model::CallToolResult,
    service::RequestContext,
    tool, tool_router,
};
use rust_proxmoxmcp_core::{
    Tier,
    fingerprint::{GuestState, fingerprint},
    preview::{PreviewInput, render_preview},
    protect::{Override, destructive_allowed, protection_of},
    selector::GuestType,
    tier::WRITE_TOOLS,
    waiver::WaiverFile,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// Arguments for planning a destroy operation.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PlanDestroyArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id.
    pub vmid: u32,
}

/// Arguments for retrieving or manipulating a change set.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ChangeSetArgs {
    /// Change set identifier.
    pub change_set_id: String,
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id.
    pub vmid: u32,
}

/// Output from plan/get operations.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ChangeSetResponse {
    /// Change set identifier.
    pub change_set_id: String,
    /// Current state.
    pub state: String,
    /// Expected fingerprint at plan time.
    pub expected_fingerprint: String,
    /// Server-rendered preview of the operation.
    pub preview: String,
    /// Approval digest for the approver to provide.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<String>,
}

/// Action for a destroy operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DestroyAction {
    /// Operation type.
    pub op: String,
    /// Cluster name.
    pub cluster: String,
    /// Guest VMID.
    pub vmid: u32,
}

/// Build a coordinator for change-set lifecycle operations.
///
/// # Errors
///
/// Returns an error if the coordinator cannot load existing state.
pub(crate) fn build_coordinator(
    state_path: Option<&std::path::Path>,
    lab_mode: bool,
) -> Result<Arc<ChangesetCoordinator>, CoordinatorError> {
    let limits = OperationLimits {
        max_operations: 100,
        max_change_sets: 100,
        max_actions_per_set: 10,
        max_change_set_bytes: 1024 * 1024,
        max_state_bytes: 10 * 1024 * 1024,
        max_targets_per_set: 10,
        max_preview_bytes: 256 * 1024,
    };
    let approval_ttl = Duration::from_secs(3600);
    let coordinator = ChangesetCoordinator::load(state_path, limits, approval_ttl, lab_mode)?;
    Ok(Arc::new(coordinator))
}

/// Proxmox has no policy engine compiled in 0.3.
///
/// This constant signature documents the fact in every change-set record. A
/// fabricated signature would be false evidence in a record whose purpose is
/// evidence.
pub(crate) const POLICY_SIGNATURE: &str = "proxmox-no-policy-engine";

/// Result size limits for change-set tools.
pub(crate) const CHANGESET_LIMITS: ResultLimits = ResultLimits {
    max_text_bytes: 256 * 1024,
    max_json_bytes: 256 * 1024,
};

// Tool handlers are in mod.rs, integrated with the main proxmox_tool_router.
// This module provides the types and helper functions.
    #[tool(
        name = "plan_proxmox_destroy",
        description = "Plan a destroy operation for a Proxmox guest with fingerprint binding."
    )]
    async fn plan_proxmox_destroy(
        &self,
        Parameters(args): Parameters<PlanDestroyArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
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

        // Resolve the guest
        let grant = match crate::server::resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };

        let authorized = match self
            .index
            .authorize(client, &args.cluster, args.vmid, &grant, Tier::Destructive)
            .await
        {
            Ok(authorized) => authorized,
            Err(error) => return tool_error(error),
        };

        let guest = authorized.guest();
        let cluster_def = match self.clusters.get(&args.cluster) {
            Ok(c) => c,
            Err(error) => return tool_error(error.to_string()),
        };

        // Build GuestState for fingerprinting
        let state = GuestState {
            cluster: args.cluster.clone(),
            vmid: guest.vmid,
            name: guest.name.clone(),
            kind: match guest.r#type {
                GuestType::Qemu => "qemu".to_owned(),
                GuestType::Lxc => "lxc".to_owned(),
            },
            node: guest.node.clone(),
            status: guest.status.clone(),
            tags: guest.tags.clone(),
            config_digest: "placeholder".to_owned(), // TODO: Task 7 fetches real digest
            disks: vec![], // TODO: Task 7 fetches real disks
        };

        let fp = fingerprint(&state);

        // Evaluate protection
        let protection = protection_of(&cluster_def, Some(guest), false);
        // TODO: Task 7 loads real waivers file
        let waivers = WaiverFile::empty();
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is before unix epoch")
            .as_secs();

        let override_ = destructive_allowed(
            &protection,
            &waivers,
            &args.cluster,
            args.vmid,
            now_unix,
            false, // TODO: lab_mode from coordinator
        );

        // Refuse if protected with no override
        if protection.is_protected() && matches!(override_, Override::None) {
            return tool_error(format!(
                "guest is protected ({}), and no waiver is available",
                protection.summary()
            ));
        }

        // Render preview
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
        let preview = render_preview(&preview_input);

        // Create the change set
        let owner = caller
            .as_ref()
            .map(|c| c.token_name.clone())
            .unwrap_or_else(|| "stdio".to_owned());

        let device = format!("{}/{}", args.cluster, args.vmid);
        let action = DestroyAction {
            op: "destroy".to_owned(),
            cluster: args.cluster.clone(),
            vmid: args.vmid,
        };

        let coordinator = match build_coordinator(None, false) {
            Ok(c) => c,
            Err(error) => return tool_error(error.to_string()),
        };

        let output = match coordinator
            .create_change_set(device, vec![action], owner.clone(), fp.clone(), POLICY_SIGNATURE.to_owned())
            .await
        {
            Ok(output) => output,
            Err(error) => return tool_error(error.to_string()),
        };

        // Waive approval based on override
        let final_output = match override_ {
            Override::Waiver { reason, ticket, until_unix } => {
                match coordinator
                    .waive_approval_operator(
                        output.change_set_id.clone(),
                        output.device.clone(),
                        owner,
                        output.digest.clone(),
                        WaiverKind::OperatorFile,
                        reason,
                        Some(until_unix),
                        ticket,
                    )
                    .await
                {
                    Ok(waived) => waived,
                    Err(error) => return tool_error(error.to_string()),
                }
            }
            Override::LabMode => {
                match coordinator
                    .waive_approval(
                        output.change_set_id.clone(),
                        output.device.clone(),
                        owner,
                        output.digest.clone(),
                    )
                    .await
                {
                    Ok(waived) => waived,
                    Err(error) => return tool_error(error.to_string()),
                }
            }
            Override::None => output,
        };

        let response = ChangeSetResponse {
            change_set_id: final_output.change_set_id,
            state: format!("{:?}", final_output.state),
            expected_fingerprint: fp,
            preview,
            expected_digest: Some(final_output.digest),
        };

        tool_result(
            Ok::<_, String>(&response),
            ResultFormat::PrettyJson,
            CHANGESET_LIMITS,
        )
    }

    #[tool(
        name = "get_proxmox_change_set",
        description = "Retrieve the status and preview of a change set."
    )]
    async fn get_proxmox_change_set(
        &self,
        Parameters(args): Parameters<ChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "get_proxmox_change_set",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let device = format!("{}/{}", args.cluster, args.vmid);
        let coordinator = match build_coordinator(None, false) {
            Ok(c) => c,
            Err(error) => return tool_error(error.to_string()),
        };

        let record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(error.to_string()),
        };

        let response = ChangeSetResponse {
            change_set_id: record.id,
            state: format!("{:?}", record.state),
            expected_fingerprint: record.expected_candidate_fingerprint,
            preview: record
                .preview
                .map(|p| p.artifact)
                .unwrap_or_else(|| "(no preview)".to_owned()),
            expected_digest: Some(record.digest),
        };

        tool_result(
            Ok::<_, String>(&response),
            ResultFormat::PrettyJson,
            CHANGESET_LIMITS,
        )
    }

    #[tool(
        name = "approve_proxmox_change_set",
        description = "Approve a change set as a second principal."
    )]
    async fn approve_proxmox_change_set(
        &self,
        Parameters(args): Parameters<ChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
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
            .map(|c| c.token_name.clone())
            .unwrap_or_else(|| "stdio-approver".to_owned());

        let device = format!("{}/{}", args.cluster, args.vmid);
        let coordinator = match build_coordinator(None, false) {
            Ok(c) => c,
            Err(error) => return tool_error(error.to_string()),
        };

        // Get the record first to retrieve its digest
        let record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(error.to_string()),
        };

        let output = match coordinator
            .approve_change_set(
                args.change_set_id.clone(),
                device,
                approver,
                record.digest,
            )
            .await
        {
            Ok(output) => output,
            Err(error) => return tool_error(error.to_string()),
        };

        let response = ChangeSetResponse {
            change_set_id: output.change_set_id,
            state: format!("{:?}", output.state),
            expected_fingerprint: "".to_owned(),
            preview: "(approved)".to_owned(),
            expected_digest: None,
        };

        tool_result(
            Ok::<_, String>(&response),
            ResultFormat::PrettyJson,
            CHANGESET_LIMITS,
        )
    }

    #[tool(
        name = "apply_proxmox_change_set",
        description = "Apply an approved change set, verifying fingerprint matches."
    )]
    async fn apply_proxmox_change_set(
        &self,
        Parameters(args): Parameters<ChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "apply_proxmox_change_set",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let device = format!("{}/{}", args.cluster, args.vmid);
        let coordinator = match build_coordinator(None, false) {
            Ok(c) => c,
            Err(error) => return tool_error(error.to_string()),
        };

        let record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(error.to_string()),
        };

        // Check approval
        if record.approval.is_none() {
            return tool_error("change set has not been approved");
        }

        // Verify fingerprint
        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let grant = match crate::server::resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };

        let authorized = match self
            .index
            .authorize(client, &args.cluster, args.vmid, &grant, Tier::Destructive)
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
            kind: match guest.r#type {
                GuestType::Qemu => "qemu".to_owned(),
                GuestType::Lxc => "lxc".to_owned(),
            },
            node: guest.node.clone(),
            status: guest.status.clone(),
            tags: guest.tags.clone(),
            config_digest: "placeholder".to_owned(),
            disks: vec![],
        };

        let current_fp = fingerprint(&state);
        if current_fp != record.expected_candidate_fingerprint {
            return tool_error("fingerprint changed after approval; guest may have moved or been reconfigured");
        }

        // Task 7 will add the real destroy operation here.
        // For now, use a minimal DeviceTransaction that satisfies the trait.
        let response = serde_json::json!({
            "change_set_id": record.id,
            "state": "Applied",
            "message": "placeholder apply (Task 7 adds real destroy)"
        });

        tool_result(
            Ok::<_, String>(&response),
            ResultFormat::PrettyJson,
            CHANGESET_LIMITS,
        )
    }
}

