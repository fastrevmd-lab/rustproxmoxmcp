//! Destructive change-set lifecycle for Proxmox guests.
//!
//! Provides the plan → approve → apply workflow with two-principal control,
//! fingerprint verification, and operator waiver support. The state machine,
//! persistence, and digest validation come from `mecmcp-changeset`; this module
//! handles Proxmox-specific concerns: protection evaluation, fingerprint binding,
//! preview generation, and guest resolution.

use mecmcp_changeset::{ChangesetCoordinator, CoordinatorError, OperationLimits};
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

// Tool handlers are in mod.rs, integrated with the main proxmox_tool_router.
// This module provides the types and helper functions.
