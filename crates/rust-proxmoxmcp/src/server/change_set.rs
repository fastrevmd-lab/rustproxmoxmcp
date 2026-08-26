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

/// Arguments for planning a guest-agent command.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PlanExecArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id. QEMU only: Proxmox has no LXC exec endpoint.
    pub vmid: u32,
    /// Argument vector, e.g. `["systemctl", "status", "nginx"]`.
    ///
    /// A list rather than a shell line: Proxmox passes it to the agent as
    /// separate arguments, so nothing re-splits it and an argument containing
    /// a space stays one argument. There is no shell, so pipes, redirection
    /// and globbing do not apply -- run a shell explicitly if you need them.
    pub command: Vec<String>,
}

/// Arguments for planning a destroy operation.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PlanDestroyArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id.
    pub vmid: u32,
    /// Which destructive operation to plan.
    ///
    /// `destroy_guest` (the default, and what 0.3 planned),
    /// `delete_snapshot`, `rollback_snapshot`, `delete_backup`, `delete_iso`,
    /// or `restore_backup`.
    ///
    /// Defaults to `destroy_guest` so a caller written against 0.3 keeps
    /// working: this argument did not exist, and every plan meant a destroy.
    #[serde(default = "default_destructive_op")]
    pub op: String,
    /// Snapshot name, for `delete_snapshot` and `rollback_snapshot`.
    #[serde(default)]
    pub snapname: Option<String>,
    /// Storage backend, for `delete_backup` and `delete_iso`.
    #[serde(default)]
    pub storage: Option<String>,
    /// Volume id, for `delete_backup`, `delete_iso` and `restore_backup`.
    #[serde(default)]
    pub volid: Option<String>,
    /// Node whose storage holds the volume, for `delete_backup` and
    /// `delete_iso`.
    ///
    /// Required for those, because `local` is node-local: the same volid on
    /// two nodes names two different volumes.
    #[serde(default)]
    pub storage_node: Option<String>,
}

/// What a plan means when the caller does not say.
fn default_destructive_op() -> String {
    "destroy_guest".to_owned()
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

/// Action for a destructive operation.
///
/// `op` is the discriminant and the remaining fields are its parameters, absent
/// when the operation does not take them. Serialised into the change set's
/// `actions`, so the digest covers exactly what will be executed — an apply
/// that dispatched on anything not in here could act on something the approver
/// never saw.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DestroyAction {
    /// Operation type.
    pub op: String,
    /// Cluster name.
    pub cluster: String,
    /// Guest VMID.
    pub vmid: u32,
    /// Snapshot name, for the snapshot operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapname: Option<String>,
    /// Storage backend, for the volume operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
    /// Volume id, for the volume operations and restore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volid: Option<String>,
    /// Argument vector, for `guest_exec`.
    ///
    /// Held as a list rather than a string so the words an approver reviewed
    /// are the words that run. Joining and re-splitting would let an argument
    /// containing a space become two.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// Node the storage lives on, for the volume operations.
    ///
    /// Recorded rather than derived from the guest at apply. `local` is
    /// node-local storage, so `local:backup/x` on pve2 and on pve3 are
    /// different volumes that happen to share a name. Deriving the node from
    /// whichever guest the vmid names could delete the same-named volume on
    /// the wrong host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_node: Option<String>,
}

/// Build a coordinator for change-set lifecycle operations.
///
/// # Errors
///
/// Returns an error if the coordinator cannot load existing state.
pub(crate) fn build_coordinator(
    state_path: Option<&std::path::Path>,
    lab_mode: bool,
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
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
    let mut coordinator = ChangesetCoordinator::load(state_path, limits, approval_ttl, lab_mode)?;
    if let Some(recorder) = evidence {
        coordinator = coordinator.with_evidence(recorder);
    }
    Ok(Arc::new(coordinator))
}

// Tool handlers are in mod.rs, integrated with the main proxmox_tool_router.
// This module provides the types and helper functions.
