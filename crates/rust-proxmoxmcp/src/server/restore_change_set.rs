//! Change-set lifecycle for restoring a backup archive into a **new** VMID.
//!
//! Mirrors `change_set.rs`'s destroy/restore change set -- plan, approve,
//! apply, with two-principal control and a fingerprint that refuses an apply
//! against state that changed since the plan -- but for a target that does
//! not exist yet. `restore_backup` (same VMID) overwrites a guest this server
//! can resolve and authorize against; this operation cannot use that guest
//! resolution path at all, because there is no guest there until the restore
//! runs.
//!
//! What replaces guest resolution is a vacancy check: the destination VMID
//! must be free of any guest, not pinned in `clusters.json`, and inside the
//! caller's guest scope, all checked before a plan is recorded and re-checked
//! before an apply dispatches the restore. `get_proxmox_change_set` and
//! `approve_proxmox_change_set` are reused unmodified: both key purely on
//! `(change_set_id, cluster, vmid)` and never resolve a guest, so a "vmid"
//! that means "the destination of a restore" rather than "an existing guest"
//! does not change what either of them does.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Arguments for planning a restore into a new VMID.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PlanRestoreNewVmidArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node to restore onto. Required: there is no guest to resolve one
    /// from, and `local` storage is node-local, so the node is part of where
    /// the archive named by `volid` can even be read from.
    pub node: String,
    /// VMID for the restored guest. Must be free, unpinned, and within the
    /// token's guest scope.
    pub target_vmid: u32,
    /// Guest type the archive restores as: `qemu` or `lxc`.
    ///
    /// There is no existing guest to read this from, unlike `restore_backup`,
    /// which infers it from the VMID being overwritten. The archive's own
    /// filename conventionally encodes it (`vzdump-qemu-...` versus
    /// `vzdump-lxc-...`), but that convention is not load-bearing anywhere
    /// else in this codebase and a custom-named archive would not follow it,
    /// so this is asked for explicitly rather than parsed out of a filename.
    pub kind: String,
    /// Backup archive volid, e.g. `local:backup/vzdump-qemu-100-....vma.zst`.
    pub volid: String,
}

/// Action for a restore-into-new-vmid change.
///
/// As with `change_set::DestroyAction`, this is what the change-set digest
/// covers and what `apply_restore_new_vmid` dispatches on -- never the raw
/// plan arguments, which a caller could resubmit differently between plan and
/// apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RestoreNewVmidAction {
    pub cluster: String,
    pub node: String,
    pub target_vmid: u32,
    pub kind: String,
    pub volid: String,
}

/// Build and validate the action a restore-new-vmid plan will record.
///
/// # Errors
///
/// Returns a human-readable message for a caller-facing tool error.
pub(crate) fn build_restore_new_vmid_action(
    args: &PlanRestoreNewVmidArgs,
) -> Result<RestoreNewVmidAction, String> {
    if args.kind != "qemu" && args.kind != "lxc" {
        return Err(format!("kind must be 'qemu' or 'lxc', got '{}'", args.kind));
    }

    rust_proxmoxmcp_core::guests::validate_path_segment(&args.node, "node")
        .map_err(|error| format!("node refused: {error}"))?;

    rust_proxmoxmcp_core::guests::validate_volid_kind(&args.volid, "backup")
        .map_err(|error| error.to_string())?;

    Ok(RestoreNewVmidAction {
        cluster: args.cluster.clone(),
        node: args.node.clone(),
        target_vmid: args.target_vmid,
        kind: args.kind.clone(),
        volid: args.volid.clone(),
    })
}

/// Render the preview an approver reviews for a restore-into-new-vmid action.
pub(crate) fn render_restore_new_vmid_preview(action: &RestoreNewVmidAction) -> String {
    format!(
        "RESTORE INTO NEW VMID {} on cluster '{}', node '{}'\n  \
         Creates a {} guest from the archive '{}'. The VMID must still be free when this \
         is applied -- if something now occupies it, the apply is refused rather than \
         overwriting it.",
        action.target_vmid, action.cluster, action.node, action.kind, action.volid
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> PlanRestoreNewVmidArgs {
        PlanRestoreNewVmidArgs {
            cluster: "pve3".to_owned(),
            node: "pve2".to_owned(),
            target_vmid: 650,
            kind: "qemu".to_owned(),
            volid: "local:backup/vzdump-qemu-100-2024_01_01-00_00_00.vma.zst".to_owned(),
        }
    }

    #[test]
    fn a_well_formed_plan_builds_an_action() {
        let action = build_restore_new_vmid_action(&args()).expect("builds");
        assert_eq!(action.target_vmid, 650);
        assert_eq!(action.kind, "qemu");
    }

    #[test]
    fn an_unknown_kind_is_refused() {
        let mut a = args();
        a.kind = "docker".to_owned();
        let error = build_restore_new_vmid_action(&a).expect_err("refused");
        assert!(error.contains("qemu"), "{error}");
    }

    #[test]
    fn a_non_backup_volid_is_refused() {
        let mut a = args();
        a.volid = "local:iso/debian.iso".to_owned();
        let error = build_restore_new_vmid_action(&a).expect_err("refused");
        assert!(error.contains("backup"), "{error}");
    }

    #[test]
    fn an_unusable_node_segment_is_refused() {
        let mut a = args();
        a.node = "pve2/bad".to_owned();
        let error = build_restore_new_vmid_action(&a).expect_err("refused");
        assert!(error.contains("node"), "{error}");
    }

    #[test]
    fn the_preview_names_the_target_and_source() {
        let action = build_restore_new_vmid_action(&args()).expect("builds");
        let preview = render_restore_new_vmid_preview(&action);
        assert!(preview.contains("650"), "{preview}");
        assert!(preview.contains("vzdump-qemu-100"), "{preview}");
    }
}
