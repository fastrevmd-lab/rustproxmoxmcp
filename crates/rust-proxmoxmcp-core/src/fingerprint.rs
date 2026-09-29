//! Proxmox guest state fingerprinting.
//!
//! The fingerprint prevents applying a change-set to a guest that changed between
//! approval and application. If the guest configuration moved, apply must refuse
//! rather than act on a target that is no longer the one the approver saw.

use sha2::{Digest, Sha256};

/// Proxmox guest state snapshot for fingerprinting.
///
/// This captures the identity and configuration state of a Proxmox guest at a
/// specific moment. The fingerprint computed from this state lets the change-set
/// system detect when a guest has changed between approval and apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestState {
    /// Cluster name (e.g., "pve3").
    pub cluster: String,
    /// Guest VMID.
    pub vmid: u32,
    /// Guest name.
    pub name: String,
    /// Guest type ("lxc" or "qemu").
    pub kind: String,
    /// Node the guest is currently on.
    pub node: String,
    /// Guest status (e.g., "running", "stopped").
    pub status: String,
    /// Guest tags (will be sorted before fingerprinting).
    pub tags: Vec<String>,
    /// Proxmox's config digest for this guest.
    pub config_digest: String,
    /// Disk identifiers and sizes in bytes (will be sorted before fingerprinting).
    pub disks: Vec<(String, u64)>,
}

/// Computes a stable fingerprint of a Proxmox guest's state.
///
/// The fingerprint is a SHA-256 hash of a serialized tuple containing all guest
/// state fields. Tags and disks are sorted before hashing so ordering does not
/// affect the fingerprint.
///
/// Returns a string in the format `sha256:<lowercase hex>`.
///
/// # Example
///
/// ```
/// use rust_proxmoxmcp_core::fingerprint::{fingerprint, GuestState};
///
/// let state = GuestState {
///     cluster: "pve3".into(),
///     vmid: 617,
///     name: "test-guest".into(),
///     kind: "lxc".into(),
///     node: "pve2".into(),
///     status: "running".into(),
///     tags: vec!["test".into()],
///     config_digest: "abc123".into(),
///     disks: vec![("rootfs".into(), 8_589_934_592)],
/// };
///
/// let fp = fingerprint(&state);
/// assert!(fp.starts_with("sha256:"));
/// ```
pub fn fingerprint(state: &GuestState) -> String {
    // Sort tags and disks to ensure ordering does not affect the fingerprint.
    let mut sorted_tags = state.tags.clone();
    sorted_tags.sort();

    let mut sorted_disks = state.disks.clone();
    sorted_disks.sort();

    // Create a tuple of all fields in the specified order.
    // Using a tuple ensures proper length encoding, preventing field values
    // from shifting boundaries (e.g., "a|b" vs "a", "b|c" collision).
    let tuple = (
        &state.cluster,
        state.vmid,
        &state.name,
        &state.kind,
        &state.node,
        &state.status,
        &sorted_tags,
        &state.config_digest,
        &sorted_disks,
    );

    // Serialize the tuple to bytes.
    let bytes =
        serde_json::to_vec(&tuple).expect("tuple serialization cannot fail with these types");

    // Hash the serialized tuple.
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();

    // Format as sha256:<lowercase hex>.
    let hex = hash
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    format!("sha256:{}", hex)
}

/// Computes a stable fingerprint for a VMID that a restore-to-new-vmid plan
/// targets, before any guest exists there.
///
/// There is no guest to fingerprint -- that is the whole point of this
/// operation -- so what can drift between plan and apply is not a guest's
/// config but whether the VMID is still free. This value is therefore
/// constant for a given `(cluster, vmid)` pair; the actual drift check is the
/// explicit vacancy re-check the apply handler performs against the live
/// cluster before dispatching the restore. This fingerprint exists so that
/// check has the same `expected_candidate_fingerprint` plumbing every other
/// change set uses, rather than a bespoke field.
///
/// Returns a string in the format `sha256:<lowercase hex>`, matching
/// [`fingerprint`] so the two are never confused for one another by shape.
#[must_use]
pub fn restore_target_fingerprint(cluster: &str, vmid: u32) -> String {
    let tuple = (cluster, vmid, "vacant-restore-target");
    let bytes =
        serde_json::to_vec(&tuple).expect("tuple serialization cannot fail with these types");

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();

    let hex = hash
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    format!("sha256:{}", hex)
}
