//! Protection resolution: the function that decides whether a guest survives.
//!
//! Protection is the union of a live Proxmox tag and a server-side pin, and it
//! fails closed on both an unreadable answer and an unknown guest.
//!
//! The union is the whole point. A live tag keeps the list current and lets
//! operators manage it where they already work — but the server's own API token
//! can clear that tag, so a tag-only policy is unprotect-then-destroy in two
//! calls. The pin in `clusters.json` cannot be edited through the Proxmox API
//! at all. Neither half is sufficient alone.
//!
//! Every applicable reason is reported rather than the first one found, because
//! the preview an approver reads should say *why* — a guest protected twice
//! over is a different situation from one protected by a tag someone may
//! reasonably remove.

use crate::inventory::Cluster;
use crate::resolve::ResolvedGuest;
use crate::waiver::WaiverFile;

/// Why a guest is protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionReason {
    /// The guest carries a tag the cluster policy marks protective.
    LiveTag(String),
    /// The guest's vmid is pinned in `clusters.json`.
    InventoryPin,
    /// The cluster could not be read, so protection cannot be ruled out.
    ResolutionFailed,
    /// The cluster does not report this guest at all.
    UnknownGuest,
}

/// The protection verdict for one guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protection {
    /// No protective signal applies.
    Unprotected,
    /// At least one protective signal applies.
    Protected {
        /// Every applicable reason, in a stable order.
        reasons: Vec<ProtectionReason>,
    },
}

/// Override allowing a destructive operation to proceed on a protected guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Override {
    /// No override applies.
    None,
    /// A matching waiver from the waivers file.
    Waiver {
        /// The reason stated in the waiver.
        reason: String,
        /// The change ticket, if any.
        ticket: Option<String>,
        /// The unix timestamp when this waiver expires.
        until_unix: u64,
    },
    /// The server is in lab mode (single-operator workflow).
    LabMode,
}

impl Protection {
    /// Whether any protective signal applies.
    #[must_use]
    pub fn is_protected(&self) -> bool {
        matches!(self, Self::Protected { .. })
    }

    /// A one-line rendering for audit metadata and previews.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Unprotected => "unprotected".to_owned(),
            Self::Protected { reasons } => reasons
                .iter()
                .map(|reason| match reason {
                    ProtectionReason::LiveTag(tag) => format!("tag:{tag}"),
                    ProtectionReason::InventoryPin => "inventory-pin".to_owned(),
                    ProtectionReason::ResolutionFailed => "resolution-failed".to_owned(),
                    ProtectionReason::UnknownGuest => "unknown-guest".to_owned(),
                })
                .collect::<Vec<_>>()
                .join(","),
        }
    }
}

/// Resolve protection for one guest.
///
/// `guest` is `None` when the cluster does not report the vmid. `resolution_failed`
/// is `true` when the cluster could not be read at all — distinguished from an
/// absent guest because they are different operational situations, and both are
/// protective.
#[must_use]
pub fn protection_of(
    cluster: &Cluster,
    guest: Option<&ResolvedGuest>,
    resolution_failed: bool,
) -> Protection {
    let mut reasons = Vec::new();

    if resolution_failed {
        reasons.push(ProtectionReason::ResolutionFailed);
    }

    match guest {
        None if !resolution_failed => reasons.push(ProtectionReason::UnknownGuest),
        None => {}
        Some(guest) => {
            for tag in &guest.tags {
                if cluster.protected_tags.contains(tag) {
                    reasons.push(ProtectionReason::LiveTag(tag.clone()));
                }
            }
            if cluster.protected_vmids.contains(&guest.vmid) {
                reasons.push(ProtectionReason::InventoryPin);
            }
        }
    }

    if reasons.is_empty() {
        Protection::Unprotected
    } else {
        Protection::Protected { reasons }
    }
}

/// Determine what override, if any, allows a destructive operation.
///
/// This evaluates the spec §4.2 rule:
///
/// ```text
/// allowed := ¬protected ∨ waiver_matches(cluster, vmid, now) ∨ lab_mode
/// ```
///
/// When the guest is unprotected, no override is needed. When the guest is
/// protected, a matching waiver takes precedence over lab mode for auditability
/// — the record should name the specific, ticketed authority rather than the
/// blanket flag.
///
/// # Parameters
/// - `protection`: the protection verdict from [`protection_of`]
/// - `waivers`: the loaded waiver file
/// - `cluster`: exact cluster name
/// - `vmid`: exact VMID
/// - `now_unix`: current unix timestamp
/// - `lab_mode`: whether the server is in lab mode
#[must_use]
pub fn destructive_allowed(
    protection: &Protection,
    waivers: &WaiverFile,
    cluster: &str,
    vmid: u32,
    now_unix: u64,
    lab_mode: bool,
) -> Override {
    // Unprotected guests need no override.
    if !protection.is_protected() {
        return Override::None;
    }

    // Check for a matching waiver first (preferred over lab mode for auditability).
    if let Some(entry) = waivers.matching(cluster, vmid, now_unix) {
        return Override::Waiver {
            reason: entry.reason().to_owned(),
            ticket: entry.ticket().map(ToOwned::to_owned),
            until_unix: entry.until_unix(),
        };
    }

    // Lab mode is the fallback.
    if lab_mode {
        return Override::LabMode;
    }

    // No override available.
    Override::None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Cluster;
    use crate::resolve::ResolvedGuest;
    use crate::selector::GuestType;

    fn cluster(protected_vmids: Vec<u32>) -> Cluster {
        Cluster {
            endpoint: "https://pve3.example.org:8006".to_owned(),
            token_id: "root@pam!mcp".to_owned(),
            token_secret_env: Some("X".to_owned()),
            token_secret_file: None,
            ca_pem_path: None,
            protected_vmids,
            protected_tags: vec!["protected".to_owned()],
        }
    }

    fn guest(vmid: u32, tags: &[&str]) -> ResolvedGuest {
        ResolvedGuest {
            cluster: "pve3".to_owned(),
            vmid,
            name: format!("guest-{vmid}"),
            r#type: GuestType::Qemu,
            node: "pve2".to_owned(),
            status: "running".to_owned(),
            tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
            pool: None,
        }
    }

    #[test]
    fn a_live_tag_alone_protects() {
        let verdict = protection_of(&cluster(vec![]), Some(&guest(905, &["protected"])), false);
        assert!(verdict.is_protected());
    }

    #[test]
    fn an_inventory_pin_alone_protects() {
        let verdict = protection_of(&cluster(vec![905]), Some(&guest(905, &[])), false);
        assert!(verdict.is_protected());
    }

    #[test]
    fn clearing_the_tag_does_not_clear_the_pin() {
        // The attack the union exists to stop: the server's own token can edit
        // tags, so a tag-only policy is unprotect-then-destroy in two calls.
        let verdict = protection_of(&cluster(vec![905]), Some(&guest(905, &["ci"])), false);
        assert!(verdict.is_protected());
    }

    #[test]
    fn a_failed_resolution_is_protected() {
        let verdict = protection_of(&cluster(vec![]), None, true);
        assert!(verdict.is_protected());
        assert!(matches!(
            verdict,
            Protection::Protected { ref reasons } if reasons.contains(&ProtectionReason::ResolutionFailed)
        ));
    }

    #[test]
    fn an_unknown_guest_is_protected() {
        let verdict = protection_of(&cluster(vec![]), None, false);
        assert!(verdict.is_protected());
        assert!(matches!(
            verdict,
            Protection::Protected { ref reasons } if reasons.contains(&ProtectionReason::UnknownGuest)
        ));
    }

    #[test]
    fn an_untagged_unpinned_known_guest_is_unprotected() {
        let verdict = protection_of(
            &cluster(vec![905]),
            Some(&guest(606, &["disposable"])),
            false,
        );
        assert!(!verdict.is_protected());
    }

    #[test]
    fn a_custom_protected_tag_is_honoured() {
        let mut cluster = cluster(vec![]);
        cluster.protected_tags = vec!["do-not-touch".to_owned()];
        let verdict = protection_of(&cluster, Some(&guest(606, &["do-not-touch"])), false);
        assert!(verdict.is_protected());
    }

    #[test]
    fn every_applicable_reason_is_reported_not_just_the_first() {
        let verdict = protection_of(
            &cluster(vec![905]),
            Some(&guest(905, &["protected"])),
            false,
        );
        let Protection::Protected { reasons } = verdict else {
            panic!("expected protected");
        };
        assert_eq!(reasons.len(), 2, "reasons were {reasons:?}");
    }
}

/// Whether a VMID that does not yet exist may be created.
///
/// The protection union is evaluated against a *resolved* guest, so it has
/// nothing to match when the guest is the one being created — the VMID is free
/// by definition. That leaves `protected_vmids` unenforced at exactly the
/// moment it is cheapest to enforce.
///
/// A pinned VMID is pinned because something important is expected to live
/// there. Letting a create claim it means the next `delete_vm` against that
/// number is refused for protecting a guest nobody intended to protect, and
/// the real one has nowhere to go. So a create into a pinned VMID is refused.
///
/// Tags cannot participate: a guest that does not exist carries none. Only the
/// inventory pin is checkable here, and saying so is better than implying the
/// tag half was consulted.
#[must_use]
pub fn creation_allowed(cluster: &Cluster, vmid: u32) -> bool {
    !cluster.protected_vmids.contains(&vmid)
}

#[cfg(test)]
mod creation_tests {
    use super::creation_allowed;
    use crate::inventory::Cluster;

    fn cluster_with(protected: Vec<u32>) -> Cluster {
        Cluster {
            endpoint: "https://pve.example.org:8006".to_owned(),
            token_id: "root@pam!mcp".to_owned(),
            token_secret_env: None,
            token_secret_file: None,
            ca_pem_path: None,
            protected_vmids: protected,
            protected_tags: vec!["protected".to_owned()],
        }
    }

    /// The case the guard exists for. `protected_vmids` is evaluated against a
    /// resolved guest everywhere else, so a create — where nothing resolves —
    /// would otherwise claim a pinned number unchallenged.
    #[test]
    fn a_pinned_vmid_cannot_be_claimed_by_a_create() {
        assert!(!creation_allowed(&cluster_with(vec![950, 960]), 950));
    }

    #[test]
    fn an_unpinned_vmid_is_free() {
        assert!(creation_allowed(&cluster_with(vec![950]), 617));
    }

    /// An empty pin list protects nothing, which is what an unconfigured
    /// cluster means — not "protect everything".
    #[test]
    fn no_pins_means_no_refusals() {
        assert!(creation_allowed(&cluster_with(Vec::new()), 950));
    }
}
