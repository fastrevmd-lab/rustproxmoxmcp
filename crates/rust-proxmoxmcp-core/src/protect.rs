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
