//! Per-token write authority and guest scope.
//!
//! `mecmcp-auth` calls this the vendor seam: the shared crate stores the grant
//! and never interprets it. Two things live here that the shared scope model
//! cannot express — the guest selector, because `CallerScopes` carries only
//! opaque name sets and has no numeric-range shape, and the action tier.
//!
//! An unparseable selector admits nothing. A restriction the server cannot
//! understand must not become an absence of restriction.

use crate::selector::{GuestFacts, Selector};
use mecmcp_auth::{Grant, GrantError};
use serde::{Deserialize, Serialize};

/// The mutating action tiers this server distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxmoxAction {
    /// Observation only.
    Read,
    /// Disruptive but reversible: lifecycle, snapshot create, backup create.
    Low,
    /// Irreversible: destroy, restore-over, rollback, shrink, delete.
    Destructive,
}

/// A token's guest scope and action authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxmoxGrant {
    /// Selector terms; a guest is in scope when any term matches.
    pub guests: Vec<String>,
    /// Action tiers this token may invoke.
    pub actions: Vec<ProxmoxAction>,
}

impl ProxmoxGrant {
    /// A grant that sees everything and may change nothing.
    #[must_use]
    pub fn read_only() -> Self {
        Self {
            guests: vec!["*".to_owned()],
            actions: vec![ProxmoxAction::Read],
        }
    }

    /// Whether this grant admits the described guest.
    ///
    /// A term that does not parse contributes no match, so a malformed grant
    /// admits nothing rather than everything. `validate` reports the same
    /// malformation at token-store load time, which is where an operator sees it.
    #[must_use]
    pub fn allows_guest(&self, facts: GuestFacts<'_>) -> bool {
        self.guests.iter().any(|term| {
            Selector::parse(term)
                .map(|selector| selector.matches(facts))
                .unwrap_or(false)
        })
    }
}

impl Grant for ProxmoxGrant {
    type Action = ProxmoxAction;

    fn allows_action(&self, action: Self::Action) -> bool {
        self.actions.contains(&action)
    }

    fn allows_subject(&self, subject: &str) -> bool {
        // A subject here is a cluster-qualified guest address, `cluster/vmid`.
        // The rich check is `allows_guest`, which sees tags and pools; this exists
        // so the shared token store can validate and display a grant, and it can
        // only honour the selector terms that a bare vmid can answer.
        let Some(vmid) = subject
            .split_once('/')
            .and_then(|(_, vmid)| vmid.parse::<u32>().ok())
        else {
            return false;
        };
        self.guests.iter().any(|term| match Selector::parse(term) {
            Ok(Selector::Any) => true,
            Ok(Selector::Vmid(other)) => other == vmid,
            Ok(Selector::VmidRange { low, high }) => vmid >= low && vmid <= high,
            _ => false,
        })
    }

    fn validate(&self) -> Result<(), GrantError> {
        for term in &self.guests {
            Selector::parse(term).map_err(|error| GrantError::Invalid(error.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selector::GuestType;
    use mecmcp_auth::Grant;

    fn facts(vmid: u32) -> GuestFacts<'static> {
        GuestFacts {
            vmid,
            r#type: GuestType::Qemu,
            node: "pve2",
            pool: None,
            tags: &[],
        }
    }

    #[test]
    fn a_band_scoped_grant_admits_only_its_band() {
        let grant = ProxmoxGrant {
            guests: vec!["vmid:600-699".to_owned()],
            actions: vec![ProxmoxAction::Read],
        };
        assert!(grant.allows_guest(facts(606)));
        assert!(!grant.allows_guest(facts(905)));
    }

    #[test]
    fn selectors_union_rather_than_intersect() {
        let grant = ProxmoxGrant {
            guests: vec!["vmid:600-699".to_owned(), "vmid:800".to_owned()],
            actions: vec![ProxmoxAction::Read],
        };
        assert!(grant.allows_guest(facts(606)));
        assert!(grant.allows_guest(facts(800)));
        assert!(!grant.allows_guest(facts(905)));
    }

    #[test]
    fn an_empty_guest_list_admits_nothing() {
        let grant = ProxmoxGrant {
            guests: Vec::new(),
            actions: vec![ProxmoxAction::Read],
        };
        assert!(!grant.allows_guest(facts(606)));
    }

    #[test]
    fn an_unparseable_selector_admits_nothing_and_fails_validation() {
        let grant = ProxmoxGrant {
            guests: vec!["site:emea".to_owned()],
            actions: vec![ProxmoxAction::Read],
        };
        assert!(!grant.allows_guest(facts(606)));
        assert!(grant.validate().is_err());
    }

    #[test]
    fn read_only_grant_permits_no_mutating_action() {
        let grant = ProxmoxGrant::read_only();
        assert!(grant.allows_action(ProxmoxAction::Read));
        assert!(!grant.allows_action(ProxmoxAction::Low));
        assert!(!grant.allows_action(ProxmoxAction::Destructive));
    }

    #[test]
    fn rejects_an_unknown_field_so_a_rewrite_cannot_silently_drop_it() {
        let error = serde_json::from_str::<ProxmoxGrant>(
            r#"{"guests":["*"],"actions":["read"],"max_targets":3}"#,
        );
        assert!(error.is_err());
    }
}
