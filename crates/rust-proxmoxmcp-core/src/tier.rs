//! Action-class tiering.
//!
//! Tier is a property of the tool, declared once here, and it selects the code
//! path. It is never a value a caller passes: a `force: true` argument is not a
//! guardrail, because a sufficiently confident caller sets it.
//!
//! `WRITE_TOOLS` is complete from release 0.1 even though releases 0.2 and 0.3
//! register the tools it names. `ScopeSet::allows_tool` excludes this registry
//! from the tool wildcard, so it is the only thing standing between a
//! `"tools": ["*"]` token and write authority the day those tools appear.

use crate::grant::ProxmoxAction;

/// Action class of a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Observation only.
    Read,
    /// Disruptive but reversible.
    Low,
    /// Irreversible.
    Destructive,
}

impl Tier {
    /// The grant action this tier requires.
    #[must_use]
    pub const fn action(self) -> ProxmoxAction {
        match self {
            Self::Read => ProxmoxAction::Read,
            Self::Low => ProxmoxAction::Low,
            Self::Destructive => ProxmoxAction::Destructive,
        }
    }
}

/// Tools excluded from a wildcard tool scope. Complete as of spec §4.3.
pub const WRITE_TOOLS: &[&str] = &[
    // low
    "clone_vm",
    "create_backup",
    "create_container",
    "create_snapshot",
    "create_vm",
    "download_iso",
    "reset_vm",
    "restart_container",
    "shutdown_vm",
    "start_container",
    "start_vm",
    "stop_container",
    "stop_vm",
    "update_container_resources",
    // low or destructive depending on direction; classified at call time
    "resize_disk",
    // destructive
    "delete_backup",
    "delete_container",
    "delete_iso",
    "delete_snapshot",
    "delete_vm",
    "restore_backup",
    "rollback_snapshot",
    // deferred to 0.5, registered here so a wildcard never reaches it
    "execute_vm_command",
];

/// Tools whose tier is `Destructive`.
const DESTRUCTIVE_TOOLS: &[&str] = &[
    "delete_backup",
    "delete_container",
    "delete_iso",
    "delete_snapshot",
    "delete_vm",
    "execute_vm_command",
    "restore_backup",
    "rollback_snapshot",
];

/// Classify a tool.
///
/// Returns `None` for a name this server does not register. An unknown tool is
/// unclassified rather than defaulted to [`Tier::Read`]; defaulting would make
/// a future tool readable by omission.
///
/// `resize_disk` reports [`Tier::Low`] here and is re-classified at call time
/// from the sign of its size argument — a shrink destroys data and a grow does
/// not. See `crate::catalog` for where that happens in release 0.2.
#[must_use]
pub fn tier_of(tool: &str) -> Option<Tier> {
    if DESTRUCTIVE_TOOLS.contains(&tool) {
        return Some(Tier::Destructive);
    }
    if WRITE_TOOLS.contains(&tool) {
        return Some(Tier::Low);
    }
    crate::catalog::read_tool(tool).map(|_| Tier::Read)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_read_tool_classifies_as_read() {
        for tool in crate::catalog::READ_TOOLS {
            assert_eq!(tier_of(tool.name), Some(Tier::Read), "tool {}", tool.name);
        }
    }

    #[test]
    fn every_write_tool_classifies_as_low_or_destructive() {
        for tool in WRITE_TOOLS {
            let tier = tier_of(tool).unwrap_or_else(|| panic!("unclassified tool {tool}"));
            assert_ne!(tier, Tier::Read, "tool {tool} classified as read");
        }
    }

    #[test]
    fn destroy_and_restore_are_destructive() {
        assert_eq!(tier_of("delete_vm"), Some(Tier::Destructive));
        assert_eq!(tier_of("delete_container"), Some(Tier::Destructive));
        assert_eq!(tier_of("restore_backup"), Some(Tier::Destructive));
        assert_eq!(tier_of("rollback_snapshot"), Some(Tier::Destructive));
    }

    #[test]
    fn stop_is_low_because_the_tier_boundary_is_data_loss_not_disruption() {
        assert_eq!(tier_of("stop_vm"), Some(Tier::Low));
    }

    #[test]
    fn no_read_tool_appears_in_the_write_registry() {
        for tool in crate::catalog::READ_TOOLS {
            assert!(
                !WRITE_TOOLS.contains(&tool.name),
                "read tool {} is in WRITE_TOOLS",
                tool.name
            );
        }
    }

    #[test]
    fn an_unknown_tool_is_unclassified_rather_than_defaulting_to_read() {
        assert_eq!(tier_of("wipe_everything"), None);
    }
}
