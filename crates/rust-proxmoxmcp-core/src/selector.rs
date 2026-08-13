//! The guest selector language used by per-token grants.
//!
//! A selector names a set of guests within a cluster. A token's grant carries a
//! list of them, and a guest is in scope when any selector matches — union, not
//! intersection, so `["vmid:600-699", "tag:ci"]` reads as "the disposable band
//! or anything tagged ci".
//!
//! Parsing rejects an unrecognised term rather than ignoring it. A selector the
//! server does not understand is a restriction the operator believes is in
//! force, so silently dropping it widens the token.

use serde::{Deserialize, Serialize};

/// Whether a guest is a virtual machine or a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuestType {
    /// A QEMU virtual machine.
    Qemu,
    /// An LXC container.
    Lxc,
}

impl GuestType {
    /// The path segment Proxmox uses for this guest type.
    #[must_use]
    pub const fn path_segment(self) -> &'static str {
        match self {
            Self::Qemu => "qemu",
            Self::Lxc => "lxc",
        }
    }
}

/// The facts a selector needs about a guest.
///
/// A borrow rather than the whole resolved guest, so this module has no
/// dependency on resolution and can be tested on its own.
#[derive(Debug, Clone, Copy)]
pub struct GuestFacts<'a> {
    /// Numeric guest id, cluster-unique.
    pub vmid: u32,
    /// VM or container.
    pub r#type: GuestType,
    /// Node the guest currently runs on.
    pub node: &'a str,
    /// Proxmox pool, when the guest is in one.
    pub pool: Option<&'a str>,
    /// Live tags.
    pub tags: &'a [String],
}

/// A malformed selector.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SelectorError {
    /// The term prefix is not one this server understands.
    #[error("unknown selector term '{0}'")]
    Unknown(String),
    /// A range was inverted, empty, or unparseable.
    #[error("invalid vmid range: {0}")]
    BadRange(String),
    /// A vmid was not a number.
    #[error("invalid vmid: {0}")]
    BadVmid(String),
}

/// One term of a guest selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// Every guest in the cluster.
    Any,
    /// Exactly this vmid.
    Vmid(u32),
    /// An inclusive vmid range.
    VmidRange {
        /// Lowest vmid in scope.
        low: u32,
        /// Highest vmid in scope.
        high: u32,
    },
    /// Any guest carrying this exact tag.
    Tag(String),
    /// Any guest in this Proxmox pool.
    Pool(String),
    /// Any guest currently on this node.
    Node(String),
    /// Any guest of this type.
    Type(GuestType),
}

impl Selector {
    /// Parse one selector term.
    ///
    /// # Errors
    /// Returns [`SelectorError`] for an unknown prefix or a malformed value.
    pub fn parse(input: &str) -> Result<Self, SelectorError> {
        if input == "*" {
            return Ok(Self::Any);
        }
        let Some((prefix, value)) = input.split_once(':') else {
            return Err(SelectorError::Unknown(input.to_owned()));
        };
        match prefix {
            "vmid" => parse_vmid_term(value),
            "tag" => Ok(Self::Tag(value.to_owned())),
            "pool" => Ok(Self::Pool(value.to_owned())),
            "node" => Ok(Self::Node(value.to_owned())),
            "type" => match value {
                "qemu" => Ok(Self::Type(GuestType::Qemu)),
                "lxc" => Ok(Self::Type(GuestType::Lxc)),
                other => Err(SelectorError::Unknown(format!("type:{other}"))),
            },
            other => Err(SelectorError::Unknown(other.to_owned())),
        }
    }

    /// Whether this selector admits the described guest.
    #[must_use]
    pub fn matches(&self, facts: GuestFacts<'_>) -> bool {
        match self {
            Self::Any => true,
            Self::Vmid(vmid) => facts.vmid == *vmid,
            Self::VmidRange { low, high } => facts.vmid >= *low && facts.vmid <= *high,
            Self::Tag(tag) => facts.tags.iter().any(|candidate| candidate == tag),
            Self::Pool(pool) => facts.pool == Some(pool.as_str()),
            Self::Node(node) => facts.node == node,
            Self::Type(kind) => facts.r#type == *kind,
        }
    }
}

/// Parse the value half of a `vmid:` term.
fn parse_vmid_term(value: &str) -> Result<Selector, SelectorError> {
    if let Some((low, high)) = value.split_once('-') {
        let low: u32 = low
            .parse()
            .map_err(|_| SelectorError::BadRange(value.to_owned()))?;
        let high: u32 = high
            .parse()
            .map_err(|_| SelectorError::BadRange(value.to_owned()))?;
        if low > high {
            return Err(SelectorError::BadRange(value.to_owned()));
        }
        return Ok(Selector::VmidRange { low, high });
    }
    value
        .parse()
        .map(Selector::Vmid)
        .map_err(|_| SelectorError::BadVmid(value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts<'a>(vmid: u32, tags: &'a [String], pool: Option<&'a str>) -> GuestFacts<'a> {
        GuestFacts {
            vmid,
            r#type: GuestType::Qemu,
            node: "pve2",
            pool,
            tags,
        }
    }

    #[test]
    fn parses_every_documented_term() {
        assert_eq!(Selector::parse("*").expect("parse"), Selector::Any);
        assert_eq!(
            Selector::parse("vmid:905").expect("parse"),
            Selector::Vmid(905)
        );
        assert_eq!(
            Selector::parse("vmid:600-699").expect("parse"),
            Selector::VmidRange {
                low: 600,
                high: 699
            }
        );
        assert_eq!(
            Selector::parse("tag:ci").expect("parse"),
            Selector::Tag("ci".to_owned())
        );
        assert_eq!(
            Selector::parse("pool:lab").expect("parse"),
            Selector::Pool("lab".to_owned())
        );
        assert_eq!(
            Selector::parse("node:pve2").expect("parse"),
            Selector::Node("pve2".to_owned())
        );
        assert_eq!(
            Selector::parse("type:lxc").expect("parse"),
            Selector::Type(GuestType::Lxc)
        );
    }

    #[test]
    fn rejects_an_unknown_term_rather_than_ignoring_it() {
        let error = Selector::parse("site:emea").expect_err("should reject");
        assert!(matches!(error, SelectorError::Unknown(term) if term == "site"));
    }

    #[test]
    fn rejects_an_inverted_range() {
        assert!(matches!(
            Selector::parse("vmid:699-600"),
            Err(SelectorError::BadRange(_))
        ));
    }

    #[test]
    fn range_is_inclusive_at_both_ends() {
        let selector = Selector::parse("vmid:600-699").expect("parse");
        assert!(selector.matches(facts(600, &[], None)));
        assert!(selector.matches(facts(699, &[], None)));
        assert!(!selector.matches(facts(599, &[], None)));
        assert!(!selector.matches(facts(700, &[], None)));
    }

    #[test]
    fn tag_match_is_exact_not_substring() {
        let selector = Selector::parse("tag:ci").expect("parse");
        let protected = vec!["ci-runner".to_owned()];
        assert!(!selector.matches(facts(600, &protected, None)));
        let exact = vec!["ci".to_owned()];
        assert!(selector.matches(facts(600, &exact, None)));
    }

    #[test]
    fn a_guest_with_no_pool_never_matches_a_pool_selector() {
        let selector = Selector::parse("pool:lab").expect("parse");
        assert!(!selector.matches(facts(600, &[], None)));
        assert!(selector.matches(facts(600, &[], Some("lab"))));
    }
}
