//! Override logic tests (waiver + lab-mode).

use rust_proxmoxmcp_core::protect::{
    DestructiveAttempt, Override, Protection, ProtectionReason, destructive_allowed,
};
use rust_proxmoxmcp_core::waiver::WaiverFile;
use std::fs;
use tempfile::TempDir;

const NOW: u64 = 1_700_000_000; // 2023-11-14

/// Build an unprotected verdict.
fn unprotected() -> Protection {
    Protection::Unprotected
}

/// Build a protected verdict.
fn protected() -> Protection {
    Protection::Protected {
        reasons: vec![ProtectionReason::LiveTag("protected".to_owned())],
    }
}

/// Build an empty waiver file.
fn empty_waivers() -> WaiverFile {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("empty.json");
    WaiverFile::load(&path).expect("load empty waivers")
}

/// Build a waiver file with one entry for the given cluster, vmid, and ops,
/// optionally restricted to one principal.
fn waivers_with(cluster: &str, vmid: u32, ops: &[&str], principal: Option<&str>) -> WaiverFile {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("waivers.json");
    let ops_json = ops
        .iter()
        .map(|op| format!("\"{op}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let principal_json = match principal {
        Some(name) => format!("\"{name}\""),
        None => "null".to_owned(),
    };
    let content = format!(
        r#"{{
  "version": 1,
  "waivers": [
    {{
      "cluster": "{cluster}",
      "vmid": {vmid},
      "until": "2023-11-15T00:00:00Z",
      "reason": "decommission",
      "ticket": "CHG-4471",
      "ops": [{ops_json}],
      "principal": {principal_json}
    }}
  ]
}}"#,
    );
    fs::write(&path, content).expect("write waiver file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("set mode 0600");
    WaiverFile::load(&path).expect("load waivers")
}

/// Build a waiver file with one entry for the given cluster and vmid,
/// covering every op this test suite exercises and no principal
/// restriction -- the common case for tests not about `ops`/`principal`
/// scoping itself.
fn waivers_for(cluster: &str, vmid: u32) -> WaiverFile {
    waivers_with(cluster, vmid, &["destroy_guest", "delete_backup"], None)
}

#[test]
fn an_unprotected_guest_needs_no_override() {
    let o = destructive_allowed(
        &unprotected(),
        &empty_waivers(),
        "pve3",
        616,
        NOW,
        false,
        DestructiveAttempt {
            op: "destroy_guest",
            principal: None,
        },
    );
    assert!(matches!(o, Override::None));
}

#[test]
fn a_protected_guest_with_no_override_is_refused() {
    // `destructive_allowed` reports the override; refusal is the caller's job when
    // the guest is protected and the override is None. Assert the discriminant.
    let o = destructive_allowed(
        &protected(),
        &empty_waivers(),
        "pve3",
        905,
        NOW,
        false,
        DestructiveAttempt {
            op: "destroy_guest",
            principal: None,
        },
    );
    assert!(
        matches!(o, Override::None),
        "no waiver, no lab mode -> no override"
    );
}

#[test]
fn a_matching_waiver_overrides_protection_and_carries_its_reason() {
    let o = destructive_allowed(
        &protected(),
        &waivers_for("pve3", 905),
        "pve3",
        905,
        NOW,
        false,
        DestructiveAttempt {
            op: "destroy_guest",
            principal: None,
        },
    );
    match o {
        Override::Waiver {
            reason,
            ticket,
            until_unix,
        } => {
            assert_eq!(reason, "decommission");
            assert_eq!(ticket.as_deref(), Some("CHG-4471"));
            assert_eq!(until_unix, 1_700_006_400); // 2023-11-15T00:00:00Z
        }
        other => panic!("expected a waiver override, got {other:?}"),
    }
}

#[test]
fn an_expired_waiver_does_not_override() {
    let past = NOW + 86_400; // one day after `until`
    let o = destructive_allowed(
        &protected(),
        &waivers_for("pve3", 905),
        "pve3",
        905,
        past,
        false,
        DestructiveAttempt {
            op: "destroy_guest",
            principal: None,
        },
    );
    assert!(
        matches!(o, Override::None),
        "an expired waiver is not a waiver"
    );
}

#[test]
fn lab_mode_overrides_protection() {
    let o = destructive_allowed(
        &protected(),
        &empty_waivers(),
        "pve3",
        905,
        NOW,
        true,
        DestructiveAttempt {
            op: "destroy_guest",
            principal: None,
        },
    );
    assert!(matches!(o, Override::LabMode));
}

#[test]
fn a_waiver_is_preferred_over_lab_mode_so_the_record_names_the_real_authority() {
    let o = destructive_allowed(
        &protected(),
        &waivers_for("pve3", 905),
        "pve3",
        905,
        NOW,
        true,
        DestructiveAttempt {
            op: "destroy_guest",
            principal: None,
        },
    );
    assert!(
        matches!(o, Override::Waiver { .. }),
        "with both available the specific, ticketed authority must be recorded"
    );
}

/// F4 regression: a waiver written for `delete_snapshot` must not also admit
/// `destroy_guest` on the same protected guest. Before the `ops` allowlist,
/// `destructive_allowed` matched on `(cluster, vmid)` alone and any
/// destructive op against the waived guest sailed through.
#[test]
fn a_waiver_for_one_op_does_not_admit_a_different_op() {
    let waivers = waivers_with("pve3", 905, &["delete_snapshot"], None);

    let snapshot_delete = destructive_allowed(
        &protected(),
        &waivers,
        "pve3",
        905,
        NOW,
        false,
        DestructiveAttempt {
            op: "delete_snapshot",
            principal: None,
        },
    );
    assert!(
        matches!(snapshot_delete, Override::Waiver { .. }),
        "the waived op must still override"
    );

    let guest_destroy = destructive_allowed(
        &protected(),
        &waivers,
        "pve3",
        905,
        NOW,
        false,
        DestructiveAttempt {
            op: "destroy_guest",
            principal: None,
        },
    );
    assert!(
        matches!(guest_destroy, Override::None),
        "a snapshot-delete waiver must not admit destroy_guest, got {guest_destroy:?}"
    );
}

/// F4 regression: a waiver restricted to one `principal` must not override
/// protection for a different caller, even for a covered op.
#[test]
fn a_waiver_restricted_to_one_principal_does_not_admit_another() {
    let waivers = waivers_with("pve3", 905, &["destroy_guest"], Some("alice"));

    let as_alice = destructive_allowed(
        &protected(),
        &waivers,
        "pve3",
        905,
        NOW,
        false,
        DestructiveAttempt {
            op: "destroy_guest",
            principal: Some("alice"),
        },
    );
    assert!(
        matches!(as_alice, Override::Waiver { .. }),
        "the named principal must still override"
    );

    let as_mallory = destructive_allowed(
        &protected(),
        &waivers,
        "pve3",
        905,
        NOW,
        false,
        DestructiveAttempt {
            op: "destroy_guest",
            principal: Some("mallory"),
        },
    );
    assert!(
        matches!(as_mallory, Override::None),
        "a principal-scoped waiver must not admit a different caller, got {as_mallory:?}"
    );

    let as_unattributed = destructive_allowed(
        &protected(),
        &waivers,
        "pve3",
        905,
        NOW,
        false,
        DestructiveAttempt {
            op: "destroy_guest",
            principal: None,
        },
    );
    assert!(
        matches!(as_unattributed, Override::None),
        "a principal-scoped waiver must not admit an unattributed caller either, \
         got {as_unattributed:?}"
    );
}

/// A waiver with no `principal` set admits any caller, including one with
/// no attributed identity -- unchanged behaviour for operators who did not
/// ask for principal scoping.
#[test]
fn a_waiver_with_no_principal_admits_any_caller() {
    let waivers = waivers_with("pve3", 905, &["destroy_guest"], None);

    let unattributed = destructive_allowed(
        &protected(),
        &waivers,
        "pve3",
        905,
        NOW,
        false,
        DestructiveAttempt {
            op: "destroy_guest",
            principal: None,
        },
    );
    assert!(matches!(unattributed, Override::Waiver { .. }));

    let attributed = destructive_allowed(
        &protected(),
        &waivers,
        "pve3",
        905,
        NOW,
        false,
        DestructiveAttempt {
            op: "destroy_guest",
            principal: Some("whoever"),
        },
    );
    assert!(matches!(attributed, Override::Waiver { .. }));
}
