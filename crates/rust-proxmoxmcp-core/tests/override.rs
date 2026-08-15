//! Override logic tests (waiver + lab-mode).

use rust_proxmoxmcp_core::protect::{Override, Protection, ProtectionReason, destructive_allowed};
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

/// Build a waiver file with one entry for the given cluster and vmid.
fn waivers_for(cluster: &str, vmid: u32) -> WaiverFile {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("waivers.json");
    let content = format!(
        r#"{{
  "version": 1,
  "waivers": [
    {{
      "cluster": "{}",
      "vmid": {},
      "until": "2023-11-15T00:00:00Z",
      "reason": "decommission",
      "ticket": "CHG-4471"
    }}
  ]
}}"#,
        cluster, vmid
    );
    fs::write(&path, content).expect("write waiver file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("set mode 0600");
    WaiverFile::load(&path).expect("load waivers")
}

#[test]
fn an_unprotected_guest_needs_no_override() {
    let o = destructive_allowed(&unprotected(), &empty_waivers(), "pve3", 616, NOW, false);
    assert!(matches!(o, Override::None));
}

#[test]
fn a_protected_guest_with_no_override_is_refused() {
    // `destructive_allowed` reports the override; refusal is the caller's job when
    // the guest is protected and the override is None. Assert the discriminant.
    let o = destructive_allowed(&protected(), &empty_waivers(), "pve3", 905, NOW, false);
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
    );
    assert!(
        matches!(o, Override::None),
        "an expired waiver is not a waiver"
    );
}

#[test]
fn lab_mode_overrides_protection() {
    let o = destructive_allowed(&protected(), &empty_waivers(), "pve3", 905, NOW, true);
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
    );
    assert!(
        matches!(o, Override::Waiver { .. }),
        "with both available the specific, ticketed authority must be recorded"
    );
}
