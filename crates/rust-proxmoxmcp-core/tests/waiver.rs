//! Waiver file loading tests.

use rust_proxmoxmcp_core::waiver::WaiverFile;
use std::io::Write;

/// Writes `body` to a temp file at mode 0600 and returns the path holder.
fn fixture(body: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("temp file");
    f.write_all(body.as_bytes()).expect("write");
    let mut perms = std::fs::metadata(f.path()).expect("metadata").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o600);
    std::fs::set_permissions(f.path(), perms).expect("chmod");
    f
}

const ONE: &str = r#"{"version":1,"waivers":[
  {"cluster":"pve3","vmid":905,"until":"2026-08-13T02:00:00Z",
   "reason":"decommission","ticket":"CHG-4471"}]}"#;

#[test]
fn a_waiver_matches_its_exact_target_inside_the_window() {
    let f = fixture(ONE);
    let w = WaiverFile::load(f.path()).expect("load");
    // 2026-08-13T01:00:00Z — inside the window.
    let hit = w
        .matching("pve3", 905, 1_786_582_800)
        .expect("should match");
    assert_eq!(hit.reason(), "decommission");
    assert_eq!(hit.ticket(), Some("CHG-4471"));
}

#[test]
fn an_expired_waiver_does_not_match() {
    let f = fixture(ONE);
    let w = WaiverFile::load(f.path()).expect("load");
    // 2026-08-13T03:00:00Z — one hour past `until`.
    assert!(w.matching("pve3", 905, 1_786_590_000).is_none());
}

#[test]
fn a_waiver_does_not_match_a_different_guest_or_cluster() {
    let f = fixture(ONE);
    let w = WaiverFile::load(f.path()).expect("load");
    let inside = 1_786_582_800;
    assert!(
        w.matching("pve3", 906, inside).is_none(),
        "vmid must match exactly"
    );
    assert!(
        w.matching("pve2", 905, inside).is_none(),
        "cluster must match exactly"
    );
}

#[test]
fn a_group_readable_file_is_refused() {
    let f = fixture(ONE);
    let mut perms = std::fs::metadata(f.path()).expect("metadata").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o640);
    std::fs::set_permissions(f.path(), perms).expect("chmod");
    let err = WaiverFile::load(f.path()).expect_err("0640 must be refused");
    assert!(
        format!("{err}").contains("0640"),
        "error should name the mode: {err}"
    );
}

#[test]
fn an_unknown_version_is_refused() {
    let f = fixture(r#"{"version":2,"waivers":[]}"#);
    assert!(
        WaiverFile::load(f.path()).is_err(),
        "unknown version must be refused"
    );
}

#[test]
fn a_missing_file_loads_as_empty_not_an_error() {
    let w = WaiverFile::load(std::path::Path::new("/nonexistent/waivers.json"))
        .expect("absent waiver file is not an error");
    assert!(w.matching("pve3", 905, 1_786_582_800).is_none());
}
