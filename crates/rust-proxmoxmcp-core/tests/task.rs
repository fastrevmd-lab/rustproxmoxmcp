//! Tests for UPID parsing and task outcome classification.

use rust_proxmoxmcp_core::task::{TaskOutcome, Upid, classify_exit_status};

const REAL: &str = "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:617:root@pam:";

#[test]
fn a_real_upid_parses_and_yields_its_node() {
    let u = Upid::parse(REAL).expect("parse");
    assert_eq!(u.node(), "pve2");
}

#[test]
fn the_node_comes_from_the_upid_not_the_caller() {
    // Guests migrate (spec §7): two 2026-08-12 renumbers were cross-node moves.
    // Polling must follow the UPID's node, never a caller-supplied one.
    let u =
        Upid::parse("UPID:pve3:0000A1B2:00C3D4E5:66BC1234:vzdestroy:617:root@pam:").expect("parse");
    assert_eq!(u.node(), "pve3");
}

#[test]
fn a_malformed_upid_is_refused_rather_than_guessed() {
    for bad in ["", "UPID:pve2", "not-a-upid", "UPID::::::::"] {
        assert!(Upid::parse(bad).is_err(), "must refuse {bad:?}");
    }
}

#[test]
fn ok_is_the_only_success_spelling() {
    assert!(matches!(classify_exit_status("OK"), TaskOutcome::Ok));
    for bad in [
        "WARNINGS: 1",
        "command 'x' failed: exit code 1",
        "interrupted by signal",
        "",
    ] {
        match classify_exit_status(bad) {
            TaskOutcome::Failed(m) => assert_eq!(m, bad),
            TaskOutcome::Ok => panic!("{bad:?} must not be treated as success"),
        }
    }
}
