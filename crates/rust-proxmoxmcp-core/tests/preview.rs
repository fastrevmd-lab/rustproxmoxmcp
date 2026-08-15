//! Integration tests for the destroy preview.

use rust_proxmoxmcp_core::fingerprint::GuestState;
use rust_proxmoxmcp_core::preview::{PreviewInput, render_preview};
use rust_proxmoxmcp_core::protect::Override;

fn base_state() -> GuestState {
    GuestState {
        cluster: "pve3".to_owned(),
        vmid: 907,
        name: "vsrx-ci".to_owned(),
        kind: "qemu".to_owned(),
        node: "pve2".to_owned(),
        status: "running".to_owned(),
        tags: vec!["ci".to_owned(), "protected".to_owned()],
        config_digest: "abc123".to_owned(),
        disks: vec![
            ("scsi0".to_owned(), 64 * 1024 * 1024 * 1024),
            ("scsi1".to_owned(), 8 * 1024 * 1024 * 1024),
        ],
    }
}

fn protected_no_override() -> PreviewInput<'static> {
    PreviewInput {
        state: Box::leak(Box::new(base_state())),
        protected: true,
        protection_summary: "tag:protected",
        override_: Box::leak(Box::new(Override::None)),
        snapshots: 3,
        latest_snapshot: Some("proven-0.19.0  (2026-08-11)"),
        last_backup: Some("2026-08-09 (3d ago), 2 retained"),
        purge_disks: true,
    }
}

fn protected_with_waiver() -> PreviewInput<'static> {
    PreviewInput {
        state: Box::leak(Box::new(base_state())),
        protected: true,
        protection_summary: "tag:protected",
        override_: Box::leak(Box::new(Override::Waiver {
            reason: "decommission".to_owned(),
            ticket: Some("CHG-4471".to_owned()),
            until_unix: 9999999999,
        })),
        snapshots: 3,
        latest_snapshot: Some("proven-0.19.0  (2026-08-11)"),
        last_backup: Some("2026-08-09 (3d ago), 2 retained"),
        purge_disks: true,
    }
}

fn protected_with_lab_mode() -> PreviewInput<'static> {
    PreviewInput {
        state: Box::leak(Box::new(base_state())),
        protected: true,
        protection_summary: "tag:protected",
        override_: Box::leak(Box::new(Override::LabMode)),
        snapshots: 3,
        latest_snapshot: Some("proven-0.19.0  (2026-08-11)"),
        last_backup: Some("2026-08-09 (3d ago), 2 retained"),
        purge_disks: true,
    }
}

fn no_backup_at_all() -> PreviewInput<'static> {
    PreviewInput {
        state: Box::leak(Box::new(base_state())),
        protected: false,
        protection_summary: "unprotected",
        override_: Box::leak(Box::new(Override::None)),
        snapshots: 0,
        latest_snapshot: None,
        last_backup: None,
        purge_disks: true,
    }
}

#[test]
fn a_protected_guest_with_no_override_renders_a_refusal() {
    let text = render_preview(&protected_no_override());
    assert!(
        text.contains("PROTECTED"),
        "the protection must be visible: {text}"
    );
    assert!(
        text.contains("REFUSED"),
        "the verdict must be REFUSED: {text}"
    );
    assert!(
        text.contains("waiver     none"),
        "absence of a waiver must be stated, not omitted"
    );
}

#[test]
fn a_waived_guest_names_the_authority_in_the_preview() {
    let text = render_preview(&protected_with_waiver());
    assert!(text.contains("CHG-4471"), "the ticket must appear: {text}");
    assert!(
        text.contains("decommission"),
        "the reason must appear: {text}"
    );
    assert!(
        !text.contains("REFUSED"),
        "a waived plan is not refused: {text}"
    );
}

#[test]
fn lab_mode_is_labelled_as_lab_mode_not_as_an_operator_waiver() {
    let text = render_preview(&protected_with_lab_mode());
    assert!(
        text.contains("lab-mode"),
        "lab mode must be named as such: {text}"
    );
    assert!(!text.contains("CHG-"), "lab mode carries no ticket: {text}");
}

#[test]
fn backup_age_is_reported_and_never_enforced() {
    // Spec §4.5: enforcing a backup precondition would imply the backup restores,
    // and this estate has a documented counter-example (ssdf-clickhouse).
    let text = render_preview(&no_backup_at_all());
    assert!(
        text.contains("backups"),
        "backup line must always be present: {text}"
    );
    assert!(
        !text.contains("REFUSED"),
        "a missing backup must not itself refuse: {text}"
    );
}
