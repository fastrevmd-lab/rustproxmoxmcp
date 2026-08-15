//! Fingerprint module tests.

use rust_proxmoxmcp_core::fingerprint::{GuestState, fingerprint};

fn base() -> GuestState {
    GuestState {
        cluster: "pve3".into(),
        vmid: 617,
        name: "test-labmode-proxmox".into(),
        kind: "lxc".into(),
        node: "pve2".into(),
        status: "running".into(),
        tags: vec!["test".into(), "disposable".into()],
        config_digest: "e94e30c44e1ead4df1c597c91406efe543c88494".into(),
        disks: vec![("rootfs".into(), 8_589_934_592)],
    }
}

#[test]
fn the_fingerprint_is_stable_for_identical_state() {
    assert_eq!(fingerprint(&base()), fingerprint(&base()));
    assert!(fingerprint(&base()).starts_with("sha256:"));
}

#[test]
fn tag_order_does_not_change_the_fingerprint() {
    let mut reordered = base();
    reordered.tags = vec!["disposable".into(), "test".into()];
    assert_eq!(
        fingerprint(&base()),
        fingerprint(&reordered),
        "tags are a set; ordering is not identity"
    );
}

#[test]
fn every_component_changes_the_fingerprint() {
    let base_fp = fingerprint(&base());
    let mut cases: Vec<(&str, GuestState)> = Vec::new();
    let mut g = base();
    g.cluster = "pve2".into();
    cases.push(("cluster", g));
    let mut g = base();
    g.vmid = 618;
    cases.push(("vmid", g));
    let mut g = base();
    g.name = "renamed".into();
    cases.push(("name", g));
    let mut g = base();
    g.kind = "qemu".into();
    cases.push(("kind", g));
    let mut g = base();
    g.node = "pve3".into();
    cases.push(("node", g));
    let mut g = base();
    g.status = "stopped".into();
    cases.push(("status", g));
    let mut g = base();
    g.tags.push("protected".into());
    cases.push(("tags", g));
    let mut g = base();
    g.config_digest = "0".repeat(40);
    cases.push(("config_digest", g));
    let mut g = base();
    g.disks = vec![("rootfs".into(), 1)];
    cases.push(("disks", g));
    for (field, state) in cases {
        assert_ne!(
            base_fp,
            fingerprint(&state),
            "{field} must be bound into the fingerprint"
        );
    }
}

#[test]
fn field_values_cannot_shift_a_boundary() {
    // The renumber case this exists for: a value containing the separator must not
    // let one guest impersonate another.
    let mut a = base();
    a.name = "x".into();
    a.node = "y|z".into();
    let mut b = base();
    b.name = "x|y".into();
    b.node = "z".into();
    assert_ne!(
        fingerprint(&a),
        fingerprint(&b),
        "a separator inside a value must not produce a colliding fingerprint"
    );
}
