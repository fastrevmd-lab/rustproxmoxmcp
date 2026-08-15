//! Change-set lifecycle tests.

mod common;

use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn planning_a_destroy_binds_the_fingerprint_and_returns_a_preview() {
    let h = common::handler_with_guest(617, false).await;
    let planned = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("plan");
    assert!(planned["change_set_id"].is_string());
    assert!(
        planned["preview"]
            .as_str()
            .expect("preview")
            .contains("DESTROY")
    );
    assert!(
        planned["expected_fingerprint"]
            .as_str()
            .expect("fp")
            .starts_with("sha256:")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn applying_without_approval_is_refused() {
    let h = common::handler_with_guest(617, false).await;
    let planned = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    let err = common::call(
        &h,
        "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect_err("an unapproved change set must not apply");
    assert!(err.to_string().to_lowercase().contains("approv"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_planner_cannot_approve_its_own_change_set() {
    let h = common::handler_with_guest(617, false).await;
    let planned = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    let err = common::call(
        &h,
        "approve_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect_err("self-approval must be refused");
    assert!(err.to_string().to_lowercase().contains("self"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn planning_a_protected_guest_without_an_override_is_refused() {
    let h = common::handler_with_guest(905, true).await;
    let err = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 905}),
    )
    .await
    .expect_err("protected without waiver must refuse");
    assert!(err.to_string().to_lowercase().contains("protect"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fingerprint_that_moved_after_approval_refuses_the_apply() {
    // Spec §4.4's renumber case, as a test.
    let h = common::handler_with_guest(617, false).await;
    let planned = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    common::approve_as_second_principal(&h, id).await;
    h.move_guest_to_node(617, "pve3"); // config digest / node changes
    let err = common::call(
        &h,
        "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect_err("a moved guest must refuse the apply");
    assert!(
        err.to_string().to_lowercase().contains("fingerprint"),
        "{err}"
    );
}
