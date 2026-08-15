//! Destroy operation end-to-end tests.

mod common;

use common::{approve_as_second_principal, call, handler_with_guest};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approved_destroy_issues_the_delete_and_follows_the_task_to_completion() {
    let h = handler_with_guest(617, false).await;
    let planned = call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":617}),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    approve_as_second_principal(&h, id).await;
    h.script_task_completion(
        "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:617:root@pam:",
        "OK",
    );

    let applied = call(
        &h,
        "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster":"pve3","vmid":617}),
    )
    .await
    .expect("apply");

    assert_eq!(applied["outcome"], "ok");
    assert!(applied["upid"].as_str().expect("upid").starts_with("UPID:"));
    let reqs = h.requests();
    assert!(
        reqs.iter()
            .any(|r| r.method == "DELETE" && r.path.contains("/lxc/617")),
        "the DELETE must actually be issued: {reqs:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_task_that_ends_non_ok_is_reported_as_a_failure_not_a_success() {
    let h = handler_with_guest(617, false).await;
    let planned = call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":617}),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    approve_as_second_principal(&h, id).await;
    h.script_task_completion(
        "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:617:root@pam:",
        "command 'lxc-destroy' failed: exit code 1",
    );
    let err = call(
        &h,
        "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster":"pve3","vmid":617}),
    )
    .await
    .expect_err("a failed task must not report success");
    assert!(err.to_string().contains("exit code 1"), "{err}");
}
