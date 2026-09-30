//! Migration end-to-end tests.
//!
//! The fixture guest (617, LXC, stopped) lives on `pve2`; the fixture cluster
//! also reports `pve3` as a member node (see `common::default_guest_routes`).

mod common;

use common::{approve_as_second_principal, call, handler_with_guest};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approved_offline_migration_issues_the_post_and_follows_the_task_to_completion() {
    let h = handler_with_guest(617, false).await;
    let planned = call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":617,"op":"migrate","target_node":"pve3"}),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    assert!(
        planned["preview"]
            .as_str()
            .expect("preview")
            .contains("MIGRATE"),
        "{planned:?}"
    );
    approve_as_second_principal(&h, id).await;
    h.script_task_completion(
        "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzmigrate:617:root@pam:",
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
    let reqs = h.requests();
    assert!(
        reqs.iter().any(|r| {
            r.method == "POST"
                && r.path.contains("/lxc/617/migrate")
                && r.body.contains("target=pve3")
        }),
        "the migrate POST with the target node must actually be issued: {reqs:?}"
    );
}

/// The rejection case the acceptance criteria calls out by name: a target
/// node that is not a member of the cluster.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migrating_to_an_unknown_node_is_refused_at_plan_time() {
    let h = handler_with_guest(617, false).await;
    let error = call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":617,"op":"migrate","target_node":"pve-does-not-exist"}),
    )
    .await
    .expect_err("an unknown target node must refuse the plan");
    assert!(error.contains("not a member of cluster"), "{error}");

    // Refused before anything is recorded: no change set exists to approve or
    // apply, and no migrate request was ever sent.
    let reqs = h.requests();
    assert!(
        !reqs.iter().any(|r| r.path.contains("/migrate")),
        "no migrate request should have been issued: {reqs:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migrating_to_the_guests_own_node_is_refused() {
    let h = handler_with_guest(617, false).await;
    let error = call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":617,"op":"migrate","target_node":"pve2"}),
    )
    .await
    .expect_err("migrating to the guest's current node must be refused");
    assert!(error.contains("already on node"), "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_migration_of_a_stopped_guest_is_refused() {
    let h = handler_with_guest(617, false).await;
    let error = call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":617,"op":"migrate","target_node":"pve3","online":true}),
    )
    .await
    .expect_err("a live migration needs a running guest");
    assert!(error.contains("requires a running guest"), "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_migrate_plan_without_a_target_node_is_refused() {
    let h = handler_with_guest(617, false).await;
    let error = call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":617,"op":"migrate"}),
    )
    .await
    .expect_err("migrate requires target_node");
    assert!(error.contains("target_node"), "{error}");
}

/// A token scoped to the generic change-set handlers but not to
/// `migrate_container` must not be able to select `migrate` as the op --
/// mirroring the existing per-operation scope check for destroy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migrate_requires_its_own_tool_scope_not_just_the_generic_handlers() {
    use common::{TestServer, TokenSpec, call_with_token, default_guest_routes};

    let spec = TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_proxmox_destroy".to_owned(),
            "get_proxmox_change_set".to_owned(),
            "approve_proxmox_change_set".to_owned(),
            "apply_proxmox_change_set".to_owned(),
            // Deliberately no migrate_container/migrate_vm scope.
        ],
        guests: vec!["*".to_owned()],
    };
    let h = TestServer::start_with_routes(spec, default_guest_routes(617, false)).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":617,"op":"migrate","target_node":"pve3"}),
    )
    .await
    .expect_err("a token with no migrate_container scope must not plan a migration");
    assert!(
        error.contains("not authorized for tool 'migrate_container'"),
        "{error}"
    );
}
