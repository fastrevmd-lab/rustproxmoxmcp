//! Restore-to-new-vmid end-to-end tests.
//!
//! The fixture cluster reports two existing guests: `905` (QEMU, running,
//! protected) and `617` (LXC, stopped) on node `pve2` -- see
//! `common::default_guest_routes`. `650` is free in that inventory, which is
//! what the success case restores into.

mod common;

use common::{TestServer, TokenSpec, call_with_token, default_guest_routes};
use serde_json::json;

/// A token scoped for the full restore-to-new-vmid lifecycle, plus a mock
/// route for the restore POST itself: `default_guest_routes` has no route
/// for `/nodes/pve2/qemu` (the endpoint `restore_backup` posts to), because
/// no existing fixture test creates or restores a guest there.
async fn restore_harness() -> TestServer {
    let spec = TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_restore_new_vmid".to_owned(),
            "get_proxmox_change_set".to_owned(),
            "approve_proxmox_change_set".to_owned(),
            "apply_restore_new_vmid".to_owned(),
            "restore_backup_new_vmid".to_owned(),
        ],
        guests: vec!["*".to_owned()],
    };

    let mut routes = default_guest_routes(617, false);
    routes.push(rust_proxmoxmcp_core::testing::Route {
        path: "/api2/json/nodes/pve2/qemu",
        status: 200,
        body: br#"{"data":"UPID:pve2:0000A1B2:00C3D4E5:66BC1234:qmrestore:650:root@pam:"}"#,
    });
    // Owner resolution for the fixture's default volid, `local:backup/vzdump-
    // qemu-100-...`: Proxmox's content listing says it belongs to vmid 100,
    // which does not exist in `default_guest_routes`' `/cluster/resources`
    // fixture (905 and 617 only) -- it stands in for an old backup whose
    // source guest is gone, the common case this restore operation exists
    // for. The token's `guests: ["*"]` scope admits it either way.
    routes.push(rust_proxmoxmcp_core::testing::Route {
        path: "/api2/json/nodes/pve2/storage/local/content",
        status: 200,
        body: br#"{"data":[{"volid":"local:backup/vzdump-qemu-100-2024_01_01-00_00_00.vma.zst","vmid":"100","content":"backup"}]}"#,
    });

    TestServer::start_with_routes(spec, routes).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approved_restore_into_a_free_vmid_issues_the_post_and_follows_the_task() {
    let h = restore_harness().await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_restore_new_vmid",
        json!({
            "cluster": "pve3",
            "node": "pve2",
            "target_vmid": 650,
            "kind": "qemu",
            "volid": "local:backup/vzdump-qemu-100-2024_01_01-00_00_00.vma.zst",
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();
    assert!(
        planned["preview"]
            .as_str()
            .expect("preview")
            .contains("RESTORE INTO NEW VMID"),
        "{planned:?}"
    );

    call_with_token(
        &h,
        &h.second_token,
        "approve_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 650}),
    )
    .await
    .expect("second principal approval should succeed");

    h.script_task_completion(
        "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:qmrestore:650:root@pam:",
        "OK",
    );

    let applied = call_with_token(
        &h,
        &h.token,
        "apply_restore_new_vmid",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 650}),
    )
    .await
    .expect("apply");

    assert_eq!(applied["outcome"], "ok");
    let reqs = h.requests();
    assert!(
        reqs.iter().any(|r| {
            r.method == "POST"
                && r.path == "/api2/json/nodes/pve2/qemu"
                && r.body.contains("vmid=650")
                && r.body.contains("restore=1")
                && r.body.contains("archive=")
                && r.body.contains("force=0")
        }),
        "the restore POST with the new vmid must actually be issued, and must never pass \
         force=1: the vacancy re-check and this POST are two separate requests, so \
         force=1 would let a guest created on this vmid in between them be silently \
         overwritten. Proxmox itself must refuse the POST atomically if the vmid is no \
         longer free: {reqs:?}"
    );
}

/// A token whose guest scope no longer covers the target vmid at apply time
/// must be refused, even though it carries every tool scope the applying
/// call checks by name. Mirrors the generic `apply_proxmox_change_set` path,
/// which re-runs its full grant check at apply rather than only at plan --
/// a token can be narrowed (or the vmid subsequently pinned) between a plan
/// being approved and it being applied, and the apply is the call that
/// actually acts on the cluster.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_guest_scope_narrowed_before_apply_is_refused() {
    let h = restore_harness().await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_restore_new_vmid",
        json!({
            "cluster": "pve3",
            "node": "pve2",
            "target_vmid": 650,
            "kind": "qemu",
            "volid": "local:backup/vzdump-qemu-100-2024_01_01-00_00_00.vma.zst",
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    call_with_token(
        &h,
        &h.second_token,
        "approve_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 650}),
    )
    .await
    .expect("second principal approval should succeed");

    // `h.narrow_token` carries the same tool scopes as `h.token` (including
    // `apply_restore_new_vmid` and `restore_backup_new_vmid`), but its guest
    // scope is vmid 1 only -- it stands in for a token whose scope was
    // narrowed after the plan was approved.
    let error = call_with_token(
        &h,
        &h.narrow_token,
        "apply_restore_new_vmid",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 650}),
    )
    .await
    .expect_err("a guest scope that no longer covers the target vmid must refuse the apply");
    assert!(
        error.contains("outside this caller's guest scope"),
        "{error}"
    );

    let reqs = h.requests();
    assert!(
        !reqs
            .iter()
            .any(|r| r.method == "POST" && r.path == "/api2/json/nodes/pve2/qemu"),
        "nothing may be sent to the cluster when the applying token's scope has narrowed: \
         {reqs:?}"
    );
}

/// The rejection case the design calls out by name: a target VMID already
/// occupied by an existing guest must be refused at plan time, not at apply
/// time -- no approval should ever be spent on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restoring_into_an_occupied_vmid_is_refused_at_plan_time() {
    let h = restore_harness().await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_restore_new_vmid",
        json!({
            "cluster": "pve3",
            "node": "pve2",
            // 617 already exists (as an LXC guest) in the fixture
            // inventory -- see `default_guest_routes`. 905 also exists
            // there but is additionally a protected pin, which would
            // exercise a different refusal than the one this test is
            // about.
            "target_vmid": 617,
            "kind": "qemu",
            "volid": "local:backup/vzdump-qemu-100-2024_01_01-00_00_00.vma.zst",
        }),
    )
    .await
    .expect_err("617 already exists and must refuse the plan");
    assert!(error.contains("already exists"), "{error}");

    // Refused before anything is recorded: no restore request was ever sent.
    let reqs = h.requests();
    assert!(
        !reqs
            .iter()
            .any(|r| r.method == "POST" && (r.path.ends_with("/qemu") || r.path.ends_with("/lxc"))),
        "no restore request should have been issued: {reqs:?}"
    );
}

/// A non-backup volid (an ISO, say) must be refused before a plan is
/// recorded: `validate_volid_kind` binds the archive's own content kind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_backup_volid_is_refused() {
    let h = restore_harness().await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_restore_new_vmid",
        json!({
            "cluster": "pve3",
            "node": "pve2",
            "target_vmid": 650,
            "kind": "qemu",
            "volid": "local:iso/debian.iso",
        }),
    )
    .await
    .expect_err("an iso volid must be refused for a restore");
    assert!(error.contains("backup"), "{error}");
}

/// A token scoped to the generic plan/apply handlers but not to
/// `restore_backup_new_vmid` must not be able to plan one -- mirroring the
/// existing per-operation scope check for destroy and migrate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_new_vmid_requires_its_own_tool_scope() {
    let spec = TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_restore_new_vmid".to_owned(),
            "get_proxmox_change_set".to_owned(),
            "approve_proxmox_change_set".to_owned(),
            "apply_restore_new_vmid".to_owned(),
            // Deliberately no restore_backup_new_vmid scope.
        ],
        guests: vec!["*".to_owned()],
    };
    let h = TestServer::start_with_routes(spec, default_guest_routes(617, false)).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_restore_new_vmid",
        json!({
            "cluster": "pve3",
            "node": "pve2",
            "target_vmid": 650,
            "kind": "qemu",
            "volid": "local:backup/vzdump-qemu-100-2024_01_01-00_00_00.vma.zst",
        }),
    )
    .await
    .expect_err("a token with no restore_backup_new_vmid scope must not plan a restore");
    assert!(
        error.contains("not authorized for tool 'restore_backup_new_vmid'"),
        "{error}"
    );
}

/// F1 regression (finding 4, MEC-1180): a token whose guest scope does not
/// cover the archive's real owner must not read from it, even when the
/// restore target vmid is in scope. Without `authorize_backup_owner`'s
/// guest-scope check, a token scoped to its own vmid range could copy a
/// live, protected, out-of-scope guest's disks into a vmid it controls
/// merely by naming that guest's archive.
///
/// Finding B (MEC-1191 re-review): the token here must have the *target*
/// vmid (650) in scope and the *owner* vmid (905) out of scope. A token with
/// neither in scope (the old `vmid:1-1` fixture) still refuses -- the
/// target-scope check in `grant.allows_new_vmid` would refuse it on 650
/// alone, so this test passed even with the owner-scope check removed
/// entirely. The assertion also pins the error to guest 905 specifically,
/// not just the generic scope message, so it cannot be satisfied by the
/// target-scope refusal either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_narrow_scoped_token_may_not_restore_from_an_out_of_scope_owners_archive() {
    let spec = TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_restore_new_vmid".to_owned(),
            "get_proxmox_change_set".to_owned(),
            "approve_proxmox_change_set".to_owned(),
            "apply_restore_new_vmid".to_owned(),
            "restore_backup_new_vmid".to_owned(),
        ],
        guests: vec!["vmid:600-699".to_owned()],
    };
    let mut routes = default_guest_routes(617, false);
    // The archive belongs to 905 -- the fixture's live, protected guest --
    // not the usual 100 this file's other tests restore from.
    routes.push(rust_proxmoxmcp_core::testing::Route {
        path: "/api2/json/nodes/pve2/storage/local/content",
        status: 200,
        body: br#"{"data":[{"volid":"local:backup/vzdump-qemu-905-2024_01_01-00_00_00.vma.zst","vmid":"905","content":"backup"}]}"#,
    });
    let h = TestServer::start_with_routes(spec, routes).await;

    // `h.token` is scoped to vmid:600-699 -- 650 (the restore target) is in
    // scope, but 905 (the archive's real owner) is not. Owner is checked
    // first, so this must refuse on 905, not 650.
    let error = common::call(
        &h,
        "plan_restore_new_vmid",
        json!({
            "cluster": "pve3",
            "node": "pve2",
            "target_vmid": 650,
            "kind": "qemu",
            "volid": "local:backup/vzdump-qemu-905-2024_01_01-00_00_00.vma.zst",
        }),
    )
    .await
    .expect_err("owner guest 905 is outside this caller's guest scope");
    assert!(
        error.contains("belongs to guest 905")
            && error.contains("outside this caller's guest scope"),
        "{error}"
    );

    let reqs = h.requests();
    assert!(
        !reqs.iter().any(|r| r.method == "POST"),
        "no restore request should have been issued: {reqs:?}"
    );
}

/// F1 regression (finding 4, MEC-1180): a protected owner with no matching
/// waiver must refuse the restore, the same as a protected guest refuses a
/// destroy plan.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restoring_from_a_protected_owners_archive_without_a_waiver_is_refused() {
    let spec = TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_restore_new_vmid".to_owned(),
            "get_proxmox_change_set".to_owned(),
            "approve_proxmox_change_set".to_owned(),
            "apply_restore_new_vmid".to_owned(),
            "restore_backup_new_vmid".to_owned(),
        ],
        guests: vec!["*".to_owned()],
    };
    let mut routes = default_guest_routes(617, false);
    routes.push(rust_proxmoxmcp_core::testing::Route {
        path: "/api2/json/nodes/pve2/storage/local/content",
        status: 200,
        body: br#"{"data":[{"volid":"local:backup/vzdump-qemu-905-2024_01_01-00_00_00.vma.zst","vmid":"905","content":"backup"}]}"#,
    });
    // A full guest scope admits 905 -- `start_with_routes` mints an empty
    // waiver file, so protection alone must still refuse this.
    let h = TestServer::start_with_routes(spec, routes).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_restore_new_vmid",
        json!({
            "cluster": "pve3",
            "node": "pve2",
            "target_vmid": 650,
            "kind": "qemu",
            "volid": "local:backup/vzdump-qemu-905-2024_01_01-00_00_00.vma.zst",
        }),
    )
    .await
    .expect_err("owner guest 905 is protected and no waiver covers this restore");
    assert!(
        error.contains("protected") && error.contains("needs a waiver"),
        "{error}"
    );
}

/// F1 regression (finding 4, MEC-1180): the apply-time re-check must catch
/// an archive whose real owner changed since the plan -- the same way
/// `apply_proxmox_change_set` refuses a guest whose fingerprint moved.
/// Proxmox's content listing is live state; nothing stops it answering
/// differently between plan and apply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archive_ownership_changing_between_plan_and_apply_is_refused() {
    let h = restore_harness().await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_restore_new_vmid",
        json!({
            "cluster": "pve3",
            "node": "pve2",
            "target_vmid": 650,
            "kind": "qemu",
            "volid": "local:backup/vzdump-qemu-100-2024_01_01-00_00_00.vma.zst",
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    call_with_token(
        &h,
        &h.second_token,
        "approve_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 650}),
    )
    .await
    .expect("second principal approval should succeed");

    // Same volid, different owner: the content listing now attributes it to
    // 905 instead of the 100 the plan recorded.
    h.replace_route(rust_proxmoxmcp_core::testing::Route {
        path: "/api2/json/nodes/pve2/storage/local/content",
        status: 200,
        body: br#"{"data":[{"volid":"local:backup/vzdump-qemu-100-2024_01_01-00_00_00.vma.zst","vmid":"905","content":"backup"}]}"#,
    });

    let error = call_with_token(
        &h,
        &h.token,
        "apply_restore_new_vmid",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 650}),
    )
    .await
    .expect_err("the archive's ownership changed since this was planned");
    assert!(
        error.contains("ownership changed since this was planned"),
        "{error}"
    );

    let reqs = h.requests();
    assert!(
        !reqs
            .iter()
            .any(|r| r.method == "POST" && r.path == "/api2/json/nodes/pve2/qemu"),
        "nothing may be sent to the cluster when the archive's owner changed since plan: \
         {reqs:?}"
    );
}

/// Finding D (MEC-1191 re-review): `approve_proxmox_change_set`'s own
/// `authorize_backup_owner` call for `RestoreNewVmidAction` -- finding 6 /
/// F2 from MEC-1180 -- has no regression test. Removing that call (and the
/// matching one in `get_proxmox_change_set`) left every existing restore
/// test passing, because they all approve with a token scoped to every
/// fixture guest.
///
/// Plans with the wide `h.token`, then approves with `h.mid_range_token`
/// (scoped to `vmid:600-699`, which covers the restore target 650 but not
/// the archive's owner, 100). With the owner check present, approval must
/// be refused on the owner's scope; removing it would let this approval
/// through on the target-vmid scope check alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approving_a_restore_requires_authority_over_the_archive_owner_too() {
    let h = restore_harness().await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_restore_new_vmid",
        json!({
            "cluster": "pve3",
            "node": "pve2",
            "target_vmid": 650,
            "kind": "qemu",
            "volid": "local:backup/vzdump-qemu-100-2024_01_01-00_00_00.vma.zst",
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    let error = call_with_token(
        &h,
        &h.mid_range_token,
        "approve_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 650}),
    )
    .await
    .expect_err(
        "an approver scoped only to the restore target, not the archive's owner, must be refused",
    );
    assert!(
        error.contains("belongs to guest 100")
            && error.contains("outside this caller's guest scope"),
        "{error}"
    );
}
