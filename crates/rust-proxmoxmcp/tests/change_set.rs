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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_protected_guest_with_matching_waiver_can_be_applied() {
    use rust_proxmoxmcp_core::waiver::{WaiverEntry, WaiverFile};
    use std::sync::Arc;

    // Create a waiver that expires far in the future (year 2100).
    // Use vmid 618 (an lxc) instead of 905 (qemu) since destroy_container
    // only handles lxc guests.
    let waiver = WaiverEntry::new(
        "pve3".to_owned(),
        618,
        4102444800, // 2100-01-01 in Unix time
        "test waiver".to_owned(),
        Some("TEST-123".to_owned()),
    );
    let waivers = Arc::new(WaiverFile::with_entries(vec![waiver]));

    let spec = common::TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_proxmox_destroy".to_owned(),
            // The operation's own tool: the per-operation scope check refuses
            // a plan whose token holds only the generic handler.
            "delete_vm".to_owned(),
            // The fixture guest is an LXC, and a guest destroy authorises
            // against its own type: delete_container, not delete_vm.
            "delete_container".to_owned(),
            "approve_proxmox_change_set".to_owned(),
            "apply_proxmox_change_set".to_owned(),
        ],
        guests: vec!["*".to_owned()],
    };

    let routes = vec![
        common::Route {
            path: "/api2/json/nodes",
            status: 200,
            body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
        },
        common::Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: br#"{"data":[{"id":"lxc/618","type":"lxc","vmid":618,"name":"test-protected","node":"pve2","status":"stopped","tags":"protected"}]}"#,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/lxc/618",
            status: 200,
            body: br#"{"data":"UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:618:root@pam:"}"#,
        },
    ];

    let h = common::TestServer::start_with_config(spec, routes, waivers, false).await;

    // Script the task completion.
    h.script_task_completion(
        "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:618:root@pam:",
        "OK",
    );

    // Plan the destroy.
    let planned = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 618}),
    )
    .await
    .expect("plan should succeed with matching waiver");

    // The waiver allows planning. Check if approval is still needed.
    let id = planned["change_set_id"].as_str().expect("id");
    let state = planned["state"].as_str().expect("state");

    // If not already approved, approve as second principal.
    if state != "Approved" {
        common::approve_as_second_principal_for(&h, id, "pve3", 618).await;
    }

    // Apply should succeed.
    let result = common::call(
        &h,
        "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 618}),
    )
    .await;

    assert!(
        result.is_ok(),
        "apply should succeed with matching waiver: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_protected_guest_with_lab_mode_can_be_applied() {
    use rust_proxmoxmcp_core::waiver::WaiverFile;
    use std::sync::Arc;

    let spec = common::TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_proxmox_destroy".to_owned(),
            // The operation's own tool: the per-operation scope check refuses
            // a plan whose token holds only the generic handler.
            "delete_vm".to_owned(),
            // The fixture guest is an LXC, and a guest destroy authorises
            // against its own type: delete_container, not delete_vm.
            "delete_container".to_owned(),
            "approve_proxmox_change_set".to_owned(),
            "apply_proxmox_change_set".to_owned(),
        ],
        guests: vec!["*".to_owned()],
    };

    // Use vmid 619 (an lxc) instead of 905 (qemu) since destroy_container
    // only handles lxc guests.
    let routes = vec![
        common::Route {
            path: "/api2/json/nodes",
            status: 200,
            body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
        },
        common::Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: br#"{"data":[{"id":"lxc/619","type":"lxc","vmid":619,"name":"test-protected","node":"pve2","status":"stopped","tags":"protected"}]}"#,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/lxc/619",
            status: 200,
            body: br#"{"data":"UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:619:root@pam:"}"#,
        },
    ];

    let h = common::TestServer::start_with_config(
        spec,
        routes,
        Arc::new(WaiverFile::empty()),
        true, // lab_mode = true
    )
    .await;

    // Script the task completion.
    h.script_task_completion(
        "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:619:root@pam:",
        "OK",
    );

    // Plan the destroy.
    let planned = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 619}),
    )
    .await
    .expect("plan should succeed with lab_mode");

    // Lab mode allows planning. Check if approval is still needed.
    let id = planned["change_set_id"].as_str().expect("id");
    let state = planned["state"].as_str().expect("state");

    // If not already approved, approve as second principal.
    if state != "Approved" {
        common::approve_as_second_principal_for(&h, id, "pve3", 619).await;
    }

    // Apply should succeed.
    let result = common::call(
        &h,
        "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 619}),
    )
    .await;

    assert!(
        result.is_ok(),
        "apply should succeed with lab_mode: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_protected_guest_with_expired_waiver_is_refused() {
    use rust_proxmoxmcp_core::waiver::{WaiverEntry, WaiverFile};
    use std::sync::Arc;

    // Create a waiver that expired in the past (year 2000).
    let waiver = WaiverEntry::new(
        "pve3".to_owned(),
        905,
        946684800, // 2000-01-01 in Unix time
        "expired waiver".to_owned(),
        None,
    );
    let waivers = Arc::new(WaiverFile::with_entries(vec![waiver]));

    let spec = common::TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec!["plan_proxmox_destroy".to_owned()],
        guests: vec!["*".to_owned()],
    };

    let routes = vec![
        common::Route {
            path: "/api2/json/nodes",
            status: 200,
            body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
        },
        common::Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: br#"{"data":[{"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2","status":"running","tags":"protected"}]}"#,
        },
    ];

    let h = common::TestServer::start_with_config(spec, routes, waivers, false).await;

    // Plan should fail because the waiver is expired.
    let err = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 905}),
    )
    .await
    .expect_err("plan should fail with expired waiver");

    assert!(
        err.to_string().to_lowercase().contains("protect"),
        "error should mention protection: {err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_set_without_a_stored_preview_cannot_be_approved() {
    let h = common::handler_with_guest(617, false).await;
    let planned = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    // Reproduce the record a failed preview write leaves behind.
    h.strip_preview(&id).await;

    let err = common::call_with_token(
        &h,
        &h.second_token,
        "approve_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect_err("a previewless change set must not be approvable");
    assert!(
        err.to_string().to_lowercase().contains("preview"),
        "the refusal must name the missing preview: {err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_set_without_a_stored_preview_cannot_be_applied() {
    // Since mecmcp 0.23.0 neither approve nor the coordinator will let an
    // approved change set exist without a preview, so this state is only
    // reachable the way the guard's own comment describes: a record an older
    // binary persisted. Write that state file by hand, start a server on it,
    // and confirm apply still refuses. Dropping this test because the tools can
    // no longer produce the state would leave the guard untested on the exact
    // upgrade path it was written for.
    let dir = tempfile::TempDir::new().expect("temp dir");
    let state_path = dir.path().join("changesets.json");

    let id = {
        let h = common::handler_with_guest_on_state(617, false, Some(state_path.clone())).await;
        let planned = common::call(
            &h,
            "plan_proxmox_destroy",
            json!({"cluster": "pve3", "vmid": 617}),
        )
        .await
        .expect("plan");
        let id = planned["change_set_id"].as_str().expect("id").to_owned();
        common::approve_as_second_principal(&h, &id).await;
        id
    };

    // Rewrite the persisted record into what a pre-0.23.0 binary would have
    // left behind: approved, no preview, and an approval digest over the v4
    // tuple, which has no preview field at all. Recomputing that digest is the
    // point -- leave it as the v5 value and persistence rejects the file as
    // tampered, so the test would pass without ever reaching apply.
    let mut state = mecmcp_changeset::persistence::read_state(&state_path, 8 * 1024 * 1024)
        .expect("read the stored state");
    {
        let record = state
            .change_sets
            .get_mut(&id)
            .expect("the record is stored");
        record.preview = None;
        let approval = record.approval.as_mut().expect("it was approved");
        approval.digest_version = 4;
        approval.digest = mecmcp_changeset::digest::compute_approval_digest_v4(
            &id,
            &record.digest,
            &record.owner,
            approval.approver.as_deref().expect("an approver"),
            approval.approved_at_unix,
        );
    }
    mecmcp_changeset::persistence::write_state_for_test(&state_path, &state, 8 * 1024 * 1024)
        .expect("persist the older-binary state");

    let h = common::handler_with_guest_on_state(617, false, Some(state_path.clone())).await;
    let err = common::call(
        &h,
        "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect_err("a previewless change set must not apply");
    assert!(
        err.to_string().to_lowercase().contains("preview"),
        "the refusal must name the missing preview: {err}"
    );
    let destroys = h
        .requests()
        .into_iter()
        .filter(|request| request.method == "DELETE")
        .count();
    assert_eq!(destroys, 0, "a refused apply must not reach the cluster");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_guest_that_moved_is_refused_even_while_the_resource_cache_is_warm() {
    let h = common::handler_with_guest(617, false).await;
    let planned = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();
    common::approve_as_second_principal(&h, &id).await;

    // Move the guest the way Proxmox does: without telling the server. The
    // sibling helper invalidates the index, which is what let the original
    // fingerprint test pass against a handler that never dropped the cache.
    h.move_guest_to_node_leaving_cache_stale(617, "pve3");

    let err = common::call(
        &h,
        "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect_err("a guest that moved must not be destroyed on an approval bound to its old state");
    assert!(
        err.to_string().to_lowercase().contains("fingerprint"),
        "the refusal must name the fingerprint: {err}"
    );

    let destroys = h
        .requests()
        .into_iter()
        .filter(|request| request.method == "DELETE")
        .count();
    assert_eq!(destroys, 0, "the guest must not be touched");
}

/// Proxmox refuses to destroy a running guest, so planning one produces a
/// change set that cannot succeed. Under two-person control that is expensive:
/// the plan succeeds, a second person approves, and only then does it fail —
/// spending an approval and requiring the same human to be asked again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn planning_a_destroy_of_a_running_guest_is_refused() {
    let h = common::TestServer::start_with_routes(
        common::TokenSpec {
            clusters: vec!["pve3".to_owned()],
            tools: vec![
                "plan_proxmox_destroy".to_owned(),
                "get_proxmox_change_set".to_owned(),
                "approve_proxmox_change_set".to_owned(),
                "apply_proxmox_change_set".to_owned(),
                "delete_container".to_owned(),
            ],
            guests: vec!["*".to_owned()],
        },
        vec![
            common::Route {
                path: "/api2/json/nodes",
                status: 200,
                body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
            },
            common::Route {
                path: "/api2/json/cluster/resources",
                status: 200,
                body: br#"{"data":[{"id":"lxc/621","type":"lxc","vmid":621,"name":"still-running","node":"pve2","status":"running","tags":"test"}]}"#,
            },
        ],
    )
    .await;

    let err = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 621}),
    )
    .await
    .expect_err("a running guest cannot be destroyed, so it must not be planned");

    assert!(err.contains("running"), "the refusal must say why: {err}");
    assert!(
        err.to_lowercase().contains("stop"),
        "the refusal must name the prerequisite: {err}"
    );
    assert!(
        err.to_lowercase().contains("approval"),
        "the refusal should explain why it happens at plan time: {err}"
    );
}

/// A plan builds the fingerprint that apply re-checks, so it must not build it
/// from a cached read. Stopping a guest and planning immediately used to record
/// `running` from a snapshot seconds old, and the apply then refused its own
/// plan as changed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plan_reads_through_a_stale_snapshot() {
    let h = common::TestServer::start_with_routes(
        common::TokenSpec {
            clusters: vec!["pve3".to_owned()],
            tools: vec![
                "plan_proxmox_destroy".to_owned(),
                "get_proxmox_change_set".to_owned(),
                "get_container_config".to_owned(),
                "delete_container".to_owned(),
            ],
            guests: vec!["*".to_owned()],
        },
        common::default_guest_routes(617, false),
    )
    .await;

    // Warm the /cluster/resources snapshot -- the cache the plan reads through.
    // This must succeed, or nothing is cached and the test proves nothing.
    common::call(
        &h,
        "get_container_config",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("the warming read must succeed or the cache is never populated");

    // The world moves underneath, without telling the server.
    h.move_guest_to_node_leaving_cache_stale(617, "pve3");

    let planned = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("plan");

    // Assert on the `node` line, not on the string "pve3": the *cluster* is
    // also called pve3, so a substring match passes no matter which node the
    // plan read. That collision is exactly what makes this worth pinning.
    let preview = planned["preview"].as_str().expect("preview");
    let node_line = preview
        .lines()
        .find(|line| line.trim_start().starts_with("node "))
        .expect("the preview names the node");
    assert!(
        node_line.contains("pve3"),
        "the plan must reflect the guest's current node, not the cached one: {node_line:?}"
    );
}

/// `/cluster/resources` can report a status this server cannot interpret. A
/// destroy needs a *confirmed* stopped guest, so anything else is refused —
/// treating an unreadable status as good enough would hand out the unusable
/// plan the check exists to prevent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn planning_a_destroy_needs_a_confirmed_stopped_guest() {
    let h = common::TestServer::start_with_routes(
        common::TokenSpec {
            clusters: vec!["pve3".to_owned()],
            tools: vec![
                "plan_proxmox_destroy".to_owned(),
                "get_proxmox_change_set".to_owned(),
                "delete_container".to_owned(),
            ],
            guests: vec!["*".to_owned()],
        },
        vec![
            common::Route {
                path: "/api2/json/nodes",
                status: 200,
                body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
            },
            common::Route {
                path: "/api2/json/cluster/resources",
                status: 200,
                body: br#"{"data":[{"id":"lxc/622","type":"lxc","vmid":622,"name":"unreadable","node":"pve2","status":"unknown","tags":"test"}]}"#,
            },
        ],
    )
    .await;

    let err = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 622}),
    )
    .await
    .expect_err("a guest that is not confirmed stopped must not be planned");
    assert!(
        err.contains("unknown"),
        "the refusal must report the status seen: {err}"
    );
    assert!(err.contains("stopped"), "and name what is required: {err}");
}

/// delete_iso must refuse a backup/ volid at plan time to prevent authorization
/// bypass (a token scoped only for delete_iso deleting backups).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plan_delete_iso_refuses_backup_volid() {
    let h = common::TestServer::start_with_routes(
        common::TokenSpec {
            clusters: vec!["pve3".to_owned()],
            tools: vec!["plan_proxmox_destroy".to_owned(), "delete_iso".to_owned()],
            guests: vec!["*".to_owned()],
        },
        vec![
            common::Route {
                path: "/api2/json/nodes",
                status: 200,
                body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
            },
            common::Route {
                path: "/api2/json/cluster/resources",
                status: 200,
                body: br#"{"data":[{"id":"lxc/617","type":"lxc","vmid":617,"name":"test","node":"pve2","status":"stopped"}]}"#,
            },
        ],
    )
    .await;

    let err = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({
            "cluster": "pve3",
            "vmid": 617,
            "op": "delete_iso",
            "storage": "local",
            "storage_node": "pve2",
            "volid": "local:backup/vzdump-lxc-617.tar.zst"
        }),
    )
    .await
    .expect_err("delete_iso must refuse a backup/ volid");

    assert!(
        err.contains("backup") && err.contains("iso"),
        "refusal must mention both content kinds: {err}"
    );
}

/// delete_backup must refuse an iso/ volid at plan time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plan_delete_backup_refuses_iso_volid() {
    let h = common::TestServer::start_with_routes(
        common::TokenSpec {
            clusters: vec!["pve3".to_owned()],
            tools: vec!["plan_proxmox_destroy".to_owned(), "delete_backup".to_owned()],
            guests: vec!["*".to_owned()],
        },
        vec![
            common::Route {
                path: "/api2/json/nodes",
                status: 200,
                body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
            },
            common::Route {
                path: "/api2/json/cluster/resources",
                status: 200,
                body: br#"{"data":[{"id":"lxc/617","type":"lxc","vmid":617,"name":"test","node":"pve2","status":"stopped"}]}"#,
            },
        ],
    )
    .await;

    let err = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({
            "cluster": "pve3",
            "vmid": 617,
            "op": "delete_backup",
            "storage": "local",
            "storage_node": "pve2",
            "volid": "local:iso/debian-13.iso"
        }),
    )
    .await
    .expect_err("delete_backup must refuse an iso/ volid");

    assert!(
        err.contains("iso") && err.contains("backup"),
        "refusal must mention both content kinds: {err}"
    );
}

/// Storage prefix in volid must match the storage parameter.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plan_refuses_volid_storage_mismatch() {
    let h = common::TestServer::start_with_routes(
        common::TokenSpec {
            clusters: vec!["pve3".to_owned()],
            tools: vec!["plan_proxmox_destroy".to_owned(), "delete_backup".to_owned()],
            guests: vec!["*".to_owned()],
        },
        vec![
            common::Route {
                path: "/api2/json/nodes",
                status: 200,
                body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
            },
            common::Route {
                path: "/api2/json/cluster/resources",
                status: 200,
                body: br#"{"data":[{"id":"lxc/617","type":"lxc","vmid":617,"name":"test","node":"pve2","status":"stopped"}]}"#,
            },
        ],
    )
    .await;

    let err = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({
            "cluster": "pve3",
            "vmid": 617,
            "op": "delete_backup",
            "storage": "nas-backup",
            "storage_node": "pve2",
            "volid": "local:backup/vzdump-lxc-617.tar.zst"
        }),
    )
    .await
    .expect_err("must refuse storage mismatch");

    assert!(
        err.contains("local") && err.contains("nas-backup"),
        "refusal must mention both storage names: {err}"
    );
}

/// restore_backup must refuse a non-backup volid at plan time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plan_restore_refuses_non_backup_volid() {
    let h = common::TestServer::start_with_routes(
        common::TokenSpec {
            clusters: vec!["pve3".to_owned()],
            tools: vec!["plan_proxmox_destroy".to_owned(), "restore_backup".to_owned()],
            guests: vec!["*".to_owned()],
        },
        vec![
            common::Route {
                path: "/api2/json/nodes",
                status: 200,
                body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
            },
            common::Route {
                path: "/api2/json/cluster/resources",
                status: 200,
                body: br#"{"data":[{"id":"lxc/617","type":"lxc","vmid":617,"name":"test","node":"pve2","status":"stopped"}]}"#,
            },
        ],
    )
    .await;

    let err = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({
            "cluster": "pve3",
            "vmid": 617,
            "op": "restore_backup",
            "volid": "local:iso/debian-13.iso"
        }),
    )
    .await
    .expect_err("restore_backup must refuse an iso/ volid");

    assert!(
        err.contains("iso") && err.contains("backup"),
        "refusal must mention both content kinds: {err}"
    );
}

#[tokio::test]
async fn an_approved_change_set_will_not_give_up_its_preview() {
    let h = common::handler_with_guest(617, false).await;
    let planned = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    common::approve_as_second_principal(&h, &id).await;

    // mecmcp 0.23.0 binds the preview digest into the approval digest, so
    // dropping the preview after approval is refused by the coordinator
    // itself -- one layer earlier than the apply-time guard. Without this the
    // approval would vouch for a preview that no longer exists.
    let err = h
        .try_strip_preview(&id)
        .await
        .expect_err("an approved change set must not lose its preview");
    assert!(
        err.to_string().to_lowercase().contains("preview"),
        "the refusal must name the preview: {err}"
    );

    // And the preview is genuinely still there afterwards.
    let record = h
        .coordinator()
        .change_sets()
        .await
        .into_iter()
        .find(|record| record.id == id)
        .expect("the change set exists");
    assert!(
        record.preview.is_some(),
        "the refused write must not have partially applied"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approval_is_spent_by_the_first_apply_and_cannot_destroy_twice() {
    use rust_proxmoxmcp_core::waiver::WaiverFile;
    use std::sync::Arc;

    // The approval must be spent before the destroy is issued, not after it
    // returns. mecmcp 0.22.0 makes `claim_change_set_for_apply` the only legal
    // `Approved -> Applying` transition precisely so two applies cannot both
    // read `Approved` and both send a DELETE. Nothing caught the regression
    // when this server still settled the record after executing: the failing
    // write was logged, not returned, so every existing test stayed green
    // while the record sat re-appliable.
    let spec = common::TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_proxmox_destroy".to_owned(),
            "delete_vm".to_owned(),
            "delete_container".to_owned(),
            "approve_proxmox_change_set".to_owned(),
            "apply_proxmox_change_set".to_owned(),
        ],
        guests: vec!["*".to_owned()],
    };
    let routes = vec![
        common::Route {
            path: "/api2/json/nodes",
            status: 200,
            body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
        },
        common::Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: br#"{"data":[{"id":"lxc/619","type":"lxc","vmid":619,"name":"test-protected","node":"pve2","status":"stopped","tags":"protected"}]}"#,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/lxc/619",
            status: 200,
            body: br#"{"data":"UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:619:root@pam:"}"#,
        },
    ];

    let h =
        common::TestServer::start_with_config(spec, routes, Arc::new(WaiverFile::empty()), true)
            .await;
    h.script_task_completion(
        "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:619:root@pam:",
        "OK",
    );

    let planned = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 619}),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();
    if planned["state"].as_str() != Some("Approved") {
        common::approve_as_second_principal_for(&h, &id, "pve3", 619).await;
    }

    common::call(
        &h,
        "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 619}),
    )
    .await
    .expect("the first apply succeeds");

    let after_first = h
        .requests()
        .into_iter()
        .filter(|request| request.method == "DELETE")
        .count();
    assert_eq!(after_first, 1, "the first apply issues exactly one destroy");

    // Same change set, same approval, second time.
    let err = common::call(
        &h,
        "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 619}),
    )
    .await
    .expect_err("a spent approval must not apply again");

    let after_second = h
        .requests()
        .into_iter()
        .filter(|request| request.method == "DELETE")
        .count();
    assert_eq!(
        after_second, 1,
        "the second apply must not reach the cluster, but {after_second} destroys were sent: {err}"
    );
}
