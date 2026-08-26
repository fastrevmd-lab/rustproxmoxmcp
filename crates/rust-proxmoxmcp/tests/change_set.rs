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
            body: br#"{"data":[{"id":"lxc/618","type":"lxc","vmid":618,"name":"test-protected","node":"pve2","status":"running","tags":"protected"}]}"#,
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
            body: br#"{"data":[{"id":"lxc/619","type":"lxc","vmid":619,"name":"test-protected","node":"pve2","status":"running","tags":"protected"}]}"#,
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
    let h = common::handler_with_guest(617, false).await;
    let planned = common::call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    // Approve while the preview is still present, then lose it. Apply carries
    // its own guard because it is a separate tool behind a separate scope.
    common::approve_as_second_principal(&h, &id).await;
    h.strip_preview(&id).await;

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
    assert_eq!(destroys, 0, "the guest must not be touched");
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
