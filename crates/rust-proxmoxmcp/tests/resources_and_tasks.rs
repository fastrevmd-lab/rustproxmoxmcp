//! Changing a container's allocation, and stopping a running task.

mod common;

use serde_json::json;

fn routes() -> Vec<common::Route> {
    vec![
        common::Route {
            path: "/api2/json/nodes",
            status: 200,
            body: br#"{"data":[{"node":"pve2","status":"online"},{"node":"pve3","status":"online"}]}"#,
        },
        common::Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: br#"{"data":[{"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2","status":"running","tags":"protected"},{"id":"lxc/617","type":"lxc","vmid":617,"name":"test-guest-617","node":"pve2","status":"running","tags":"test"},{"id":"qemu/700","type":"qemu","vmid":700,"name":"a-vm","node":"pve2","status":"running","tags":"test"}]}"#,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/lxc/617/config",
            status: 200,
            body: br#"{"data":null}"#,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/tasks/UPID%3Apve2%3A0000A1B2%3A00C3D4E5%3A66BC1234%3Avzdump%3A617%3Aroot%40pam%3A",
            status: 200,
            body: br#"{"data":null}"#,
        },
    ]
}

fn spec(tools: &[&str], guests: &[&str]) -> common::TokenSpec {
    common::TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: tools.iter().map(|t| (*t).to_owned()).collect(),
        guests: guests.iter().map(|g| (*g).to_owned()).collect(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_container_allocation_is_changed() {
    let h = common::TestServer::start_with_routes(
        spec(&["update_container_resources"], &["*"]),
        routes(),
    )
    .await;

    let out = common::call(
        &h,
        "update_container_resources",
        json!({"cluster":"pve3","vmid":617,"cores":4,"memory_mb":2048}),
    )
    .await
    .expect("update");

    assert_eq!(out["cores"], 4);
    let put = h
        .requests()
        .into_iter()
        .find(|r| r.method == "PUT" && r.path.ends_with("/lxc/617/config"));
    assert!(put.is_some(), "Proxmox updates a config with PUT, not POST");
}

/// A call with no fields would PUT nothing and report success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_resource_change_is_refused() {
    let h = common::TestServer::start_with_routes(
        spec(&["update_container_resources"], &["*"]),
        routes(),
    )
    .await;

    let err = common::call(
        &h,
        "update_container_resources",
        json!({"cluster":"pve3","vmid":617}),
    )
    .await
    .expect_err("nothing to change must be refused");
    assert!(err.to_lowercase().contains("at least one"), "{err}");
}

/// The endpoint is LXC-only; a QEMU guest would fail inside Proxmox with a
/// message about the path rather than the guest type.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_qemu_guest_is_refused_by_name() {
    let h = common::TestServer::start_with_routes(
        spec(&["update_container_resources"], &["*"]),
        routes(),
    )
    .await;

    let err = common::call(
        &h,
        "update_container_resources",
        json!({"cluster":"pve3","vmid":700,"cores":2}),
    )
    .await
    .expect_err("a VM is not a container");
    assert!(err.to_uppercase().contains("QEMU"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backup_task_can_be_stopped() {
    let h = common::TestServer::start_with_routes(spec(&["stop_task"], &["*"]), routes()).await;

    let out = common::call(
        &h,
        "stop_task",
        json!({
            "cluster":"pve3","node":"pve2",
            "upid":"UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdump:617:root@pam:"
        }),
    )
    .await
    .expect("stop");
    assert!(out["upid"].as_str().expect("upid").contains("vzdump"));
}

/// Stopping a restore half-way leaves a guest that is neither its old self nor
/// its new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopping_a_restore_is_refused() {
    let h = common::TestServer::start_with_routes(spec(&["stop_task"], &["*"]), routes()).await;

    for worker in ["qmrestore", "vzrestore", "qmdestroy", "vzdestroy"] {
        let upid = format!("UPID:pve2:0000A1B2:00C3D4E5:66BC1234:{worker}:617:root@pam:");
        let err = common::call(
            &h,
            "stop_task",
            json!({"cluster":"pve3","node":"pve2","upid":upid}),
        )
        .await
        .expect_err("a restore or destroy must not be interruptible");
        assert!(err.contains("half-way"), "{worker}: {err}");
    }

    let deletes = h
        .requests()
        .into_iter()
        .filter(|r| r.method == "DELETE")
        .count();
    assert_eq!(deletes, 0, "no cancel may be sent");
}

/// A malformed handle cannot be classified, and guessing "safe" would admit the
/// case the check exists to catch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_task_handle_is_refused() {
    let h = common::TestServer::start_with_routes(spec(&["stop_task"], &["*"]), routes()).await;

    let err = common::call(
        &h,
        "stop_task",
        json!({"cluster":"pve3","node":"pve2","upid":"not-a-upid"}),
    )
    .await
    .expect_err("an unreadable handle must be refused");
    assert!(!err.is_empty());
}

/// A task belongs to a node, not a guest, so a narrowed guest scope has nothing
/// to match against.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_narrowed_token_may_not_stop_a_task() {
    let h =
        common::TestServer::start_with_routes(spec(&["stop_task"], &["vmid:600-699"]), routes())
            .await;

    let err = common::call(
        &h,
        "stop_task",
        json!({
            "cluster":"pve3","node":"pve2",
            "upid":"UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdump:617:root@pam:"
        }),
    )
    .await
    .expect_err("a guest-scoped token must not stop a node task");
    assert!(err.contains('*'), "{err}");
}

/// `get_container_ip` reads an LXC interface list, so a QEMU guest has to be
/// refused by name rather than sent to a path that does not exist for it.
///
/// Covers a guard that had no test: removing it failed nothing in the
/// workspace, which was found while sabotage-checking the LXC guard on
/// `update_container_resources` and hitting this one by mistake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_container_ip_refuses_a_qemu_guest_by_name() {
    let h =
        common::TestServer::start_with_routes(spec(&["get_container_ip"], &["*"]), routes()).await;

    let err = common::call(&h, "get_container_ip", json!({"cluster":"pve3","vmid":700}))
        .await
        .expect_err("a VM has no container interface list");
    assert!(
        err.to_uppercase().contains("QEMU") || err.to_lowercase().contains("container"),
        "the refusal must name the guest-type mismatch: {err}"
    );
}
