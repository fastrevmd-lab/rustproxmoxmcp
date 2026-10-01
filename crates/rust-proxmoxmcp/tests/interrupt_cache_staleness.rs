//! A `protected` tag added to a guest between calls must be honoured by the
//! very next interrupting call, not only once the 10s resource cache expires.
//!
//! The plan/apply (`plan_proxmox_destroy`) and HA-rule paths already drop the
//! resource cache immediately before they resolve, precisely so a waiver or a
//! freshly added `protected` tag is seen right away. The direct-commit
//! lifecycle verbs (`stop_vm`, `shutdown_vm`, `reset_vm`, `stop_container`,
//! `restart_container`) and `stop_task`/`update_container_resources` went
//! through a different code path that trusted whatever `/cluster/resources`
//! snapshot was already cached -- so a guest protected moments ago could
//! still be stopped, reset or have its resources changed without a waiver,
//! for as long as the cache stayed warm.
//!
//! All fixture VMIDs, node names and addresses are synthetic; nothing here
//! reaches a real Proxmox cluster.

mod common;

use common::{Route, TestServer, TokenSpec, default_guest_routes};
use serde_json::json;

fn spec() -> TokenSpec {
    TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "stop_container".to_owned(),
            "restart_container".to_owned(),
            "update_container_resources".to_owned(),
        ],
        guests: vec!["*".to_owned()],
    }
}

/// Mark the fixture guest (`lxc/617`) `protected` in the mock Proxmox's
/// `/cluster/resources` response, without touching the server's resolve
/// cache. This is what a `protected` tag added by an operator between two
/// tool calls looks like: the backend has already moved, nothing has told
/// the cached index.
fn mark_guest_617_protected_leaving_cache_stale(server: &TestServer) {
    server.replace_route(Route {
        path: "/api2/json/cluster/resources",
        status: 200,
        body: br#"{"data":[{"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2","status":"running","tags":"protected"},{"id":"lxc/617","type":"lxc","vmid":617,"name":"test-guest-617","node":"pve2","status":"stopped","tags":"protected"}]}"#,
    });
}

fn lifecycle_routes() -> Vec<Route> {
    let mut routes = default_guest_routes(617, false);
    routes.push(Route {
        path: "/api2/json/nodes/pve2/lxc/617/status/stop",
        status: 200,
        body: br#"{"data":"UPID:pve2:00000001:00000001:00000001:vzstop:617:root@pam:"}"#,
    });
    routes.push(Route {
        path: "/api2/json/nodes/pve2/lxc/617/status/reboot",
        status: 200,
        body: br#"{"data":"UPID:pve2:00000002:00000002:00000002:vzreboot:617:root@pam:"}"#,
    });
    routes
}

/// A `protected` tag added after the resource cache was warmed must still
/// refuse `stop_container`, the next call, not merely once the cache's TTL
/// (300s in this fixture -- comfortably longer than the test) elapses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_container_sees_a_protected_tag_added_after_the_cache_warmed() {
    let h = TestServer::start_with_direct_commit(spec(), lifecycle_routes(), true).await;

    // Warm the resolve cache on the unprotected fixture guest.
    common::call(
        &h,
        "update_container_resources",
        json!({"cluster": "pve3", "vmid": 617, "cores": 1}),
    )
    .await
    .expect("priming call against the unprotected guest must succeed");

    // The guest becomes protected in Proxmox; nothing invalidates the cache.
    mark_guest_617_protected_leaving_cache_stale(&h);

    let err = common::call(
        &h,
        "stop_container",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect_err(
        "stop_container must see the protected tag added since the cache warmed, \
             not serve the stale unprotected snapshot",
    );
    assert!(
        err.contains("protected"),
        "refusal must name protection, got: {err}"
    );
}

/// As above, for `restart_container`: a second member of
/// `tier::INTERRUPTING_TOOLS` that goes through `serve_lifecycle`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_container_sees_a_protected_tag_added_after_the_cache_warmed() {
    let h = TestServer::start_with_direct_commit(spec(), lifecycle_routes(), true).await;

    common::call(
        &h,
        "update_container_resources",
        json!({"cluster": "pve3", "vmid": 617, "cores": 1}),
    )
    .await
    .expect("priming call against the unprotected guest must succeed");

    mark_guest_617_protected_leaving_cache_stale(&h);

    let err = common::call(
        &h,
        "restart_container",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect_err(
        "restart_container must see the protected tag added since the cache warmed, \
             not serve the stale unprotected snapshot",
    );
    assert!(
        err.contains("protected"),
        "refusal must name protection, got: {err}"
    );
}

/// `update_container_resources` is a direct-commit tool, but it is not in
/// `tier::INTERRUPTING_TOOLS` -- wait, it is. It is checked here because it
/// goes through `authorize_low_with_interrupts` rather than
/// `serve_lifecycle`, the other code path this fix touches.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_container_resources_sees_a_protected_tag_added_after_the_cache_warmed() {
    let h = TestServer::start_with_direct_commit(spec(), lifecycle_routes(), true).await;

    // Prime the cache with an unrelated read-shaped call that still resolves
    // the guest: the same `update_container_resources` tool, called once
    // while the guest is still unprotected, against a free-standing route
    // set up for exactly that in `lifecycle_routes`.
    common::call(
        &h,
        "update_container_resources",
        json!({"cluster": "pve3", "vmid": 617, "cores": 1}),
    )
    .await
    .expect("priming call against the unprotected guest must succeed");

    mark_guest_617_protected_leaving_cache_stale(&h);

    let err = common::call(
        &h,
        "update_container_resources",
        json!({"cluster": "pve3", "vmid": 617, "cores": 2}),
    )
    .await
    .expect_err(
        "update_container_resources must see the protected tag added since the cache warmed",
    );
    assert!(
        err.contains("protected"),
        "refusal must name protection, got: {err}"
    );
}
