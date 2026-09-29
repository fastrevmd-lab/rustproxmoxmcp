//! `--allow-direct-commit` gates the tools that mutate a Proxmox guest in one
//! call with no independent second-principal approval.
//!
//! The interrupting lifecycle verbs (`stop_vm`, `shutdown_vm`, `reset_vm`,
//! `stop_container`, `restart_container`), `clone_vm`, `create_vm`,
//! `create_container`, `resize_disk`, and `create_backup` act on Proxmox
//! immediately -- there is no change-set flow to route an operational command
//! like "stop this guest" through. Without the flag, the server must refuse
//! those calls before they ever reach Proxmox. With the flag, the call
//! proceeds.
//!
//! `start_vm` and `start_container` are deliberately not gated (additive, not
//! disruptive), which `start_vm_is_not_gated_by_direct_commit` pins so a
//! future change to the gated-tool list is a visible decision, not silent
//! drift either way.
//!
//! All fixture VMIDs, node names and addresses below are synthetic; nothing
//! here reaches a real Proxmox cluster.

mod common;

use common::{Route, TestServer, TokenSpec};
use serde_json::json;

/// Every tool name the direct-commit gate covers, alongside the arguments a
/// minimal successful call needs. Kept as one table so a test can iterate it
/// and a reviewer can see the whole gated surface in one place.
struct GatedCall {
    tool: &'static str,
    args: serde_json::Value,
}

fn gated_calls() -> Vec<GatedCall> {
    vec![
        GatedCall {
            tool: "stop_vm",
            args: json!({"cluster": "pve3", "vmid": 600}),
        },
        GatedCall {
            tool: "shutdown_vm",
            args: json!({"cluster": "pve3", "vmid": 600}),
        },
        GatedCall {
            tool: "reset_vm",
            args: json!({"cluster": "pve3", "vmid": 600}),
        },
        GatedCall {
            tool: "stop_container",
            args: json!({"cluster": "pve3", "vmid": 617}),
        },
        GatedCall {
            tool: "restart_container",
            args: json!({"cluster": "pve3", "vmid": 617}),
        },
        GatedCall {
            tool: "clone_vm",
            args: json!({"cluster": "pve3", "vmid": 600, "newid": 601, "full": true}),
        },
        GatedCall {
            tool: "create_vm",
            args: json!({"cluster": "pve3", "node": "pve2", "vmid": 602, "config": {"name": "gate-602"}}),
        },
        GatedCall {
            tool: "create_container",
            args: json!({"cluster": "pve3", "node": "pve2", "vmid": 618, "config": {"hostname": "gate-618"}}),
        },
        GatedCall {
            tool: "resize_disk",
            args: json!({"cluster": "pve3", "vmid": 600, "disk": "scsi0", "size": "+8G"}),
        },
        GatedCall {
            tool: "create_backup",
            args: json!({"cluster": "pve3", "vmid": 600, "storage": "local", "mode": "snapshot"}),
        },
    ]
}

/// Every tool name above, for building a token scoped to exactly this surface.
fn gated_tool_names() -> Vec<String> {
    gated_calls()
        .into_iter()
        .map(|call| call.tool.to_owned())
        .chain(["start_vm".to_owned(), "start_container".to_owned()])
        .collect()
}

/// Routes for every endpoint a gated call in [`gated_calls`] would reach if
/// the direct-commit gate let it through. `qemu/600` and `lxc/617` are
/// ordinary, unprotected, running guests; `602` and `618` are free VMIDs a
/// create may claim; `601` is a free VMID a clone may claim.
fn gate_routes() -> Vec<Route> {
    vec![
        Route {
            path: "/api2/json/nodes",
            status: 200,
            body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
        },
        Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: br#"{"data":[
                {"id":"qemu/600","type":"qemu","vmid":600,"name":"gate-600","node":"pve2","status":"running","tags":""},
                {"id":"lxc/617","type":"lxc","vmid":617,"name":"gate-617","node":"pve2","status":"running","tags":""}
            ]}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/600/status/start",
            status: 200,
            body: br#"{"data":"UPID:pve2:00000001:00000001:00000001:qmstart:600:root@pam:"}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/600/status/stop",
            status: 200,
            body: br#"{"data":"UPID:pve2:00000002:00000002:00000002:qmstop:600:root@pam:"}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/600/status/shutdown",
            status: 200,
            body: br#"{"data":"UPID:pve2:00000003:00000003:00000003:qmshutdown:600:root@pam:"}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/600/status/reset",
            status: 200,
            body: br#"{"data":"UPID:pve2:00000004:00000004:00000004:qmreset:600:root@pam:"}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/status/start",
            status: 200,
            body: br#"{"data":"UPID:pve2:00000005:00000005:00000005:vzstart:617:root@pam:"}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/status/stop",
            status: 200,
            body: br#"{"data":"UPID:pve2:00000006:00000006:00000006:vzstop:617:root@pam:"}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/status/reboot",
            status: 200,
            body: br#"{"data":"UPID:pve2:00000007:00000007:00000007:vzreboot:617:root@pam:"}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/600/clone",
            status: 200,
            body: br#"{"data":"UPID:pve2:00000008:00000008:00000008:qmclone:600:root@pam:"}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu",
            status: 200,
            body: br#"{"data":"UPID:pve2:00000009:00000009:00000009:qmcreate:602:root@pam:"}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc",
            status: 200,
            body: br#"{"data":"UPID:pve2:0000000a:0000000a:0000000a:vzcreate:618:root@pam:"}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/600/resize",
            status: 200,
            body: br#"{"data":null}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/vzdump",
            status: 200,
            body: br#"{"data":"UPID:pve2:0000000b:0000000b:0000000b:vzdump:600:root@pam:"}"#,
        },
    ]
}

fn spec() -> TokenSpec {
    TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: gated_tool_names(),
        guests: vec!["*".to_owned()],
    }
}

/// Without `--allow-direct-commit`, every gated tool is refused before it
/// reaches Proxmox, and the refusal names the flag a caller would set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_calls_never_reach_proxmox_and_name_the_flag() {
    for call in gated_calls() {
        let h = TestServer::start_with_direct_commit(spec(), gate_routes(), false).await;

        let err = common::call(&h, call.tool, call.args.clone())
            .await
            .expect_err(&format!(
                "{} must be refused when --allow-direct-commit is not set",
                call.tool
            ));
        assert!(
            err.contains("allow-direct-commit"),
            "{}: refusal must name the flag, got: {err}",
            call.tool
        );

        // The gate runs after the guest is resolved (a read against
        // `/cluster/resources`) but before the mutating call, so a refused
        // call may still have made a GET. It must never have POSTed -- every
        // gated tool's actual mutation is a POST.
        let posted = h.requests().into_iter().any(|r| r.method == "POST");
        assert!(
            !posted,
            "{}: a refused direct-commit call must not POST to Proxmox",
            call.tool
        );
    }
}

/// With `--allow-direct-commit`, every gated tool proceeds and reaches
/// Proxmox -- the flag is a process-wide switch, not a per-call one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_gated_tool_succeeds_with_the_flag() {
    let h = TestServer::start_with_direct_commit(spec(), gate_routes(), true).await;

    for call in gated_calls() {
        common::call(&h, call.tool, call.args.clone())
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "{} must succeed with --allow-direct-commit: {error}",
                    call.tool
                )
            });
    }
}

/// `start_vm` and `start_container` are additive, not disruptive, and must
/// stay reachable with no flag at all -- pinned so a future change to the
/// gated-tool list is a visible decision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_verbs_are_not_gated_by_direct_commit() {
    let h = TestServer::start_with_direct_commit(spec(), gate_routes(), false).await;

    common::call(&h, "start_vm", json!({"cluster": "pve3", "vmid": 600}))
        .await
        .expect("start_vm is additive and must not require --allow-direct-commit");

    common::call(
        &h,
        "start_container",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("start_container is additive and must not require --allow-direct-commit");
}

/// `create_backup` with `mode: "stop"` is exactly as disruptive as `stop_vm`
/// -- it stops the guest for the duration of the backup -- so it must be
/// refused under the same gate as the lifecycle tools even though
/// `create_backup` itself is gated unconditionally regardless of mode. This
/// proves the interruption fix (`tier::backup_interrupts`) and the
/// direct-commit fix compose correctly: a `snapshot`-mode backup and a
/// `stop`-mode backup are both refused without the flag, and both succeed
/// with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_backup_with_stop_mode_is_refused_under_the_same_gate() {
    let h = TestServer::start_with_direct_commit(spec(), gate_routes(), false).await;

    let err = common::call(
        &h,
        "create_backup",
        json!({"cluster": "pve3", "vmid": 600, "storage": "local", "mode": "stop"}),
    )
    .await
    .expect_err("mode: stop must be refused without --allow-direct-commit");
    assert!(
        err.contains("allow-direct-commit"),
        "refusal must name the flag, got: {err}"
    );

    let h = TestServer::start_with_direct_commit(spec(), gate_routes(), true).await;
    common::call(
        &h,
        "create_backup",
        json!({"cluster": "pve3", "vmid": 600, "storage": "local", "mode": "stop"}),
    )
    .await
    .expect("mode: stop must succeed with --allow-direct-commit");
}
