//! `list_backups`, `list_isos`, `list_templates`, `list_tasks`, and the HA
//! rule reads (`list_ha_rules`, `get_ha_rule`) name no single
//! guest -- they list data shared across every guest on a storage, a node, or
//! the cluster --
//! so a grant narrowed to specific guests has no selector that can narrow
//! them, exactly the situation `download_iso` and node-level `stop_task`
//! already refuse for the same reason (see provisioning_tools.rs and
//! resources_and_tasks.rs).

mod common;

use serde_json::json;

fn routes() -> Vec<common::Route> {
    vec![
        common::Route {
            path: "/api2/json/nodes",
            status: 200,
            body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
        },
        common::Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: br#"{"data":[]}"#,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/storage/local/content",
            status: 200,
            body: br#"{"data":[]}"#,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/tasks",
            status: 200,
            body: br#"{"data":[]}"#,
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

/// A storage listing belongs to no guest, so a narrowed guest scope cannot be
/// checked against it -- refused, the same way `download_iso` refuses to
/// write to one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_narrowed_token_may_not_list_storage_content() {
    for tool in ["list_backups", "list_isos", "list_templates"] {
        let h =
            common::TestServer::start_with_routes(spec(&[tool], &["vmid:600-699"]), routes()).await;

        let err = common::call(
            &h,
            tool,
            json!({"cluster":"pve3","node":"pve2","storage":"local"}),
        )
        .await
        .expect_err(&format!(
            "{tool}: a guest-scoped token must not reach storage"
        ));
        assert!(
            err.contains('*'),
            "{tool}: the refusal must name the required scope: {err}"
        );

        let reached_storage = h
            .requests()
            .into_iter()
            .any(|r| r.path.ends_with("/storage/local/content"));
        assert!(
            !reached_storage,
            "{tool}: the request must not reach Proxmox"
        );
    }
}

/// An unrestricted token still gets the ordinary answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unrestricted_token_lists_storage_content() {
    for tool in ["list_backups", "list_isos", "list_templates"] {
        let h = common::TestServer::start_with_routes(spec(&[tool], &["*"]), routes()).await;

        common::call(
            &h,
            tool,
            json!({"cluster":"pve3","node":"pve2","storage":"local"}),
        )
        .await
        .unwrap_or_else(|e| panic!("{tool}: an unrestricted token must be admitted: {e}"));
    }
}

/// A node's task list is shared across every guest on that node, so it needs
/// the same unrestricted-scope requirement as storage -- the read-side
/// counterpart of the node-level `stop_task` guard.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_narrowed_token_may_not_list_tasks() {
    let h =
        common::TestServer::start_with_routes(spec(&["list_tasks"], &["vmid:600-699"]), routes())
            .await;

    let err = common::call(&h, "list_tasks", json!({"cluster":"pve3","node":"pve2"}))
        .await
        .expect_err("a guest-scoped token must not list a node's tasks");
    assert!(err.contains('*'), "{err}");

    let reached_tasks = h.requests().into_iter().any(|r| r.path.ends_with("/tasks"));
    assert!(!reached_tasks, "the request must not reach Proxmox");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unrestricted_token_lists_tasks() {
    let h = common::TestServer::start_with_routes(spec(&["list_tasks"], &["*"]), routes()).await;

    common::call(&h, "list_tasks", json!({"cluster":"pve3","node":"pve2"}))
        .await
        .expect("an unrestricted token must be admitted");
}

/// HA rules name arbitrary guests in their `resources`/`services`
/// (`vm:100`, ...), and neither read filters its output by the caller's guest
/// scope, so a narrowed token would learn about guests outside its grant.
fn ha_routes() -> Vec<common::Route> {
    vec![
        common::Route {
            path: "/api2/json/cluster/ha/rules",
            status: 200,
            body: br#"{"data":[{"rule":"keep-together","type":"colocation","resources":"vm:100,vm:101","affinity":"positive"}]}"#,
        },
        common::Route {
            path: "/api2/json/cluster/ha/rules/keep-together",
            status: 200,
            body: br#"{"data":{"rule":"keep-together","type":"colocation","resources":"vm:100,vm:101","affinity":"positive","digest":"aabbcc"}}"#,
        },
    ]
}

fn ha_args(tool: &str) -> serde_json::Value {
    if tool == "get_ha_rule" {
        json!({"cluster":"pve3","rule":"keep-together"})
    } else {
        json!({"cluster":"pve3"})
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_narrowed_token_may_not_read_ha_rules() {
    for tool in ["list_ha_rules", "get_ha_rule"] {
        let h =
            common::TestServer::start_with_routes(spec(&[tool], &["vmid:600-699"]), ha_routes())
                .await;

        let err = common::call(&h, tool, ha_args(tool))
            .await
            .expect_err(&format!(
                "{tool}: a guest-scoped token must not read HA rules"
            ));
        assert!(
            err.contains('*'),
            "{tool}: the refusal must name the required scope: {err}"
        );

        let reached_ha = h
            .requests()
            .into_iter()
            .any(|r| r.path.contains("/cluster/ha/rules"));
        assert!(!reached_ha, "{tool}: the request must not reach Proxmox");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unrestricted_token_reads_ha_rules() {
    for tool in ["list_ha_rules", "get_ha_rule"] {
        let h = common::TestServer::start_with_routes(spec(&[tool], &["*"]), ha_routes()).await;

        common::call(&h, tool, ha_args(tool))
            .await
            .unwrap_or_else(|e| panic!("{tool}: an unrestricted token must be admitted: {e}"));
    }
}
