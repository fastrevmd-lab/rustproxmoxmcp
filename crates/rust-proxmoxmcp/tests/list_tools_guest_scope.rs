//! `list_backups`, `list_isos`, `list_templates`, and `list_tasks` name no
//! guest -- they list data shared across every guest on a storage or a node --
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
