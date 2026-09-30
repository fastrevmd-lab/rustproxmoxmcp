//! A narrowed guest scope must survive a listing tool, not just a
//! vmid-addressed one.
//!
//! `get_vms`/`get_containers` read `/cluster/resources` and never pass a
//! `vmid` through to `serve_read`'s per-guest authorization check, so
//! without a dedicated filter a token scoped to a handful of guests could
//! enumerate every guest in the cluster.

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
            body: br#"{"data":[
              {"id":"qemu/100","type":"qemu","vmid":100,"name":"out-of-scope","node":"pve2","status":"running","tags":""},
              {"id":"qemu/650","type":"qemu","vmid":650,"name":"in-scope","node":"pve2","status":"running","tags":""}
            ]}"#,
        },
    ]
}

fn spec(guests: &[&str]) -> common::TokenSpec {
    common::TokenSpec {
        clusters: vec!["*".to_owned()],
        tools: vec!["get_vms".to_owned(), "get_containers".to_owned()],
        guests: guests.iter().map(|g| (*g).to_owned()).collect(),
    }
}

/// A token narrowed to `vmid:600-699` calling `get_vms` sees only the guest
/// inside its range, and the pagination envelope's `total` reflects that --
/// not the cluster's real guest count.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_narrowed_token_only_sees_guests_in_its_vmid_range() {
    let h = common::TestServer::start_with_routes(spec(&["vmid:600-699"]), routes()).await;

    let out = common::call(&h, "get_vms", json!({"cluster": "pve3"}))
        .await
        .expect("get_vms");

    let items = out["items"].as_array().expect("items array");
    let vmids: Vec<u64> = items
        .iter()
        .filter_map(|item| item.get("vmid")?.as_u64())
        .collect();

    assert_eq!(
        vmids,
        vec![650],
        "the out-of-scope guest 100 must not appear"
    );
    assert_eq!(
        out["total"], 1,
        "total must reflect the filtered count, not the cluster's real size"
    );
}

/// An unrestricted (`*`) token still sees every guest -- the filter must not
/// narrow a wildcard grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wildcard_token_sees_every_guest() {
    let h = common::TestServer::start_with_routes(spec(&["*"]), routes()).await;

    let out = common::call(&h, "get_vms", json!({"cluster": "pve3"}))
        .await
        .expect("get_vms");

    let items = out["items"].as_array().expect("items array");
    let vmids: Vec<u64> = items
        .iter()
        .filter_map(|item| item.get("vmid")?.as_u64())
        .collect();

    assert_eq!(vmids, vec![100, 650]);
    assert_eq!(out["total"], 2);
}
