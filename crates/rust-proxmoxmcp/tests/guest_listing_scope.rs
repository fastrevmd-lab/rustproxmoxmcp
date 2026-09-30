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

fn tag_routes() -> Vec<common::Route> {
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
              {"id":"qemu/100","type":"qemu","vmid":100,"name":"ci-a","node":"pve2","status":"running","tags":"ci"},
              {"id":"qemu/101","type":"qemu","vmid":101,"name":"ci-b","node":"pve2","status":"running","tags":" ci ; x"},
              {"id":"qemu/102","type":"qemu","vmid":102,"name":"no-tag","node":"pve2","status":"running","tags":""},
              {"id":"lxc/200","type":"lxc","vmid":200,"name":"ci-ct","node":"pve2","status":"running","tags":"ci"},
              {"id":"lxc/201","type":"lxc","vmid":201,"name":"no-tag-ct","node":"pve2","status":"running","tags":""}
            ]}"#,
        },
    ]
}

/// A `tag:ci` token calling `get_vms` sees only the ci-tagged VMs, including
/// one whose tags string is `" ci ; x"` -- proving the listing filter and
/// `GuestIndex`'s own tag selector parse Proxmox's semicolon-separated tag
/// field the same way. Two parsers disagreeing about the same field is an
/// exploit, not a quirk.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tag_scoped_token_sees_only_matching_vms() {
    let h = common::TestServer::start_with_routes(spec(&["tag:ci"]), tag_routes()).await;

    let out = common::call(&h, "get_vms", json!({"cluster": "pve3"}))
        .await
        .expect("get_vms");

    let items = out["items"].as_array().expect("items array");
    let vmids: Vec<u64> = items
        .iter()
        .filter_map(|item| item.get("vmid")?.as_u64())
        .collect();

    assert_eq!(vmids, vec![100, 101], "only the ci-tagged VMs");
    assert_eq!(out["total"], 2);
}

/// As above, for `get_containers`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tag_scoped_token_sees_only_matching_containers() {
    let h = common::TestServer::start_with_routes(spec(&["tag:ci"]), tag_routes()).await;

    let out = common::call(&h, "get_containers", json!({"cluster": "pve3"}))
        .await
        .expect("get_containers");

    let items = out["items"].as_array().expect("items array");
    let vmids: Vec<u64> = items
        .iter()
        .filter_map(|item| item.get("vmid")?.as_u64())
        .collect();

    assert_eq!(vmids, vec![200], "only the ci-tagged container");
    assert_eq!(out["total"], 1);
}

fn pool_routes() -> Vec<common::Route> {
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
              {"id":"qemu/100","type":"qemu","vmid":100,"name":"lab-vm","node":"pve2","status":"running","tags":"","pool":"lab"},
              {"id":"qemu/101","type":"qemu","vmid":101,"name":"other-vm","node":"pve2","status":"running","tags":""},
              {"id":"lxc/200","type":"lxc","vmid":200,"name":"lab-ct","node":"pve2","status":"running","tags":"","pool":"lab"},
              {"id":"lxc/201","type":"lxc","vmid":201,"name":"other-ct","node":"pve2","status":"running","tags":""}
            ]}"#,
        },
    ]
}

/// A `pool:lab` token calling `get_vms`/`get_containers` sees only the pool
/// member of each.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pool_scoped_token_sees_only_pool_members() {
    let h = common::TestServer::start_with_routes(spec(&["pool:lab"]), pool_routes()).await;

    let vms = common::call(&h, "get_vms", json!({"cluster": "pve3"}))
        .await
        .expect("get_vms");
    let vm_ids: Vec<u64> = vms["items"]
        .as_array()
        .expect("items array")
        .iter()
        .filter_map(|item| item.get("vmid")?.as_u64())
        .collect();
    assert_eq!(vm_ids, vec![100]);
    assert_eq!(vms["total"], 1);

    let containers = common::call(&h, "get_containers", json!({"cluster": "pve3"}))
        .await
        .expect("get_containers");
    let ct_ids: Vec<u64> = containers["items"]
        .as_array()
        .expect("items array")
        .iter()
        .filter_map(|item| item.get("vmid")?.as_u64())
        .collect();
    assert_eq!(ct_ids, vec![200]);
    assert_eq!(containers["total"], 1);
}

/// Pagination is applied to the already-filtered listing, not the cluster's
/// full inventory: `offset:1, limit:1` for a narrowed token returns the
/// second in-scope guest, with `total` reflecting the filtered count and
/// `has_more` false once that guest is the last one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pagination_operates_on_the_filtered_listing() {
    let routes = vec![
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
              {"id":"qemu/601","type":"qemu","vmid":601,"name":"in-scope-a","node":"pve2","status":"running","tags":""},
              {"id":"qemu/650","type":"qemu","vmid":650,"name":"in-scope-b","node":"pve2","status":"running","tags":""}
            ]}"#,
        },
    ];
    let h = common::TestServer::start_with_routes(spec(&["vmid:600-699"]), routes).await;

    let out = common::call(
        &h,
        "get_vms",
        json!({"cluster": "pve3", "offset": 1, "limit": 1}),
    )
    .await
    .expect("get_vms");

    let items = out["items"].as_array().expect("items array");
    let vmids: Vec<u64> = items
        .iter()
        .filter_map(|item| item.get("vmid")?.as_u64())
        .collect();

    assert_eq!(vmids, vec![650], "second in-scope guest");
    assert_eq!(out["total"], 2, "total reflects the two in-scope guests");
    assert_eq!(out["has_more"], false);
}

/// An entry with no `node`, or a non-numeric `vmid`, is dropped from the
/// listing rather than crashing the whole response or being guessed at --
/// fail closed, same as `parse_resource_guest` and `fetch_guests`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_entries_are_dropped_from_a_narrowed_listing() {
    let routes = vec![
        common::Route {
            path: "/api2/json/nodes",
            status: 200,
            body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
        },
        common::Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: br#"{"data":[
              {"id":"qemu/650","type":"qemu","vmid":650,"name":"in-scope","node":"pve2","status":"running","tags":""},
              {"id":"qemu/no-node","type":"qemu","vmid":651,"name":"no-node","status":"running","tags":""},
              {"id":"qemu/string-vmid","type":"qemu","vmid":"652","name":"string-vmid","node":"pve2","status":"running","tags":""}
            ]}"#,
        },
    ];
    let h = common::TestServer::start_with_routes(spec(&["vmid:600-699"]), routes).await;

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
        "malformed entries must be dropped, not surfaced or crashed on"
    );
    assert_eq!(out["total"], 1);
}
