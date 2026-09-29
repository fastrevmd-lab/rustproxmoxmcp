//! Proxmox firewall read tools: rules, IPSets, aliases, security groups, and
//! options at cluster, node and guest scope.
//!
//! Every tool gets a populated fixture and an empty fixture, matching the
//! shape Proxmox actually returns for each: an empty array for list-shaped
//! endpoints, and `{}` for the singleton `options` endpoints (Proxmox never
//! omits the object entirely, even with nothing configured).

mod common;

use serde_json::json;

/// Cluster- and node-scoped fixtures. Shared by every cluster/node-level test
/// below; a guest-scoped test layers `default_guest_routes` on top.
fn cluster_routes(rules: &'static [u8], options: &'static [u8]) -> Vec<common::Route> {
    vec![
        common::Route {
            path: "/api2/json/nodes",
            status: 200,
            body:
                br#"{"data":[{"node":"pve2","status":"online"},{"node":"pve3","status":"online"}]}"#,
        },
        common::Route {
            path: "/api2/json/cluster/firewall/rules",
            status: 200,
            body: rules,
        },
        common::Route {
            path: "/api2/json/cluster/firewall/options",
            status: 200,
            body: options,
        },
        common::Route {
            path: "/api2/json/cluster/firewall/groups",
            status: 200,
            body: rules,
        },
        common::Route {
            path: "/api2/json/cluster/firewall/groups/webservers",
            status: 200,
            body: rules,
        },
        common::Route {
            path: "/api2/json/cluster/firewall/ipset",
            status: 200,
            body: rules,
        },
        common::Route {
            path: "/api2/json/cluster/firewall/ipset/blocklist",
            status: 200,
            body: rules,
        },
        common::Route {
            path: "/api2/json/cluster/firewall/aliases",
            status: 200,
            body: rules,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/firewall/rules",
            status: 200,
            body: rules,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/firewall/options",
            status: 200,
            body: options,
        },
    ]
}

fn spec(tool: &str) -> common::TokenSpec {
    common::TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![tool.to_owned()],
        guests: vec!["*".to_owned()],
    }
}

const POPULATED_RULES: &[u8] =
    br#"{"data":[{"pos":0,"type":"in","action":"ACCEPT","enable":1,"proto":"tcp","dport":"22"}]}"#;
const EMPTY_RULES: &[u8] = br#"{"data":[]}"#;
const POPULATED_OPTIONS: &[u8] =
    br#"{"data":{"enable":1,"policy_in":"DROP","policy_out":"ACCEPT"}}"#;
const EMPTY_OPTIONS: &[u8] = br#"{"data":{}}"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cluster_firewall_rules_populated_and_empty() {
    let h = common::TestServer::start_with_routes(
        spec("get_cluster_firewall_rules"),
        cluster_routes(POPULATED_RULES, POPULATED_OPTIONS),
    )
    .await;
    let out = common::call(&h, "get_cluster_firewall_rules", json!({"cluster": "pve3"}))
        .await
        .expect("populated rules read");
    assert_eq!(out.as_array().expect("array").len(), 1);

    let h_empty = common::TestServer::start_with_routes(
        spec("get_cluster_firewall_rules"),
        cluster_routes(EMPTY_RULES, EMPTY_OPTIONS),
    )
    .await;
    let out_empty = common::call(
        &h_empty,
        "get_cluster_firewall_rules",
        json!({"cluster": "pve3"}),
    )
    .await
    .expect("empty rules read");
    assert_eq!(out_empty.as_array().expect("array").len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cluster_firewall_options_populated_and_empty() {
    let h = common::TestServer::start_with_routes(
        spec("get_cluster_firewall_options"),
        cluster_routes(POPULATED_RULES, POPULATED_OPTIONS),
    )
    .await;
    let out = common::call(
        &h,
        "get_cluster_firewall_options",
        json!({"cluster": "pve3"}),
    )
    .await
    .expect("populated options read");
    assert_eq!(out["policy_in"], "DROP");

    let h_empty = common::TestServer::start_with_routes(
        spec("get_cluster_firewall_options"),
        cluster_routes(EMPTY_RULES, EMPTY_OPTIONS),
    )
    .await;
    let out_empty = common::call(
        &h_empty,
        "get_cluster_firewall_options",
        json!({"cluster": "pve3"}),
    )
    .await
    .expect("empty options read");
    assert_eq!(out_empty.as_object().expect("object").len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn firewall_security_groups_populated_and_empty() {
    let h = common::TestServer::start_with_routes(
        spec("list_firewall_security_groups"),
        cluster_routes(POPULATED_RULES, POPULATED_OPTIONS),
    )
    .await;
    let out = common::call(
        &h,
        "list_firewall_security_groups",
        json!({"cluster": "pve3"}),
    )
    .await
    .expect("populated groups read");
    assert_eq!(out.as_array().expect("array").len(), 1);

    let h_empty = common::TestServer::start_with_routes(
        spec("list_firewall_security_groups"),
        cluster_routes(EMPTY_RULES, EMPTY_OPTIONS),
    )
    .await;
    let out_empty = common::call(
        &h_empty,
        "list_firewall_security_groups",
        json!({"cluster": "pve3"}),
    )
    .await
    .expect("empty groups read");
    assert_eq!(out_empty.as_array().expect("array").len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn firewall_security_group_rules_addresses_the_named_group() {
    let h = common::TestServer::start_with_routes(
        spec("get_firewall_security_group_rules"),
        cluster_routes(POPULATED_RULES, POPULATED_OPTIONS),
    )
    .await;
    let out = common::call(
        &h,
        "get_firewall_security_group_rules",
        json!({"cluster": "pve3", "group": "webservers"}),
    )
    .await
    .expect("populated group rules read");
    assert_eq!(out.as_array().expect("array").len(), 1);

    let h_empty = common::TestServer::start_with_routes(
        spec("get_firewall_security_group_rules"),
        cluster_routes(EMPTY_RULES, EMPTY_OPTIONS),
    )
    .await;
    let out_empty = common::call(
        &h_empty,
        "get_firewall_security_group_rules",
        json!({"cluster": "pve3", "group": "webservers"}),
    )
    .await
    .expect("empty group rules read");
    assert_eq!(out_empty.as_array().expect("array").len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn firewall_ipsets_populated_and_empty() {
    let h = common::TestServer::start_with_routes(
        spec("list_firewall_ipsets"),
        cluster_routes(POPULATED_RULES, POPULATED_OPTIONS),
    )
    .await;
    let out = common::call(&h, "list_firewall_ipsets", json!({"cluster": "pve3"}))
        .await
        .expect("populated ipsets read");
    assert_eq!(out.as_array().expect("array").len(), 1);

    let h_empty = common::TestServer::start_with_routes(
        spec("list_firewall_ipsets"),
        cluster_routes(EMPTY_RULES, EMPTY_OPTIONS),
    )
    .await;
    let out_empty = common::call(&h_empty, "list_firewall_ipsets", json!({"cluster": "pve3"}))
        .await
        .expect("empty ipsets read");
    assert_eq!(out_empty.as_array().expect("array").len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn firewall_ipset_entries_addresses_the_named_ipset() {
    let h = common::TestServer::start_with_routes(
        spec("get_firewall_ipset_entries"),
        cluster_routes(POPULATED_RULES, POPULATED_OPTIONS),
    )
    .await;
    let out = common::call(
        &h,
        "get_firewall_ipset_entries",
        json!({"cluster": "pve3", "name": "blocklist"}),
    )
    .await
    .expect("populated ipset entries read");
    assert_eq!(out.as_array().expect("array").len(), 1);

    let h_empty = common::TestServer::start_with_routes(
        spec("get_firewall_ipset_entries"),
        cluster_routes(EMPTY_RULES, EMPTY_OPTIONS),
    )
    .await;
    let out_empty = common::call(
        &h_empty,
        "get_firewall_ipset_entries",
        json!({"cluster": "pve3", "name": "blocklist"}),
    )
    .await
    .expect("empty ipset entries read");
    assert_eq!(out_empty.as_array().expect("array").len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn firewall_aliases_populated_and_empty() {
    let h = common::TestServer::start_with_routes(
        spec("list_firewall_aliases"),
        cluster_routes(POPULATED_RULES, POPULATED_OPTIONS),
    )
    .await;
    let out = common::call(&h, "list_firewall_aliases", json!({"cluster": "pve3"}))
        .await
        .expect("populated aliases read");
    assert_eq!(out.as_array().expect("array").len(), 1);

    let h_empty = common::TestServer::start_with_routes(
        spec("list_firewall_aliases"),
        cluster_routes(EMPTY_RULES, EMPTY_OPTIONS),
    )
    .await;
    let out_empty = common::call(
        &h_empty,
        "list_firewall_aliases",
        json!({"cluster": "pve3"}),
    )
    .await
    .expect("empty aliases read");
    assert_eq!(out_empty.as_array().expect("array").len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_firewall_rules_populated_and_empty() {
    let h = common::TestServer::start_with_routes(
        spec("get_node_firewall_rules"),
        cluster_routes(POPULATED_RULES, POPULATED_OPTIONS),
    )
    .await;
    let out = common::call(
        &h,
        "get_node_firewall_rules",
        json!({"cluster": "pve3", "node": "pve2"}),
    )
    .await
    .expect("populated node rules read");
    assert_eq!(out.as_array().expect("array").len(), 1);

    let h_empty = common::TestServer::start_with_routes(
        spec("get_node_firewall_rules"),
        cluster_routes(EMPTY_RULES, EMPTY_OPTIONS),
    )
    .await;
    let out_empty = common::call(
        &h_empty,
        "get_node_firewall_rules",
        json!({"cluster": "pve3", "node": "pve2"}),
    )
    .await
    .expect("empty node rules read");
    assert_eq!(out_empty.as_array().expect("array").len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_firewall_options_populated_and_empty() {
    let h = common::TestServer::start_with_routes(
        spec("get_node_firewall_options"),
        cluster_routes(POPULATED_RULES, POPULATED_OPTIONS),
    )
    .await;
    let out = common::call(
        &h,
        "get_node_firewall_options",
        json!({"cluster": "pve3", "node": "pve2"}),
    )
    .await
    .expect("populated node options read");
    assert_eq!(out["policy_in"], "DROP");

    let h_empty = common::TestServer::start_with_routes(
        spec("get_node_firewall_options"),
        cluster_routes(EMPTY_RULES, EMPTY_OPTIONS),
    )
    .await;
    let out_empty = common::call(
        &h_empty,
        "get_node_firewall_options",
        json!({"cluster": "pve3", "node": "pve2"}),
    )
    .await
    .expect("empty node options read");
    assert_eq!(out_empty.as_object().expect("object").len(), 0);
}

/// Guest-scoped routes: reuses `default_guest_routes` (fixture guest 617, an
/// LXC on pve2) and layers the guest firewall endpoints on top.
fn guest_routes(rules: &'static [u8], options: &'static [u8]) -> Vec<common::Route> {
    let mut routes = common::default_guest_routes(617, false);
    routes.extend(cluster_routes(rules, options));
    routes.extend([
        common::Route {
            path: "/api2/json/nodes/pve2/lxc/617/firewall/rules",
            status: 200,
            body: rules,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/lxc/617/firewall/options",
            status: 200,
            body: options,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/lxc/617/firewall/aliases",
            status: 200,
            body: rules,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/lxc/617/firewall/ipset",
            status: 200,
            body: rules,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/lxc/617/firewall/ipset/blocklist",
            status: 200,
            body: rules,
        },
    ]);
    routes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_firewall_rules_populated_and_empty() {
    let h = common::TestServer::start_with_routes(
        spec("get_guest_firewall_rules"),
        guest_routes(POPULATED_RULES, POPULATED_OPTIONS),
    )
    .await;
    let out = common::call(
        &h,
        "get_guest_firewall_rules",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("populated guest rules read");
    assert_eq!(out.as_array().expect("array").len(), 1);

    let h_empty = common::TestServer::start_with_routes(
        spec("get_guest_firewall_rules"),
        guest_routes(EMPTY_RULES, EMPTY_OPTIONS),
    )
    .await;
    let out_empty = common::call(
        &h_empty,
        "get_guest_firewall_rules",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("empty guest rules read");
    assert_eq!(out_empty.as_array().expect("array").len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_firewall_options_populated_and_empty() {
    let h = common::TestServer::start_with_routes(
        spec("get_guest_firewall_options"),
        guest_routes(POPULATED_RULES, POPULATED_OPTIONS),
    )
    .await;
    let out = common::call(
        &h,
        "get_guest_firewall_options",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("populated guest options read");
    assert_eq!(out["policy_in"], "DROP");

    let h_empty = common::TestServer::start_with_routes(
        spec("get_guest_firewall_options"),
        guest_routes(EMPTY_RULES, EMPTY_OPTIONS),
    )
    .await;
    let out_empty = common::call(
        &h_empty,
        "get_guest_firewall_options",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("empty guest options read");
    assert_eq!(out_empty.as_object().expect("object").len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_firewall_aliases_populated_and_empty() {
    let h = common::TestServer::start_with_routes(
        spec("list_guest_firewall_aliases"),
        guest_routes(POPULATED_RULES, POPULATED_OPTIONS),
    )
    .await;
    let out = common::call(
        &h,
        "list_guest_firewall_aliases",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("populated guest aliases read");
    assert_eq!(out.as_array().expect("array").len(), 1);

    let h_empty = common::TestServer::start_with_routes(
        spec("list_guest_firewall_aliases"),
        guest_routes(EMPTY_RULES, EMPTY_OPTIONS),
    )
    .await;
    let out_empty = common::call(
        &h_empty,
        "list_guest_firewall_aliases",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("empty guest aliases read");
    assert_eq!(out_empty.as_array().expect("array").len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_firewall_ipsets_populated_and_empty() {
    let h = common::TestServer::start_with_routes(
        spec("list_guest_firewall_ipsets"),
        guest_routes(POPULATED_RULES, POPULATED_OPTIONS),
    )
    .await;
    let out = common::call(
        &h,
        "list_guest_firewall_ipsets",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("populated guest ipsets read");
    assert_eq!(out.as_array().expect("array").len(), 1);

    let h_empty = common::TestServer::start_with_routes(
        spec("list_guest_firewall_ipsets"),
        guest_routes(EMPTY_RULES, EMPTY_OPTIONS),
    )
    .await;
    let out_empty = common::call(
        &h_empty,
        "list_guest_firewall_ipsets",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("empty guest ipsets read");
    assert_eq!(out_empty.as_array().expect("array").len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_firewall_ipset_entries_addresses_the_named_ipset() {
    let h = common::TestServer::start_with_routes(
        spec("get_guest_firewall_ipset_entries"),
        guest_routes(POPULATED_RULES, POPULATED_OPTIONS),
    )
    .await;
    let out = common::call(
        &h,
        "get_guest_firewall_ipset_entries",
        json!({"cluster": "pve3", "vmid": 617, "name": "blocklist"}),
    )
    .await
    .expect("populated guest ipset entries read");
    assert_eq!(out.as_array().expect("array").len(), 1);

    let h_empty = common::TestServer::start_with_routes(
        spec("get_guest_firewall_ipset_entries"),
        guest_routes(EMPTY_RULES, EMPTY_OPTIONS),
    )
    .await;
    let out_empty = common::call(
        &h_empty,
        "get_guest_firewall_ipset_entries",
        json!({"cluster": "pve3", "vmid": 617, "name": "blocklist"}),
    )
    .await
    .expect("empty guest ipset entries read");
    assert_eq!(out_empty.as_array().expect("array").len(), 0);
}

/// None of these tools appear in `WRITE_TOOLS`: a wildcard read token must
/// reach every one of them without being granted anything by name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wildcard_read_token_reaches_every_firewall_read_tool() {
    let h = common::TestServer::start_with_routes(
        common::TokenSpec::full(),
        guest_routes(POPULATED_RULES, POPULATED_OPTIONS),
    )
    .await;

    common::call(&h, "get_cluster_firewall_rules", json!({"cluster": "pve3"}))
        .await
        .expect("wildcard token reaches get_cluster_firewall_rules");

    common::call(
        &h,
        "get_guest_firewall_options",
        json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("wildcard token reaches get_guest_firewall_options");
}
