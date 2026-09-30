//! A narrowed token must not be able to tell an out-of-scope guest apart
//! from one that does not exist, by looping a vmid-addressed read tool and
//! comparing error text. Regression for the `authorize` fix in
//! `rust-proxmoxmcp-core`'s `GuestIndex`.

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
              {"id":"qemu/100","type":"qemu","vmid":100,"name":"out-of-scope","node":"pve2","status":"running","tags":""}
            ]}"#,
        },
    ]
}

fn narrowed_spec() -> common::TokenSpec {
    common::TokenSpec {
        clusters: vec!["*".to_owned()],
        tools: vec!["get_vm_config".to_owned()],
        guests: vec!["vmid:600-699".to_owned()],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_existing_out_of_scope_guest_and_an_absent_guest_read_identically() {
    let h = common::TestServer::start_with_routes(narrowed_spec(), routes()).await;

    // 100 exists in the fixture but is outside vmid:600-699.
    let out_of_scope = common::call(&h, "get_vm_config", json!({"cluster": "pve3", "vmid": 100}))
        .await
        .expect_err("100 is outside the token's guest scope");

    // 999 does not appear in the fixture at all.
    let absent = common::call(&h, "get_vm_config", json!({"cluster": "pve3", "vmid": 999}))
        .await
        .expect_err("999 does not exist");

    assert_eq!(
        out_of_scope, absent,
        "an out-of-scope guest must not be distinguishable from an absent one \
         by error text -- that lets a narrowed token enumerate the cluster's \
         real inventory one vmid at a time"
    );
}
