//! HA rule change-set end-to-end tests.

mod common;

use common::{TestServer, TokenSpec, call_with_token};
use rust_proxmoxmcp_core::testing::Route;
use serde_json::json;

fn ha_rule_spec() -> TokenSpec {
    TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_ha_rule_change".to_owned(),
            "get_ha_rule_change_set".to_owned(),
            "approve_ha_rule_change".to_owned(),
            "apply_ha_rule_change".to_owned(),
            "create_ha_rule".to_owned(),
            "update_ha_rule".to_owned(),
            "delete_ha_rule".to_owned(),
        ],
        guests: vec!["*".to_owned()],
    }
}

async fn approve_ha_rule_as_second_principal(server: &TestServer, change_set_id: &str, rule: &str) {
    call_with_token(
        server,
        &server.second_token,
        "approve_ha_rule_change",
        json!({"change_set_id": change_set_id, "cluster": "pve3", "rule": rule}),
    )
    .await
    .expect("second principal approval should succeed");
}

/// `/cluster/resources` with the two guests the fixture rules name. HA rule
/// writes are authorized against every guest a rule names, the same way a
/// destroy plan is authorized against its guest, so those guests must
/// resolve. `protected` tags vm:101.
fn guests_route(protected: bool) -> Route {
    Route {
        path: "/api2/json/cluster/resources",
        status: 200,
        body: if protected {
            br#"{"data":[{"id":"qemu/100","type":"qemu","vmid":100,"name":"ha-a","node":"pve2","status":"running","tags":"test"},{"id":"qemu/101","type":"qemu","vmid":101,"name":"ha-b","node":"pve3","status":"running","tags":"protected"}]}"#
        } else {
            br#"{"data":[{"id":"qemu/100","type":"qemu","vmid":100,"name":"ha-a","node":"pve2","status":"running","tags":"test"},{"id":"qemu/101","type":"qemu","vmid":101,"name":"ha-b","node":"pve3","status":"running","tags":"test"}]}"#
        },
    }
}

/// No rule named `keep-together` exists yet, so `fetch_rule` (a GET on
/// `/cluster/ha/rules/{rule}`) answers 404 -- a `create` plan is exactly this
/// shape.
fn no_such_rule_routes() -> Vec<Route> {
    vec![
        guests_route(false),
        Route {
            path: "/api2/json/cluster/ha/rules/keep-together",
            status: 404,
            body: br#"{"data":null}"#,
        },
        Route {
            path: "/api2/json/cluster/ha/rules",
            status: 200,
            body: br#"{"data":null}"#,
        },
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approved_create_issues_the_post_with_the_rule_body() {
    let h = TestServer::start_with_routes(ha_rule_spec(), no_such_rule_routes()).await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "colocation",
            "services": ["vm:100", "vm:101"],
            "affinity": "positive"
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    assert!(
        planned["preview"]
            .as_str()
            .expect("preview")
            .contains("CREATE"),
        "{planned:?}"
    );

    approve_ha_rule_as_second_principal(&h, id, "keep-together").await;

    let applied = call_with_token(
        &h,
        &h.token,
        "apply_ha_rule_change",
        json!({"change_set_id": id, "cluster": "pve3", "rule": "keep-together"}),
    )
    .await
    .expect("apply");
    assert_eq!(applied["outcome"], "ok");

    let reqs = h.requests();
    assert!(
        reqs.iter().any(|r| {
            r.method == "POST"
                && r.path == "/api2/json/cluster/ha/rules"
                && r.body.contains("rule=keep-together")
                && r.body.contains("type=colocation")
                && r.body.contains("affinity=positive")
        }),
        "the create POST must actually be issued with the rule's fields: {reqs:?}"
    );
}

/// The rejection case the acceptance criteria asks for on the HA side: a plan
/// against a rule that already exists must be refused before any approval is
/// spent on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creating_a_rule_that_already_exists_is_refused_at_plan_time() {
    let h = TestServer::start_with_routes(
        ha_rule_spec(),
        vec![Route {
            path: "/api2/json/cluster/ha/rules/keep-together",
            status: 200,
            body: br#"{"data":{"rule":"keep-together","type":"colocation","services":"vm:100,vm:101","affinity":"positive","digest":"aabbcc"}}"#,
        }],
    )
    .await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "colocation",
            "services": ["vm:100", "vm:101"],
            "affinity": "positive"
        }),
    )
    .await
    .expect_err("a plan against an existing rule must be refused");
    assert!(error.contains("already exists"), "{error}");

    let reqs = h.requests();
    assert!(
        !reqs.iter().any(|r| r.method == "POST"),
        "nothing should have been written: {reqs:?}"
    );
}

/// A colocation rule does not take `nodes` -- that is a location-rule
/// concept -- so a plan naming both must be refused before it is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_colocation_rule_with_nodes_is_refused() {
    let h = TestServer::start_with_routes(ha_rule_spec(), no_such_rule_routes()).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "colocation",
            "services": ["vm:100"],
            "nodes": "pve2:100"
        }),
    )
    .await
    .expect_err("a colocation rule must not take nodes");
    assert!(error.contains("does not take nodes"), "{error}");
}

/// A malformed service id (not `vm:<n>` or `ct:<n>`) must be refused before
/// it is ever sent toward the cluster.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_service_id_is_refused() {
    let h = TestServer::start_with_routes(ha_rule_spec(), no_such_rule_routes()).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "colocation",
            "services": ["vm:100;rm -rf"],
            "affinity": "positive"
        }),
    )
    .await
    .expect_err("a malformed service id must be refused");
    assert!(error.contains("vmid"), "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_a_rule_that_does_not_exist_is_refused() {
    let h = TestServer::start_with_routes(ha_rule_spec(), no_such_rule_routes()).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({"cluster": "pve3", "rule": "keep-together", "op": "delete"}),
    )
    .await
    .expect_err("deleting a rule that does not exist must be refused");
    assert!(error.contains("does not exist"), "{error}");
}

/// The fingerprint drift guard: a rule that changed between plan and apply
/// (someone edited it out of band) must refuse the apply, the same as a
/// guest that moved between a destroy plan and its apply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_that_changed_after_approval_refuses_the_apply() {
    let h = TestServer::start_with_routes(ha_rule_spec(), existing_rule_routes(false)).await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "delete"
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    approve_ha_rule_as_second_principal(&h, &id, "keep-together").await;

    // The rule's comment changes underneath the plan -- same fingerprint
    // shape as `move_guest_to_node` for a guest.
    h.replace_route(Route {
        path: "/api2/json/cluster/ha/rules/keep-together",
        status: 200,
        body: br#"{"data":{"rule":"keep-together","type":"colocation","services":"vm:100,vm:101","affinity":"positive","comment":"changed out of band","digest":"ddeeff"}}"#,
    });

    let error = call_with_token(
        &h,
        &h.token,
        "apply_ha_rule_change",
        json!({"change_set_id": id, "cluster": "pve3", "rule": "keep-together"}),
    )
    .await
    .expect_err("a rule that changed since the plan must refuse the apply");
    assert!(error.contains("fingerprint changed"), "{error}");
}

/// An existing `keep-together` colocation rule over vm:100 and vm:101, plus
/// the guests it names.
fn existing_rule_routes(protected: bool) -> Vec<Route> {
    vec![
        guests_route(protected),
        Route {
            path: "/api2/json/cluster/ha/rules/keep-together",
            status: 200,
            body: br#"{"data":{"rule":"keep-together","type":"colocation","services":"vm:100,vm:101","affinity":"positive","digest":"aabbcc"}}"#,
        },
    ]
}

/// A rule naming a `protected` guest is refused at plan time: an HA rule
/// moves the guests it names, so it is gated like a destroy of each of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_naming_a_protected_guest_is_refused_at_plan_time() {
    let mut routes = no_such_rule_routes();
    routes[0] = guests_route(true);
    let h = TestServer::start_with_routes(ha_rule_spec(), routes).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "colocation",
            "services": ["vm:100", "vm:101"],
            "affinity": "positive"
        }),
    )
    .await
    .expect_err("a rule naming a protected guest must be refused");
    assert!(error.contains("protected"), "{error}");
}

/// Deleting an existing rule is gated on the guests the rule currently
/// names, not only on what the delete request names (nothing).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_a_rule_over_a_protected_guest_is_refused() {
    let h = TestServer::start_with_routes(ha_rule_spec(), existing_rule_routes(true)).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({"cluster": "pve3", "rule": "keep-together", "op": "delete"}),
    )
    .await
    .expect_err("a delete touching a protected guest must be refused");
    assert!(error.contains("protected"), "{error}");
}

/// A token whose guest scope does not cover the named guests cannot plan a
/// rule over them, even though it carries every HA tool scope.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_outside_the_token_guest_scope_is_refused() {
    let h = TestServer::start_with_routes(ha_rule_spec(), no_such_rule_routes()).await;

    let error = call_with_token(
        &h,
        &h.narrow_token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "colocation",
            "services": ["vm:100", "vm:101"],
            "affinity": "positive"
        }),
    )
    .await
    .expect_err("a rule outside the guest scope must be refused");
    assert!(error.contains("scope"), "{error}");
}

/// The guest gate runs again at apply: a guest tagged `protected` after the
/// approval refuses the apply, and nothing is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_guest_protected_after_approval_refuses_the_apply() {
    let h = TestServer::start_with_routes(ha_rule_spec(), existing_rule_routes(false)).await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({"cluster": "pve3", "rule": "keep-together", "op": "delete"}),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    approve_ha_rule_as_second_principal(&h, &id, "keep-together").await;

    h.replace_route(guests_route(true));

    let error = call_with_token(
        &h,
        &h.token,
        "apply_ha_rule_change",
        json!({"change_set_id": id, "cluster": "pve3", "rule": "keep-together"}),
    )
    .await
    .expect_err("a guest protected since approval must refuse the apply");
    assert!(error.contains("protected"), "{error}");

    let reqs = h.requests();
    assert!(
        !reqs.iter().any(|r| r.method == "DELETE"),
        "nothing should have been deleted: {reqs:?}"
    );
}
