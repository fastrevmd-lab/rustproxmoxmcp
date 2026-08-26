//! End-to-end tests through the assembled router with a real MCP client.
//!
//! These tests drive the same `build_http_router` that `main` uses, with a
//! mock Proxmox behind it. They prove the assembly wires up correctly —
//! component tests cannot.

mod common;

use mecmcp_transport::test_client::McpClient;

/// Test 1: Tool list is filtered by the token's tool scope.
///
/// A token scoped to `get_nodes` sees exactly that one tool.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lists_only_the_tools_the_token_scope_permits() {
    let harness = common::TestServer::start(common::TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec!["get_nodes".to_owned()],
        guests: vec!["*".to_owned()],
    })
    .await;

    // McpClient is synchronous/blocking, so spawn_blocking to avoid deadlock.
    let url = harness.url.clone();
    let token = harness.token.clone();

    let tools_result = tokio::task::spawn_blocking(move || {
        let client = McpClient::new(&url)
            .expect("create client")
            .with_bearer(&token);

        let session_id = client.initialize().expect("initialize");
        client.tools_list(&session_id).expect("list tools")
    })
    .await
    .expect("blocking task completes");

    // Extract tool names from the result.
    let tools = tools_result
        .get("tools")
        .expect("tools field")
        .as_array()
        .expect("tools is an array");

    let names: Vec<String> = tools
        .iter()
        .filter_map(|tool| tool.get("name")?.as_str())
        .map(str::to_owned)
        .collect();

    assert_eq!(names, vec!["get_nodes".to_owned()]);
}

/// Test 2: A permitted read returns cluster data.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_permitted_read_returns_cluster_data() {
    let harness = common::TestServer::start(common::TokenSpec::full()).await;

    let url = harness.url.clone();
    let token = harness.token.clone();

    let result = tokio::task::spawn_blocking(move || {
        let client = McpClient::new(&url)
            .expect("create client")
            .with_bearer(&token);

        let session_id = client.initialize().expect("initialize");
        client
            .tools_call(
                &session_id,
                "get_nodes",
                serde_json::json!({ "cluster": "pve3" }),
            )
            .expect("call get_nodes")
    })
    .await
    .expect("blocking task completes");

    let result_str = result.to_string();
    assert!(
        result_str.contains("pve2"),
        "result should contain pve2: {result_str}"
    );
}

/// Test 3: A cluster outside scope is refused before any Proxmox request.
///
/// The key assertion is `proxmox_request_count() == 0`, proving the stage-1
/// preflight rejected without sending anything to Proxmox.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cluster_outside_scope_is_refused_before_any_proxmox_request() {
    let harness = common::TestServer::start(common::TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec!["get_nodes".to_owned()],
        guests: vec!["*".to_owned()],
    })
    .await;

    let url = harness.url.clone();
    let token = harness.token.clone();

    let outcome = tokio::task::spawn_blocking(move || {
        let client = McpClient::new(&url)
            .expect("create client")
            .with_bearer(&token);

        let session_id = client.initialize().expect("initialize");
        client.tools_call(
            &session_id,
            "get_nodes",
            serde_json::json!({ "cluster": "pve2" }),
        )
    })
    .await
    .expect("blocking task completes");

    assert!(
        outcome.is_err(),
        "expected a refusal from the preflight: {outcome:?}"
    );

    assert_eq!(
        harness.proxmox_request_count(),
        0,
        "the preflight must reject before any outbound request"
    );
}

/// Test 4: A guest outside the grant selector is refused after resolution.
///
/// The error must mention "scope" and must NOT leak the guest's name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_guest_outside_the_grant_selector_is_refused_after_resolution() {
    let harness = common::TestServer::start(common::TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec!["get_vm_config".to_owned()],
        guests: vec!["vmid:600-699".to_owned()],
    })
    .await;

    let url = harness.url.clone();
    let token = harness.token.clone();

    let result = tokio::task::spawn_blocking(move || {
        let client = McpClient::new(&url)
            .expect("create client")
            .with_bearer(&token);

        let session_id = client.initialize().expect("initialize");
        client.tools_call(
            &session_id,
            "get_vm_config",
            serde_json::json!({ "cluster": "pve3", "vmid": 905 }),
        )
    })
    .await
    .expect("blocking task completes");

    // The call should succeed at the transport level (200 OK) but return a
    // tool error with the scope violation.
    assert!(
        result.is_ok(),
        "call should complete with a tool error, not a transport error"
    );

    let result_str = result.expect("unwrap result").to_string();
    assert!(
        result_str.contains("scope"),
        "error should mention scope: {result_str}"
    );
    assert!(
        !result_str.contains("vsrx-prod"),
        "a refused call must not leak the guest name: {result_str}"
    );
}

/// Test 5: A bad token is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_token_is_refused() {
    let harness = common::TestServer::start(common::TokenSpec::full()).await;

    let url = harness.url.clone();

    let outcome = tokio::task::spawn_blocking(move || {
        let client = McpClient::new(&url)
            .expect("create client")
            .with_bearer("not-a-real-token");

        client.initialize()
    })
    .await
    .expect("blocking task completes");

    assert!(outcome.is_err(), "bad token should be refused");
}

/// `get_vm_config` and `get_container_config` name the guest type in their path
/// rather than templating it, so supplying `kind` made `expand_path` refuse the
/// call. Both failed on every invocation, and neither had a test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn type_specific_config_reads_reach_proxmox() {
    let harness = common::TestServer::start_with_routes(
        common::TokenSpec {
            clusters: vec!["pve3".to_owned()],
            tools: vec!["get_container_config".to_owned()],
            guests: vec!["*".to_owned()],
        },
        common::default_guest_routes(617, false),
    )
    .await;

    let config = common::call(
        &harness,
        "get_container_config",
        serde_json::json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("a container config read must reach Proxmox");

    assert_eq!(config["hostname"], "test-guest-617");
}

/// A path that names one guest type may only serve that type. Not sending
/// `kind` any more would otherwise let `get_vm_config` run against a container
/// and address `/nodes/pve2/qemu/617/config`, which cannot exist — an opaque
/// Proxmox error where a plain mismatch belongs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_type_specific_read_refuses_the_other_guest_type() {
    let harness = common::TestServer::start_with_routes(
        common::TokenSpec {
            clusters: vec!["pve3".to_owned()],
            tools: vec!["get_vm_config".to_owned()],
            guests: vec!["*".to_owned()],
        },
        common::default_guest_routes(617, false),
    )
    .await;

    // 617 is an LXC.
    let err = common::call(
        &harness,
        "get_vm_config",
        serde_json::json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect_err("a QEMU-only read must refuse a container");

    assert!(
        err.contains("lxc"),
        "the refusal must name the actual type: {err}"
    );
    assert!(err.contains("qemu"), "and the type the tool serves: {err}");
}
