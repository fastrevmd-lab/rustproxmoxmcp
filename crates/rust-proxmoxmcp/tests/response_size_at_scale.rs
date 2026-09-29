//! Lab test for MEC-456: does an unpaginated list tool break at realistic
//! large-cluster scale?
//!
//! There are two independent caps in the read path, and this test measures
//! against both:
//! - `rust-proxmoxmcp-core::client::MAX_RESPONSE_BYTES` (8 MiB): the largest
//!   body accepted from Proxmox itself, enforced while the response streams.
//! - `mecmcp_server::ResultLimits::max_json_bytes` (512 KiB, see
//!   `RESULT_LIMITS` in `server::mod`): the largest *pretty-printed* JSON a
//!   tool call is allowed to hand back to the MCP caller.
//!
//! Both refuse outright rather than truncate (fail closed, per the house
//! style), so the question is not "does data get corrupted" but "at what
//! cluster size does a legitimate list call stop working at all, with no
//! pagination parameter to work around it."
//!
//! Each generator below mirrors the real Proxmox field set for its endpoint
//! (`/cluster/resources`, `/nodes/{node}/tasks`,
//! `/nodes/{node}/storage/{storage}/content`) so the byte counts are
//! representative, not toy-sized.

mod common;

use common::{Route, TestServer, TokenSpec};

const NODES_ROUTE: Route = Route {
    path: "/api2/json/nodes",
    status: 200,
    body: br#"{"data":[{"node":"pve-node01","status":"online"}]}"#,
};

/// One realistic QEMU entry from `/cluster/resources`.
fn guest_resource_json(vmid: u32) -> String {
    format!(
        r#"{{"id":"qemu/{vmid}","type":"qemu","vmid":{vmid},"node":"pve-node01","status":"running","name":"guest-{vmid:05}.prod.internal","cpu":0.034521,"maxcpu":4,"mem":1717986918,"maxmem":4294967296,"disk":0,"maxdisk":34359738368,"diskread":123456789012,"diskwrite":98765432109,"netin":555555555555,"netout":444444444444,"uptime":864321,"template":0,"tags":"prod;webtier;customer-acme-{vmid:05}","pool":"customer-acme","hastate":"started"}}"#
    )
}

/// One realistic entry from `/nodes/{node}/tasks`.
fn task_json(n: u32) -> String {
    format!(
        r#"{{"upid":"UPID:pve-node01:0000{n:04X}:0003C4D5:66F1A2B3:vzdump:{n}:root@pam:","node":"pve-node01","pid":{n},"pstart":123456,"starttime":{ts},"type":"vzdump","id":"{n}","user":"root@pam","status":"OK","endtime":{end}}}"#,
        ts = 1_758_000_000u64 + u64::from(n),
        end = 1_758_000_010u64 + u64::from(n),
    )
}

/// One realistic entry from `/nodes/{node}/storage/{storage}/content?content=backup`.
fn backup_json(vmid: u32, n: u32) -> String {
    format!(
        r#"{{"volid":"local:backup/vzdump-qemu-{vmid}-2026_09_{day:02}-02_00_{sec:02}.vma.zst","content":"backup","format":"vma.zst","size":34359738368,"vmid":{vmid},"ctime":{ctime},"notes":"nightly backup {n}","subtype":"qemu","verification":{{"state":"ok","upid":"UPID:pve-node01:0000AAAA:0003C4D5:66F1A2B3:verificationjob::root@pam:"}}}}"#,
        day = (n % 28) + 1,
        sec = n % 60,
        ctime = 1_758_000_000u64 + u64::from(n),
    )
}

fn json_array_body(items: impl Iterator<Item = String>) -> Vec<u8> {
    let joined = items.collect::<Vec<_>>().join(",");
    format!(r#"{{"data":[{joined}]}}"#).into_bytes()
}

fn leak_route(path: String, body: Vec<u8>) -> Route {
    Route {
        path: Box::leak(path.into_boxed_str()),
        status: 200,
        body: Box::leak(body.into_boxed_slice()),
    }
}

/// Call a read tool and return `(is_error, response_text)`.
async fn call(server: &TestServer, tool: &'static str, args: serde_json::Value) -> (bool, String) {
    let url = server.url.clone();
    let token = server.token.clone();
    let result = tokio::task::spawn_blocking(move || {
        let client = mecmcp_transport::test_client::McpClient::new(&url)
            .expect("create client")
            .with_bearer(&token);
        let session_id = client.initialize().expect("initialize");
        client.tools_call(&session_id, tool, args).expect("call")
    })
    .await
    .expect("blocking task completes");

    let is_error = result
        .get("isError")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    (is_error, result.to_string())
}

/// Measures the raw serialized size (compact JSON, as Proxmox would send it
/// over the wire) of an N-guest `/cluster/resources` fixture, and the
/// pretty-printed size the MCP tool result would carry (2-space indent,
/// which `serde_json::to_string_pretty` produces and roughly doubles a
/// dense array's size). Printed under `--nocapture` for the written record
/// this issue's acceptance criteria calls for.
#[test]
fn guest_list_size_at_realistic_cluster_scale() {
    for count in [100u32, 500, 1_000, 2_000, 5_000, 10_000] {
        let items: Vec<String> = (0..count).map(guest_resource_json).collect();
        let compact = format!(r#"{{"data":[{}]}}"#, items.join(","));
        let value: serde_json::Value = serde_json::from_str(&compact).expect("valid fixture");
        let pretty = serde_json::to_string_pretty(&value).expect("pretty print");
        println!(
            "guests={count:>6}  upstream(compact)={:>10} bytes  mcp_result(pretty)={:>10} bytes",
            compact.len(),
            pretty.len(),
        );
    }
}

/// End-to-end proof at the scale found above: a `get_vms` call against a
/// cluster with enough guests to cross the 512 KiB MCP result cap fails
/// closed with a clear error, not a truncated or corrupted list -- and a
/// cluster just under that size succeeds with every guest present.
///
/// A single Proxmox cluster tops out at 32 nodes; at ~50-100 guests per node
/// (a realistic dense VDI/MSP node), 1,600-3,200 guests cluster-wide is a
/// plausible "large cluster," not a synthetic edge case.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_vms_fails_closed_once_the_result_cap_is_crossed() {
    // From guest_list_size_at_realistic_cluster_scale: each guest record
    // pretty-prints to ~540 bytes, so 1,000 guests (~540 KB) already clears
    // the 512 KiB (524,288-byte) mcp_server::ResultLimits::max_json_bytes
    // cap baked into RESULT_LIMITS in server/mod.rs -- well inside a single
    // 32-node cluster's realistic guest count.
    let over_cap = leak_route(
        "/api2/json/cluster/resources".to_owned(),
        json_array_body((0..1_000u32).map(guest_resource_json)),
    );
    let server =
        TestServer::start_with_routes(TokenSpec::full(), vec![NODES_ROUTE, over_cap]).await;

    let (is_error, text) = call(&server, "get_vms", serde_json::json!({ "cluster": "pve3" })).await;

    assert!(
        is_error,
        "1,000 guests should exceed the MCP result cap and refuse, got: {text}"
    );
    assert!(
        text.contains("exceeds") && text.contains("byte limit"),
        "refusal should name the byte-limit cause, not read as a generic \
         failure an operator can't act on: {text}"
    );

    // A cluster comfortably under the cap still gets every guest back whole.
    let under_cap = leak_route(
        "/api2/json/cluster/resources".to_owned(),
        json_array_body((0..200u32).map(guest_resource_json)),
    );
    let small_server =
        TestServer::start_with_routes(TokenSpec::full(), vec![NODES_ROUTE, under_cap]).await;
    let (small_is_error, small_text) = call(
        &small_server,
        "get_vms",
        serde_json::json!({ "cluster": "pve3" }),
    )
    .await;
    assert!(
        !small_is_error,
        "200 guests should stay under the cap: {small_text}"
    );
    assert!(
        small_text.contains("guest-00000") && small_text.contains("guest-00199"),
        "every guest should be present, not truncated: first and last IDs missing"
    );
}

/// Same shape of failure for `list_tasks` -- the other list tool with no
/// server-side page size and no client-side pagination.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_tasks_fails_closed_once_the_result_cap_is_crossed() {
    let over_cap = leak_route(
        "/api2/json/nodes/pve-node01/tasks".to_owned(),
        json_array_body((0..2_500u32).map(task_json)),
    );
    let server =
        TestServer::start_with_routes(TokenSpec::full(), vec![NODES_ROUTE, over_cap]).await;

    let (is_error, text) = call(
        &server,
        "list_tasks",
        serde_json::json!({ "cluster": "pve3", "node": "pve-node01" }),
    )
    .await;

    assert!(
        is_error,
        "2,500 tasks should exceed the MCP result cap and refuse, got: {text}"
    );
    assert!(
        text.contains("exceeds") && text.contains("byte limit"),
        "refusal should name the byte-limit cause: {text}"
    );
}

/// Same shape of failure for `list_backups` -- a storage backend holding a
/// realistic multi-month retention window for a busy cluster.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_backups_fails_closed_once_the_result_cap_is_crossed() {
    let over_cap = leak_route(
        "/api2/json/nodes/pve-node01/storage/local/content".to_owned(),
        json_array_body((0..1_500u32).map(|n| backup_json(100 + (n % 300), n))),
    );
    let server =
        TestServer::start_with_routes(TokenSpec::full(), vec![NODES_ROUTE, over_cap]).await;

    let (is_error, text) = call(
        &server,
        "list_backups",
        serde_json::json!({ "cluster": "pve3", "node": "pve-node01", "storage": "local" }),
    )
    .await;

    assert!(
        is_error,
        "1,500 backup archives should exceed the MCP result cap and refuse, got: {text}"
    );
    assert!(
        text.contains("exceeds") && text.contains("byte limit"),
        "refusal should name the byte-limit cause: {text}"
    );
}
