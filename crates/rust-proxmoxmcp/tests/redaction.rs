//! Proves the fix for the privacy finding that `get_vm_config` and
//! `get_container_config` handed a model Proxmox's `description` and
//! `cicustom` guest-config fields verbatim.
//!
//! Operators routinely use `description` for free-form notes -- including,
//! in practice, pasted credentials -- and `cicustom` names a cloud-init
//! snippet reference that is still an arbitrary vendor string this server
//! does not control. Rather than hand-checking just the two tools the
//! finding names, this drives every tool in the server's own read-tool
//! registry (`rust_proxmoxmcp_core::catalog::READ_TOOLS`, the same catalog
//! `serve_read` dispatches through) against a mock Proxmox whose guest
//! configs embed a fake secret, and asserts the secret never reaches any
//! tool's output -- on success or on error.
//!
//! All addresses below are RFC 5737 documentation ranges / `example.net`;
//! nothing here is a real Proxmox response.

mod common;

use rust_proxmoxmcp_core::testing::Route;

/// A secret shaped so mecmcp-redact's denylist-and-shape scrubber actually
/// catches it: a `key: value` line whose key ("password") is on the
/// denylist, the same way an operator's pasted note looks in practice.
const FAKE_SECRET: &str = "FAKE-api-token-9f8e7d6c5b4a3210";

/// A second secret, opaque (no recognizable shape), placed under a
/// denylisted key name (`authkey`) that is *not* one of the five curated
/// free-text keys `redact_free_text_fields` scans. This proves the
/// mecmcp-redact key-denylist pass -- which runs over the *whole* response
/// via `mecmcp_server::tool_result`'s `OutputRedaction::Apply`, not just
/// this server's curated free-text fields -- actually reaches a field this
/// server never specifically wrote code for.
const DENYLISTED_KEY_SECRET: &str = "FAKE-authkey-outside-freetext-allowlist";

/// A third secret, shaped as a Juniper/glibc crypt hash (`$<id>$<content>`),
/// placed under an ordinary key name (`fingerprint`) that is on neither the
/// free-text allowlist nor mecmcp-redact's key denylist. Proves the
/// value-shape catch-all catches a secret by its *shape* alone, independent
/// of what key it happens to be filed under.
const SHAPE_SECRET: &str = "$9$not-a-real-secret-cryptHash12345";

fn secret_bearing_description() -> String {
    format!("re-provisioned 2026-09-27 (ticket OPS-4110); backup admin password: {FAKE_SECRET}")
}

const EMPTY_ARRAY: &[u8] = br#"{"data":[]}"#;
const EMPTY_OBJECT: &[u8] = br#"{"data":{}}"#;

/// Serialize `data` as a Proxmox `{"data": ...}` envelope and leak it to get
/// a `'static` body for a [`Route`]. The mock server never frees routes, so
/// this matches the existing pattern for the guest-config fixtures below
/// rather than adding a new lifetime story.
fn leaked_data(data: serde_json::Value) -> &'static [u8] {
    let body = serde_json::json!({ "data": data }).to_string();
    Box::leak(body.into_boxed_str()).as_bytes()
}

/// A one-element array whose single object carries `key: FAKE_SECRET` in a
/// free-text field, used for every list-shaped fixture below (snapshots,
/// backups, firewall rules/aliases/ipsets/groups) so the sweep test can
/// prove each of those response shapes gets redacted too, not just guest
/// config.
fn secret_bearing_list(extra: serde_json::Value) -> &'static [u8] {
    leaked_data(serde_json::Value::Array(vec![extra]))
}

/// Routes for a mock Proxmox with one QEMU guest (905) and one LXC guest
/// (617) on node `pve2`, each carrying a `description` with an embedded fake
/// secret and a `cicustom` cloud-init snippet reference (never itself
/// fetched by this server). `sshkeys` on the QEMU guest is a fake public key
/// that must survive redaction untouched.
fn routes_with_embedded_secret() -> Vec<Route> {
    let description = secret_bearing_description();
    let qemu_config = serde_json::json!({
        "data": {
            "vmid": 905,
            "name": "vsrx-prod",
            "cores": 2,
            "memory": 2048,
            "sshkeys": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEY demo@example.net\n",
            "description": description.clone(),
            "cicustom": "user=local:snippets/postinstall-905.yml",
        }
    })
    .to_string();
    let lxc_config = serde_json::json!({
        "data": {
            "hostname": "test-guest-617",
            "cores": 1,
            "memory": 512,
            "digest": "aabbccddeeff00112233445566778899aabbccdd",
            "description": description,
            "cicustom": "user=local:snippets/postinstall-617.yml",
        }
    })
    .to_string();

    vec![
        Route {
            path: "/api2/json/nodes",
            status: 200,
            body: br#"{"data":[{"node":"pve2","status":"online"},{"node":"pve3","status":"online"}]}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/status",
            status: 200,
            body: EMPTY_OBJECT,
        },
        Route {
            path: "/api2/json/cluster/status",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: br#"{"data":[
              {"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2","status":"running","tags":""},
              {"id":"lxc/617","type":"lxc","vmid":617,"name":"test-guest-617","node":"pve2","status":"stopped","tags":""}
            ]}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/905/config",
            status: 200,
            body: Box::leak(qemu_config.into_boxed_str()).as_bytes(),
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/config",
            status: 200,
            body: Box::leak(lxc_config.into_boxed_str()).as_bytes(),
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/905/status/current",
            status: 200,
            body: EMPTY_OBJECT,
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/status/current",
            status: 200,
            body: EMPTY_OBJECT,
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/905/snapshot",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"name": "pre-upgrade", "description": description.clone()})),
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/snapshot",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"name": "pre-upgrade", "description": description.clone()})),
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/interfaces",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/nodes/pve2/storage",
            status: 200,
            body: secret_bearing_list(serde_json::json!({
                "storage": "backup-nfs",
                "type": "nfs",
                "content": "backup",
                "authkey": DENYLISTED_KEY_SECRET,
                "fingerprint": SHAPE_SECRET,
            })),
        },
        Route {
            path: "/api2/json/nodes/pve2/storage/local/content",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"volid": "local:backup/vzdump-qemu-905.vma.zst", "content": "backup", "notes": description.clone()})),
        },
        Route {
            path: "/api2/json/nodes/pve2/tasks",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/nodes/pve2/tasks/fake-upid-1/status",
            status: 200,
            body: EMPTY_OBJECT,
        },
        Route {
            path: "/api2/json/cluster/firewall/rules",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"pos": 0, "action": "ACCEPT", "type": "in", "comment": description.clone()})),
        },
        Route {
            path: "/api2/json/cluster/firewall/options",
            status: 200,
            body: EMPTY_OBJECT,
        },
        Route {
            path: "/api2/json/cluster/firewall/groups",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"group": "test-group", "comment": description.clone()})),
        },
        Route {
            path: "/api2/json/cluster/firewall/groups/test-group",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"pos": 0, "action": "ACCEPT", "type": "in", "comment": description.clone()})),
        },
        Route {
            path: "/api2/json/cluster/firewall/ipset",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"name": "test-ipset", "comment": description.clone()})),
        },
        Route {
            path: "/api2/json/cluster/firewall/ipset/test-ipset",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"cidr": "192.0.2.0/24", "comment": description.clone()})),
        },
        Route {
            path: "/api2/json/cluster/firewall/aliases",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"name": "test-alias", "cidr": "192.0.2.0/24", "comment": description.clone()})),
        },
        Route {
            path: "/api2/json/nodes/pve2/firewall/rules",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"pos": 0, "action": "ACCEPT", "type": "in", "comment": description.clone()})),
        },
        Route {
            path: "/api2/json/nodes/pve2/firewall/options",
            status: 200,
            body: EMPTY_OBJECT,
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/905/firewall/rules",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"pos": 0, "action": "ACCEPT", "type": "in", "comment": description.clone()})),
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/firewall/rules",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"pos": 0, "action": "ACCEPT", "type": "in", "comment": description.clone()})),
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/905/firewall/options",
            status: 200,
            body: EMPTY_OBJECT,
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/firewall/options",
            status: 200,
            body: EMPTY_OBJECT,
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/905/firewall/aliases",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"name": "test-alias", "cidr": "192.0.2.0/24", "comment": description.clone()})),
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/firewall/aliases",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"name": "test-alias", "cidr": "192.0.2.0/24", "comment": description.clone()})),
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/905/firewall/ipset",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"name": "test-ipset", "comment": description.clone()})),
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/firewall/ipset",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"name": "test-ipset", "comment": description.clone()})),
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/905/firewall/ipset/test-ipset",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"cidr": "192.0.2.0/24", "comment": description.clone()})),
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/firewall/ipset/test-ipset",
            status: 200,
            body: secret_bearing_list(serde_json::json!({"cidr": "192.0.2.0/24", "comment": description.clone()})),
        },
    ]
}

/// `get_vm_config` on the QEMU fixture: the embedded secret must not survive,
/// and `sshkeys` (a public key, not a secret) must be untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_vm_config_redacts_description_and_cicustom() {
    let harness = common::TestServer::start_with_routes(
        common::TokenSpec::full(),
        routes_with_embedded_secret(),
    )
    .await;

    let config = common::call(
        &harness,
        "get_vm_config",
        serde_json::json!({"cluster": "pve3", "vmid": 905}),
    )
    .await
    .expect("get_vm_config should succeed against the fixture");

    let rendered = config.to_string();
    assert!(
        !rendered.contains(FAKE_SECRET),
        "get_vm_config leaked the fake secret: {rendered}"
    );
    assert!(
        config["sshkeys"]
            .as_str()
            .expect("sshkeys is a string")
            .contains("ssh-ed25519"),
        "sshkeys (a public key, not a secret) must survive redaction: {config}"
    );
}

/// `get_container_config` on the LXC fixture: same guarantee for the
/// container path, which is a separate code path in Proxmox but shares
/// `serve_read`'s executor in this server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_container_config_redacts_description_and_cicustom() {
    let harness = common::TestServer::start_with_routes(
        common::TokenSpec::full(),
        routes_with_embedded_secret(),
    )
    .await;

    let config = common::call(
        &harness,
        "get_container_config",
        serde_json::json!({"cluster": "pve3", "vmid": 617}),
    )
    .await
    .expect("get_container_config should succeed against the fixture");

    let rendered = config.to_string();
    assert!(
        !rendered.contains(FAKE_SECRET),
        "get_container_config leaked the fake secret: {rendered}"
    );
}

/// `get_storage`'s fixture carries two secret shapes this server writes no
/// redaction code for itself: a denylisted key name (`authkey`) outside the
/// five curated free-text keys, and a crypt-hash-shaped value under an
/// ordinary key (`fingerprint`). Both must still come back redacted, proving
/// that `serve_read`'s `tool_result(..., OutputRedaction::Apply)` call --
/// which runs `mecmcp_redact::redact_json_value` over the *entire* response,
/// not just the curated free-text fields -- actually covers the response
/// body outside what `redact_free_text_fields` targets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_storage_redacts_denylisted_key_and_shape_secrets() {
    let harness = common::TestServer::start_with_routes(
        common::TokenSpec::full(),
        routes_with_embedded_secret(),
    )
    .await;

    let storage = common::call(
        &harness,
        "get_storage",
        serde_json::json!({"cluster": "pve3", "node": "pve2"}),
    )
    .await
    .expect("get_storage should succeed against the fixture");

    let rendered = storage.to_string();
    assert!(
        !rendered.contains(DENYLISTED_KEY_SECRET),
        "get_storage leaked a denylisted-key secret outside the free-text allowlist: {rendered}"
    );
    assert!(
        !rendered.contains(SHAPE_SECRET),
        "get_storage leaked a crypt-hash-shaped secret under a non-denylisted key: {rendered}"
    );
}

/// The full read-tool sweep: every tool in the server's own catalog, called
/// against both guest fixtures, must never echo the fake secret -- whether
/// it answers with data or with an error. This is the backstop the two tests
/// above don't give: a future catalog entry that starts passing through
/// guest config (or an existing one nobody thought to check) is caught here
/// automatically, because the tool list comes from
/// `rust_proxmoxmcp_core::catalog::READ_TOOLS` rather than a list this test
/// maintains by hand.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_read_tool_leaks_the_fake_secret() {
    // The sweep below drives ~120 calls (60 catalog tools x 2 guests) back
    // to back on one token, which is exactly what the production per-token
    // rate limit (`LimitsConfig::default()`: burst 40, 20 req/s) exists to
    // throttle. That is correct behaviour for a real client; it also means
    // the default limit would report most of this sweep as a transport
    // error rather than exercising the handler, so this test raises the
    // limit instead of disabling redaction coverage.
    let limits = mecmcp_transport::LimitsConfig {
        max_requests_per_second_per_token: 1000,
        max_request_burst_per_token: 1000,
        max_requests_per_second_per_ip: 1000,
        max_request_burst_per_ip: 1000,
        ..mecmcp_transport::LimitsConfig::default()
    };
    let harness = common::TestServer::start_with_limits(
        common::TokenSpec::full(),
        routes_with_embedded_secret(),
        limits,
    )
    .await;

    let tool_names: Vec<&'static str> = rust_proxmoxmcp_core::catalog::READ_TOOLS
        .iter()
        .map(|tool| tool.name)
        .collect();
    assert!(
        !tool_names.is_empty(),
        "the catalog must not be empty, or this sweep proves nothing"
    );

    // (vmid, tool) pairs to call, in a fixed order so results can be zipped
    // back up after the sweep runs.
    let plan: Vec<(u32, &'static str)> = [905u32, 617]
        .into_iter()
        .flat_map(|vmid| tool_names.iter().map(move |&tool| (vmid, tool)))
        .collect();

    let calls: Vec<(&'static str, serde_json::Value)> = plan
        .iter()
        .map(|&(vmid, tool)| {
            // A superset of every field any read tool's argument struct
            // names. None of the read-argument structs deny unknown fields
            // (only the write ones do), so passing all of them to every
            // tool is safe -- each handler's `Parameters<T>` only looks at
            // the fields its own `T` declares.
            let args = serde_json::json!({
                "cluster": "pve3",
                "node": "pve2",
                "vmid": vmid,
                "storage": "local",
                "group": "test-group",
                "name": "test-ipset",
                "upid": "fake-upid-1",
            });
            (tool, args)
        })
        .collect();

    // One MCP session for the whole sweep (120 calls: 60 tools x 2 guests).
    // The first cut of this test opened a fresh session per call, which
    // tripped the per-IP rate limiter after ~15 `initialize`s -- every call
    // past that point returned a transport error that the test treated as
    // "no leak found", so roughly three quarters of the catalog was never
    // actually exercised.
    let results = common::call_many_on_one_session(&harness, &harness.token, calls)
        .await
        .expect("session for the sweep should establish");
    assert_eq!(
        results.len(),
        plan.len(),
        "sweep must return one result per planned call"
    );

    // Label each (vmid, tool) call distinctly so the shared leak-check
    // helper below can report exactly which call leaked, the same
    // granularity the old inline assertion gave per iteration.
    let mut rendered_by_label: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for ((vmid, tool), outcome) in plan.iter().zip(results) {
        let rendered = match outcome {
            Ok(value) => value.to_string(),
            Err(message) => {
                // A transport-level failure (session drop, rate limit, a
                // connection error) means this call never reached a
                // handler, so it proves nothing about redaction -- unlike a
                // tool-level error (bad vmid/guest-type mismatch, unknown
                // parameter), which is real, redacted output and belongs in
                // the leak check below.
                assert!(
                    !message.starts_with("initialize:")
                        && !message.starts_with("call:")
                        && !message.starts_with("spawn_blocking:"),
                    "tool '{tool}' (vmid {vmid}) never reached a handler: {message}"
                );
                message
            }
        };
        rendered_by_label.insert(format!("{tool}@{vmid}"), rendered);
    }

    let labels: Vec<&str> = rendered_by_label.keys().map(String::as_str).collect();
    let leaking = mecmcp_redact::testing::tools_leaking_secrets(
        &labels,
        &[FAKE_SECRET, DENYLISTED_KEY_SECRET, SHAPE_SECRET],
        |label| {
            rendered_by_label
                .get(label)
                .expect("label came from this same map's keys")
                .clone()
        },
    );
    // `leaking` is a list of "tool@vmid" labels (from `rendered_by_label`'s
    // keys), never a secret value, but CodeQL's taint tracking still treats
    // it as tainted because the exercised closure's return flowed from
    // secret-bearing rendered output upstream. Assert on a derived count
    // rather than formatting `leaking` itself (mirrors the same workaround
    // in rustopnsmcp's `respond_redacts_every_known_opnsense_secret_shape`).
    let leaking_count = leaking.len();
    assert!(
        leaking.is_empty(),
        "{leaking_count} tool@vmid call(s) leaked the fake secret"
    );
}
