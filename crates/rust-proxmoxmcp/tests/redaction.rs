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

fn secret_bearing_description() -> String {
    format!("re-provisioned 2026-09-27 (ticket OPS-4110); backup admin password: {FAKE_SECRET}")
}

const EMPTY_ARRAY: &[u8] = br#"{"data":[]}"#;
const EMPTY_OBJECT: &[u8] = br#"{"data":{}}"#;

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
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/snapshot",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/interfaces",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/nodes/pve2/storage",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/nodes/pve2/storage/local/content",
            status: 200,
            body: EMPTY_ARRAY,
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
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/cluster/firewall/options",
            status: 200,
            body: EMPTY_OBJECT,
        },
        Route {
            path: "/api2/json/cluster/firewall/groups",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/cluster/firewall/groups/test-group",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/cluster/firewall/ipset",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/cluster/firewall/ipset/test-ipset",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/cluster/firewall/aliases",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/nodes/pve2/firewall/rules",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/nodes/pve2/firewall/options",
            status: 200,
            body: EMPTY_OBJECT,
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/905/firewall/rules",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/firewall/rules",
            status: 200,
            body: EMPTY_ARRAY,
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
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/firewall/aliases",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/905/firewall/ipset",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/firewall/ipset",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/905/firewall/ipset/test-ipset",
            status: 200,
            body: EMPTY_ARRAY,
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/firewall/ipset/test-ipset",
            status: 200,
            body: EMPTY_ARRAY,
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
    let harness = common::TestServer::start_with_routes(
        common::TokenSpec::full(),
        routes_with_embedded_secret(),
    )
    .await;

    let tool_names: Vec<&str> = rust_proxmoxmcp_core::catalog::READ_TOOLS
        .iter()
        .map(|tool| tool.name)
        .collect();
    assert!(
        !tool_names.is_empty(),
        "the catalog must not be empty, or this sweep proves nothing"
    );

    for vmid in [905u32, 617] {
        for &tool in &tool_names {
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

            let outcome = common::call(&harness, tool, args).await;
            let rendered = match outcome {
                Ok(value) => value.to_string(),
                Err(message) => message,
            };
            assert!(
                !rendered.contains(FAKE_SECRET),
                "tool '{tool}' (vmid {vmid}) leaked the fake secret: {rendered}"
            );
        }
    }
}
