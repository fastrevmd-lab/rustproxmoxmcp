//! QEMU config-update end-to-end tests, including cloud-init fields.
//!
//! `update_vm_config` is a new op on the existing `plan_proxmox_destroy` /
//! `apply_proxmox_change_set` change-set flow (like `migrate` would be),
//! rather than a dedicated pair of tools: it shares the guest resolution,
//! protection, and fingerprint machinery every other destructive op already
//! has.

mod common;

use common::{TestServer, TokenSpec, call_with_token};
use rust_proxmoxmcp_core::testing::Route;
use serde_json::json;

/// An unprotected, running QEMU guest (vmid 650 on pve2) with a token scoped
/// for the full plan/approve/apply lifecycle plus `update_vm_config` itself.
async fn config_update_harness() -> TestServer {
    let spec = TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_proxmox_destroy".to_owned(),
            "get_proxmox_change_set".to_owned(),
            "approve_proxmox_change_set".to_owned(),
            "apply_proxmox_change_set".to_owned(),
            "update_vm_config".to_owned(),
        ],
        guests: vec!["*".to_owned()],
    };

    let routes = vec![
        Route {
            path: "/api2/json/nodes",
            status: 200,
            body: br#"{"data":[{"node":"pve2","status":"online"},{"node":"pve3","status":"online"}]}"#,
        },
        Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: br#"{"data":[{"id":"qemu/650","type":"qemu","vmid":650,"name":"test-vm-650","node":"pve2","status":"running","tags":""}]}"#,
        },
        // The GET this endpoint answers is used twice (plan-time and
        // apply-time fingerprinting) via plain path matching. The POST that
        // performs the actual update is registered separately below, using
        // the method-scoped convention `TlsMockServer` supports precisely
        // for this: the same path means something different to a GET than
        // to a POST.
        Route {
            path: "/api2/json/nodes/pve2/qemu/650/config",
            status: 200,
            body: br#"{"data":{"name":"test-vm-650","cores":2,"memory":2048,"digest":"aabbccddeeff00112233445566778899aabbccdd"}}"#,
        },
        Route {
            path: "POST /api2/json/nodes/pve2/qemu/650/config",
            status: 200,
            body: br#"{"data":"UPID:pve2:0000A1B2:00C3D4E5:66BC1234:qmconfig:650:root@pam:"}"#,
        },
    ];

    TestServer::start_with_routes(spec, routes).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approved_config_update_issues_the_post_including_cloud_init_fields() {
    let h = config_update_harness().await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_proxmox_destroy",
        json!({
            "cluster": "pve3",
            "vmid": 650,
            "op": "update_vm_config",
            "config": {
                "cores": "4",
                "ciuser": "admin",
                "sshkeys": "ssh-ed25519%20AAAA...",
                "ipconfig0": "ip=dhcp",
                "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1",
            },
        }),
    )
    .await
    .expect("plan");

    let preview = planned["preview"].as_str().expect("preview").to_owned();
    assert!(preview.contains("cores=4"), "{preview}");
    assert!(preview.contains("ciuser=admin"), "{preview}");

    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    call_with_token(
        &h,
        &h.second_token,
        "approve_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 650}),
    )
    .await
    .expect("second principal approval should succeed");

    h.script_task_completion(
        "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:qmconfig:650:root@pam:",
        "OK",
    );

    let applied = call_with_token(
        &h,
        &h.token,
        "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 650}),
    )
    .await
    .expect("apply");

    assert_eq!(applied["outcome"], "ok");

    let reqs = h.requests();
    assert!(
        reqs.iter().any(|r| {
            r.method == "POST"
                && r.path == "/api2/json/nodes/pve2/qemu/650/config"
                && r.body.contains("cores=4")
                && r.body.contains("ciuser=admin")
        }),
        "the config POST must actually be issued with the cloud-init fields: {reqs:?}"
    );
}

/// `cipassword` is refused outright, not redacted-then-sent: a plaintext
/// cloud-init password would otherwise sit in the change-set state file on
/// disk until the record is pruned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cipassword_is_refused_at_plan_time() {
    let h = config_update_harness().await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_proxmox_destroy",
        json!({
            "cluster": "pve3",
            "vmid": 650,
            "op": "update_vm_config",
            "config": {"cores": "4", "cipassword": "super-secret"},
        }),
    )
    .await
    .expect_err("cipassword must be refused");
    assert!(error.contains("cipassword"), "{error}");
    assert!(
        !error.contains("super-secret"),
        "the refusal message must not echo the secret value: {error}"
    );

    let reqs = h.requests();
    assert!(
        !reqs
            .iter()
            .any(|r| r.method == "POST" && r.path.ends_with("/config")),
        "nothing may be posted: {reqs:?}"
    );
}

/// The config-update key check is an allowlist: disk/media keys, `delete`,
/// and boolean spellings other than the literal `firewall=0` must all be
/// refused, even though none of them appear on any denylist by name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allowlist_bypasses_are_refused() {
    let h = config_update_harness().await;

    for (key, value) in [
        // `delete=protection` removes the protection flag without ever
        // naming it as a value.
        ("delete", "protection"),
        // Attaching or importing another guest's disk volume.
        ("scsi5", "local-lvm:vm-101-disk-0"),
        ("scsi6", "local-lvm:0,import-from=local-lvm:vm-101-disk-0"),
        // Attaching untrusted boot media.
        ("ide2", "local:iso/untrusted.iso,media=cdrom"),
    ] {
        let error = call_with_token(
            &h,
            &h.token,
            "plan_proxmox_destroy",
            json!({
                "cluster": "pve3",
                "vmid": 650,
                "op": "update_vm_config",
                "config": {key: value},
            }),
        )
        .await
        .expect_err("an allowlist bypass must be refused");
        assert!(error.contains(key), "the refusal must name {key}: {error}");
    }

    // `firewall=off`/`firewall=false` are Proxmox-accepted boolean spellings
    // that a literal `firewall=0` match alone would miss.
    for value in [
        "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=off",
        "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=false",
        // No `firewall=` field at all -- Proxmox defaults to off.
        "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
    ] {
        let error = call_with_token(
            &h,
            &h.token,
            "plan_proxmox_destroy",
            json!({
                "cluster": "pve3",
                "vmid": 650,
                "op": "update_vm_config",
                "config": {"net0": value},
            }),
        )
        .await
        .expect_err("a netN value that does not explicitly enable the firewall must be refused");
        assert!(error.contains("firewall"), "{error}");
    }

    let reqs = h.requests();
    assert!(
        !reqs
            .iter()
            .any(|r| r.method == "POST" && r.path.ends_with("/config")),
        "nothing may be posted: {reqs:?}"
    );
}

/// Rejection case 1: an unsafe/denied key must be refused at plan time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unsafe_config_key_is_refused_at_plan_time() {
    let h = config_update_harness().await;

    for (key, value) in [
        ("hookscript", "local:snippets/evil.pl"),
        ("args", "-device foo"),
        ("boot", "order=ide2"),
        ("hostpci0", "0000:01:00"),
        ("protection", "0"),
    ] {
        let error = call_with_token(
            &h,
            &h.token,
            "plan_proxmox_destroy",
            json!({
                "cluster": "pve3",
                "vmid": 650,
                "op": "update_vm_config",
                "config": {key: value},
            }),
        )
        .await
        .expect_err("an unsafe config key must be refused");
        assert!(error.contains(key), "the refusal must name {key}: {error}");
    }

    let reqs = h.requests();
    assert!(
        !reqs
            .iter()
            .any(|r| r.method == "POST" && r.path.ends_with("/config")),
        "nothing may be posted: {reqs:?}"
    );
}

/// A `netN` value that disables the per-interface firewall is refused even
/// though `netN` is not itself a denylisted key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabling_the_per_interface_firewall_is_refused() {
    let h = config_update_harness().await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_proxmox_destroy",
        json!({
            "cluster": "pve3",
            "vmid": 650,
            "op": "update_vm_config",
            "config": {"net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=0"},
        }),
    )
    .await
    .expect_err("firewall=0 must be refused");
    assert!(error.contains("firewall"), "{error}");
}

/// Rejection case 2: fingerprint drift between plan and apply must be
/// refused -- the config changed on the device between approval and apply,
/// matching the existing drift-refusal pattern used elsewhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_config_change_between_plan_and_apply_is_refused() {
    let h = config_update_harness().await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_proxmox_destroy",
        json!({
            "cluster": "pve3",
            "vmid": 650,
            "op": "update_vm_config",
            "config": {"cores": "4"},
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    call_with_token(
        &h,
        &h.second_token,
        "approve_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 650}),
    )
    .await
    .expect("second principal approval should succeed");

    // The guest's config changed on the device after approval: a different
    // digest, as an out-of-band edit (or another tool) would leave it.
    h.set_guest_config(
        "pve2",
        "qemu",
        650,
        br#"{"data":{"name":"test-vm-650","cores":2,"memory":2048,"digest":"drifted0011223344556677889900aabbccddeeff"}}"#,
    );

    let error = call_with_token(
        &h,
        &h.token,
        "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "vmid": 650}),
    )
    .await
    .expect_err("drift between plan and apply must refuse the apply");
    assert!(error.contains("fingerprint changed"), "{error}");

    let reqs = h.requests();
    assert!(
        !reqs
            .iter()
            .any(|r| r.method == "POST" && r.path.ends_with("/config")),
        "a drifted apply must not write anything: {reqs:?}"
    );
}

/// A token scoped to the generic change-set handlers but not to
/// `update_vm_config` must not be able to select it as the op.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_vm_config_requires_its_own_tool_scope() {
    let spec = TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_proxmox_destroy".to_owned(),
            "get_proxmox_change_set".to_owned(),
            "approve_proxmox_change_set".to_owned(),
            "apply_proxmox_change_set".to_owned(),
            // Deliberately no update_vm_config scope.
        ],
        guests: vec!["*".to_owned()],
    };
    let routes = vec![
        Route {
            path: "/api2/json/nodes",
            status: 200,
            body: br#"{"data":[{"node":"pve2","status":"online"},{"node":"pve3","status":"online"}]}"#,
        },
        Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: br#"{"data":[{"id":"qemu/650","type":"qemu","vmid":650,"name":"test-vm-650","node":"pve2","status":"running","tags":""}]}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/qemu/650/config",
            status: 200,
            body: br#"{"data":{"name":"test-vm-650","cores":2,"memory":2048,"digest":"aabbccddeeff00112233445566778899aabbccdd"}}"#,
        },
    ];
    let h = TestServer::start_with_routes(spec, routes).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_proxmox_destroy",
        json!({
            "cluster": "pve3",
            "vmid": 650,
            "op": "update_vm_config",
            "config": {"cores": "4"},
        }),
    )
    .await
    .expect_err("a token with no update_vm_config scope must not plan one");
    assert!(
        error.contains("not authorized for tool 'update_vm_config'"),
        "{error}"
    );
}

/// This tool updates QEMU config only; an LXC guest must be refused before
/// any approval is spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_lxc_guest_is_refused() {
    // The fixture guest 617 is an LXC (see `common::default_guest_routes`).
    // `handler_with_guest`'s own token does not carry `update_vm_config`, so
    // mint one that does for this specific check.
    let spec = TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_proxmox_destroy".to_owned(),
            "get_proxmox_change_set".to_owned(),
            "approve_proxmox_change_set".to_owned(),
            "apply_proxmox_change_set".to_owned(),
            "update_vm_config".to_owned(),
        ],
        guests: vec!["*".to_owned()],
    };
    let routes = common::default_guest_routes(617, false);
    let h = TestServer::start_with_routes(spec, routes).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_proxmox_destroy",
        json!({
            "cluster": "pve3",
            "vmid": 617,
            "op": "update_vm_config",
            "config": {"cores": "4"},
        }),
    )
    .await
    .expect_err("an LXC guest must be refused");
    assert!(error.contains("QEMU"), "{error}");
}
