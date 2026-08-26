//! Creating guests and downloading images.
//!
//! Both address something that does not exist yet — a free VMID, a file not on
//! the storage — so neither can be authorised the way every other tool is, by
//! resolving the guest and matching it against the grant.

mod common;

use serde_json::json;

/// Routes for the create and download endpoints, plus the reads the server
/// makes on its way there.
fn provisioning_routes() -> Vec<common::Route> {
    vec![
        common::Route {
            path: "/api2/json/nodes",
            status: 200,
            body: br#"{"data":[{"node":"pve2","status":"online"},{"node":"pve3","status":"online"}]}"#,
        },
        common::Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: br#"{"data":[{"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2","status":"running","tags":"protected"},{"id":"lxc/617","type":"lxc","vmid":617,"name":"test-guest-617","node":"pve2","status":"running","tags":"test"}]}"#,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/qemu",
            status: 200,
            body: br#"{"data":"UPID:pve2:0000A1B2:00C3D4E5:66BC1234:qmcreate:650:root@pam:"}"#,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/lxc",
            status: 200,
            body: br#"{"data":"UPID:pve2:0000A1B3:00C3D4E6:66BC1235:vzcreate:651:root@pam:"}"#,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/storage/local/download-url",
            status: 200,
            body: br#"{"data":"UPID:pve2:0000A1B4:00C3D4E7:66BC1236:download:local:root@pam:"}"#,
        },
    ]
}

fn spec_with(tools: &[&str], guests: &[&str]) -> common::TokenSpec {
    common::TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: tools.iter().map(|t| (*t).to_owned()).collect(),
        guests: guests.iter().map(|g| (*g).to_owned()).collect(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_vm_is_created_at_a_free_vmid() {
    let h = common::TestServer::start_with_routes(
        spec_with(&["create_vm"], &["*"]),
        provisioning_routes(),
    )
    .await;

    let created = common::call(
        &h,
        "create_vm",
        json!({"cluster":"pve3","node":"pve2","vmid":650,"config":{"name":"test-650","memory":"2048"}}),
    )
    .await
    .expect("create");

    assert_eq!(created["vmid"], 650);
    assert_eq!(created["kind"], "qemu");
    assert!(created["upid"].as_str().expect("upid").starts_with("UPID:"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_container_is_created_through_the_lxc_endpoint() {
    let h = common::TestServer::start_with_routes(
        spec_with(&["create_container"], &["*"]),
        provisioning_routes(),
    )
    .await;

    let created = common::call(
        &h,
        "create_container",
        json!({"cluster":"pve3","node":"pve2","vmid":651,"config":{"hostname":"ct-651"}}),
    )
    .await
    .expect("create");

    assert_eq!(created["kind"], "lxc");
    let hit_lxc = h
        .requests()
        .into_iter()
        .any(|r| r.method == "POST" && r.path == "/api2/json/nodes/pve2/lxc");
    assert!(hit_lxc, "a container must be created through the lxc path");
}

/// The whole reason `allows_new_vmid` exists: nothing resolves a guest here, so
/// the destination is the only thing the grant can be checked against.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_vmid_outside_the_token_scope_is_refused() {
    let h = common::TestServer::start_with_routes(
        spec_with(&["create_vm"], &["vmid:600-699"]),
        provisioning_routes(),
    )
    .await;

    let err = common::call(
        &h,
        "create_vm",
        json!({"cluster":"pve3","node":"pve2","vmid":800,"config":{}}),
    )
    .await
    .expect_err("800 is outside vmid:600-699");
    assert!(err.to_lowercase().contains("scope"), "{err}");

    let created = h
        .requests()
        .into_iter()
        .filter(|r| r.method == "POST" && r.path.ends_with("/qemu"))
        .count();
    assert_eq!(created, 0, "nothing may be created");
}

/// A pinned VMID is pinned because something important belongs there. Creating
/// over it strands the real guest, and the protection union cannot catch it
/// because there is no guest to resolve.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creating_over_a_protected_pin_is_refused() {
    let h = common::TestServer::start_with_routes(
        spec_with(&["create_vm"], &["*"]),
        provisioning_routes(),
    )
    .await;

    let err = common::call(
        &h,
        "create_vm",
        json!({"cluster":"pve3","node":"pve2","vmid":905,"config":{}}),
    )
    .await
    .expect_err("905 is a protected pin");
    assert!(err.to_lowercase().contains("protected"), "{err}");
}

/// `hookscript` and `args` execute on the hypervisor, not in the guest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_keys_that_run_on_the_host_are_refused() {
    let h = common::TestServer::start_with_routes(
        spec_with(&["create_vm", "create_container"], &["*"]),
        provisioning_routes(),
    )
    .await;

    for key in ["hookscript", "args"] {
        let err = common::call(
            &h,
            "create_vm",
            json!({"cluster":"pve3","node":"pve2","vmid":650,"config":{key:"/anything"}}),
        )
        .await
        .expect_err("a host-escaping config key must be refused");
        assert!(err.contains(key), "the refusal must name {key}: {err}");
    }

    let created = h
        .requests()
        .into_iter()
        .filter(|r| r.method == "POST" && r.path.ends_with("/qemu"))
        .count();
    assert_eq!(created, 0, "nothing may be created");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_image_download_requests_checksum_verification() {
    let h = common::TestServer::start_with_routes(
        spec_with(&["download_iso"], &["*"]),
        provisioning_routes(),
    )
    .await;

    let out = common::call(
        &h,
        "download_iso",
        json!({
            "cluster":"pve3","node":"pve2","storage":"local",
            "filename":"debian.iso","url":"https://example.invalid/debian.iso",
            "checksum_algorithm":"sha256","checksum":"abc123"
        }),
    )
    .await
    .expect("download");

    // Requested, not observed: Proxmox verifies inside the download task, so a
    // mismatch surfaces as a failed task after this call has returned.
    assert_eq!(out["checksum_verification_requested"], true);
}

/// Proxmox ignores one half without the other, so a caller supplying only one
/// would believe a checksum was verified when nothing was checked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_a_checksum_is_refused() {
    let h = common::TestServer::start_with_routes(
        spec_with(&["download_iso"], &["*"]),
        provisioning_routes(),
    )
    .await;

    let err = common::call(
        &h,
        "download_iso",
        json!({
            "cluster":"pve3","node":"pve2","storage":"local",
            "filename":"debian.iso","url":"https://example.invalid/debian.iso",
            "checksum_algorithm":"sha256"
        }),
    )
    .await
    .expect_err("a lone algorithm must be refused");
    assert!(err.to_lowercase().contains("checksum"), "{err}");
}

/// A storage belongs to no guest, so a narrowed guest scope cannot be checked
/// against it. Such a token is refused rather than quietly granted the run of
/// storage every guest shares.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_narrowed_token_may_not_write_to_storage() {
    let h = common::TestServer::start_with_routes(
        spec_with(&["download_iso"], &["vmid:600-699"]),
        provisioning_routes(),
    )
    .await;

    let err = common::call(
        &h,
        "download_iso",
        json!({
            "cluster":"pve3","node":"pve2","storage":"local",
            "filename":"debian.iso","url":"https://example.invalid/debian.iso"
        }),
    )
    .await
    .expect_err("a guest-scoped token must not reach storage");
    assert!(
        err.contains('*'),
        "the refusal must name the required scope: {err}"
    );

    let downloads = h
        .requests()
        .into_iter()
        .filter(|r| r.path.ends_with("/download-url"))
        .count();
    assert_eq!(downloads, 0, "nothing may be downloaded");
}

/// Proxmox restores a backup by POSTing to the *same* endpoint a create uses,
/// with `archive`, `restore` and `force` added. Without the existence check a
/// `create_vm` grant would overwrite a live guest, skipping the destructive
/// tier, the protection check and change-set approval.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creating_over_an_existing_guest_is_refused() {
    let h = common::TestServer::start_with_routes(
        spec_with(&["create_vm"], &["*"]),
        provisioning_routes(),
    )
    .await;

    let err = common::call(
        &h,
        "create_vm",
        json!({"cluster":"pve3","node":"pve2","vmid":617,"config":{"name":"hijack"}}),
    )
    .await
    .expect_err("617 already exists");
    assert!(err.contains("already exists"), "{err}");

    let created = h
        .requests()
        .into_iter()
        .filter(|r| r.method == "POST" && (r.path.ends_with("/qemu") || r.path.ends_with("/lxc")))
        .count();
    assert_eq!(created, 0, "nothing may be posted");
}

/// The restore controls are refused by name as well, so a caller is told what
/// was wrong rather than only that the vmid was taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_controls_are_refused_in_a_create() {
    let h = common::TestServer::start_with_routes(
        spec_with(&["create_vm"], &["*"]),
        provisioning_routes(),
    )
    .await;

    for key in ["archive", "restore", "force"] {
        let err = common::call(
            &h,
            "create_vm",
            json!({"cluster":"pve3","node":"pve2","vmid":650,"config":{key:"x"}}),
        )
        .await
        .expect_err("a restore control must be refused");
        assert!(err.contains(key), "{key}: {err}");
    }
}

/// `mp0=/,mp=/host` with a privileged container mounts host root inside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_mounts_and_device_passthrough_are_refused() {
    let h = common::TestServer::start_with_routes(
        spec_with(&["create_container", "create_vm"], &["*"]),
        provisioning_routes(),
    )
    .await;

    for (key, value) in [
        ("mp0", "/,mp=/host"),
        ("hostpci0", "0000:01:00"),
        ("usb0", "host=1234:5678"),
        ("lxc.cgroup.devices.allow", "a"),
    ] {
        let err = common::call(
            &h,
            "create_container",
            json!({"cluster":"pve3","node":"pve2","vmid":651,"config":{key:value}}),
        )
        .await
        .expect_err("a host-reaching config key must be refused");
        assert!(err.contains(key), "the refusal must name {key}: {err}");
    }

    let created = h
        .requests()
        .into_iter()
        .filter(|r| r.method == "POST" && r.path.ends_with("/lxc"))
        .count();
    assert_eq!(created, 0, "nothing may be created");
}

/// An ordinary key can still carry a host path in its value: `scsi0` must stay
/// allowed for `local-lvm:32` and refused for `/dev/sdb`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_path_in_any_value_is_refused() {
    let h = common::TestServer::start_with_routes(
        spec_with(&["create_vm"], &["*"]),
        provisioning_routes(),
    )
    .await;

    let err = common::call(
        &h,
        "create_vm",
        json!({"cluster":"pve3","node":"pve2","vmid":650,"config":{"scsi0":"/dev/sdb"}}),
    )
    .await
    .expect_err("a host device path must be refused");
    assert!(err.to_lowercase().contains("host path"), "{err}");

    // The same key with a storage reference is fine.
    common::call(
        &h,
        "create_vm",
        json!({"cluster":"pve3","node":"pve2","vmid":650,"config":{"scsi0":"local-lvm:32"}}),
    )
    .await
    .expect("a storage-backed disk must still be allowed");
}

/// Proxmox reads an omitted `unprivileged` as 0 -- privileged. Refusing the key
/// outright therefore permitted only privileged containers, which was the exact
/// opposite of the intent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_container_defaults_to_unprivileged() {
    let h = common::TestServer::start_with_routes(
        spec_with(&["create_container"], &["*"]),
        provisioning_routes(),
    )
    .await;

    common::call(
        &h,
        "create_container",
        json!({"cluster":"pve3","node":"pve2","vmid":651,"config":{"hostname":"ct-651"}}),
    )
    .await
    .expect("create");

    let body = h
        .requests()
        .into_iter()
        .find(|r| r.method == "POST" && r.path.ends_with("/lxc"))
        .map(|r| r.body.clone())
        .expect("the create must have been sent");
    assert!(
        body.contains("unprivileged=1"),
        "silence must not select the privileged option: {body}"
    );
}

/// `unprivileged=1` is the safe setting and must be accepted; 0 is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unprivileged_one_is_allowed_and_zero_is_not() {
    let h = common::TestServer::start_with_routes(
        spec_with(&["create_container"], &["*"]),
        provisioning_routes(),
    )
    .await;

    common::call(
        &h,
        "create_container",
        json!({"cluster":"pve3","node":"pve2","vmid":651,"config":{"unprivileged":"1"}}),
    )
    .await
    .expect("unprivileged=1 is the safe setting and must be allowed");

    let err = common::call(
        &h,
        "create_container",
        json!({"cluster":"pve3","node":"pve2","vmid":651,"config":{"unprivileged":"0"}}),
    )
    .await
    .expect_err("a privileged container must be refused");
    assert!(err.contains("privileged"), "{err}");
}
