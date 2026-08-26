//! Tests for the low-tier guest lifecycle primitives.
//!
//! These exercise the wire shape — path, method, and form body — because a
//! lifecycle call that reaches the wrong path or encodes its parameters the
//! wrong way fails in a way only the bytes reveal.

use rust_proxmoxmcp_core::client::ProxmoxClient;
use rust_proxmoxmcp_core::error::ProxmoxError;
use rust_proxmoxmcp_core::guests::{LifecycleVerb, create_backup, create_snapshot, lifecycle};
use rust_proxmoxmcp_core::selector::GuestType;
use rust_proxmoxmcp_core::testing::{Route, TlsMockServer, cluster_for};
use std::io::Write as _;
use std::path::PathBuf;

fn create_secret_file(value: &str) -> PathBuf {
    let mut file = tempfile::NamedTempFile::new().expect("create secret file");
    file.write_all(value.as_bytes()).expect("write");
    file.flush().expect("flush");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("chmod");
    }
    file.into_temp_path().keep().expect("keep")
}

fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn client_for(server: &TlsMockServer) -> ProxmoxClient {
    let secret_path = create_secret_file("not-a-real-secret-0123456789abcdef");
    let mut cluster = cluster_for(server.uri(), server.ca_pem_path());
    cluster.token_secret_file = Some(secret_path);
    ProxmoxClient::new(cluster).expect("client construction")
}

const UPID: &[u8] = br#"{"data":"UPID:pve2:0000A1B2:00C3D4E5:66BC1234:qmstart:905:root@pam:"}"#;

#[tokio::test]
async fn every_lifecycle_verb_reaches_its_own_path() {
    ensure_crypto_provider();

    for (verb, segment) in [
        (LifecycleVerb::Start, "start"),
        (LifecycleVerb::Stop, "stop"),
        (LifecycleVerb::Shutdown, "shutdown"),
        (LifecycleVerb::Reset, "reset"),
        (LifecycleVerb::Reboot, "reboot"),
    ] {
        let path: &'static str =
            Box::leak(format!("/api2/json/nodes/pve2/qemu/905/status/{segment}").into_boxed_str());
        let server = TlsMockServer::start(vec![Route {
            path,
            status: 200,
            body: UPID,
        }])
        .await;
        let client = client_for(&server);

        lifecycle(&client, "pve2", GuestType::Qemu, 905, verb)
            .await
            .unwrap_or_else(|error| panic!("{segment} should succeed: {error}"));

        let recorded = server.requests();
        let request = recorded.last().expect("one request");
        assert_eq!(request.method, "POST", "{segment} must be a POST");
        assert_eq!(request.path, path, "{segment} reached the wrong path");
    }
}

#[tokio::test]
async fn the_guest_type_selects_the_path_segment() {
    ensure_crypto_provider();

    // A container is /lxc/, a VM is /qemu/. Sending one to the other's path is
    // how a stop reaches a guest that merely shares a vmid on another node.
    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/lxc/610/status/stop",
        status: 200,
        body: br#"{"data":"UPID:pve2:1:2:3:vzstop:610:root@pam:"}"#,
    }])
    .await;
    let client = client_for(&server);

    lifecycle(&client, "pve2", GuestType::Lxc, 610, LifecycleVerb::Stop)
        .await
        .expect("container stop");

    let recorded = server.requests();
    assert_eq!(
        recorded.last().expect("request").path,
        "/api2/json/nodes/pve2/lxc/610/status/stop"
    );
}

#[tokio::test]
async fn a_snapshot_sends_its_name_in_the_body() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/lxc/950/snapshot",
        status: 200,
        body: br#"{"data":"UPID:pve2:1:2:3:vzsnapshot:950:root@pam:"}"#,
    }])
    .await;
    let client = client_for(&server);

    create_snapshot(
        &client,
        "pve2",
        GuestType::Lxc,
        950,
        "pre-upgrade-20260825",
        Some("before the release wave"),
    )
    .await
    .expect("snapshot");

    let recorded = server.requests();
    let body = &recorded.last().expect("request").body;
    assert!(body.contains("snapname=pre-upgrade-20260825"), "{body}");
    assert!(
        body.contains("description=before%20the%20release%20wave"),
        "{body}"
    );
}

#[tokio::test]
async fn an_empty_snapshot_description_is_omitted_not_sent_blank() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/lxc/950/snapshot",
        status: 200,
        body: br#"{"data":"UPID:pve2:1:2:3:vzsnapshot:950:root@pam:"}"#,
    }])
    .await;
    let client = client_for(&server);

    create_snapshot(&client, "pve2", GuestType::Lxc, 950, "snap", Some(""))
        .await
        .expect("snapshot");

    let recorded = server.requests();
    let body = &recorded.last().expect("request").body;
    assert!(
        !body.contains("description"),
        "an empty description must be omitted, not sent blank: {body}"
    );
}

#[tokio::test]
async fn a_backup_names_the_guest_in_the_body_not_the_path() {
    ensure_crypto_provider();

    // vzdump is a node-level endpoint; the guest is a body parameter. Getting
    // this backwards produces a 501 that reads like a Proxmox fault.
    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/vzdump",
        status: 200,
        body: br#"{"data":"UPID:pve2:1:2:3:vzdump:950:root@pam:"}"#,
    }])
    .await;
    let client = client_for(&server);

    create_backup(&client, "pve2", 950, "local", "snapshot", Some("zstd"))
        .await
        .expect("backup");

    let recorded = server.requests();
    let request = recorded.last().expect("request");
    assert_eq!(request.path, "/api2/json/nodes/pve2/vzdump");
    assert!(request.body.contains("vmid=950"), "{}", request.body);
    assert!(request.body.contains("storage=local"), "{}", request.body);
    assert!(request.body.contains("mode=snapshot"), "{}", request.body);
    assert!(request.body.contains("compress=zstd"), "{}", request.body);
}

#[tokio::test]
async fn a_malformed_upid_is_refused_rather_than_returned() {
    ensure_crypto_provider();

    // Returning an unparseable UPID would hand the caller a handle that every
    // later task query rejects, blaming the wrong layer.
    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/qemu/905/status/start",
        status: 200,
        body: br#"{"data":"not-a-upid"}"#,
    }])
    .await;
    let client = client_for(&server);

    let error = lifecycle(&client, "pve2", GuestType::Qemu, 905, LifecycleVerb::Start)
        .await
        .expect_err("a malformed UPID must be refused");

    assert!(
        matches!(error, ProxmoxError::Malformed(_)),
        "expected Malformed, got {error:?}"
    );
}
