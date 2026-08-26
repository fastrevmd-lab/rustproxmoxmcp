//! Wire shapes for the provisioning primitives.

use rust_proxmoxmcp_core::client::ProxmoxClient;
use rust_proxmoxmcp_core::guests::{clone_guest, create_guest, download_url, resize_disk};
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

const UPID: &[u8] = br#"{"data":"UPID:pve2:0000A1B2:00C3D4E5:66BC1234:qmclone:905:root@pam:"}"#;

/// A container names itself `hostname`, a VM names itself `name`. Sending the
/// wrong spelling is silently ignored by Proxmox, so the clone would succeed
/// with the wrong name and nobody would be told.
#[tokio::test]
async fn a_clone_uses_the_name_field_its_guest_type_expects() {
    ensure_crypto_provider();

    for (kind, path, expected) in [
        (
            GuestType::Lxc,
            "/api2/json/nodes/pve2/lxc/610/clone",
            "hostname=cloned",
        ),
        (
            GuestType::Qemu,
            "/api2/json/nodes/pve2/qemu/610/clone",
            "name=cloned",
        ),
    ] {
        let server = TlsMockServer::start(vec![Route {
            path,
            status: 200,
            body: UPID,
        }])
        .await;
        let client = client_for(&server);

        clone_guest(&client, "pve2", kind, 610, 611, Some("cloned"), true)
            .await
            .expect("clone");

        let recorded = server.requests();
        let body = &recorded.last().expect("request").body;
        assert!(body.contains(expected), "{kind:?}: {body}");
        assert!(body.contains("newid=611"), "{body}");
        assert!(body.contains("full=1"), "{body}");
    }
}

/// A linked clone shares base storage with its source, so the choice must
/// reach Proxmox rather than being defaulted here.
#[tokio::test]
async fn a_linked_clone_sends_full_zero() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/qemu/610/clone",
        status: 200,
        body: UPID,
    }])
    .await;
    let client = client_for(&server);

    clone_guest(&client, "pve2", GuestType::Qemu, 610, 611, None, false)
        .await
        .expect("clone");

    let recorded = server.requests();
    let body = &recorded.last().expect("request").body;
    assert!(body.contains("full=0"), "{body}");
    assert!(!body.contains("name="), "no name was given: {body}");
}

/// A resize can answer synchronously with `null`. Treating that as an error
/// would report a completed resize as a failure.
#[tokio::test]
async fn a_synchronous_resize_is_not_an_error() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/lxc/610/resize",
        status: 200,
        body: br#"{"data":null}"#,
    }])
    .await;
    let client = client_for(&server);

    let handle = resize_disk(&client, "pve2", GuestType::Lxc, 610, "rootfs", "+8G")
        .await
        .expect("a null answer means it completed, not that it failed");
    assert!(handle.is_empty(), "a synchronous resize has no task handle");

    let recorded = server.requests();
    let body = &recorded.last().expect("request").body;
    assert!(body.contains("disk=rootfs"), "{body}");
    assert!(
        body.contains("size=%2B8G"),
        "the + must survive encoding: {body}"
    );
}

#[tokio::test]
async fn creating_a_guest_posts_the_config_with_the_vmid() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/lxc",
        status: 200,
        body: UPID,
    }])
    .await;
    let client = client_for(&server);

    create_guest(
        &client,
        "pve2",
        GuestType::Lxc,
        620,
        &[
            ("ostemplate", "local:vztmpl/debian-13.tar.zst"),
            ("cores", "2"),
        ],
    )
    .await
    .expect("create");

    let recorded = server.requests();
    let body = &recorded.last().expect("request").body;
    assert!(body.contains("vmid=620"), "{body}");
    assert!(body.contains("cores=2"), "{body}");
}

/// Proxmox verifies a download only when algorithm and value are both present.
/// Sending one alone is silently ignored, so an operator who supplied a
/// checksum would believe it was checked when it was not.
#[tokio::test]
async fn a_checksum_travels_as_a_pair_or_not_at_all() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/storage/local/download-url",
        status: 200,
        body: UPID,
    }])
    .await;
    let client = client_for(&server);

    download_url(
        &client,
        "pve2",
        "local",
        "iso",
        "debian.iso",
        "https://example.org/debian.iso",
        Some(("sha256", "abc123")),
    )
    .await
    .expect("download");

    let recorded = server.requests();
    let body = &recorded.last().expect("request").body;
    assert!(body.contains("checksum-algorithm=sha256"), "{body}");
    assert!(body.contains("checksum=abc123"), "{body}");

    // And without one, neither field appears.
    let server2 = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/storage/local/download-url",
        status: 200,
        body: UPID,
    }])
    .await;
    let client2 = client_for(&server2);
    download_url(
        &client2,
        "pve2",
        "local",
        "iso",
        "debian.iso",
        "https://example.org/debian.iso",
        None,
    )
    .await
    .expect("download");
    let body2 = &server2.requests().last().expect("request").body.clone();
    assert!(!body2.contains("checksum"), "{body2}");
}
