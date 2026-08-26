//! Wire shapes for the destructive primitives.
//!
//! Each asserts the path and method, because a destructive call that reaches
//! the wrong path either fails loudly or — worse — succeeds against something
//! the caller did not name.

use rust_proxmoxmcp_core::client::ProxmoxClient;
use rust_proxmoxmcp_core::guests::{
    delete_snapshot, delete_volume, destroy_vm, restore_backup, rollback_snapshot,
};
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

const UPID: &[u8] = br#"{"data":"UPID:pve2:0000A1B2:00C3D4E5:66BC1234:qmdestroy:905:root@pam:"}"#;

#[tokio::test]
async fn destroying_a_vm_uses_the_qemu_path_and_purges_unreferenced_disks() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/qemu/905",
        status: 200,
        body: UPID,
    }])
    .await;
    let client = client_for(&server);

    destroy_vm(&client, "pve2", 905, true)
        .await
        .expect("destroy");

    let recorded = server.requests();
    let request = recorded.last().expect("request");
    assert_eq!(request.method, "DELETE");
    assert_eq!(request.path, "/api2/json/nodes/pve2/qemu/905");
    assert!(request.target.contains("purge=1"), "{}", request.target);
    assert!(
        request.target.contains("destroy-unreferenced-disks=1"),
        "a purge that leaves disks behind is not a purge: {}",
        request.target
    );
}

#[tokio::test]
async fn deleting_a_snapshot_names_it_in_the_path() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/lxc/950/snapshot/pre-upgrade-20260825",
        status: 200,
        body: UPID,
    }])
    .await;
    let client = client_for(&server);

    delete_snapshot(&client, "pve2", GuestType::Lxc, 950, "pre-upgrade-20260825")
        .await
        .expect("delete snapshot");

    let recorded = server.requests();
    assert_eq!(recorded.last().expect("request").method, "DELETE");
}

#[tokio::test]
async fn rolling_back_posts_to_the_rollback_subpath() {
    ensure_crypto_provider();

    // The distinction that matters: DELETE on the snapshot path removes the
    // snapshot, POST on .../rollback restores the guest to it. Confusing the
    // two destroys the wrong thing.
    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/lxc/950/snapshot/pre-upgrade-20260825/rollback",
        status: 200,
        body: UPID,
    }])
    .await;
    let client = client_for(&server);

    rollback_snapshot(&client, "pve2", GuestType::Lxc, 950, "pre-upgrade-20260825")
        .await
        .expect("rollback");

    let recorded = server.requests();
    let request = recorded.last().expect("request");
    assert_eq!(request.method, "POST", "a rollback is a POST, not a DELETE");
    assert!(request.path.ends_with("/rollback"), "{}", request.path);
}

#[tokio::test]
async fn deleting_a_volume_addresses_it_by_volid() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        // The encoded form is what goes on the wire: the volid is one path
        // segment, so its colon and slash are percent-encoded.
        path: "/api2/json/nodes/pve2/storage/local/content/local%3Abackup%2Fvzdump-lxc-950.tar.zst",
        status: 200,
        body: br#"{"data":null}"#,
    }])
    .await;
    let client = client_for(&server);

    // A null `data` is a normal answer here, not an error: some storage types
    // delete synchronously and return no UPID.
    delete_volume(
        &client,
        "pve2",
        "local",
        "local:backup/vzdump-lxc-950.tar.zst",
    )
    .await
    .expect("a synchronous delete returning null must not be an error");

    let recorded = server.requests();
    let request = recorded.last().expect("request");
    assert_eq!(request.method, "DELETE");
    assert!(
        request.path.contains("%2F"),
        "the volid must reach Proxmox as one encoded segment: {}",
        request.path
    );
}

#[tokio::test]
async fn a_volid_that_could_traverse_is_refused() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![]).await;
    let client = client_for(&server);

    // `expand_path` would have caught this; appending the volid ourselves means
    // this call site has to.
    for bad in ["", "local:../../etc/passwd", "no-colon/path"] {
        let error = delete_volume(&client, "pve2", "local", bad)
            .await
            .expect_err("a malformed volid must be refused");
        assert!(
            matches!(
                error,
                rust_proxmoxmcp_core::error::ProxmoxError::Malformed(_)
            ),
            "{bad}: expected Malformed, got {error:?}"
        );
    }
}

#[tokio::test]
async fn restoring_posts_the_archive_and_force_in_the_body() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/lxc",
        status: 200,
        body: UPID,
    }])
    .await;
    let client = client_for(&server);

    restore_backup(
        &client,
        "pve2",
        GuestType::Lxc,
        950,
        "local:backup/vzdump-lxc-950.tar.zst",
        true,
    )
    .await
    .expect("restore");

    let recorded = server.requests();
    let request = recorded.last().expect("request");
    assert_eq!(request.method, "POST");
    assert_eq!(
        request.path, "/api2/json/nodes/pve2/lxc",
        "restore posts to the type collection, with the guest named in the body"
    );
    assert!(request.body.contains("vmid=950"), "{}", request.body);
    assert!(request.body.contains("restore=1"), "{}", request.body);
    assert!(
        request.body.contains("force=1"),
        "overwriting an existing guest needs force: {}",
        request.body
    );
}

#[tokio::test]
async fn a_restore_without_force_says_so() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/qemu",
        status: 200,
        body: UPID,
    }])
    .await;
    let client = client_for(&server);

    restore_backup(
        &client,
        "pve2",
        GuestType::Qemu,
        905,
        "local:backup/x",
        false,
    )
    .await
    .expect("restore");

    let recorded = server.requests();
    assert!(
        recorded.last().expect("request").body.contains("force=0"),
        "force must be sent explicitly, not omitted and defaulted by Proxmox"
    );
}
