//! Resolution turns (cluster, vmid) into a live guest. The caller never names
//! a node: guests migrate, and two of the 2026-08-12 renumbers moved node.

use rust_proxmoxmcp_core::{
    client::ProxmoxClient, error::ProxmoxError, resolve::GuestIndex, selector::GuestType,
};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

mod common;
use common::{cluster_for, Route, TlsMockServer};

const RESOURCES: &[u8] = br#"{"data":[
  {"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2",
   "status":"running","tags":"protected","pool":"ops"},
  {"id":"lxc/606","type":"lxc","vmid":606,"name":"rustsdcmcp-606","node":"pve3",
   "status":"running","tags":"disposable;lab"}
]}"#;

/// Create a secret file with mode 0600 and return its path.
fn create_secret_file(value: &str) -> PathBuf {
    let mut file = tempfile::NamedTempFile::new().expect("create secret file");
    file.write_all(value.as_bytes())
        .expect("write secret value");
    file.flush().expect("flush secret file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("set secret file permissions");
    }

    // Keep the file alive by leaking it — tests are short-lived.
    file.into_temp_path().keep().expect("keep secret file")
}

/// Install a crypto provider once for the whole test binary.
fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

async fn index_and_client() -> (GuestIndex, ProxmoxClient, TlsMockServer) {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/cluster/resources",
        status: 200,
        body: RESOURCES,
    }])
    .await;

    let secret_path = create_secret_file("0123456789abcdef");
    let mut cluster = cluster_for(server.uri(), server.ca_pem_path());
    cluster.token_secret_file = Some(secret_path);

    let client = ProxmoxClient::new(cluster).expect("client");
    let index = GuestIndex::new(Duration::from_secs(10));

    (index, client, server)
}

#[tokio::test]
async fn resolves_a_guest_to_its_current_node() {
    let (index, client, _server) = index_and_client().await;
    let guest = index
        .resolve(&client, "pve3", 905)
        .await
        .expect("resolve");
    assert_eq!(guest.node, "pve2");
    assert_eq!(guest.name, "vsrx-prod");
    assert_eq!(guest.r#type, GuestType::Qemu);
}

#[tokio::test]
async fn splits_semicolon_separated_tags() {
    let (index, client, _server) = index_and_client().await;
    let guest = index
        .resolve(&client, "pve3", 606)
        .await
        .expect("resolve");
    assert_eq!(guest.tags, vec!["disposable".to_owned(), "lab".to_owned()]);
}

#[tokio::test]
async fn an_absent_vmid_is_not_found_rather_than_a_default() {
    let (index, client, _server) = index_and_client().await;
    let error = index
        .resolve(&client, "pve3", 4242)
        .await
        .expect_err("absent");
    assert!(matches!(error, ProxmoxError::NotFound { .. }));
}

#[tokio::test]
async fn a_guest_with_no_pool_resolves_with_none() {
    let (index, client, _server) = index_and_client().await;
    let guest = index
        .resolve(&client, "pve3", 606)
        .await
        .expect("resolve");
    assert_eq!(guest.pool, None);
}

#[tokio::test]
async fn a_second_resolve_within_the_ttl_issues_no_second_request() {
    let (index, client, server) = index_and_client().await;
    index
        .resolve(&client, "pve3", 905)
        .await
        .expect("first");
    index
        .resolve(&client, "pve3", 606)
        .await
        .expect("second");
    assert_eq!(server.request_count(), 1);
}
