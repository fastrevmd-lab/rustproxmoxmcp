//! Stage-2 authorization. Stage 1 (tool + cluster) runs in the preflight with
//! no I/O; everything that needs a resolved guest happens here, behind a type
//! that cannot be constructed any other way.

use rust_proxmoxmcp_core::Intent;
use rust_proxmoxmcp_core::{
    client::ProxmoxClient,
    error::ProxmoxError,
    grant::{ProxmoxAction, ProxmoxGrant},
    resolve::GuestIndex,
    tier::Tier,
};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use rust_proxmoxmcp_core::testing::{Route, TlsMockServer, cluster_for};

const RESOURCES: &[u8] = br#"{"data":[
  {"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2",
   "status":"running","tags":"protected"},
  {"id":"lxc/606","type":"lxc","vmid":606,"name":"rustsdcmcp-606","node":"pve3",
   "status":"running","tags":"disposable"}
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

async fn fixture() -> (GuestIndex, ProxmoxClient, TlsMockServer) {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/cluster/resources",
        status: 200,
        body: RESOURCES,
    }])
    .await;

    let secret_path = create_secret_file("not-a-real-secret-0123456789abcdef");
    let mut cluster = cluster_for(server.uri(), server.ca_pem_path());
    cluster.token_secret_file = Some(secret_path);
    cluster.protected_vmids = vec![905];

    let client = ProxmoxClient::new(cluster).expect("client");
    let index = GuestIndex::new(Duration::from_secs(10));

    (index, client, server)
}

fn band_grant() -> ProxmoxGrant {
    ProxmoxGrant {
        guests: vec!["vmid:600-699".to_owned()],
        actions: vec![ProxmoxAction::Read],
    }
}

#[tokio::test]
async fn authorizes_an_in_scope_guest_for_a_granted_tier() {
    let (index, client, _server) = fixture().await;
    let authorized = index
        .authorize(&client, "pve3", 606, &band_grant(), Intent::read())
        .await
        .expect("authorize");
    assert_eq!(authorized.guest().vmid, 606);
    assert_eq!(authorized.tier(), Tier::Read);
    assert!(!authorized.protection().is_protected());
}

#[tokio::test]
async fn refuses_a_guest_outside_the_grant_selector() {
    let (index, client, _server) = fixture().await;
    let error = index
        .authorize(&client, "pve3", 905, &band_grant(), Intent::read())
        .await
        .expect_err("905 is outside 600-699");
    assert!(error.to_string().contains("905"));
    assert!(error.to_string().contains("scope"));
}

#[tokio::test]
async fn refuses_a_tier_the_grant_does_not_carry() {
    let (index, client, _server) = fixture().await;
    let error = index
        .authorize(
            &client,
            "pve3",
            606,
            &band_grant(),
            Intent {
                tier: Tier::Destructive,
                interrupts: false,
                override_applies: None,
            },
        )
        .await
        .expect_err("grant carries read only");
    assert!(error.to_string().contains("destructive") || error.to_string().contains("Destructive"));
}

#[tokio::test]
async fn a_protected_guest_still_authorizes_for_read_and_reports_protection() {
    // Protection gates the destructive tier, not observation. A read of a
    // protected guest is exactly how an operator checks that it is protected.
    let (index, client, _server) = fixture().await;
    let grant = ProxmoxGrant::read_only();
    let authorized = index
        .authorize(&client, "pve3", 905, &grant, Intent::read())
        .await
        .expect("read of a protected guest is allowed");
    assert!(authorized.protection().is_protected());
    assert!(authorized.protection().summary().contains("inventory-pin"));
    assert!(authorized.protection().summary().contains("tag:protected"));
}

#[tokio::test]
async fn an_unknown_guest_is_not_found_and_never_yields_an_authorized_guest() {
    let (index, client, _server) = fixture().await;
    let error = index
        .authorize(
            &client,
            "pve3",
            4242,
            &ProxmoxGrant::read_only(),
            Intent::read(),
        )
        .await
        .expect_err("absent");
    assert!(matches!(error, ProxmoxError::NotFound { .. }));
}
