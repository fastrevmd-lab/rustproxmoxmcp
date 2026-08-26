//! Resolution turns (cluster, vmid) into a live guest. The caller never names
//! a node: guests migrate, and two of the 2026-08-12 renumbers moved node.

use rust_proxmoxmcp_core::{
    client::ProxmoxClient, error::ProxmoxError, resolve::GuestIndex, selector::GuestType,
};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use rust_proxmoxmcp_core::testing::{Route, TlsMockServer, cluster_for};

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

    let secret_path = create_secret_file("not-a-real-secret-0123456789abcdef");
    let mut cluster = cluster_for(server.uri(), server.ca_pem_path());
    cluster.token_secret_file = Some(secret_path);

    let client = ProxmoxClient::new(cluster).expect("client");
    let index = GuestIndex::new(Duration::from_secs(10));

    (index, client, server)
}

#[tokio::test]
async fn resolves_a_guest_to_its_current_node() {
    let (index, client, _server) = index_and_client().await;
    let guest = index.resolve(&client, "pve3", 905).await.expect("resolve");
    assert_eq!(guest.node, "pve2");
    assert_eq!(guest.name, "vsrx-prod");
    assert_eq!(guest.r#type, GuestType::Qemu);
}

#[tokio::test]
async fn splits_semicolon_separated_tags() {
    let (index, client, _server) = index_and_client().await;
    let guest = index.resolve(&client, "pve3", 606).await.expect("resolve");
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
    let guest = index.resolve(&client, "pve3", 606).await.expect("resolve");
    assert_eq!(guest.pool, None);
}

#[tokio::test]
async fn a_second_resolve_within_the_ttl_issues_no_second_request() {
    let (index, client, server) = index_and_client().await;
    index.resolve(&client, "pve3", 905).await.expect("first");
    index.resolve(&client, "pve3", 606).await.expect("second");
    assert_eq!(server.request_count(), 1);
}

/// A fetch that began before an invalidation must not publish its result
/// afterwards.
///
/// This is the race a destructive apply depends on not happening: it drops the
/// cluster snapshot precisely so its fingerprint re-check sees post-change
/// state. Last-insert-wins would let an older in-flight fetch put the
/// pre-change snapshot back, and the re-check would compare equal and destroy
/// a guest that had moved.
///
/// The fetch is parked mid-flight with `hold_responses` so the interleaving is
/// deterministic rather than hoped for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fetch_started_before_an_invalidation_does_not_repopulate_the_cache() {
    let (index, client, server) = index_and_client().await;
    let index = std::sync::Arc::new(index);
    let client = std::sync::Arc::new(client);

    // Park every response, then start a fetch that will read the OLD body.
    let hold = server.hold_responses().await;
    let stale_fetch = {
        let index = std::sync::Arc::clone(&index);
        let client = std::sync::Arc::clone(&client);
        tokio::spawn(async move { index.resolve(&client, "pve3", 905).await.map(|g| g.node) })
    };

    // Wait until the server has actually received it, so the fetch is in
    // flight rather than merely spawned.
    for _ in 0..200 {
        if server.request_count() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(server.request_count() >= 1, "the fetch must be in flight");

    // The world changes, and the cache is invalidated -- both while that
    // earlier fetch is still parked holding pre-change data.
    server.replace_route(Route {
        path: "/api2/json/cluster/resources",
        status: 200,
        body: br#"{"data":[{"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve3","status":"running","tags":"protected"}]}"#,
    });
    index.invalidate_cluster("pve3");

    // Let the parked fetch complete. Its body is the pre-change one.
    drop(hold);
    let _ = stale_fetch.await.expect("join");

    // The next reader must not be served that reinserted pre-change snapshot.
    let after = index.resolve(&client, "pve3", 905).await.expect("resolve");
    assert_eq!(
        after.node, "pve3",
        "a fetch that started before the invalidation must not repopulate the cache"
    );
}

/// Invalidating one cluster must not evict another's snapshot.
#[tokio::test]
async fn invalidating_one_cluster_leaves_the_others_cached() {
    let (index, client, server) = index_and_client().await;

    index.resolve(&client, "pve3", 905).await.expect("warm a");
    index.resolve(&client, "other", 905).await.expect("warm b");
    let warmed = server.request_count();

    index.invalidate_cluster("pve3");

    // The untouched cluster answers from cache: no new request.
    index.resolve(&client, "other", 905).await.expect("cached");
    assert_eq!(
        server.request_count(),
        warmed,
        "invalidating pve3 must not evict the other cluster"
    );

    // The invalidated one refetches.
    index.resolve(&client, "pve3", 905).await.expect("refetch");
    assert!(
        server.request_count() > warmed,
        "the invalidated cluster must refetch"
    );
}
