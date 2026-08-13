//! Integration tests for the Proxmox HTTP client against a mock cluster.
//!
//! These tests use a hand-rolled TLS server because `mecmcp-http` rejects
//! plaintext URLs at construction and `wiremock` has no TLS support.

use rust_proxmoxmcp_core::client::ProxmoxClient;
use rust_proxmoxmcp_core::error::ProxmoxError;
use rust_proxmoxmcp_core::testing::{Route, TlsMockServer, cluster_for};
use std::io::Write as _;
use std::path::PathBuf;

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
///
/// `mecmcp-http` deliberately does not pick a provider, so tests stand in for
/// the consumer binary. `install_default` is process-global and one-shot.
fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

#[tokio::test]
async fn unwraps_the_data_envelope() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes",
        status: 200,
        body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
    }])
    .await;

    let secret_path = create_secret_file("0123456789abcdef");
    let mut cluster = cluster_for(server.uri(), server.ca_pem_path());
    cluster.token_secret_file = Some(secret_path);

    let client = ProxmoxClient::new(cluster).expect("client construction");
    let value = client
        .get_json("/api2/json/nodes", &[], &[])
        .await
        .expect("get nodes");

    assert_eq!(value[0]["node"], "pve2");

    // Verify the Authorization header is exactly the expected Proxmox format.
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("PVEAPIToken=root@pam!mcp=0123456789abcdef")
    );
}

#[tokio::test]
async fn expands_a_path_template_and_percent_encodes_the_value() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/qemu/905/config",
        status: 200,
        body: br#"{"data":{"digest":"abc123","name":"vsrx-prod"}}"#,
    }])
    .await;

    let secret_path = create_secret_file("0123456789abcdef");
    let mut cluster = cluster_for(server.uri(), server.ca_pem_path());
    cluster.token_secret_file = Some(secret_path);

    let client = ProxmoxClient::new(cluster).expect("client construction");
    let value = client
        .get_json(
            "/api2/json/nodes/{node}/qemu/{vmid}/config",
            &[("node", "pve2"), ("vmid", "905")],
            &[],
        )
        .await
        .expect("get config");

    assert_eq!(value["digest"], "abc123");
}

#[tokio::test]
async fn a_path_parameter_cannot_escape_its_segment() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![]).await;

    let secret_path = create_secret_file("0123456789abcdef");
    let mut cluster = cluster_for(server.uri(), server.ca_pem_path());
    cluster.token_secret_file = Some(secret_path);

    let client = ProxmoxClient::new(cluster).expect("client construction");
    let error = client
        .get_json(
            "/api2/json/nodes/{node}/status",
            &[("node", "pve2/../../access/users")],
            &[],
        )
        .await
        .expect_err("segment escape must be refused");

    assert!(
        matches!(error, ProxmoxError::Malformed(_)),
        "expected Malformed, got {error:?}"
    );

    // Verify no request reached the server.
    assert_eq!(server.request_count(), 0);
}

#[tokio::test]
async fn a_401_becomes_unauthorized_without_echoing_the_body() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes",
        status: 401,
        body: b"authentication failure: token 0123456789abcdef",
    }])
    .await;

    let secret_path = create_secret_file("0123456789abcdef");
    let mut cluster = cluster_for(server.uri(), server.ca_pem_path());
    cluster.token_secret_file = Some(secret_path);

    let client = ProxmoxClient::new(cluster).expect("client construction");
    let error = client
        .get_json("/api2/json/nodes", &[], &[])
        .await
        .expect_err("401 must error");

    assert!(
        matches!(error, ProxmoxError::Unauthorized),
        "expected Unauthorized, got {error:?}"
    );
    assert!(
        !error.to_string().contains("0123456789abcdef"),
        "secret must not leak into error message"
    );
}

#[tokio::test]
async fn a_plaintext_endpoint_is_refused_at_construction() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![]).await;
    let secret_path = create_secret_file("0123456789abcdef");

    let mut cluster = cluster_for("http://pve3.example.org:8006", server.ca_pem_path());
    cluster.ca_pem_path = None;
    cluster.token_secret_file = Some(secret_path);

    let result = ProxmoxClient::new(cluster);
    assert!(
        result.is_err(),
        "plaintext endpoint must be refused at construction"
    );
}

#[tokio::test]
async fn appends_query_parameters() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/storage/local/content",
        status: 200,
        body: br#"{"data":[{"volid":"local:backup/vzdump.tar"}]}"#,
    }])
    .await;

    let secret_path = create_secret_file("0123456789abcdef");
    let mut cluster = cluster_for(server.uri(), server.ca_pem_path());
    cluster.token_secret_file = Some(secret_path);

    let client = ProxmoxClient::new(cluster).expect("client construction");
    let value = client
        .get_json(
            "/api2/json/nodes/{node}/storage/{storage}/content",
            &[("node", "pve2"), ("storage", "local")],
            &[("content", "backup")],
        )
        .await
        .expect("get content");

    assert_eq!(value[0]["volid"], "local:backup/vzdump.tar");

    // Verify the query parameter reached the server.
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].target.contains("content=backup"),
        "query parameter must appear in target, got: {}",
        requests[0].target
    );
}
