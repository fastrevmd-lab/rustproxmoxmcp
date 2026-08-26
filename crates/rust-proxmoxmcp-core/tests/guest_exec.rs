//! `guest_exec` — the most dangerous operation in the surface.
//!
//! Strictly more powerful than `destroy_vm`: it can do anything the guest's
//! root user can, and leaves no Proxmox-level record of *what* it did. These
//! tests pin the wire shape, because an argv that re-splits inside the guest is
//! a different command than the one an approver reviewed.

use rust_proxmoxmcp_core::client::ProxmoxClient;
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

#[tokio::test]
async fn guest_exec_sends_argv_as_repeated_fields() {
    ensure_crypto_provider();

    // Joining argv into one string would hand the guest's shell a line to
    // re-split, so an argument containing a space would become two — a
    // different command than the approver reviewed.
    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/qemu/905/agent/exec",
        status: 200,
        body: br#"{"data":{"pid":4242}}"#,
    }])
    .await;
    let client = client_for(&server);

    let pid = rust_proxmoxmcp_core::guests::guest_exec(
        &client,
        "pve2",
        905,
        &[
            "/bin/systemctl".to_owned(),
            "restart".to_owned(),
            "my service".to_owned(),
        ],
    )
    .await
    .expect("exec");

    assert_eq!(pid, 4242);

    let recorded = server.requests();
    let body = &recorded.last().expect("request").body;
    assert_eq!(
        body.matches("command=").count(),
        3,
        "each argv element is its own field: {body}"
    );
    assert!(
        body.contains("command=my%20service"),
        "an argument with a space must stay one argument: {body}"
    );
}

#[tokio::test]
async fn guest_exec_refuses_an_empty_command() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![]).await;
    let client = client_for(&server);

    let error = rust_proxmoxmcp_core::guests::guest_exec(&client, "pve2", 905, &[])
        .await
        .expect_err("an empty command must be refused");
    assert!(matches!(
        error,
        rust_proxmoxmcp_core::error::ProxmoxError::Malformed(_)
    ));
}

#[tokio::test]
async fn guest_exec_reports_a_missing_pid_rather_than_guessing() {
    ensure_crypto_provider();

    let server = TlsMockServer::start(vec![Route {
        path: "/api2/json/nodes/pve2/qemu/905/agent/exec",
        status: 200,
        body: br#"{"data":{}}"#,
    }])
    .await;
    let client = client_for(&server);

    // Without a pid there is no handle to read the result with, so reporting
    // success would claim a command ran whose outcome nobody can check.
    let error =
        rust_proxmoxmcp_core::guests::guest_exec(&client, "pve2", 905, &["/bin/true".to_owned()])
            .await
            .expect_err("a response without a pid must not read as success");
    assert!(matches!(
        error,
        rust_proxmoxmcp_core::error::ProxmoxError::Malformed(_)
    ));
}
