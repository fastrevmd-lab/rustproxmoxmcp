//! Shared test fixtures for Proxmox client integration tests.
//!
//! The `TlsMockServer` provides an HTTPS endpoint for client tests. `mecmcp-http`
//! rejects plaintext URLs at construction, so every test needs a working TLS
//! server. This harness generates a self-signed certificate for `localhost` and
//! serves minimal HTTP/1.1 responses while recording requests.

use rust_proxmoxmcp_core::inventory::Cluster;
use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A route the mock server knows how to serve.
pub struct Route {
    /// Path to match (without query string).
    pub path: &'static str,
    /// HTTP status code to return.
    pub status: u16,
    /// Response body bytes.
    pub body: &'static [u8],
}

/// A recorded HTTP request.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    /// HTTP method (GET, POST, etc.).
    #[allow(dead_code)]
    pub method: String,
    /// Full request target including query string.
    pub target: String,
    /// Value of the Authorization header, if present.
    pub authorization: Option<String>,
}

/// An HTTPS server serving canned routes and recording requests.
pub struct TlsMockServer {
    uri: String,
    ca_pem_file: tempfile::NamedTempFile,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl TlsMockServer {
    /// Start an HTTPS listener on `127.0.0.1:0` serving `routes`.
    ///
    /// Returns a server with a localhost URI and a CA PEM file for the client's
    /// `extra_root_certificates`.
    pub async fn start(routes: Vec<Route>) -> Self {
        let (cert_pem, server_config) = Self::tls_material();
        let (listener, port) = Self::bind_local().await;

        let mut ca_pem_file =
            tempfile::NamedTempFile::new().expect("failed to create temp CA PEM file");
        ca_pem_file
            .write_all(cert_pem.as_bytes())
            .expect("failed to write CA PEM");
        ca_pem_file.flush().expect("failed to flush CA PEM");

        let requests = Arc::new(Mutex::new(Vec::new()));
        Self::serve(listener, server_config, routes, Arc::clone(&requests));

        Self {
            uri: format!("https://localhost:{port}"),
            ca_pem_file,
            requests,
        }
    }

    /// The HTTPS endpoint URI.
    ///
    /// Note: uses `localhost`, not `127.0.0.1`, to match the certificate's SAN.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Path to the CA PEM file for `extra_root_certificates`.
    pub fn ca_pem_path(&self) -> &Path {
        self.ca_pem_file.path()
    }

    /// All requests recorded so far.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("lock requests").clone()
    }

    /// Number of requests recorded so far.
    pub fn request_count(&self) -> usize {
        self.requests.lock().expect("lock requests").len()
    }

    /// Generate a self-signed `localhost` certificate.
    ///
    /// Returns the PEM for the client's `extra_root_certificates` and a matching
    /// rustls server config. ALPN is pinned to `http/1.1` to match `mecmcp-http`.
    ///
    /// The crypto provider is named explicitly rather than left to
    /// `ServerConfig::builder`'s auto-detection. Under `cargo test --workspace`,
    /// feature unification enables both the `aws-lc-rs` and `ring` rustls
    /// providers, auto-detection cannot choose, and it panics — while
    /// `cargo test -p rust-proxmoxmcp-core` passes. Naming the provider makes
    /// the test behave the same either way.
    fn tls_material() -> (String, rustls::ServerConfig) {
        let key_pair = rcgen::KeyPair::generate().expect("generate key pair");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .expect("create certificate params");
        let cert = params.self_signed(&key_pair).expect("self-sign certificate");

        let cert_pem = cert.pem();
        let key_der =
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("safe protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der)
            .expect("single cert");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        (cert_pem, server_config)
    }

    /// Bind a TCP listener on `127.0.0.1:0` and return it with its port.
    async fn bind_local() -> (tokio::net::TcpListener, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local listener");
        let port = listener.local_addr().expect("listener local addr").port();
        (listener, port)
    }

    /// Serve TLS requests, matching routes by path and recording each request.
    fn serve(
        listener: tokio::net::TcpListener,
        server_config: rustls::ServerConfig,
        routes: Vec<Route>,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
    ) {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let routes = routes.clone();
                let requests = Arc::clone(&requests);
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    Self::handle_request(&mut tls, &routes, &requests).await;
                });
            }
        });
    }

    /// Handle one HTTP request: parse, record, and respond.
    async fn handle_request<S>(
        stream: &mut S,
        routes: &[Route],
        requests: &Arc<Mutex<Vec<RecordedRequest>>>,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        // Read the request headers.
        let mut buffer = Vec::new();
        let mut byte = [0u8; 1];
        while stream
            .read_exact(&mut byte)
            .await
            .expect("read request byte")
            == 1
        {
            buffer.push(byte[0]);
            if buffer.ends_with(b"\r\n\r\n") {
                break;
            }
        }

        let request_text =
            String::from_utf8_lossy(&buffer[..buffer.len().saturating_sub(4)]).to_string();
        let lines: Vec<&str> = request_text.lines().collect();
        if lines.is_empty() {
            return;
        }

        // Parse the request line: "GET /path?query HTTP/1.1"
        let parts: Vec<&str> = lines[0].split_whitespace().collect();
        if parts.len() < 2 {
            return;
        }
        let method = parts[0].to_owned();
        let target = parts[1].to_owned();

        // Parse headers to extract Authorization (case-insensitive).
        let mut authorization = None;
        for line in &lines[1..] {
            if let Some((name, value)) = line.split_once(':')
                && name.trim().eq_ignore_ascii_case("authorization")
            {
                authorization = Some(value.trim().to_owned());
                break;
            }
        }

        // Record the request.
        requests
            .lock()
            .expect("lock requests")
            .push(RecordedRequest {
                method,
                target: target.clone(),
                authorization,
            });

        // Match a route by path (ignoring query string).
        let path = target.split('?').next().expect("split target");
        let route = routes.iter().find(|r| r.path == path);

        let (status, body) = if let Some(r) = route {
            (r.status, r.body)
        } else {
            (404, b"Not Found" as &[u8])
        };

        // Write the response.
        let response = format!(
            "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(body).await;
        let _ = stream.flush().await;
    }
}

// Routes must be Clone for spawning per-connection handlers.
impl Clone for Route {
    fn clone(&self) -> Self {
        Self {
            path: self.path,
            status: self.status,
            body: self.body,
        }
    }
}

/// Build a cluster pointed at the mock server.
///
/// Shared by all client integration tests.
pub fn cluster_for(endpoint: &str, ca_pem: &Path) -> Cluster {
    Cluster {
        endpoint: endpoint.to_owned(),
        token_id: "root@pam!mcp".to_owned(),
        token_secret_env: None,
        token_secret_file: Some(ca_pem.with_file_name("token.secret")),
        ca_pem_path: Some(ca_pem.to_owned()),
        protected_vmids: vec![905],
        protected_tags: vec!["protected".to_owned()],
    }
}
