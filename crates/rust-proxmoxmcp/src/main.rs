//! One MCP server for many Proxmox VE clusters.

mod cli;
mod http_transport;
mod server;

use anyhow::{Context as _, Result};
use cli::ProxmoxCli;
use http_transport::build_http_router;
use mecmcp_auth::TokenStoreFile;
use mecmcp_runtime::cli::{Command, TokenAction, Transport};
use mecmcp_transport::{LimitsConfig, serve_router};
use rmcp::ServiceExt as _;
use rust_proxmoxmcp_core::{
    ProxmoxAction, ProxmoxGrant,
    client::ProxmoxClient,
    inventory::ClusterInventory,
    resolve::GuestIndex,
    selector::Selector,
};
use server::ProxmoxServer;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};

/// Build a vendor grant for token minting when --guests or --actions are given.
///
/// Returns `None` for non-Add operations or when no Proxmox-specific grant fields
/// are present, allowing the caller to pass `None` to preserve grantless tokens.
fn build_token_grant(args: &ProxmoxCli, action: &TokenAction) -> Result<Option<ProxmoxGrant>> {
    // Only Add uses grants; other operations round-trip existing ones untouched.
    if !matches!(action, TokenAction::Add { .. }) {
        return Ok(None);
    }

    // No grant fields given: token will work for cluster-scoped tools only.
    if args.guests.is_empty() {
        eprintln!(
            "Note: This token cannot use guest-addressed tools. \
             Use --guests '*' or a selector (vmid:X, tag:Y, pool:Z) to grant guest access."
        );
        return Ok(None);
    }

    // Validate each selector at mint time. A selector that cannot parse produces
    // a token that silently admits nothing, which an operator cannot diagnose.
    for term in &args.guests {
        Selector::parse(term).map_err(|error| {
            anyhow::anyhow!("invalid --guests selector '{term}': {error}")
        })?;
    }

    // Parse action names. Default is already set by clap to "read".
    let actions: Result<Vec<ProxmoxAction>> = args
        .actions
        .iter()
        .map(|name| match name.as_str() {
            "read" => Ok(ProxmoxAction::Read),
            "low" => Ok(ProxmoxAction::Low),
            "destructive" => Ok(ProxmoxAction::Destructive),
            other => Err(anyhow::anyhow!(
                "invalid --actions value '{other}': must be read, low, or destructive"
            )),
        })
        .collect();

    Ok(Some(ProxmoxGrant {
        guests: args.guests.clone(),
        actions: actions?,
    }))
}

#[tokio::main]
async fn main() -> Result<()> {
    // mecmcp decision D4: the consumer installs the process-global rustls crypto
    // provider, and it must be installed before ANYTHING builds a TLS-capable
    // client. The binary installs it, once, before any client is constructed.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("a rustls crypto provider was already installed"))?;

    let parsed = mecmcp_runtime::cli::parse_with_provenance::<ProxmoxCli>(
        "rust-proxmoxmcp",
        env!("CARGO_PKG_VERSION"),
    );
    let mut args = parsed.cli;

    mecmcp_runtime::cli_validate::validate(&args.common)
        .map_err(|refusal| anyhow::anyhow!("{refusal}"))?;

    init_audit(&args.common)?;

    if let Some(Command::Token { action }) = args.common.command.take() {
        // Token management is deliberately local: it validates against the fixed
        // tool registry and does not load cluster inventory or build clients.
        let grant = build_token_grant(&args, &action)?;
        return mecmcp_runtime::token_cmd::run_with_grant::<ProxmoxGrant>(
            action,
            &[],
            server::KNOWN_TOOLS,
            grant,
        )
        .map_err(|error| anyhow::anyhow!("{error}"));
    }

    let clusters = Arc::new(
        ClusterInventory::load(&args.clusters_file)
            .with_context(|| format!("loading {}", args.clusters_file.display()))?,
    );

    let mut clients = BTreeMap::new();
    for name in clusters.names() {
        let cluster = clusters.get(&name)?;
        clients.insert(
            name.clone(),
            ProxmoxClient::new(cluster).with_context(|| format!("build client for {name}"))?,
        );
    }
    let clients = Arc::new(clients);

    let index = Arc::new(GuestIndex::new(Duration::from_secs(
        clusters.policy().resource_cache_ttl_secs,
    )));

    // SIGHUP reloads the inventory in place. A failed reload leaves the previous
    // contents in effect and logs; it must never take the server down.
    install_sighup_reload(Arc::clone(&clusters), Arc::clone(&index))?;

    match args.common.transport {
        Transport::Stdio => serve_stdio(clusters, clients, index).await,
        Transport::StreamableHttp => {
            let token_store = load_http_token_store(&args.common)?;
            let tls = load_listener_tls(&args.common)?;
            let host = args
                .common
                .host
                .parse::<std::net::IpAddr>()
                .context("invalid --host IP address")?;
            let address = SocketAddr::new(host, args.common.port);
            let shutdown = tokio_util::sync::CancellationToken::new();

            // Install signal handlers
            let signal_shutdown = shutdown.clone();
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                let mut sigterm =
                    signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
                let mut sigint =
                    signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
                tokio::spawn(async move {
                    tokio::select! {
                        _ = sigterm.recv() => {
                            tracing::info!("SIGTERM received");
                        }
                        _ = sigint.recv() => {
                            tracing::info!("SIGINT received");
                        }
                    }
                    signal_shutdown.cancel();
                });
            }
            #[cfg(not(unix))]
            {
                tokio::spawn(async move {
                    tokio::signal::ctrl_c().await.ok();
                    tracing::info!("Ctrl+C received");
                    signal_shutdown.cancel();
                });
            }

            let shutdown_timeout = Duration::from_secs(10);
            serve_http(
                clusters,
                clients,
                index,
                address,
                token_store,
                args.common.allowed_host,
                args.common.allowed_origin,
                LimitsConfig::default(),
                false,
                tls,
                shutdown,
                shutdown_timeout,
            )
            .await
        }
    }
}

fn init_audit(args: &mecmcp_runtime::cli::Cli) -> Result<()> {
    let redaction = if args.audit_redact.trim().is_empty() {
        None
    } else {
        Some(
            mecmcp_audit::AuditRedaction::parse(
                &args.audit_redact,
                args.audit_hmac_key_file.as_deref(),
            )
            .map_err(|error| anyhow::anyhow!("invalid --audit-redact: {error}"))?,
        )
    };
    mecmcp_audit::init_tracing(&mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
        journald: args.audit_journald,
    })
    .context("initializing audit tracing")?;
    mecmcp_audit::install_duration_metric_name("rust_proxmoxmcp_tool_duration_seconds");
    Ok(())
}

async fn serve_stdio(
    clusters: Arc<ClusterInventory>,
    clients: Arc<BTreeMap<String, ProxmoxClient>>,
    index: Arc<GuestIndex>,
) -> Result<()> {
    let handler = ProxmoxServer::new(clusters, clients, index);
    let service = handler
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await
        .context("starting MCP stdio service")?;
    service
        .waiting()
        .await
        .map(|_| ())
        .context("MCP stdio service exited with error")
}

fn load_http_token_store(
    args: &mecmcp_runtime::cli::Cli,
) -> Result<Option<Arc<TokenStoreFile<ProxmoxGrant>>>> {
    match (&args.tokens_file, args.allow_no_auth) {
        (Some(path), false) => {
            let store = Arc::new(
                TokenStoreFile::<ProxmoxGrant>::load(path)
                    .with_context(|| format!("loading {}", path.display()))?,
            );
            tracing::info!(tokens = store.store().len(), "token store loaded");
            Ok(Some(store))
        }
        (None, true) => {
            tracing::warn!(
                "--allow-no-auth: Streamable HTTP accepts ordinary read requests \
                 without authentication on loopback; write tools remain denied"
            );
            Ok(None)
        }
        (Some(_), true) => {
            Err(anyhow::anyhow!(
                "contradictory flags: both --tokens-file and --allow-no-auth were given"
            ))
        }
        (None, false) => {
            Err(anyhow::anyhow!(
                "Streamable HTTP requires either --tokens-file or --allow-no-auth"
            ))
        }
    }
}

fn load_listener_tls(
    args: &mecmcp_runtime::cli::Cli,
) -> Result<Option<Arc<rustls::ServerConfig>>> {
    let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) else {
        return Ok(None);
    };
    // The process-global provider is installed in `main`; do not install again —
    // `install_default` returns Err when one is already set, and treating that
    // as fatal would break every TLS start.
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    mecmcp_transport::load_tls(cert, key, Arc::new(provider))
        .context("loading listener TLS")
        .map(Some)
}

fn install_sighup_reload(
    clusters: Arc<ClusterInventory>,
    index: Arc<GuestIndex>,
) -> std::io::Result<()> {
    mecmcp_runtime::signals::install_hup_handler(move || {
        match clusters.reload() {
            Ok(count) => {
                index.invalidate();
                tracing::info!(clusters = count, "cluster inventory reloaded");
            }
            Err(error) => {
                tracing::error!(%error, "cluster inventory reload failed; retaining previous snapshot");
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn serve_http(
    clusters: Arc<ClusterInventory>,
    clients: Arc<BTreeMap<String, ProxmoxClient>>,
    index: Arc<GuestIndex>,
    address: SocketAddr,
    token_store: Option<Arc<TokenStoreFile<ProxmoxGrant>>>,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    limits: LimitsConfig,
    enable_metrics: bool,
    tls: Option<Arc<rustls::ServerConfig>>,
    shutdown: tokio_util::sync::CancellationToken,
    shutdown_timeout: Duration,
) -> Result<()> {
    let handler = ProxmoxServer::new(clusters, clients, index);
    let (router, shutdown_token) = build_http_router(
        handler,
        token_store,
        allowed_hosts,
        allowed_origins,
        limits,
        enable_metrics,
        shutdown,
    )
    .map_err(|error| anyhow::anyhow!("building HTTP router: {error}"))?;

    serve_router(router, address, tls, shutdown_token, shutdown_timeout)
        .await
        .map_err(anyhow::Error::from)
}
