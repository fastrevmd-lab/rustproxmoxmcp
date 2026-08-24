//! One MCP server for many Proxmox VE clusters.

mod cli;
mod http_transport;
mod server;

use anyhow::{Context as _, Result};
use cli::{ProxmoxCli, TokenCli, TokenCommand};
use http_transport::build_http_router;
use mecmcp_auth::TokenStoreFile;
use mecmcp_runtime::cli::{Command, TokenAction, Transport};
use mecmcp_transport::{LimitsConfig, serve_router};
use rmcp::ServiceExt as _;
use rust_proxmoxmcp_core::{
    ProxmoxAction, ProxmoxGrant, client::ProxmoxClient, inventory::ClusterInventory,
    resolve::GuestIndex, selector::Selector,
};
use server::ProxmoxServer;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};

/// Build a vendor grant from TokenCommand::Add fields.
///
/// Returns `None` when no guest selectors are given, allowing cluster-scoped
/// tokens. Validates selectors at mint time and prints a note when omitted.
fn build_token_grant_from_add(
    guests: &[String],
    actions: &[String],
) -> Result<Option<ProxmoxGrant>> {
    // No grant fields given: token will work for cluster-scoped tools only.
    if guests.is_empty() {
        eprintln!(
            "Note: This token cannot use guest-addressed tools. \
             Use --guests '*' or a selector (vmid:X, tag:Y, pool:Z) to grant guest access."
        );
        return Ok(None);
    }

    // Validate each selector at mint time. A selector that cannot parse produces
    // a token that silently admits nothing, which an operator cannot diagnose.
    for term in guests {
        Selector::parse(term)
            .map_err(|error| anyhow::anyhow!("invalid --guests selector '{term}': {error}"))?;
    }

    // Parse action names.
    let parsed_actions: Result<Vec<ProxmoxAction>> = actions
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
        guests: guests.to_vec(),
        actions: parsed_actions?,
    }))
}

/// Convert `TokenCommand` to `TokenAction` and extract grant for Add.
fn token_command_to_action(command: TokenCommand) -> Result<(TokenAction, Option<ProxmoxGrant>)> {
    match command {
        TokenCommand::Add {
            tokens_file,
            name,
            devices,
            tools,
            guests,
            actions,
            provider,
            provider_tier,
            on_behalf_of,
            actor_type,
            server_pid,
        } => {
            let grant = build_token_grant_from_add(&guests, &actions)?;
            let action = TokenAction::Add {
                tokens_file,
                name,
                devices,
                tools,
                provider,
                provider_tier,
                on_behalf_of,
                actor_type,
                server_pid,
            };
            Ok((action, grant))
        }
        TokenCommand::Revoke {
            tokens_file,
            name,
            server_pid,
        } => Ok((
            TokenAction::Revoke {
                tokens_file,
                name,
                server_pid,
            },
            None,
        )),
        TokenCommand::List { tokens_file } => Ok((TokenAction::List { tokens_file }, None)),
        TokenCommand::Rotate {
            tokens_file,
            name,
            server_pid,
        } => Ok((
            TokenAction::Rotate {
                tokens_file,
                name,
                server_pid,
            },
            None,
        )),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // mecmcp decision D4: the consumer installs the process-global rustls crypto
    // provider, and it must be installed before ANYTHING builds a TLS-capable
    // client. The binary installs it, once, before any client is constructed.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("a rustls crypto provider was already installed"))?;

    // Dispatch token commands before parsing ProxmoxCli.
    //
    // This keeps grant-specific flags (--guests, --actions) off the server's help
    // and allows them to appear after the subcommand where they belong. The
    // flattened Cli still declares its own `token` subcommand, but TokenCli owns
    // the complete token surface including --help when argv names `token`.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("token") {
        use clap::Parser;
        // Build args for TokenCli: [program_name, add/revoke/list/rotate, ...]
        // Skip "token" at index 1 since TokenCli expects the subcommand directly.
        let token_args = std::iter::once(args[0].clone())
            .chain(args.iter().skip(2).cloned())
            .collect::<Vec<_>>();
        let token_cli = TokenCli::parse_from(token_args);
        let (action, grant) = token_command_to_action(token_cli.command)?;
        return mecmcp_runtime::token_cmd::run_with_grant::<ProxmoxGrant>(
            action,
            &[],
            server::KNOWN_TOOLS,
            grant,
        )
        .map_err(|error| anyhow::anyhow!("{error}"));
    }

    let parsed = mecmcp_runtime::cli::parse_with_provenance::<ProxmoxCli>(
        "rust-proxmoxmcp",
        env!("CARGO_PKG_VERSION"),
    );
    let mut args = parsed.cli;

    mecmcp_runtime::cli_validate::validate(&args.common)
        .map_err(|refusal| anyhow::anyhow!("{refusal}"))?;

    init_audit(&args.common)?;

    if let Some(Command::Token { .. }) = args.common.command.take() {
        // This path fires when a server flag precedes the subcommand
        // (e.g., `--clusters-file X token add ...`). The early dispatch at argv[1]
        // does not intercept it, so TokenCli's grant-specific flags (--guests,
        // --actions) are unavailable. Refuse rather than silently minting a
        // grantless token.
        return Err(anyhow::anyhow!(
            "token subcommand must appear before server flags; use: \
             rust-proxmoxmcp token add [options]"
        ));
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

    let waivers = Arc::new(
        rust_proxmoxmcp_core::waiver::WaiverFile::load(&args.waivers_file)
            .with_context(|| format!("loading {}", args.waivers_file.display()))?,
    );

    // Built before serving because the coordinator takes the recorder, and
    // started eagerly so a misconfiguration stops the server here rather than
    // at the first change.
    let evidence = match args.common.evidence.into_config() {
        Ok(Some(config)) => {
            tracing::info!(
                server_id = %config.server_id,
                run_id = %config.run_id,
                "SSDF evidence pipeline enabled"
            );
            // aws-lc-rs, not ring: this server's rustls is built with that
            // provider (workspace Cargo.toml), and the fleet is genuinely split.
            // Taking the provider as a parameter rather than hardcoding one in
            // mecmcp-audit is what lets both halves use the same transport.
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let transport = Arc::new(
                mecmcp_transport::evidence_transport::EvidenceHttpTransport::new(
                    args.common.evidence.ca_file(),
                    provider,
                )
                .context("building the SSDF evidence transport")?,
            );
            Some(
                mecmcp_audit::EvidenceService::start_with_transport(config, transport)
                    .context("starting the SSDF evidence pipeline")?,
            )
        }
        Ok(None) => None,
        Err(error) => anyhow::bail!("SSDF evidence configuration: {error}"),
    };
    let recorder = evidence
        .as_ref()
        .map(mecmcp_audit::EvidenceService::recorder);

    let served = match args.common.transport {
        Transport::Stdio => {
            // SIGHUP reloads the inventory in place. Stdio has no token store.
            install_sighup_reload(Arc::clone(&clusters), Arc::clone(&index), None)?;
            serve_stdio(clusters, clients, index, waivers, args.lab_mode, recorder).await
        }
        Transport::StreamableHttp => {
            let token_store = load_http_token_store(&args.common)?;

            // Check for stale secrets (superseded token files, old TLS keys) in both
            // /var/lib/proxmoxmcp and /etc/proxmoxmcp. Warn, never refuse.
            let live_files = ["tokens.json"];
            for dir in [
                std::path::Path::new("/var/lib/proxmoxmcp"),
                std::path::Path::new("/etc/proxmoxmcp"),
            ] {
                let stale = mecmcp_auth::find_stale_secrets(dir, &live_files);
                for secret in stale {
                    tracing::warn!(
                        path = %secret.path.display(),
                        reason = ?secret.reason,
                        "Stale secret file detected. Consider removing after verifying it is no longer referenced."
                    );
                }
            }

            // Install SIGHUP handler that reloads both inventory and token store.
            install_sighup_reload(
                Arc::clone(&clusters),
                Arc::clone(&index),
                token_store.clone(),
            )?;

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
                args.common.allow_insecure_bind,
                tls,
                shutdown,
                shutdown_timeout,
                waivers,
                args.lab_mode,
                recorder,
            )
            .await
        }
    };

    // Deliver what is still spooled, whichever way serving ended. Bound rather
    // than returned directly so the flush runs on the error path too -- which
    // is exactly when an unshipped trail matters most.
    if let Some(service) = evidence
        && let Err(error) = service.shutdown()
    {
        tracing::error!(%error, "the SSDF evidence pipeline did not flush cleanly");
    }

    served
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
    waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
    lab_mode: bool,
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
) -> Result<()> {
    let handler = ProxmoxServer::new_with_default_coordinator(
        clusters, clients, index, waivers, lab_mode, evidence,
    )
    .context("build server")?;

    if lab_mode {
        tracing::warn!(
            target: "audit",
            "lab mode enabled: change sets for protected guests are approved on creation \
             with no second principal. Records carry approval_waiver=lab-mode. \
             Do not run this against production devices."
        );
    }

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
            // The CONFIGURED path is the primary; /etc is the legacy fallback, so an
            // upgrade whose tokens have not been moved yet still starts.
            //
            // Do NOT discard the CLI value and resolve between two hardcoded paths.
            // An operator who passes `--tokens-file /some/other.json` would then be
            // silently served a different file — a misconfiguration that looks like
            // success, which is worse than refusing.
            use std::path::Path;
            const LEGACY_TOKENS: &str = "/etc/proxmoxmcp/tokens.json";
            let fallback = Path::new(LEGACY_TOKENS);
            let resolved = mecmcp_auth::resolve_token_path(path, fallback)
                .with_context(|| "resolving token file path")?;

            if let (true, Some(fallback_from)) = (resolved.used_fallback, &resolved.fallback_from) {
                tracing::warn!(
                    path = %resolved.path.display(),
                    fallback_from = %fallback_from.display(),
                    "Using fallback token file (primary does not exist). \
                     Token operations (add, revoke, rotate) will fail under ProtectSystem=strict. \
                     Move to /var/lib/proxmoxmcp/tokens.json to restore write capability."
                );
            }

            let store = Arc::new(
                TokenStoreFile::<ProxmoxGrant>::load(&resolved.path)
                    .with_context(|| format!("loading {}", resolved.path.display()))?,
            );
            tracing::info!(
                path = %resolved.path.display(),
                tokens = store.store().len(),
                "token store loaded"
            );
            Ok(Some(store))
        }
        (None, true) => {
            tracing::warn!(
                "--allow-no-auth: Streamable HTTP accepts ordinary read requests \
                 without authentication on loopback; write tools remain denied"
            );
            Ok(None)
        }
        (Some(_), true) => Err(anyhow::anyhow!(
            "contradictory flags: both --tokens-file and --allow-no-auth were given"
        )),
        (None, false) => Err(anyhow::anyhow!(
            "Streamable HTTP requires either --tokens-file or --allow-no-auth"
        )),
    }
}

fn load_listener_tls(args: &mecmcp_runtime::cli::Cli) -> Result<Option<Arc<rustls::ServerConfig>>> {
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
    token_store: Option<Arc<TokenStoreFile<ProxmoxGrant>>>,
) -> std::io::Result<()> {
    mecmcp_runtime::signals::install_hup_handler(move || {
        // Reload cluster inventory.
        match clusters.reload() {
            Ok(count) => {
                index.invalidate();
                tracing::info!(clusters = count, "cluster inventory reloaded");
            }
            Err(error) => {
                tracing::error!(%error, "cluster inventory reload failed; retaining previous snapshot");
            }
        }

        // Reload token store if present (HTTP mode only).
        if let Some(ref store) = token_store {
            match store.reload() {
                Ok(()) => {
                    let count = store.store().len();
                    tracing::info!(tokens = count, "token store reloaded");
                }
                Err(error) => {
                    tracing::error!(%error, "token store reload failed; retaining previous snapshot");
                }
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
    allow_insecure_bind: bool,
    tls: Option<Arc<rustls::ServerConfig>>,
    shutdown: tokio_util::sync::CancellationToken,
    shutdown_timeout: Duration,
    waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
    lab_mode: bool,
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
) -> Result<()> {
    let handler = ProxmoxServer::new_with_default_coordinator(
        clusters, clients, index, waivers, lab_mode, evidence,
    )
    .context("build server")?;

    if lab_mode {
        tracing::warn!(
            target: "audit",
            "lab mode enabled: change sets for protected guests are approved on creation \
             with no second principal. Records carry approval_waiver=lab-mode. \
             Do not run this against production devices."
        );
    }

    let plan = build_http_router(
        handler,
        token_store,
        allowed_hosts,
        allowed_origins,
        limits,
        enable_metrics,
        allow_insecure_bind,
        shutdown,
    )
    .map_err(|error| anyhow::anyhow!("building HTTP router: {error}"))?;

    serve_router(plan, address, tls, shutdown_timeout)
        .await
        .map_err(anyhow::Error::from)
}
