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

/// Resolve the token file path, applying the legacy fallback ONLY when the
/// configured path is the canonical /var/lib/proxmoxmcp/tokens.json.
///
/// Any other configured path is used verbatim and fails if absent — that is the
/// honest outcome. This prevents a typo or deliberately deleted custom store from
/// silently reactivating unrelated or revoked credentials at the legacy path.
fn resolve_tokens(configured: &std::path::Path) -> Result<mecmcp_auth::ResolvedTokenPath> {
    resolve_tokens_with(
        configured,
        std::path::Path::new("/var/lib/proxmoxmcp/tokens.json"),
        std::path::Path::new("/etc/proxmoxmcp/tokens.json"),
    )
}

/// The rule behind [`resolve_tokens`], with the two well-known paths injected so
/// it can be exercised against real files in a test rather than against absolute
/// paths that never exist there.
fn resolve_tokens_with(
    configured: &std::path::Path,
    canonical: &std::path::Path,
    legacy: &std::path::Path,
) -> Result<mecmcp_auth::ResolvedTokenPath> {
    // Byte-exact, not `Path` equality. `Path` comparison normalizes away trailing
    // separators and `.` components, so `/var/lib/<svc>/tokens.json/` compares
    // EQUAL to the canonical path — while `metadata()` on that spelling returns
    // NotFound when the file is absent, indistinguishable from the plain form.
    // A typo would therefore pass this gate and activate the legacy store, which
    // is exactly the fail-closed behaviour this check exists to provide.
    if configured.as_os_str() != canonical.as_os_str() {
        return Ok(mecmcp_auth::ResolvedTokenPath {
            path: configured.to_path_buf(),
            used_fallback: false,
            fallback_from: None,
        });
    }

    mecmcp_auth::resolve_token_path(configured, legacy).context("resolving token file path")
}

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

/// Build a replacement vendor grant for `TokenCommand::SetScopes`.
///
/// Returns `None` when neither `--guests` nor `--actions` is given, which
/// leaves the existing grant untouched. `--actions` alone is refused: a grant
/// carries both halves, and inventing a guest selector to satisfy the other
/// half would grant reach the operator never named.
fn build_token_grant_from_set_scopes(
    guests: Option<&Vec<String>>,
    actions: Option<&Vec<String>>,
) -> Result<Option<ProxmoxGrant>> {
    match (guests, actions) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(anyhow::anyhow!(
            "--actions requires --guests: a grant carries both, and this command \
             replaces it wholesale rather than merging"
        )),
        (Some(guests), actions) => {
            // Default to read when actions are omitted, matching `add`. An
            // omitted action list must not silently preserve a destructive
            // grant the operator is replacing.
            let actions = actions.cloned().unwrap_or_else(|| vec!["read".to_owned()]);
            build_token_grant_from_add(guests, &actions)
        }
    }
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
        TokenCommand::SetScopes {
            tokens_file,
            name,
            devices,
            tools,
            guests,
            actions,
            yes,
            server_pid,
        } => {
            let grant = build_token_grant_from_set_scopes(guests.as_ref(), actions.as_ref())?;
            Ok((
                TokenAction::SetScopes {
                    tokens_file,
                    name,
                    devices,
                    tools,
                    yes,
                    server_pid,
                },
                grant,
            ))
        }
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

        // Install a subscriber before dispatching. `run_with_grant` emits the
        // scope change as a `target: "audit"` event, and this path returns
        // long before the server's `init_audit`, so without one every token
        // mutation — a mint, a revoke, a privilege widening — is written to
        // disk having left no record that it happened.
        //
        // Deliberately minimal: the token CLI carries no audit flags, so there
        // is no log file, journald sink, or redaction policy to honour. The
        // operator running the command is the audience, and stderr is where
        // they are looking.
        init_token_audit();

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

/// Install a stderr subscriber for the standalone token command path.
///
/// Separate from [`init_audit`] because the token CLI has no audit flags to
/// read: there is no log file, journald sink, or redaction policy on this
/// path, only an operator at a terminal. Failure is ignored because a
/// subscriber already installed is not an error worth refusing a token
/// operation over.
fn init_token_audit() {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    // `audit=info` is added on top of whatever RUST_LOG says, rather than
    // relying on the default filter.
    //
    // `mecmcp_audit::init_tracing` builds its filter with
    // `EnvFilter::try_from_default_env()`, so a target-specific RUST_LOG such
    // as `rust_proxmoxmcp=debug` produces a filter that does not enable the
    // `audit` target at all. Measured: with that value set, `set-scopes --yes`
    // widened the token and printed nothing. A privilege escalation that an
    // environment variable can silence is not audited.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        .add_directive(
            "audit=info"
                .parse()
                .expect("a static directive always parses"),
        );

    // `try_init`, not `init`: a subscriber already installed is not a reason
    // to refuse a token operation.
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .try_init();
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
            // Apply the legacy /etc fallback ONLY when the configured path is the
            // canonical /var/lib/proxmoxmcp/tokens.json. A typo or deliberately
            // deleted custom store must fail, not silently reactivate credentials
            // from /etc. The resolve_tokens wrapper enforces that restriction.
            let resolved = resolve_tokens(path)?;

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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod token_path_tests {
    use super::resolve_tokens_with;

    /// The canonical path is absent and the legacy store exists: the fallback
    /// must fire, so an upgrade that has not migrated yet still starts.
    #[test]
    fn canonical_path_falls_back_to_an_existing_legacy_store() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");
        std::fs::write(&legacy, "{}").unwrap();

        let resolved = resolve_tokens_with(&canonical, &canonical, &legacy).unwrap();
        assert_eq!(
            resolved.path, legacy,
            "the legacy store should have been used"
        );
        assert!(resolved.used_fallback);
    }

    /// The same legacy store exists, but the operator configured a DIFFERENT
    /// path. Falling back here would silently reactivate credentials they did
    /// not ask for — a typo or a deleted store must fail, not resurrect tokens.
    #[test]
    fn a_custom_path_never_falls_back_to_the_legacy_store() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");
        std::fs::write(&legacy, "{}").unwrap();
        let custom = dir.path().join("operator-chosen.json");

        let resolved = resolve_tokens_with(&custom, &canonical, &legacy).unwrap();
        assert_eq!(
            resolved.path, custom,
            "an operator-supplied path must be used verbatim"
        );
        assert!(
            !resolved.used_fallback,
            "a custom path must never resolve to the legacy /etc store"
        );
    }

    /// A malformed spelling of the canonical path must NOT reach the fallback.
    ///
    /// `Path` equality normalizes away a trailing separator, so
    /// `.../tokens.json/` compares equal to the canonical path; and when the
    /// file is absent `metadata()` returns NotFound for that spelling too,
    /// indistinguishable from the plain form. A typo would therefore activate
    /// the legacy store — the opposite of fail-closed. The comparison is
    /// byte-exact for this reason.
    #[test]
    fn a_trailing_slash_spelling_does_not_reach_the_legacy_store() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");
        std::fs::write(&legacy, "{}").unwrap();

        let mut malformed = canonical.clone().into_os_string();
        malformed.push("/");
        let malformed = std::path::PathBuf::from(malformed);

        let resolved = resolve_tokens_with(&malformed, &canonical, &legacy).unwrap();
        assert!(
            !resolved.used_fallback,
            "a trailing-slash spelling must not activate the legacy store"
        );
        assert_eq!(
            resolved.path, malformed,
            "the given path must be used verbatim"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod set_scopes_grant_tests {
    use super::build_token_grant_from_set_scopes;
    use rust_proxmoxmcp_core::ProxmoxAction;

    /// Neither half given: the existing grant is left alone. `set-scopes` is
    /// for changing what an operator names, not for clearing what they did not.
    #[test]
    fn neither_half_leaves_the_grant_unchanged() {
        let grant = build_token_grant_from_set_scopes(None, None).unwrap();
        assert!(grant.is_none(), "an untouched grant must be None");
    }

    /// A grant carries guests *and* actions. Accepting actions alone would
    /// force this code to invent a guest selector, granting reach the operator
    /// never named.
    #[test]
    fn actions_without_guests_is_refused() {
        let error = build_token_grant_from_set_scopes(None, Some(&vec!["destructive".to_owned()]))
            .expect_err("--actions alone must be refused");
        assert!(
            error.to_string().contains("--actions requires --guests"),
            "the refusal must name the missing flag, got: {error}"
        );
    }

    /// Omitting actions defaults to read, matching `add`. It must not preserve
    /// whatever the token held before: the grant is replaced wholesale, so a
    /// silent carry-over would keep a destructive action through a call the
    /// operator believed was narrowing.
    #[test]
    fn guests_without_actions_defaults_to_read() {
        let grant = build_token_grant_from_set_scopes(Some(&vec!["*".to_owned()]), None)
            .unwrap()
            .expect("naming guests builds a grant");
        assert_eq!(grant.actions, vec![ProxmoxAction::Read]);
        assert_eq!(grant.guests, vec!["*".to_owned()]);
    }

    /// An unparseable selector is caught at the CLI, not left to produce a
    /// token that silently admits nothing.
    #[test]
    fn an_invalid_selector_is_refused() {
        let error = build_token_grant_from_set_scopes(Some(&vec!["nonsense:zzz".to_owned()]), None)
            .expect_err("an invalid selector must be refused");
        assert!(
            error.to_string().contains("invalid --guests selector"),
            "got: {error}"
        );
    }

    /// Every action name round-trips, including the one that matters most.
    #[test]
    fn destructive_is_accepted_when_named() {
        let grant = build_token_grant_from_set_scopes(
            Some(&vec!["*".to_owned()]),
            Some(&vec![
                "read".to_owned(),
                "low".to_owned(),
                "destructive".to_owned(),
            ]),
        )
        .unwrap()
        .expect("grant");
        assert_eq!(
            grant.actions,
            vec![
                ProxmoxAction::Read,
                ProxmoxAction::Low,
                ProxmoxAction::Destructive
            ]
        );
    }
}
