//! Command-line surface.
//!
//! `mecmcp_runtime::cli::Cli` is flattened rather than reimplemented, so every
//! shared flag — transport, bind, TLS, allowed hosts, audit — behaves exactly as
//! it does on the sibling servers.
//!
//! Release 0.3 adds `--lab-mode` and `--waivers-file` for the two-person control
//! override system (spec §4.2). These flags are spelled identically on every
//! mecmcp server.
//!
//! Token management is intercepted before parsing to prevent grant flags
//! (`--guests`, `--actions`) from appearing in the server's help. See
//! [`TokenCli`] and the dispatch logic in `main.rs`.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// `rust-proxmoxmcp` command line.
#[derive(Debug, Parser)]
#[command(name = "rust-proxmoxmcp", version)]
pub struct ProxmoxCli {
    /// Flags shared with the rest of the mechub MCP family.
    #[command(flatten)]
    pub common: mecmcp_runtime::cli::Cli,

    /// Cluster inventory. Must be mode 0600 and owned by the service user.
    #[arg(long, default_value = "/etc/proxmoxmcp/clusters.json")]
    pub clusters_file: PathBuf,

    /// Run without two-person control for destructive operations.
    ///
    /// For a single-operator lab. No approver is invented: a waived change set
    /// records `approver: null` with a lab-mode waiver, so it stays
    /// distinguishable from one a second person reviewed.
    ///
    /// Spelled identically on every mecmcp server.
    #[arg(long = "lab-mode")]
    pub lab_mode: bool,

    /// Time-boxed operator waivers (spec §4.2). Mode 0600, service-owned.
    #[arg(long = "waivers-file", default_value = "/etc/proxmoxmcp/waivers.json")]
    pub waivers_file: PathBuf,
}

/// Token management CLI, parsed only when argv starts with `token`.
///
/// This is dispatched before `ProxmoxCli` to keep grant-specific flags
/// (`--guests`, `--actions`) off the server's help text. They apply only to
/// token operations, not the server, so showing them as top-level flags would
/// violate the principle that "a flag that is present but ignored is worse than
/// one that is absent."
#[derive(Debug, Parser)]
#[command(name = "rust-proxmoxmcp", version)]
pub struct TokenCli {
    /// Token subcommand (add, revoke, list, rotate).
    #[command(subcommand)]
    pub command: TokenCommand,
}

/// Token subcommands.
#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Mint a new token and append to the file.
    Add {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Stable audit name for the token.
        #[arg(long)]
        name: String,
        /// Comma-separated device names, or '*' for all.
        #[arg(long, value_delimiter = ',')]
        devices: Vec<String>,
        /// Comma-separated tool names, or '*' for all.
        #[arg(long, value_delimiter = ',')]
        tools: Vec<String>,
        /// Guest selectors for token grant (comma-separated).
        ///
        /// A token carrying no guest grant cannot call guest-addressed tools.
        /// Use '*' for all guests, or selectors like 'vmid:600-699', 'tag:ci',
        /// 'pool:lab'.
        #[arg(long, value_delimiter = ',')]
        guests: Vec<String>,
        /// Actions this token may invoke (comma-separated).
        ///
        /// Valid actions: read, low, destructive. Default: read.
        #[arg(long, value_delimiter = ',', default_value = "read")]
        actions: Vec<String>,
        /// Provider name (e.g., "anthropic", "ollama"). Optional.
        #[arg(long)]
        provider: Option<String>,
        /// Provider tier: "public" or "private". Required if provider is set.
        #[arg(long)]
        provider_tier: Option<String>,
        /// The human on whose behalf this credential acts. Optional.
        #[arg(long)]
        on_behalf_of: Option<String>,
        /// Actor type: "human", "agent", or "unknown". Optional.
        #[arg(long)]
        actor_type: Option<String>,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Revoke a token by name.
    Revoke {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token name to revoke.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// List all tokens in the store.
    List {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
    },
    /// Rotate a token's secret, preserving its grant.
    Rotate {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token name to rotate.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Change an existing token's scopes without reissuing its secret.
    ///
    /// The alternatives all mint a new secret: `rotate` preserves scopes and
    /// changes the secret — the exact inverse of what is wanted — and
    /// `revoke`+`add` does the same. Hand-editing `tokens.json` keeps the
    /// secret but skips every validation this path performs.
    ///
    /// Note that `--tools '*'` does not reach a mutating tool: `WRITE_TOOLS`
    /// is deliberately excluded from the tool wildcard, so `start_vm` and its
    /// peers must be named explicitly or the preflight refuses the call with
    /// `403 insufficient_scope`.
    SetScopes {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Replacement device scope. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        devices: Option<Vec<String>>,
        /// Replacement tool scope. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        tools: Option<Vec<String>>,
        /// Replacement guest selectors ('*', 'vmid:600-699', 'tag:ci', ...).
        ///
        /// Replaced wholesale, not merged: naming one selector drops the
        /// others. Merging would make it impossible to *remove* a selector
        /// through this command, and a guest grant is a scope where "I meant
        /// to replace it" must not silently mean "I added to it".
        ///
        /// Omit both this and --actions to leave the grant unchanged.
        #[arg(long, value_delimiter = ',')]
        guests: Option<Vec<String>>,
        /// Replacement actions (read, low, destructive). Replaced wholesale.
        ///
        /// Only meaningful together with --guests, because a grant carries
        /// both; passing --actions alone is refused rather than silently
        /// inventing a guest selector.
        #[arg(long, value_delimiter = ',')]
        actions: Option<Vec<String>>,
        /// Apply a widening without the interactive confirmation.
        #[arg(long)]
        yes: bool,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_mode_flag_is_observable_when_passed() {
        let cli = ProxmoxCli::parse_from(["rust-proxmoxmcp", "--lab-mode"]);
        assert!(
            cli.lab_mode,
            "a flag that parses but never converts is the defect that took a sibling server down"
        );
    }

    #[test]
    fn lab_mode_defaults_to_false() {
        let cli = ProxmoxCli::parse_from(["rust-proxmoxmcp"]);
        assert!(!cli.lab_mode, "the default must be false");
    }

    #[test]
    fn set_scopes_leaves_omitted_scopes_unchanged() {
        let cli = TokenCli::parse_from([
            "token",
            "set-scopes",
            "--tokens-file",
            "/etc/proxmoxmcp/tokens.json",
            "--name",
            "claude-proxmox",
            "--tools",
            "get_nodes,get_vms",
        ]);
        let TokenCommand::SetScopes {
            devices,
            tools,
            guests,
            actions,
            yes,
            ..
        } = cli.command
        else {
            panic!("expected SetScopes");
        };
        assert_eq!(devices, None, "an omitted scope must stay unchanged");
        assert_eq!(
            tools,
            Some(vec!["get_nodes".to_owned(), "get_vms".to_owned()])
        );
        assert_eq!(guests, None);
        assert_eq!(actions, None);
        assert!(!yes, "a widening is confirmed unless --yes is passed");
    }

    #[test]
    fn set_scopes_parses_the_grant_halves() {
        let cli = TokenCli::parse_from([
            "token",
            "set-scopes",
            "--tokens-file",
            "/etc/proxmoxmcp/tokens.json",
            "--name",
            "claude-proxmox",
            "--guests",
            "vmid:600-699,tag:ci",
            "--actions",
            "read,low",
            "--yes",
        ]);
        let TokenCommand::SetScopes {
            guests,
            actions,
            yes,
            ..
        } = cli.command
        else {
            panic!("expected SetScopes");
        };
        assert_eq!(
            guests,
            Some(vec!["vmid:600-699".to_owned(), "tag:ci".to_owned()])
        );
        assert_eq!(actions, Some(vec!["read".to_owned(), "low".to_owned()]));
        assert!(yes);
    }
}
