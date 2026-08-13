//! Command-line surface.
//!
//! `mecmcp_runtime::cli::Cli` is flattened rather than reimplemented, so every
//! shared flag — transport, bind, TLS, allowed hosts, audit — behaves exactly as
//! it does on the sibling servers.
//!
//! Release 0.1 adds exactly one flag. `--lab-mode` and `--waivers-file` belong
//! to 0.3 and are deliberately absent: a flag that is present but ignored is
//! worse than one that is absent, because the operator cannot tell.

use clap::Parser;
use mecmcp_runtime::cli::Cli;
use std::path::PathBuf;

/// `rust-proxmoxmcp` command line.
#[derive(Debug, Parser)]
#[command(name = "rust-proxmoxmcp", version)]
pub struct ProxmoxCli {
    /// Flags shared with the rest of the mechub MCP family.
    #[command(flatten)]
    pub common: Cli,

    /// Cluster inventory. Must be mode 0600 and owned by the service user.
    #[arg(long, default_value = "/etc/proxmoxmcp/clusters.json")]
    pub clusters_file: PathBuf,
}
