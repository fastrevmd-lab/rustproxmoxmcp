//! One MCP server for many Proxmox VE clusters.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cli;
pub mod http_transport;
pub mod server;
