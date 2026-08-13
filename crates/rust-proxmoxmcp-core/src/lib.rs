//! Proxmox VE domain logic for `rust-proxmoxmcp`.
//!
//! This crate holds everything vendor-shaped and nothing MCP-shaped: cluster
//! inventory, guest resolution, the authorization spine, and the read catalog.
//! The binary crate owns transport, tool registration, and CLI.
//!
//! # The authorization spine
//!
//! Proxmox has no candidate configuration, so change control keys on the
//! identity of the target rather than on a config diff. Every mutating API in
//! this crate takes an `AuthorizedGuest`, a type with no public constructor
//! produced only by `resolve::authorize`. A caller that skips authorization
//! does not compile.

pub mod authorized;
pub mod catalog;
pub mod client;
pub mod error;
pub mod grant;
pub mod inventory;
pub mod protect;
pub mod resolve;
pub mod selector;
pub mod tier;

pub use error::ProxmoxError;
pub use inventory::{Cluster, ClusterInventory, ClusterPolicy};
pub use selector::{GuestType, Selector};
