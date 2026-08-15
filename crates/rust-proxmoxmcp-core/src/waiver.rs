//! Time-boxed operator waiver file.
//!
//! An operator with root access to the MCP server host can write a waiver file
//! at a known path. Each waiver entry names a cluster, VMID, expiry timestamp,
//! and reason. When a destructive operation would be refused by the protection
//! system, a matching unexpired waiver allows it to proceed.
//!
//! The waiver file must be mode 0600 and owned by the service user. An absent
//! file is treated as an empty waiver list, not an error.

use chrono::DateTime;
use mecmcp_secret::{FileLimits, SecretError, read_hardened_file};
use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

/// Errors loading or parsing a waiver file.
#[derive(Debug, Error)]
pub enum WaiverError {
    /// Hardened file loader refused the file.
    #[error("waiver file security check failed: {0}")]
    SecurityCheck(#[from] SecretError),
    /// JSON parsing failed.
    #[error("waiver file is not valid json: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// Unsupported version.
    #[error("unsupported waiver file version: {0}")]
    UnsupportedVersion(u32),
    /// RFC 3339 timestamp parsing failed.
    #[error("invalid timestamp in waiver entry: {0}")]
    InvalidTimestamp(String),
}

/// One waiver entry from the file.
#[derive(Debug, Clone)]
pub struct WaiverEntry {
    cluster: String,
    vmid: u32,
    until_unix: u64,
    reason: String,
    ticket: Option<String>,
}

impl WaiverEntry {
    /// The reason for this waiver.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The change ticket, if any.
    #[must_use]
    pub fn ticket(&self) -> Option<&str> {
        self.ticket.as_deref()
    }

    /// The cluster this waiver applies to.
    #[must_use]
    pub fn cluster(&self) -> &str {
        &self.cluster
    }

    /// The VMID this waiver applies to.
    #[must_use]
    pub fn vmid(&self) -> u32 {
        self.vmid
    }

    /// The unix timestamp when this waiver expires.
    #[must_use]
    pub fn until_unix(&self) -> u64 {
        self.until_unix
    }
}

/// The loaded waiver file.
#[derive(Debug)]
pub struct WaiverFile {
    waivers: Vec<WaiverEntry>,
}

/// On-disk representation for deserialization.
#[derive(Debug, Deserialize)]
struct WaiverFileRaw {
    version: u32,
    waivers: Vec<WaiverEntryRaw>,
}

/// On-disk representation of one entry.
#[derive(Debug, Deserialize)]
struct WaiverEntryRaw {
    cluster: String,
    vmid: u32,
    until: String,
    reason: String,
    ticket: Option<String>,
}

impl WaiverFile {
    /// Create an empty waiver file (no waivers active).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            waivers: Vec::new(),
        }
    }

    /// Load a waiver file from disk.
    ///
    /// An absent file returns an empty waiver list. A present file must be mode
    /// 0600, owned by the effective uid, and contain version-1 JSON.
    ///
    /// # Errors
    /// Returns [`WaiverError`] when the file exists but has wrong permissions,
    /// wrong owner, unsupported version, or invalid JSON/timestamps.
    pub fn load(path: &Path) -> Result<Self, WaiverError> {
        // Absent file is empty, not an error.
        if !path.exists() {
            return Ok(Self {
                waivers: Vec::new(),
            });
        }

        // Load through the hardened loader (checks mode 0600, regular file, owner).
        let limits = FileLimits::default();
        let contents_bytes = read_hardened_file(path, limits)?;
        let contents = String::from_utf8_lossy(contents_bytes.expose());
        let raw: WaiverFileRaw = serde_json::from_str(&contents)?;

        // Check version.
        if raw.version != 1 {
            return Err(WaiverError::UnsupportedVersion(raw.version));
        }

        // Parse timestamps.
        let waivers = raw
            .waivers
            .into_iter()
            .map(|entry| {
                let until_dt = DateTime::parse_from_rfc3339(&entry.until)
                    .map_err(|error| WaiverError::InvalidTimestamp(error.to_string()))?;
                let until_unix = until_dt.timestamp() as u64;
                Ok(WaiverEntry {
                    cluster: entry.cluster,
                    vmid: entry.vmid,
                    until_unix,
                    reason: entry.reason,
                    ticket: entry.ticket,
                })
            })
            .collect::<Result<Vec<_>, WaiverError>>()?;

        Ok(Self { waivers })
    }

    /// Find a matching unexpired waiver for the given guest.
    ///
    /// Returns the first matching entry where cluster and VMID match exactly and
    /// `now_unix < until_unix`.
    ///
    /// # Parameters
    /// - `cluster`: exact cluster name
    /// - `vmid`: exact VMID
    /// - `now_unix`: current unix timestamp
    #[must_use]
    pub fn matching(&self, cluster: &str, vmid: u32, now_unix: u64) -> Option<&WaiverEntry> {
        self.waivers.iter().find(|entry| {
            entry.cluster == cluster && entry.vmid == vmid && now_unix < entry.until_unix
        })
    }

    /// Create a waiver file with specific entries.
    ///
    /// This is primarily for testing, but is safe to use in production if
    /// waivers are being sourced from something other than a file.
    #[must_use]
    pub fn with_entries(waivers: Vec<WaiverEntry>) -> Self {
        Self { waivers }
    }
}

impl WaiverEntry {
    /// Create a waiver entry.
    ///
    /// This is primarily for testing, but is safe to use in production if
    /// waivers are being constructed programmatically.
    #[must_use]
    pub fn new(
        cluster: String,
        vmid: u32,
        until_unix: u64,
        reason: String,
        ticket: Option<String>,
    ) -> Self {
        Self {
            cluster,
            vmid,
            until_unix,
            reason,
            ticket,
        }
    }
}
