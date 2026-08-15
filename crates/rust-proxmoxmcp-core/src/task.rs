//! Proxmox VE task tracking types.
//!
//! Most Proxmox mutations return a UPID and complete in the background. This
//! module provides types for parsing the UPID and classifying task outcomes.

/// A parsed Proxmox UPID.
///
/// UPID format (spec §8):
/// `UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:`
///
/// The node is authoritative: guests migrate (spec §7), and polling must
/// follow the UPID's node, never a caller-supplied one. Two 2026-08-12
/// renumbers were cross-node moves (114→907, 900→908, both pve3→pve2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upid {
    node: String,
    kind: String,
    id: String,
}

impl Upid {
    /// Parse a UPID string.
    ///
    /// # Errors
    ///
    /// Returns [`TaskError::MalformedUpid`] if the input does not have the
    /// expected format: literal `UPID` prefix, followed by at least eight
    /// colon-separated fields.
    pub fn parse(upid: &str) -> Result<Self, TaskError> {
        let parts: Vec<&str> = upid.split(':').collect();

        // Require literal UPID prefix plus at least 8 fields total (9 parts)
        // Format: UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:
        if parts.len() < 9 || parts[0] != "UPID" {
            return Err(TaskError::MalformedUpid(upid.to_owned()));
        }

        // Reject empty fields in critical positions
        if parts[1].is_empty() || parts[5].is_empty() || parts[6].is_empty() {
            return Err(TaskError::MalformedUpid(upid.to_owned()));
        }

        Ok(Self {
            node: parts[1].to_owned(),
            kind: parts[5].to_owned(),
            id: parts[6].to_owned(),
        })
    }

    /// The node this task is running on.
    ///
    /// The node is authoritative because guests migrate — polling must use
    /// this value, never a caller-supplied node.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// The task type (e.g., `vzdestroy`, `qmstart`).
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The guest or resource identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// The outcome of a completed Proxmox task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskOutcome {
    /// The task completed successfully.
    Ok,
    /// The task failed, with the exit status message.
    Failed(String),
}

/// Classify a Proxmox task exit status.
///
/// Per spec §8, only the exact string `"OK"` is treated as success. Proxmox
/// has several non-OK spellings (`"WARNINGS: 1"`, error messages, etc.), and
/// interpreting them belongs to this crate rather than `mecmcp-job`.
///
/// `"WARNINGS: 1"` is a failure: a destructive operation that reports warnings
/// must not be recorded as a clean success.
#[must_use]
pub fn classify_exit_status(status: &str) -> TaskOutcome {
    if status == "OK" {
        TaskOutcome::Ok
    } else {
        TaskOutcome::Failed(status.to_owned())
    }
}

/// Errors from task operations.
#[derive(Debug, thiserror::Error)]
pub enum TaskError {
    /// The UPID string did not have the expected format.
    #[error("malformed UPID: {0}")]
    MalformedUpid(String),
}
