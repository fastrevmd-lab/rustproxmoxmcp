//! Guest lifecycle operations.
//!
//! Operations that create, modify, or destroy guests, all mediated by the
//! authorization spine. Destructive operations require an `AuthorizedGuest`
//! from `resolve::authorize`, which cannot be forged.

use crate::client::ProxmoxClient;
use crate::error::ProxmoxError;
use crate::task::Upid;

/// Destroy a container and return its UPID string.
///
/// Issues `DELETE /nodes/{node}/lxc/{vmid}` with the purge parameter, then
/// returns the UPID string. The node is resolved from the cluster resource
/// list, never from the caller (spec §7): guests migrate, and two 2026-08-12
/// renumbers were cross-node moves (114→907, 900→908, both pve3→pve2).
///
/// This is the primitive operation. Calling it directly bypasses change-set
/// control — production workflows must use the change-set apply handler
/// instead.
///
/// # Errors
///
/// Returns [`ProxmoxError::Malformed`] if the response has no `data` member,
/// the data is not a string, or the UPID is malformed;
/// [`ProxmoxError::Unauthorized`] for 401/403, [`ProxmoxError::Api`] for any
/// other error status, or [`ProxmoxError::Http`] for network errors.
pub async fn destroy_container(
    client: &ProxmoxClient,
    node: &str,
    vmid: u32,
    purge: bool,
) -> Result<String, ProxmoxError> {
    let purge_value = if purge { "1" } else { "0" };
    let path_template = "/api2/json/nodes/{node}/lxc/{vmid}";
    let params = &[("node", node), ("vmid", &vmid.to_string())];
    let query = &[("purge", purge_value)];

    let data = client.delete_json(path_template, params, query).await?;

    // The DELETE returns {"data": "UPID:..."}.
    let upid_str = data
        .as_str()
        .ok_or_else(|| ProxmoxError::Malformed("data is not a string".into()))?
        .to_owned();

    // Validate it parses correctly, then return the original string.
    Upid::parse(&upid_str).map_err(|error| ProxmoxError::Malformed(error.to_string()))?;

    Ok(upid_str)
}

/// A guest lifecycle verb that Proxmox exposes under `status/`.
///
/// Each maps to `POST /nodes/{node}/{kind}/{vmid}/status/{verb}`, where `kind`
/// comes from the resolved guest rather than the caller. The set is closed:
/// a verb this enum does not name cannot be reached, so a typo in a tool
/// registration is a compile error rather than a 501 from Proxmox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleVerb {
    /// Start a stopped guest.
    Start,
    /// Stop a guest immediately, without asking the OS.
    Stop,
    /// Ask the guest OS to shut down cleanly.
    Shutdown,
    /// Reset a QEMU guest — a hard power cycle.
    Reset,
    /// Reboot a guest.
    Reboot,
}

impl LifecycleVerb {
    /// The Proxmox path segment for this verb.
    #[must_use]
    pub const fn path_segment(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Shutdown => "shutdown",
            Self::Reset => "reset",
            Self::Reboot => "reboot",
        }
    }
}

/// Run a lifecycle verb against a guest and return its UPID.
///
/// `kind` is the guest type resolved from `/cluster/resources`, never a value
/// the caller supplied — guests migrate, and a caller-supplied node or type is
/// how a request reaches the wrong guest.
///
/// This is the primitive. It performs no authorization: callers reach it only
/// through an [`crate::AuthorizedGuest`], which cannot be forged.
///
/// # Errors
///
/// Returns [`ProxmoxError::Malformed`] if the response has no `data` member,
/// the data is not a string, or the UPID is malformed;
/// [`ProxmoxError::Unauthorized`] for 401/403, [`ProxmoxError::Api`] for any
/// other error status, or [`ProxmoxError::Http`] for network errors.
pub async fn lifecycle(
    client: &ProxmoxClient,
    node: &str,
    kind: crate::selector::GuestType,
    vmid: u32,
    verb: LifecycleVerb,
) -> Result<String, ProxmoxError> {
    let path_template = "/api2/json/nodes/{node}/{kind}/{vmid}/status/{verb}";
    let vmid_string = vmid.to_string();
    let params = &[
        ("node", node),
        ("kind", kind.path_segment()),
        ("vmid", vmid_string.as_str()),
        ("verb", verb.path_segment()),
    ];

    let data = client.post_form(path_template, params, &[]).await?;
    upid_from(data)
}

/// Take a snapshot of a guest and return the UPID.
///
/// `description` is optional because Proxmox treats it as optional; an empty
/// one is omitted rather than sent as an empty field.
///
/// # Errors
///
/// As [`lifecycle`].
pub async fn create_snapshot(
    client: &ProxmoxClient,
    node: &str,
    kind: crate::selector::GuestType,
    vmid: u32,
    snapname: &str,
    description: Option<&str>,
) -> Result<String, ProxmoxError> {
    let path_template = "/api2/json/nodes/{node}/{kind}/{vmid}/snapshot";
    let vmid_string = vmid.to_string();
    let params = &[
        ("node", node),
        ("kind", kind.path_segment()),
        ("vmid", vmid_string.as_str()),
    ];

    let mut form: Vec<(&str, &str)> = vec![("snapname", snapname)];
    if let Some(description) = description.filter(|value| !value.is_empty()) {
        form.push(("description", description));
    }

    let data = client.post_form(path_template, params, &form).await?;
    upid_from(data)
}

/// Start a vzdump backup of one guest and return the UPID.
///
/// Unlike the other operations here this posts to a node-level endpoint with
/// the guest named in the body, because that is the shape Proxmox exposes.
///
/// # Errors
///
/// As [`lifecycle`].
pub async fn create_backup(
    client: &ProxmoxClient,
    node: &str,
    vmid: u32,
    storage: &str,
    mode: &str,
    compress: Option<&str>,
) -> Result<String, ProxmoxError> {
    let path_template = "/api2/json/nodes/{node}/vzdump";
    let params = &[("node", node)];

    let vmid_string = vmid.to_string();
    let mut form: Vec<(&str, &str)> = vec![
        ("vmid", vmid_string.as_str()),
        ("storage", storage),
        ("mode", mode),
    ];
    if let Some(compress) = compress.filter(|value| !value.is_empty()) {
        form.push(("compress", compress));
    }

    let data = client.post_form(path_template, params, &form).await?;
    upid_from(data)
}

/// Unwrap a `{"data":"UPID:..."}` response, validating the UPID parses.
///
/// The UPID is validated and the *original* string returned: re-rendering a
/// parsed UPID would hand back a value Proxmox did not send, and the task
/// endpoints are keyed on the exact string.
fn upid_from(data: serde_json::Value) -> Result<String, ProxmoxError> {
    let upid_str = data
        .as_str()
        .ok_or_else(|| ProxmoxError::Malformed("data is not a string".into()))?
        .to_owned();

    Upid::parse(&upid_str).map_err(|error| ProxmoxError::Malformed(error.to_string()))?;

    Ok(upid_str)
}
