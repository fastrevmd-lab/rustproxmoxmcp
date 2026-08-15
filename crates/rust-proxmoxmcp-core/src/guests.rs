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
