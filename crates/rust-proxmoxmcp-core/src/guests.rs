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

/// Destroy a QEMU guest and return its UPID string.
///
/// The QEMU sibling of [`destroy_container`]. Kept separate rather than
/// folded into one function taking a [`crate::selector::GuestType`], because
/// the two carry different query parameters — `purge` means the same thing but
/// `destroy-unreferenced-disks` exists only here — and a single function would
/// have to accept parameters that are meaningless for half its callers.
///
/// This is the primitive operation. Calling it directly bypasses change-set
/// control; production workflows must use the change-set apply handler.
///
/// # Errors
///
/// As [`destroy_container`].
pub async fn destroy_vm(
    client: &ProxmoxClient,
    node: &str,
    vmid: u32,
    purge: bool,
) -> Result<String, ProxmoxError> {
    let purge_value = if purge { "1" } else { "0" };
    let path_template = "/api2/json/nodes/{node}/qemu/{vmid}";
    let vmid_string = vmid.to_string();
    let params = &[("node", node), ("vmid", vmid_string.as_str())];
    let query = &[
        ("purge", purge_value),
        ("destroy-unreferenced-disks", purge_value),
    ];

    let data = client.delete_json(path_template, params, query).await?;
    upid_from(data)
}

/// Delete one snapshot of a guest and return the UPID.
///
/// # Errors
///
/// As [`destroy_container`].
pub async fn delete_snapshot(
    client: &ProxmoxClient,
    node: &str,
    kind: crate::selector::GuestType,
    vmid: u32,
    snapname: &str,
) -> Result<String, ProxmoxError> {
    let path_template = "/api2/json/nodes/{node}/{kind}/{vmid}/snapshot/{snapname}";
    let vmid_string = vmid.to_string();
    let params = &[
        ("node", node),
        ("kind", kind.path_segment()),
        ("vmid", vmid_string.as_str()),
        ("snapname", snapname),
    ];

    let data = client.delete_json(path_template, params, &[]).await?;
    upid_from(data)
}

/// Roll a guest back to one of its snapshots and return the UPID.
///
/// Destructive in a way deletion is not: it *replaces* the guest's current
/// state rather than removing a named object, so everything written since the
/// snapshot is lost. A preview for this operation should say what is being
/// overwritten, not merely what is being restored.
///
/// # Errors
///
/// As [`destroy_container`].
pub async fn rollback_snapshot(
    client: &ProxmoxClient,
    node: &str,
    kind: crate::selector::GuestType,
    vmid: u32,
    snapname: &str,
) -> Result<String, ProxmoxError> {
    let path_template = "/api2/json/nodes/{node}/{kind}/{vmid}/snapshot/{snapname}/rollback";
    let vmid_string = vmid.to_string();
    let params = &[
        ("node", node),
        ("kind", kind.path_segment()),
        ("vmid", vmid_string.as_str()),
        ("snapname", snapname),
    ];

    let data = client.post_form(path_template, params, &[]).await?;
    upid_from(data)
}

/// Delete one volume from a storage backend.
///
/// Serves both `delete_backup` and `delete_iso`: Proxmox exposes archives and
/// ISO images through the same `/storage/{storage}/content/{volid}` endpoint,
/// and the volid carries which is which. The tools stay separate because their
/// blast radius differs — an ISO can be re-downloaded, a backup cannot.
///
/// Returns the raw `data` member rather than a UPID: this endpoint answers
/// synchronously with `null` on some storage types.
///
/// The volid is percent-encoded before expansion. A Proxmox volid legitimately
/// contains a slash — `local:backup/vzdump-lxc-950.tar.zst` — and
/// `mecmcp-openapi` refuses a parameter that would span a path segment rather
/// than sanitising it. That guard is right: it cannot tell a real volid from a
/// traversal attempt. Encoding here says which one this is, at the one call
/// site that knows.
///
/// # Errors
///
/// As [`destroy_container`], minus the UPID parse.
pub async fn delete_volume(
    client: &ProxmoxClient,
    node: &str,
    storage: &str,
    volid: &str,
) -> Result<serde_json::Value, ProxmoxError> {
    // A volid cannot go through `expand_path`. `mecmcp-openapi` refuses a
    // parameter containing a literal `/` **or any percent-encoded form of
    // one**, deliberately: it cannot tell a legitimate volid from a traversal
    // attempt, and an extra segment addresses a different endpoint rather than
    // decorating the request.
    //
    // A Proxmox volid genuinely contains one — `local:backup/vzdump-lxc-950
    // .tar.zst` — so the guard and the API disagree, and this is the one call
    // site that knows which is which.
    //
    // The resolution keeps the guard doing everything it still can: `node` and
    // `storage` are expanded through it as normal, and only the volid is
    // encoded and appended here, after being checked for the things the guard
    // would have caught.
    if volid.is_empty() {
        return Err(ProxmoxError::Malformed("volid is empty".into()));
    }
    if volid.contains("..") {
        return Err(ProxmoxError::Malformed(
            "volid contains '..', which cannot name a Proxmox volume".into(),
        ));
    }
    if volid.chars().any(char::is_control) {
        return Err(ProxmoxError::Malformed(
            "volid contains a control character".into(),
        ));
    }
    // Proxmox volids are `storage:kind/name`. Requiring the colon keeps a bare
    // path from being addressed as a volume.
    if !volid.contains(':') {
        return Err(ProxmoxError::Malformed(
            "volid is not in storage:path form".into(),
        ));
    }

    let prefix = mecmcp_openapi::expand_path(
        "/api2/json/nodes/{node}/storage/{storage}/content",
        &[("node", node), ("storage", storage)],
    )
    .map_err(|error| ProxmoxError::Malformed(error.to_string()))?;

    // No placeholders left, so this passes through expansion untouched and the
    // encoded volid reaches Proxmox as one segment.
    let path = format!("{prefix}/{}", crate::client::percent_encode(volid));

    client.delete_json(&path, &[], &[]).await
}

/// Restore a guest from a backup archive and return the UPID.
///
/// The most destructive operation in the surface. It overwrites the guest at
/// `vmid` with the archive's contents, and unlike a rollback there is no
/// snapshot of the pre-restore state unless someone took one.
///
/// `force` is required by Proxmox to overwrite an existing guest; passing it
/// is the caller's decision, not this function's default.
///
/// # Errors
///
/// As [`destroy_container`].
pub async fn restore_backup(
    client: &ProxmoxClient,
    node: &str,
    kind: crate::selector::GuestType,
    vmid: u32,
    archive: &str,
    force: bool,
) -> Result<String, ProxmoxError> {
    let path_template = "/api2/json/nodes/{node}/{kind}";
    let params = &[("node", node), ("kind", kind.path_segment())];

    let vmid_string = vmid.to_string();
    let force_value = if force { "1" } else { "0" };
    let form = &[
        ("vmid", vmid_string.as_str()),
        ("archive", archive),
        ("force", force_value),
        ("restore", "1"),
    ];

    let data = client.post_form(path_template, params, form).await?;
    upid_from(data)
}

/// Whether a disk resize destroys data.
///
/// Proxmox takes the size as a delta (`+8G`) or an absolute value (`32G`).
/// A grow adds capacity; a **shrink discards whatever lived beyond the new
/// end**, which is data loss and therefore destructive rather than low tier.
///
/// `tier::tier_of` reports `resize_disk` as `Low` because a tool's tier cannot
/// depend on an argument. The re-classification happens here, at the one place
/// that has the argument to look at.
///
/// A value this cannot classify is treated as **shrinking**. Guessing "grow"
/// on an unparseable size would let a possible shrink through; guessing
/// "shrink" only costs a refusal the caller can retry as an explicit `+N`.
/// Shrinking is not offered by any tool on this server -- there is no
/// change-set path to it -- so a false "shrink" is never a data-loss risk.
#[must_use]
pub fn resize_shrinks(size: &str) -> bool {
    let trimmed = size.trim();
    // A leading `+` is Proxmox's delta form and is the only unambiguous grow.
    // Everything else — an absolute value, a negative delta, an empty or
    // malformed string — is treated as a shrink.
    !trimmed.starts_with('+') || trimmed.len() < 2
}

/// Clone a guest into a new VMID and return the UPID.
///
/// `full` selects a full copy over a linked clone. A linked clone shares base
/// storage with its source, so deleting the source later breaks the clone —
/// which is why the choice is the caller's rather than a default here.
///
/// # Errors
///
/// As [`lifecycle`].
pub async fn clone_guest(
    client: &ProxmoxClient,
    node: &str,
    kind: crate::selector::GuestType,
    source_vmid: u32,
    new_vmid: u32,
    name: Option<&str>,
    full: bool,
) -> Result<String, ProxmoxError> {
    let path_template = "/api2/json/nodes/{node}/{kind}/{vmid}/clone";
    let source_string = source_vmid.to_string();
    let params = &[
        ("node", node),
        ("kind", kind.path_segment()),
        ("vmid", source_string.as_str()),
    ];

    let new_string = new_vmid.to_string();
    let full_value = if full { "1" } else { "0" };
    let mut form: Vec<(&str, &str)> = vec![("newid", new_string.as_str()), ("full", full_value)];
    // `hostname` for a container, `name` for a VM: the same concept under two
    // spellings, and sending the wrong one is silently ignored by Proxmox.
    if let Some(name) = name.filter(|value| !value.is_empty()) {
        form.push((
            match kind {
                crate::selector::GuestType::Lxc => "hostname",
                crate::selector::GuestType::Qemu => "name",
            },
            name,
        ));
    }

    let data = client.post_form(path_template, params, &form).await?;
    upid_from(data)
}

/// Resize a guest disk and return the UPID.
///
/// `size` is Proxmox's form: `+8G` to grow by, or an absolute value. See
/// [`resize_shrinks`] for why the two are not interchangeable to the
/// authorization spine.
///
/// Answers synchronously on some storage types, so the returned handle may be
/// empty rather than a UPID.
///
/// # Errors
///
/// As [`lifecycle`], minus the UPID parse when the answer is synchronous.
pub async fn resize_disk(
    client: &ProxmoxClient,
    node: &str,
    kind: crate::selector::GuestType,
    vmid: u32,
    disk: &str,
    size: &str,
) -> Result<String, ProxmoxError> {
    let path_template = "/api2/json/nodes/{node}/{kind}/{vmid}/resize";
    let vmid_string = vmid.to_string();
    let params = &[
        ("node", node),
        ("kind", kind.path_segment()),
        ("vmid", vmid_string.as_str()),
    ];
    let form = &[("disk", disk), ("size", size)];

    let data = client.post_form(path_template, params, form).await?;
    // A synchronous answer is `null`, not a UPID. Returning an empty handle
    // rather than failing keeps a completed resize from reading as an error.
    Ok(data.as_str().unwrap_or_default().to_owned())
}

/// Create a guest and return the UPID.
///
/// `config` carries the guest's whole definition, which differs enough between
/// QEMU and LXC that this function does not model it: the caller passes the
/// form fields Proxmox documents for the type it is creating.
///
/// # Errors
///
/// As [`lifecycle`].
pub async fn create_guest(
    client: &ProxmoxClient,
    node: &str,
    kind: crate::selector::GuestType,
    vmid: u32,
    config: &[(&str, &str)],
) -> Result<String, ProxmoxError> {
    let path_template = "/api2/json/nodes/{node}/{kind}";
    let params = &[("node", node), ("kind", kind.path_segment())];

    let vmid_string = vmid.to_string();
    let mut form: Vec<(&str, &str)> = vec![("vmid", vmid_string.as_str())];
    form.extend_from_slice(config);

    let data = client.post_form(path_template, params, &form).await?;
    upid_from(data)
}

/// Download an ISO or container template onto a storage backend.
///
/// # Errors
///
/// As [`lifecycle`].
pub async fn download_url(
    client: &ProxmoxClient,
    node: &str,
    storage: &str,
    content: &str,
    filename: &str,
    url: &str,
    checksum: Option<(&str, &str)>,
) -> Result<String, ProxmoxError> {
    let path_template = "/api2/json/nodes/{node}/storage/{storage}/download-url";
    let params = &[("node", node), ("storage", storage)];

    let mut form: Vec<(&str, &str)> =
        vec![("content", content), ("filename", filename), ("url", url)];
    // Proxmox verifies the download when both are given. Sending one without
    // the other is silently ignored, so they travel together or not at all.
    if let Some((algorithm, value)) = checksum {
        form.push(("checksum-algorithm", algorithm));
        form.push(("checksum", value));
    }

    let data = client.post_form(path_template, params, &form).await?;
    upid_from(data)
}
