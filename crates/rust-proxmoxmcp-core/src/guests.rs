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
    let Some(delta) = trimmed.strip_prefix('+') else {
        return true;
    };
    // The `+` alone does not make it a grow. `+banana`, `++8G` and `+-8G` all
    // start with one and none of them names an amount to add; a length check
    // admitted every one of them to the low tier, which is the opposite of
    // what the contract above promises.
    !names_a_positive_amount(delta)
}

/// Whether `value` is a positive Proxmox size: digits, an optional decimal
/// fraction, and an optional `K`/`M`/`G`/`T` unit in either case.
///
/// Zero is not a positive amount. `+0G` adds nothing, so admitting it to the
/// low tier would spend an authorisation on a call that cannot grow anything.
fn names_a_positive_amount(value: &str) -> bool {
    let digits = match value.chars().last() {
        Some(unit) if matches!(unit, 'K' | 'M' | 'G' | 'T' | 'k' | 'm' | 'g' | 't') => {
            &value[..value.len() - unit.len_utf8()]
        }
        _ => value,
    };

    let mut parts = digits.splitn(2, '.');
    let whole = parts.next().unwrap_or_default();
    if whole.is_empty() || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    if let Some(fraction) = parts.next()
        && (fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }

    digits
        .bytes()
        .any(|byte| byte.is_ascii_digit() && byte != b'0')
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

/// Run a command inside a QEMU guest through the guest agent.
///
/// The most dangerous operation in this surface, and the reason it is reachable
/// only through a change set. It is strictly more powerful than `destroy_vm`:
/// it can do anything the guest's root user can, and it leaves no Proxmox-level
/// record of what it did — the task says a command ran, not what it changed.
///
/// QEMU only. A container has no guest agent; `pct exec` is a different
/// mechanism with different authorization, and pretending the two are one tool
/// would hide that difference.
///
/// Returns the agent's PID, which `guest-exec-status` reads. Not a UPID: the
/// command runs inside the guest, so Proxmox's task system never sees it and
/// the task endpoints cannot report on it.
///
/// # Errors
///
/// Returns [`ProxmoxError::Malformed`] if the response carries no PID,
/// [`ProxmoxError::Unauthorized`] for 401/403, [`ProxmoxError::Api`] for any
/// other error status, or [`ProxmoxError::Http`] for network errors.
pub async fn guest_exec(
    client: &ProxmoxClient,
    node: &str,
    vmid: u32,
    command: &[String],
) -> Result<i64, ProxmoxError> {
    if command.is_empty() {
        return Err(ProxmoxError::Malformed("command is empty".into()));
    }

    let path_template = "/api2/json/nodes/{node}/qemu/{vmid}/agent/exec";
    let vmid_string = vmid.to_string();
    let params = &[("node", node), ("vmid", vmid_string.as_str())];

    // Proxmox takes the argv as repeated `command` fields, which preserves the
    // caller's word boundaries. Joining into one string would hand the guest's
    // shell a line to re-split, and an argument containing a space would become
    // two — a different command than the approver reviewed.
    let form: Vec<(&str, &str)> = command
        .iter()
        .map(|argument| ("command", argument.as_str()))
        .collect();

    let data = client.post_form(path_template, params, &form).await?;

    data.get("pid")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| ProxmoxError::Malformed("agent exec returned no pid".into()))
}

/// Change an LXC guest's CPU, memory or swap allocation.
///
/// Proxmox applies `cores` to a running container immediately, but `memory`
/// and `swap` take effect only at the next start — the container keeps its old
/// allocation until then. This function reports what it sent, not what took
/// effect, because the API does not distinguish them.
///
/// Returns the raw `data` member. Proxmox answers a config update
/// synchronously with `null` rather than a UPID, so there is no task to follow
/// and [`upid_from`] would reject the reply.
///
/// # Errors
///
/// As [`destroy_container`], minus the UPID parse.
pub async fn update_container_resources(
    client: &ProxmoxClient,
    node: &str,
    vmid: u32,
    cores: Option<u32>,
    memory_mb: Option<u32>,
    swap_mb: Option<u32>,
) -> Result<serde_json::Value, ProxmoxError> {
    let path_template = "/api2/json/nodes/{node}/lxc/{vmid}/config";
    let vmid_string = vmid.to_string();
    let params = &[("node", node), ("vmid", vmid_string.as_str())];

    // Held so the borrowed form entries below outlive the request.
    let cores_string = cores.map(|value| value.to_string());
    let memory_string = memory_mb.map(|value| value.to_string());
    let swap_string = swap_mb.map(|value| value.to_string());

    let mut form: Vec<(&str, &str)> = Vec::new();
    if let Some(value) = cores_string.as_deref() {
        form.push(("cores", value));
    }
    if let Some(value) = memory_string.as_deref() {
        form.push(("memory", value));
    }
    if let Some(value) = swap_string.as_deref() {
        form.push(("swap", value));
    }

    // An empty form would PUT nothing and return success, reporting a change
    // that never happened.
    if form.is_empty() {
        return Err(ProxmoxError::Malformed(
            "no resource fields given: set at least one of cores, memory or swap".into(),
        ));
    }

    client.put_form(path_template, params, &form).await
}

/// Whether interrupting this task leaves the guest in a partial state.
///
/// A UPID carries its worker type: `UPID:node:pid:pstart:starttime:TYPE:id:user:`.
/// Most tasks are safe to stop — a cancelled `vzdump` leaves an incomplete
/// archive and nothing else. A restore or a destroy is different: both rewrite
/// a guest in place, and stopping one half-way leaves something that is neither
/// the old guest nor the new one.
///
/// Unparseable input is treated as unsafe. Guessing "safe" on a malformed UPID
/// would let exactly the case this exists to catch through.
#[must_use]
pub fn stopping_task_leaves_partial_state(upid: &str) -> bool {
    // Field 5, zero-indexed, after the literal `UPID` prefix.
    let Some(worker_type) = upid.split(':').nth(5) else {
        return true;
    };
    if worker_type.is_empty() {
        return true;
    }
    matches!(
        worker_type,
        // Restores and destroys rewrite a guest in place...
        "qmrestore" | "vzrestore" | "qmdestroy" | "vzdestroy"
        // ...and so does a rollback, which is the same replacement with the
        // source being a snapshot rather than an archive. Interrupting one
        // leaves disks and configuration from different points in time.
        | "qmrollback" | "vzrollback"
    )
}

/// The node a task handle names, without requiring the rest to parse.
///
/// [`crate::task::Upid`] refuses a handle whose worker id is empty, which is
/// legitimate for node jobs -- `UPID:pve2:...:aptupdate::root@pam:` has none.
/// Cancelling those is exactly what a node-level stop is for, so the node is
/// read directly rather than through a parse that rejects them.
///
/// Returns `None` when the handle is not a UPID at all.
#[must_use]
pub fn upid_node(upid: &str) -> Option<&str> {
    let mut fields = upid.split(':');
    if fields.next()? != "UPID" {
        return None;
    }
    let node = fields.next()?;
    if node.is_empty() || node.chars().any(|c| c.is_control() || c == '/') {
        return None;
    }
    Some(node)
}

/// Whether a task handle names a guest, and which one.
///
/// Decided by the **worker kind**, not by whether the id happens to be a
/// number. Proxmox emits node-level work with numeric ids too --
/// `cephdestroyosd:<osdid>` is an OSD number, not a VMID -- so treating any
/// digits as a guest would let a guest-scoped token cancel node work whenever
/// the numbers coincided, and would reject an unrestricted caller whose OSD
/// number does not resolve as a guest.
///
/// QEMU workers are `qm*` and container workers are `vz*`. Both still need a
/// numeric id: a node-wide `vzdump` with no guest id is node-level work under
/// a guest-shaped kind.
#[must_use]
pub fn task_guest(upid: &str) -> Option<u32> {
    let mut fields = upid.split(':');
    let kind = fields.nth(5)?;
    if !(kind.starts_with("qm") || kind.starts_with("vz")) {
        return None;
    }
    fields.next()?.parse::<u32>().ok()
}

/// Ask Proxmox to stop a running task.
///
/// The task is asked to stop; it is not guaranteed to have stopped when this
/// returns, and a task that has already finished is not an error. Callers that
/// need to know the outcome read the task status afterwards.
///
/// # Errors
///
/// As [`destroy_container`], minus the UPID parse.
pub async fn stop_task(
    client: &ProxmoxClient,
    node: &str,
    upid: &str,
) -> Result<serde_json::Value, ProxmoxError> {
    // A UPID contains colons and slashes, so it cannot go through `expand_path`
    // for the same reason a volid cannot — the guard cannot tell a legitimate
    // UPID from a traversal attempt. Only `node` is expanded through it; the
    // UPID is checked and encoded here, at the one call site that knows.
    if upid.is_empty() {
        return Err(ProxmoxError::Malformed("upid is empty".into()));
    }
    if !upid.starts_with("UPID:") {
        return Err(ProxmoxError::Malformed(format!(
            "'{upid}' is not a task handle: a UPID begins with 'UPID:'"
        )));
    }

    if upid.contains("..") {
        return Err(ProxmoxError::Malformed(
            "upid contains '..', which cannot name a task".into(),
        ));
    }
    if upid.chars().any(char::is_control) {
        return Err(ProxmoxError::Malformed(
            "upid contains a control character".into(),
        ));
    }

    let prefix = mecmcp_openapi::expand_path("/api2/json/nodes/{node}/tasks", &[("node", node)])
        .map_err(|error| ProxmoxError::Malformed(error.to_string()))?;

    // No placeholders left, so this passes through expansion untouched and the
    // encoded UPID reaches Proxmox as one segment.
    let path = format!("{prefix}/{}", crate::client::percent_encode(upid));

    client.delete_json(&path, &[], &[]).await
}

#[cfg(test)]
mod task_cancellation_tests {
    use super::stopping_task_leaves_partial_state;

    /// A cancelled backup or migration leaves nothing half-written that the
    /// guest depends on.
    #[test]
    fn ordinary_tasks_are_safe_to_stop() {
        for upid in [
            "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdump:617:root@pam:",
            "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:qmigrate:617:root@pam:",
            "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:download:local:root@pam:",
        ] {
            assert!(
                !stopping_task_leaves_partial_state(upid),
                "{upid} is safe to interrupt"
            );
        }
    }

    /// A restore or destroy rewrites a guest in place. Stopping one half-way
    /// leaves something that is neither the old guest nor the new one.
    #[test]
    fn restores_and_destroys_are_not() {
        for upid in [
            "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:qmrestore:617:root@pam:",
            "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzrestore:617:root@pam:",
            "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:qmdestroy:617:root@pam:",
            "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:617:root@pam:",
            "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:qmrollback:617:root@pam:",
            "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzrollback:617:root@pam:",
        ] {
            assert!(
                stopping_task_leaves_partial_state(upid),
                "{upid} must not be interrupted"
            );
        }
    }

    /// Guessing "safe" on input this cannot read would admit exactly the case
    /// the check exists to catch.
    #[test]
    fn unreadable_input_is_treated_as_unsafe() {
        for upid in [
            "",
            "UPID:",
            "not-a-upid",
            "UPID:pve2:a:b:c",
            "UPID:pve2:a:b:c::617:root:",
        ] {
            assert!(
                stopping_task_leaves_partial_state(upid),
                "{upid:?} cannot be classified and must be refused"
            );
        }
    }
}

#[cfg(test)]
mod task_addressing_tests {
    use super::{task_guest, upid_node};

    #[test]
    fn a_guest_worker_names_its_guest() {
        for (upid, want) in [
            (
                "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:qmigrate:905:root@pam:",
                Some(905),
            ),
            (
                "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdump:617:root@pam:",
                Some(617),
            ),
            (
                "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:qmstart:100:root@pam:",
                Some(100),
            ),
        ] {
            assert_eq!(task_guest(upid), want, "{upid}");
        }
    }

    /// Node-level work carries numeric ids too. `cephdestroyosd:3` is OSD 3,
    /// and reading it as guest 3 would let a token scoped to guest 3 cancel it.
    #[test]
    fn node_work_with_a_numeric_id_is_not_a_guest() {
        for upid in [
            "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:cephdestroyosd:3:root@pam:",
            "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:srvreload:pve2:root@pam:",
            "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:aptupdate::root@pam:",
            // A node-wide backup under a guest-shaped kind, with no guest id.
            "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdump::root@pam:",
        ] {
            assert_eq!(task_guest(upid), None, "{upid}");
        }
    }

    /// A node job with no worker id is still cancellable, so its node must be
    /// readable without the strict parse that rejects the empty field.
    #[test]
    fn the_node_is_readable_even_without_a_worker_id() {
        assert_eq!(
            upid_node("UPID:pve2:0000A1B2:00C3D4E5:66BC1234:aptupdate::root@pam:"),
            Some("pve2")
        );
        assert_eq!(upid_node("not-a-upid"), None);
        assert_eq!(upid_node("UPID::x:y:z:aptupdate::root@pam:"), None);
    }
}
