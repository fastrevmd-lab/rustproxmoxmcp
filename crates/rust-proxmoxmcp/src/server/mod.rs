//! The MCP tool surface for release 0.1: reads only.

mod change_set;

use mecmcp_auth::{CallerCtx, ScopeSet};
use mecmcp_server::{
    ResultFormat, ResultLimits, authorize_call, caller_from_extensions, filter_tools_for_scope,
    tool_error, tool_result,
};
use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Implementation, ListToolsResult, PaginatedRequestParams,
        ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use rust_proxmoxmcp_core::{
    Intent, ProxmoxGrant, catalog::read_tool, client::ProxmoxClient, guests::LifecycleVerb,
    inventory::ClusterInventory, resolve::GuestIndex, selector::GuestType, tier::WRITE_TOOLS,
};
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Tool names that exist only as an authorization scope.
///
/// No `#[tool]` handler answers to these — the generic `plan_proxmox_destroy`
/// and `apply_proxmox_change_set` handlers do the work. They are in
/// `KNOWN_TOOLS` so the token CLI accepts them as a scope, and in `WRITE_TOOLS`
/// so a wildcard token does not reach them.
///
/// Enumerated rather than left implicit because two invariants have to know
/// about them: every other `KNOWN_TOOLS` entry must have a handler, and must
/// fall into a known tier category. Naming the exception keeps both checks
/// meaningful for everything else.
#[cfg_attr(not(test), allow(dead_code))]
const AUTHORIZATION_ONLY_TOOLS: &[&str] = &[
    "delete_backup",
    "delete_container",
    "delete_iso",
    "delete_snapshot",
    "delete_vm",
    "execute_vm_command",
    "restore_backup",
    "rollback_snapshot",
];

/// The concrete tool name a destructive operation authorises against.
///
/// `plan_proxmox_destroy` and `apply_proxmox_change_set` are generic handlers.
/// Authorising only those would let a token allowlisted for them select any
/// operation — `op: "delete_backup"` from a token never granted
/// `delete_backup` — which defeats the point of `WRITE_TOOLS` naming each
/// destructive tool separately.
///
/// So the operation maps to its own tool name and that scope is enforced too,
/// at plan and again at apply. Both, because a scope can be narrowed between
/// the two, and the apply is the call that acts.
///
/// `destroy_guest` maps by the *resolved* guest type, because `delete_vm` and
/// `delete_container` are distinct scopes in `WRITE_TOOLS` and the dispatch
/// calls a different primitive for each. Mapping both to `delete_vm` would
/// deny a token granted `delete_container` its own containers, and let a token
/// granted only `delete_vm` delete them.
const fn tool_for_op(op: &str, kind: GuestType) -> Option<&'static str> {
    match op.as_bytes() {
        b"destroy_guest" | b"destroy" => Some(match kind {
            GuestType::Lxc => "delete_container",
            GuestType::Qemu => "delete_vm",
        }),
        b"delete_snapshot" => Some("delete_snapshot"),
        b"rollback_snapshot" => Some("rollback_snapshot"),
        b"delete_backup" => Some("delete_backup"),
        b"delete_iso" => Some("delete_iso"),
        b"restore_backup" => Some("restore_backup"),
        b"guest_exec" => Some("execute_vm_command"),
        _ => None,
    }
}

/// Render the preview an approver reviews for one destructive action.
///
/// Operation-specific by necessity. `render_preview` produces a guest-destroy
/// description, so reusing it showed `DESTROY` for a rollback, a restore and a
/// volume deletion alike — an approver would have been asked to sign off on
/// something other than what would run.
fn render_destructive_preview(
    action: &change_set::DestroyAction,
    guest_name: &str,
    node: &str,
) -> String {
    let target = format!(
        "{} (vmid {}, {}, node {})",
        guest_name, action.vmid, action.cluster, node
    );
    match action.op.as_str() {
        "destroy_guest" | "destroy" => {
            format!(
                "DESTROY {target}\n  The guest and its disks are removed. This cannot be undone."
            )
        }
        "delete_snapshot" => format!(
            "DELETE SNAPSHOT '{}' of {target}\n  The snapshot is removed. The guest is untouched.",
            action.snapname.as_deref().unwrap_or("?")
        ),
        "rollback_snapshot" => format!(
            "ROLLBACK {target} to snapshot '{}'\n  \
             OVERWRITES the guest's current state. Everything written since that \
             snapshot is lost. This is not a deletion — it is a replacement.",
            action.snapname.as_deref().unwrap_or("?")
        ),
        "delete_backup" => format!(
            "DELETE BACKUP '{}' on storage '{}' at node '{}'\n  \
             The archive is removed. A backup cannot be re-created from the guest \
             as it was when the backup was taken.",
            action.volid.as_deref().unwrap_or("?"),
            action.storage.as_deref().unwrap_or("?"),
            action.storage_node.as_deref().unwrap_or("?")
        ),
        "delete_iso" => format!(
            "DELETE ISO '{}' on storage '{}' at node '{}'\n  \
             The image is removed. It can be downloaded again.",
            action.volid.as_deref().unwrap_or("?"),
            action.storage.as_deref().unwrap_or("?"),
            action.storage_node.as_deref().unwrap_or("?")
        ),
        "restore_backup" => format!(
            "RESTORE {target} from '{}'\n  \
             OVERWRITES the guest with the archive's contents. Unlike a rollback \
             there is no snapshot of the pre-restore state unless one was taken.",
            action.volid.as_deref().unwrap_or("?")
        ),
        "guest_exec" => {
            // Rendered one argument per line and quoted. An approver has to be
            // able to see exactly what will run, including where the word
            // boundaries fall -- a command joined into a single line hides
            // whether an argument contained a space.
            let argv = action
                .command
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|word| format!("    {word:?}"))
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                "RUN COMMAND in {target}\n  \
                 Executed by the QEMU guest agent as its user, normally root. \
                 There is no shell: these arguments are passed through as given.\n\
                 {argv}"
            )
        }
        other => format!("UNKNOWN OPERATION '{other}' on {target}"),
    }
}

/// Build and validate the action a destructive plan will record.
///
/// Each operation names exactly the parameters it needs, and a missing one is
/// refused here rather than defaulted at apply time. The action is what the
/// change-set digest covers, so anything not decided now is something the
/// approver cannot have reviewed.
fn build_destroy_action(
    args: &change_set::PlanDestroyArgs,
) -> Result<change_set::DestroyAction, String> {
    let require = |value: &Option<String>, name: &str| -> Result<String, String> {
        value
            .as_ref()
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or_else(|| format!("{} requires {name}", args.op))
    };

    let mut storage_node = None;
    let (snapname, storage, volid) = match args.op.as_str() {
        // What 0.3 planned, and still the default.
        "destroy_guest" => (None, None, None),
        "delete_snapshot" | "rollback_snapshot" => {
            (Some(require(&args.snapname, "snapname")?), None, None)
        }
        "delete_backup" | "delete_iso" => {
            // `local` is node-local storage, so the node is part of the
            // volume's identity rather than a detail of where to send the
            // request. Required at plan time and recorded in the action, so
            // apply cannot derive it from whichever guest the vmid names.
            storage_node = Some(require(&args.storage_node, "storage_node")?);
            (
                None,
                Some(require(&args.storage, "storage")?),
                Some(require(&args.volid, "volid")?),
            )
        }
        // No storage: the archive volid names its own storage, and accepting a
        // second one invites the two to disagree.
        "restore_backup" => (None, None, Some(require(&args.volid, "volid")?)),
        other => {
            return Err(format!(
                "unknown destructive operation '{other}'; expected one of \
                 destroy_guest, delete_snapshot, rollback_snapshot, delete_backup, \
                 delete_iso, restore_backup"
            ));
        }
    };

    Ok(change_set::DestroyAction {
        op: args.op.clone(),
        cluster: args.cluster.clone(),
        vmid: args.vmid,
        snapname,
        storage,
        volid,
        storage_node,
        command: None,
    })
}

/// Build the action for a guest-agent command.
///
/// Separate from [`build_destroy_action`] because the parameters do not
/// overlap: this needs an argv and nothing else, and the destroy operations
/// need storage coordinates it has no use for. Both produce the same action
/// type, so approve and apply are shared.
fn build_exec_action(args: &change_set::PlanExecArgs) -> Result<change_set::DestroyAction, String> {
    if args.command.is_empty() {
        return Err(
            "command is empty: give the argv to run, e.g. [\"systemctl\", \"status\", \"nginx\"]"
                .to_owned(),
        );
    }
    if args.command.iter().any(|word| word.is_empty()) {
        return Err(
            "command contains an empty argument, which the guest would receive as a bare '' and \
             is almost never intended"
                .to_owned(),
        );
    }
    if args.command.iter().any(|word| word.contains('\0')) {
        return Err("command contains a NUL byte".to_owned());
    }

    Ok(change_set::DestroyAction {
        op: "guest_exec".to_owned(),
        cluster: args.cluster.clone(),
        vmid: args.vmid,
        snapname: None,
        storage: None,
        volid: None,
        storage_node: None,
        command: Some(args.command.clone()),
    })
}

/// How many times an apply reads a guest-agent command's status before giving
/// up. With [`GUEST_EXEC_POLL_DELAY`] this is a thirty-second ceiling.
const GUEST_EXEC_POLL_ATTEMPTS: u32 = 30;

/// Gap between guest-agent status reads.
const GUEST_EXEC_POLL_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

/// Principal recorded on a receipt written by startup recovery.
///
/// The executor of an apply is the token that called
/// `apply_proxmox_change_set`, which is not the approver — two-person control
/// exists so those differ. When the process that knew the executor dies before
/// writing the receipt, that identity is simply gone, and no field on the
/// change set carries it. An explicit marker says so; reusing the approver
/// would put a name on a destructive execution that person did not perform.
const RECOVERED_EXECUTOR: &str = "unknown:recovered-at-startup";

/// Result size limits for MCP tool responses.
const RESULT_LIMITS: ResultLimits = ResultLimits {
    max_text_bytes: 512 * 1024,
    max_json_bytes: 512 * 1024,
};

/// Every tool registered by this release. Kept sorted; asserted against the
/// catalog by a test so the two cannot drift.
pub const KNOWN_TOOLS: &[&str] = &[
    "apply_proxmox_change_set",
    "approve_proxmox_change_set",
    "clone_vm",
    "create_backup",
    "create_container",
    "create_snapshot",
    "create_vm",
    "delete_backup",
    "delete_container",
    "delete_iso",
    "delete_snapshot",
    "delete_vm",
    "download_iso",
    "execute_vm_command",
    "get_cluster_status",
    "get_container_config",
    "get_container_ip",
    "get_containers",
    "get_guest_status",
    "get_node_status",
    "get_nodes",
    "get_proxmox_change_set",
    "get_storage",
    "get_task_status",
    "get_vm_config",
    "get_vms",
    "list_backups",
    "list_isos",
    "list_snapshots",
    "list_tasks",
    "list_templates",
    "plan_proxmox_destroy",
    "plan_proxmox_exec",
    "reset_vm",
    "resize_disk",
    "restart_container",
    "restore_backup",
    "rollback_snapshot",
    "shutdown_vm",
    "start_container",
    "start_vm",
    "stop_container",
    "stop_task",
    "stop_vm",
    "update_container_resources",
];

/// Arguments for a cluster-scoped read.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClusterArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
}

/// Arguments for a node-scoped read.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct NodeArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node name as reported by `get_nodes`.
    pub node: String,
}

/// Arguments for a guest-scoped read.
///
/// There is deliberately no `node` field. Guests migrate between nodes, and the
/// server resolves the current one on every call; accepting a node from the
/// caller is how a request addresses the wrong guest after a migration.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GuestArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id, unique within the cluster.
    pub vmid: u32,
}

/// Arguments for cloning one guest.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CloneArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Guest to clone from.
    pub vmid: u32,
    /// VMID for the new guest. Must not be a protected pin.
    pub newid: u32,
    /// Name or hostname for the clone. Optional.
    #[serde(default)]
    pub name: Option<String>,
    /// Full copy rather than a linked clone.
    ///
    /// Defaults to a full copy: a linked clone shares base storage with its
    /// source, so deleting the source later breaks the clone. The cheaper
    /// option should be asked for, not assumed.
    #[serde(default = "default_true")]
    pub full: bool,
}

/// A download URL with its credentials removed, for the audit record.
///
/// A presigned or private URL carries its authorisation in the userinfo or the
/// query string. The audit log is durable and may be shipped onward, so the
/// full URL must not go into it -- the origin and path are what an auditor
/// needs to know what was fetched.
fn redact_download_url(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let rest = rest.split('#').next().unwrap_or(rest);
    let (authority_and_path, query) = match rest.split_once('?') {
        Some((head, _)) => (head, true),
        None => (rest, false),
    };
    // Anything before an '@' in the authority is userinfo.
    let authority_and_path = match authority_and_path.split_once('/') {
        Some((authority, path)) => {
            let authority = authority.rsplit('@').next().unwrap_or(authority);
            format!("{authority}/{path}")
        }
        None => authority_and_path
            .rsplit('@')
            .next()
            .unwrap_or(authority_and_path)
            .to_owned(),
    };
    let suffix = if query { "?<redacted>" } else { "" };
    if scheme.is_empty() {
        format!("{authority_and_path}{suffix}")
    } else {
        format!("{scheme}://{authority_and_path}{suffix}")
    }
}

/// Config keys `create_vm` and `create_container` refuse.
///
/// `create_guest` forwards arbitrary key/value pairs to Proxmox, which is what
/// lets one function serve both QEMU and LXC without modelling either. That
/// passthrough is only safe if the keys that leave the guest are refused, and
/// there are more of them than they first appear:
///
/// - `archive`, `restore` and `force` turn a create into a **restore**.
///   `guests::restore_backup` posts to the *same* endpoint with the same body
///   shape; the only difference is these three fields. Without this, a token
///   holding only `create_vm` could overwrite an existing guest, skipping the
///   destructive tier, the protection check and change-set approval entirely.
/// - `hookscript` names a script Proxmox runs **on the node**, and `args` is
///   appended to the `kvm` command line on the node.
/// - `mpN` mounts a host path into a container. With `unprivileged=0` that is
///   host root inside a privileged container.
/// - `hostpciN`, `usbN`, `devN`, `serialN` and `parallelN` pass host devices
///   through.
/// - `lxc.*` is raw LXC configuration, which can express all of the above.
/// - `cicustom` runs cloud-init snippets from storage.
///
/// Refused rather than dropped, so a caller is told their config was not
/// applied as written.
const REFUSED_CONFIG_KEYS: &[&str] = &[
    "archive",
    "restore",
    "force",
    "hookscript",
    "args",
    "unprivileged",
    "cicustom",
];

/// Key prefixes refused for the same reasons, where Proxmox numbers the key.
const REFUSED_CONFIG_PREFIXES: &[&str] =
    &["mp", "hostpci", "usb", "dev", "serial", "parallel", "lxc."];

/// Arguments for changing an LXC guest's resource allocation.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ContainerResourceArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id.
    pub vmid: u32,
    /// CPU cores. Applied to a running container immediately.
    #[serde(default)]
    pub cores: Option<u32>,
    /// Memory in MiB. Takes effect at the next start.
    #[serde(default)]
    pub memory_mb: Option<u32>,
    /// Swap in MiB. Takes effect at the next start.
    #[serde(default)]
    pub swap_mb: Option<u32>,
}

/// Arguments for stopping a running task.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct StopTaskArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node running the task. A UPID names its node, but Proxmox addresses the
    /// cancel by path, so it is taken explicitly rather than parsed out.
    pub node: String,
    /// Task handle, as returned by any tool that starts one.
    pub upid: String,
}

/// Arguments for creating a guest from scratch.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateGuestArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node to create the guest on. Required: there is no guest to resolve.
    pub node: String,
    /// VMID for the new guest. Must be free and within the token's scope.
    pub vmid: u32,
    /// Proxmox config keys, forwarded as given.
    ///
    /// QEMU and LXC diverge enough that a shared type would be a union of two
    /// half-populated things, so this stays untyped. `hookscript` and `args`
    /// are refused: both execute on the node rather than in the guest.
    #[serde(default)]
    pub config: std::collections::BTreeMap<String, String>,
}

/// Arguments for downloading an image to a storage.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DownloadIsoArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node whose storage receives the file. `local` is node-local, so the
    /// same storage name on two nodes is two different places.
    pub node: String,
    /// Storage identifier.
    pub storage: String,
    /// Filename to write.
    pub filename: String,
    /// Source URL.
    pub url: String,
    /// Content type. `iso` or `vztmpl`.
    #[serde(default = "default_download_content")]
    pub content: String,
    /// Checksum algorithm, e.g. `sha256`.
    ///
    /// Proxmox verifies only when the algorithm and value are both present and
    /// silently ignores one without the other, so this server refuses a lone
    /// half rather than letting a caller believe a checksum was checked.
    #[serde(default)]
    pub checksum_algorithm: Option<String>,
    /// Checksum value. Travels with `checksum_algorithm`.
    #[serde(default)]
    pub checksum: Option<String>,
}

/// Images are the overwhelmingly common case.
fn default_download_content() -> String {
    "iso".to_owned()
}

/// Arguments for resizing one guest disk.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResizeArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id.
    pub vmid: u32,
    /// Disk to resize, e.g. `rootfs`, `scsi0`.
    pub disk: String,
    /// New size: `+8G` to grow by.
    ///
    /// Only the `+` form is treated as growing. An absolute value may be
    /// smaller than the current disk, which destroys data, so it is refused.
    /// Shrinking is not supported: `qm resize` and `pct resize` reject a
    /// reduction, so there is no supported path to it from here either.
    pub size: String,
}

/// Arguments for taking a snapshot of one guest.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SnapshotArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id, unique within the cluster.
    pub vmid: u32,
    /// Snapshot name, as it will appear in `list_snapshots`.
    pub snapname: String,
    /// Optional free-text description. An empty one is omitted.
    #[serde(default)]
    pub description: Option<String>,
}

/// Arguments for backing up one guest.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct BackupArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id, unique within the cluster.
    pub vmid: u32,
    /// Target storage, as reported by `get_storage`.
    pub storage: String,
    /// vzdump mode: `snapshot`, `suspend`, or `stop`.
    ///
    /// Defaults to `snapshot`, the only mode that does not interrupt the
    /// guest — which is what keeps `create_backup` out of the interrupting
    /// set and therefore usable on a protected guest.
    #[serde(default = "default_backup_mode")]
    pub mode: String,
    /// Optional compression: `zstd`, `lzo`, `gzip`.
    #[serde(default)]
    pub compress: Option<String>,
}

/// vzdump's non-interrupting mode.
fn default_backup_mode() -> String {
    "snapshot".to_owned()
}

/// A clone is a full copy unless the caller asks otherwise.
const fn default_true() -> bool {
    true
}

/// Arguments for a storage-scoped read.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct StorageArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node name as reported by `get_nodes`.
    pub node: String,
    /// Storage backend name.
    pub storage: String,
}

/// Arguments for a task-scoped read.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TaskArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node name as reported by `get_nodes`.
    pub node: String,
    /// Proxmox task UPID.
    pub upid: String,
}

/// The MCP server.
#[derive(Clone)]
pub struct ProxmoxServer {
    #[allow(dead_code)]
    clusters: Arc<ClusterInventory>,
    clients: Arc<BTreeMap<String, ProxmoxClient>>,
    index: Arc<GuestIndex>,
    coordinator: Arc<mecmcp_changeset::ChangesetCoordinator>,
    /// SSDF evidence recorder, when the pipeline is configured.
    ///
    /// Held here as well as on the coordinator because the apply path does not
    /// go through `commit_operation` -- it issues the destroy directly -- and
    /// that is the only coordinator call that emits `apply_intent` and
    /// `result_receipt`. Proposal and approval come from the coordinator;
    /// execution has to come from here.
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
    lab_mode: bool,
    tool_router: ToolRouter<Self>,
}

impl ProxmoxServer {
    /// Build the server over a loaded inventory and its per-cluster clients.
    ///
    /// **`coordinator` and `evidence` must share one recorder.** The
    /// coordinator emits proposal and approval; this server emits apply intent
    /// and the receipt, because the apply path issues the destroy directly and
    /// never reaches `commit_operation`. A coordinator built without the
    /// recorder produces execution records whose proposal context is missing,
    /// and one built with a *different* recorder splits a single change across
    /// two chains -- both verify as valid chains, so neither is reported.
    /// [`new_with_default_coordinator`](Self::new_with_default_coordinator)
    /// builds both from one recorder and is the safe entry point.
    #[must_use]
    pub fn new(
        clusters: Arc<ClusterInventory>,
        clients: Arc<BTreeMap<String, ProxmoxClient>>,
        index: Arc<GuestIndex>,
        coordinator: Arc<mecmcp_changeset::ChangesetCoordinator>,
        waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
        lab_mode: bool,
        evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    ) -> Self {
        Self {
            clusters: clusters.clone(),
            clients: clients.clone(),
            index: index.clone(),
            coordinator,
            evidence,
            waivers,
            lab_mode,
            tool_router: Self::proxmox_tool_router(),
        }
    }

    /// Build the server with a default in-memory coordinator.
    ///
    /// # Errors
    ///
    /// Returns an error if the coordinator cannot be created.
    pub fn new_with_default_coordinator(
        clusters: Arc<ClusterInventory>,
        clients: Arc<BTreeMap<String, ProxmoxClient>>,
        index: Arc<GuestIndex>,
        waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
        lab_mode: bool,
        evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
        state_file: Option<&std::path::Path>,
    ) -> Result<Self, mecmcp_changeset::CoordinatorError> {
        let coordinator = change_set::build_coordinator(state_file, lab_mode, evidence.clone())?;
        Ok(Self::new(
            clusters,
            clients,
            index,
            coordinator,
            waivers,
            lab_mode,
            evidence,
        ))
    }

    /// The change-set coordinator backing this server.
    ///
    /// Exposed so callers -- integration tests in particular -- can inspect or
    /// construct store states the tool surface itself cannot produce, such as a
    /// record whose preview is absent.
    ///
    /// Unused by the binary target, which is why it carries the allow: the
    /// integration tests are separate crates and do not count as uses here.
    #[allow(dead_code)]
    pub fn coordinator(&self) -> &Arc<mecmcp_changeset::ChangesetCoordinator> {
        &self.coordinator
    }

    /// Recover the caller's context, or `None` on the stdio path.
    fn caller(context: &RequestContext<RoleServer>) -> Option<CallerCtx<ProxmoxGrant>> {
        caller_from_extensions::<ProxmoxGrant>(&context.extensions).cloned()
    }

    /// Look up the client for a cluster the caller is entitled to reach.
    fn client_for(&self, cluster: &str) -> Result<&ProxmoxClient, Box<CallToolResult>> {
        self.clients
            .get(cluster)
            .ok_or_else(|| Box::new(tool_error(format!("unknown cluster: {cluster}"))))
    }
}

/// Resolve the grant for a guest-addressed call.
///
/// Distinguishes two cases:
/// - `caller` is `None` (stdio path, no bearer token): returns the wildcard read-only grant
/// - `caller` is `Some` with `grant: None` (authenticated token that declared no scope): refuses
///
/// # Errors
///
/// Returns a `CallToolResult` error when an authenticated token carries no guest selector.
fn resolve_grant(
    caller: Option<&CallerCtx<ProxmoxGrant>>,
) -> Result<ProxmoxGrant, Box<CallToolResult>> {
    match caller {
        None => Ok(rust_proxmoxmcp_core::ProxmoxGrant::read_only()),
        Some(ctx) => ctx.grant.clone().ok_or_else(|| {
            Box::new(tool_error(format!(
                "token '{}' carries no 'guests' selector; add one to tokens.json",
                ctx.token_name
            )))
        }),
    }
}

/// Derive a scope description from the caller's tool and device scopes.
fn scope_desc(caller: Option<&CallerCtx<ProxmoxGrant>>) -> &'static str {
    caller
        .map(|c| match (&c.tools, &c.devices) {
            (ScopeSet::Wildcard, ScopeSet::Wildcard) => "global",
            (ScopeSet::Wildcard, ScopeSet::Allowlist(_)) => "device-scoped",
            (ScopeSet::Allowlist(_), _) => "tool-scoped",
        })
        .unwrap_or("stdio")
}

impl ProxmoxServer {
    /// Execute one catalog-declared read.
    ///
    /// Guest-scoped tools resolve the guest and run stage-2 authorization,
    /// yielding an `AuthorizedGuest` whose node fills the `{node}` parameter.
    /// Cluster- and node-scoped tools take their parameters from the request.
    async fn serve_read(
        &self,
        tool: &'static str,
        cluster: &str,
        extra_params: &[(&str, &str)],
        vmid: Option<u32>,
        context: &RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(context);
        if let Err(error) = authorize_call(caller.as_ref(), tool, Some(cluster), WRITE_TOOLS) {
            return tool_error(error);
        }

        let Some(entry) = read_tool(tool) else {
            return tool_error(format!("unregistered tool: {tool}"));
        };
        let client = match self.client_for(cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let mut params: Vec<(&str, String)> = extra_params
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned()))
            .collect();

        if let Some(vmid) = vmid {
            let grant = match resolve_grant(caller.as_ref()) {
                Ok(grant) => grant,
                Err(error) => return *error,
            };
            let authorized = match self
                .index
                .authorize(client, cluster, vmid, &grant, Intent::read())
                .await
            {
                Ok(authorized) => authorized,
                Err(error) => return tool_error(error),
            };
            let guest = authorized.guest();
            params.push(("node", guest.node.clone()));
            params.push(("vmid", guest.vmid.to_string()));
            params.push(("kind", guest.r#type.path_segment().to_owned()));

            tracing::info!(
                tool,
                cluster,
                vmid = guest.vmid,
                node = %guest.node,
                guest_name = %guest.name,
                tier = "read",
                protection = %authorized.protection().summary(),
                scope = scope_desc(caller.as_ref()),
                "proxmox read authorized"
            );
        }

        let borrowed: Vec<(&str, &str)> = params
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();

        let result = match client.get_json(entry.path, &borrowed, entry.query).await {
            Ok(mut value) => {
                // Apply type_filter if present
                if let Some(filter_type) = entry.type_filter
                    && let Some(array) = value.as_array_mut()
                {
                    array.retain(|item| {
                        item.get("type")
                            .and_then(|v| v.as_str())
                            .is_some_and(|t| t == filter_type.path_segment())
                    });
                }
                Ok(value)
            }
            Err(error) => Err(error),
        };

        match result {
            Ok(value) => tool_result(
                Ok::<_, String>(value),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }
}

#[tool_router(router = proxmox_tool_router, vis = "pub(crate)")]
impl ProxmoxServer {
    #[tool(
        name = "get_cluster_status",
        description = "Cluster quorum and node membership."
    )]
    async fn get_cluster_status(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read("get_cluster_status", &args.cluster, &[], None, &context)
            .await
    }

    #[tool(
        name = "get_nodes",
        description = "All nodes in the cluster with status and resource totals."
    )]
    async fn get_nodes(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read("get_nodes", &args.cluster, &[], None, &context)
            .await
    }

    #[tool(
        name = "get_node_status",
        description = "Detailed status for one node."
    )]
    async fn get_node_status(
        &self,
        Parameters(args): Parameters<NodeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_node_status",
            &args.cluster,
            &[("node", args.node.as_str())],
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "get_vms",
        description = "All QEMU guests across the cluster, with node, status and tags."
    )]
    async fn get_vms(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read("get_vms", &args.cluster, &[], None, &context)
            .await
    }

    #[tool(
        name = "get_containers",
        description = "All LXC guests across the cluster, with node, status and tags."
    )]
    async fn get_containers(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read("get_containers", &args.cluster, &[], None, &context)
            .await
    }

    #[tool(
        name = "get_vm_config",
        description = "Configuration of one QEMU guest, including its Proxmox digest."
    )]
    async fn get_vm_config(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_vm_config",
            &args.cluster,
            &[],
            Some(args.vmid),
            &context,
        )
        .await
    }

    #[tool(
        name = "get_container_config",
        description = "Configuration of one LXC guest, including its Proxmox digest."
    )]
    async fn get_container_config(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_container_config",
            &args.cluster,
            &[],
            Some(args.vmid),
            &context,
        )
        .await
    }

    /// Re-probe every apply that was in flight when this process last stopped.
    ///
    /// Called once at startup. A change set left in `Applying` with a
    /// `task_id` means the previous process started a destructive operation
    /// and died before observing its result. Proxmox kept running it, so the
    /// answer exists — it just has to be asked for.
    ///
    /// Without this the record stays `Applying` forever and an operator has to
    /// read the device to find out what happened. That is the "detectable but
    /// not recoverable" limitation the 0.3 README documented.
    ///
    /// Failures here are logged, never fatal: a server that refuses to start
    /// because one historical task cannot be re-probed is worse than one that
    /// starts and says which change set is still unresolved.
    pub async fn recover_in_flight(&self) {
        let records = self.coordinator.change_sets().await;
        for mut record in records {
            if record.state != mecmcp_changeset::ChangeSetState::Applying {
                // A handle on a settled record means the process died between
                // finishing and clearing it. Nothing to re-probe, but say so:
                // it is evidence about a crash, not noise.
                if record.task_id.is_some() {
                    tracing::warn!(
                        target: "audit",
                        change_set = %record.id,
                        state = ?record.state,
                        "a settled change set still carries a task handle; \
                         the previous process died after finishing"
                    );
                }
                continue;
            }
            let Some(task_id) = record.task_id.clone() else {
                tracing::error!(
                    target: "audit",
                    change_set = %record.id,
                    device = %record.device,
                    "an apply is stuck in Applying with no task handle; it predates \
                     handle persistence and must be resolved against the device by hand"
                );
                continue;
            };

            let Ok(upid) = rust_proxmoxmcp_core::task::Upid::parse(&task_id) else {
                tracing::error!(
                    target: "audit",
                    change_set = %record.id,
                    %task_id,
                    "the stored task handle does not parse; cannot re-probe"
                );
                continue;
            };

            // The cluster is on the record: `device` is `{cluster}/{vmid}`, the
            // shape `plan_destroy` writes. Asking every configured client in
            // turn would be worse than unnecessary — a UPID names its node, not
            // its cluster, and two clusters can both have a node of that name,
            // so the first one that answers could be answering about a
            // different task entirely.
            let Some((cluster, _)) = record.device.split_once('/') else {
                tracing::error!(
                    target: "audit",
                    change_set = %record.id,
                    device = %record.device,
                    "the record's device is not cluster/vmid; cannot choose a client"
                );
                continue;
            };
            let cluster = cluster.to_owned();

            let Some(client) = self.clients.get(&cluster) else {
                tracing::error!(
                    target: "audit",
                    change_set = %record.id,
                    %cluster,
                    "the record names a cluster this server no longer configures; \
                     leaving it Applying rather than guessing"
                );
                continue;
            };

            let upid_encoded = task_id.replace(':', "%3A");
            let path = format!(
                "/api2/json/nodes/{}/tasks/{upid_encoded}/status",
                upid.node()
            );
            let data = match client.get_json(&path, &[], &[]).await {
                Ok(data) => data,
                Err(error) => {
                    tracing::error!(
                        target: "audit",
                        change_set = %record.id,
                        %cluster,
                        %task_id,
                        %error,
                        "could not read the task status; leaving it Applying"
                    );
                    continue;
                }
            };

            let status = data.get("status").and_then(serde_json::Value::as_str);
            if status == Some("running") {
                // Still going. Leave it alone — this process did not start it
                // and must not adopt a poll loop for it, but the operator can
                // now see which task it is.
                tracing::warn!(
                    target: "audit",
                    change_set = %record.id,
                    %cluster,
                    %task_id,
                    "an apply from a previous process is still running"
                );
                continue;
            }

            // A stopped task without an exit status is an answer this code
            // does not have. Defaulting to "" would classify as failure and
            // assert an outcome nobody observed — the same mistake
            // `load_with_recovery` used to make. Leave it `Applying` and say
            // so; a human can read the task.
            let Some(exitstatus) = data.get("exitstatus").and_then(serde_json::Value::as_str)
            else {
                tracing::error!(
                    target: "audit",
                    change_set = %record.id,
                    %cluster,
                    %task_id,
                    "the task is no longer running but reports no exit status; \
                     leaving it Applying rather than inventing an outcome"
                );
                continue;
            };

            let outcome = rust_proxmoxmcp_core::task::classify_exit_status(exitstatus);
            let succeeded = matches!(outcome, rust_proxmoxmcp_core::task::TaskOutcome::Ok);
            record.state = if succeeded {
                mecmcp_changeset::ChangeSetState::Applied
            } else {
                mecmcp_changeset::ChangeSetState::Failed
            };
            record.task_id = None;

            // Close the evidence chain. Without this the record settles while
            // the chain still ends at apply intent, so the evidence says a
            // destroy was attempted and never says what happened to it.
            if let Some(recorder) = &self.evidence
                && let Err(receipt_error) = recorder.result_receipt(
                    &record.id,
                    &record.id,
                    &record.device,
                    // Not `record.approver`. The approver is who authorised the
                    // change set; the executor is whichever token called
                    // `apply_proxmox_change_set`, and two-person control exists
                    // precisely so those differ. Naming the approver here would
                    // attribute a destructive execution to someone who did not
                    // perform it — a worse defect in an audit trail than
                    // admitting the executor is unknown, which is the honest
                    // answer: the process that knew it died, and nothing
                    // persisted it.
                    RECOVERED_EXECUTOR,
                    succeeded,
                    // Matches the normal path: a nonempty value is serialised
                    // into `error`, so passing the exit status on success
                    // produces a receipt reading `outcome: success` alongside
                    // `error: "OK"`.
                    if succeeded { "" } else { exitstatus },
                )
            {
                tracing::error!(
                    %receipt_error,
                    change_set = %record.id,
                    "recovered outcome not written to the evidence chain"
                );
            }

            tracing::warn!(
                target: "audit",
                change_set = %record.id,
                %cluster,
                %task_id,
                state = ?record.state,
                %exitstatus,
                "recovered an apply that was in flight at shutdown"
            );

            if let Err(error) = self.coordinator.update_change_set(record).await {
                tracing::error!(%error, "could not persist the recovered outcome");
            }
        }
    }

    /// Run one recorded destructive action and return its task handle.
    ///
    /// Dispatches on the action the change set carries, so the work performed
    /// is exactly the work the digest covered.
    ///
    /// `delete_backup` and `delete_iso` share `delete_volume` — Proxmox exposes
    /// both through the same content endpoint — and answer synchronously on
    /// some storage types, so they may have no task handle at all. An empty
    /// handle is returned as `None` rather than as `Some("")`, which would
    /// leave the change set looking recoverable against a task that never
    /// existed.
    async fn execute_destructive(
        &self,
        client: &ProxmoxClient,
        action: &change_set::DestroyAction,
        kind: GuestType,
        node: &str,
        vmid: u32,
    ) -> Result<(String, Option<serde_json::Value>), rust_proxmoxmcp_core::ProxmoxError> {
        use rust_proxmoxmcp_core::guests;

        let missing = |name: &str| {
            rust_proxmoxmcp_core::ProxmoxError::Malformed(format!(
                "{} action is missing {name}",
                action.op
            ))
        };

        match action.op.as_str() {
            // 0.3 wrote `op: "destroy"`; a change set planned then and applied
            // now must still work, so both spellings dispatch here.
            "destroy_guest" | "destroy" => match kind {
                GuestType::Lxc => guests::destroy_container(client, node, vmid, true).await,
                GuestType::Qemu => guests::destroy_vm(client, node, vmid, true).await,
            }
            .map(|upid| (upid, None)),
            "delete_snapshot" => {
                let snapname = action
                    .snapname
                    .as_deref()
                    .ok_or_else(|| missing("snapname"))?;
                guests::delete_snapshot(client, node, kind, vmid, snapname)
                    .await
                    .map(|upid| (upid, None))
            }
            "rollback_snapshot" => {
                let snapname = action
                    .snapname
                    .as_deref()
                    .ok_or_else(|| missing("snapname"))?;
                guests::rollback_snapshot(client, node, kind, vmid, snapname)
                    .await
                    .map(|upid| (upid, None))
            }
            "delete_backup" | "delete_iso" => {
                let storage = action
                    .storage
                    .as_deref()
                    .ok_or_else(|| missing("storage"))?;
                let volid = action.volid.as_deref().ok_or_else(|| missing("volid"))?;
                // The node the action recorded, not the guest's. `local` is
                // node-local storage, so `local:backup/x` on pve2 and on pve3
                // are different volumes that share a name — using whichever
                // node the vmid happens to sit on could delete the wrong one.
                let storage_node = action
                    .storage_node
                    .as_deref()
                    .ok_or_else(|| missing("storage_node"))?;
                let data = guests::delete_volume(client, storage_node, storage, volid).await?;
                Ok((data.as_str().unwrap_or_default().to_owned(), None))
            }
            "restore_backup" => {
                let volid = action.volid.as_deref().ok_or_else(|| missing("volid"))?;
                guests::restore_backup(client, node, kind, vmid, volid, true)
                    .await
                    .map(|upid| (upid, None))
            }
            "guest_exec" => {
                // The agent is a QEMU feature; Proxmox exposes no LXC exec.
                if kind != GuestType::Qemu {
                    return Err(rust_proxmoxmcp_core::ProxmoxError::Malformed(format!(
                        "vmid {vmid} is an LXC container; the guest agent is a QEMU feature and \
                         Proxmox exposes no exec endpoint for containers"
                    )));
                }
                let command = action
                    .command
                    .as_deref()
                    .ok_or_else(|| missing("command"))?;

                let (pid, output) = guests::guest_exec_and_wait(
                    client,
                    node,
                    vmid,
                    command,
                    GUEST_EXEC_POLL_ATTEMPTS,
                    GUEST_EXEC_POLL_DELAY,
                )
                .await?;

                // No UPID: the agent runs the command itself rather than
                // through a Proxmox task, so there is no handle to follow and
                // nothing for startup recovery to re-probe.
                Ok((
                    String::new(),
                    Some(serde_json::json!({
                        "pid": pid,
                        "exited": output.exited,
                        "exit_code": output.exit_code,
                        "stdout": output.stdout,
                        "stderr": output.stderr,
                        "truncated": output.truncated,
                    })),
                ))
            }
            other => Err(rust_proxmoxmcp_core::ProxmoxError::Malformed(format!(
                "unknown destructive operation '{other}'"
            ))),
        }
    }

    /// Stage 1 + stage 2 authorization for a low-tier guest call.
    ///
    /// Shared by the additive tools, which need the same gate as the
    /// lifecycle verbs but no verb dispatch. Interruption is derived from the
    /// tool name inside `Intent::low`, so an additive tool cannot accidentally
    /// be treated as interrupting or vice versa.
    /// Authorize an operation that names a VMID which does not exist yet.
    ///
    /// [`Self::authorize_low`] cannot serve this: it resolves the guest, and
    /// there is no guest. The protection union is likewise guest-derived, so
    /// [`creation_allowed`] answers the pinned-VMID question instead.
    ///
    /// Returns the client on success.
    ///
    /// [`creation_allowed`]: rust_proxmoxmcp_core::protect::creation_allowed
    async fn authorize_creation(
        &self,
        tool: &'static str,
        cluster: &str,
        vmid: u32,
        context: &RequestContext<RoleServer>,
    ) -> Result<&ProxmoxClient, Box<CallToolResult>> {
        use rust_proxmoxmcp_core::grant::ProxmoxAction;
        use rust_proxmoxmcp_core::protect::creation_allowed;

        let caller = Self::caller(context);
        if let Err(error) = authorize_call(caller.as_ref(), tool, Some(cluster), WRITE_TOOLS) {
            return Err(Box::new(tool_error(error)));
        }

        let client = self.client_for(cluster)?;
        let grant = resolve_grant(caller.as_ref())?;

        if !grant.allows_action(ProxmoxAction::Low) {
            return Err(Box::new(tool_error(
                "creation requires the 'low' action tier, which this token does not carry",
            )));
        }

        // The guest scope has to admit the *destination*. Nothing else looks at
        // it, because there is no source guest whose scope could stand in.
        if !grant.allows_new_vmid(vmid) {
            return Err(Box::new(tool_error(format!(
                "vmid {vmid} is outside this token's guest scope, so it may not be created"
            ))));
        }

        // A pinned VMID is pinned because something important is expected to
        // live there. Letting a create claim it strands the real guest.
        if !creation_allowed(client.cluster(), vmid) {
            return Err(Box::new(tool_error(format!(
                "vmid {vmid} is a protected pin on cluster {cluster} and must not be created"
            ))));
        }

        // The guest must not already exist. This is what makes "create" mean
        // create, and it is load-bearing rather than tidy: Proxmox restores a
        // backup by POSTing to the *same* endpoint this uses, with `archive`,
        // `restore` and `force` added. Refusing those keys stops the obvious
        // spelling; refusing an existing VMID stops the whole class, including
        // whatever the next spelling turns out to be.
        //
        // A protected guest is caught here too, before its tags are ever
        // consulted, because it exists.
        match self.index.resolve(client, cluster, vmid).await {
            Ok(existing) => {
                return Err(Box::new(tool_error(format!(
                    "vmid {vmid} already exists on cluster {cluster} as '{}' -- creating cannot \
                     overwrite it. Destroy it through plan_proxmox_destroy first, or choose a free \
                     vmid.",
                    existing.name
                ))));
            }
            Err(rust_proxmoxmcp_core::ProxmoxError::NotFound { .. }) => {}
            Err(error) => {
                // Anything other than a clean "absent" leaves the question
                // unanswered, and a create that cannot prove the VMID is free
                // must not proceed.
                return Err(Box::new(tool_error(format!(
                    "could not establish whether vmid {vmid} is free on cluster {cluster}: {error}"
                ))));
            }
        }

        Ok(client)
    }

    /// Refuse config a `low` create must not be able to express.
    ///
    /// Two checks, because a key list alone is not enough. A key can be
    /// perfectly ordinary and still carry a host path in its value --
    /// `scsi0=/dev/sdb` passes a host disk through under a key that must stay
    /// allowed for `scsi0=local-lvm:32`.
    fn reject_unsafe_config(
        config: &std::collections::BTreeMap<String, String>,
    ) -> Option<CallToolResult> {
        let mut offending: Vec<String> = Vec::new();

        for key in config.keys() {
            let lower = key.to_ascii_lowercase();
            let numbered = REFUSED_CONFIG_PREFIXES.iter().any(|prefix| {
                lower.strip_prefix(prefix).is_some_and(|rest| {
                    // `lxc.` is a namespace; the rest are `mp0`, `usb1`, ...
                    prefix.ends_with('.')
                        || (!rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
                })
            });
            if REFUSED_CONFIG_KEYS.contains(&lower.as_str()) || numbered {
                offending.push(key.clone());
            }
        }

        if !offending.is_empty() {
            return Some(tool_error(format!(
                "config key(s) {} are refused: they express a restore, host code execution, a host \
                 mount or device passthrough, none of which a 'low' create may do. Create the guest \
                 without them and set them from the Proxmox UI if you genuinely need them.",
                offending.join(", ")
            )));
        }

        // A host path in any value, under any key. Proxmox storage references
        // are `storage:spec`; an absolute path is the host's filesystem.
        let host_pathed: Vec<String> = config
            .iter()
            .filter(|(_, value)| {
                value.split(',').any(|field| {
                    let candidate = field.split_once('=').map_or(field, |(_, v)| v);
                    candidate.starts_with('/')
                })
            })
            .map(|(key, _)| key.clone())
            .collect();

        if !host_pathed.is_empty() {
            return Some(tool_error(format!(
                "config key(s) {} carry an absolute host path. A guest disk is named \
                 'storage:spec'; a path names the hypervisor's own filesystem, which a 'low' \
                 create must not reach.",
                host_pathed.join(", ")
            )));
        }

        None
    }

    async fn authorize_low(
        &self,
        tool: &'static str,
        args: &GuestArgs,
        context: &RequestContext<RoleServer>,
    ) -> Result<rust_proxmoxmcp_core::AuthorizedGuest, Box<CallToolResult>> {
        use rust_proxmoxmcp_core::protect::{Override, destructive_allowed, protection_of};

        let caller = Self::caller(context);
        if let Err(error) = authorize_call(caller.as_ref(), tool, Some(&args.cluster), WRITE_TOOLS)
        {
            return Err(Box::new(tool_error(error)));
        }

        let client = self.client_for(&args.cluster)?;
        let grant = resolve_grant(caller.as_ref())?;

        let resolved = self
            .index
            .resolve(client, &args.cluster, args.vmid)
            .await
            .map_err(|error| Box::new(tool_error(error)))?;
        let protection = protection_of(client.cluster(), Some(&resolved), false);

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let override_ = destructive_allowed(
            &protection,
            &self.waivers,
            &args.cluster,
            args.vmid,
            now_unix,
            self.lab_mode,
        );
        let override_applies = !matches!(override_, Override::None);

        self.index
            .authorize(
                client,
                &args.cluster,
                args.vmid,
                &grant,
                Intent::low_with_override(tool, override_applies),
            )
            .await
            .map_err(|error| Box::new(tool_error(error)))
    }

    /// Serve one low-tier lifecycle verb.
    ///
    /// Shared by all seven lifecycle tools because the only differences are
    /// the verb, the guest type the tool name implies, and the audit label.
    /// Writing them out seven times would be seven chances to forget the
    /// protection check.
    async fn serve_lifecycle(
        &self,
        tool: &'static str,
        verb: LifecycleVerb,
        required_type: GuestType,
        args: &GuestArgs,
        context: &RequestContext<RoleServer>,
    ) -> CallToolResult {
        use rust_proxmoxmcp_core::protect::{Override, destructive_allowed, protection_of};

        let caller = Self::caller(context);
        if let Err(error) = authorize_call(caller.as_ref(), tool, Some(&args.cluster), WRITE_TOOLS)
        {
            return tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };

        // Resolve first so protection can be computed before authorization,
        // exactly as the destroy path does: a waiver or lab mode has to be
        // known before the gate runs, not after it has already refused.
        let resolved = match self.index.resolve(client, &args.cluster, args.vmid).await {
            Ok(guest) => guest,
            Err(error) => return tool_error(error),
        };
        let protection = protection_of(client.cluster(), Some(&resolved), false);

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs();

        // Reuses the destroy path's override rules. An interrupting call is not
        // destructive, but the question a waiver answers is the same one:
        // may this protected guest be disrupted right now?
        let override_ = destructive_allowed(
            &protection,
            &self.waivers,
            &args.cluster,
            args.vmid,
            now_unix,
            self.lab_mode,
        );
        let override_applies = !matches!(override_, Override::None);

        let authorized = match self
            .index
            .authorize(
                client,
                &args.cluster,
                args.vmid,
                &grant,
                Intent::low_with_override(tool, override_applies),
            )
            .await
        {
            Ok(authorized) => authorized,
            Err(error) => return tool_error(error),
        };

        let guest = authorized.guest();
        if guest.r#type != required_type {
            return tool_error(format!(
                "{tool} requires {} guest {}, but it is {}",
                required_type.path_segment(),
                args.vmid,
                guest.r#type.path_segment()
            ));
        }

        let upid = match rust_proxmoxmcp_core::guests::lifecycle(
            client,
            &guest.node,
            guest.r#type,
            guest.vmid,
            verb,
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        tracing::info!(
            target: "audit",
            tool,
            cluster = args.cluster,
            vmid = guest.vmid,
            node = %guest.node,
            guest_name = %guest.name,
            tier = "low",
            interrupts = rust_proxmoxmcp_core::tier::interrupts_service(tool),
            protection = %authorized.protection().summary(),
            override_applied = override_applies,
            scope = scope_desc(caller.as_ref()),
            upid = %upid,
            "proxmox lifecycle call"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({
                "upid": upid,
                "vmid": guest.vmid,
                "node": guest.node,
            })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "get_container_ip",
        description = "Network interfaces and addresses of one LXC guest."
    )]
    async fn get_container_ip(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        // This tool is LXC-only. We need to resolve the guest first to check its type.
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "get_container_ip",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };
        let authorized = match self
            .index
            .authorize(client, &args.cluster, args.vmid, &grant, Intent::read())
            .await
        {
            Ok(authorized) => authorized,
            Err(error) => return tool_error(error),
        };

        let guest = authorized.guest();
        if guest.r#type != GuestType::Lxc {
            return tool_error(format!(
                "get_container_ip requires an LXC guest, but {} is a QEMU VM",
                args.vmid
            ));
        }

        let vmid_str = guest.vmid.to_string();
        let params = vec![("node", guest.node.as_str()), ("vmid", vmid_str.as_str())];

        tracing::info!(
            tool = "get_container_ip",
            cluster = args.cluster,
            vmid = guest.vmid,
            node = %guest.node,
            guest_name = %guest.name,
            tier = "read",
            protection = %authorized.protection().summary(),
            scope = scope_desc(caller.as_ref()),
            "proxmox read authorized"
        );

        let entry = read_tool("get_container_ip").expect("tool in catalog");
        match client.get_json(entry.path, &params, entry.query).await {
            Ok(value) => tool_result(
                Ok::<_, String>(value),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "get_guest_status",
        description = "Current runtime status of one guest."
    )]
    async fn get_guest_status(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_guest_status",
            &args.cluster,
            &[],
            Some(args.vmid),
            &context,
        )
        .await
    }

    #[tool(name = "list_snapshots", description = "Snapshots of one guest.")]
    async fn list_snapshots(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_snapshots",
            &args.cluster,
            &[],
            Some(args.vmid),
            &context,
        )
        .await
    }

    #[tool(
        name = "get_storage",
        description = "Storage backends visible to one node, with usage."
    )]
    async fn get_storage(
        &self,
        Parameters(args): Parameters<NodeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_storage",
            &args.cluster,
            &[("node", args.node.as_str())],
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "list_backups",
        description = "Backup archives on one storage backend."
    )]
    async fn list_backups(
        &self,
        Parameters(args): Parameters<StorageArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_backups",
            &args.cluster,
            &[
                ("node", args.node.as_str()),
                ("storage", args.storage.as_str()),
            ],
            None,
            &context,
        )
        .await
    }

    #[tool(name = "list_isos", description = "ISO images on one storage backend.")]
    async fn list_isos(
        &self,
        Parameters(args): Parameters<StorageArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_isos",
            &args.cluster,
            &[
                ("node", args.node.as_str()),
                ("storage", args.storage.as_str()),
            ],
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "list_templates",
        description = "Container templates on one storage backend."
    )]
    async fn list_templates(
        &self,
        Parameters(args): Parameters<StorageArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_templates",
            &args.cluster,
            &[
                ("node", args.node.as_str()),
                ("storage", args.storage.as_str()),
            ],
            None,
            &context,
        )
        .await
    }

    #[tool(name = "list_tasks", description = "Recent tasks on one node.")]
    async fn list_tasks(
        &self,
        Parameters(args): Parameters<NodeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_tasks",
            &args.cluster,
            &[("node", args.node.as_str())],
            None,
            &context,
        )
        .await
    }

    #[tool(name = "get_task_status", description = "Status of one task by UPID.")]
    async fn get_task_status(
        &self,
        Parameters(args): Parameters<TaskArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_task_status",
            &args.cluster,
            &[("node", args.node.as_str()), ("upid", args.upid.as_str())],
            None,
            &context,
        )
        .await
    }

    #[tool(name = "start_vm", description = "Start a stopped QEMU guest.")]
    async fn start_vm(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_lifecycle(
            "start_vm",
            LifecycleVerb::Start,
            GuestType::Qemu,
            &args,
            &context,
        )
        .await
    }

    #[tool(
        name = "stop_vm",
        description = "Stop a QEMU guest immediately, without asking the guest OS."
    )]
    async fn stop_vm(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_lifecycle(
            "stop_vm",
            LifecycleVerb::Stop,
            GuestType::Qemu,
            &args,
            &context,
        )
        .await
    }

    #[tool(
        name = "shutdown_vm",
        description = "Ask a QEMU guest's OS to shut down cleanly."
    )]
    async fn shutdown_vm(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_lifecycle(
            "shutdown_vm",
            LifecycleVerb::Shutdown,
            GuestType::Qemu,
            &args,
            &context,
        )
        .await
    }

    #[tool(name = "reset_vm", description = "Hard power-cycle a QEMU guest.")]
    async fn reset_vm(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_lifecycle(
            "reset_vm",
            LifecycleVerb::Reset,
            GuestType::Qemu,
            &args,
            &context,
        )
        .await
    }

    #[tool(name = "start_container", description = "Start a stopped LXC guest.")]
    async fn start_container(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_lifecycle(
            "start_container",
            LifecycleVerb::Start,
            GuestType::Lxc,
            &args,
            &context,
        )
        .await
    }

    #[tool(
        name = "stop_container",
        description = "Stop an LXC guest immediately."
    )]
    async fn stop_container(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_lifecycle(
            "stop_container",
            LifecycleVerb::Stop,
            GuestType::Lxc,
            &args,
            &context,
        )
        .await
    }

    #[tool(name = "restart_container", description = "Reboot an LXC guest.")]
    async fn restart_container(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_lifecycle(
            "restart_container",
            LifecycleVerb::Reboot,
            GuestType::Lxc,
            &args,
            &context,
        )
        .await
    }

    #[tool(
        name = "create_snapshot",
        description = "Take a snapshot of one guest. Additive, so permitted on a protected guest."
    )]
    async fn create_snapshot(
        &self,
        Parameters(args): Parameters<SnapshotArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let guest_args = GuestArgs {
            cluster: args.cluster.clone(),
            vmid: args.vmid,
        };
        let authorized = match self
            .authorize_low("create_snapshot", &guest_args, &context)
            .await
        {
            Ok(authorized) => authorized,
            Err(result) => return *result,
        };
        let guest = authorized.guest();

        let upid = match rust_proxmoxmcp_core::guests::create_snapshot(
            match self.client_for(&args.cluster) {
                Ok(client) => client,
                Err(result) => return *result,
            },
            &guest.node,
            guest.r#type,
            guest.vmid,
            &args.snapname,
            args.description.as_deref(),
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        tracing::info!(
            target: "audit",
            tool = "create_snapshot",
            cluster = args.cluster,
            vmid = guest.vmid,
            node = %guest.node,
            tier = "low",
            interrupts = false,
            protection = %authorized.protection().summary(),
            snapname = %args.snapname,
            upid = %upid,
            "proxmox snapshot created"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({ "upid": upid, "vmid": guest.vmid, "node": guest.node })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "create_backup",
        description = "Back up one guest with vzdump. Additive, so permitted on a protected guest."
    )]
    async fn create_backup(
        &self,
        Parameters(args): Parameters<BackupArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let guest_args = GuestArgs {
            cluster: args.cluster.clone(),
            vmid: args.vmid,
        };
        let authorized = match self
            .authorize_low("create_backup", &guest_args, &context)
            .await
        {
            Ok(authorized) => authorized,
            Err(result) => return *result,
        };
        let guest = authorized.guest();

        let upid = match rust_proxmoxmcp_core::guests::create_backup(
            match self.client_for(&args.cluster) {
                Ok(client) => client,
                Err(result) => return *result,
            },
            &guest.node,
            guest.vmid,
            &args.storage,
            &args.mode,
            args.compress.as_deref(),
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        tracing::info!(
            target: "audit",
            tool = "create_backup",
            cluster = args.cluster,
            vmid = guest.vmid,
            node = %guest.node,
            tier = "low",
            interrupts = false,
            protection = %authorized.protection().summary(),
            storage = %args.storage,
            mode = %args.mode,
            upid = %upid,
            "proxmox backup started"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({ "upid": upid, "vmid": guest.vmid, "node": guest.node })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "clone_vm",
        description = "Clone a guest into a new VMID. Additive, so permitted on a protected source."
    )]
    async fn clone_vm(
        &self,
        Parameters(args): Parameters<CloneArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use rust_proxmoxmcp_core::protect::creation_allowed;

        let guest_args = GuestArgs {
            cluster: args.cluster.clone(),
            vmid: args.vmid,
        };
        let authorized = match self.authorize_low("clone_vm", &guest_args, &context).await {
            Ok(authorized) => authorized,
            Err(result) => return *result,
        };

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        // The destination must be inside the caller's guest grant.
        //
        // `authorize_low` above checked the *source*; nothing has looked at
        // `newid`. Without this a token scoped to `vmid:600-699` could clone
        // 606 into 800 — creating a guest outside the range it was granted,
        // and probing which VMIDs are free while doing it.
        let grant = match resolve_grant(Self::caller(&context).as_ref()) {
            Ok(grant) => grant,
            Err(result) => return *result,
        };
        if !grant.allows_new_vmid(args.newid) {
            return tool_error(format!(
                "token scope does not admit vmid {} as a clone destination",
                args.newid
            ));
        }

        // And it must not be a protected pin. The protection union is evaluated
        // against a resolved guest, so it has nothing to say about a VMID that
        // does not exist yet. A pinned VMID is pinned because something is
        // expected to live there; letting a clone claim it means the real guest
        // has nowhere to go and the next delete against that number protects
        // the wrong thing.
        if !creation_allowed(client.cluster(), args.newid) {
            return tool_error(format!(
                "vmid {} is a protected pin in cluster {}; a clone may not claim it",
                args.newid, args.cluster
            ));
        }

        let guest = authorized.guest();
        let upid = match rust_proxmoxmcp_core::guests::clone_guest(
            client,
            &guest.node,
            guest.r#type,
            guest.vmid,
            args.newid,
            args.name.as_deref(),
            args.full,
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        tracing::info!(
            target: "audit",
            tool = "clone_vm",
            cluster = args.cluster,
            vmid = guest.vmid,
            newid = args.newid,
            node = %guest.node,
            tier = "low",
            interrupts = false,
            full = args.full,
            protection = %authorized.protection().summary(),
            upid = %upid,
            "proxmox clone started"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({ "upid": upid, "vmid": args.newid, "node": guest.node })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    /// Shared body for `create_vm` and `create_container`.
    ///
    /// The two differ only in the path segment Proxmox wants, but they stay
    /// separate tools: a caller asking for a container should not have to know
    /// that a `kind` flag exists, and the tool name is what the token scope
    /// names.
    async fn create_guest_inner(
        &self,
        tool: &'static str,
        kind: GuestType,
        args: CreateGuestArgs,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        if let Some(refusal) = Self::reject_unsafe_config(&args.config) {
            return refusal;
        }

        let client = match self
            .authorize_creation(tool, &args.cluster, args.vmid, &context)
            .await
        {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let config: Vec<(&str, &str)> = args
            .config
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();

        let upid = match rust_proxmoxmcp_core::guests::create_guest(
            client, &args.node, kind, args.vmid, &config,
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        // Deliberately no cache invalidation. The POST returns when the
        // create *task* starts, not when the guest appears in
        // `/cluster/resources`, so a refresh raced against it would fetch a
        // snapshot that still lacks the guest and cache that absence for a full
        // TTL -- turning a short wait into a longer one. The response says to
        // follow the task instead.

        tracing::info!(
            target: "audit",
            tool = tool,
            cluster = args.cluster,
            vmid = args.vmid,
            node = %args.node,
            kind = %kind.path_segment(),
            config_keys = %args.config.keys().cloned().collect::<Vec<_>>().join(","),
            tier = "low",
            interrupts = false,
            upid = %upid,
            "proxmox guest created"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({
                "upid": upid,
                "vmid": args.vmid,
                "node": args.node,
                "kind": kind.path_segment(),
            })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "update_container_resources",
        description = "Change an LXC guest's cores, memory or swap. Memory and swap take effect at the next start, not immediately."
    )]
    async fn update_container_resources(
        &self,
        Parameters(args): Parameters<ContainerResourceArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        if args.cores.is_none() && args.memory_mb.is_none() && args.swap_mb.is_none() {
            return tool_error(
                "give at least one of cores, memory_mb or swap_mb: a call with none would report \
                 a change that never happened.",
            );
        }

        let guest_args = GuestArgs {
            cluster: args.cluster.clone(),
            vmid: args.vmid,
        };
        let authorized = match self
            .authorize_low("update_container_resources", &guest_args, &context)
            .await
        {
            Ok(authorized) => authorized,
            Err(result) => return *result,
        };

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        let guest = authorized.guest();

        // The endpoint is LXC-only. A QEMU guest would 501 from Proxmox with a
        // message about the path, which reads as a server fault rather than a
        // guest-type mismatch.
        if guest.r#type != GuestType::Lxc {
            return tool_error(format!(
                "vmid {} is a QEMU guest; this tool changes LXC allocations only. Resize a VM from \
                 the Proxmox UI or CLI.",
                guest.vmid
            ));
        }

        if let Err(error) = rust_proxmoxmcp_core::guests::update_container_resources(
            client,
            &guest.node,
            guest.vmid,
            args.cores,
            args.memory_mb,
            args.swap_mb,
        )
        .await
        {
            return tool_error(error);
        }

        tracing::info!(
            target: "audit",
            tool = "update_container_resources",
            cluster = args.cluster,
            vmid = guest.vmid,
            node = %guest.node,
            tier = "low",
            interrupts = true,
            cores = ?args.cores,
            memory_mb = ?args.memory_mb,
            swap_mb = ?args.swap_mb,
            protection = %authorized.protection().summary(),
            "proxmox container resources changed"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({
                "vmid": guest.vmid,
                "node": guest.node,
                "cores": args.cores,
                "memory_mb": args.memory_mb,
                "swap_mb": args.swap_mb,
                "note": "cores apply immediately; memory and swap take effect at the next start",
            })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "stop_task",
        description = "Ask Proxmox to stop a running task. Restores and destroys are refused: stopping one half-way leaves a guest that is neither its old self nor its new one."
    )]
    async fn stop_task(
        &self,
        Parameters(args): Parameters<StopTaskArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use rust_proxmoxmcp_core::grant::ProxmoxAction;
        use rust_proxmoxmcp_core::guests::stopping_task_leaves_partial_state;

        // Checked before authorization, because the answer decides whether this
        // call belongs to the low tier at all — the same reason `resize_disk`
        // classifies its size argument first.
        if stopping_task_leaves_partial_state(&args.upid) {
            return tool_error(format!(
                "task '{}' rewrites a guest in place, so stopping it half-way would leave \
                 something that is neither the old guest nor the new one. Let it finish and \
                 repair the result afterwards. Backups, migrations and downloads can be stopped.",
                args.upid
            ));
        }

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "stop_task",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(result) => return *result,
        };

        if !grant.allows_action(ProxmoxAction::Low) {
            return tool_error("stop_task requires the 'low' action tier");
        }

        // A task names a node, not a guest. Its `id` field may name one, but a
        // node-wide task has none, so there is nothing for a guest selector to
        // match — the same gap `download_iso` runs into.
        if !grant.is_unrestricted_guest_scope() {
            return tool_error(
                "stop_task addresses a node-level task rather than a guest, so it requires a token \
                 whose guest scope is '*'. This token is narrowed to specific guests and cannot be \
                 checked against a task.",
            );
        }

        if let Err(error) =
            rust_proxmoxmcp_core::guests::stop_task(client, &args.node, &args.upid).await
        {
            return tool_error(error);
        }

        tracing::info!(
            target: "audit",
            tool = "stop_task",
            cluster = args.cluster,
            node = %args.node,
            tier = "low",
            interrupts = true,
            upid = %args.upid,
            "proxmox task stop requested"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({
                "upid": args.upid,
                "node": args.node,
                "note": "a stop was requested; read the task status to learn whether it stopped",
            })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "create_vm",
        description = "Create a QEMU guest at a free VMID. Config keys are forwarded to Proxmox as given; 'hookscript' and 'args' are refused because they execute on the node."
    )]
    async fn create_vm(
        &self,
        Parameters(args): Parameters<CreateGuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.create_guest_inner("create_vm", GuestType::Qemu, args, context)
            .await
    }

    #[tool(
        name = "create_container",
        description = "Create an LXC guest at a free VMID. Config keys are forwarded to Proxmox as given; 'hookscript' and 'args' are refused because they execute on the node."
    )]
    async fn create_container(
        &self,
        Parameters(args): Parameters<CreateGuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.create_guest_inner("create_container", GuestType::Lxc, args, context)
            .await
    }

    #[tool(
        name = "download_iso",
        description = "Download an image to a node's storage. Requires an unrestricted guest scope, because a storage is shared and no guest selector can narrow it."
    )]
    async fn download_iso(
        &self,
        Parameters(args): Parameters<DownloadIsoArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use rust_proxmoxmcp_core::grant::ProxmoxAction;

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "download_iso",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(result) => return *result,
        };

        if !grant.allows_action(ProxmoxAction::Low) {
            return tool_error("download_iso requires the 'low' action tier");
        }

        // A storage names no guest, so `allows_guest` has nothing to match and
        // no selector this grant carries can narrow the call. A narrowed token
        // is therefore refused outright rather than silently granted the run of
        // storage every guest shares. See `is_unrestricted_guest_scope`.
        if !grant.is_unrestricted_guest_scope() {
            return tool_error(
                "download_iso writes to storage that is not scoped to any guest, so it requires a \
                 token whose guest scope is '*'. This token is narrowed to specific guests and \
                 cannot be checked against a storage.",
            );
        }

        // Proxmox verifies only when both halves are present and ignores one
        // without the other, which would leave a caller believing a checksum
        // was checked when it was not.
        let checksum = match (args.checksum_algorithm.as_deref(), args.checksum.as_deref()) {
            (Some(algorithm), Some(value)) => Some((algorithm, value)),
            (None, None) => None,
            _ => {
                return tool_error(
                    "checksum and checksum_algorithm travel together: Proxmox ignores one without \
                     the other, so supplying a single half would report a verified download that \
                     was never verified. Give both, or neither.",
                );
            }
        };

        let upid = match rust_proxmoxmcp_core::guests::download_url(
            client,
            &args.node,
            &args.storage,
            &args.content,
            &args.filename,
            &args.url,
            checksum,
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        tracing::info!(
            target: "audit",
            tool = "download_iso",
            cluster = args.cluster,
            node = %args.node,
            storage = %args.storage,
            filename = %args.filename,
            url = %redact_download_url(&args.url),
            checksum_verification_requested = checksum.is_some(),
            tier = "low",
            interrupts = false,
            upid = %upid,
            "proxmox image download started"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({
                "upid": upid,
                "node": args.node,
                "storage": args.storage,
                "filename": args.filename,
                // Requested, not observed. The POST returns when the download
                // task starts; Proxmox verifies the checksum inside that task,
                // so a mismatch surfaces as a failed task afterwards. Reporting
                // "verified" here would assert something this call cannot know.
                "checksum_verification_requested": checksum.is_some(),
                "note": "follow the upid with get_task_status; a checksum mismatch fails the task",
            })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "resize_disk",
        description = "Grow a guest disk. Only the '+N' form is accepted. Shrinking is not supported: Proxmox itself rejects a reduction, so there is no path to it here."
    )]
    async fn resize_disk(
        &self,
        Parameters(args): Parameters<ResizeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use rust_proxmoxmcp_core::guests::resize_shrinks;

        // Checked before authorization, because the answer decides which tier
        // this call belongs to. A shrink is not a low-tier operation and must
        // not be authorised as one — `authorize_low` would grant it on a
        // `low` action tier the operator never intended for data loss.
        if resize_shrinks(&args.size) {
            return tool_error(format!(
                "size '{}' is not an unambiguous grow, so this server will not perform it. \
                 Only the '+N' form adds capacity; an absolute size may be smaller than the \
                 current disk, which destroys data. Shrinking is not supported here, and \
                 Proxmox does not support it either: `qm resize` and `pct resize` reject a \
                 reduction. Re-issue this call with a '+N' size to grow the disk.",
                args.size
            ));
        }

        let guest_args = GuestArgs {
            cluster: args.cluster.clone(),
            vmid: args.vmid,
        };
        let authorized = match self
            .authorize_low("resize_disk", &guest_args, &context)
            .await
        {
            Ok(authorized) => authorized,
            Err(result) => return *result,
        };

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        let guest = authorized.guest();

        let upid = match rust_proxmoxmcp_core::guests::resize_disk(
            client,
            &guest.node,
            guest.r#type,
            guest.vmid,
            &args.disk,
            &args.size,
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        tracing::info!(
            target: "audit",
            tool = "resize_disk",
            cluster = args.cluster,
            vmid = guest.vmid,
            node = %guest.node,
            tier = "low",
            interrupts = false,
            disk = %args.disk,
            size = %args.size,
            protection = %authorized.protection().summary(),
            // Empty when the storage answered synchronously. Present or not,
            // it is the only handle correlating this event with the task, so
            // it belongs in the record rather than only in the response.
            upid = %upid,
            "proxmox disk resized"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({ "upid": upid, "vmid": guest.vmid, "node": guest.node })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "plan_proxmox_destroy",
        description = "Plan a guest destroy operation for two-principal approval."
    )]
    async fn plan_destroy(
        &self,
        Parameters(args): Parameters<change_set::PlanDestroyArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let cluster = args.cluster.clone();
        let vmid = args.vmid;
        self.plan_change_set(
            "plan_proxmox_destroy",
            cluster,
            vmid,
            || build_destroy_action(&args),
            context,
        )
        .await
    }

    #[tool(
        name = "plan_proxmox_exec",
        description = "Plan a command to run inside a QEMU guest via its agent, for approval. There is no shell: the argv is passed through as given. QEMU only."
    )]
    async fn plan_exec(
        &self,
        Parameters(args): Parameters<change_set::PlanExecArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let cluster = args.cluster.clone();
        let vmid = args.vmid;
        self.plan_change_set(
            "plan_proxmox_exec",
            cluster,
            vmid,
            || build_exec_action(&args),
            context,
        )
        .await
    }

    /// Shared body for every plan tool.
    ///
    /// `plan_proxmox_destroy` and `plan_proxmox_exec` differ only in the action
    /// they build and the scope they authorise against. Everything after that --
    /// protection, the override decision, the fingerprint, the per-operation
    /// scope check, change-set creation and preview persistence -- is one flow,
    /// and it is the flow the security properties live in. Two copies would
    /// drift, and the copy that drifted would be the one nobody re-read.
    async fn plan_change_set(
        &self,
        plan_tool: &'static str,
        cluster: String,
        vmid: u32,
        build: impl FnOnce() -> Result<change_set::DestroyAction, String>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::ChangeSetResponse;
        use mecmcp_changeset::WaiverKind;
        use rust_proxmoxmcp_core::{
            fingerprint::{GuestState, fingerprint},
            preview::{PreviewInput, render_preview},
            protect::{Override, destructive_allowed, protection_of},
        };

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(caller.as_ref(), plan_tool, Some(&cluster), WRITE_TOOLS)
        {
            return tool_error(error);
        }

        let client = match self.client_for(&cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };

        // Resolve guest and compute protection to determine override.
        let guest = match self.index.resolve(client, &cluster, vmid).await {
            Ok(guest) => guest,
            Err(error) => return tool_error(error),
        };
        let protection = protection_of(client.cluster(), Some(&guest), false);

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs();

        let override_ = destructive_allowed(
            &protection,
            &self.waivers,
            &cluster,
            vmid,
            now_unix,
            self.lab_mode,
        );

        let override_applies = !matches!(override_, Override::None);

        // Now authorize with the override information.
        let authorized = match self
            .index
            .authorize(
                client,
                &cluster,
                vmid,
                &grant,
                Intent::destructive(override_applies),
            )
            .await
        {
            Ok(authorized) => authorized,
            Err(error) => return tool_error(error),
        };

        let guest = authorized.guest();

        // Compute fingerprint.
        let state = GuestState {
            cluster: cluster.clone(),
            vmid: guest.vmid,
            name: guest.name.clone(),
            kind: guest.r#type.path_segment().to_owned(),
            node: guest.node.clone(),
            status: guest.status.clone(),
            tags: guest.tags.clone(),
            config_digest: String::new(),
            disks: Vec::new(),
        };

        let expected_fingerprint = fingerprint(&state);

        // Built before the preview, because the preview describes it.
        let action = match build() {
            Ok(action) => action,
            Err(error) => return tool_error(error),
        };

        // The operation's own tool scope, on top of `plan_proxmox_destroy`.
        // Without this a token allowlisted for the generic handlers could
        // select any operation, and `WRITE_TOOLS` naming each destructive tool
        // separately would mean nothing.
        let Some(op_tool) = tool_for_op(&action.op, guest.r#type) else {
            return tool_error(format!("unknown destructive operation '{}'", action.op));
        };
        if let Err(error) = authorize_call(caller.as_ref(), op_tool, Some(&cluster), WRITE_TOOLS) {
            return tool_error(error);
        }

        // Render preview.
        let preview_input = PreviewInput {
            state: &state,
            protected: protection.is_protected(),
            protection_summary: &protection.summary(),
            override_: &override_,
            snapshots: 0,
            latest_snapshot: None,
            last_backup: None,
            purge_disks: true,
        };

        // The generic renderer describes a guest destroy. For every other
        // operation that is the wrong text, so the approver would be signing
        // off on something other than what runs. The guest-destroy path keeps
        // the richer renderer — it has snapshot and backup context this one
        // does not — and every other operation gets a description of itself.
        let preview_text = if matches!(action.op.as_str(), "destroy_guest" | "destroy") {
            render_preview(&preview_input)
        } else {
            render_destructive_preview(&action, &guest.name, &guest.node)
        };

        // Use the shared coordinator.
        let coordinator = self.coordinator.clone();

        let owner = caller
            .as_ref()
            .map(|ctx| ctx.token_name.clone())
            .unwrap_or_else(|| "stdio".to_owned());

        let device = format!("{}/{}", cluster, vmid);
        // Validate the operation and its parameters before anything is
        // recorded. A change set whose action names an operation the apply
        // cannot dispatch is a change set an approver may sign and nobody can
        // execute — worse, one whose parameters are missing would dispatch
        // with defaults the approver never saw.

        // This server has no policy engine in 0.3.
        let policy_signature = "proxmox-no-policy-engine";

        // For now, create the change set without preview binding.
        // TODO: implement preview binding properly once the coordinator API is clarified.
        let output = match coordinator
            .create_change_set(
                device.clone(),
                vec![action],
                owner.clone(),
                expected_fingerprint.clone(),
                policy_signature.to_owned(),
            )
            .await
        {
            Ok(output) => output,
            Err(error) => return tool_error(format!("create: {error}")),
        };

        // Persist the preview the approver will read, with its own digest.
        //
        // `create_change_set` takes no preview, so this is a second write. What
        // it buys is tamper evidence: `validate_preview` recomputes the digest
        // on load, so the text an approver reviewed cannot be edited afterwards
        // without the store refusing it.
        //
        // It does **not** make the approval cryptographically cover the
        // preview: the plan digest is over (owner, device, fingerprint,
        // actions), and the approval is over that digest. The action is what
        // the approval binds, and the preview is rendered from the action —
        // but nothing forces them to agree. Tracked separately; the README and
        // migration guide now describe the binding that exists rather than the
        // one that does not.
        let Some(mut with_preview) = coordinator
            .change_sets()
            .await
            .into_iter()
            .find(|record| record.id == output.change_set_id)
        else {
            // The record was created a moment ago, so not finding it means the
            // store dropped or evicted it. This used to be a silent skip that
            // returned a *successful* plan for a change set with no preview.
            tracing::error!(
                change_set = %output.change_set_id,
                "the change set could not be read back; the plan is refused"
            );
            return tool_error(
                "plan refused: the change set could not be read back to store its \
                 preview. It has no preview, so approve and apply will refuse it. \
                 Plan the operation again.",
            );
        };

        with_preview.preview = Some(mecmcp_changeset::PreviewRecord {
            digest: mecmcp_changeset::preview_digest(&preview_text),
            artifact: preview_text.clone(),
            job_id: None,
        });
        if let Err(error) = coordinator.update_change_set(with_preview).await {
            // Fail the plan rather than return one whose preview is not in the
            // store. The record itself is left behind and expires on its own —
            // there is no cancel tool — but `approve` and `apply` now refuse a
            // previewless record, so it cannot be acted on in the meantime.
            tracing::error!(
                %error,
                change_set = %output.change_set_id,
                "the preview could not be persisted; the plan is refused"
            );
            return tool_error(format!(
                "plan refused: the preview could not be persisted ({error}). The \
                 change set has no stored preview, so approve and apply will refuse \
                 it. Plan the operation again."
            ));
        }

        // Apply override.
        let output = match override_ {
            Override::Waiver {
                reason,
                ticket,
                until_unix,
            } => match coordinator
                .waive_approval_operator(
                    output.change_set_id.clone(),
                    device.clone(),
                    owner.clone(),
                    output.digest.clone(),
                    WaiverKind::OperatorFile,
                    reason,
                    Some(until_unix),
                    ticket,
                )
                .await
            {
                Ok(waived) => waived,
                Err(error) => return tool_error(format!("waiver: {error}")),
            },
            Override::LabMode => match coordinator
                .waive_approval(
                    output.change_set_id.clone(),
                    device.clone(),
                    owner.clone(),
                    output.digest.clone(),
                )
                .await
            {
                Ok(waived) => waived,
                Err(error) => return tool_error(format!("lab-mode: {error}")),
            },
            Override::None => output,
        };

        let response = ChangeSetResponse {
            change_set_id: output.change_set_id,
            state: format!("{:?}", output.state),
            expected_fingerprint,
            preview: preview_text,
            expected_digest: Some(output.digest),
        };

        tool_result(
            Ok::<_, String>(response),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "get_proxmox_change_set",
        description = "Retrieve the current state of a change set."
    )]
    async fn get_change_set(
        &self,
        Parameters(args): Parameters<change_set::ChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::ChangeSetResponse;

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "get_proxmox_change_set",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let coordinator = self.coordinator.clone();

        let device = format!("{}/{}", args.cluster, args.vmid);
        let record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(format!("get: {error}")),
        };

        let preview_text = record
            .preview
            .as_ref()
            .map(|p| p.artifact.clone())
            .unwrap_or_else(|| "(no preview)".to_owned());

        let response = ChangeSetResponse {
            change_set_id: record.id,
            state: format!("{:?}", record.state),
            expected_fingerprint: record.expected_candidate_fingerprint,
            preview: preview_text,
            expected_digest: Some(record.digest),
        };

        tool_result(
            Ok::<_, String>(response),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "approve_proxmox_change_set",
        description = "Approve a planned change set as a second principal."
    )]
    async fn approve_change_set(
        &self,
        Parameters(args): Parameters<change_set::ChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::ChangeSetResponse;

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "approve_proxmox_change_set",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let approver = caller
            .as_ref()
            .map(|ctx| ctx.token_name.clone())
            .unwrap_or_else(|| "stdio".to_owned());

        let coordinator = self.coordinator.clone();

        let device = format!("{}/{}", args.cluster, args.vmid);
        let record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(format!("get: {error}")),
        };

        // A change set with no stored preview must never be approved. The
        // approval digest covers (owner, device, fingerprint, actions) and not
        // the preview, so nothing downstream would notice the absence: this
        // handler used to substitute the literal string "(no preview)" and
        // approve anyway, recording an approval over text no one could read.
        let Some(preview) = record.preview.as_ref() else {
            return tool_error(
                "approval refused: this change set has no stored preview, so there is \
                 nothing to review. Plan the operation again.",
            );
        };

        let output = match coordinator
            .approve_change_set(
                args.change_set_id.clone(),
                device.clone(),
                approver,
                record.digest.clone(),
            )
            .await
        {
            Ok(output) => output,
            Err(error) => {
                let msg = error.to_string();
                // Reword the self-approval error to match test expectations.
                if msg.contains("owner cannot approve their own") {
                    return tool_error(
                        "self-approval refused: the planner cannot approve their own change set",
                    );
                }
                return tool_error(format!("approve: {error}"));
            }
        };

        let preview_text = preview.artifact.clone();

        let response = ChangeSetResponse {
            change_set_id: output.change_set_id,
            state: format!("{:?}", output.state),
            expected_fingerprint: record.expected_candidate_fingerprint,
            preview: preview_text,
            expected_digest: Some(output.digest),
        };

        tool_result(
            Ok::<_, String>(response),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "apply_proxmox_change_set",
        description = "Apply an approved change set."
    )]
    async fn apply_change_set(
        &self,
        Parameters(args): Parameters<change_set::ChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use rust_proxmoxmcp_core::{
            fingerprint::{GuestState, fingerprint},
            protect::{Override, destructive_allowed, protection_of},
        };

        let caller = Self::caller(&context);
        // The evidence records belong to *this* call, not to the change set.
        // `request_id` is the join key transport audit uses, so putting the
        // change-set id there makes two attempts indistinguishable and breaks
        // correlation with the tool call that actually did it. The principal is
        // the caller too: this handler lets a different scoped token apply a set
        // someone else planned, and naming the planner as executor is false.
        let apply_request_id = caller
            .as_ref()
            .map_or_else(|| "stdio".to_owned(), |ctx| ctx.request_id.to_string());
        let apply_principal = caller
            .as_ref()
            .map_or_else(|| "stdio".to_owned(), |ctx| ctx.token_name.clone());
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "apply_proxmox_change_set",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let coordinator = self.coordinator.clone();

        let device = format!("{}/{}", args.cluster, args.vmid);
        let mut record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(format!("get: {error}")),
        };

        // Same invariant as `approve_change_set`, enforced again here because
        // approval and apply are separate tools with separate scopes: a record
        // approved by an older binary must still not execute without a preview.
        if record.preview.is_none() {
            return tool_error(
                "apply refused: this change set has no stored preview, so the action it \
                 would take was never recorded for review. Plan the operation again.",
            );
        }

        // Re-resolve and verify fingerprint.
        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };

        // Drop the cached `/cluster/resources` snapshot before re-resolving.
        //
        // The fingerprint re-check below exists to refuse an apply against a
        // guest that moved since the plan. `GuestIndex` caches that snapshot
        // for `resource_cache_ttl_secs`, so without this the plan and the
        // apply read the *same* cached response and the comparison could not
        // fail -- inside the TTL the whole check was a no-op, and a rename,
        // migration, status change or a newly added `protected` tag would all
        // compare equal.
        //
        // The existing test only caught a move because its harness invalidates
        // the cache itself; production never did. One extra fetch on a
        // destructive apply is not a cost worth trading this for.
        //
        // Scoped to this cluster: a global drop would evict still-valid
        // snapshots for every other cluster, and their next operation would
        // pay a fetch that can fail if that cluster is momentarily
        // unreachable. The generation bump inside is what stops a fetch that
        // started before this point from re-publishing pre-change state.
        self.index.invalidate_cluster(&args.cluster);

        // Resolve guest and compute protection to determine override.
        let guest = match self.index.resolve(client, &args.cluster, args.vmid).await {
            Ok(guest) => guest,
            Err(error) => return tool_error(error),
        };
        let protection = protection_of(client.cluster(), Some(&guest), false);

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs();

        let override_ = destructive_allowed(
            &protection,
            &self.waivers,
            &args.cluster,
            args.vmid,
            now_unix,
            self.lab_mode,
        );

        let override_applies = !matches!(override_, Override::None);

        // Now authorize with the override information.
        let authorized = match self
            .index
            .authorize(
                client,
                &args.cluster,
                args.vmid,
                &grant,
                Intent::destructive(override_applies),
            )
            .await
        {
            Ok(authorized) => authorized,
            Err(error) => return tool_error(error),
        };

        let guest = authorized.guest();

        let state = GuestState {
            cluster: args.cluster.clone(),
            vmid: guest.vmid,
            name: guest.name.clone(),
            kind: guest.r#type.path_segment().to_owned(),
            node: guest.node.clone(),
            status: guest.status.clone(),
            tags: guest.tags.clone(),
            config_digest: String::new(),
            disks: Vec::new(),
        };

        let current_fingerprint = fingerprint(&state);

        if current_fingerprint != record.expected_candidate_fingerprint {
            return tool_error(format!(
                "fingerprint changed (expected {}, got {})",
                record.expected_candidate_fingerprint, current_fingerprint
            ));
        }

        // Verify the change set is approved.
        if record.state != mecmcp_changeset::ChangeSetState::Approved {
            return tool_error(format!(
                "change set not approved (state: {:?})",
                record.state
            ));
        }

        // A guest is about to be destroyed. This is written -- and, with a spool
        // attached, persisted -- *before* the DELETE goes out, and refused if it
        // cannot be. The apply path does not go through `commit_operation`, so
        // nothing else emits it: without this, an approved destroy completes
        // with proposal and approval on the record and no execution evidence at
        // all. A guest destroyed with no record that anyone tried is the exact
        // state this chain exists to rule out, and `purge` makes it permanent.
        if let Some(recorder) = &self.evidence
            && let Err(error) = recorder.apply_intent(
                &apply_request_id,
                &record.id,
                &record.device,
                &apply_principal,
            )
        {
            return tool_error(format!(
                "destroy refused: the apply-intent evidence record could not be persisted \
                 ({error}); the change set is still approved and can be retried"
            ));
        }

        // Dispatch on the action the change set recorded, not on the tool
        // name. The digest covers `actions`, so this is the only description of
        // the work that the approver actually signed; reading the operation
        // from anywhere else would let an apply do something the approval did
        // not cover.
        let action: change_set::DestroyAction = match record.actions.first() {
            Some(value) => match serde_json::from_value(value.clone()) {
                Ok(action) => action,
                Err(error) => {
                    return tool_error(format!(
                        "the change set's action could not be read ({error}); \
                         it cannot be applied"
                    ));
                }
            },
            None => return tool_error("the change set records no action".to_owned()),
        };

        // Again at apply. A scope can be narrowed between plan and apply, and
        // the apply is the call that acts — checking only at plan would let a
        // token whose authority was revoked still execute what it had planned.
        let Some(op_tool) = tool_for_op(&action.op, guest.r#type) else {
            return tool_error(format!(
                "the change set names an unknown operation '{}'",
                action.op
            ));
        };
        if let Err(error) =
            authorize_call(caller.as_ref(), op_tool, Some(&args.cluster), WRITE_TOOLS)
        {
            return tool_error(error);
        }

        let (upid_str, execution_detail) = match self
            .execute_destructive(client, &action, guest.r#type, &state.node, args.vmid)
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                // Proxmox answering "no" and the request vanishing are different
                // facts, and the receipt must not conflate them. An `Api`,
                // `Unauthorized`, `Denied` or `NotFound` means the server
                // answered and refused: definitive, and the trail should say so
                // rather than end at an intent with no outcome. A transport
                // failure or an unparseable response means the DELETE may have
                // been accepted -- recording that as a failure would state the
                // guest still exists when it may not, so the chain is left at
                // apply intent, which is what "go and look" looks like here.
                let definitive = matches!(
                    error,
                    rust_proxmoxmcp_core::ProxmoxError::Api { .. }
                        | rust_proxmoxmcp_core::ProxmoxError::Unauthorized
                        | rust_proxmoxmcp_core::ProxmoxError::Denied(_)
                        | rust_proxmoxmcp_core::ProxmoxError::NotFound { .. }
                );
                if definitive {
                    if let Some(recorder) = &self.evidence
                        && let Err(receipt_error) = recorder.result_receipt(
                            &apply_request_id,
                            &record.id,
                            &record.device,
                            &apply_principal,
                            false,
                            &error.to_string(),
                        )
                    {
                        tracing::error!(%receipt_error, "failure receipt not persisted");
                    }
                    record.state = mecmcp_changeset::ChangeSetState::Failed;
                    let _ = self.coordinator.update_change_set(record).await;
                } else {
                    tracing::error!(
                        %error,
                        "the destroy failed without a definitive answer; the outcome is \
                         indeterminate and no result receipt is emitted"
                    );
                }
                return tool_error(error);
            }
        };

        // A storage that deleted synchronously returns no handle. That is a
        // completed operation, not a failure — parsing the empty string as a
        // UPID would report an error for a volume that is already gone, write
        // no success receipt, and leave the record `Approved` and retryable
        // against a volume that no longer exists.
        if upid_str.is_empty() {
            if let Some(recorder) = &self.evidence
                && let Err(receipt_error) = recorder.result_receipt(
                    &apply_request_id,
                    &record.id,
                    &record.device,
                    &apply_principal,
                    true,
                    "",
                )
            {
                tracing::error!(
                    %receipt_error,
                    change_set_id = %record.id,
                    "the operation completed but its result receipt could not be persisted"
                );
            }

            record.state = mecmcp_changeset::ChangeSetState::Applied;
            record.task_id = None;
            if let Err(error) = self.coordinator.update_change_set(record).await {
                tracing::error!(%error, "could not mark the change set applied");
            }

            // `outcome` describes the apply, not the command. A guest-agent
            // command that ran and exited non-zero is a *completed* apply --
            // what was approved happened -- and its own result is data. Both
            // are reported so neither can be read as the other.
            let mut response = serde_json::json!({
                "outcome": "ok",
                "synchronous": true,
                "upid": serde_json::Value::Null,
            });
            if let Some(detail) = execution_detail
                && let Some(object) = response.as_object_mut()
            {
                {
                    object.insert("execution".to_owned(), detail);
                    object.insert(
                        "note".to_owned(),
                        serde_json::Value::String(
                            "outcome describes the apply; read execution.exit_code for what the \
                             command itself returned"
                                .to_owned(),
                        ),
                    );
                }
            }

            return tool_result::<_, String>(Ok(response), ResultFormat::PrettyJson, RESULT_LIMITS);
        }

        // Parse the UPID to extract the node for polling.
        // Per spec §7, the node is authoritative: guests migrate, so we must
        // poll the node from the UPID, never a caller-supplied one.
        let upid = match rust_proxmoxmcp_core::task::Upid::parse(&upid_str) {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        // Persist the UPID BEFORE polling (spec §8).
        //
        // The window this closes is between Proxmox accepting the operation and
        // this process observing its result. A crash in that window used to
        // leave the record in `Applying` with nothing recorded about which
        // vendor operation to ask after — detectable, but resolvable only by a
        // human reading the device. With the handle on disk, `recover_in_flight`
        // can re-probe it at startup.
        //
        // A failure to persist is logged rather than fatal: the destructive
        // operation has already been accepted by Proxmox, so refusing here
        // would abandon a running task *and* report failure for something that
        // is going to happen anyway. Losing the handle is worse than the write
        // failing quietly, so it is said loudly instead.
        {
            let mut in_flight = record.clone();
            // `Applying`, not the `Approved` snapshot this was verified from.
            // `recover_in_flight` looks for `Applying` plus a handle, so
            // persisting `Approved + task_id` would store the handle somewhere
            // recovery never looks — and would leave the set approved, so a
            // retry could issue a second destroy against a guest the first one
            // already removed.
            in_flight.state = mecmcp_changeset::ChangeSetState::Applying;
            in_flight.task_id = Some(upid_str.clone());
            if let Err(error) = self.coordinator.update_change_set(in_flight).await {
                tracing::error!(
                    target: "audit",
                    %error,
                    change_set = %record.id,
                    upid = %upid_str,
                    "task handle not persisted; a crash now leaves this apply unrecoverable"
                );
            }
        }

        // Poll the task to completion using mecmcp_job.
        let token = tokio_util::sync::CancellationToken::new();
        let config = mecmcp_job::PollConfig {
            first_interval: std::time::Duration::from_secs(1),
            max_interval: std::time::Duration::from_secs(8),
            multiplier: 2,
            deadline: std::time::Duration::from_secs(300),
        };

        let poll_node = upid.node().to_owned();
        let poll_upid = upid_str.clone();
        let exitstatus = match mecmcp_job::poll_until_ready(&token, config, |_attempt| {
            let node = poll_node.clone();
            let upid_str = poll_upid.clone();
            async move {
                // URL-encode the UPID for the path.
                let upid_encoded = upid_str.replace(':', "%3A");
                let path = format!("/api2/json/nodes/{node}/tasks/{upid_encoded}/status");
                let data = client
                    .get_json(&path, &[], &[])
                    .await
                    .map_err(|error| format!("task status request failed: {error}"))?;

                let status = data
                    .get("status")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "status field missing or not a string".to_string())?;

                if status == "running" {
                    Ok(mecmcp_job::Probe::Pending)
                } else if status == "stopped" {
                    let exitstatus = data
                        .get("exitstatus")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "exitstatus field missing or not a string".to_string())?;
                    Ok(mecmcp_job::Probe::Ready(exitstatus.to_owned()))
                } else {
                    Err(format!("unexpected task status: {status}"))
                }
            }
        })
        .await
        {
            Ok(exitstatus) => exitstatus,
            Err(mecmcp_job::PollError::Cancelled { attempts }) => {
                return tool_error(format!("polling cancelled after {attempts} attempt(s)"));
            }
            Err(mecmcp_job::PollError::DeadlineExceeded { attempts, deadline }) => {
                return tool_error(format!(
                    "polling exceeded its {deadline:?} deadline after {attempts} attempt(s)"
                ));
            }
            Err(mecmcp_job::PollError::Probe { attempts, source }) => {
                return tool_error(format!("probe failed on attempt {attempts}: {source}"));
            }
            Err(mecmcp_job::PollError::Config(error)) => {
                return tool_error(format!("invalid poll configuration: {error}"));
            }
        };

        // Classify the exit status using the Task 3 classifier.
        let outcome = rust_proxmoxmcp_core::task::classify_exit_status(&exitstatus);

        // Proxmox answered. A failure is recorded as fully as a success -- a
        // trail that only shows what worked cannot answer the question anyone
        // asks it. This cannot fail closed: the guest is already gone.
        if let Some(recorder) = &self.evidence {
            let succeeded = matches!(outcome, rust_proxmoxmcp_core::task::TaskOutcome::Ok);
            if let Err(error) = recorder.result_receipt(
                &apply_request_id,
                &record.id,
                &record.device,
                &apply_principal,
                succeeded,
                if succeeded { "" } else { &exitstatus },
            ) {
                tracing::error!(
                    %error,
                    change_set_id = %record.id,
                    "the destroy completed but its result receipt could not be persisted; \
                     the evidence chain ends at apply intent"
                );
            }
        }

        match outcome {
            rust_proxmoxmcp_core::task::TaskOutcome::Ok => {
                record.state = mecmcp_changeset::ChangeSetState::Applied;
                // The outcome is known, so the handle has nothing left to
                // recover. Leaving it set would make a finished apply look
                // in-flight to `recover_in_flight` on the next start.
                record.task_id = None;
                if let Err(error) = self.coordinator.update_change_set(record).await {
                    tracing::error!(%error, "could not mark the change set applied");
                }
                let response = serde_json::json!({
                    "outcome": "ok",
                    "upid": upid_str,
                    "exitstatus": exitstatus,
                });
                tool_result(
                    Ok::<_, String>(response),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                )
            }
            rust_proxmoxmcp_core::task::TaskOutcome::Failed(message) => {
                // Finalise the set. `result_receipt` is terminal -- it forgets
                // the change's proposal context -- so leaving this `Approved`
                // invites a retry whose intent and receipt would carry an empty
                // digest and principal, which is worse than refusing the retry.
                // A fresh plan is the correct path after a failed destroy.
                record.state = mecmcp_changeset::ChangeSetState::Failed;
                record.task_id = None;
                if let Err(error) = self.coordinator.update_change_set(record).await {
                    tracing::error!(%error, "could not mark the change set failed");
                }
                tool_error(format!("task failed: {message}"))
            }
        }
    }
}

/// Wrap a filtered tool list in the result shape a 2026-07-28 client accepts.
///
/// `ListToolsResult::with_all_items` leaves `ttl_ms` and `cache_scope` unset and
/// both are omitted on the wire; a client on that protocol validates the result
/// and rejects it, which surfaces as "tools fetch failed" against a server that
/// is healthy and answering in milliseconds. Servers that do not override
/// `list_tools` get these from rmcp's generated handler — this one filters by
/// scope, so it supplies them itself.
///
/// Gated on the negotiated version exactly as rmcp does: the fields belong to
/// 2026-07-28 and later, and a strict legacy client rejects what it did not
/// negotiate.
///
/// `private` where rmcp's unfiltered list says `public`, because this list is
/// per token: a cache keyed only on the URL must not serve one caller's
/// permitted surface to another.
fn listed_tools(tools: Vec<rmcp::model::Tool>, cache_hints: bool) -> ListToolsResult {
    let listed = ListToolsResult::with_all_items(tools);
    if cache_hints {
        listed
            .with_ttl_ms(0)
            .with_cache_scope(rmcp::model::CacheScope::Private)
    } else {
        listed
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ProxmoxServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "rust-proxmoxmcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "Proxmox VE MCP server. Guest-addressed tools take (cluster, vmid); \
                 the server resolves the node itself because guests migrate.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<ProxmoxGrant>(&context.extensions);
        let all_tools = self.tool_router.list_all();
        let visible = filter_tools_for_scope(all_tools, caller, WRITE_TOOLS);
        // `with_all_items` leaves `ttl_ms` and `cache_scope` unset, and both
        // are omitted on the wire. A 2026-07-28 client validates the tools/list
        // result and rejects one without them — reported as "tools fetch
        // failed" against a server that is otherwise healthy and fast. Servers
        // that do not override `list_tools` get these from rmcp's generated
        // handler; this one filters by scope, so it supplies them itself.
        //
        // `private`: the list is per token, so a cache keyed only on the URL
        // must not serve one caller's surface to another.
        let cache_hints = context
            .protocol_version()
            .is_some_and(|version| version >= rmcp::model::ProtocolVersion::V_2026_07_28);
        Ok(listed_tools(visible, cache_hints))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tools_includes_read_catalog_and_changeset_tools() {
        // Read tools from catalog.
        let read_tools: std::collections::HashSet<&str> = rust_proxmoxmcp_core::catalog::READ_TOOLS
            .iter()
            .map(|tool| tool.name)
            .collect();

        // Changeset tools added in Task 6.
        let changeset_tools = [
            "plan_proxmox_destroy",
            "get_proxmox_change_set",
            "approve_proxmox_change_set",
            "apply_proxmox_change_set",
        ];

        // Low-tier tools added in 0.4. Listed rather than derived from
        // WRITE_TOOLS, because that registry deliberately names tools no
        // release has registered yet — deriving from it would let this test
        // pass for a tool that does not exist.
        let low_tools = [
            "clone_vm",
            "create_backup",
            "create_container",
            "create_snapshot",
            "create_vm",
            "download_iso",
            "plan_proxmox_exec",
            "reset_vm",
            "resize_disk",
            "stop_task",
            "restart_container",
            "shutdown_vm",
            "start_container",
            "start_vm",
            "stop_container",
            "stop_vm",
            "update_container_resources",
        ];

        for tool in KNOWN_TOOLS {
            assert!(
                read_tools.contains(tool)
                    || changeset_tools.contains(tool)
                    || low_tools.contains(tool)
                    || AUTHORIZATION_ONLY_TOOLS.contains(tool),
                "{tool} is in KNOWN_TOOLS but not in READ_TOOLS, changeset, low-tier, \
                 or authorization-only tools"
            );
        }

        // Every low-tier tool is registered, and every one is in WRITE_TOOLS so
        // a wildcard token cannot reach it.
        for tool in &low_tools {
            assert!(
                KNOWN_TOOLS.contains(tool),
                "low-tier tool {tool} missing from KNOWN_TOOLS"
            );
            assert!(
                rust_proxmoxmcp_core::tier::WRITE_TOOLS.contains(tool),
                "low-tier tool {tool} is not in WRITE_TOOLS, so a wildcard token would reach it"
            );
        }

        // Verify changeset tools are present.
        for tool in &changeset_tools {
            assert!(
                KNOWN_TOOLS.contains(tool),
                "changeset tool {tool} missing from KNOWN_TOOLS"
            );
        }
    }

    #[test]
    fn changeset_write_tools_are_registered() {
        let changeset_write = [
            "plan_proxmox_destroy",
            "approve_proxmox_change_set",
            "apply_proxmox_change_set",
        ];
        for tool in &changeset_write {
            assert!(
                KNOWN_TOOLS.contains(tool),
                "changeset write tool {tool} must be registered"
            );
        }
    }

    #[test]
    fn known_tools_is_sorted_so_review_diffs_stay_readable() {
        let mut sorted = KNOWN_TOOLS.to_vec();
        sorted.sort_unstable();
        assert_eq!(KNOWN_TOOLS, sorted.as_slice());
    }

    #[test]
    fn every_known_tool_has_a_registered_handler() {
        // KNOWN_TOOLS is hand-maintained; the router is generated from #[tool]
        // attributes. Nothing else in the build makes them agree.
        let router = ProxmoxServer::proxmox_tool_router();
        let registered: std::collections::BTreeSet<String> = router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect();
        for name in KNOWN_TOOLS {
            // The authorization-only names deliberately have no handler: the
            // generic plan/apply handlers do the work, and these exist so a
            // token can be scoped to one operation rather than all of them.
            if AUTHORIZATION_ONLY_TOOLS.contains(name) {
                continue;
            }
            assert!(
                registered.contains(*name),
                "{name} is in KNOWN_TOOLS but has no #[tool] handler"
            );
        }
        // Compare against the names that actually have handlers: the
        // authorization-only entries are in KNOWN_TOOLS by design and the
        // router will never list them.
        let handler_names = KNOWN_TOOLS
            .iter()
            .filter(|name| !AUTHORIZATION_ONLY_TOOLS.contains(*name))
            .count();
        assert_eq!(
            registered.len(),
            handler_names,
            "router has tools absent from KNOWN_TOOLS"
        );
    }

    #[test]
    fn authenticated_token_without_grant_is_refused() {
        use mecmcp_auth::{ActorType, ScopeSet};

        // An authenticated caller (Some) with no grant (grant: None) must be refused.
        // This is the grantless-token case: a token that omits the 'grant' key in
        // tokens.json produces CallerCtx { grant: None, ... }.
        let grantless_caller = CallerCtx {
            token_name: "test-grantless-token".to_owned(),
            grant: None,
            tools: ScopeSet::Wildcard,
            devices: ScopeSet::Wildcard,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Agent,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };

        let result = resolve_grant(Some(&grantless_caller));
        assert!(
            result.is_err(),
            "grantless authenticated token must be refused, not granted wildcard access"
        );

        // The error must name the token so the operator can find it in tokens.json.
        let error_result = result.expect_err("already checked is_err");
        let error_text = format!("{error_result:?}");
        assert!(
            error_text.contains("test-grantless-token"),
            "error message must name the token: {error_text}"
        );
        assert!(
            error_text.contains("guests"),
            "error message must mention 'guests' selector: {error_text}"
        );
    }

    #[test]
    fn stdio_path_gets_wildcard_read_grant() {
        // The stdio path (caller = None, no bearer token) gets the wildcard read grant.
        let grant = resolve_grant(None).expect("stdio path should succeed");
        assert_eq!(
            grant.guests.len(),
            1,
            "read_only grant should have one selector"
        );
        // The read_only grant is constructed as guests: ["*"], actions: [Read]
    }
}

#[cfg(test)]
mod tools_list_cache_tests {
    use super::listed_tools;

    /// A 2026-07-28 client rejects a tools/list without these, and the failure
    /// reads as an unreachable server rather than a malformed reply.
    #[test]
    fn a_modern_client_gets_a_private_cache_descriptor() {
        let listed = listed_tools(Vec::new(), true);
        assert_eq!(
            listed.ttl_ms,
            Some(0),
            "a 2026-07-28 client rejects a tools/list without ttlMs"
        );
        assert_eq!(
            listed.cache_scope,
            Some(rmcp::model::CacheScope::Private),
            "the list is filtered per token, so it must not be shared"
        );
    }

    /// The fields are not part of the older result shape, and a strict legacy
    /// client rejects what it did not negotiate.
    #[test]
    fn a_legacy_client_gets_no_cache_descriptor() {
        let listed = listed_tools(Vec::new(), false);
        assert_eq!(listed.ttl_ms, None);
        assert_eq!(listed.cache_scope, None);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod destructive_action_tests {
    use super::build_destroy_action;
    use crate::server::change_set::PlanDestroyArgs;

    fn args(op: &str) -> PlanDestroyArgs {
        PlanDestroyArgs {
            cluster: "pve3".to_owned(),
            vmid: 617,
            op: op.to_owned(),
            snapname: None,
            storage: None,
            volid: None,
            storage_node: None,
        }
    }

    /// A caller written against 0.3 passed no `op` and meant a destroy. Serde
    /// fills the default, so that plan must still build the same action.
    #[test]
    fn the_default_operation_is_a_guest_destroy() {
        let action = build_destroy_action(&args("destroy_guest")).unwrap();
        assert_eq!(action.op, "destroy_guest");
        assert_eq!(action.vmid, 617);
        assert!(action.snapname.is_none());
    }

    /// Each operation names exactly what it needs, refused at plan time rather
    /// than defaulted at apply time — the action is what the digest covers, so
    /// anything undecided now is something the approver cannot review.
    #[test]
    fn a_missing_parameter_is_refused_at_plan_time() {
        for (op, missing) in [
            ("delete_snapshot", "snapname"),
            ("rollback_snapshot", "snapname"),
            ("delete_backup", "storage"),
            ("restore_backup", "volid"),
        ] {
            let error = build_destroy_action(&args(op)).expect_err("must be refused");
            assert!(
                error.contains(missing),
                "{op}: the refusal must name the missing parameter, got: {error}"
            );
        }
    }

    /// An empty string is not a parameter.
    #[test]
    fn an_empty_parameter_counts_as_missing() {
        let mut a = args("delete_snapshot");
        a.snapname = Some(String::new());
        assert!(build_destroy_action(&a).is_err());
    }

    /// A typo must not become a change set nobody can execute.
    #[test]
    fn an_unknown_operation_is_refused_with_the_valid_set() {
        let error = build_destroy_action(&args("delete_everything")).expect_err("refused");
        assert!(error.contains("unknown destructive operation"), "{error}");
        assert!(
            error.contains("rollback_snapshot"),
            "the refusal should list what is valid, got: {error}"
        );
    }

    /// `restore_backup` takes no storage: the archive volid names its own, and
    /// accepting a second one invites the two to disagree.
    #[test]
    fn restore_takes_the_volid_alone() {
        let mut a = args("restore_backup");
        a.volid = Some("local:backup/vzdump-lxc-617.tar.zst".to_owned());
        a.storage = Some("ignored".to_owned());
        let action = build_destroy_action(&a).unwrap();
        assert!(
            action.storage.is_none(),
            "a storage passed to restore must not reach the action"
        );
        assert_eq!(
            action.volid.as_deref(),
            Some("local:backup/vzdump-lxc-617.tar.zst")
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod destructive_scope_tests {
    use super::{build_destroy_action, render_destructive_preview, tool_for_op};
    use crate::server::change_set::PlanDestroyArgs;
    use rust_proxmoxmcp_core::selector::GuestType;

    /// Every operation authorises against its own tool name, so a token
    /// allowlisted only for the generic handlers cannot select any operation
    /// it likes.
    #[test]
    fn every_operation_maps_to_its_own_tool() {
        for (op, tool) in [
            ("destroy_guest", "delete_vm"),
            ("destroy", "delete_vm"),
            ("delete_snapshot", "delete_snapshot"),
            ("rollback_snapshot", "rollback_snapshot"),
            ("delete_backup", "delete_backup"),
            ("delete_iso", "delete_iso"),
            ("restore_backup", "restore_backup"),
        ] {
            assert_eq!(tool_for_op(op, GuestType::Qemu), Some(tool), "{op}");
        }
        assert_eq!(tool_for_op("delete_everything", GuestType::Qemu), None);
    }

    /// Every mapped tool is in WRITE_TOOLS, or the scope check would be
    /// authorising against a name a wildcard token already reaches.
    #[test]
    fn every_mapped_tool_is_excluded_from_the_wildcard() {
        for op in [
            "destroy_guest",
            "delete_snapshot",
            "rollback_snapshot",
            "delete_backup",
            "delete_iso",
            "restore_backup",
        ] {
            let tool = tool_for_op(op, GuestType::Qemu).unwrap();
            assert!(
                rust_proxmoxmcp_core::tier::WRITE_TOOLS.contains(&tool),
                "{tool} is not in WRITE_TOOLS, so a wildcard token would reach it"
            );
        }
    }

    fn action(
        op: &str,
        snapname: Option<&str>,
        volid: Option<&str>,
    ) -> super::change_set::DestroyAction {
        super::change_set::DestroyAction {
            op: op.to_owned(),
            cluster: "pve3".to_owned(),
            vmid: 617,
            snapname: snapname.map(ToOwned::to_owned),
            storage: Some("local".to_owned()),
            volid: volid.map(ToOwned::to_owned),
            storage_node: Some("pve2".to_owned()),
            command: None,
        }
    }

    /// The preview must describe the operation that will run. Reusing the
    /// guest-destroy renderer showed `DESTROY` for a rollback, a restore and a
    /// volume delete alike — an approver would have signed off on a different
    /// operation than the one recorded.
    #[test]
    fn each_operation_previews_as_itself() {
        let cases = [
            ("delete_snapshot", "DELETE SNAPSHOT"),
            ("rollback_snapshot", "ROLLBACK"),
            ("delete_backup", "DELETE BACKUP"),
            ("delete_iso", "DELETE ISO"),
            ("restore_backup", "RESTORE"),
        ];
        for (op, expected) in cases {
            let text = render_destructive_preview(
                &action(op, Some("snap"), Some("local:backup/x")),
                "g",
                "pve2",
            );
            assert!(text.starts_with(expected), "{op}: {text}");
            assert!(
                !text.starts_with("DESTROY"),
                "{op} previewed as a guest destroy"
            );
        }
    }

    /// The two that replace state rather than remove an object must say so.
    /// An approver reading "delete" for a rollback would not know that
    /// everything written since the snapshot is lost.
    #[test]
    fn replacing_operations_warn_that_state_is_overwritten() {
        let rollback =
            render_destructive_preview(&action("rollback_snapshot", Some("s"), None), "g", "pve2");
        assert!(rollback.contains("OVERWRITES"), "{rollback}");
        let restore = render_destructive_preview(
            &action("restore_backup", None, Some("local:backup/x")),
            "g",
            "pve2",
        );
        assert!(restore.contains("OVERWRITES"), "{restore}");
    }

    /// A volume's node is part of its identity, because `local` is node-local.
    #[test]
    fn a_volume_operation_requires_its_storage_node() {
        let args = PlanDestroyArgs {
            cluster: "pve3".to_owned(),
            vmid: 617,
            op: "delete_backup".to_owned(),
            snapname: None,
            storage: Some("local".to_owned()),
            volid: Some("local:backup/x".to_owned()),
            storage_node: None,
        };
        let error = build_destroy_action(&args).expect_err("storage_node is required");
        assert!(error.contains("storage_node"), "{error}");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod grantable_scope_tests {
    use super::{KNOWN_TOOLS, tool_for_op};
    use rust_proxmoxmcp_core::selector::GuestType;

    /// Every name the scope check demands must be grantable through the token
    /// CLI, which validates against `KNOWN_TOOLS`.
    ///
    /// This is the test that was missing. The check landed without it and made
    /// the whole destructive tier unusable: `token add --tools delete_snapshot`
    /// was refused as an unknown tool, and a wildcard excludes these by design,
    /// so no token could plan or apply *any* destructive operation. The unit
    /// tests passed throughout because they build tokens directly and never
    /// cross the CLI's validation.
    #[test]
    fn every_operation_scope_is_grantable() {
        for op in [
            "destroy_guest",
            "destroy",
            "delete_snapshot",
            "rollback_snapshot",
            "delete_backup",
            "delete_iso",
            "restore_backup",
        ] {
            for kind in [GuestType::Lxc, GuestType::Qemu] {
                let tool = tool_for_op(op, kind).unwrap();
                assert!(
                    KNOWN_TOOLS.contains(&tool),
                    "{op} authorises against '{tool}', which the token CLI rejects as unknown"
                );
            }
        }
    }

    /// ...and every one of them stays excluded from the tool wildcard, or
    /// making them grantable would have handed them to every `*` token.
    #[test]
    fn grantable_does_not_mean_reachable_by_wildcard() {
        for op in ["destroy_guest", "delete_snapshot", "restore_backup"] {
            for kind in [GuestType::Lxc, GuestType::Qemu] {
                let tool = tool_for_op(op, kind).unwrap();
                assert!(
                    rust_proxmoxmcp_core::tier::WRITE_TOOLS.contains(&tool),
                    "{tool} became reachable by a wildcard token"
                );
            }
        }
    }

    /// A container destroy and a VM destroy are different scopes. Mapping both
    /// to `delete_vm` denied a `delete_container` token its own containers, and
    /// let a `delete_vm` token delete them.
    #[test]
    fn a_guest_destroy_authorises_against_its_guest_type() {
        assert_eq!(
            tool_for_op("destroy_guest", GuestType::Lxc),
            Some("delete_container")
        );
        assert_eq!(
            tool_for_op("destroy_guest", GuestType::Qemu),
            Some("delete_vm")
        );
        // The 0.3 spelling maps the same way.
        assert_eq!(
            tool_for_op("destroy", GuestType::Lxc),
            Some("delete_container")
        );
    }
}
