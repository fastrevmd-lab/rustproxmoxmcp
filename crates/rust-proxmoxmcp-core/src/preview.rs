//! Server-generated destroy preview for change-set approval.
//!
//! The preview is the evidence a human approver reads before approving a
//! destructive operation. It renders the server's own account of the target
//! rather than the calling agent's claim, so an agent cannot fabricate the
//! protection status or the override authority.

use crate::fingerprint::GuestState;
use crate::protect::Override;

/// Input for rendering a destroy preview.
#[derive(Debug)]
pub struct PreviewInput<'a> {
    /// Guest state snapshot.
    pub state: &'a GuestState,
    /// Whether the guest is protected.
    pub protected: bool,
    /// One-line protection summary.
    pub protection_summary: &'a str,
    /// Override allowing the operation, if any.
    pub override_: &'a Override,
    /// Number of snapshots.
    pub snapshots: usize,
    /// Latest snapshot name and date, if any.
    pub latest_snapshot: Option<&'a str>,
    /// Last backup date and retention count, if any.
    pub last_backup: Option<&'a str>,
    /// Whether to purge disks after destroy.
    pub purge_disks: bool,
}

/// Render a destroy preview for change-set approval.
///
/// The preview is the evidence a human approver reads. Every line is rendered
/// every time, including `waiver     none` — an omitted line reads as "not
/// applicable"; a present line reading `none` is evidence the server looked.
///
/// Backup age is reported and never gates the verdict (spec §4.5). Enforcing
/// a backup precondition would imply the backup restores, and this estate has
/// a documented counter-example (ssdf-clickhouse).
pub fn render_preview(input: &PreviewInput<'_>) -> String {
    let mut lines = Vec::new();

    // Header: DESTROY  cluster / vmid name  (kind, status)
    lines.push(format!(
        "DESTROY  {} / {} {}  ({}, {})",
        input.state.cluster,
        input.state.vmid,
        input.state.name,
        input.state.kind,
        input.state.status
    ));

    // tags line
    let tags_line = if input.state.tags.is_empty() {
        "  tags       (none)".to_owned()
    } else {
        let tags_str = input.state.tags.join(", ");
        if input.protected {
            format!("  tags       {}          ← PROTECTED", tags_str)
        } else {
            format!("  tags       {}", tags_str)
        }
    };
    lines.push(tags_line);

    // node line
    lines.push(format!("  node       {}", input.state.node));

    // disks line
    let disks_str = if input.state.disks.is_empty() {
        "(none)".to_owned()
    } else {
        input
            .state
            .disks
            .iter()
            .map(|(name, bytes)| format!("{} {}", name, format_size(*bytes)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let purge_str = if input.purge_disks { "yes" } else { "no" };
    lines.push(format!(
        "  disks      {}    (purge: {})",
        disks_str, purge_str
    ));

    // snapshots line
    let snapshots_line = if let Some(latest) = input.latest_snapshot {
        format!("  snapshots  {}   latest: {}", input.snapshots, latest)
    } else if input.snapshots > 0 {
        format!("  snapshots  {}", input.snapshots)
    } else {
        "  snapshots  0".to_owned()
    };
    lines.push(snapshots_line);

    // backups line — ALWAYS present, spec §4.5
    let backups_line = if let Some(backup_info) = input.last_backup {
        format!("  backups    last: {}", backup_info)
    } else {
        "  backups    none".to_owned()
    };
    lines.push(backups_line);

    // waiver line — ALWAYS present
    let waiver_line = match input.override_ {
        Override::None => "  waiver     none".to_owned(),
        Override::Waiver { reason, ticket, .. } => {
            if let Some(ticket) = ticket {
                format!("  waiver     {} — {}", ticket, reason)
            } else {
                format!("  waiver     {}", reason)
            }
        }
        Override::LabMode => "  waiver     lab-mode".to_owned(),
    };
    lines.push(waiver_line);

    // verdict line — only if protected with no override
    if input.protected && matches!(input.override_, Override::None) {
        lines.push("  verdict    REFUSED — protected, no waiver".to_owned());
    }

    lines.join("\n")
}

/// Format a byte count as human-readable size.
fn format_size(bytes: u64) -> String {
    const GB: u64 = 1024 * 1024 * 1024;
    const MB: u64 = 1024 * 1024;

    if bytes >= GB {
        let gb = bytes / GB;
        format!("{}G", gb)
    } else if bytes >= MB {
        let mb = bytes / MB;
        format!("{}M", mb)
    } else {
        format!("{}B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::GuestState;
    use crate::protect::Override;

    fn base_state() -> GuestState {
        GuestState {
            cluster: "pve3".to_owned(),
            vmid: 907,
            name: "vsrx-ci".to_owned(),
            kind: "qemu".to_owned(),
            node: "pve2".to_owned(),
            status: "running".to_owned(),
            tags: vec!["ci".to_owned(), "protected".to_owned()],
            config_digest: "abc123".to_owned(),
            disks: vec![
                ("scsi0".to_owned(), 64 * 1024 * 1024 * 1024),
                ("scsi1".to_owned(), 8 * 1024 * 1024 * 1024),
            ],
        }
    }

    fn base_input<'a>(state: &'a GuestState, override_: &'a Override) -> PreviewInput<'a> {
        PreviewInput {
            state,
            protected: true,
            protection_summary: "tag:protected",
            override_,
            snapshots: 3,
            latest_snapshot: Some("proven-0.19.0  (2026-08-11)"),
            last_backup: Some("2026-08-09 (3d ago), 2 retained"),
            purge_disks: true,
        }
    }

    #[test]
    fn header_line_shows_cluster_vmid_name_kind_status() {
        let state = base_state();
        let override_ = Override::None;
        let input = base_input(&state, &override_);
        let text = render_preview(&input);
        assert!(
            text.starts_with("DESTROY  pve3 / 907 vsrx-ci  (qemu, running)"),
            "unexpected header: {}",
            text.lines().next().unwrap_or("")
        );
    }

    #[test]
    fn disks_are_formatted_in_human_readable_units() {
        let state = base_state();
        let override_ = Override::None;
        let input = base_input(&state, &override_);
        let text = render_preview(&input);
        assert!(text.contains("scsi0 64G"), "disks were {}", text);
        assert!(text.contains("scsi1 8G"), "disks were {}", text);
    }
}
