//! Change-set lifecycle for PVE 9 HA rules.
//!
//! Mirrors the guest destructive change-set in `change_set.rs` -- plan,
//! approve, apply, with two-principal control and a fingerprint that refuses
//! an apply against a rule that changed since the plan -- but for a cluster
//! resource rather than a guest. There is no vendor task to poll: an HA rule
//! write answers synchronously. No write reaches `/cluster/ha/rules` except
//! through this plan → approve → apply path.
//!
//! The rule itself belongs to no one guest, but it moves the guests it names.
//! So beyond the cluster and tool scopes, plan and apply both run
//! `ProxmoxServer::authorize_ha_rule_guests` over every guest the change and
//! the current rule name: the `destructive` action tier, the caller's guest
//! selector, and the `protected`-tag/inventory-pin guard, exactly as a
//! destroy plan of each of those guests would be gated.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Arguments for planning an HA rule change.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PlanHaRuleArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// HA rule id. Proxmox's own naming rules apply (lowercase letters,
    /// digits, hyphens and underscores).
    pub rule: String,
    /// `create`, `update` or `delete`. Defaults to `create`.
    #[serde(default = "default_ha_rule_op")]
    pub op: String,
    /// `node-affinity` or `resource-affinity`. Required for `create`; must be
    /// omitted for `update` and `delete` -- Proxmox does not let a rule
    /// change type. `location` and `colocation` (the pre-PVE-9-GA names) are
    /// accepted as deprecated aliases for the two, respectively.
    #[serde(default)]
    pub rule_type: Option<String>,
    /// Resource ids the rule applies to, e.g. `["vm:100", "ct:200"]`.
    /// Required for `create`; optional for `update` (replaces the list);
    /// must be omitted for `delete`. Sent to Proxmox as `resources`.
    #[serde(default)]
    pub resources: Option<Vec<String>>,
    /// Deprecated alias for `resources`, kept for callers written against
    /// the pre-PVE-9-GA field name. Give one of the two, not both.
    #[serde(default)]
    pub services: Option<Vec<String>>,
    /// `node-affinity` only: comma-separated `node[:priority]` entries.
    /// Required when creating a `node-affinity` rule.
    #[serde(default)]
    pub nodes: Option<String>,
    /// `resource-affinity` only: `positive` (keep together) or `negative`
    /// (keep apart). Required when creating a `resource-affinity` rule.
    #[serde(default)]
    pub affinity: Option<String>,
    /// Whether the rule is strict rather than advisory.
    #[serde(default)]
    pub strict: Option<bool>,
    /// Free-text comment.
    #[serde(default)]
    pub comment: Option<String>,
    /// Create or leave the rule disabled.
    #[serde(default)]
    pub disable: Option<bool>,
}

fn default_ha_rule_op() -> String {
    "create".to_owned()
}

/// Arguments identifying an HA rule change set.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct HaChangeSetArgs {
    /// Change set identifier.
    pub change_set_id: String,
    /// Inventory name of the cluster.
    pub cluster: String,
    /// HA rule id.
    pub rule: String,
}

/// Action for an HA rule change.
///
/// `op` is the discriminant; the remaining fields are its parameters. As with
/// `change_set::DestroyAction`, this is what the change-set digest covers and
/// what `apply_ha_rule_change` dispatches on -- never the raw plan arguments,
/// which a caller could resubmit differently between plan and apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HaRuleAction {
    pub op: String,
    pub cluster: String,
    pub rule: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affinity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable: Option<bool>,
}

/// The device key `ChangesetCoordinator` tracks this rule's change sets under.
///
/// `ha-rule:` cannot collide with a guest device key (`"{cluster}/{vmid}"`,
/// always digits after the slash), so the two families of change sets never
/// contend for the same coordinator slot even though they share one
/// coordinator instance.
pub(crate) fn ha_rule_device(cluster: &str, rule: &str) -> String {
    format!("{cluster}/ha-rule:{rule}")
}

/// The concrete tool name an HA rule operation authorises against.
///
/// Same reasoning as `tool_for_op` in `mod.rs`: `plan_ha_rule_change` and
/// `apply_ha_rule_change` are generic, so a token scoped only to those could
/// otherwise select any operation regardless of which one `WRITE_TOOLS` says
/// it holds.
pub(crate) const fn tool_for_ha_op(op: &str) -> Option<&'static str> {
    match op.as_bytes() {
        b"create" => Some("create_ha_rule"),
        b"update" => Some("update_ha_rule"),
        b"delete" => Some("delete_ha_rule"),
        _ => None,
    }
}

/// Build and validate the action a plan will record.
///
/// # Errors
///
/// Returns a human-readable message for a caller-facing tool error.
pub(crate) fn build_ha_rule_action(args: &PlanHaRuleArgs) -> Result<HaRuleAction, String> {
    rust_proxmoxmcp_core::guests::validate_path_segment(&args.rule, "rule")
        .map_err(|error| format!("rule id refused: {error}"))?;

    match args.op.as_str() {
        "create" => build_create_or_update(args, true),
        "update" => build_create_or_update(args, false),
        "delete" => {
            for (value, name) in [
                (&args.rule_type, "rule_type"),
                (&args.nodes, "nodes"),
                (&args.affinity, "affinity"),
            ] {
                if value.is_some() {
                    return Err(format!("delete does not take {name}"));
                }
            }
            if args.resources.is_some() || args.services.is_some() {
                return Err("delete does not take resources".to_owned());
            }
            Ok(HaRuleAction {
                op: "delete".to_owned(),
                cluster: args.cluster.clone(),
                rule: args.rule.clone(),
                rule_type: None,
                resources: None,
                nodes: None,
                affinity: None,
                strict: None,
                comment: None,
                disable: None,
            })
        }
        other => Err(format!(
            "unknown HA rule operation '{other}'; expected one of create, update, delete"
        )),
    }
}

/// Merge `resources` and its deprecated `services` alias.
///
/// Only one may be given: accepting both silently would leave it unclear
/// which one wins, and Proxmox's API takes a single `resources` field.
fn merge_resources_alias(args: &PlanHaRuleArgs) -> Result<Option<Vec<String>>, String> {
    match (&args.resources, &args.services) {
        (Some(_), Some(_)) => Err(
            "give only one of 'resources' or the deprecated 'services' alias, not both".to_owned(),
        ),
        (Some(resources), None) => Ok(Some(resources.clone())),
        (None, Some(services)) => Ok(Some(services.clone())),
        (None, None) => Ok(None),
    }
}

/// Normalise a caller-supplied rule type, accepting the pre-PVE-9-GA names
/// (`location`, `colocation`) as deprecated aliases for the current ones
/// (`node-affinity`, `resource-affinity`). Any other value passes through
/// unchanged for the caller below to reject.
fn normalise_rule_type(rule_type: &str) -> &str {
    match rule_type {
        "location" => "node-affinity",
        "colocation" => "resource-affinity",
        other => other,
    }
}

fn build_create_or_update(args: &PlanHaRuleArgs, is_create: bool) -> Result<HaRuleAction, String> {
    let rule_type = if is_create {
        let rule_type = args
            .rule_type
            .clone()
            .ok_or_else(|| "create requires rule_type".to_owned())?;
        let normalised = normalise_rule_type(&rule_type).to_owned();
        if normalised != "node-affinity" && normalised != "resource-affinity" {
            return Err(format!(
                "rule_type must be 'node-affinity' or 'resource-affinity', got '{rule_type}'"
            ));
        }
        Some(normalised)
    } else {
        if args.rule_type.is_some() {
            return Err(
                "update does not take rule_type; Proxmox cannot change a rule's type, \
                         delete and recreate it instead"
                    .to_owned(),
            );
        }
        None
    };

    let resources = match merge_resources_alias(args)? {
        Some(resources) => {
            if resources.is_empty() {
                return Err("resources, if given, must name at least one guest".to_owned());
            }
            for resource in &resources {
                rust_proxmoxmcp_core::ha_rules::validate_service_id(resource)
                    .map_err(|error| error.to_string())?;
            }
            Some(resources)
        }
        None if is_create => return Err("create requires resources".to_owned()),
        None => None,
    };

    // Validated against the *declared* type on create, since `rule_type` is
    // known then. An update carries no type -- Proxmox's own PUT knows the
    // rule's existing type and would refuse a mismatched field itself -- so
    // update accepts either `nodes` or `affinity` without cross-checking them
    // against a type this plan does not know.
    if is_create {
        let declared = rule_type.as_deref().expect("set above for create");
        match declared {
            "node-affinity" => {
                if args.affinity.is_some() {
                    return Err("a node-affinity rule does not take affinity".to_owned());
                }
                let Some(nodes) = &args.nodes else {
                    return Err("a node-affinity rule requires nodes".to_owned());
                };
                validate_nodes_list(nodes)?;
            }
            "resource-affinity" => {
                if args.nodes.is_some() {
                    return Err("a resource-affinity rule does not take nodes".to_owned());
                }
                let Some(affinity) = &args.affinity else {
                    return Err("a resource-affinity rule requires affinity".to_owned());
                };
                if affinity != "positive" && affinity != "negative" {
                    return Err(format!(
                        "affinity must be 'positive' or 'negative', got '{affinity}'"
                    ));
                }
            }
            _ => unreachable!("validated above"),
        }
    } else {
        if let Some(nodes) = &args.nodes {
            validate_nodes_list(nodes)?;
        }
        if let Some(affinity) = &args.affinity
            && affinity != "positive"
            && affinity != "negative"
        {
            return Err(format!(
                "affinity must be 'positive' or 'negative', got '{affinity}'"
            ));
        }
        if !is_create
            && resources.is_none()
            && args.nodes.is_none()
            && args.affinity.is_none()
            && args.strict.is_none()
            && args.comment.is_none()
            && args.disable.is_none()
        {
            return Err(
                "update names no field to change; give at least one of resources, nodes, \
                 affinity, strict, comment or disable"
                    .to_owned(),
            );
        }
    }

    Ok(HaRuleAction {
        op: if is_create { "create" } else { "update" }.to_owned(),
        cluster: args.cluster.clone(),
        rule: args.rule.clone(),
        rule_type,
        resources,
        nodes: args.nodes.clone(),
        affinity: args.affinity.clone(),
        strict: args.strict,
        comment: args.comment.clone(),
        disable: args.disable,
    })
}

/// The vmids an HA rule change touches: those the action names plus those the
/// rule currently names.
///
/// The current rule is read from `resources` (the PVE 9 field) and, failing
/// that, `services`; either may be a comma-separated string or an array.
///
/// # Errors
///
/// Returns a message when a service id, from either source, is not in
/// `vm:<vmid>`/`ct:<vmid>` form -- a guest this cannot identify is a guest it
/// cannot authorize, so it is refused rather than skipped.
pub(crate) fn guests_touched(
    action: &HaRuleAction,
    existing: Option<&serde_json::Value>,
) -> Result<std::collections::BTreeSet<u32>, String> {
    let mut ids: Vec<String> = action.resources.clone().unwrap_or_default();

    if let Some(rule) = existing {
        let field = rule.get("resources").or_else(|| rule.get("services"));
        match field {
            Some(serde_json::Value::String(list)) => ids.extend(
                list.split(',')
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                    .map(ToOwned::to_owned),
            ),
            Some(serde_json::Value::Array(entries)) => {
                for entry in entries {
                    let Some(entry) = entry.as_str() else {
                        return Err(format!(
                            "HA rule '{}' lists a non-string resource {entry}",
                            action.rule
                        ));
                    };
                    ids.push(entry.trim().to_owned());
                }
            }
            Some(serde_json::Value::Null) | None => {}
            Some(other) => {
                return Err(format!(
                    "HA rule '{}' has an unreadable resource list {other}",
                    action.rule
                ));
            }
        }
    }

    let mut vmids = std::collections::BTreeSet::new();
    for id in ids {
        rust_proxmoxmcp_core::ha_rules::validate_service_id(&id)
            .map_err(|error| error.to_string())?;
        let (_, number) = id.split_once(':').expect("validated above");
        let vmid = number
            .parse::<u32>()
            .map_err(|_| format!("service '{id}' names a vmid out of range"))?;
        vmids.insert(vmid);
    }
    Ok(vmids)
}

/// Validate a `node[:priority]` comma list, the form Proxmox's `nodes` field
/// for a node-affinity rule takes.
fn validate_nodes_list(nodes: &str) -> Result<(), String> {
    if nodes.is_empty() {
        return Err("nodes must name at least one node".to_owned());
    }
    for entry in nodes.split(',') {
        let node_name = entry.split(':').next().unwrap_or(entry);
        if node_name.is_empty() {
            return Err(format!("nodes entry '{entry}' names no node"));
        }
        rust_proxmoxmcp_core::guests::validate_path_segment(node_name, "nodes")
            .map_err(|error| format!("nodes entry '{entry}' refused: {error}"))?;
        if let Some((_, priority)) = entry.split_once(':')
            && !priority.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(format!(
                "nodes entry '{entry}' has a non-numeric priority '{priority}'"
            ));
        }
    }
    Ok(())
}

/// The operation-required fields an action does not carry.
///
/// Mirrors `missing_required_fields` in `mod.rs`: `build_ha_rule_action`
/// requires all of these at plan time, so a record it produced cannot be
/// incomplete. This is the guard against a record planned by an older
/// version, imported, or hand-written.
pub(crate) fn missing_required_ha_fields(action: &HaRuleAction) -> Vec<&'static str> {
    match action.op.as_str() {
        "create" => {
            let mut missing = Vec::new();
            if action.rule_type.is_none() {
                missing.push("rule_type");
            }
            if action.resources.as_ref().is_none_or(Vec::is_empty) {
                missing.push("resources");
            }
            match action.rule_type.as_deref() {
                Some("node-affinity") if action.nodes.is_none() => missing.push("nodes"),
                Some("resource-affinity") if action.affinity.is_none() => missing.push("affinity"),
                _ => {}
            }
            missing
        }
        "update" | "delete" => Vec::new(),
        _ => Vec::new(),
    }
}

/// Render every field an action sets, one `  name: value` line per field the
/// caller gave -- so `strict`/`disable` show their explicit value rather than
/// silently defaulting, and a set `comment` is redacted rather than printed
/// raw (it is free text, the same class of field `redact_free_text_fields`
/// strips before a preview or a stored rule reaches the model).
fn render_proposed_fields(action: &HaRuleAction) -> String {
    let mut lines = Vec::new();
    if let Some(rule_type) = &action.rule_type {
        lines.push(format!("  type: {rule_type}"));
    }
    if let Some(resources) = &action.resources {
        lines.push(format!("  resources: {}", resources.join(", ")));
    }
    if let Some(nodes) = &action.nodes {
        lines.push(format!("  nodes: {nodes}"));
    }
    if let Some(affinity) = &action.affinity {
        lines.push(format!("  affinity: {affinity}"));
    }
    if let Some(strict) = action.strict {
        lines.push(format!("  strict: {strict}"));
    }
    if let Some(disable) = action.disable {
        lines.push(format!("  disable: {disable}"));
    }
    if let Some(comment) = &action.comment {
        lines.push(format!(
            "  comment: {}",
            mecmcp_redact::redact_text(comment)
        ));
    }
    lines.join("\n")
}

/// Render the preview an approver reviews for one HA rule action.
pub(crate) fn render_ha_rule_preview(
    action: &HaRuleAction,
    existing: Option<&serde_json::Value>,
) -> String {
    let target = format!("HA rule '{}' on cluster '{}'", action.rule, action.cluster);
    match action.op.as_str() {
        "create" => format!("CREATE {target}\n{}", render_proposed_fields(action)),
        "update" => format!(
            "UPDATE {target}\n  This changes cluster-wide guest placement policy.\n\
             Proposed change:\n{}\n  Current definition: {}",
            render_proposed_fields(action),
            existing
                .map(|v| v.to_string())
                .unwrap_or_else(|| "(unknown)".to_owned())
        ),
        "delete" => format!(
            "DELETE {target}\n  Removes the placement/affinity policy for the guests it names. \
             Current definition: {}",
            existing
                .map(|v| v.to_string())
                .unwrap_or_else(|| "(unknown)".to_owned())
        ),
        other => format!("UNKNOWN OPERATION '{other}' on {target}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F2: an update preview must show every proposed field, not just the
    /// rule's current definition -- otherwise the second-principal approver
    /// approves a change they cannot see, including `strict`/`disable`
    /// toggles and a comment that could carry cluster-shape detail.
    #[test]
    fn update_preview_shows_every_proposed_field() {
        let action = HaRuleAction {
            op: "update".to_owned(),
            cluster: "pve3".to_owned(),
            rule: "keep-together".to_owned(),
            rule_type: None,
            resources: Some(vec!["vm:100".to_owned(), "vm:200".to_owned()]),
            nodes: None,
            affinity: Some("negative".to_owned()),
            strict: Some(true),
            comment: Some("evacuate before maintenance; password: hunter2fake".to_owned()),
            disable: Some(false),
        };
        let existing = serde_json::json!({"rule": "keep-together", "resources": "vm:100"});

        let preview = render_ha_rule_preview(&action, Some(&existing));

        assert!(preview.contains("resources: vm:100, vm:200"), "{preview}");
        assert!(preview.contains("affinity: negative"), "{preview}");
        assert!(preview.contains("strict: true"), "{preview}");
        assert!(preview.contains("disable: false"), "{preview}");
        assert!(
            preview.contains("evacuate before maintenance"),
            "an operator note with no secret shape must still show, so the \
             approver sees what they are approving: {preview}"
        );
        assert!(
            !preview.contains("hunter2fake"),
            "a credential-shaped substring in the comment must be redacted, \
             not shown verbatim: {preview}"
        );
    }

    /// The create preview gets the same treatment.
    #[test]
    fn create_preview_shows_strict_and_disable() {
        let action = HaRuleAction {
            op: "create".to_owned(),
            cluster: "pve3".to_owned(),
            rule: "keep-together".to_owned(),
            rule_type: Some("node-affinity".to_owned()),
            resources: Some(vec!["vm:100".to_owned()]),
            nodes: Some("pve2".to_owned()),
            affinity: None,
            strict: Some(true),
            comment: None,
            disable: Some(true),
        };

        let preview = render_ha_rule_preview(&action, None);

        assert!(preview.contains("type: node-affinity"), "{preview}");
        assert!(preview.contains("resources: vm:100"), "{preview}");
        assert!(preview.contains("strict: true"), "{preview}");
        assert!(preview.contains("disable: true"), "{preview}");
    }
}
