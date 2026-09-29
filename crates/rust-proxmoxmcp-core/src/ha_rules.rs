//! HA rule operations against PVE 9's unified `ha-rules` model.
//!
//! PVE 9 replaced the older HA groups mechanism (`/cluster/ha/groups`) with a
//! single `ha-rules` resource covering both node placement (`location` rules)
//! and guest-to-guest affinity (`colocation` rules). This module speaks only
//! the current model; `ha-groups` is deliberately not implemented here.
//!
//! HA rules are cluster-scoped configuration, not a single guest's state, so
//! nothing here goes through [`crate::resolve::authorize`] or produces an
//! [`crate::AuthorizedGuest`] -- there is no guest to authorize against. The
//! change-set control that guest operations get from that type comes instead
//! from the plan/approve/apply handlers in `rust-proxmoxmcp`, which fingerprint
//! the rule's own JSON body rather than a guest's config digest.

use crate::client::ProxmoxClient;
use crate::error::ProxmoxError;

/// Fetch one HA rule's current body, if it exists.
///
/// `Ok(None)` distinguishes "the rule does not exist" from every other
/// failure: a `create` plan needs exactly that fact, and a `delete` or
/// `update` plan needs its absence to be an error rather than a silent no-op.
///
/// # Errors
///
/// Propagates any client error other than a 404, which becomes `Ok(None)`.
pub async fn fetch_rule(
    client: &ProxmoxClient,
    rule: &str,
) -> Result<Option<serde_json::Value>, ProxmoxError> {
    let path_template = "/api2/json/cluster/ha/rules/{rule}";
    let params = &[("rule", rule)];

    match client.get_json(path_template, params, &[]).await {
        Ok(value) => Ok(Some(value)),
        Err(ProxmoxError::Api { status: 404, .. }) => Ok(None),
        Err(error) => Err(error),
    }
}

/// List every HA rule in the cluster.
///
/// # Errors
///
/// Propagates any client error. Returns [`ProxmoxError::Malformed`] if the
/// response is not an array.
pub async fn list_rules(client: &ProxmoxClient) -> Result<Vec<serde_json::Value>, ProxmoxError> {
    let data = client
        .get_json("/api2/json/cluster/ha/rules", &[], &[])
        .await?;
    data.as_array()
        .cloned()
        .ok_or_else(|| ProxmoxError::Malformed("ha rules response is not an array".into()))
}

/// Fields shared by an HA rule create or update.
///
/// Not every field applies to every rule type: `nodes` is meaningful only for
/// `location`, `affinity` only for `colocation`. Validated against the rule
/// type before either function below sends anything -- see
/// `rust_proxmoxmcp::server::ha_change_set::build_ha_rule_action`, which is
/// the one place that validation happens, so the two cannot drift.
pub struct HaRuleFields<'a> {
    /// `"location"` or `"colocation"`.
    pub rule_type: &'a str,
    /// Service ids the rule applies to, e.g. `["vm:100", "ct:200"]`.
    pub services: &'a [String],
    /// `location` only: `"node[:priority]"` entries, comma-joined by the
    /// caller into Proxmox's list form.
    pub nodes: Option<&'a str>,
    /// `colocation` only: `"positive"` or `"negative"`.
    pub affinity: Option<&'a str>,
    /// Whether the rule is strict (a location rule that cannot be satisfied
    /// refuses the operation) or advisory.
    pub strict: Option<bool>,
    /// Free-text comment.
    pub comment: Option<&'a str>,
    /// Create or leave the rule disabled.
    pub disable: Option<bool>,
}

/// Create a new HA rule.
///
/// Synchronous: HA rule changes are cluster configuration, not a task, so
/// there is no UPID to follow.
///
/// # Errors
///
/// Propagates any client error, including the cluster's own refusal if `rule`
/// already names an existing rule.
pub async fn create_rule(
    client: &ProxmoxClient,
    rule: &str,
    fields: &HaRuleFields<'_>,
) -> Result<(), ProxmoxError> {
    let services_value = services_form(fields.services);
    let mut form: Vec<(&str, &str)> = vec![
        ("rule", rule),
        ("type", fields.rule_type),
        ("services", &services_value),
    ];
    push_optional_fields(&mut form, fields);

    client
        .post_form("/api2/json/cluster/ha/rules", &[], &form)
        .await?;
    Ok(())
}

/// Update an existing HA rule.
///
/// `digest` is Proxmox's own optimistic-concurrency token for the rule, read
/// back from [`fetch_rule`] at plan time. Sent when present so the cluster
/// itself refuses a write against a rule that changed underneath the
/// change-set's own fingerprint check -- belt and braces, not a substitute for
/// it: the fingerprint check runs first and is what this server's own apply
/// handler can act on without a round trip.
///
/// # Errors
///
/// Propagates any client error.
pub async fn update_rule(
    client: &ProxmoxClient,
    rule: &str,
    fields: &HaRuleFields<'_>,
    digest: Option<&str>,
) -> Result<(), ProxmoxError> {
    let path_template = "/api2/json/cluster/ha/rules/{rule}";
    let params = &[("rule", rule)];

    let services_value = services_form(fields.services);
    let mut form: Vec<(&str, &str)> = Vec::new();
    if !fields.services.is_empty() {
        form.push(("services", &services_value));
    }
    push_optional_fields(&mut form, fields);
    if let Some(digest) = digest {
        form.push(("digest", digest));
    }

    if form.is_empty() {
        return Err(ProxmoxError::Malformed(
            "update names no field to change".into(),
        ));
    }

    client.put_form(path_template, params, &form).await?;
    Ok(())
}

/// Delete an HA rule.
///
/// # Errors
///
/// Propagates any client error, including the cluster's own refusal if `rule`
/// does not exist.
pub async fn delete_rule(client: &ProxmoxClient, rule: &str) -> Result<(), ProxmoxError> {
    let path_template = "/api2/json/cluster/ha/rules/{rule}";
    let params = &[("rule", rule)];
    client.delete_json(path_template, params, &[]).await?;
    Ok(())
}

fn services_form(services: &[String]) -> String {
    services.join(",")
}

fn push_optional_fields<'a>(form: &mut Vec<(&'a str, &'a str)>, fields: &HaRuleFields<'a>) {
    if let Some(nodes) = fields.nodes {
        form.push(("nodes", nodes));
    }
    if let Some(affinity) = fields.affinity {
        form.push(("affinity", affinity));
    }
    if let Some(strict) = fields.strict {
        form.push(("strict", if strict { "1" } else { "0" }));
    }
    if let Some(comment) = fields.comment.filter(|value| !value.is_empty()) {
        form.push(("comment", comment));
    }
    if let Some(disable) = fields.disable {
        form.push(("disable", if disable { "1" } else { "0" }));
    }
}

/// Validate a service id has the shape Proxmox's `ha-rules` accepts:
/// `vm:<digits>` or `ct:<digits>`.
///
/// Checked here rather than left to the cluster's own validation, for the
/// same reason `build_destroy_action` validates a volid before it is recorded
/// in a change set: an action the digest covers should not carry a value that
/// was never going to be accepted, discovered only after approval is spent.
///
/// # Errors
///
/// Returns [`ProxmoxError::Malformed`] if `service` does not match the form
/// above.
pub fn validate_service_id(service: &str) -> Result<(), ProxmoxError> {
    let Some((prefix, id)) = service.split_once(':') else {
        return Err(ProxmoxError::Malformed(format!(
            "service '{service}' is not in vm:<vmid> or ct:<vmid> form"
        )));
    };
    if prefix != "vm" && prefix != "ct" {
        return Err(ProxmoxError::Malformed(format!(
            "service '{service}' has prefix '{prefix}', expected 'vm' or 'ct'"
        )));
    }
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ProxmoxError::Malformed(format!(
            "service '{service}' does not name a numeric vmid"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_service_ids_are_accepted() {
        for service in ["vm:100", "ct:200", "vm:999999"] {
            assert!(validate_service_id(service).is_ok(), "{service}");
        }
    }

    #[test]
    fn service_ids_without_a_recognised_prefix_are_rejected() {
        for service in ["vmid:100", "100", "vm-100", ""] {
            assert!(validate_service_id(service).is_err(), "{service}");
        }
    }

    #[test]
    fn service_ids_with_a_non_numeric_vmid_are_rejected() {
        for service in ["vm:", "vm:abc", "vm:100;rm -rf", "ct:1.5"] {
            assert!(validate_service_id(service).is_err(), "{service}");
        }
    }
}
