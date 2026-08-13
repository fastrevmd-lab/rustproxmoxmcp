//! Multi-cluster inventory.
//!
//! `clusters.json` is read through `mecmcp-inventory`'s hardened loader, which
//! requires mode 0600, a regular file, and ownership by the service user. The
//! canonical envelope uses the key `devices` — the shared loader's vocabulary —
//! and this crate reads it as clusters.
//!
//! Credentials never appear in this file. Each cluster names an environment
//! variable or a separate 0600 file, loaded through `mecmcp-secret` into an
//! [`OutboundSecret`] that is zeroized on drop and implements neither `Debug`
//! nor `Serialize`.

use crate::error::ProxmoxError;
use mecmcp_inventory::{FileInventory, Inventory, InventoryError};
use mecmcp_secret::{OutboundSecret, SecretLimits, load_from_env, load_from_file};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One Proxmox VE cluster.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cluster {
    /// Base URL including scheme and port, e.g. `https://pve3.example.org:8006`.
    pub endpoint: String,
    /// API token identity in `user@realm!tokenid` form.
    pub token_id: String,
    /// Environment variable holding the token secret.
    #[serde(default)]
    pub token_secret_env: Option<String>,
    /// File holding the token secret. Mutually exclusive with the env form.
    #[serde(default)]
    pub token_secret_file: Option<PathBuf>,
    /// PEM trust anchor for this cluster's API certificate.
    ///
    /// `mecmcp-http` offers no insecure-skip-verify at any layer, so this is
    /// the only way to reach a cluster with a private CA.
    #[serde(default)]
    pub ca_pem_path: Option<PathBuf>,
    /// VMIDs protected regardless of their live tags.
    ///
    /// The durable half of the protection union: a holder of the server's own
    /// API token can clear a Proxmox tag, and cannot touch this list.
    #[serde(default)]
    pub protected_vmids: Vec<u32>,
    /// Tag names that mark a guest protected. Defaults to `["protected"]`.
    #[serde(default = "default_protected_tags")]
    pub protected_tags: Vec<String>,
}

fn default_protected_tags() -> Vec<String> {
    vec!["protected".to_owned()]
}

/// Inventory-wide settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterPolicy {
    /// How long a `/cluster/resources` snapshot may be reused.
    #[serde(default = "default_ttl")]
    pub resource_cache_ttl_secs: u64,
}

fn default_ttl() -> u64 {
    10
}

impl Default for ClusterPolicy {
    fn default() -> Self {
        Self {
            resource_cache_ttl_secs: default_ttl(),
        }
    }
}

impl Cluster {
    /// Load this cluster's API token secret.
    ///
    /// # Errors
    /// Returns [`ProxmoxError::Config`] when neither or both sources are
    /// configured, or when the hardened loader refuses the source.
    pub fn load_secret(&self) -> Result<OutboundSecret, ProxmoxError> {
        let limits = SecretLimits::default();
        match (&self.token_secret_env, &self.token_secret_file) {
            (Some(variable), None) => load_from_env(variable, limits)
                .map_err(|error| ProxmoxError::Config(error.to_string())),
            (None, Some(path)) => load_from_file(path, limits)
                .map_err(|error| ProxmoxError::Config(error.to_string())),
            (Some(_), Some(_)) => Err(ProxmoxError::Config(
                "exactly one of token_secret_env or token_secret_file must be set, not both".into(),
            )),
            (None, None) => Err(ProxmoxError::Config(
                "one of token_secret_env or token_secret_file must be set".into(),
            )),
        }
    }

    /// The `Authorization` header value for this cluster.
    ///
    /// Proxmox uses `PVEAPIToken=<id>=<secret>`, which is not the Bearer
    /// scheme, so this is attached with `secret_header` rather than
    /// `bearer_auth`.
    #[must_use]
    pub fn authorization_value(&self, secret: &OutboundSecret) -> String {
        format!("PVEAPIToken={}={}", self.token_id, secret.expose())
    }
}

/// The loaded cluster inventory, hot-reloadable on SIGHUP.
pub struct ClusterInventory {
    inner: FileInventory<Cluster, ClusterPolicy>,
}

impl ClusterInventory {
    /// Load `clusters.json` through the hardened loader.
    ///
    /// # Errors
    /// Returns [`InventoryError`] when the file is missing, wrongly permissioned,
    /// not a regular file, or structurally invalid.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, InventoryError> {
        Ok(Self {
            inner: FileInventory::load(path)?,
        })
    }

    /// Re-read the file in place, returning the number of clusters loaded.
    ///
    /// # Errors
    /// Returns [`InventoryError`] on any load failure. The previous contents
    /// remain in effect when a reload fails.
    pub fn reload(&self) -> Result<usize, InventoryError> {
        self.inner.reload()
    }

    /// All cluster names, in stable order.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.inner.names()
    }

    /// Resolve one cluster by exact name.
    ///
    /// # Errors
    /// Returns [`ProxmoxError::UnknownCluster`] when the name is absent.
    pub fn get(&self, name: &str) -> Result<Cluster, ProxmoxError> {
        self.inner
            .get_device(name)
            .map_err(|_| ProxmoxError::UnknownCluster(name.to_owned()))
    }

    /// Inventory-wide policy, or defaults when the file omits it.
    #[must_use]
    pub fn policy(&self) -> ClusterPolicy {
        self.inner.get_policy().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_fixture(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(contents.as_bytes()).expect("write");
        // The hardened loader requires 0600.
        std::fs::set_permissions(file.path(), std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("chmod");
        file
    }

    const FIXTURE: &str = r#"{
      "version": 1,
      "devices": {
        "pve3": {
          "endpoint": "https://pve3.example.org:8006",
          "token_id": "root@pam!mcp",
          "token_secret_env": "PVE_PVE3_TOKEN",
          "protected_vmids": [905, 907],
          "protected_tags": ["protected"]
        }
      }
    }"#;

    #[test]
    fn loads_clusters_and_exposes_names() {
        let file = write_fixture(FIXTURE);
        let inventory = ClusterInventory::load(file.path()).expect("load");
        assert_eq!(inventory.names(), vec!["pve3".to_owned()]);
    }

    #[test]
    fn resolves_a_cluster_by_name() {
        let file = write_fixture(FIXTURE);
        let inventory = ClusterInventory::load(file.path()).expect("load");
        let cluster = inventory.get("pve3").expect("cluster");
        assert_eq!(cluster.endpoint, "https://pve3.example.org:8006");
        assert_eq!(cluster.protected_vmids, vec![905, 907]);
    }

    #[test]
    fn unknown_cluster_is_a_typed_error_not_a_panic() {
        let file = write_fixture(FIXTURE);
        let inventory = ClusterInventory::load(file.path()).expect("load");
        let error = inventory.get("pve9").expect_err("should not resolve");
        assert!(matches!(error, ProxmoxError::UnknownCluster(name) if name == "pve9"));
    }

    #[test]
    fn rejects_an_unknown_field_rather_than_dropping_it() {
        let file = write_fixture(
            r#"{"version":1,"devices":{"pve3":{"endpoint":"https://a:8006",
                "token_id":"root@pam!mcp","token_secret_env":"X","verify_tls":false}}}"#,
        );
        assert!(ClusterInventory::load(file.path()).is_err());
    }

    #[test]
    fn defaults_the_resource_cache_ttl() {
        let file = write_fixture(FIXTURE);
        let inventory = ClusterInventory::load(file.path()).expect("load");
        assert_eq!(inventory.policy().resource_cache_ttl_secs, 10);
    }

    #[test]
    fn defaults_protected_tags_when_omitted() {
        let file = write_fixture(
            r#"{
              "version": 1,
              "devices": {
                "pve3": {
                  "endpoint": "https://pve3.example.org:8006",
                  "token_id": "root@pam!mcp",
                  "token_secret_env": "PVE_PVE3_TOKEN"
                }
              }
            }"#,
        );
        let inventory = ClusterInventory::load(file.path()).expect("load");
        let cluster = inventory.get("pve3").expect("cluster");
        assert_eq!(cluster.protected_tags, vec!["protected".to_owned()]);
    }

    #[test]
    fn defaults_resource_cache_ttl_secs_via_serde() {
        let file = write_fixture(
            r#"{
              "version": 1,
              "devices": {
                "pve3": {
                  "endpoint": "https://pve3.example.org:8006",
                  "token_id": "root@pam!mcp",
                  "token_secret_env": "PVE_PVE3_TOKEN"
                }
              },
              "policy": {}
            }"#,
        );
        let inventory = ClusterInventory::load(file.path()).expect("load");
        assert_eq!(inventory.policy().resource_cache_ttl_secs, 10);
    }

    #[test]
    fn missing_secret_file_reports_config_error_not_malformed_response() {
        let file = write_fixture(
            r#"{
              "version": 1,
              "devices": {
                "pve3": {
                  "endpoint": "https://pve3.example.org:8006",
                  "token_id": "root@pam!mcp",
                  "token_secret_file": "/nonexistent/pve3.token"
                }
              }
            }"#,
        );
        let inventory = ClusterInventory::load(file.path()).expect("load");
        let cluster = inventory.get("pve3").expect("cluster");
        let result = cluster.load_secret();
        let rendered = match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("should fail to load missing secret file"),
        };
        assert!(
            !rendered.contains("malformed"),
            "error should not mention 'malformed', got: {rendered}"
        );
        assert!(
            rendered.contains("configuration error") || rendered.contains("config"),
            "error should mention configuration, got: {rendered}"
        );
        assert!(
            rendered.contains("/nonexistent/pve3.token"),
            "error should mention the file path, got: {rendered}"
        );
    }
}
