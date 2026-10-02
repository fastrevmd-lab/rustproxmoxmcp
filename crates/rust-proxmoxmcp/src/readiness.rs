//! `/readyz` cluster reachability.
//!
//! [`mecmcp_transport::ReadinessCheck`] probes are synchronous, non-blocking
//! closures that `/readyz` calls on every request; a probe cannot itself make
//! a network call to a Proxmox cluster without blocking the request thread.
//! Instead, a background task polls each configured cluster's API on an
//! interval and records the outcome in an [`AtomicBool`], which the probe
//! closure only reads.
//!
//! One [`ReadinessCheck`] is registered per cluster, named after it, so a
//! `/readyz` failure identifies which cluster is unreachable rather than
//! reporting a single fleet-wide flag.

use mecmcp_transport::ReadinessCheck;
use rust_proxmoxmcp_core::client::ProxmoxClient;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio_util::task::AbortOnDropHandle;

/// How often each cluster's API is polled for reachability.
const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// A lightweight, parameter-free, read-only endpoint used purely to confirm
/// the cluster's API is answering. Already used elsewhere in this crate for
/// `get_nodes`, so it carries no privilege beyond what every deployment
/// already grants its service token.
const PROBE_PATH: &str = "/api2/json/nodes";

/// Fixed reason reported on `/readyz` for an unreachable cluster.
///
/// `/readyz` is unauthenticated, so [`ReadinessCheck::new`] requires a
/// `&'static str` reason that cannot carry a runtime detail (the underlying
/// HTTP error, a timeout, a TLS failure). The failing [`ReadinessCheck`]'s
/// name already identifies which cluster; operators get the detail from the
/// server log at the poll call site instead.
const UNREACHABLE_REASON: &str = "cluster is unreachable";

/// Tracks whether one cluster answered its last reachability poll.
///
/// Cheap to clone -- clones share the same flag. Starts reachable: a cluster
/// with no completed poll yet is not known to be down, and treating
/// "unknown" as "down" would fail `/readyz` for every cluster on a fresh
/// start until the first poll (up to [`POLL_INTERVAL`] later) completes.
#[derive(Clone)]
struct ClusterReachability {
    reachable: Arc<AtomicBool>,
}

impl ClusterReachability {
    fn new() -> Self {
        Self {
            reachable: Arc::new(AtomicBool::new(true)),
        }
    }

    fn record(&self, reachable: bool) {
        self.reachable.store(reachable, Ordering::Relaxed);
    }

    /// Build a `/readyz` probe closure reading this tracker's live state.
    fn probe(&self) -> impl Fn() -> Result<(), &'static str> + Send + Sync + Clone + use<> {
        let state = self.clone();
        move || {
            if state.reachable.load(Ordering::Relaxed) {
                Ok(())
            } else {
                Err(UNREACHABLE_REASON)
            }
        }
    }
}

/// Register a `/readyz` [`ReadinessCheck`] per configured cluster and spawn
/// the background pollers that keep them current.
///
/// The returned handles abort their polling tasks when dropped
/// ([`AbortOnDropHandle`]); the caller must keep them alive for as long as
/// the server should keep polling, typically for the lifetime of the HTTP
/// serve loop.
pub fn spawn_cluster_readiness(
    clients: &Arc<BTreeMap<String, ProxmoxClient>>,
) -> (Vec<ReadinessCheck>, Vec<AbortOnDropHandle<()>>) {
    let mut checks = Vec::with_capacity(clients.len());
    let mut handles = Vec::with_capacity(clients.len());

    for name in clients.keys() {
        let tracker = ClusterReachability::new();
        let check_name: &'static str =
            Box::leak(format!("proxmox_cluster_{name}").into_boxed_str());
        checks.push(ReadinessCheck::new(check_name, tracker.probe()));

        let clients = Arc::clone(clients);
        let name = name.clone();
        let tracker = tracker.clone();
        handles.push(AbortOnDropHandle::new(tokio::spawn(async move {
            let mut tick = tokio::time::interval(POLL_INTERVAL);
            loop {
                tick.tick().await;
                let Some(client) = clients.get(&name) else {
                    // The inventory this client set was built from no longer
                    // names this cluster. Nothing left to poll.
                    break;
                };
                let reachable = client.get_json(PROBE_PATH, &[], &[]).await.is_ok();
                if !reachable {
                    tracing::warn!(
                        target: "audit",
                        cluster = %name,
                        "readiness poll: cluster did not answer {PROBE_PATH}"
                    );
                }
                tracker.record(reachable);
            }
        })));
    }

    (checks, handles)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_tracker_probes_ready() {
        let tracker = ClusterReachability::new();
        assert_eq!(tracker.probe()(), Ok(()));
    }

    #[test]
    fn recording_unreachable_flips_the_probe_to_failing() {
        let tracker = ClusterReachability::new();
        tracker.record(false);
        assert_eq!(tracker.probe()(), Err(UNREACHABLE_REASON));
    }

    #[test]
    fn recording_reachable_again_clears_a_prior_failure() {
        let tracker = ClusterReachability::new();
        tracker.record(false);
        tracker.record(true);
        assert_eq!(tracker.probe()(), Ok(()));
    }

    #[test]
    fn clones_share_the_same_underlying_state() {
        let tracker = ClusterReachability::new();
        let clone = tracker.clone();

        clone.record(false);
        assert_eq!(tracker.probe()(), Err(UNREACHABLE_REASON));
    }

    #[test]
    fn probe_reflects_state_recorded_after_it_was_built() {
        let tracker = ClusterReachability::new();
        let probe = tracker.probe();

        tracker.record(false);
        assert_eq!(probe(), Err(UNREACHABLE_REASON));

        tracker.record(true);
        assert_eq!(probe(), Ok(()));
    }

    #[tokio::test]
    async fn one_readiness_check_is_registered_per_cluster() {
        use rust_proxmoxmcp_core::inventory::Cluster;
        use std::io::Write as _;

        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });

        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let mut clients = BTreeMap::new();
        for name in ["alpha", "beta"] {
            let secret_path = temp_dir.path().join(format!("{name}-secret.txt"));
            let mut secret_file = std::fs::File::create(&secret_path).expect("create secret file");
            secret_file
                .write_all(b"test-secret")
                .expect("write secret file");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
                    .expect("set secret file permissions");
            }

            let cluster = Cluster {
                endpoint: "https://127.0.0.1:1".to_owned(),
                token_id: "test@pam!test".to_owned(),
                token_secret_env: None,
                token_secret_file: Some(secret_path),
                ca_pem_path: None,
                protected_vmids: vec![],
                protected_tags: vec!["protected".to_owned()],
            };
            clients.insert(
                name.to_owned(),
                ProxmoxClient::new(cluster).expect("build client"),
            );
        }
        let clients = Arc::new(clients);

        let (checks, handles) = spawn_cluster_readiness(&clients);
        assert_eq!(checks.len(), 2);
        assert_eq!(handles.len(), 2);
        drop(handles);
    }
}
