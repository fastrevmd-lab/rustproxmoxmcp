//! `/readyz` cluster reachability.
//!
//! [`mecmcp_transport::ReadinessCheck`] probes are synchronous, non-blocking
//! closures that `/readyz` calls on every request; a probe cannot itself make
//! a network call to a Proxmox cluster without blocking the request thread.
//! Instead, a background task polls each configured cluster's API on an
//! interval and records the outcome in an [`AtomicBool`], which the probe
//! closure only reads.
//!
//! `/readyz` is unauthenticated, so exactly one fixed-name
//! [`ReadinessCheck`] is registered for the whole fleet: it fails if any
//! configured cluster is currently unreachable. Which cluster is down is
//! never put in the probe's name or its `/readyz` body -- operator
//! inventory names are not data an unauthenticated caller should get -- it
//! only goes to the server log at the poll call site.

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

/// Fixed name for the single fleet-wide `/readyz` check.
///
/// One name for all clusters, not one check per cluster: a per-cluster name
/// would put operator inventory names on an unauthenticated endpoint.
const CHECK_NAME: &str = "proxmox_cluster_reachability";

/// Fixed reason reported on `/readyz` when any cluster is unreachable.
///
/// `/readyz` is unauthenticated, so [`ReadinessCheck::new`] requires a
/// `&'static str` reason that cannot carry a runtime detail (which cluster,
/// the underlying HTTP error, a timeout, a TLS failure). Operators get that
/// detail from the server log at the poll call site instead.
const UNREACHABLE_REASON: &str = "one or more configured clusters are unreachable";

/// Tracks whether one cluster answered its last reachability poll.
///
/// Cheap to clone -- clones share the same flag. Starts unreachable: a
/// cluster with no completed poll yet has not been verified, and `/readyz`
/// meaning "verified ready" is worth a few seconds of 503 at startup rather
/// than a false "ready" for a blackholed cluster. `tokio::time::interval`'s
/// first tick fires immediately, so the first poll starts at t=0 and this
/// window is normally far shorter than [`POLL_INTERVAL`].
#[derive(Clone)]
struct ClusterReachability {
    reachable: Arc<AtomicBool>,
}

impl ClusterReachability {
    fn new() -> Self {
        Self {
            reachable: Arc::new(AtomicBool::new(false)),
        }
    }

    fn record(&self, reachable: bool) {
        self.reachable.store(reachable, Ordering::Relaxed);
    }

    fn is_reachable(&self) -> bool {
        self.reachable.load(Ordering::Relaxed)
    }
}

/// Build the single fleet-wide `/readyz` probe: ready only if every tracked
/// cluster's last poll succeeded.
fn fleet_probe(
    trackers: Arc<[ClusterReachability]>,
) -> impl Fn() -> Result<(), &'static str> + Send + Sync + Clone + use<> {
    move || {
        if trackers.iter().all(ClusterReachability::is_reachable) {
            Ok(())
        } else {
            Err(UNREACHABLE_REASON)
        }
    }
}

/// Register the single `/readyz` [`ReadinessCheck`] for the fleet and spawn
/// the background pollers that keep it current.
///
/// The returned handles abort their polling tasks when dropped
/// ([`AbortOnDropHandle`]); the caller must keep them alive for as long as
/// the server should keep polling, typically for the lifetime of the HTTP
/// serve loop.
pub fn spawn_cluster_readiness(
    clients: &Arc<BTreeMap<String, ProxmoxClient>>,
) -> (Vec<ReadinessCheck>, Vec<AbortOnDropHandle<()>>) {
    let trackers: Vec<ClusterReachability> =
        clients.keys().map(|_| ClusterReachability::new()).collect();
    let trackers: Arc<[ClusterReachability]> = trackers.into();
    let mut handles = Vec::with_capacity(clients.len());

    for (name, tracker) in clients.keys().zip(trackers.iter()) {
        let clients = Arc::clone(clients);
        let name = name.clone();
        let tracker = tracker.clone();
        handles.push(AbortOnDropHandle::new(tokio::spawn(async move {
            let mut tick = tokio::time::interval(POLL_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut was_reachable = None;
            loop {
                tick.tick().await;
                let Some(client) = clients.get(&name) else {
                    // The inventory this client set was built from no longer
                    // names this cluster. Nothing left to poll.
                    break;
                };
                let result = client.get_json(PROBE_PATH, &[], &[]).await;
                let reachable = result.is_ok();
                // Log only on a state transition, so a cluster that stays
                // down doesn't write a line every POLL_INTERVAL.
                if was_reachable != Some(reachable) {
                    if let Err(error) = &result {
                        tracing::warn!(
                            cluster = %name,
                            error = %error,
                            "readiness poll: cluster did not answer {PROBE_PATH}"
                        );
                    } else {
                        tracing::info!(cluster = %name, "readiness poll: cluster is reachable again");
                    }
                }
                was_reachable = Some(reachable);
                tracker.record(reachable);
            }
        })));
    }

    let checks = vec![ReadinessCheck::new(CHECK_NAME, fleet_probe(trackers))];
    (checks, handles)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_tracker_is_not_yet_reachable() {
        let tracker = ClusterReachability::new();
        assert!(!tracker.is_reachable());
    }

    #[test]
    fn recording_reachable_flips_the_tracker() {
        let tracker = ClusterReachability::new();
        tracker.record(true);
        assert!(tracker.is_reachable());
    }

    #[test]
    fn recording_unreachable_again_clears_a_prior_success() {
        let tracker = ClusterReachability::new();
        tracker.record(true);
        tracker.record(false);
        assert!(!tracker.is_reachable());
    }

    #[test]
    fn clones_share_the_same_underlying_state() {
        let tracker = ClusterReachability::new();
        let clone = tracker.clone();

        clone.record(true);
        assert!(tracker.is_reachable());
    }

    #[test]
    fn fleet_probe_is_ready_only_when_every_tracker_is_reachable() {
        let a = ClusterReachability::new();
        let b = ClusterReachability::new();
        let trackers: Arc<[ClusterReachability]> = vec![a.clone(), b.clone()].into();
        let probe = fleet_probe(trackers);

        assert_eq!(probe(), Err(UNREACHABLE_REASON));

        a.record(true);
        assert_eq!(probe(), Err(UNREACHABLE_REASON), "b is still unreachable");

        b.record(true);
        assert_eq!(probe(), Ok(()));

        a.record(false);
        assert_eq!(probe(), Err(UNREACHABLE_REASON), "a went back down");
    }

    #[tokio::test]
    async fn one_fleet_wide_readiness_check_is_registered_regardless_of_cluster_count() {
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
        assert_eq!(checks.len(), 1, "one fixed-name check for the whole fleet");
        assert_eq!(handles.len(), 2, "one poller per configured cluster");
        drop(handles);
    }
}
