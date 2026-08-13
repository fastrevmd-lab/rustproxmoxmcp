//! Guest resolution and authorization.
//!
//! Every guest-addressed tool takes `(cluster, vmid)` and never a node. Guests
//! migrate; a caller-supplied node is an opportunity to act on a stale
//! assumption, and after a migration it addresses the wrong place entirely.
//!
//! Resolution reads `/cluster/resources` once per TTL window rather than once
//! per call, because the same snapshot answers node, name, status, tags and
//! pool for every guest at once.

use crate::client::ProxmoxClient;
use crate::error::ProxmoxError;
use crate::selector::{GuestFacts, GuestType};
use std::collections::BTreeMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// A guest as the cluster currently reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGuest {
    /// Inventory name of the cluster this guest lives in.
    pub cluster: String,
    /// Numeric guest id.
    pub vmid: u32,
    /// Display name.
    pub name: String,
    /// VM or container.
    pub r#type: GuestType,
    /// Node the guest is on right now.
    pub node: String,
    /// Runtime status, e.g. `running` or `stopped`.
    pub status: String,
    /// Live tags, split from Proxmox's semicolon-separated field.
    pub tags: Vec<String>,
    /// Proxmox pool, when the guest is in one.
    pub pool: Option<String>,
}

impl ResolvedGuest {
    /// Borrow the facts a selector needs.
    #[must_use]
    pub fn facts(&self) -> GuestFacts<'_> {
        GuestFacts {
            vmid: self.vmid,
            r#type: self.r#type,
            node: &self.node,
            pool: self.pool.as_deref(),
            tags: &self.tags,
        }
    }
}

/// One cached `/cluster/resources` snapshot.
struct Snapshot {
    taken: Instant,
    guests: BTreeMap<u32, ResolvedGuest>,
}

/// A TTL-bounded index of every guest in every cluster.
pub struct GuestIndex {
    ttl: Duration,
    snapshots: RwLock<BTreeMap<String, Snapshot>>,
}

impl GuestIndex {
    /// Build an index whose snapshots expire after `ttl`.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            snapshots: RwLock::new(BTreeMap::new()),
        }
    }

    /// Resolve one guest, refreshing the cluster snapshot when it has expired.
    ///
    /// The lock is released between the read attempt and the fetch. Two
    /// concurrent resolves for the same cluster may both fetch; the second
    /// insert simply wins. That is acceptable here (the cost is one redundant
    /// GET, the data is equivalent) and is much simpler than holding a lock
    /// across an await, which would serialise every caller behind the slowest
    /// cluster.
    ///
    /// # Errors
    /// Returns [`ProxmoxError::NotFound`] when the cluster does not report the
    /// vmid, and propagates any client error from refreshing the snapshot.
    pub async fn resolve(
        &self,
        client: &ProxmoxClient,
        cluster: &str,
        vmid: u32,
    ) -> Result<ResolvedGuest, ProxmoxError> {
        if let Some(guest) = self.lookup_fresh(cluster, vmid) {
            return Ok(guest);
        }
        let guests = fetch_guests(client, cluster).await?;
        let found = guests.get(&vmid).cloned();
        if let Ok(mut snapshots) = self.snapshots.write() {
            snapshots.insert(
                cluster.to_owned(),
                Snapshot {
                    taken: Instant::now(),
                    guests,
                },
            );
        }
        found.ok_or_else(|| ProxmoxError::NotFound {
            what: format!("guest {vmid} in cluster {cluster}"),
        })
    }

    /// Drop every cached snapshot, e.g. after a mutation.
    pub fn invalidate(&self) {
        if let Ok(mut snapshots) = self.snapshots.write() {
            snapshots.clear();
        }
    }

    /// Read one guest out of a snapshot that has not expired.
    fn lookup_fresh(&self, cluster: &str, vmid: u32) -> Option<ResolvedGuest> {
        let snapshots = self.snapshots.read().ok()?;
        let snapshot = snapshots.get(cluster)?;
        if snapshot.taken.elapsed() > self.ttl {
            return None;
        }
        snapshot.guests.get(&vmid).cloned()
    }
}

/// Read and parse `/cluster/resources` for one cluster.
async fn fetch_guests(
    client: &ProxmoxClient,
    cluster: &str,
) -> Result<BTreeMap<u32, ResolvedGuest>, ProxmoxError> {
    let value = client
        .get_json("/api2/json/cluster/resources", &[], &[])
        .await?;
    let entries = value
        .as_array()
        .ok_or_else(|| ProxmoxError::Malformed("cluster/resources is not an array".into()))?;

    let mut guests = BTreeMap::new();
    for entry in entries {
        let Some(kind) = entry.get("type").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let r#type = match kind {
            "qemu" => GuestType::Qemu,
            "lxc" => GuestType::Lxc,
            _ => continue,
        };
        let Some(vmid) = entry.get("vmid").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let vmid = u32::try_from(vmid)
            .map_err(|_| ProxmoxError::Malformed(format!("vmid {vmid} out of range")))?;
        let node = entry
            .get("node")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ProxmoxError::Malformed(format!("guest {vmid} has no node")))?;

        guests.insert(
            vmid,
            ResolvedGuest {
                cluster: cluster.to_owned(),
                vmid,
                name: entry
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                r#type,
                node: node.to_owned(),
                status: entry
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                tags: parse_tags(entry.get("tags").and_then(serde_json::Value::as_str)),
                pool: entry
                    .get("pool")
                    .and_then(serde_json::Value::as_str)
                    .filter(|pool| !pool.is_empty())
                    .map(str::to_owned),
            },
        );
    }
    Ok(guests)
}

/// Split Proxmox's semicolon-separated tag string.
fn parse_tags(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .split(';')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_owned)
        .collect()
}
