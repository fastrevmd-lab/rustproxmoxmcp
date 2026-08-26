//! Guest resolution and authorization.
//!
//! Every guest-addressed tool takes `(cluster, vmid)` and never a node. Guests
//! migrate; a caller-supplied node is an opportunity to act on a stale
//! assumption, and after a migration it addresses the wrong place entirely.
//!
//! Resolution reads `/cluster/resources` once per TTL window rather than once
//! per call, because the same snapshot answers node, name, status, tags and
//! pool for every guest at once.

use crate::authorized::AuthorizedGuest;
use crate::client::ProxmoxClient;
use crate::error::ProxmoxError;
use crate::grant::ProxmoxGrant;
use crate::protect::protection_of;
use crate::selector::{GuestFacts, GuestType};
use crate::tier::Tier;
use std::collections::BTreeMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Bumped by every invalidation.
    ///
    /// A fetch that began before an invalidation must not insert its result
    /// afterwards. Without this, `resolve`'s last-insert-wins behaviour lets a
    /// pre-change snapshot land back in the cache *after* a caller deliberately
    /// dropped it -- which is how a destructive apply could re-read the state
    /// its own invalidation was meant to discard.
    generation: AtomicU64,
}

impl GuestIndex {
    /// Build an index whose snapshots expire after `ttl`.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            snapshots: RwLock::new(BTreeMap::new()),
            generation: AtomicU64::new(0),
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
        // Read the generation *before* fetching, so an invalidation that
        // happens while this request is in flight can be detected below.
        let generation_before = self.generation.load(Ordering::Acquire);
        let guests = fetch_guests(client, cluster).await?;
        let found = guests.get(&vmid).cloned();
        if let Ok(mut snapshots) = self.snapshots.write() {
            // Compare *inside* the critical section. Checking before taking the
            // lock is a time-of-check/time-of-use hole: an invalidation could
            // bump the generation and clear the map in the gap, and this insert
            // would then republish pre-change state on the strength of a
            // comparison that was already stale.
            //
            // This is correct only because invalidation bumps the generation
            // *before* it takes this lock. Either it bumps first and this check
            // sees the new value and declines, or this insert lands first and
            // the invalidation that follows removes it.
            //
            // The value is still returned either way -- it came from this fetch
            // and is as fresh as the request that asked for it. What is refused
            // is publishing it to later callers who asked for post-invalidation
            // state.
            if self.generation.load(Ordering::Acquire) == generation_before {
                snapshots.insert(
                    cluster.to_owned(),
                    Snapshot {
                        taken: Instant::now(),
                        guests,
                    },
                );
            }
        }
        found.ok_or_else(|| ProxmoxError::NotFound {
            what: format!("guest {vmid} in cluster {cluster}"),
        })
    }

    /// Drop every cached snapshot, e.g. after a mutation.
    ///
    /// Prefer [`Self::invalidate_cluster`] when only one cluster changed: this
    /// evicts snapshots for every other cluster too, and their next operation
    /// pays a fetch that can fail if that cluster is momentarily unreachable.
    pub fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut snapshots) = self.snapshots.write() {
            snapshots.clear();
        }
    }

    /// Drop one cluster's cached snapshot.
    ///
    /// The generation bump is global even though the eviction is not. It has to
    /// be: a concurrent fetch records only the cluster it asked for, and making
    /// the check per-cluster would mean tracking a generation per in-flight
    /// request for no practical gain. The cost of the coarse bump is that a
    /// fetch for an unrelated cluster may decline to cache and be repeated.
    pub fn invalidate_cluster(&self, cluster: &str) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut snapshots) = self.snapshots.write() {
            snapshots.remove(cluster);
        }
    }

    /// Resolve a guest and run stage-2 authorization for `tier`.
    ///
    /// Order matters. The guest is resolved first, because the grant selector
    /// and the protection check both need live facts. The scope check runs
    /// before the protection check so an out-of-scope caller learns nothing
    /// about whether the guest is protected.
    ///
    /// Protection does not gate [`Tier::Read`]: observing a protected guest is
    /// how an operator confirms it is protected. It is carried on the returned
    /// value so the audit event and, from 0.3, the change-set preview can
    /// report it.
    ///
    /// # Parameters
    /// - `override_applies`: Whether a waiver or lab-mode override allows this
    ///   destructive operation on a protected guest. The caller computes this
    ///   via [`crate::protect::destructive_allowed`]. When `None`, defaults to
    ///   no override (fail-closed).
    ///
    /// # Errors
    /// Returns [`ProxmoxError::NotFound`] for an absent guest,
    /// [`ProxmoxError::Denied`] when the grant does not admit the guest, does
    /// not carry the tier, or when the tier is gated by protection and no
    /// override applies.
    pub async fn authorize(
        &self,
        client: &ProxmoxClient,
        cluster: &str,
        vmid: u32,
        grant: &ProxmoxGrant,
        intent: Intent,
    ) -> Result<AuthorizedGuest, ProxmoxError> {
        let Intent {
            tier,
            interrupts,
            override_applies,
        } = intent;
        let guest = self.resolve(client, cluster, vmid).await?;

        if !grant.allows_guest(guest.facts()) {
            return Err(ProxmoxError::Denied(format!(
                "token scope does not admit guest {vmid} in cluster {cluster}"
            )));
        }

        if !mecmcp_auth::Grant::allows_action(grant, tier.action()) {
            return Err(ProxmoxError::Denied(format!(
                "token grant does not carry the {tier:?} action tier"
            )));
        }

        let protection = protection_of(client.cluster(), Some(&guest), false);

        // Protection holds back anything that would disrupt the guest, which is
        // a wider set than the destructive tier. `interrupts` carries the
        // low-tier half: a stop destroys nothing, so it stays `Tier::Low`, but
        // taking a protected guest out of service is exactly what protection
        // exists to prevent. Before 0.4 no low-tier tool existed, so keying on
        // `== Destructive` was indistinguishable from "everything disruptive".
        //
        // The complement is deliberate: start, snapshot and backup are `Low`
        // and *not* interrupting, so they stay available on a protected guest.
        if (tier == Tier::Destructive || interrupts)
            && protection.is_protected()
            && !override_applies.unwrap_or(false)
        {
            let kind = if tier == Tier::Destructive {
                "a destructive call"
            } else {
                "interrupting a protected guest"
            };
            return Err(ProxmoxError::Denied(format!(
                "guest {vmid} is protected ({}); {kind} needs a waiver",
                protection.summary()
            )));
        }

        Ok(AuthorizedGuest::new(guest, protection, tier))
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

/// What a caller intends to do to a guest.
///
/// Bundled rather than passed as three parameters because they are one
/// decision: the tier drives the grant action, interruption drives protection,
/// and the override records that a waiver or `--lab-mode` already applies.
/// Splitting them across the signature invited a caller to pass the wrong
/// boolean; naming the constructors makes the intent unambiguous at the call
/// site.
#[derive(Debug, Clone, Copy)]
pub struct Intent {
    /// Action class, which selects the grant action required.
    pub tier: Tier,
    /// Whether the call takes a running guest out of service.
    pub interrupts: bool,
    /// Whether a waiver or lab mode already permits a protected guest.
    pub override_applies: Option<bool>,
}

impl Intent {
    /// Observation. Never interrupts, never needs an override.
    #[must_use]
    pub const fn read() -> Self {
        Self {
            tier: Tier::Read,
            interrupts: false,
            override_applies: None,
        }
    }

    /// A low-tier call, with interruption derived from the tool name.
    ///
    /// Derived rather than passed so a new tool cannot be added with the wrong
    /// answer: `crate::tier::interrupts_service` is the single place that
    /// decides, and it is covered by tests naming both halves of the list.
    #[must_use]
    pub fn low(tool: &str) -> Self {
        Self {
            tier: Tier::Low,
            interrupts: crate::tier::interrupts_service(tool),
            override_applies: None,
        }
    }

    /// A low-tier call against a guest a waiver or lab mode already permits.
    #[must_use]
    pub fn low_with_override(tool: &str, override_applies: bool) -> Self {
        Self {
            override_applies: Some(override_applies),
            ..Self::low(tool)
        }
    }

    /// A destructive call. Its tier already refuses a protected guest, so
    /// interruption is not consulted.
    #[must_use]
    pub const fn destructive(override_applies: bool) -> Self {
        Self {
            tier: Tier::Destructive,
            interrupts: false,
            override_applies: Some(override_applies),
        }
    }
}
