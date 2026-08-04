//! Public-facing types shared across the uplink crate's modules.
//!
//! Runtime state has been split out by concern:
//! - [`crate::manager::state`] — manager container & active-uplink selection
//! - [`crate::manager::status`] — per-uplink probe/runtime status
//! - [`crate::manager::standby_pool`] — warm-standby connection pool
//! - [`crate::manager::sticky`] — sticky-route entry
//! - [`crate::manager::candidates`] — load-balancing candidate state
//! - [`crate::manager::probe::outcome`] — probe result
//! - [`crate::routing_key`] — routing-key enum
//!
//! What remains here is the minimal set of types referenced from outside
//! the manager module tree (config DTOs, candidate handles, snapshot DTOs).

use std::sync::Arc;

use crate::config::UplinkConfig;

// Re-exports so internal modules can keep importing through `crate::types::*`
// for the central runtime types they routinely touch.
pub use crate::manager::state::UplinkManager;

/// Runtime handle for a configured uplink. Cheap to clone (shared `Arc`).
/// Exists to distinguish a runtime-attached uplink reference from the raw
/// [`UplinkConfig`] DTO at call sites. Field access goes through `Deref`.
#[derive(Clone, Debug)]
pub struct Uplink(Arc<UplinkConfig>);

impl Uplink {
    pub fn new(config: UplinkConfig) -> Self {
        Self(Arc::new(config))
    }
}

impl From<UplinkConfig> for Uplink {
    fn from(config: UplinkConfig) -> Self {
        Self::new(config)
    }
}

impl std::ops::Deref for Uplink {
    type Target = UplinkConfig;
    fn deref(&self) -> &UplinkConfig {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct UplinkCandidate {
    pub index: usize,
    pub uplink: Uplink,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransportKind {
    Tcp,
    Udp,
}

/// Snapshot of the manager's `active_uplinks` selection, published on the
/// `subscribe_active_uplinks()` watch channel after every
/// `set_active_uplink_index_for_transport(...)` mutation. Cheap to clone.
///
/// Consumers (SOCKS5 strict-abort watcher, UDP proactive wakeup) compare
/// the relevant field against the index their session is pinned to and react
/// to mismatches without having to poll the manager's async lock.
///
/// `intent` records *why* the pointer moved, which is the only thing that tells
/// a live session on the old uplink whether it is meant to survive. See
/// [`SwitchIntent`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActiveUplinksSnapshot {
    pub global: Option<usize>,
    pub tcp: Option<usize>,
    pub udp: Option<usize>,
    pub intent: SwitchIntent,
}

/// Why the strict active-uplink pointer moved — and therefore what should
/// happen to the live sessions still bound to the uplink it moved off.
///
/// This is deliberately three-valued rather than the `soft: bool` it replaced.
/// A boolean could only say "the operator asked for a soft switch", which left
/// every machine-driven repoint indistinguishable from an operator *hard*
/// switch, i.e. from a deliberate decision to abandon those sessions. It is not
/// one: when a probe failover or a mass carrier death moves the pointer, nobody
/// decided the sessions should die — they die only because the strict-active
/// check happens to reset anything it finds stranded, and it wins the race
/// against the flow's own carrier-death migration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SwitchIntent {
    /// Operator hard switch (`POST /control/activate {"soft": false}`, a hard
    /// scheduled reselect, or any soft request clamped off a `shared_resume`
    /// group). The operator is draining this uplink: sessions must come off it
    /// for real, and a migration would defeat that — under a mesh cluster a
    /// migrated session is relayed back to its *home*, which is the very node
    /// being drained. Live sessions are aborted.
    ///
    /// The default, so a snapshot that predates any explicit switch abandons
    /// nothing it should have carried: `global`/`tcp`/`udp` are `None` there and
    /// the verdict never reaches the intent at all.
    #[default]
    OperatorHard,
    /// Operator soft switch on a `shared_resume` group: carry live sessions to
    /// the new active via cluster resume, falling back to the abort a hard
    /// switch would have given on anything short of success.
    OperatorSoft,
    /// Machine-driven repoint: probe failover, runtime-failure failover,
    /// auto-failback, carrier-degraded failover, loss-driven failover, or the
    /// initial selection.
    ///
    /// Not a decision about sessions at all — so on a cluster it is treated like
    /// [`Self::OperatorSoft`] (see [`Self::migrates_live_flows`]). The uplink it
    /// moved off is usually unhealthy, which is exactly when a session's own
    /// resume is worth attempting: the parked upstream lives on the *server*,
    /// and the mesh reaches it from the new edge without the client's broken
    /// path to the old one.
    Failover,
}

impl SwitchIntent {
    /// Whether a session stranded by this switch should attempt to migrate
    /// instead of being torn down.
    ///
    /// `shared_resume` is load-bearing for [`Self::Failover`]: off a cluster the
    /// new active is a different server with nothing parked for this session, so
    /// a migration could only ever miss and the dial would be pure latency
    /// before the same teardown. (An operator soft switch is already clamped to
    /// hard off a cluster upstream of here, so the same gate is redundant —
    /// applied anyway so the rule reads the same for both.)
    pub const fn migrates_live_flows(self, shared_resume: bool) -> bool {
        match self {
            Self::OperatorHard => false,
            Self::OperatorSoft | Self::Failover => shared_resume,
        }
    }

    /// Intent an operator-originated switch carries, given the soft flag it
    /// requested *after* clamping to the group's `shared_resume`.
    pub const fn from_operator_soft(applied_soft: bool) -> Self {
        if applied_soft {
            Self::OperatorSoft
        } else {
            Self::OperatorHard
        }
    }
}

impl ActiveUplinksSnapshot {
    /// Index that a TCP session in this group should treat as authoritative:
    /// `global` when the group is in strict-global, otherwise per-transport
    /// TCP. Returns `None` for non-strict groups (the consumer should never
    /// have subscribed in that case).
    pub fn tcp_for(&self, strict_global: bool) -> Option<usize> {
        if strict_global { self.global } else { self.tcp }
    }

    /// Same as [`Self::tcp_for`] for the UDP transport.
    pub fn udp_for(&self, strict_global: bool) -> Option<usize> {
        if strict_global { self.global } else { self.udp }
    }
}

// Snapshot data types live in the `outline-metrics` crate (they cross the
// producer/consumer boundary between the uplink manager here and the
// prometheus renderer); re-exported so existing `crate::uplink::*Snapshot`
// imports keep working.
pub use outline_metrics::{StickyRouteSnapshot, UplinkManagerSnapshot, UplinkSnapshot};
