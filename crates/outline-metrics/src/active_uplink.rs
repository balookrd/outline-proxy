//! Sync snapshot of the currently-active uplink per (group, scope), kept
//! outside the async `UplinkManager::active_uplinks` lock so it can be
//! consulted from synchronous `Drop` paths without blocking on a Tokio
//! runtime.
//!
//! Used by [`crate::transport::record_uplink_connection_close`] (called from
//! `UpstreamTransportGuard::drop`) to classify a closing connection as
//! belonging either to the still-active uplink (`active`) or to a stranded
//! one (`inactive`). The latter is the symptom of "leak into an inactive
//! uplink after switchover" that this metric pair is built to detect — in
//! `Global` and `PerUplink` modes a TCP/UDP session cannot migrate to a
//! different egress when the probe / operator flips the active pointer,
//! so in strict mode the ingress layer forcibly tears it down on switch
//! (SOCKS5 sends TCP RST, TUN sends RST+ACK, UDP transports atomically
//! swap to the new uplink). The `inactive` bucket therefore reflects the
//! brief window between the switch and the abort/swap; a sustained
//! non-zero rate indicates that strict mode is disabled
//! (`active_active` / `per_flow`) and stranded sessions are draining
//! naturally.
//!
//! Lives outside any feature gate so callers compile against the same API
//! regardless of whether the `prometheus` feature is enabled. The state
//! itself is zero-cost when nothing reads it.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;

#[derive(Debug, Default, Clone)]
struct ActiveUplinkSnapshot {
    /// Active uplink name in `Global` routing scope. `Some` only when the
    /// group is configured for `active_passive` + `global`.
    global: Option<Arc<str>>,
    /// Active uplink name for TCP in `PerUplink` routing scope. `Some` only
    /// when the group is configured for `active_passive` + `per_uplink`.
    tcp: Option<Arc<str>>,
    /// UDP counterpart to [`Self::tcp`].
    udp: Option<Arc<str>>,
}

static ACTIVE_UPLINKS: LazyLock<RwLock<HashMap<String, ActiveUplinkSnapshot>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Publish the currently-active uplink for a group running in `Global`
/// routing scope. Pass `None` to clear (e.g. when the group is reconfigured
/// out of `active_passive`).
pub fn set_global_active_uplink(group: &str, uplink: Option<&str>) {
    let mut state = ACTIVE_UPLINKS.write();
    let entry = state.entry(group.to_string()).or_default();
    entry.global = uplink.map(Arc::from);
}

/// Publish the currently-active uplink for a group running in `PerUplink`
/// routing scope, scoped to a single transport (`"tcp"` or `"udp"`).
pub fn set_per_uplink_active_uplink(group: &str, transport: &str, uplink: Option<&str>) {
    let mut state = ACTIVE_UPLINKS.write();
    let entry = state.entry(group.to_string()).or_default();
    let value = uplink.map(Arc::from);
    match transport {
        "tcp" => entry.tcp = value,
        "udp" => entry.udp = value,
        _ => {},
    }
}

/// Look up the uplink currently considered "active" for the given group +
/// transport. Returns `None` when the group has no active-uplink entry —
/// e.g. it runs in `PerFlow` scope where every uplink is potentially
/// active and the inactive/active classification does not apply.
///
/// `Global` is consulted first because in `Global` scope the same uplink
/// serves both transports; the per-transport slots are only relevant in
/// `PerUplink` scope (where `global` is `None`).
pub fn current_active_uplink(group: &str, transport: &str) -> Option<Arc<str>> {
    let state = ACTIVE_UPLINKS.read();
    let entry = state.get(group)?;
    if let Some(global) = entry.global.as_ref() {
        return Some(Arc::clone(global));
    }
    match transport {
        "tcp" => entry.tcp.as_ref().map(Arc::clone),
        "udp" => entry.udp.as_ref().map(Arc::clone),
        _ => None,
    }
}

/// Forget every cached active-uplink entry. Test-only — production code
/// never calls this; the sync snapshot is overwritten on every successful
/// `set_*_active_uplink` call from the manager.
#[cfg(test)]
#[doc(hidden)]
pub fn reset_for_tests() {
    ACTIVE_UPLINKS.write().clear();
}
