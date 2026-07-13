//! `(group, uplink)`-keyed cache over a pre-resolved counter handle.
//!
//! The byte / datagram counters on the relay hot path (`add_bytes` /
//! `add_udp_datagram`) hash their `&str` label tuple and probe the sharded
//! registry map on every chunk or datagram. Resolving a concrete counter
//! handle once and reusing it removes that per-call cost — but a flow can fail
//! over to a different uplink mid-stream, and the cached handle must then move
//! to the new `(group, uplink)` series so the bytes are not misattributed.
//!
//! [`FailoverCounter`] encodes that invalidation once: it remembers the two
//! `Arc<str>` label values the handle was resolved for and re-resolves only
//! when either is swapped for a *different allocation*. `Arc::ptr_eq` is a
//! pointer compare (no string hashing), so the steady-state hot path is a
//! cheap identity check plus the final atomic add — mirroring the per-flow
//! gauge caching in `TunTcpFlowGauges`.
//!
//! Only *counter* handles may be cached this way. Histograms are the only
//! metric kind under idle-eviction, so a long-lived cached histogram handle
//! whose series was evicted would silently buffer samples the renderer never
//! drains again. The handles resolved here (`*_bytes_total` /
//! `*_datagrams_total`) are `IntCounter`s, which are never idle-evicted, so the
//! exported values stay bit-for-bit identical to the per-call path.

use std::sync::Arc;

/// Caches a counter handle resolved for a `(group, uplink)` label pair,
/// re-resolving via the caller-supplied closure only when either `Arc<str>`
/// changes identity since the last lookup.
///
/// `H` is the pre-resolved handle type (`FlowBytesCounter` / `UdpFlowCounters`
/// in the real build, their zero-sized stubs otherwise). Cloning an `Arc<str>`
/// preserves its allocation pointer, so passing fresh clones of a stable label
/// (e.g. `state.routing.group_name.clone()` each iteration) still hits the
/// cache; a runtime failover that installs a *new* `Arc<str>` for the uplink
/// is what forces a re-resolve.
pub struct FailoverCounter<H> {
    key: Option<(Arc<str>, Arc<str>)>,
    handle: Option<H>,
}

impl<H> Default for FailoverCounter<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H> FailoverCounter<H> {
    /// Creates an empty cache. The first [`get`](Self::get) resolves and stores
    /// the handle.
    pub const fn new() -> Self {
        Self { key: None, handle: None }
    }

    /// Returns the cached handle for `(group, uplink)`, calling `resolve` to
    /// (re)build it only when either label changed identity since the last
    /// call. `resolve` receives the two labels as `&str` and must return the
    /// handle for exactly that series (typically a `flow_bytes_counter` /
    /// `udp_flow_counters` call).
    #[inline]
    pub fn get(
        &mut self,
        group: &Arc<str>,
        uplink: &Arc<str>,
        resolve: impl FnOnce(&str, &str) -> H,
    ) -> &H {
        let fresh = match &self.key {
            Some((cached_group, cached_uplink)) => {
                Arc::ptr_eq(cached_group, group) && Arc::ptr_eq(cached_uplink, uplink)
            },
            None => false,
        };
        if !fresh {
            self.handle = Some(resolve(group, uplink));
            self.key = Some((Arc::clone(group), Arc::clone(uplink)));
        }
        self.handle.as_ref().expect("handle set above when not fresh")
    }
}
