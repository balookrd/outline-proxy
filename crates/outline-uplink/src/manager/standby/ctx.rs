use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::debug;
use url::Url;

use outline_metrics as metrics;
use outline_transport::TransportStream;

use crate::config::{SsPathKind, TransportMode};
use crate::manager::standby_pool::TrackedDeque;
use crate::types::{TransportKind, Uplink, UplinkManager};

pub(super) const STANDBY_WS_PEEK_TIMEOUT: Duration = Duration::from_millis(1);

/// Transport-specific view of a standby pool, resolved once up-front so the
/// generic helpers (`try_take_alive`, `validate`, `refill`, `keepalive`) do
/// not thread `match transport { … }` through every loop.
///
/// TCP and UDP pools are structurally identical (pool deque + refill lock +
/// configured URL + effective mode + metric labels); this struct bundles the
/// per-transport differences so the algorithm can be written once.
///
/// The SS-UDP *acquire* is bespoke (`acquire_udp_standby_or_connect`) rather
/// than a generic take, but it DOES reuse this UDP pool — so on a combined-SS
/// uplink the refill must dial each pool's leg with the matching discriminator
/// (`combined_ss`, resolved per-wire in [`UplinkManager::standby_ctx`]); a UDP
/// pool filled with TCP-leg streams silently drops every reused datagram.
pub(super) struct StandbyCtx<'a> {
    pub(super) manager: &'a UplinkManager,
    pub(super) uplink: &'a Uplink,
    pub(super) index: usize,
    pub(super) transport: TransportKind,
    /// Which wire this pool prewarms: `active_wire(index, transport)` when
    /// `tun_wire_dial` is on, else always `0`. Reading `active_wire`
    /// unconditionally would prewarm a wire nothing dials whenever the gate
    /// is off — `shuffle_timer` moves `active_wire` regardless of the gate —
    /// and every take would miss against a pool nothing ever fills correctly.
    pub(super) wire: u8,
    /// The deque that holds pooled `TransportStream`s for this transport.
    pub(super) pool: &'a TrackedDeque,
    /// Serialises concurrent refill attempts for this transport.
    pub(super) refill_lock: &'a Mutex<()>,
    /// Records which wire `pool`'s carriers were actually dialed on. Compared
    /// against `wire` in `try_take_alive` to detect a pool left stale by a
    /// wire rotation.
    pub(super) wire_marker: &'a AtomicU8,
    /// Prometheus label fragment (`"tcp"` / `"udp"`).
    pub(super) label: &'static str,
    /// Source tag passed to `connect_transport` during refill.
    pub(super) refill_source: &'static str,
    pub(super) desired: usize,
    pub(super) url: Option<&'a Url>,
    pub(super) mode: TransportMode,
    /// The combined-SS path discriminator this pool's dials must carry, taken
    /// from the wire (`wire`) rather than the parent uplink: a pool filled
    /// with the other leg's streams silently drops every reused datagram.
    pub(super) combined_ss: Option<SsPathKind>,
}

impl UplinkManager {
    /// Builds the per-transport standby context for `(index, transport)`.
    /// Async because the effective mode depends on runtime downgrade state.
    pub(super) async fn standby_ctx(
        &self,
        index: usize,
        transport: TransportKind,
    ) -> StandbyCtx<'_> {
        let uplink = &self.inner.uplinks[index];
        let pool = &self.inner.standby_pools[index];
        let lb = &self.inner.load_balancing;
        // With the gate off the pool must stay exactly where it is today —
        // on the primary wire. `shuffle_timer` moves `active_wire` regardless
        // of the gate, so reading it unconditionally would prewarm a wire
        // that nothing dials, and every take would miss.
        let wire = if lb.tun_wire_dial {
            self.active_wire(index, transport)
        } else {
            0
        };
        let spec = crate::WireSpec::of(uplink, wire).unwrap_or_else(|| {
            // An active wire past the end of the chain is a bug in the wire
            // state machine, not a reason to stop prewarming: fall back to
            // the primary rather than leaving the pool cold.
            crate::WireSpec::from_uplink(uplink)
        });
        match transport {
            TransportKind::Tcp => StandbyCtx {
                manager: self,
                uplink,
                index,
                transport,
                wire: spec.wire,
                pool: &pool.tcp,
                refill_lock: &pool.tcp_refill,
                wire_marker: pool.wire_marker(TransportKind::Tcp),
                label: "tcp",
                refill_source: "standby_tcp",
                desired: lb.warm_standby_tcp,
                url: spec.dial_url(crate::Plane::Tcp),
                mode: self.effective_tcp_mode_for_wire(index, spec.wire).await,
                combined_ss: spec.combined_ss_kind(SsPathKind::Tcp),
            },
            TransportKind::Udp => StandbyCtx {
                manager: self,
                uplink,
                index,
                transport,
                wire: spec.wire,
                pool: &pool.udp,
                refill_lock: &pool.udp_refill,
                wire_marker: pool.wire_marker(TransportKind::Udp),
                label: "udp",
                refill_source: "standby_udp",
                desired: lb.warm_standby_udp,
                url: spec.dial_url(crate::Plane::Udp),
                mode: self.effective_udp_mode_for_wire(index, spec.wire).await,
                combined_ss: spec.combined_ss_kind(SsPathKind::Udp),
            },
        }
    }

    /// Test-only handle onto [`Self::standby_ctx`]: `StandbyCtx` is
    /// `pub(super)` to `standby`, so tests that only need to read its
    /// resolved `wire` (e.g. confirming a refill would prewarm the active
    /// wire) must live inside this module tree.
    #[cfg(test)]
    pub(super) async fn standby_ctx_for_test(
        &self,
        index: usize,
        transport: TransportKind,
    ) -> StandbyCtx<'_> {
        self.standby_ctx(index, transport).await
    }
}

impl<'a> StandbyCtx<'a> {
    pub(super) fn mode_is_http1(&self) -> bool {
        matches!(self.mode, TransportMode::WsH1)
    }

    pub(super) fn group(&self) -> &str {
        &self.manager.inner.group_name
    }

    /// Emits `record_warm_standby_acquire` with the transport's label.
    pub(super) fn record_acquire(&self, outcome: &'static str) {
        metrics::record_warm_standby_acquire(self.label, self.group(), &self.uplink.name, outcome);
    }

    /// The marker recording which wire `self.pool`'s carriers were actually
    /// dialed on.
    pub(super) fn pool_wire_marker(&self) -> &AtomicU8 {
        self.wire_marker
    }

    /// Pops one pooled WS stream for `wanted` — the wire the caller is
    /// dialing — and returns it if it passes the liveness pre-flight
    /// (`is_connection_alive` + 1 ms peek). Stale entries are discarded with a
    /// `"stale"` metric; `None` means either the pool holds nothing usable for
    /// `wanted`, or `wanted` is not the wire this pool prewarms at all.
    ///
    /// A take that removed anything from the pool — the returned stream, the
    /// stale entries it walked past, or both — schedules exactly ONE background
    /// refill, which restores every drained slot in a single pass. Spawning per
    /// `pop_front()` meant a take that discarded K stale entries fired K refill
    /// tasks, K-1 of which found the pool already back at `desired` and did
    /// nothing but resolve a standby context and bounce off the refill mutex.
    pub(super) async fn try_take_alive(
        &self,
        candidate_name: &str,
        wanted: u8,
    ) -> Option<TransportStream> {
        use tokio_tungstenite::tungstenite::protocol::Message;

        // Asking for a wire the pool is not prewarming is not a staleness
        // problem: the pool belongs to the active wire, and this caller wants
        // a different one. Draining here would fight the refill loop in a
        // permanent cycle — drain, refill on the active wire, drain again on
        // the next take for another wire.
        if wanted != self.wire {
            return None;
        }
        // The marker names the wire these carriers were dialed on. A mismatch
        // means the active wire moved under a filled pool: drain it so the
        // refill repopulates on the wire flows are landing on now.
        let filled_on = self.pool_wire_marker().load(Ordering::Relaxed);
        if filled_on != self.wire {
            let drained = self.pool.drain_all().await;
            if drained > 0 {
                debug!(
                    uplink = %self.uplink.name,
                    transport = ?self.transport,
                    filled_on,
                    active = self.wire,
                    drained,
                    "draining a warm pool filled on a wire that is no longer active",
                );
            }
            self.pool_wire_marker().store(self.wire, Ordering::Relaxed);
            self.record_acquire("wire_changed");
            return None;
        }

        let mut popped_any = false;
        let taken = loop {
            let Some(mut ws) = self.pool.lock().await.pop_front() else {
                break None;
            };
            popped_any = true;

            // Check the underlying shared connection (H2/H3) first — if a
            // previous open_websocket timeout marked it as broken, the 1ms
            // peek alone would not catch it because H2 keepalive may still
            // succeed on the dying connection.
            let alive = if !ws.is_connection_alive() {
                false
            } else {
                match timeout(STANDBY_WS_PEEK_TIMEOUT, ws.next()).await {
                    Err(_elapsed) => true, // would-block: socket still open
                    Ok(None) => false,
                    Ok(Some(Err(_))) => false,
                    Ok(Some(Ok(Message::Close(_)))) => false,
                    Ok(Some(Ok(_))) => true, // stray control/data frame, still usable
                }
            };
            if !alive {
                debug!(
                    uplink = %candidate_name,
                    transport = ?self.transport,
                    "discarded stale warm-standby websocket at acquisition time"
                );
                self.record_acquire("stale");
                // drop `ws`, loop to try the next pool entry
                continue;
            }
            self.record_acquire("hit");
            debug!(
                uplink = %candidate_name,
                transport = ?self.transport,
                "using warm-standby websocket"
            );
            break Some(ws);
        };

        // Refill after the walk, so the loop's discards are covered by the same
        // task as the entry we handed out. Skipped when the pool was already
        // empty: nothing was drained, and the caller's fresh dial plus the
        // maintenance sweep already own that case.
        if popped_any {
            self.manager.spawn_refill(self.index, self.transport);
        }
        taken
    }
}
