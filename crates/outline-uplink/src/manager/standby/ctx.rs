use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::debug;
use url::Url;

use outline_metrics as metrics;
use outline_transport::TransportStream;

use crate::config::{SsPathKind, TransportMode, UplinkTransport};
use crate::manager::standby_pool::WirePool;
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
    /// The **parent** uplink. Read only for things that are per-uplink by
    /// definition — the display name that labels every metric and log line,
    /// and the padding / fingerprint scopes `dial_in_uplink_scope` applies.
    /// Everything a dial's shape depends on comes off the [`crate::WireSpec`]
    /// this context was built from and is mirrored into the fields below:
    /// reading `uplink` for any of those would target the primary carrier no
    /// matter which wire the pool is actually prewarming.
    pub(super) uplink: &'a Uplink,
    pub(super) index: usize,
    pub(super) transport: TransportKind,
    /// Which wire this pool prewarms: `active_wire(index, transport)` when
    /// `tun_wire_dial` is on, else always `0`. Reading `active_wire`
    /// unconditionally would prewarm a wire nothing dials whenever the gate
    /// is off — `shuffle_timer` moves `active_wire` regardless of the gate —
    /// and every take would miss against a pool nothing ever fills correctly.
    pub(super) wire: u8,
    /// The pool that holds pre-dialed carriers for this transport. Its own
    /// wire — which wire those carriers were dialed on — lives inside its
    /// mutex, so rotating it and mutating its entries is one transaction.
    pub(super) pool: &'a WirePool,
    /// Serialises concurrent refill attempts for this transport.
    pub(super) refill_lock: &'a Mutex<()>,
    /// Prometheus label fragment (`"tcp"` / `"udp"`).
    pub(super) label: &'static str,
    /// Source tag passed to `connect_transport` during refill.
    pub(super) refill_source: &'static str,
    pub(super) desired: usize,
    pub(super) url: Option<&'a Url>,
    pub(super) mode: TransportMode,
    /// The transport family of `wire` — **not** of the parent uplink. A
    /// fallback wire may differ in family from its parent (the fleet's shape
    /// is a VLESS primary with SS fallbacks), and two dial decisions turn on
    /// it: whether the pool may be filled at all, and whether the dial has to
    /// negotiate XHTTP datagram record framing. Reading the parent's family
    /// pooled an SS-UDP carrier that never negotiated record boundaries under
    /// a VLESS parent, and every datagram reused off that carrier lost its
    /// framing.
    pub(super) wire_transport: UplinkTransport,
    /// The combined-SS path discriminator this pool's dials must carry, taken
    /// from the wire (`wire`) rather than the parent uplink: a pool filled
    /// with the other leg's streams silently drops every reused datagram.
    pub(super) combined_ss: Option<SsPathKind>,
    /// This wire's routing mark. Per-wire because a fallback can be pinned to
    /// a different egress from its parent — dialing the pool with the
    /// parent's mark would send the carrier out of the wrong interface.
    pub(super) fwmark: Option<u32>,
    /// This wire's address-family preference, per-wire for the same reason as
    /// [`Self::fwmark`].
    pub(super) ipv6_first: bool,
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
                label: "tcp",
                refill_source: "standby_tcp",
                desired: lb.warm_standby_tcp,
                url: spec.dial_url(crate::Plane::Tcp),
                mode: self.effective_tcp_mode_for_wire(index, spec.wire).await,
                wire_transport: spec.transport,
                combined_ss: spec.combined_ss_kind(SsPathKind::Tcp),
                fwmark: spec.fwmark,
                ipv6_first: spec.ipv6_first,
            },
            TransportKind::Udp => StandbyCtx {
                manager: self,
                uplink,
                index,
                transport,
                wire: spec.wire,
                pool: &pool.udp,
                refill_lock: &pool.udp_refill,
                label: "udp",
                refill_source: "standby_udp",
                desired: lb.warm_standby_udp,
                url: spec.dial_url(crate::Plane::Udp),
                mode: self.effective_udp_mode_for_wire(index, spec.wire).await,
                wire_transport: spec.transport,
                combined_ss: spec.combined_ss_kind(SsPathKind::Udp),
                fwmark: spec.fwmark,
                ipv6_first: spec.ipv6_first,
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

    /// Pops one pooled WS stream for `wanted` — the wire the caller is
    /// dialing — and returns it if it passes the liveness pre-flight
    /// (`is_connection_alive` + 1 ms peek). Stale entries are discarded with a
    /// `"stale"` metric; `None` means either the pool holds nothing usable for
    /// `wanted`, or `wanted` is not the wire this pool prewarms at all.
    ///
    /// The wire is checked twice, at two different granularities, and both
    /// checks matter: once against the pool as a whole (has it rotated since
    /// it was filled?) and once against each carrier as it comes off the front
    /// (was *this* carrier dialed on the wanted wire?). The per-carrier check
    /// is the one that cannot be outrun by a concurrent writer, because the
    /// wire it compares travels with the carrier rather than describing the
    /// pool at some earlier moment.
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
        // The pool's own wire names what its carriers were dialed on. A
        // mismatch means the active wire moved under a filled pool: drain it
        // so the refill repopulates on the wire flows are landing on now.
        //
        // Drain and restamp are ONE transaction, under one guard. Split in
        // two — drain under the pool lock, restamp after releasing it — they
        // leave the pool empty but still named for the old wire, and a refill
        // dial for that old wire parked on the lock lands squarely in the
        // gap: its push is accepted, and the restamp that follows declares
        // the carrier to belong to the new wire.
        let rotated = {
            let mut guard = self.pool.lock().await;
            let filled_on = guard.wire();
            (filled_on != self.wire).then(|| (filled_on, guard.claim_wire(self.wire)))
        };
        if let Some((filled_on, drained)) = rotated {
            if drained > 0 {
                debug!(
                    uplink = %self.uplink.name,
                    transport = ?self.transport,
                    filled_on,
                    active = self.wire,
                    drained,
                    "draining a warm pool filled on a wire that is no longer active",
                );
                // Mirrors the ordinary pop loop below: a take that removes
                // anything from the pool schedules exactly one background
                // refill. This drain removes everything at once, so without
                // this call the pool would sit cold until the next
                // `WARM_STANDBY_MAINTENANCE_INTERVAL` sweep (15s) — precisely
                // when a rotation, often a failover, is pushing fresh flows
                // at it. Skipped when nothing was drained (the pool was
                // already empty): the pool is still restamped above, and an
                // empty pool is exactly the case the caller's own fresh dial
                // plus the maintenance sweep already own.
                self.manager.spawn_refill(self.index, self.transport);
            }
            self.record_acquire("wire_changed");
            return None;
        }

        let mut popped_any = false;
        let taken = loop {
            // Ask for `self.wire` explicitly rather than popping blind: the
            // pop is the last point at which a carrier's wire can still be
            // checked before it is handed to a flow, and on UDP it is the
            // only one — `UdpWsTransport::from_websocket` is built off this
            // stream with the wanted wire's credentials, and a mismatch there
            // silently drops every reused datagram with no recovery.
            let popped = self.pool.lock().await.pop_front_for_wire(self.wire);
            if popped.foreign_dropped > 0 {
                popped_any = true;
                debug!(
                    uplink = %candidate_name,
                    transport = ?self.transport,
                    dropped = popped.foreign_dropped,
                    wanted = self.wire,
                    "discarded pooled carriers belonging to another wire",
                );
                self.record_acquire("wire_changed");
            }
            let Some(mut ws) = popped.stream else {
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
