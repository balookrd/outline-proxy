use anyhow::{Context, Result};
use futures_util::StreamExt;
use tokio::time::{Instant, timeout};
use tracing::{debug, warn};

use outline_metrics as metrics;
use outline_transport::{
    DialNetworkOptions, TransportDialOptions, TransportStream, connect_transport,
};

use crate::config::UplinkTransport;
use crate::error_classify::StandbyProbeExpected;
use crate::manager::standby_pool::{PooledCarrier, PushOutcome};
use crate::probe::is_expected_standby_probe_failure;
use crate::types::TransportKind;

use super::ctx::{STANDBY_WS_PEEK_TIMEOUT, StandbyCtx};

impl<'a> StandbyCtx<'a> {
    /// The resume negotiation this pool's dials carry.
    ///
    /// A pooled TCP carrier is handed to the next session that asks for one, so
    /// it is a **new session's** first dial in every way that matters to the
    /// server — including the one that decides whether the session gets a
    /// downlink replay ring at all. Dialing it without the capabilities is why
    /// most of the fleet's sessions had no ring: `warm_standby_acquire_total`
    /// runs ~74% `hit`, and every one of those sessions answered its first
    /// migration `REPLAY_TRUNCATED` with `reason="no_ring"`.
    ///
    /// The UDP pool keeps the plain shape: SS-UDP has no v1/v2 protocol to
    /// negotiate — it neither emits the control frames nor keeps a ring — so
    /// advertising there would claim a capability the datagram path does not
    /// have.
    fn pool_resume_options(&self) -> outline_transport::DialResumeOptions {
        match self.transport {
            TransportKind::Tcp => outline_transport::DialResumeOptions::new_session(),
            TransportKind::Udp => outline_transport::DialResumeOptions::default(),
        }
    }

    /// Whether this pool's dials must negotiate XHTTP datagram record framing.
    ///
    /// A pooled SS-UDP stream is handed to a datagram session, so it has to
    /// negotiate record boundaries at dial time exactly like an on-demand
    /// `UdpWsTransport::connect` does — the negotiation rides the dial's
    /// request headers and cannot be added afterwards. VLESS frames its own
    /// records and opts out.
    ///
    /// Keyed on the **wire's** family, never the parent's. The two differ on
    /// the fleet's own shape (VLESS primary, SS fallbacks): a VLESS parent
    /// whose UDP active wire is an SS fallback would otherwise pool a carrier
    /// with no record framing, `acquire_udp_on_wire` would take the SS branch,
    /// the wire tags would match, and every datagram reused off that carrier
    /// would lose its boundaries — the same silent-drop class as SS-UDP over
    /// XHTTP without record negotiation.
    pub(super) fn dial_datagram_records(&self) -> bool {
        matches!(self.transport, TransportKind::Udp)
            && matches!(self.wire_transport, UplinkTransport::Ss)
    }

    /// The socket-level knobs this pool's dials carry.
    ///
    /// Per-wire, not per-uplink: a fallback can be pinned to a different
    /// egress (`fwmark`) or address family from its parent, and the pool is
    /// prewarming that fallback. Reading the parent's here would open the
    /// pooled carriers out of an interface no flow on this wire uses.
    pub(super) fn dial_network_options(&self) -> DialNetworkOptions {
        DialNetworkOptions {
            fwmark: self.fwmark,
            ipv6_first: self.ipv6_first,
        }
    }

    /// Reports a transport-level downgrade observed on a refill dial into the
    /// descent slot of the wire that was actually dialed.
    ///
    /// The wire-aware entry point, not the parent-level one: the pool follows
    /// the active wire, so a fallback wire's silent `xhttp_h3 → xhttp_h2`
    /// fallback reported against primary's slot caps a carrier that never
    /// failed, for `mode_downgrade_duration`, while the fallback's own slot
    /// stays empty — which also strands `wire_is_at_carrier_floor` below the
    /// floor and never releases the rotation gate for that wire. Refill is the
    /// dominant dial producer on this client, so the mis-attribution repeats
    /// for as long as the pool sits on a fallback.
    pub(super) fn note_dial_downgrade(&self, requested: crate::config::TransportMode) {
        self.manager.note_silent_transport_fallback_for_wire(
            self.index,
            self.transport,
            self.wire,
            requested,
        );
    }

    /// Drains the pool, peeks each entry for liveness, and writes survivors
    /// back. Entries that slipped in as Http1 fallbacks under H2/H3 are
    /// evicted unconditionally (they each own a distinct TCP socket, so
    /// keeping them defeats pooling and accumulates FDs).
    pub(super) async fn validate(&self) {
        use tokio_tungstenite::tungstenite::protocol::Message;

        if self.desired == 0 {
            return;
        }

        let mode_is_http1 = self.mode_is_http1();
        // The carriers come out tagged with the wire each was dialed on, and
        // go back in only if the pool still prewarms that wire — see
        // `WirePoolGuard::restore`. The sweep holds them outside the lock for
        // as long as the probes take, and the pool reads as *empty* for that
        // whole stretch: long enough for a take to rotate it onto another
        // wire, or for a refill to find it cold and claim it. Handing these
        // back unconditionally would file old-wire carriers under the new
        // wire's identity.
        let mut drained = {
            let mut guard = self.pool.lock().await;
            guard.take_all()
        };

        if drained.is_empty() {
            return;
        }

        let mut alive = std::collections::VecDeque::with_capacity(drained.len());
        while let Some(PooledCarrier { wire, stream: mut ws }) = drained.pop_front() {
            let started = Instant::now();
            // Evict Http1 connections that are present as H2/H3 fallbacks.
            // These each own their own TCP socket, so keeping them in the
            // pool accumulates FDs without sharing the underlying
            // connection. When Http1 is the explicitly configured mode,
            // skip eviction and let the standard timeout-peek decide
            // liveness instead.
            if matches!(ws, TransportStream::Http1 { .. }) && !mode_is_http1 {
                debug!(
                    uplink = %self.uplink.name,
                    transport = ?self.transport,
                    "evicting Http1 fallback connection from warm-standby pool"
                );
                drop(ws);
                continue;
            }
            // Liveness probe: non-blocking read with a 1 ms timeout. Many
            // servers don't respond to WebSocket ping frames, so we peek
            // instead: closure surfaces as a Close frame or an error
            // immediately; a read timeout means the connection is still
            // alive.
            let alive_result: Result<()> = if !ws.is_connection_alive() {
                Err(anyhow::Error::from(StandbyProbeExpected)
                    .context("underlying shared connection is closed"))
            } else {
                match timeout(STANDBY_WS_PEEK_TIMEOUT, ws.next()).await {
                    Err(_elapsed) => Ok(()), // still open — nothing to read
                    Ok(None) => Err(anyhow::Error::from(StandbyProbeExpected)
                        .context("standby websocket stream ended")),
                    Ok(Some(Err(e))) => {
                        Err(anyhow::Error::from(e).context("standby websocket error"))
                    },
                    Ok(Some(Ok(Message::Close(frame)))) => {
                        Err(anyhow::Error::from(StandbyProbeExpected)
                            .context(format!("standby websocket closed by server: {:?}", frame)))
                    },
                    Ok(Some(Ok(_))) => Ok(()), // unexpected data frame — still alive
                }
            };
            metrics::record_probe(
                self.group(),
                &self.uplink.name,
                self.label,
                "standby_ws",
                alive_result.is_ok(),
                started.elapsed(),
            );
            match alive_result {
                Ok(()) => alive.push_back(PooledCarrier { wire, stream: ws }),
                Err(error) => {
                    if is_expected_standby_probe_failure(&error) {
                        debug!(
                            uplink = %self.uplink.name,
                            transport = ?self.transport,
                            error = %format!("{error:#}"),
                            "dropping stale warm-standby websocket"
                        );
                    } else {
                        warn!(
                            uplink = %self.uplink.name,
                            transport = ?self.transport,
                            error = %format!("{error:#}"),
                            "dropping stale warm-standby websocket"
                        );
                    }
                },
            }
        }

        let stranded = self.pool.lock().await.restore(alive);
        if stranded > 0 {
            debug!(
                uplink = %self.uplink.name,
                transport = ?self.transport,
                stranded,
                "dropping swept warm-standby carriers: the pool rolled onto another wire \
                 while they were out being probed",
            );
        }
    }

    /// Attempts to add a freshly dialed `ws` to the pool on behalf of
    /// `self.wire`. Returns the pool's new length on success; `None` means
    /// `ws` was dropped instead, either because the pool already reached
    /// `desired` (a concurrent validate()/keepalive()/refill() got there
    /// first) or because the pool no longer prewarms the wire this stream was
    /// dialed for.
    ///
    /// Both checks happen inside [`WirePoolGuard::push_for_wire`], under the
    /// one pool guard, rather than once before the dial started. `refill`
    /// resolves its wire up front and then dials — and the dial is the one
    /// thing on this path with no upper bound on how long it takes. If
    /// `active_wire` moves and a concurrent take rotates this pool onto the
    /// new wire while THIS dial is still in flight, the wire the caller
    /// resolved against is already stale by the time the stream comes back.
    /// Pushing it anyway would seat a carrier dialed under the OLD wire's
    /// credentials in a pool that says it serves the new one: on UDP the take
    /// path builds the datagram transport straight off a pool pop, so a
    /// mismatched carrier there means every reused datagram silently drops
    /// with no protocol-level recovery — TCP at least fails `do_tcp_ss_setup`
    /// and falls back to a fresh dial. Checking once before the dial cannot
    /// see this: the window only opens *during* the dial, so the check has to
    /// live at the one point after it has had its chance to open — the push.
    ///
    /// Dropping the stream on a mismatch (rather than, say, re-filing it
    /// under the wire the pool now serves) is deliberate: a wasted dial is
    /// far cheaper than a mis-credentialed carrier, and the refill loop that
    /// queued this dial will simply stop (see `refill`'s `None` arm) rather
    /// than chase a wire that has already moved once.
    pub(super) async fn try_pool_dialed_stream(&self, ws: TransportStream) -> Option<usize> {
        let outcome = self.pool.lock().await.push_for_wire(self.wire, self.desired, ws);
        match outcome {
            PushOutcome::Pooled(len) => Some(len),
            // Connection was dropped by the guard; pool already full.
            PushOutcome::Full => None,
            PushOutcome::WrongWire => {
                // A rotation storm that keeps outrunning in-flight dials
                // burns them one after another, so this needs a counter and
                // not only a `debug!` line: on `/metrics` it lands in
                // `warm_standby_refill_total{result="wire_changed"}`, next to
                // the `success` / `error` outcomes of the same dials.
                metrics::record_warm_standby_refill(
                    self.label,
                    self.group(),
                    &self.uplink.name,
                    "wire_changed",
                );
                debug!(
                    uplink = %self.uplink.name,
                    transport = ?self.transport,
                    dialed_for = self.wire,
                    "dropping a warm-standby dial: its pool rolled onto another wire while it was in flight",
                );
                None
            },
        }
    }

    /// Dials connections until the pool reaches `desired`. Holds the refill
    /// lock for the whole loop so concurrent refill callers serialise their
    /// dials. Discards Http1 results that appeared as H2/H3 fallbacks to
    /// avoid pooling per-slot TCP sockets under a shared-connection mode.
    pub(super) async fn refill(&self) {
        if self.desired == 0 {
            return;
        }
        // The wire's family, not the parent's: whether this pool can be filled
        // at all is a property of the carrier being dialed.
        if !matches!(self.wire_transport, UplinkTransport::Ss | UplinkTransport::Vless) {
            return;
        }
        let Some(url) = self.url else { return };

        let cache = self.manager.inner.dns_cache.as_ref();
        let refill_guard = self.refill_lock.lock().await;

        // Read current length once; track additions with a counter to avoid
        // re-locking on every iteration just to check the pool size.
        //
        // Claiming the wire for a pool that is genuinely empty closes the one
        // window `try_take_alive`'s drain-on-mismatch cannot: a pool that has
        // never been filled starts on wire `0` by default, so a refill that
        // lands here with `self.wire != 0` (an active wire already moved
        // before this pool's first fill — startup race, not steady state)
        // must not leave a fresh, correctly-wired pool looking stale to the
        // very next take. Guarded to the empty case only: a pool that still
        // holds carriers from a wire this refill has not yet touched
        // (`current_len >= desired`, so the loop below never dials) keeps its
        // old wire — that mismatch is exactly what `try_take_alive` is
        // supposed to catch and drain. Both the emptiness test and the claim
        // happen under one guard, so nothing can push into "the empty pool"
        // between them.
        let mut current_len = {
            let mut guard = self.pool.lock().await;
            if guard.is_empty() {
                guard.claim_wire(self.wire);
            }
            guard.len()
        };
        let mode_is_http1 = self.mode_is_http1();

        loop {
            if current_len >= self.desired {
                break;
            }

            // The parent, deliberately, and the last thing on this path that
            // reads it: padding and the fingerprint strategy are configured
            // per uplink rather than per wire (see `WireSpec`'s module docs),
            // and every sibling dial site scopes them off the parent the same
            // way. Everything the dial's *shape* depends on comes off the
            // wire — see the option builders below.
            let ws = crate::dial::dial_in_uplink_scope(
                self.uplink,
                connect_transport(
                    TransportDialOptions::new(cache, url, self.mode, self.refill_source)
                        // Resolved against THIS wire, not the parent — see
                        // `dial_network_options`.
                        .with_network(self.dial_network_options())
                        // The combined-SS discriminator (the hidden tcp/udp bit in the
                        // session-id / WS token) must match THIS pool's leg. A UDP
                        // standby stream dialed with the TCP token lands on the server's
                        // SS-TCP relay, so `acquire_udp_standby_or_connect` reusing it for
                        // a datagram session feeds every packet into the TCP decryptor and
                        // the echo never returns — combined-SS UDP looks dead while
                        // VLESS-UDP (no pool) keeps working. Split-path uplinks are
                        // unaffected (`combined_ss_kind` is `None` regardless of leg).
                        // Taken from the ctx (resolved against `self.wire`, not the
                        // parent) — a pool filled on a fallback wire must carry that
                        // wire's own combined-SS shape, not the primary's.
                        .with_combined_ss_kind(self.combined_ss)
                        // A pooled TCP carrier becomes some session's first
                        // carrier, so it dials as a new session would — the
                        // advertisement is what gives that session a ring.
                        .with_resume(self.pool_resume_options())
                        // Resolved against THIS wire's family — see
                        // `dial_datagram_records`.
                        .with_datagram_records(self.dial_datagram_records()),
                ),
            )
            .await
            .with_context(|| format!("failed to preconnect to {}", url));

            match ws {
                Ok(ws) => {
                    // Surface a transport-level downgrade observed during
                    // refill into this wire's descent window so
                    // `effective_*_mode_for_wire` converges to the
                    // actually-dialable mode before any user session even
                    // arrives. Without this, the first cold refill after
                    // restart would silently fill the pool with H2 entries
                    // while the manager still thought it was on H3.
                    if let Some(requested) = ws.downgraded_from() {
                        self.note_dial_downgrade(requested);
                    }
                    // H2/H3 connections are shared (one socket per server, N
                    // streams per socket), so pooling them is cheap. When
                    // H2/H3 is configured but the server fell back to Http1,
                    // each "standby" slot owns its own TCP socket — pooling
                    // defeats the purpose and accumulates FDs silently. Bail
                    // out in that case. When Http1 is *explicitly*
                    // configured, pooling a single Http1 connection is the
                    // intended behavior.
                    if matches!(ws, TransportStream::Http1 { .. }) && !mode_is_http1 {
                        break;
                    }

                    // Read the probe before the stream is handed to
                    // `try_pool_dialed_stream`, which either moves it into the
                    // pool or drops it — `loss_probe()` borrows, it does not
                    // consume, but there is no `ws` left to call it on once
                    // that returns.
                    let probe = ws.loss_probe();

                    match self.try_pool_dialed_stream(ws).await {
                        Some(len) => {
                            // The warm pool follows the active wire
                            // (`self.wire`), so attribution must too — filing
                            // every pooled carrier under the primary slot
                            // would put the loss verdict where nothing reads
                            // it once the pool has rolled onto a fallback.
                            // Registering here — not just on the sibling
                            // on-demand dial sites — matters because this
                            // pool is the majority producer of user carriers:
                            // without it, every carrier that started life as
                            // a pooled entry (most of them) went unmeasured,
                            // and on an explicitly-`h1` pool, where each slot
                            // owns its own socket rather than sharing a
                            // carrier opened elsewhere, its carriers were
                            // never measured at all. Filed only once the
                            // stream is actually pooled: a carrier dropped by
                            // `try_pool_dialed_stream`'s wire-mismatch check
                            // was never handed to anyone, so a probe for it
                            // would just be dead weight in the registry.
                            self.manager.register_carrier_loss_probe(
                                self.index,
                                self.wire,
                                self.transport,
                                probe,
                            );
                            current_len = len;
                            metrics::record_warm_standby_refill(
                                self.label,
                                self.group(),
                                &self.uplink.name,
                                "success",
                            );
                            debug!(
                                uplink = %self.uplink.name,
                                transport = ?self.transport,
                                desired = self.desired,
                                "warm-standby websocket replenished"
                            );
                        },
                        None => {
                            // Either the pool already reached `desired` (a
                            // concurrent validate()/keepalive()/refill() got
                            // there first) or this pool's wire marker no
                            // longer names the wire this dial was for (see
                            // `try_pool_dialed_stream`) — either way there is
                            // nothing left for this refill call to do.
                            break;
                        },
                    }
                },
                Err(error) => {
                    metrics::record_warm_standby_refill(
                        self.label,
                        self.group(),
                        &self.uplink.name,
                        "error",
                    );
                    warn!(
                        uplink = %self.uplink.name,
                        transport = ?self.transport,
                        error = %format!("{error:#}"),
                        "failed to replenish warm-standby websocket"
                    );
                    break;
                },
            }
        }

        drop(refill_guard);
    }
}
