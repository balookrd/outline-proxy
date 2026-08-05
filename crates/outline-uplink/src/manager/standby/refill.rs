use std::sync::atomic::Ordering;

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
use crate::probe::is_expected_standby_probe_failure;
use crate::types::TransportKind;
use outline_transport::collections::maybe_shrink_vecdeque;

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
        let mut drained = std::collections::VecDeque::new();
        {
            let mut guard = self.pool.lock().await;
            drained.extend(guard.drain(..));
        }

        if drained.is_empty() {
            return;
        }

        let mut alive = std::collections::VecDeque::with_capacity(drained.len());
        while let Some(mut ws) = drained.pop_front() {
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
                Ok(()) => alive.push_back(ws),
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

        let mut guard = self.pool.lock().await;
        guard.extend(alive);
        maybe_shrink_vecdeque(&mut guard);
    }

    /// Attempts to add a freshly dialed `ws` to the pool. Returns the pool's
    /// new length on success; `None` means `ws` was dropped instead, either
    /// because the pool already reached `desired` (a concurrent
    /// validate()/keepalive()/refill() got there first) or because the
    /// pool's wire marker no longer names the wire this stream was dialed
    /// for.
    ///
    /// The marker is re-read here, under the pool lock, rather than only
    /// once before the dial started. `refill` stamps (or inherits) the
    /// marker up front and then dials — and the dial itself is the one thing
    /// on this path with no upper bound on how long it takes. If `active_wire`
    /// moves and a concurrent take drains-and-restamps this pool for the new
    /// wire while THIS dial is still in flight, the marker the caller
    /// resolved against is already stale by the time the stream comes back.
    /// Pushing it anyway would let the fresher marker vouch for a carrier
    /// dialed under the OLD wire's credentials: on UDP the take path builds
    /// the datagram transport straight off a pool pop it trusts completely,
    /// so a mismatched carrier there means every reused datagram silently
    /// drops with no protocol-level recovery — TCP at least fails
    /// `do_tcp_ss_setup` and falls back to a fresh dial. Checking once before
    /// the dial cannot see this: the window only opens *during* the dial, so
    /// the check has to live at the one point after it has had its chance to
    /// open — the push.
    ///
    /// Dropping the stream on a mismatch (rather than, say, trying to
    /// re-file it under the wire the marker now names) is deliberate: a
    /// wasted dial is far cheaper than a mis-credentialed carrier, and the
    /// refill loop that queued this dial will simply stop (see `refill`'s
    /// `None` arm) rather than chase a wire that has already moved once.
    pub(super) async fn try_pool_dialed_stream(&self, ws: TransportStream) -> Option<usize> {
        let mut guard = self.pool.lock().await;
        if self.pool_wire_marker().load(Ordering::Relaxed) != self.wire {
            drop(guard);
            debug!(
                uplink = %self.uplink.name,
                transport = ?self.transport,
                dialed_for = self.wire,
                "dropping a warm-standby dial: its pool rolled onto another wire while it was in flight",
            );
            return None;
        }
        if guard.len() >= self.desired {
            // Connection is dropped here; pool already full.
            return None;
        }
        guard.push_back(ws);
        Some(guard.len())
    }

    /// Dials connections until the pool reaches `desired`. Holds the refill
    /// lock for the whole loop so concurrent refill callers serialise their
    /// dials. Discards Http1 results that appeared as H2/H3 fallbacks to
    /// avoid pooling per-slot TCP sockets under a shared-connection mode.
    pub(super) async fn refill(&self) {
        if self.desired == 0 {
            return;
        }
        if !matches!(self.uplink.transport, UplinkTransport::Ss | UplinkTransport::Vless) {
            return;
        }
        let Some(url) = self.url else { return };

        let cache = self.manager.inner.dns_cache.as_ref();
        let refill_guard = self.refill_lock.lock().await;

        // Read current length once; track additions with a counter to avoid
        // re-locking on every iteration just to check the pool size.
        let mut current_len = self.pool.lock().await.len();
        let mode_is_http1 = self.mode_is_http1();

        // Stamp the marker before dialing into a pool that is genuinely
        // empty. This closes the one window `try_take_alive`'s drain-on-
        // mismatch cannot: a pool that has never been filled starts with the
        // marker at its `0` default, so a refill that lands here with
        // `self.wire != 0` (an active wire already moved before this pool's
        // first fill — startup race, not steady state) must not leave a
        // fresh, correctly-wired pool looking stale to the very next take.
        // Guarded to the empty case only: a pool that still holds entries
        // from a wire this refill has not yet touched (`current_len >=
        // desired`, so the loop below never dials) must keep its old marker
        // — that mismatch is exactly what `try_take_alive` is supposed to
        // catch and drain.
        if current_len == 0 {
            self.pool_wire_marker().store(self.wire, Ordering::Relaxed);
        }

        loop {
            if current_len >= self.desired {
                break;
            }

            let ws = crate::dial::dial_in_uplink_scope(
                self.uplink,
                connect_transport(
                    TransportDialOptions::new(cache, url, self.mode, self.refill_source)
                        .with_network(DialNetworkOptions {
                            fwmark: self.uplink.fwmark,
                            ipv6_first: self.uplink.ipv6_first,
                        })
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
                        // A pooled SS-UDP stream is handed to a datagram
                        // session, so it must negotiate XHTTP record framing at
                        // dial time exactly like an on-demand
                        // `UdpWsTransport::connect` does — the negotiation
                        // rides the dial's request headers and cannot be added
                        // afterwards. VLESS pools frame their own records and
                        // opt out.
                        .with_datagram_records(
                            matches!(self.transport, TransportKind::Udp)
                                && matches!(self.uplink.transport, UplinkTransport::Ss),
                        ),
                ),
            )
            .await
            .with_context(|| format!("failed to preconnect to {}", url));

            match ws {
                Ok(ws) => {
                    // Surface a transport-level downgrade observed during
                    // refill into the per-uplink window so `effective_*_ws_mode`
                    // converges to the actually-dialable mode before any user
                    // session even arrives. Without this, the first cold
                    // refill after restart would silently fill the pool with
                    // H2 entries while the manager still thought it was on H3.
                    if let Some(requested) = ws.downgraded_from() {
                        self.manager.note_silent_transport_fallback(
                            self.index,
                            self.transport,
                            requested,
                        );
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
                                true,
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
                        false,
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
