mod ctx;
mod keepalive;
mod refill;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::time::{Instant, sleep};
use tracing::debug;

use outline_metrics as metrics;
use outline_transport::{
    DialNetworkOptions, DialResumeOptions, TransportDialOptions, TransportOperation,
    TransportStream, UdpSessionTransport, UdpWsTransport, VlessUdpSessionMux, connect_transport,
    global_resume_cache,
};

use crate::config::{SsPathKind, UplinkTransport};
use crate::manager::status::PerTransportStatus;
use outline_transport::collections::maybe_shrink_vecdeque;

/// Resolve `(deadline, cap)` from a per-transport status snapshot
/// against the configured mode. Returns the cap when the window is
/// active and the cap is set; falls back to the configured mode
/// otherwise (no window, expired window, or somehow the cap is
/// missing — defensive: a corrupted state should not strand the
/// uplink on a stale mode).
fn capped_or_configured(
    status: &PerTransportStatus,
    configured: crate::config::TransportMode,
) -> crate::config::TransportMode {
    status
        .descent
        .active_cap(tokio::time::Instant::now())
        .unwrap_or(configured)
}

use crate::types::{TransportKind, UplinkCandidate, UplinkManager};

const WARM_STANDBY_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15);

/// Composes the cache key used by the cross-transport resumption
/// helpers in [`outline_transport::global_resume_cache`]. The form
/// `<uplink_name>#<transport>` keeps TCP and UDP entries separate so
/// the next TCP reconnect cannot pick up a UDP-session ID by accident.
///
/// Importantly, the key is **identity-level** — keyed on the parent
/// uplink's display name only — so a fallback dial (different wire
/// family, same uplink) presents the *same* X-Outline-Resume token as
/// the primary dial. The server-side resume mechanism re-attaches the
/// upstream session across wire switches, enabling seamless handover
/// from e.g. VLESS to WS on the same uplink without renegotiating the
/// upstream conversation.
pub(crate) fn resume_cache_key(uplink_name: &str, transport: &str) -> String {
    format!("{uplink_name}#{transport}")
}

impl UplinkManager {
    /// Returns the effective TCP dial mode for `index`, falling back to
    /// the per-uplink mode-downgrade cap when the configured carrier
    /// has been marked broken by repeated runtime / dial errors. The
    /// cap is family-aware: `WsH3` / `Quic` collapse to `WsH2`,
    /// `XhttpH3` collapses to `XhttpH2`, `XhttpH2` to `XhttpH1`.
    /// A multi-step XHTTP downgrade converges over consecutive dials —
    /// the writer in [`extend_mode_downgrade`] lowers the cap one rank
    /// per observed fallback. Applies to Ws and Vless transports;
    /// Shadowsocks always returns the configured mode unchanged.
    ///
    /// [`extend_mode_downgrade`]: crate::manager::mode_downgrade
    pub async fn effective_tcp_mode(&self, index: usize) -> crate::config::TransportMode {
        let uplink = &self.inner.uplinks[index];
        let configured = uplink.tcp_dial_mode();
        if !matches!(uplink.transport, UplinkTransport::Ss | UplinkTransport::Vless) {
            return configured;
        }
        let status = self.inner.read_status(index);
        capped_or_configured(&status.tcp, configured)
    }

    /// Same as `effective_tcp_mode`, but for the UDP-over-WS /
    /// UDP-over-QUIC / UDP-over-XHTTP transport.
    pub(crate) async fn effective_udp_mode(&self, index: usize) -> crate::config::TransportMode {
        let uplink = &self.inner.uplinks[index];
        let configured = uplink.udp_dial_mode();
        if !matches!(uplink.transport, UplinkTransport::Ss | UplinkTransport::Vless) {
            return configured;
        }
        let status = self.inner.read_status(index);
        capped_or_configured(&status.udp, configured)
    }

    /// Pops one connection from the TCP standby pool without falling back to
    /// a fresh dial.  Returns `None` if the pool is empty, or if the popped
    /// entry fails a quick liveness peek (pre-flight check to avoid handing
    /// a stale socket to a fresh SOCKS session).
    ///
    /// The background validation loop runs every 15 s; that is not tight
    /// enough when the upstream closes idle WebSocket connections within a
    /// 10–20 s window.  Re-peeking at acquisition time costs at most
    /// `STANDBY_WS_PEEK_TIMEOUT` (1 ms) per take and closes the race where
    /// a session is handed a socket that server already FIN'd between
    /// validation cycles.  If the peek reports closure, the entry is
    /// dropped and we return `None`; the caller transparently falls back
    /// to `connect_tcp_ws_fresh`, and the pool refill task fills the slot.
    pub async fn try_take_tcp_standby(
        &self,
        candidate: &UplinkCandidate,
    ) -> Option<TransportStream> {
        if !matches!(candidate.uplink.transport, UplinkTransport::Ss | UplinkTransport::Vless) {
            return None;
        }
        let ctx = self.standby_ctx(candidate.index, TransportKind::Tcp).await;
        ctx.try_take_alive(&candidate.uplink.name).await
    }

    /// Dials a fresh TCP WebSocket connection, bypassing the standby pool.
    /// The Ack-Prefix capability is *not* advertised — the dial path used
    /// by initial session setup keeps legacy resume-only semantics. Use
    /// [`Self::connect_tcp_ws_fresh_with_ack_prefix`] from the
    /// pinned-relay mid-session retry path to opt in.
    pub async fn connect_tcp_ws_fresh(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
    ) -> Result<TransportStream> {
        self.connect_tcp_ws_fresh_internal(candidate, source, false, false, 0)
            .await
    }

    /// Same as [`Self::connect_tcp_ws_fresh`] but advertises
    /// `X-Outline-Resume-Ack-Prefix: 1` on the upgrade so the server
    /// emits the v1 control frame on a successful resume hit. Caller
    /// must consume it via the SS reader's
    /// `upstream_acked_offset()` (Phase 2.3.d) before treating bytes
    /// as upstream payload. Used exclusively by the pinned-relay
    /// mid-session retry orchestrator.
    pub async fn connect_tcp_ws_fresh_with_ack_prefix(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
    ) -> Result<TransportStream> {
        self.connect_tcp_ws_fresh_internal(candidate, source, true, false, 0)
            .await
    }

    /// Variant used by the v2 Symmetric Downlink Replay retry path:
    /// advertises both v1 and v2 capabilities, and reports the
    /// caller's `client_acked_offset` via the
    /// `X-Outline-Resume-Down-Acked` request header so the server can
    /// emit a precise replay slice. Caller is expected to gate this
    /// on `LoadBalancingConfig::tcp_symmetric_replay_enabled` and to
    /// have advertised v1 already (the dialer's local v2-on-v1 gate
    /// double-checks this on the response side).
    pub async fn connect_tcp_ws_fresh_with_symmetric_replay(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
        client_acked_offset: u64,
    ) -> Result<TransportStream> {
        self.connect_tcp_ws_fresh_internal(candidate, source, true, true, client_acked_offset)
            .await
    }

    async fn connect_tcp_ws_fresh_internal(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
        ack_prefix_requested: bool,
        symmetric_replay_requested: bool,
        client_acked_offset: u64,
    ) -> Result<TransportStream> {
        let cache = self.inner.dns_cache.as_ref();
        if !matches!(candidate.uplink.transport, UplinkTransport::Ss | UplinkTransport::Vless) {
            bail!("uplink {} does not use websocket transport", candidate.uplink.name);
        }
        metrics::record_warm_standby_acquire(
            "tcp",
            &self.inner.group_name,
            &candidate.uplink.name,
            "miss",
        );
        let mode = self.effective_tcp_mode(candidate.index).await;
        debug!(
            uplink = %candidate.uplink.name,
            mode = %mode,
            ack_prefix_requested,
            "no warm-standby TCP websocket available, dialing on-demand"
        );
        let url = candidate
            .uplink
            .tcp_dial_url()
            .ok_or_else(|| anyhow!("uplink {} missing tcp dial URL", candidate.uplink.name))?;
        let started = Instant::now();
        // Cross-transport session resumption: present the last Session
        // ID this uplink received so an outline-ss-rust server with the
        // feature enabled can re-attach to a still-parked upstream.
        // Cache key is the uplink's display name — unique within a
        // group, stable across reconnects. The store-if-issued at the
        // bottom records the new ID for the next reconnect.
        let resume_key = resume_cache_key(self.resume_scope(&candidate.uplink.name, "tcp"), "tcp");
        let resume_request = global_resume_cache().get(&resume_key);
        let ws = crate::dial::dial_in_uplink_scope(
            &candidate.uplink,
            connect_transport(
                TransportDialOptions::new(cache, url, mode, source)
                    .with_network(DialNetworkOptions {
                        fwmark: candidate.uplink.fwmark,
                        ipv6_first: candidate.uplink.ipv6_first,
                    })
                    .with_combined_ss_kind(candidate.uplink.combined_ss_kind(SsPathKind::Tcp))
                    .with_resume(DialResumeOptions {
                        resume_request,
                        ack_prefix_requested,
                        symmetric_replay_requested,
                        client_acked_offset,
                    }),
            ),
        )
        .await
        .with_context(|| TransportOperation::Connect { target: format!("to {}", url) })?;
        global_resume_cache().store_if_issued(resume_key, ws.issued_session_id());
        // Feed the on-demand dial latency into the RTT EWMA so real
        // connection quality is reflected in routing scores, not just probe
        // ping/pong times.
        self.report_connection_latency(candidate.index, TransportKind::Tcp, started.elapsed())
            .await;
        // Mirror a transport-level downgrade (host clamp via `ws_mode_cache`
        // or inline H3→H2/H1 fallback inside `connect_transport`)
        // into the per-uplink `mode_downgrade_until` window. Without this,
        // `effective_tcp_mode` keeps reporting H3 while every actual dial
        // is silently clamped to H2 — the "ss/ws/h3 stays put" symptom.
        if let Some(requested) = ws.downgraded_from() {
            self.note_silent_transport_fallback(candidate.index, TransportKind::Tcp, requested);
        }
        Ok(ws)
    }

    pub async fn acquire_tcp_standby_or_connect(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
    ) -> Result<TransportStream> {
        if let Some(ws) = self.try_take_tcp_standby(candidate).await {
            return Ok(ws);
        }
        self.connect_tcp_ws_fresh(candidate, source).await
    }

    pub async fn acquire_udp_standby_or_connect(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
    ) -> Result<UdpSessionTransport> {
        use outline_transport::UplinkConnectionBinding;
        let cache = self.inner.dns_cache.as_ref();
        // Per-uplink attribution for the open-connection gauge / close-time
        // classification counter. Built once per dial because every code path
        // below ends in a transport that owns its own `_lifetime` guard
        // attached via `with_uplink_binding`.
        let binding = || {
            UplinkConnectionBinding::new(
                self.inner.group_name.as_str(),
                "udp",
                candidate.uplink.name.as_str(),
            )
        };
        if candidate.uplink.transport == UplinkTransport::Vless {
            // VLESS UDP has no warm-standby pool — each destination opens its
            // own session inside the mux on first packet, so there is no
            // single pre-dialed stream to hand out up front.
            metrics::record_warm_standby_acquire(
                "udp",
                &self.inner.group_name,
                &candidate.uplink.name,
                "miss",
            );
            let udp_ws_url = candidate.uplink.udp_dial_url().ok_or_else(|| {
                anyhow!("vless dial URL is not configured for uplink {}", candidate.uplink.name)
            })?;
            let uuid = candidate.uplink.vless_id.ok_or_else(|| {
                anyhow!("uplink {} is VLESS but has no vless_id", candidate.uplink.name)
            })?;
            let mode = self.effective_udp_mode(candidate.index).await;
            // Hook fired the first time the mux observes a transport-level
            // H3→H2/H1 downgrade on a per-target dial. The mux latches on
            // the first call so a burst of fresh sessions during the same
            // outage doesn't spam the uplink-manager. Mirrors the QUIC-mux
            // `on_fallback` wiring above so both pivots flow through the
            // same per-uplink `mode_downgrade_until` window.
            let manager = self.clone();
            let index = candidate.index;
            let on_downgrade: outline_transport::VlessUdpDowngradeNotifier =
                Arc::new(move |requested: outline_transport::TransportMode| {
                    manager.note_silent_transport_fallback(index, TransportKind::Udp, requested);
                });
            let mux = VlessUdpSessionMux::new_with_limits(
                Arc::clone(&self.inner.dns_cache),
                udp_ws_url.clone(),
                mode,
                uuid,
                candidate.uplink.fwmark,
                candidate.uplink.ipv6_first,
                source,
                self.inner.load_balancing.udp_ws_keepalive_interval,
                self.inner.load_balancing.vless_udp_mux_limits,
            )
            .with_on_downgrade(Some(on_downgrade))
            .with_padding_override(candidate.uplink.padding)
            .with_uplink_binding(binding());
            return Ok(UdpSessionTransport::Vless(mux));
        }

        // WS-pooled UDP: try to reuse a pooled stream first. `try_take_alive`
        // loops past zombie entries (e.g. underlying H2/H3 torn down after
        // pooling) so we never hand a dead transport to the caller.
        let ctx = self.standby_ctx(candidate.index, TransportKind::Udp).await;
        if let Some(ws) = ctx.try_take_alive(&candidate.uplink.name).await {
            // `from_websocket` reads the carrier padding at build time, which on
            // the hot path runs after the dial returns — outside any dial scope.
            // Wrap the build in the per-uplink padding scope so a padded uplink's
            // reused standby stream frames its datagrams (mirrors VLESS-UDP).
            let transport = crate::dial::with_uplink_padding_scope(&candidate.uplink, async {
                UdpWsTransport::from_websocket(
                    ws,
                    candidate.uplink.cipher,
                    &candidate.uplink.password,
                    source,
                    self.inner.load_balancing.udp_ws_keepalive_interval,
                )
            })
            .await?;
            return Ok(UdpSessionTransport::Ss(transport.with_uplink_binding(binding())));
        }

        metrics::record_warm_standby_acquire(
            "udp",
            &self.inner.group_name,
            &candidate.uplink.name,
            "miss",
        );
        debug!(
            uplink = %candidate.uplink.name,
            "no warm-standby UDP websocket available, dialing on-demand"
        );
        // Combined-SS-aware: `udp_dial_url()` resolves to `ss_xhttp_url`/
        // `ss_ws_url` on a combined wire (split `udp_ws_url` is None there).
        let udp_ws_url = candidate.uplink.udp_dial_url().ok_or_else(|| {
            anyhow!("no udp dial URL configured for uplink {}", candidate.uplink.name)
        })?;
        let mode = self.effective_udp_mode(candidate.index).await;
        let started = Instant::now();
        // Cross-transport session resumption for SS-UDP-over-WS.
        // Mirrors the TCP path's ResumeCache wiring; the cache key
        // distinguishes TCP and UDP slots so a TCP-side reconnect
        // doesn't steal the UDP-side Session ID and vice versa.
        let udp_resume_key =
            resume_cache_key(self.resume_scope(&candidate.uplink.name, "udp"), "udp");
        let udp_resume_request = global_resume_cache().get(&udp_resume_key);
        // Scope the per-uplink padding override over the dial + build: padding
        // is read when `from_websocket` builds the transport (after the dial
        // returns), so the scope must wrap the whole future. raw QUIC (handled
        // above) and the global default are unaffected by an absent override.
        let connect = UdpWsTransport::connect_with_resume(
            cache,
            udp_ws_url,
            mode,
            candidate.uplink.cipher,
            &candidate.uplink.password,
            candidate.uplink.fwmark,
            candidate.uplink.ipv6_first,
            source,
            self.inner.load_balancing.udp_ws_keepalive_interval,
            udp_resume_request,
            candidate.uplink.combined_ss_kind(SsPathKind::Udp),
        );
        let (transport, udp_issued, udp_downgraded_from) =
            crate::dial::with_uplink_padding_scope(&candidate.uplink, connect)
                .await
                .with_context(|| TransportOperation::Connect {
                    target: format!("to {}", udp_ws_url),
                })?;
        global_resume_cache().store_if_issued(udp_resume_key, udp_issued);
        self.report_connection_latency(candidate.index, TransportKind::Udp, started.elapsed())
            .await;
        // Mirror a transport-level downgrade (host clamp via `ws_mode_cache`
        // or inline H3→H2/H1 fallback) into the per-uplink window so
        // `effective_udp_mode` reflects reality on subsequent dials.
        if let Some(requested) = udp_downgraded_from {
            self.note_silent_transport_fallback(candidate.index, TransportKind::Udp, requested);
        }
        Ok(UdpSessionTransport::Ss(transport.with_uplink_binding(binding())))
    }

    pub(crate) async fn refill_all_standby(&self) {
        for index in 0..self.inner.uplinks.len() {
            // Administratively-disabled uplinks (operator on/off) are kept out
            // of every automatic path: do not open or maintain warm-standby
            // sockets to a server the operator parked.
            if !self.inner.admin_enabled(index) {
                continue;
            }
            self.maintain_pool(index, TransportKind::Tcp).await;
            self.maintain_pool(index, TransportKind::Udp).await;
        }
    }

    pub(crate) fn spawn_refill(&self, index: usize, transport: TransportKind) {
        let manager = self.clone();
        tokio::spawn(async move {
            manager.refill_pool(index, transport).await;
        });
    }

    pub(crate) async fn maintain_pool(&self, index: usize, transport: TransportKind) {
        let ctx = self.standby_ctx(index, transport).await;
        ctx.validate().await;
        ctx.refill().await;
    }

    /// Sends WebSocket ping frames on idle TCP standby sockets so middleboxes
    /// keep the connection state warm, then replenishes any entries that were
    /// dropped as stale.
    pub(crate) async fn keepalive_tcp_pool(&self, index: usize) {
        if self.inner.load_balancing.warm_standby_tcp == 0 {
            return;
        }
        let ctx = self.standby_ctx(index, TransportKind::Tcp).await;
        if !matches!(ctx.uplink.transport, UplinkTransport::Ss | UplinkTransport::Vless) {
            return;
        }
        ctx.keepalive().await;
        ctx.refill().await;
    }

    async fn refill_pool(&self, index: usize, transport: TransportKind) {
        let ctx = self.standby_ctx(index, transport).await;
        ctx.refill().await;
    }

    pub(crate) async fn clear_standby(&self, index: usize, transport: TransportKind) {
        let pool = &self.inner.standby_pools[index];
        let deque = match transport {
            TransportKind::Tcp => &pool.tcp,
            TransportKind::Udp => &pool.udp,
        };
        let mut guard = deque.lock().await;
        guard.clear();
        maybe_shrink_vecdeque(&mut guard);
    }

    pub fn spawn_warm_standby_loop(&self) {
        if self.inner.load_balancing.warm_standby_tcp == 0
            && self.inner.load_balancing.warm_standby_udp == 0
        {
            return;
        }

        let manager = self.clone();
        let mut shutdown = self.shutdown_rx();
        tokio::spawn(async move {
            manager.refill_all_standby().await;
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    _ = sleep(WARM_STANDBY_MAINTENANCE_INTERVAL) => {}
                }
                manager.refill_all_standby().await;
            }
        });
    }

    /// Spawns a background loop that pings warm-standby **TCP** pool
    /// connections at `tcp_ws_standby_keepalive_interval` to keep them alive
    /// through NAT/firewall idle-timeout windows.  This is separate from the
    /// 15-second validation loop: the validation loop also runs for UDP and
    /// handles refill; this loop is TCP-only and intentionally runs more
    /// frequently.
    pub fn spawn_standby_keepalive_loop(&self) {
        let interval = match self.inner.load_balancing.tcp_ws_standby_keepalive_interval {
            Some(d) if self.inner.load_balancing.warm_standby_tcp > 0 => d,
            _ => return,
        };

        let manager = self.clone();
        let mut shutdown = self.shutdown_rx();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    _ = sleep(interval) => {}
                }
                for index in 0..manager.inner.uplinks.len() {
                    if !manager.inner.admin_enabled(index) {
                        continue;
                    }
                    manager.keepalive_tcp_pool(index).await;
                }
            }
        });
    }

    pub async fn run_standby_maintenance(&self) {
        self.refill_all_standby().await;
    }

    #[cfg(test)]
    pub(crate) async fn run_tcp_standby_keepalive(&self, index: usize) {
        self.keepalive_tcp_pool(index).await;
    }
}
