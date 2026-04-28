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
    TransportOperation, UdpSessionTransport, UdpWsTransport, VlessUdpSessionMux, WsTransportStream,
    connect_shadowsocks_udp_with_source, connect_websocket_with_resume,
    connect_websocket_with_source, global_resume_cache,
};

use crate::config::UplinkTransport;
use crate::utils::maybe_shrink_vecdeque;

use crate::types::{TransportKind, UplinkCandidate, UplinkManager};

const WARM_STANDBY_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15);

/// Composes the cache key used by the cross-transport resumption
/// helpers in [`outline_transport::global_resume_cache`]. The form
/// `<uplink_name>#<transport>` keeps TCP and UDP entries separate so
/// the next TCP reconnect cannot pick up a UDP-session ID by accident.
pub(super) fn resume_cache_key(uplink_name: &str, transport: &str) -> String {
    format!("{uplink_name}#{transport}")
}

impl UplinkManager {
    /// Returns the effective TCP dial mode for `index`, falling back to H2
    /// when an "advanced" mode (H3 or raw QUIC) has been marked broken by
    /// repeated runtime / dial errors.  Applies to Ws and Vless transports.
    pub async fn effective_tcp_ws_mode(
        &self,
        index: usize,
    ) -> crate::config::WsTransportMode {
        let uplink = &self.inner.uplinks[index];
        let configured = uplink.tcp_dial_mode();
        let advanced = matches!(
            configured,
            crate::config::WsTransportMode::H3 | crate::config::WsTransportMode::Quic
        );
        let supports_downgrade = matches!(
            uplink.transport,
            UplinkTransport::Ws | UplinkTransport::Vless
        );
        if advanced && supports_downgrade {
            let status = self.inner.read_status(index);
            if status
                .tcp
                .h3_downgrade_until
                .is_some_and(|t| t > tokio::time::Instant::now())
            {
                return crate::config::WsTransportMode::H2;
            }
        }
        configured
    }

    /// Same as `effective_tcp_ws_mode`, but for the UDP-over-WS / UDP-over-QUIC
    /// transport.
    pub(crate) async fn effective_udp_ws_mode(
        &self,
        index: usize,
    ) -> crate::config::WsTransportMode {
        let uplink = &self.inner.uplinks[index];
        let configured = uplink.udp_dial_mode();
        let advanced = matches!(
            configured,
            crate::config::WsTransportMode::H3 | crate::config::WsTransportMode::Quic
        );
        let supports_downgrade = matches!(
            uplink.transport,
            UplinkTransport::Ws | UplinkTransport::Vless
        );
        if advanced && supports_downgrade {
            let status = self.inner.read_status(index);
            if status
                .udp
                .h3_downgrade_until
                .is_some_and(|t| t > tokio::time::Instant::now())
            {
                return crate::config::WsTransportMode::H2;
            }
        }
        configured
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
    ) -> Option<WsTransportStream> {
        if !matches!(
            candidate.uplink.transport,
            UplinkTransport::Ws | UplinkTransport::Vless
        ) {
            return None;
        }
        // The pool is never refilled when the effective TCP mode is raw
        // QUIC (refill returns early), so the lookup would always come
        // back empty. Skip it to avoid the per-call pool lock and the
        // bogus `miss` counter inflation against a pool that cannot
        // produce a stream by design.
        if self.effective_tcp_ws_mode(candidate.index).await
            == outline_transport::WsTransportMode::Quic
        {
            return None;
        }
        let ctx = self.standby_ctx(candidate.index, TransportKind::Tcp).await;
        ctx.try_take_alive(&candidate.uplink.name).await
    }

    /// Dials a fresh TCP WebSocket connection, bypassing the standby pool.
    pub async fn connect_tcp_ws_fresh(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
    ) -> Result<WsTransportStream> {
        let cache = self.inner.dns_cache.as_ref();
        if !matches!(
            candidate.uplink.transport,
            UplinkTransport::Ws | UplinkTransport::Vless
        ) {
            bail!("uplink {} does not use websocket transport", candidate.uplink.name);
        }
        metrics::record_warm_standby_acquire(
            "tcp",
            &self.inner.group_name,
            &candidate.uplink.name,
            "miss",
        );
        let mode = self.effective_tcp_ws_mode(candidate.index).await;
        debug!(
            uplink = %candidate.uplink.name,
            mode = %mode,
            "no warm-standby TCP websocket available, dialing on-demand"
        );
        let url = candidate.uplink.tcp_dial_url().ok_or_else(|| {
            anyhow!("uplink {} missing tcp dial URL", candidate.uplink.name)
        })?;
        let started = Instant::now();
        // Cross-transport session resumption: present the last Session
        // ID this uplink received so an outline-ss-rust server with the
        // feature enabled can re-attach to a still-parked upstream.
        // Cache key is the uplink's display name — unique within a
        // group, stable across reconnects. The store-if-issued at the
        // bottom records the new ID for the next reconnect.
        let resume_key = resume_cache_key(&candidate.uplink.name, "tcp");
        let resume_request = global_resume_cache().get(&resume_key);
        let ws = connect_websocket_with_resume(
            cache,
            url,
            mode,
            candidate.uplink.fwmark,
            candidate.uplink.ipv6_first,
            source,
            resume_request,
        )
        .await
        .with_context(|| TransportOperation::Connect {
            target: format!("to {}", url),
        })?;
        global_resume_cache().store_if_issued(resume_key, ws.issued_session_id());
        // Feed the on-demand dial latency into the RTT EWMA so real
        // connection quality is reflected in routing scores, not just probe
        // ping/pong times.
        self.report_connection_latency(candidate.index, TransportKind::Tcp, started.elapsed())
            .await;
        // Mirror a transport-level downgrade (host clamp via `ws_mode_cache`
        // or inline H3→H2/H1 fallback inside `connect_websocket_with_resume`)
        // into the per-uplink `h3_downgrade_until` window. Without this,
        // `effective_tcp_ws_mode` keeps reporting H3 while every actual dial
        // is silently clamped to H2 — the "ss/ws/h3 stays put" symptom.
        if let Some(requested) = ws.downgraded_from() {
            self.note_silent_transport_fallback(
                candidate.index,
                TransportKind::Tcp,
                requested,
            );
        }
        Ok(ws)
    }

    pub async fn acquire_tcp_standby_or_connect(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
    ) -> Result<WsTransportStream> {
        if let Some(ws) = self.try_take_tcp_standby(candidate).await {
            return Ok(ws);
        }
        self.connect_tcp_ws_fresh(candidate, source).await
    }

    /// Dial a fresh TCP session over raw QUIC. Returns a ready-to-use
    /// `(TcpWriter, TcpReader)` pair — no warm-standby pool is involved
    /// because QUIC connection sharing already happens at the
    /// per-ALPN cache layer (`outline_transport::quic`).
    ///
    /// `source` selects between probe and shared paths (probes bypass
    /// the connection cache; everything else can reuse).
    #[cfg(feature = "quic")]
    pub async fn connect_tcp_quic_fresh(
        &self,
        candidate: &UplinkCandidate,
        target: &socks5_proto::TargetAddr,
        source: &'static str,
    ) -> Result<(outline_transport::TcpWriter, outline_transport::TcpReader)> {
        use outline_transport::UpstreamTransportGuard;
        let cache = self.inner.dns_cache.as_ref();
        let uplink = &candidate.uplink;
        let url = uplink.tcp_dial_url().ok_or_else(|| {
            anyhow!("uplink {} missing dial URL for quic transport", uplink.name)
        })?;
        let lifetime = UpstreamTransportGuard::new(source, "tcp");
        let started = Instant::now();
        let (writer, reader) = match uplink.transport {
            UplinkTransport::Vless => {
                let uuid = uplink
                    .vless_id
                    .as_ref()
                    .ok_or_else(|| anyhow!("uplink {} missing vless_id", uplink.name))?;
                // Cross-transport resumption shares the `#tcp` cache
                // slot between VLESS-TCP-WS and VLESS-TCP-raw-QUIC
                // dials of the same uplink — server-side both park
                // under `Parked::Tcp(Vless)`, so one Session ID is
                // valid through either transport.
                let resume_key = resume_cache_key(&uplink.name, "tcp");
                let resume_request = global_resume_cache().get(&resume_key);
                let resume_id_bytes = resume_request.map(|id| *id.as_bytes());
                let (w, r, issued_rx) =
                    outline_transport::connect_vless_tcp_quic_with_resume(
                        cache,
                        url,
                        uplink.fwmark,
                        uplink.ipv6_first,
                        source,
                        uuid,
                        target,
                        lifetime,
                        resume_id_bytes.as_ref(),
                    )
                    .await
                    .with_context(|| TransportOperation::Connect {
                        target: format!("vless quic to {}", url),
                    })?;
                // The dial returns before the server's handshake response
                // is read — saves one full RTT on every cold dial. The
                // reader fires `issued_rx` from inside its first
                // `read_chunk` call once the response addons have been
                // parsed; we forward the result into the global resume
                // cache asynchronously so this dial path stays
                // non-blocking. If the connection dies before any
                // payload arrives, `issued_rx` resolves to `Err(_)` and
                // we simply don't update the cache, which is correct —
                // a session ID we never observed is not worth storing.
                tokio::spawn(async move {
                    if let Ok(issued) = issued_rx.await {
                        global_resume_cache().store_if_issued(resume_key, issued);
                    }
                });
                (
                    outline_transport::TcpWriter::Vless(w),
                    outline_transport::TcpReader::Vless(r),
                )
            }
            UplinkTransport::Ws => {
                // Standalone "shadowsocks-over-quic" path uses the
                // existing WS uplink config: same URL field, but
                // `tcp_ws_mode = "quic"` selects this branch.
                let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
                let (mut w, r) = outline_transport::connect_ss_tcp_quic(
                    cache,
                    url,
                    uplink.fwmark,
                    uplink.ipv6_first,
                    source,
                    uplink.cipher,
                    &master_key,
                    Arc::clone(&lifetime),
                )
                .await
                .with_context(|| TransportOperation::Connect {
                    target: format!("ss quic to {}", url),
                })?;
                let request_salt = w.request_salt();
                let r = r.with_request_salt(request_salt);
                let target_wire = target.to_wire_bytes()?;
                w.send_chunk(&target_wire)
                    .await
                    .context("failed to send target address over ss-quic")?;
                (
                    outline_transport::TcpWriter::QuicSs(w),
                    outline_transport::TcpReader::QuicSs(r),
                )
            }
            UplinkTransport::Shadowsocks => {
                bail!(
                    "uplink {} uses direct shadowsocks transport, not compatible with quic mode",
                    uplink.name
                );
            }
        };
        self.report_connection_latency(candidate.index, TransportKind::Tcp, started.elapsed())
            .await;
        Ok((writer, reader))
    }

    pub async fn acquire_udp_standby_or_connect(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
    ) -> Result<UdpSessionTransport> {
        let cache = self.inner.dns_cache.as_ref();
        if candidate.uplink.transport == UplinkTransport::Shadowsocks {
            metrics::record_warm_standby_acquire(
                "udp",
                &self.inner.group_name,
                &candidate.uplink.name,
                "miss",
            );
            let udp_addr = candidate.uplink.udp_addr.as_ref().ok_or_else(|| {
                anyhow!("udp_addr is not configured for uplink {}", candidate.uplink.name)
            })?;
            let started = Instant::now();
            let socket = connect_shadowsocks_udp_with_source(
                cache,
                udp_addr,
                candidate.uplink.fwmark,
                candidate.uplink.ipv6_first,
                source,
            )
            .await
            .with_context(|| TransportOperation::Connect { target: format!("to {}", udp_addr) })?;
            self.report_connection_latency(candidate.index, TransportKind::Udp, started.elapsed())
                .await;
            return UdpWsTransport::from_socket(
                socket,
                candidate.uplink.cipher,
                &candidate.uplink.password,
                source,
            )
            .map(UdpSessionTransport::Ss);
        }

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
            let udp_ws_url = candidate.uplink.vless_ws_url.as_ref().ok_or_else(|| {
                anyhow!("vless_ws_url is not configured for uplink {}", candidate.uplink.name)
            })?;
            let uuid = candidate.uplink.vless_id.ok_or_else(|| {
                anyhow!("uplink {} is VLESS but has no vless_id", candidate.uplink.name)
            })?;
            let mode = self.effective_udp_ws_mode(candidate.index).await;
            #[cfg(feature = "quic")]
            if mode == outline_transport::WsTransportMode::Quic {
                let quic_mux = outline_transport::VlessUdpQuicMux::new(
                    Arc::clone(&self.inner.dns_cache),
                    udp_ws_url.clone(),
                    uuid,
                    candidate.uplink.fwmark,
                    candidate.uplink.ipv6_first,
                    source,
                    self.inner.load_balancing.vless_udp_mux_limits,
                );
                // WS fallback factory: same uplink parameters as the QUIC
                // mux, but mode forced to H2 — the H3-downgrade window
                // recorded by the on_fallback callback below makes any
                // fresh WS dial during the cooldown skip H3 anyway, so
                // hard-coding H2 here keeps the post-fallback path
                // deterministic instead of racing the cache update.
                let dns_cache = Arc::clone(&self.inner.dns_cache);
                let ws_url = udp_ws_url.clone();
                let fwmark = candidate.uplink.fwmark;
                let ipv6_first = candidate.uplink.ipv6_first;
                let keepalive = self.inner.load_balancing.udp_ws_keepalive_interval;
                let limits = self.inner.load_balancing.vless_udp_mux_limits;
                let ws_factory: outline_transport::WsFallbackFactory = Box::new(move || {
                    VlessUdpSessionMux::new_with_limits(
                        dns_cache,
                        ws_url,
                        outline_transport::WsTransportMode::H2,
                        uuid,
                        fwmark,
                        ipv6_first,
                        source,
                        keepalive,
                        limits,
                    )
                });
                let manager = self.clone();
                let index = candidate.index;
                let on_fallback: outline_transport::FallbackNotifier =
                    Arc::new(move |error: &anyhow::Error| {
                        manager.note_advanced_mode_dial_failure(
                            index,
                            TransportKind::Udp,
                            error,
                        );
                    });
                let hybrid = outline_transport::VlessUdpHybridMux::from_quic(
                    quic_mux,
                    ws_factory,
                    Some(on_fallback),
                );
                return Ok(UdpSessionTransport::VlessQuic(hybrid));
            }
            // Hook fired the first time the mux observes a transport-level
            // H3→H2/H1 downgrade on a per-target dial. The mux latches on
            // the first call so a burst of fresh sessions during the same
            // outage doesn't spam the uplink-manager. Mirrors the QUIC-mux
            // `on_fallback` wiring above so both pivots flow through the
            // same per-uplink `h3_downgrade_until` window.
            let manager = self.clone();
            let index = candidate.index;
            let on_downgrade: outline_transport::VlessUdpDowngradeNotifier =
                Arc::new(move |requested: outline_transport::WsTransportMode| {
                    manager.note_silent_transport_fallback(
                        index,
                        TransportKind::Udp,
                        requested,
                    );
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
            .with_on_downgrade(Some(on_downgrade));
            return Ok(UdpSessionTransport::Vless(mux));
        }

        // WS-pooled UDP: try to reuse a pooled stream first. `try_take_alive`
        // loops past zombie entries (e.g. underlying H2/H3 torn down after
        // pooling) so we never hand a dead transport to the caller.
        let ctx = self.standby_ctx(candidate.index, TransportKind::Udp).await;
        if let Some(ws) = ctx.try_take_alive(&candidate.uplink.name).await {
            return UdpWsTransport::from_websocket(
                ws,
                candidate.uplink.cipher,
                &candidate.uplink.password,
                source,
                self.inner.load_balancing.udp_ws_keepalive_interval,
            )
            .map(UdpSessionTransport::Ss);
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
        let udp_ws_url = candidate.uplink.udp_ws_url.as_ref().ok_or_else(|| {
            anyhow!("udp_ws_url is not configured for uplink {}", candidate.uplink.name)
        })?;
        let mut mode = self.effective_udp_ws_mode(candidate.index).await;
        let started = Instant::now();
        #[cfg(feature = "quic")]
        if mode == outline_transport::WsTransportMode::Quic {
            match outline_transport::connect_ss_udp_quic(
                cache,
                udp_ws_url,
                candidate.uplink.fwmark,
                candidate.uplink.ipv6_first,
                source,
                candidate.uplink.cipher,
                &candidate.uplink.password,
            )
            .await
            {
                Ok(transport) => {
                    self.report_connection_latency(
                        candidate.index,
                        TransportKind::Udp,
                        started.elapsed(),
                    )
                    .await;
                    return Ok(UdpSessionTransport::Ss(transport));
                }
                Err(e) => {
                    tracing::warn!(
                        uplink = %candidate.uplink.name,
                        url = %udp_ws_url,
                        error = %format!("{e:#}"),
                        fallback = "ws/h2",
                        "ss raw-QUIC UDP dial failed, falling back to WS over H2"
                    );
                    self.note_advanced_mode_dial_failure(
                        candidate.index,
                        TransportKind::Udp,
                        &e,
                    );
                    mode = self.effective_udp_ws_mode(candidate.index).await;
                }
            }
        }
        // Cross-transport session resumption for SS-UDP-over-WS.
        // Mirrors the TCP path's ResumeCache wiring; the cache key
        // distinguishes TCP and UDP slots so a TCP-side reconnect
        // doesn't steal the UDP-side Session ID and vice versa.
        let udp_resume_key = resume_cache_key(&candidate.uplink.name, "udp");
        let udp_resume_request = global_resume_cache().get(&udp_resume_key);
        let (transport, udp_issued, udp_downgraded_from) = UdpWsTransport::connect_with_resume(
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
        )
        .await
        .with_context(|| TransportOperation::Connect { target: format!("to {}", udp_ws_url) })?;
        global_resume_cache().store_if_issued(udp_resume_key, udp_issued);
        self.report_connection_latency(candidate.index, TransportKind::Udp, started.elapsed())
            .await;
        // Mirror a transport-level downgrade (host clamp via `ws_mode_cache`
        // or inline H3→H2/H1 fallback) into the per-uplink window so
        // `effective_udp_ws_mode` reflects reality on subsequent dials.
        if let Some(requested) = udp_downgraded_from {
            self.note_silent_transport_fallback(
                candidate.index,
                TransportKind::Udp,
                requested,
            );
        }
        Ok(UdpSessionTransport::Ss(transport))
    }

    pub(crate) async fn refill_all_standby(&self) {
        for index in 0..self.inner.uplinks.len() {
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
        if !matches!(ctx.uplink.transport, UplinkTransport::Ws | UplinkTransport::Vless) {
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
