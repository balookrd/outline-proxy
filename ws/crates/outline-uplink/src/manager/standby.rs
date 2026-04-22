use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::Mutex;
use tokio::time::{Instant, sleep, timeout};
use tracing::{debug, warn};
use url::Url;

const WARM_STANDBY_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15);

use crate::utils::maybe_shrink_vecdeque;
use outline_metrics as metrics;
use outline_transport::{
    TransportOperation, UdpWsTransport, WsTransportStream,
    connect_shadowsocks_udp_with_source, connect_websocket_with_source,
};
use crate::config::{UplinkTransport, WsTransportMode};

use super::super::probe::is_expected_standby_probe_failure;
use super::super::error_text::StandbyProbeExpected;
use super::super::types::{
    TrackedDeque, TransportKind, Uplink, UplinkCandidate, UplinkManager,
};

const STANDBY_WS_PEEK_TIMEOUT: Duration = Duration::from_millis(1);
const STANDBY_TCP_KEEPALIVE_SEND_TIMEOUT: Duration = Duration::from_secs(1);

// ── StandbyCtx ───────────────────────────────────────────────────────────────

/// Transport-specific view of a standby pool, resolved once up-front so the
/// generic helpers (`try_take_alive`, `validate`, `refill`, `keepalive`) do
/// not thread `match transport { … }` through every loop.
///
/// TCP and UDP pools are structurally identical (pool deque + refill lock +
/// configured URL + effective mode + metric labels); this struct bundles the
/// per-transport differences so the algorithm can be written once.
///
/// Shadowsocks UDP does not fit this model (no WS pool) and is handled
/// separately in `acquire_udp_standby_or_connect`.
struct StandbyCtx<'a> {
    manager: &'a UplinkManager,
    uplink: &'a Uplink,
    index: usize,
    transport: TransportKind,
    /// The deque that holds pooled `WsTransportStream`s for this transport.
    pool: &'a TrackedDeque,
    /// Serialises concurrent refill attempts for this transport.
    refill_lock: &'a Mutex<()>,
    /// Prometheus label fragment (`"tcp"` / `"udp"`).
    label: &'static str,
    /// Source tag passed to `connect_websocket_with_source` during refill.
    refill_source: &'static str,
    desired: usize,
    url: Option<&'a Url>,
    mode: WsTransportMode,
}

impl UplinkManager {
    /// Builds the per-transport standby context for `(index, transport)`.
    /// Async because the effective mode depends on runtime downgrade state.
    async fn standby_ctx(&self, index: usize, transport: TransportKind) -> StandbyCtx<'_> {
        let uplink = &self.inner.uplinks[index];
        let pool = &self.inner.standby_pools[index];
        let lb = &self.inner.load_balancing;
        match transport {
            TransportKind::Tcp => StandbyCtx {
                manager: self,
                uplink,
                index,
                transport,
                pool: &pool.tcp,
                refill_lock: &pool.tcp_refill,
                label: "tcp",
                refill_source: "standby_tcp",
                desired: lb.warm_standby_tcp,
                url: uplink.tcp_ws_url.as_ref(),
                mode: self.effective_tcp_ws_mode(index).await,
            },
            TransportKind::Udp => StandbyCtx {
                manager: self,
                uplink,
                index,
                transport,
                pool: &pool.udp,
                refill_lock: &pool.udp_refill,
                label: "udp",
                refill_source: "standby_udp",
                desired: lb.warm_standby_udp,
                url: uplink.udp_ws_url.as_ref(),
                mode: self.effective_udp_ws_mode(index).await,
            },
        }
    }
}

impl<'a> StandbyCtx<'a> {
    fn mode_is_http1(&self) -> bool {
        matches!(self.mode, WsTransportMode::Http1)
    }

    fn group(&self) -> &str {
        &self.manager.inner.group_name
    }

    /// Emits `record_warm_standby_acquire` with the transport's label.
    fn record_acquire(&self, outcome: &'static str) {
        metrics::record_warm_standby_acquire(
            self.label,
            self.group(),
            &self.uplink.name,
            outcome,
        );
    }

    /// Pops one pooled WS stream and returns it if it passes the liveness
    /// pre-flight (`is_connection_alive` + 1 ms peek). Stale entries are
    /// discarded with a `"stale"` metric; `None` means the pool was drained
    /// without finding a usable entry. Each successful pop schedules a
    /// background refill so the pool does not bleed below `desired`.
    async fn try_take_alive(&self, candidate_name: &str) -> Option<WsTransportStream> {
        use tokio_tungstenite::tungstenite::protocol::Message;

        loop {
            let mut ws = self.pool.lock().await.pop_front()?;
            self.manager.spawn_refill(self.index, self.transport);

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
            return Some(ws);
        }
    }

    /// Drains the pool, peeks each entry for liveness, and writes survivors
    /// back. Entries that slipped in as Http1 fallbacks under H2/H3 are
    /// evicted unconditionally (they each own a distinct TCP socket, so
    /// keeping them defeats pooling and accumulates FDs).
    async fn validate(&self) {
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
            if matches!(ws, WsTransportStream::Http1 { .. }) && !mode_is_http1 {
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
                    Ok(Some(Err(e))) => Err(anyhow::Error::from(e)
                        .context("standby websocket error")),
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

    /// Dials connections until the pool reaches `desired`. Holds the refill
    /// lock for the whole loop so concurrent refill callers serialise their
    /// dials. Discards Http1 results that appeared as H2/H3 fallbacks to
    /// avoid pooling per-slot TCP sockets under a shared-connection mode.
    async fn refill(&self) {
        if self.desired == 0 {
            return;
        }
        if self.uplink.transport != UplinkTransport::Ws {
            return;
        }
        let Some(url) = self.url else { return };

        let cache = self.manager.inner.dns_cache.as_ref();
        let refill_guard = self.refill_lock.lock().await;

        // Read current length once; track additions with a counter to avoid
        // re-locking on every iteration just to check the pool size.
        let mut current_len = self.pool.lock().await.len();
        let mode_is_http1 = self.mode_is_http1();

        loop {
            if current_len >= self.desired {
                break;
            }

            let ws = connect_websocket_with_source(
                cache,
                url,
                self.mode,
                self.uplink.fwmark,
                self.uplink.ipv6_first,
                self.refill_source,
            )
            .await
            .with_context(|| format!("failed to preconnect to {}", url));

            match ws {
                Ok(ws) => {
                    // H2/H3 connections are shared (one socket per server, N
                    // streams per socket), so pooling them is cheap. When
                    // H2/H3 is configured but the server fell back to Http1,
                    // each "standby" slot owns its own TCP socket — pooling
                    // defeats the purpose and accumulates FDs silently. Bail
                    // out in that case. When Http1 is *explicitly*
                    // configured, pooling a single Http1 connection is the
                    // intended behavior.
                    if matches!(ws, WsTransportStream::Http1 { .. }) && !mode_is_http1 {
                        break;
                    }

                    // Re-check actual pool size before pushing — validate()
                    // or keepalive() may have pushed entries back while we
                    // were dialling, so the pool could already be at
                    // capacity.
                    let mut guard = self.pool.lock().await;
                    if guard.len() >= self.desired {
                        drop(guard);
                        // Connection is dropped here; pool already full.
                        break;
                    }
                    guard.push_back(ws);
                    current_len = guard.len();
                    drop(guard);
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

    /// Drains the pool, sends a WebSocket ping frame on each entry, then
    /// peeks for a response or closure. Callers: TCP keepalive loop. UDP
    /// keepalive rides on the transport's own keepalive interval so this is
    /// not wired up for UDP.
    async fn keepalive(&self) {
        use tokio_tungstenite::tungstenite::protocol::Message;

        if self.desired == 0 {
            return;
        }
        if self.uplink.transport != UplinkTransport::Ws {
            return;
        }

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
            let keepalive_result: Result<()> = if !ws.is_connection_alive() {
                Err(anyhow::Error::from(StandbyProbeExpected)
                    .context("underlying shared connection is closed"))
            } else {
                match timeout(
                    STANDBY_TCP_KEEPALIVE_SEND_TIMEOUT,
                    ws.send(Message::Ping(vec![].into())),
                )
                .await
                {
                    Err(_elapsed) => Err(anyhow::Error::from(StandbyProbeExpected)
                        .context("standby websocket ping timed out")),
                    Ok(Err(error)) => Err(anyhow::Error::from(error)
                        .context("standby websocket ping failed")),
                    Ok(Ok(())) => match timeout(STANDBY_WS_PEEK_TIMEOUT, ws.next()).await {
                        Err(_elapsed) => Ok(()), // still open — nothing to read
                        Ok(None) => Err(anyhow::Error::from(StandbyProbeExpected)
                            .context("standby websocket stream ended")),
                        Ok(Some(Err(error))) => {
                            Err(anyhow::Error::from(error).context("standby websocket error"))
                        },
                        Ok(Some(Ok(Message::Close(frame)))) => {
                            Err(anyhow::Error::from(StandbyProbeExpected)
                                .context(format!(
                                    "standby websocket closed by server: {:?}",
                                    frame
                                )))
                        },
                        Ok(Some(Ok(_))) => Ok(()), // control/data frame — still alive
                    },
                }
            };
            metrics::record_probe(
                self.group(),
                &self.uplink.name,
                self.label,
                "standby_ws_keepalive",
                keepalive_result.is_ok(),
                started.elapsed(),
            );
            match keepalive_result {
                Ok(()) => alive.push_back(ws),
                Err(error) => {
                    if is_expected_standby_probe_failure(&error) {
                        debug!(
                            uplink = %self.uplink.name,
                            transport = ?self.transport,
                            error = %format!("{error:#}"),
                            "dropping stale warm-standby websocket after keepalive ping"
                        );
                    } else {
                        warn!(
                            uplink = %self.uplink.name,
                            transport = ?self.transport,
                            error = %format!("{error:#}"),
                            "dropping stale warm-standby websocket after keepalive ping"
                        );
                    }
                },
            }
        }

        let mut guard = self.pool.lock().await;
        guard.extend(alive);
        maybe_shrink_vecdeque(&mut guard);
    }
}

impl UplinkManager {
    /// Returns the effective TCP WebSocket mode for `index`, falling back to
    /// H2 when H3 has been marked broken by repeated runtime errors.
    pub(crate) async fn effective_tcp_ws_mode(
        &self,
        index: usize,
    ) -> crate::config::WsTransportMode {
        let uplink = &self.inner.uplinks[index];
        if uplink.transport == UplinkTransport::Ws
            && uplink.tcp_ws_mode == crate::config::WsTransportMode::H3
        {
            let status = self.inner.read_status(index);
            if status
                .tcp
                .h3_downgrade_until
                .is_some_and(|t| t > tokio::time::Instant::now())
            {
                return crate::config::WsTransportMode::H2;
            }
        }
        uplink.tcp_ws_mode
    }

    /// Same as `effective_tcp_ws_mode`, but for the UDP-over-WS transport.
    pub(crate) async fn effective_udp_ws_mode(
        &self,
        index: usize,
    ) -> crate::config::WsTransportMode {
        let uplink = &self.inner.uplinks[index];
        if uplink.transport == UplinkTransport::Ws
            && uplink.udp_ws_mode == crate::config::WsTransportMode::H3
        {
            let status = self.inner.read_status(index);
            if status
                .udp
                .h3_downgrade_until
                .is_some_and(|t| t > tokio::time::Instant::now())
            {
                return crate::config::WsTransportMode::H2;
            }
        }
        uplink.udp_ws_mode
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
        if candidate.uplink.transport != UplinkTransport::Ws {
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
        if candidate.uplink.transport != UplinkTransport::Ws {
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
        let started = Instant::now();
        let ws = connect_websocket_with_source(
            cache,
            candidate.uplink.tcp_ws_url.as_ref().ok_or_else(|| {
                anyhow!("uplink {} missing tcp_ws_url", candidate.uplink.name)
            })?,
            mode,
            candidate.uplink.fwmark,
            candidate.uplink.ipv6_first,
            source,
        )
        .await
        .with_context(|| TransportOperation::Connect {
            target: format!(
                "to {}",
                candidate.uplink.tcp_ws_url.as_ref().expect("validated tcp_ws_url")
            ),
        })?;
        // Feed the on-demand dial latency into the RTT EWMA so real
        // connection quality is reflected in routing scores, not just probe
        // ping/pong times.
        self.report_connection_latency(candidate.index, TransportKind::Tcp, started.elapsed())
            .await;
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

    pub async fn acquire_udp_standby_or_connect(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
    ) -> Result<UdpWsTransport> {
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
            );
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
            );
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
        let mode = self.effective_udp_ws_mode(candidate.index).await;
        let started = Instant::now();
        let transport = UdpWsTransport::connect(
            cache,
            udp_ws_url,
            mode,
            candidate.uplink.cipher,
            &candidate.uplink.password,
            candidate.uplink.fwmark,
            candidate.uplink.ipv6_first,
            source,
            self.inner.load_balancing.udp_ws_keepalive_interval,
        )
        .await
        .with_context(|| TransportOperation::Connect { target: format!("to {}", udp_ws_url) })?;
        self.report_connection_latency(candidate.index, TransportKind::Udp, started.elapsed())
            .await;
        Ok(transport)
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
        if ctx.uplink.transport != UplinkTransport::Ws {
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
