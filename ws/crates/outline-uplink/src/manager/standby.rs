use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use tokio::time::{Instant, sleep, timeout};
use tracing::{debug, warn};

const WARM_STANDBY_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15);

use crate::utils::maybe_shrink_vecdeque;
use outline_metrics as metrics;
use outline_transport::{
    TransportOperation, WsTransportStream, UdpWsTransport,
    connect_shadowsocks_udp_with_source, connect_websocket_with_source,
};
use crate::config::{UplinkTransport, WsTransportMode};

use super::super::probe::is_expected_standby_probe_failure;
use super::super::error_text::StandbyProbeExpected;
use super::super::types::{TransportKind, UplinkCandidate, UplinkManager};

const STANDBY_WS_PEEK_TIMEOUT: Duration = Duration::from_millis(1);
const STANDBY_TCP_KEEPALIVE_SEND_TIMEOUT: Duration = Duration::from_secs(1);

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

    /// Pops one connection from the TCP standby pool without falling back to a
    /// fresh dial.  Returns `None` if the pool is empty, or if the popped
    /// entry fails a quick liveness peek (pre-flight check to avoid handing a
    /// stale socket to a fresh SOCKS session).
    ///
    /// The background validation loop runs every 15 s; that is not tight
    /// enough when the upstream closes idle WebSocket connections within a
    /// 10–20 s window.  Re-peeking at acquisition time costs at most
    /// `STANDBY_WS_PEEK_TIMEOUT` (1 ms) per take and closes the race where
    /// a session is handed a socket that server already FIN'd between
    /// validation cycles.  If the peek reports closure, the entry is
    /// dropped and we return `None`; the caller transparently falls back
    /// to `connect_tcp_ws_fresh`, and the pool refill task fills the slot.
    pub async fn try_take_tcp_standby(&self, candidate: &UplinkCandidate) -> Option<WsTransportStream> {
        use tokio_tungstenite::tungstenite::protocol::Message;

        if candidate.uplink.transport != UplinkTransport::Ws {
            return None;
        }
        loop {
            let mut ws = self.inner.standby_pools[candidate.index]
                .tcp
                .lock()
                .await
                .pop_front()?;
            self.spawn_refill(candidate.index, TransportKind::Tcp);

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
                    uplink = %candidate.uplink.name,
                    "discarded stale warm-standby TCP websocket at acquisition time"
                );
                metrics::record_warm_standby_acquire(
                    "tcp",
                    &self.inner.group_name,
                    &candidate.uplink.name,
                    "stale",
                );
                // drop `ws`, loop to try the next pool entry
                continue;
            }
            metrics::record_warm_standby_acquire(
                "tcp",
                &self.inner.group_name,
                &candidate.uplink.name,
                "hit",
            );
            debug!(uplink = %candidate.uplink.name, "using warm-standby TCP websocket");
            return Some(ws);
        }
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
        let ws =
            connect_websocket_with_source(cache, 
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
        // Feed the on-demand dial latency into the RTT EWMA so real connection
        // quality is reflected in routing scores, not just probe ping/pong times.
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
            let socket = connect_shadowsocks_udp_with_source(cache, 
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

        let pool = &self.inner.standby_pools[candidate.index];
        // Loop past entries whose underlying shared connection has been
        // torn down since the entry was pooled — otherwise we'd hand a
        // zombie transport to the caller and probe-timeout-marked H2/H3
        // connections would resurface here. Mirrors `try_take_tcp_standby`.
        loop {
            let Some(ws) = pool.udp.lock().await.pop_front() else { break };
            self.spawn_refill(candidate.index, TransportKind::Udp);
            if !ws.is_connection_alive() {
                metrics::record_warm_standby_acquire(
                    "udp",
                    &self.inner.group_name,
                    &candidate.uplink.name,
                    "stale",
                );
                debug!(
                    uplink = %candidate.uplink.name,
                    "discarded stale warm-standby UDP websocket at acquisition time"
                );
                drop(ws);
                continue;
            }
            metrics::record_warm_standby_acquire(
                "udp",
                &self.inner.group_name,
                &candidate.uplink.name,
                "hit",
            );
            debug!(uplink = %candidate.uplink.name, "using warm-standby UDP websocket");
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
        debug!(uplink = %candidate.uplink.name, "no warm-standby UDP websocket available, dialing on-demand");
        let udp_ws_url = candidate.uplink.udp_ws_url.as_ref().ok_or_else(|| {
            anyhow!("udp_ws_url is not configured for uplink {}", candidate.uplink.name)
        })?;
        let mode = self.effective_udp_ws_mode(candidate.index).await;
        let started = Instant::now();
        let transport = UdpWsTransport::connect(cache, 
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
        self.validate_pool(index, transport).await;
        self.refill_pool(index, transport).await;
    }

    /// Sends WebSocket ping frames on idle TCP standby sockets so middleboxes
    /// keep the connection state warm, then replenishes any entries that were
    /// dropped as stale.
    pub(crate) async fn keepalive_tcp_pool(&self, index: usize) {
        use tokio_tungstenite::tungstenite::protocol::Message;

        if self.inner.load_balancing.warm_standby_tcp == 0 {
            return;
        }

        let uplink = self.inner.uplinks[index].clone();
        if uplink.transport != UplinkTransport::Ws {
            return;
        }

        let pool = &self.inner.standby_pools[index];
        let mut drained = std::collections::VecDeque::new();
        {
            let mut guard = pool.tcp.lock().await;
            drained.extend(guard.drain(..));
        }

        if drained.is_empty() {
            self.refill_pool(index, TransportKind::Tcp).await;
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
                    Ok(Ok(())) => {
                        match timeout(STANDBY_WS_PEEK_TIMEOUT, ws.next()).await {
                            Err(_elapsed) => Ok(()), // still open — nothing to read
                            Ok(None) => Err(anyhow::Error::from(StandbyProbeExpected)
                                .context("standby websocket stream ended")),
                            Ok(Some(Err(error))) => {
                                Err(anyhow::Error::from(error).context("standby websocket error"))
                            },
                            Ok(Some(Ok(Message::Close(frame)))) => {
                                Err(anyhow::Error::from(StandbyProbeExpected)
                                    .context(format!("standby websocket closed by server: {:?}", frame)))
                            },
                            Ok(Some(Ok(_))) => Ok(()), // control/data frame — still alive
                        }
                    },
                }
            };
            metrics::record_probe(
                &self.inner.group_name,
                &uplink.name,
                "tcp",
                "standby_ws_keepalive",
                keepalive_result.is_ok(),
                started.elapsed(),
            );
            match keepalive_result {
                Ok(()) => alive.push_back(ws),
                Err(error) => {
                    if is_expected_standby_probe_failure(&error) {
                        debug!(
                            uplink = %uplink.name,
                            transport = ?TransportKind::Tcp,
                            error = %format!("{error:#}"),
                            "dropping stale warm-standby websocket after keepalive ping"
                        );
                    } else {
                        warn!(
                            uplink = %uplink.name,
                            transport = ?TransportKind::Tcp,
                            error = %format!("{error:#}"),
                            "dropping stale warm-standby websocket after keepalive ping"
                        );
                    }
                },
            }
        }

        let mut guard = pool.tcp.lock().await;
        guard.extend(alive);
        maybe_shrink_vecdeque(&mut guard);
        drop(guard);

        self.refill_pool(index, TransportKind::Tcp).await;
    }

    async fn refill_pool(&self, index: usize, transport: TransportKind) {
        let cache = self.inner.dns_cache.as_ref();
        let desired = match transport {
            TransportKind::Tcp => self.inner.load_balancing.warm_standby_tcp,
            TransportKind::Udp => self.inner.load_balancing.warm_standby_udp,
        };
        if desired == 0 {
            return;
        }

        let uplink = self.inner.uplinks[index].clone();
        if uplink.transport != UplinkTransport::Ws {
            return;
        }
        let pool = &self.inner.standby_pools[index];
        let refill_guard = match transport {
            TransportKind::Tcp => pool.tcp_refill.lock().await,
            TransportKind::Udp => pool.udp_refill.lock().await,
        };

        let transport_label = match transport {
            TransportKind::Tcp => "tcp",
            TransportKind::Udp => "udp",
        };
        let pool_vec = match transport {
            TransportKind::Tcp => &pool.tcp,
            TransportKind::Udp => &pool.udp,
        };

        // Read current length once; track additions with a counter to avoid
        // re-locking on every iteration just to check the pool size.
        let mut current_len = pool_vec.lock().await.len();

        loop {
            if current_len >= desired {
                break;
            }

            // Carry the configured mode alongside the dial result so the Http1
        // fallback guard below can distinguish "explicitly Http1" (pool it)
        // from "H2/H3 fell back to Http1" (discard, avoid FD accumulation).
        let (ws, mode_is_http1) = match transport {
                TransportKind::Tcp => {
                    let mode = self.effective_tcp_ws_mode(index).await;
                    let is_http1 = matches!(mode, WsTransportMode::Http1);
                    let Some(tcp_ws_url) = uplink.tcp_ws_url.as_ref() else {
                        break;
                    };
                    let result = connect_websocket_with_source(cache, 
                        tcp_ws_url,
                        mode,
                        uplink.fwmark,
                        uplink.ipv6_first,
                        "standby_tcp",
                    )
                    .await
                    .with_context(|| format!("failed to preconnect to {}", tcp_ws_url));
                    (result, is_http1)
                },
                TransportKind::Udp => {
                    if uplink.transport != UplinkTransport::Ws {
                        break;
                    }
                    let Some(url) = uplink.udp_ws_url.as_ref() else {
                        break;
                    };
                    let mode = self.effective_udp_ws_mode(index).await;
                    let is_http1 = matches!(mode, WsTransportMode::Http1);
                    let result = connect_websocket_with_source(cache, 
                        url,
                        mode,
                        uplink.fwmark,
                        uplink.ipv6_first,
                        "standby_udp",
                    )
                    .await
                    .with_context(|| format!("failed to preconnect to {}", url));
                    (result, is_http1)
                },
            };

            match ws {
                Ok(ws) => {
                    // H2/H3 connections are shared (one socket per server, N
                    // streams per socket), so pooling them is cheap.  When
                    // H2/H3 is configured but the server fell back to Http1,
                    // each "standby" slot owns its own TCP socket — pooling
                    // defeats the purpose and accumulates FDs silently.  Bail
                    // out in that case.  When Http1 is *explicitly* configured,
                    // pooling a single Http1 connection is the intended behavior.
                    if matches!(ws, outline_transport::WsTransportStream::Http1 { .. }) && !mode_is_http1 {
                        break;
                    }

                    // Re-check actual pool size before pushing — validate_pool
                    // or keepalive_tcp_pool may have pushed entries back while
                    // we were dialling, so the pool could already be at capacity.
                    let mut guard = pool_vec.lock().await;
                    if guard.len() >= desired {
                        drop(guard);
                        // Connection is dropped here; pool already full.
                        break;
                    }
                    guard.push_back(ws);
                    current_len = guard.len();
                    drop(guard);
                    metrics::record_warm_standby_refill(
                        transport_label,
                        &self.inner.group_name,
                        &uplink.name,
                        true,
                    );
                    debug!(
                        uplink = %uplink.name,
                        transport = ?transport,
                        desired,
                        "warm-standby websocket replenished"
                    );
                },
                Err(error) => {
                    metrics::record_warm_standby_refill(
                        transport_label,
                        &self.inner.group_name,
                        &uplink.name,
                        false,
                    );
                    warn!(
                        uplink = %uplink.name,
                        transport = ?transport,
                        error = %format!("{error:#}"),
                        "failed to replenish warm-standby websocket"
                    );
                    break;
                },
            }
        }

        drop(refill_guard);
    }

    async fn validate_pool(&self, index: usize, transport: TransportKind) {
        use tokio_tungstenite::tungstenite::protocol::Message;

        let desired = match transport {
            TransportKind::Tcp => self.inner.load_balancing.warm_standby_tcp,
            TransportKind::Udp => self.inner.load_balancing.warm_standby_udp,
        };
        if desired == 0 {
            return;
        }

        let uplink = self.inner.uplinks[index].clone();
        // Determine if this transport is explicitly configured as Http1.
        // Http1 connections that slipped in as H2/H3 fallbacks must be evicted;
        // those present because Http1 is the configured mode should be
        // validated normally via the timeout-peek below.
        let mode_is_http1 = match transport {
            TransportKind::Tcp => matches!(
                self.effective_tcp_ws_mode(index).await,
                WsTransportMode::Http1
            ),
            TransportKind::Udp => matches!(
                self.effective_udp_ws_mode(index).await,
                WsTransportMode::Http1
            ),
        };
        let pool = &self.inner.standby_pools[index];
        let mut drained = std::collections::VecDeque::new();
        {
            let mut guard = match transport {
                TransportKind::Tcp => pool.tcp.lock().await,
                TransportKind::Udp => pool.udp.lock().await,
            };
            drained.extend(guard.drain(..));
        }

        if drained.is_empty() {
            return;
        }

        let mut alive = std::collections::VecDeque::with_capacity(drained.len());
        while let Some(mut ws) = drained.pop_front() {
            let started = Instant::now();
            // Evict Http1 connections that are present as H2/H3 fallbacks.
            // These each own their own TCP socket, so keeping them in the pool
            // accumulates FDs without sharing the underlying connection.
            // When Http1 is the explicitly configured mode, skip eviction and
            // let the standard timeout-peek decide liveness instead.
            if matches!(ws, outline_transport::WsTransportStream::Http1 { .. }) && !mode_is_http1 {
                debug!(
                    uplink = %uplink.name,
                    transport = ?transport,
                    "evicting Http1 fallback connection from warm-standby pool"
                );
                drop(ws);
                continue;
            }
            // Check liveness with a non-blocking read (1 ms timeout).
            // Many servers do not respond to WebSocket ping frames, so we use
            // a quick peek instead: if the server has closed the connection we
            // will see a Close frame or an error immediately; otherwise the
            // read times out and we treat the connection as still alive.
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
                &self.inner.group_name,
                &uplink.name,
                match transport {
                    TransportKind::Tcp => "tcp",
                    TransportKind::Udp => "udp",
                },
                "standby_ws",
                alive_result.is_ok(),
                started.elapsed(),
            );
            match alive_result {
                Ok(()) => alive.push_back(ws),
                Err(error) => {
                    if is_expected_standby_probe_failure(&error) {
                        debug!(
                            uplink = %uplink.name,
                            transport = ?transport,
                            error = %format!("{error:#}"),
                            "dropping stale warm-standby websocket"
                        );
                    } else {
                        warn!(
                            uplink = %uplink.name,
                            transport = ?transport,
                            error = %format!("{error:#}"),
                            "dropping stale warm-standby websocket"
                        );
                    }
                },
            }
        }

        let mut guard = match transport {
            TransportKind::Tcp => pool.tcp.lock().await,
            TransportKind::Udp => pool.udp.lock().await,
        };
        guard.extend(alive);
        maybe_shrink_vecdeque(&mut guard);
    }

    pub(crate) async fn clear_standby(&self, index: usize, transport: TransportKind) {
        let pool = &self.inner.standby_pools[index];
        match transport {
            TransportKind::Tcp => {
                let mut guard = pool.tcp.lock().await;
                guard.clear();
                maybe_shrink_vecdeque(&mut guard);
            },
            TransportKind::Udp => {
                let mut guard = pool.udp.lock().await;
                guard.clear();
                maybe_shrink_vecdeque(&mut guard);
            },
        }
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

    /// Spawns a background loop that pings warm-standby **TCP** pool connections
    /// at `tcp_ws_standby_keepalive_interval` to keep them alive through NAT/
    /// firewall idle-timeout windows.  This is separate from the 15-second
    /// validation loop: the validation loop also runs for UDP and handles
    /// refill; this loop is TCP-only and intentionally runs more frequently.
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
