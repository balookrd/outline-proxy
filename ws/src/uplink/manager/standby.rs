use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::time::{Instant, timeout};
use tracing::{debug, warn};

use crate::memory::maybe_shrink_vecdeque;
use crate::metrics;
use crate::transport::{
    AnyWsStream, UdpWsTransport, connect_shadowsocks_udp_with_source, connect_websocket_with_source,
};
use crate::types::UplinkTransport;

use super::super::probe::is_expected_standby_probe_failure;
use super::super::types::{TransportKind, UplinkCandidate, UplinkManager};

impl UplinkManager {
    /// Returns the effective TCP WebSocket mode for `index`, falling back to
    /// H2 when H3 has been marked broken by repeated runtime errors.
    pub(super) async fn effective_tcp_ws_mode(
        &self,
        index: usize,
    ) -> crate::types::WsTransportMode {
        let uplink = &self.inner.uplinks[index];
        if uplink.transport == UplinkTransport::Websocket
            && uplink.tcp_ws_mode == crate::types::WsTransportMode::H3
        {
            let statuses = self.inner.statuses.read().await;
            let status = &statuses[index];
            if status.h3_tcp_downgrade_until.is_some_and(|t| t > tokio::time::Instant::now()) {
                return crate::types::WsTransportMode::H2;
            }
        }
        uplink.tcp_ws_mode
    }

    /// Pops one connection from the TCP standby pool without falling back to a
    /// fresh dial.  Returns `None` if the pool is empty.  Callers can use this
    /// to implement a silent retry: attempt the pool entry first; if it turns
    /// out to be stale, fall back to `connect_tcp_ws_fresh` without recording
    /// a runtime failure.
    pub async fn try_take_tcp_standby(&self, candidate: &UplinkCandidate) -> Option<AnyWsStream> {
        if candidate.uplink.transport != UplinkTransport::Websocket {
            return None;
        }
        let ws = self.inner.standby_pools[candidate.index].tcp.lock().await.pop_front()?;
        self.spawn_refill(candidate.index, TransportKind::Tcp);
        metrics::record_warm_standby_acquire("tcp", &candidate.uplink.name, "hit");
        debug!(uplink = %candidate.uplink.name, "using warm-standby TCP websocket");
        Some(ws)
    }

    /// Dials a fresh TCP WebSocket connection, bypassing the standby pool.
    pub async fn connect_tcp_ws_fresh(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
    ) -> Result<AnyWsStream> {
        if candidate.uplink.transport != UplinkTransport::Websocket {
            bail!("uplink {} does not use websocket transport", candidate.uplink.name);
        }
        metrics::record_warm_standby_acquire("tcp", &candidate.uplink.name, "miss");
        let mode = self.effective_tcp_ws_mode(candidate.index).await;
        debug!(
            uplink = %candidate.uplink.name,
            mode = %mode,
            "no warm-standby TCP websocket available, dialing on-demand"
        );
        let started = Instant::now();
        let ws =
            connect_websocket_with_source(
                candidate.uplink.tcp_ws_url.as_ref().ok_or_else(|| {
                    anyhow!("uplink {} missing tcp_ws_url", candidate.uplink.name)
                })?,
                mode,
                candidate.uplink.fwmark,
                candidate.uplink.ipv6_first,
                source,
            )
            .await
            .with_context(|| {
                format!(
                    "failed to connect to {}",
                    candidate.uplink.tcp_ws_url.as_ref().expect("validated tcp_ws_url")
                )
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
    ) -> Result<AnyWsStream> {
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
        if candidate.uplink.transport == UplinkTransport::Shadowsocks {
            metrics::record_warm_standby_acquire("udp", &candidate.uplink.name, "miss");
            let udp_addr = candidate.uplink.udp_addr.as_ref().ok_or_else(|| {
                anyhow!("udp_addr is not configured for uplink {}", candidate.uplink.name)
            })?;
            let started = Instant::now();
            let socket = connect_shadowsocks_udp_with_source(
                udp_addr,
                candidate.uplink.fwmark,
                candidate.uplink.ipv6_first,
                source,
            )
            .await
            .with_context(|| format!("failed to connect to {}", udp_addr))?;
            self.report_connection_latency(candidate.index, TransportKind::Udp, started.elapsed())
                .await;
            return Ok(UdpWsTransport::from_socket(
                socket,
                candidate.uplink.cipher,
                &candidate.uplink.password,
                source,
            )?);
        }

        let pool = &self.inner.standby_pools[candidate.index];
        if let Some(ws) = pool.udp.lock().await.pop_front() {
            self.spawn_refill(candidate.index, TransportKind::Udp);
            metrics::record_warm_standby_acquire("udp", &candidate.uplink.name, "hit");
            debug!(uplink = %candidate.uplink.name, "using warm-standby UDP websocket");
            return Ok(UdpWsTransport::from_websocket(
                ws,
                candidate.uplink.cipher,
                &candidate.uplink.password,
                source,
                self.inner.load_balancing.udp_ws_keepalive_interval,
            )?);
        }

        metrics::record_warm_standby_acquire("udp", &candidate.uplink.name, "miss");
        debug!(uplink = %candidate.uplink.name, "no warm-standby UDP websocket available, dialing on-demand");
        let udp_ws_url = candidate.uplink.udp_ws_url.as_ref().ok_or_else(|| {
            anyhow!("udp_ws_url is not configured for uplink {}", candidate.uplink.name)
        })?;
        let started = Instant::now();
        let transport = UdpWsTransport::connect(
            udp_ws_url,
            candidate.uplink.udp_ws_mode,
            candidate.uplink.cipher,
            &candidate.uplink.password,
            candidate.uplink.fwmark,
            candidate.uplink.ipv6_first,
            source,
            self.inner.load_balancing.udp_ws_keepalive_interval,
        )
        .await
        .with_context(|| format!("failed to connect to {}", udp_ws_url))?;
        self.report_connection_latency(candidate.index, TransportKind::Udp, started.elapsed())
            .await;
        Ok(transport)
    }

    pub(super) async fn refill_all_standby(&self) {
        for index in 0..self.inner.uplinks.len() {
            self.maintain_pool(index, TransportKind::Tcp).await;
            self.maintain_pool(index, TransportKind::Udp).await;
        }
    }

    pub(super) fn spawn_refill(&self, index: usize, transport: TransportKind) {
        let manager = self.clone();
        tokio::spawn(async move {
            manager.refill_pool(index, transport).await;
        });
    }

    pub(super) async fn maintain_pool(&self, index: usize, transport: TransportKind) {
        self.validate_pool(index, transport).await;
        self.refill_pool(index, transport).await;
    }

    async fn refill_pool(&self, index: usize, transport: TransportKind) {
        let desired = match transport {
            TransportKind::Tcp => self.inner.load_balancing.warm_standby_tcp,
            TransportKind::Udp => self.inner.load_balancing.warm_standby_udp,
        };
        if desired == 0 {
            return;
        }

        let uplink = std::sync::Arc::clone(&self.inner.uplinks[index]);
        if uplink.transport != UplinkTransport::Websocket {
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

            let ws = match transport {
                TransportKind::Tcp => {
                    let mode = self.effective_tcp_ws_mode(index).await;
                    let Some(tcp_ws_url) = uplink.tcp_ws_url.as_ref() else {
                        break;
                    };
                    connect_websocket_with_source(
                        tcp_ws_url,
                        mode,
                        uplink.fwmark,
                        uplink.ipv6_first,
                        "standby_tcp",
                    )
                    .await
                    .with_context(|| format!("failed to preconnect to {}", tcp_ws_url))
                }
                TransportKind::Udp => {
                    if uplink.transport != UplinkTransport::Websocket {
                        break;
                    }
                    let Some(url) = uplink.udp_ws_url.as_ref() else {
                        break;
                    };
                    connect_websocket_with_source(
                        url,
                        uplink.udp_ws_mode,
                        uplink.fwmark,
                        uplink.ipv6_first,
                        "standby_udp",
                    )
                    .await
                    .with_context(|| format!("failed to preconnect to {}", url))
                }
            };

            match ws {
                Ok(ws) => {
                    pool_vec.lock().await.push_back(ws);
                    current_len += 1;
                    metrics::record_warm_standby_refill(transport_label, &uplink.name, true);
                    debug!(
                        uplink = %uplink.name,
                        transport = ?transport,
                        desired,
                        "warm-standby websocket replenished"
                    );
                }
                Err(error) => {
                    metrics::record_warm_standby_refill(transport_label, &uplink.name, false);
                    warn!(
                        uplink = %uplink.name,
                        transport = ?transport,
                        error = %format!("{error:#}"),
                        "failed to replenish warm-standby websocket"
                    );
                    break;
                }
            }
        }

        drop(refill_guard);
    }

    async fn validate_pool(&self, index: usize, transport: TransportKind) {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::protocol::Message;

        let desired = match transport {
            TransportKind::Tcp => self.inner.load_balancing.warm_standby_tcp,
            TransportKind::Udp => self.inner.load_balancing.warm_standby_udp,
        };
        if desired == 0 {
            return;
        }

        let uplink = std::sync::Arc::clone(&self.inner.uplinks[index]);
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
            // Check liveness with a non-blocking read (1 ms timeout).
            // Many servers do not respond to WebSocket ping frames, so we use
            // a quick peek instead: if the server has closed the connection we
            // will see a Close frame or an error immediately; otherwise the
            // read times out and we treat the connection as still alive.
            let alive_result: Result<()> = match timeout(Duration::from_millis(1), ws.next()).await
            {
                Err(_elapsed) => Ok(()), // still open — nothing to read
                Ok(None) => Err(anyhow!("standby websocket stream ended")),
                Ok(Some(Err(e))) => Err(anyhow!("standby websocket error: {e}")),
                Ok(Some(Ok(Message::Close(frame)))) => {
                    Err(anyhow!("standby websocket closed by server: {:?}", frame))
                }
                Ok(Some(Ok(_))) => Ok(()), // unexpected data frame — still alive
            };
            metrics::record_probe(
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
                }
            }
        }

        let mut guard = match transport {
            TransportKind::Tcp => pool.tcp.lock().await,
            TransportKind::Udp => pool.udp.lock().await,
        };
        guard.extend(alive);
        maybe_shrink_vecdeque(&mut guard);
    }

    pub(super) async fn clear_standby(&self, index: usize, transport: TransportKind) {
        let pool = &self.inner.standby_pools[index];
        match transport {
            TransportKind::Tcp => {
                let mut guard = pool.tcp.lock().await;
                guard.clear();
                maybe_shrink_vecdeque(&mut guard);
            }
            TransportKind::Udp => {
                let mut guard = pool.udp.lock().await;
                guard.clear();
                maybe_shrink_vecdeque(&mut guard);
            }
        }
    }
}
