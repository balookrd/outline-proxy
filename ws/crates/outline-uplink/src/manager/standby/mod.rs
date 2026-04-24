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
    connect_shadowsocks_udp_with_source, connect_websocket_with_source,
};

use crate::config::UplinkTransport;
use crate::utils::maybe_shrink_vecdeque;

use crate::types::{TransportKind, UplinkCandidate, UplinkManager};

const WARM_STANDBY_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15);

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
            // own WS session inside the mux on first packet, so there is no
            // single pre-dialed stream to hand out up front.
            metrics::record_warm_standby_acquire(
                "udp",
                &self.inner.group_name,
                &candidate.uplink.name,
                "miss",
            );
            let udp_ws_url = candidate.uplink.udp_ws_url.as_ref().ok_or_else(|| {
                anyhow!("udp_ws_url is not configured for uplink {}", candidate.uplink.name)
            })?;
            let uuid = candidate.uplink.vless_uuid.ok_or_else(|| {
                anyhow!("uplink {} is VLESS but has no uuid", candidate.uplink.name)
            })?;
            let mode = self.effective_udp_ws_mode(candidate.index).await;
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
            );
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
