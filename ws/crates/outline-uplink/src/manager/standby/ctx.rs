use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::debug;
use url::Url;

use outline_metrics as metrics;
use outline_transport::TransportStream;

use crate::config::TransportMode;
use crate::types::{TrackedDeque, TransportKind, Uplink, UplinkManager};

pub(super) const STANDBY_WS_PEEK_TIMEOUT: Duration = Duration::from_millis(1);

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
pub(super) struct StandbyCtx<'a> {
    pub(super) manager: &'a UplinkManager,
    pub(super) uplink: &'a Uplink,
    pub(super) index: usize,
    pub(super) transport: TransportKind,
    /// The deque that holds pooled `TransportStream`s for this transport.
    pub(super) pool: &'a TrackedDeque,
    /// Serialises concurrent refill attempts for this transport.
    pub(super) refill_lock: &'a Mutex<()>,
    /// Prometheus label fragment (`"tcp"` / `"udp"`).
    pub(super) label: &'static str,
    /// Source tag passed to `connect_websocket_with_source` during refill.
    pub(super) refill_source: &'static str,
    pub(super) desired: usize,
    pub(super) url: Option<&'a Url>,
    pub(super) mode: TransportMode,
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
                url: uplink.tcp_dial_url(),
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
                url: uplink.udp_dial_url(),
                mode: self.effective_udp_ws_mode(index).await,
            },
        }
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
    pub(super) async fn try_take_alive(
        &self,
        candidate_name: &str,
    ) -> Option<TransportStream> {
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
}
