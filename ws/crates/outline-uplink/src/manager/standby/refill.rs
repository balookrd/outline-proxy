use anyhow::{Context, Result};
use futures_util::StreamExt;
use tokio::time::{Instant, timeout};
use tracing::{debug, warn};

use outline_metrics as metrics;
use outline_transport::{WsTransportStream, connect_websocket_with_source};

use crate::config::UplinkTransport;
use crate::error_text::StandbyProbeExpected;
use crate::probe::is_expected_standby_probe_failure;
use crate::utils::maybe_shrink_vecdeque;

use super::ctx::{STANDBY_WS_PEEK_TIMEOUT, StandbyCtx};

impl<'a> StandbyCtx<'a> {
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
    pub(super) async fn refill(&self) {
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
}
