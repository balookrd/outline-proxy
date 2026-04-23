use std::time::Duration;

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use tokio::time::{Instant, timeout};
use tracing::{debug, warn};

use outline_metrics as metrics;

use crate::config::UplinkTransport;
use crate::error_text::StandbyProbeExpected;
use crate::probe::is_expected_standby_probe_failure;
use crate::utils::maybe_shrink_vecdeque;

use super::ctx::{STANDBY_WS_PEEK_TIMEOUT, StandbyCtx};

const STANDBY_TCP_KEEPALIVE_SEND_TIMEOUT: Duration = Duration::from_secs(1);

impl<'a> StandbyCtx<'a> {
    /// Drains the pool, sends a WebSocket ping frame on each entry, then
    /// peeks for a response or closure. Callers: TCP keepalive loop. UDP
    /// keepalive rides on the transport's own keepalive interval so this is
    /// not wired up for UDP.
    pub(super) async fn keepalive(&self) {
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
