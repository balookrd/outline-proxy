use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tracing::{debug, info, warn};

use shadowsocks_crypto::SHADOWSOCKS_MAX_PAYLOAD;
use outline_metrics as metrics;
use outline_transport::TcpWriter;
use socks5_proto::{
    SOCKS_STATUS_NOT_ALLOWED, SOCKS_STATUS_SUCCESS, TargetAddr, send_reply, socket_addr_to_target,
};

use super::super::Route;
use outline_uplink::{TransportKind, UplinkManager};
use super::failover::{
    ActiveTcpUplink, MAX_CHUNK0_FAILOVER_BUF,
    connect_tcp_uplink, connect_tcp_uplink_fresh,
};
use super::session::{
    IdleGuard, UplinkOutcome, drive_tcp_session_tasks,
};
use super::direct::handle_tcp_direct;
use crate::client_io::ClientIo;
use crate::proxy::TcpTimeouts;

/// Maximum number of transparent retries on the *same* uplink when chunk 0
/// dies with a transport-level reset (WebSocket RST / clean Close before any
/// response bytes). Transit flaps routinely RST fresh WS handshakes on
/// several uplinks within a few hundred milliseconds; silently redialing
/// once or twice avoids surfacing a brief network event to the client as a
/// user-visible disconnect, and is cheaper than a full cross-uplink failover.
const CHUNK0_RST_MAX_RETRIES: u8 = 2;

/// Delay between transparent chunk-0 retries. Short enough that the worst
/// case (two retries) stays well under a second, long enough to let a
/// transit/DPI flap clear before dialing again.
const CHUNK0_RST_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(300);

// ---------------------------------------------------------------------------
// Replay buffer state
// ---------------------------------------------------------------------------

/// Accumulates client→upstream bytes during the phase-1 failover window so
/// they can be replayed verbatim to a replacement uplink if the first one
/// fails before returning any response data.
///
/// Once the total buffered size exceeds [`MAX_CHUNK0_FAILOVER_BUF`],
/// `overflow` is set and cross-uplink failover is disabled — the upstream is
/// given the full `upstream_response` window instead of the aggressive
/// chunk-0 timeout, and no replay attempt is made on any subsequent uplink.
struct ReplayBufState {
    /// All chunk bytes stored contiguously; avoids one heap allocation per chunk.
    buf: BytesMut,
    /// End offset of each logical chunk within `buf`.
    splits: Vec<usize>,
    total: usize,
    overflow: bool,
}

impl ReplayBufState {
    fn new() -> Self {
        Self {
            buf: BytesMut::new(),
            splits: Vec::with_capacity(8),
            total: 0,
            overflow: false,
        }
    }

    /// Attempts to buffer `chunk`.
    ///
    /// Returns `true` if this call caused `overflow` to be set for the
    /// **first time** — the caller should promote `attempt_timeout` to the
    /// full `upstream_response` window immediately.  Returns `false` either
    /// when the chunk was buffered successfully or when overflow was already
    /// set on a prior call (no-op).
    fn push(&mut self, chunk: &[u8]) -> bool {
        if self.overflow {
            return false;
        }
        if self.total + chunk.len() <= MAX_CHUNK0_FAILOVER_BUF {
            self.buf.extend_from_slice(chunk);
            self.total += chunk.len();
            self.splits.push(self.total);
            false
        } else {
            self.overflow = true;
            true // overflow just triggered
        }
    }

    /// Sends every buffered chunk to `writer` in order.  Wraps errors with
    /// the supplied `context` string before propagating.
    async fn replay_to(&self, writer: &mut TcpWriter, context: &'static str) -> Result<()> {
        let bytes = &self.buf[..];
        let mut start = 0;
        for &end in &self.splits {
            writer.send_chunk(&bytes[start..end]).await.context(context)?;
            start = end;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Phase 1 — uplink selection + chunk-0 failover
// ---------------------------------------------------------------------------

/// Waits for the first upstream response chunk while forwarding client data,
/// transparently failing over to alternative uplinks (and replaying buffered
/// client bytes) when an uplink resets or stalls before responding.
///
/// Returns `Ok(Some(chunk))` once the first upstream byte arrives.  Returns
/// `Ok(None)` when the upstream closed cleanly before sending any data; in
/// that case `client_write` has already been shut down and the caller should
/// return `Ok(())` immediately.
async fn try_uplinks(
    uplinks: &UplinkManager,
    active: &mut ActiveTcpUplink,
    target: &TargetAddr,
    strict_transport: bool,
    tried_indexes: &mut HashSet<usize>,
    chunk0_attempt_timeout: std::time::Duration,
    timeouts: &TcpTimeouts,
    client_read: &mut OwnedReadHalf,
    client_write: &mut OwnedWriteHalf,
    replay: &mut ReplayBufState,
) -> Result<Option<Vec<u8>>> {
    let mut client_half_closed = false;
    let mut deferred_phase1_failures: Vec<(usize, String, String)> = Vec::new();
    // Counts transparent same-uplink retries after a chunk-0 WS reset.
    // Reset to 0 whenever we switch to a different uplink.
    let mut rst_retries_on_current_uplink: u8 = 0;
    // Single scratch buffer reused across every phase-1 failover attempt.
    // Allocated once here so a chunk-0 failover does not re-allocate 64 KiB
    // per retry.
    let mut rbuf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];

    loop {
        let can_failover = strict_transport
            && !replay.overflow
            && tried_indexes.len() < uplinks.uplinks().len();
        // `attempt_timeout` is mutable because `replay.overflow` can flip to
        // true mid-iteration (when the client body exceeds
        // MAX_CHUNK0_FAILOVER_BUF).  Once replay is no longer possible,
        // cross-uplink failover is pointless, so we must switch to the
        // configured `upstream_response` window instead of continuing to
        // enforce the aggressive chunk-0 timeout.  Without this promotion,
        // a large request body (e.g. Codex `compact`) would always hit the
        // 10 s deadline as soon as the client finished sending — fail over to
        // the next uplink with a truncated replay — time out again — and
        // eventually surface a client-side "error sending request" even
        // though the upstream was simply taking longer than 10 s to produce
        // its first byte.
        let mut attempt_timeout = if can_failover {
            chunk0_attempt_timeout
        } else {
            timeouts.upstream_response
        };
        let mut deadline = tokio::time::Instant::now() + attempt_timeout;

        let attempt: Result<Vec<u8>> = loop {
            if client_half_closed {
                break tokio::time::timeout_at(deadline, active.reader.read_chunk())
                    .await
                    .map_err(|_| {
                        anyhow!(
                            "upstream did not respond within {}s (chunk 0)",
                            attempt_timeout.as_secs(),
                        )
                    })?;
            }

            tokio::select! {
                result = active.reader.read_chunk() => {
                    break result;
                }
                n_res = client_read.read(&mut rbuf) => {
                    match n_res {
                        Ok(0) => {
                            active.writer.close().await.context("uplink half-close failed")?;
                            client_half_closed = true;
                        }
                        Ok(n) => {
                            active.writer
                                .send_chunk(&rbuf[..n])
                                .await
                                .context("uplink write failed")?;
                            metrics::add_bytes(
                                "tcp",
                                "client_to_upstream",
                                uplinks.group_name(),
                                &active.name,
                                n,
                            );
                            // Do not treat client→upstream bytes during phase 1
                            // as proof that the uplink is healthy yet.  A broken
                            // uplink can still accept writes and then reset or
                            // stall before producing the first response byte.
                            if replay.push(&rbuf[..n]) {
                                // Overflow just triggered — promote to the full
                                // response window immediately so the deadline
                                // reflects the new timeout before we reset it.
                                attempt_timeout = timeouts.upstream_response;
                            }
                            // Treat the deadline as "no response after the last
                            // request activity", not "no response since the
                            // beginning of phase 1".  Computed after the
                            // possible promotion above so the longer window
                            // takes effect on the very same chunk.
                            deadline = tokio::time::Instant::now() + attempt_timeout;
                        }
                        Err(e) => break Err(e.into()),
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    break Err(anyhow!(
                        "upstream did not respond within {}s (chunk 0)",
                        attempt_timeout.as_secs(),
                    ));
                }
            }
        };

        match attempt {
            Ok(chunk) if chunk.is_empty() => {
                client_write.shutdown().await.context("client shutdown failed")?;
                return Ok(None);
            }
            Ok(chunk) => {
                // Flush deferred failure records now that we have proof the
                // session is alive via a different uplink.
                for (failed_index, failed_uplink_name, failed_error) in
                    deferred_phase1_failures.drain(..)
                {
                    let deferred_error = anyhow!(failed_error.clone());
                    uplinks
                        .report_runtime_failure(
                            failed_index,
                            TransportKind::Tcp,
                            &deferred_error,
                        )
                        .await;
                    debug!(
                        uplink = %failed_uplink_name,
                        error = %failed_error,
                        recovered_via = %active.name,
                        "recorded deferred TCP chunk-0 runtime failure after successful failover"
                    );
                }
                return Ok(Some(chunk));
            }
            Err(ref e) if active.reader.closed_cleanly() => {
                debug!(
                    uplink = %active.name,
                    error = %format!("{e:#}"),
                    "upstream closed before sending any data (phase 1)"
                );
                client_write.shutdown().await.context("client shutdown failed")?;
                return Ok(None);
            }
            Err(e) => {
                let mut phase1_error = e;

                // ── Warm-standby stale-socket retry ─────────────────────────
                // If the connection came from the standby pool, try once more
                // with a fresh dial before treating the failure as real.
                if active.source == super::failover::TcpUplinkSource::Standby {
                    debug!(
                        uplink = %active.name,
                        error = %format!("{phase1_error:#}"),
                        "TCP phase-1 failure on warm-standby socket; retrying same uplink with a fresh dial"
                    );
                    match connect_tcp_uplink_fresh(uplinks, &active.candidate, target).await {
                        Ok(reconnected) => {
                            active.replace_transport(reconnected);
                            replay
                                .replay_to(&mut active.writer, "replay to fresh uplink after standby failure failed")
                                .await?;
                            if client_half_closed {
                                active.writer
                                    .close()
                                    .await
                                    .context("fresh uplink half-close after standby failure failed")?;
                            }
                            continue;
                        }
                        Err(connect_err) => {
                            phase1_error = connect_err
                                .context("fresh dial retry after warm-standby phase-1 failure failed");
                        }
                    }
                }

                // ── Transparent same-uplink RST retry ────────────────────────
                // A brief transit flap at the uplink egress frequently resets
                // fresh WS handshakes on multiple uplinks within a few hundred
                // ms; jumping straight to cross-uplink failover is a worse
                // outcome than re-dialing the same endpoint once the flap
                // clears.  Bounded retries + short backoff cap the worst-case
                // recovery at well under a second.  Only applied to fresh-dial
                // sources: Standby has its own retry branch above, and
                // DirectSocket does not go through WebSocket.
                if active.source == super::failover::TcpUplinkSource::FreshDial
                    && rst_retries_on_current_uplink < CHUNK0_RST_MAX_RETRIES
                    && crate::disconnect::is_websocket_closed(&phase1_error)
                {
                    let attempt_num = rst_retries_on_current_uplink + 1;
                    debug!(
                        uplink = %active.name,
                        target = %target,
                        retry = attempt_num,
                        max_retries = CHUNK0_RST_MAX_RETRIES,
                        error = %format!("{phase1_error:#}"),
                        "TCP chunk-0 transport reset; silently retrying same uplink before failover"
                    );
                    tokio::time::sleep(CHUNK0_RST_RETRY_BACKOFF).await;
                    match connect_tcp_uplink_fresh(uplinks, &active.candidate, target).await {
                        Ok(reconnected) => {
                            active.replace_transport(reconnected);
                            rst_retries_on_current_uplink = attempt_num;
                            replay
                                .replay_to(&mut active.writer, "replay to retried uplink after chunk-0 reset failed")
                                .await?;
                            if client_half_closed {
                                active.writer
                                    .close()
                                    .await
                                    .context("retried uplink half-close after chunk-0 reset failed")?;
                            }
                            continue;
                        }
                        Err(connect_err) => {
                            phase1_error = connect_err
                                .context("fresh dial retry after chunk-0 transport reset failed");
                        }
                    }
                }

                let error_text = format!("{phase1_error:#}");
                let attempted_uplinks = outline_uplink::deduplicate_attempted_uplink_names(
                    deferred_phase1_failures.iter().map(|(_, name, _)| name.as_str()),
                    &active.name,
                );
                warn!(
                    uplink = %active.name,
                    attempted_uplinks = ?attempted_uplinks,
                    target = %target,
                    rst_retries_applied = rst_retries_on_current_uplink,
                    error = %error_text,
                    "TCP chunk-0 failure"
                );

                if !can_failover {
                    if deferred_phase1_failures.is_empty() {
                        // Apply the same attribution logic as phase 2: a
                        // WebSocket close (including Close 1013 "try again"
                        // from the server) means the uplink itself is healthy —
                        // the remote target was just unreachable.  Using
                        // report_runtime_failure here would put the uplink into
                        // a cooldown and degrade unrelated sessions for blocked
                        // social-media targets.  Use the lighter
                        // report_upstream_close instead so the probe cycle is
                        // not skipped but no cooldown is imposed.
                        if crate::disconnect::is_upstream_runtime_failure(&phase1_error) {
                            uplinks
                                .report_runtime_failure(
                                    active.index,
                                    TransportKind::Tcp,
                                    &phase1_error,
                                )
                                .await;
                        } else if crate::disconnect::is_websocket_closed(&phase1_error) {
                            uplinks
                                .report_upstream_close(active.index, TransportKind::Tcp)
                                .await;
                        }
                    } else {
                        warn!(
                            last_uplink = %active.name,
                            attempts = attempted_uplinks.len(),
                            attempted_uplinks = ?attempted_uplinks,
                            error = %error_text,
                            "suppressing TCP chunk-0 runtime failure attribution because every attempted uplink stalled before the first response"
                        );
                    }
                    return Err(phase1_error);
                }

                // ── Cross-uplink failover ─────────────────────────────────────
                deferred_phase1_failures.push((
                    active.index,
                    active.name.to_string(),
                    error_text,
                ));

                let candidates = uplinks
                    .tcp_failover_candidates(target, active.index)
                    .await;
                let next = candidates
                    .into_iter()
                    .find(|c| !tried_indexes.contains(&c.index));
                let Some(next_candidate) = next else {
                    return Err(
                        phase1_error
                            .context("no alternative uplink available for chunk-0 failover"),
                    );
                };
                tried_indexes.insert(next_candidate.index);

                let reconnected =
                    match connect_tcp_uplink(uplinks, &next_candidate, target).await {
                        Ok(v) => v,
                        Err(connect_err) => {
                            uplinks
                                .report_runtime_failure(
                                    next_candidate.index,
                                    TransportKind::Tcp,
                                    &connect_err,
                                )
                                .await;
                            return Err(connect_err.context("chunk-0 failover connect failed"));
                        }
                    };

                uplinks
                    .confirm_runtime_failover_uplink(
                        TransportKind::Tcp,
                        Some(target),
                        next_candidate.index,
                    )
                    .await;
                metrics::record_failover(
                    "tcp",
                    uplinks.group_name(),
                    &active.name,
                    &next_candidate.uplink.name,
                );
                metrics::record_uplink_selected(
                    "tcp",
                    uplinks.group_name(),
                    &next_candidate.uplink.name,
                );
                info!(
                    from = %active.name,
                    to = %next_candidate.uplink.name,
                    "TCP chunk-0 failover"
                );

                active.switch_to(next_candidate, reconnected);
                rst_retries_on_current_uplink = 0;

                replay
                    .replay_to(&mut active.writer, "replay to failover uplink failed")
                    .await?;
                if client_half_closed {
                    active.writer
                        .close()
                        .await
                        .context("failover uplink half-close failed")?;
                }
                // Fall through → loop restarts with the new uplink.
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 2 — bidirectional relay
// ---------------------------------------------------------------------------

/// Drives the long-lived bidirectional relay between the SOCKS client and the
/// pinned upstream after phase 1 has completed successfully.
///
/// Spawns an uplink task (client→upstream) and a downlink task
/// (upstream→client), wires them through an idle watcher, and reports any
/// mid-stream transport failures back to the uplink manager so that broken
/// transports trigger the H3→H2 downgrade and flush stale standby connections
/// promptly.
async fn run_relay(
    uplinks: UplinkManager,
    active: ActiveTcpUplink,
    target_label: Arc<str>,
    first_chunk: Vec<u8>,
    mut client_read: OwnedReadHalf,
    mut client_write: OwnedWriteHalf,
    timeouts: &TcpTimeouts,
) -> Result<()> {
    // Once phase 1 completed and we received the first upstream bytes, this
    // SOCKS TCP session is pinned to the uplink that completed setup.
    // Strict active-uplink reselection only affects new sessions and
    // chunk-0 failover; established TCP tunnels are not migrated
    // transparently and should only end on a real transport error.
    let active_index = active.index;
    let active_name = active.name;
    let mut writer = active.writer;
    let mut reader = active.reader;

    // Idle-watcher activity channel: each data task signals a token after
    // every successful non-keepalive payload transfer.  Keepalive frames
    // deliberately do NOT signal activity — they only prove the local
    // WebSocket writer task is alive, not that the upstream server is
    // still reading, so counting them would defeat the watcher.
    let (activity_tx, activity_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let activity_for_uplink = activity_tx.clone();
    let activity_for_downlink = activity_tx.clone();
    // Drop the original handle so the channel closes naturally once both
    // data tasks finish and drop their clones.
    drop(activity_tx);

    let name_for_uplink_task = Arc::clone(&active_name);
    let manager_for_uplink_task = uplinks.clone();
    let keepalive_interval = uplinks.load_balancing().tcp_active_keepalive_interval;
    let uplink = async move {
        let mut buf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];
        let mut chunks_sent: u64 = 0;
        loop {
            // When a keepalive interval is set, race the client read against
            // a sleep timer.  If the timer fires first we send a Shadowsocks
            // keepalive frame (no-op for SS1, 0-length encrypted chunk for
            // SS2022) and loop immediately with a fresh timer.  This defeats
            // upstream proxy / NAT idle-timeout disconnections that otherwise
            // kill long-lived sessions (SSH, etc.) after ~25–30 s of silence.
            let read = if let Some(d) = keepalive_interval {
                tokio::select! {
                    result = client_read.read(&mut buf) => result.map_err(ClientIo::ReadFailed)?,
                    _ = tokio::time::sleep(d) => {
                        writer
                            .send_keepalive()
                            .await
                            .context("upstream TCP keepalive failed")?;
                        // A successfully sent keepalive means the upstream
                        // path is alive.  Signal the idle watcher so it
                        // doesn't kill the session while the remote target
                        // is merely slow to respond (e.g. a long model
                        // inference step on an SSE stream).
                        let _ = activity_for_uplink.send(());
                        continue;
                    }
                }
            } else {
                client_read.read(&mut buf).await.map_err(ClientIo::ReadFailed)?
            };
            if read == 0 {
                // Client-side EOF.  Signal the upstream that we will not
                // send any more data (for WebSocket transport this emits a
                // Close frame; for a direct socket this half-closes the TCP
                // write side) and exit the uplink task.  The downlink task
                // is *not* aborted here: the server may still have in-flight
                // bytes to deliver — e.g. an SSH server sending its final
                // response after the client-side TUN/SOCKS5 layer half-
                // closed the flow — and tearing the upstream down eagerly
                // would truncate them and kill long-lived sessions the
                // moment the TUN hits its own idle timeout.  The downlink
                // will finish naturally once the server echoes our close.
                debug!(
                    uplink = %name_for_uplink_task,
                    transport_supports_tcp_half_close = writer.supports_half_close(),
                    "client closed SOCKS TCP session; initiating upstream half-close and awaiting downlink"
                );
                writer.close().await?;
                break;
            }
            metrics::add_bytes(
                "tcp",
                "client_to_upstream",
                manager_for_uplink_task.group_name(),
                &name_for_uplink_task,
                read,
            );
            writer.send_chunk(&buf[..read]).await?;
            let _ = activity_for_uplink.send(());
            chunks_sent += 1;
            if chunks_sent == 1 {
                debug!(uplink = %name_for_uplink_task, "first chunk sent to upstream");
            }
            manager_for_uplink_task
                .report_active_traffic(active_index, TransportKind::Tcp)
                .await;
        }
        Ok::<UplinkOutcome, anyhow::Error>(UplinkOutcome::Finished)
    };

    let name_for_downlink_task = Arc::clone(&active_name);
    let manager_for_downlink_task = uplinks.clone();
    let downlink = async move {
        metrics::add_bytes(
            "tcp",
            "upstream_to_client",
            manager_for_downlink_task.group_name(),
            &name_for_downlink_task,
            first_chunk.len(),
        );
        client_write
            .write_all(&first_chunk)
            .await
            .map_err(ClientIo::WriteFailed)?;
        let _ = activity_for_downlink.send(());
        manager_for_downlink_task
            .report_active_traffic(active_index, TransportKind::Tcp)
            .await;

        let mut chunks_forwarded: u64 = 1;
        loop {
            let chunk = match reader.read_chunk().await {
                Ok(chunk) => chunk,
                Err(_err) if reader.closed_cleanly() => {
                    if chunks_forwarded == 0 {
                        debug!(
                            uplink = %name_for_downlink_task,
                            "upstream closed before sending any data"
                        );
                    }
                    break;
                }
                Err(err) => return Err(err),
            };
            if chunk.is_empty() {
                // An empty decrypted payload is not valid in Shadowsocks;
                // treat it as EOF rather than busy-looping without any await.
                break;
            }
            chunks_forwarded += 1;
            metrics::add_bytes(
                "tcp",
                "upstream_to_client",
                manager_for_downlink_task.group_name(),
                &name_for_downlink_task,
                chunk.len(),
            );
            client_write
                .write_all(&chunk)
                .await
                .map_err(ClientIo::WriteFailed)?;
            let _ = activity_for_downlink.send(());
            manager_for_downlink_task
                .report_active_traffic(active_index, TransportKind::Tcp)
                .await;
        }
        client_write
            .shutdown()
            .await
            .context("client shutdown failed")?;
        Ok::<(), anyhow::Error>(())
    };

    // Preserve client half-close semantics (client EOF while still waiting
    // for the response), but do not keep the upstream transport alive after
    // the server side has already closed cleanly.
    let result = drive_tcp_session_tasks(
        uplink,
        downlink,
        Some(IdleGuard::new(activity_rx, timeouts.socks_upstream_idle)),
        target_label,
        timeouts.post_client_eof_downstream,
    )
    .await;

    // Report mid-stream upstream transport failures so that broken transports
    // (e.g. H3 APPLICATION_CLOSE received after session establishment) trigger
    // the H3→H2 downgrade and flush stale warm-standby connections
    // immediately, rather than waiting for the next connection attempt to fail.
    // Client-side disconnects and intentional uplink switches are excluded.
    if let Err(ref err) = result {
        if crate::disconnect::is_upstream_runtime_failure(err) {
            uplinks
                .report_runtime_failure(active_index, TransportKind::Tcp, err)
                .await;
        } else if crate::disconnect::is_websocket_closed(err) {
            // The upstream server closed the WebSocket connection
            // mid-stream (server-initiated close, not a client
            // disconnect).  We do not set a full runtime-failure
            // cooldown to avoid penalising the uplink for normal
            // per-connection lifetime limits, but we clear the
            // activity timestamp so the probe is not skipped on the
            // next cycle — this lets the probe detect a downed server
            // promptly rather than waiting for probe.interval of silence.
            uplinks
                .report_upstream_close(active_index, TransportKind::Tcp)
                .await;
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn serve_tcp_connect(
    mut client: TcpStream,
    dispatch: Route,
    target: TargetAddr,
    dns_cache: Arc<outline_transport::DnsCache>,
    timeouts: TcpTimeouts,
) -> Result<()> {
    let uplinks = match dispatch {
        Route::Direct { fwmark } => {
            info!(target = %target, "TCP route: direct connection");
            return handle_tcp_direct(client, target, fwmark, &dns_cache, timeouts).await;
        }
        Route::Drop => {
            info!(target = %target, "TCP route: policy drop");
            return handle_tcp_drop(client, &target).await;
        }
        Route::Group { name, manager } => {
            debug!(target = %target, group = %name, "TCP route: dispatching via group");
            manager
        }
    };

    let session = metrics::track_session("tcp");
    let result = async {
        // ── Initial uplink selection ─────────────────────────────────────────
        let mut last_error = None;
        let mut selected = None;
        let strict_transport = uplinks.strict_active_uplink_for(TransportKind::Tcp);
        let chunk0_attempt_timeout = uplinks.load_balancing().tcp_chunk0_failover_timeout;
        let mut tried_indexes = HashSet::new();
        loop {
            let candidates = uplinks.tcp_candidates(&target).await;
            let iter = if strict_transport {
                candidates.into_iter().take(1).collect::<Vec<_>>()
            } else {
                candidates
            };
            if iter.is_empty() {
                break;
            }
            let mut progressed = false;
            for candidate in iter {
                if strict_transport && !tried_indexes.insert(candidate.index) {
                    continue;
                }
                progressed = true;
                match connect_tcp_uplink(&uplinks, &candidate, &target).await {
                    Ok(connected) => {
                        selected = Some((candidate, connected));
                        break;
                    }
                    Err(error) => {
                        uplinks
                            .report_runtime_failure(candidate.index, TransportKind::Tcp, &error)
                            .await;
                        last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
                    }
                }
            }
            if selected.is_some() || !strict_transport || !progressed {
                break;
            }
        }

        let (candidate, connected) = selected.ok_or_else(|| {
            anyhow!(
                "all TCP uplinks failed: {}",
                last_error.unwrap_or_else(|| "no uplinks available".to_string())
            )
        })?;
        let mut active = ActiveTcpUplink::new(candidate.clone(), connected);
        uplinks
            .confirm_selected_uplink(TransportKind::Tcp, Some(&target), active.index)
            .await;
        metrics::record_uplink_selected("tcp", uplinks.group_name(), &active.name);
        info!(
            uplink = %active.name,
            weight = candidate.uplink.weight,
            target = %target,
            "selected TCP uplink"
        );

        let bound_addr = socket_addr_to_target(client.local_addr()?);
        send_reply(&mut client, SOCKS_STATUS_SUCCESS, &bound_addr).await?;

        let (mut client_read, mut client_write) = client.into_split();
        let mut replay = ReplayBufState::new();

        // ── Phase 1: chunk-0 failover ────────────────────────────────────────
        let first_chunk = match try_uplinks(
            &uplinks,
            &mut active,
            &target,
            strict_transport,
            &mut tried_indexes,
            chunk0_attempt_timeout,
            &timeouts,
            &mut client_read,
            &mut client_write,
            &mut replay,
        )
        .await?
        {
            Some(chunk) => chunk,
            None => return Ok(()),
        };

        // Phase-1 replay buffer is no longer needed; release memory before
        // the long-lived phase-2 tasks take over.
        drop(replay);

        // ── Phase 2: bidirectional relay ─────────────────────────────────────
        let target_label: Arc<str> = Arc::from(target.to_string());
        run_relay(
            uplinks,
            active,
            target_label,
            first_chunk,
            client_read,
            client_write,
            &timeouts,
        )
        .await
    }
    .await;

    session.finish(result.is_ok());
    result
}

/// Send a SOCKS5 reply with REP=0x02 (connection not allowed by ruleset) and
/// close the client connection. Used when a matched route has `via = "drop"`.
async fn handle_tcp_drop(mut client: TcpStream, target: &TargetAddr) -> Result<()> {
    let bound_addr = socket_addr_to_target(client.local_addr()?);
    send_reply(&mut client, SOCKS_STATUS_NOT_ALLOWED, &bound_addr).await?;
    debug!(target = %target, "TCP route: drop reply sent");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// `handle_tcp_drop` must send a SOCKS5 REP=0x02 (not allowed) reply and
    /// return `Ok(())` without forwarding any data.
    #[tokio::test]
    async fn handle_tcp_drop_sends_not_allowed_reply() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect_fut = tokio::net::TcpStream::connect(addr);
        let accept_fut = listener.accept();
        let (connect_res, accept_res) = tokio::join!(connect_fut, accept_fut);
        let mut client_side = connect_res.unwrap();
        let (server_side, _) = accept_res.unwrap();

        let target = TargetAddr::IpV4("1.2.3.4".parse().unwrap(), 80);
        handle_tcp_drop(server_side, &target).await.unwrap();

        // SOCKS5 reply: VER REP RSV ATYP(IPv4) ADDR(4) PORT(2) = 10 bytes
        let mut reply = [0u8; 10];
        client_side.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 5, "VER must be 5");
        assert_eq!(reply[1], SOCKS_STATUS_NOT_ALLOWED, "REP must be 0x02 (not allowed)");
        assert_eq!(reply[2], 0, "RSV must be 0");
        assert_eq!(reply[3], 1, "ATYP must be 1 (IPv4)");
    }
}
