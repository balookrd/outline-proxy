use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use socks5_proto::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use outline_metrics as metrics;
use outline_transport::TcpWriter;
use shadowsocks_crypto::SHADOWSOCKS_MAX_PAYLOAD;

use outline_uplink::{TransportKind, UplinkManager, UplinkTransport};

use super::super::failover::{
    ActiveTcpUplink, ConnectedTcpUplink, redial_for_mid_session_retry,
};
use super::super::session::{IdleGuard, UplinkOutcome, drive_tcp_session_tasks};
use super::ring_buffer::{ClientUpstreamRingBuffer, ReplayError};
use crate::client_io::ClientIo;
use crate::proxy::TcpTimeouts;

enum UplinkIo {
    ClientRead(usize),
    KeepaliveSent,
}

async fn read_client_or_keepalive<R: AsyncRead + Unpin>(
    client_read: &mut R,
    buf: &mut [u8],
    keepalive_interval: Option<Duration>,
    writer: &mut TcpWriter,
) -> Result<UplinkIo> {
    if let Some(interval) = keepalive_interval {
        tokio::select! {
            result = client_read.read(buf) => {
                Ok(UplinkIo::ClientRead(result.map_err(ClientIo::ReadFailed)?))
            }
            _ = tokio::time::sleep(interval) => {
                writer
                    .send_keepalive()
                    .await
                    .context("upstream TCP keepalive failed")?;
                Ok(UplinkIo::KeepaliveSent)
            }
        }
    } else {
        Ok(UplinkIo::ClientRead(client_read.read(buf).await.map_err(ClientIo::ReadFailed)?))
    }
}

/// Drives the long-lived bidirectional relay between the SOCKS client
/// and the pinned upstream after chunk-0 failover has completed.
///
/// Spawns an uplink task (client→upstream) and a downlink task
/// (upstream→client), wires them through an idle watcher, and reports
/// any mid-stream transport failures back to the uplink manager so
/// that broken transports trigger the H3→H2 downgrade and flush stale
/// standby connections promptly.
///
/// When the group's `tcp_mid_session_retry_buffer_bytes` is non-zero
/// AND the uplink is configured for SS-WS, the relay also wires the
/// Ack-Prefix Protocol mid-session retry path:
///
///   1. Every uplink chunk is appended to a bounded
///      [`ClientUpstreamRingBuffer`] before being sent.
///   2. On the first retriable mid-session failure, the relay
///      re-dials the same uplink with the Ack-Prefix capability bit
///      set, parses the server-reported `up_acked` offset from the
///      new SS reader, replays the buffered tail starting at that
///      offset, and resumes the relay loop with the fresh transport.
///   3. The retry budget is `1` per session — a second mid-session
///      reset propagates as before.
///
/// Outcomes are surfaced on
/// `outline_ws_rust_uplink_mid_session_retries_total{outcome}` with
/// `outcome ∈ {success, failed_redial, failed_replay,
/// buffer_overflow}`. The downlink direction is intentionally NOT
/// replayed — v1 narrows zero-loss replay to the uplink only, so SSH-
/// style sessions still observe downlink byte gaps on retry.
pub(super) async fn run_relay(
    uplinks: UplinkManager,
    active: ActiveTcpUplink,
    target: TargetAddr,
    target_label: Arc<str>,
    first_chunk: Vec<u8>,
    client_read: OwnedReadHalf,
    client_write: OwnedWriteHalf,
    timeouts: &TcpTimeouts,
) -> Result<()> {
    // Once chunk-0 failover completed and we received the first upstream bytes,
    // this SOCKS TCP session is pinned to the uplink that completed setup.
    // Strict active-uplink reselection only affects new sessions and chunk-0
    // failover; established TCP tunnels are not migrated transparently and
    // should only end on a real transport error (or — Phase 2.4 — be
    // re-dialled within the same uplink via the Ack-Prefix retry path).
    let active_index = active.index;
    let active_name = Arc::clone(&active.name);
    let candidate = active.candidate.clone();

    let lb_snapshot = uplinks.load_balancing();
    let buffer_cap = lb_snapshot.tcp_mid_session_retry_buffer_bytes;
    let keepalive_interval = lb_snapshot.tcp_active_keepalive_interval;
    // Mid-session retry only operates on the SS-WS dial path in v1 —
    // VLESS-WS and raw-QUIC do not negotiate the capability, and the
    // SS-direct-socket path bypasses the WS layer entirely. The
    // orchestrator skips retry for those uplinks rather than dialling
    // a path that would not give us the offset header.
    let retry_eligible = buffer_cap > 0 && candidate.uplink.transport == UplinkTransport::Ws;
    let mut budget: u8 = if retry_eligible { 1 } else { 0 };

    let ring: Option<Arc<Mutex<ClientUpstreamRingBuffer>>> = retry_eligible
        .then(|| Arc::new(Mutex::new(ClientUpstreamRingBuffer::new(buffer_cap))));

    let client_read = Arc::new(Mutex::new(client_read));
    let client_write = Arc::new(Mutex::new(client_write));

    // Per-iteration owned values. After a successful redial they are
    // replaced with the fresh transport; until that moment, the closures
    // own them by move.
    let mut writer = active.writer;
    let mut reader = active.reader;
    // The first chunk is what chunk-0 failover already received from the
    // upstream — it must be flushed downstream before we start reading
    // from the new SS reader. Iteration 0 owns it; subsequent iterations
    // do not have one (replay covers the uplink direction; the downlink
    // simply continues from wherever the new server left off).
    let mut first_chunk_for_iter = Some(first_chunk);

    // Final outcome, set once the loop exits.
    let final_result;

    loop {
        // Idle-watcher activity channel: each data task signals a token
        // after every successful non-keepalive payload transfer. Keepalive
        // frames deliberately do NOT signal activity — they only prove
        // the local WebSocket writer task is alive, not that the upstream
        // server is still reading. A fresh channel per iteration so the
        // watcher's deadline restarts after a successful redial.
        let (activity_tx, activity_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let activity_for_uplink = activity_tx.clone();
        let activity_for_downlink = activity_tx.clone();
        drop(activity_tx);

        let name_for_uplink = Arc::clone(&active_name);
        let manager_for_uplink = uplinks.clone();
        let cr_for_uplink = Arc::clone(&client_read);
        let ring_for_uplink = ring.clone();
        let mut uplink_writer = writer;
        let uplink = async move {
            let mut buf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];
            let mut chunks_sent: u64 = 0;
            loop {
                let read = {
                    let mut cr_guard = cr_for_uplink.lock().await;
                    match read_client_or_keepalive(
                        &mut *cr_guard,
                        &mut buf,
                        keepalive_interval,
                        &mut uplink_writer,
                    )
                    .await?
                    {
                        UplinkIo::ClientRead(read) => read,
                        UplinkIo::KeepaliveSent => continue,
                    }
                };
                if read == 0 {
                    // Client-side EOF. Signal upstream half-close (Close
                    // frame for WS, half-close FIN for sockets) and
                    // exit the uplink task. Downlink is NOT aborted —
                    // a server may still have in-flight bytes (SSH
                    // banner, HTTP response after request body) and
                    // tearing the upstream down eagerly would truncate
                    // them.
                    debug!(
                        uplink = %name_for_uplink,
                        transport_supports_tcp_half_close = uplink_writer.supports_half_close(),
                        "client closed SOCKS TCP session; initiating upstream half-close and awaiting downlink"
                    );
                    uplink_writer.close().await?;
                    break;
                }
                metrics::add_bytes(
                    "tcp",
                    "client_to_upstream",
                    manager_for_uplink.group_name(),
                    &name_for_uplink,
                    read,
                );
                // Push BEFORE send so the buffer's `total_sent` matches
                // the bytes the server will see if the send succeeds.
                // Order matters for the Ack-Prefix offset semantics:
                // server reports bytes it ACKED, so anything we pushed
                // but failed to send is still counted in our buffer and
                // a future replay will re-emit it.
                if let Some(r) = &ring_for_uplink {
                    let mut r_guard = r.lock().await;
                    if let Err(push_err) = r_guard.push(&buf[..read]) {
                        // Single-chunk overflow: replay can never
                        // reconstruct this byte range, so the retry
                        // budget for this session is effectively burned.
                        // We still send the chunk through so the active
                        // session continues; the metric records that
                        // future retries on this session would fail
                        // `failed_replay`. Dropping the session here
                        // would be a surprise to the user — the chunk
                        // is valid and the upstream wants it.
                        metrics::record_mid_session_retry(
                            "tcp",
                            manager_for_uplink.group_name(),
                            &name_for_uplink,
                            "buffer_overflow",
                        );
                        debug!(
                            uplink = %name_for_uplink,
                            error = ?push_err,
                            "uplink chunk exceeds mid-session retry buffer cap; \
                             retry budget for this session is effectively burned"
                        );
                    }
                }
                uplink_writer.send_chunk(&buf[..read]).await?;
                let _ = activity_for_uplink.send(());
                chunks_sent += 1;
                if chunks_sent == 1 {
                    debug!(uplink = %name_for_uplink, "first chunk sent to upstream");
                }
                manager_for_uplink
                    .report_active_traffic(active_index, TransportKind::Tcp)
                    .await;
            }
            Ok::<UplinkOutcome, anyhow::Error>(UplinkOutcome::Finished)
        };

        let name_for_downlink = Arc::clone(&active_name);
        let manager_for_downlink = uplinks.clone();
        let cw_for_downlink = Arc::clone(&client_write);
        let mut downlink_reader = reader;
        let downlink_first_chunk = first_chunk_for_iter.take();
        let downlink = async move {
            let already_forwarded = if let Some(fc) = downlink_first_chunk {
                if !fc.is_empty() {
                    metrics::add_bytes(
                        "tcp",
                        "upstream_to_client",
                        manager_for_downlink.group_name(),
                        &name_for_downlink,
                        fc.len(),
                    );
                    let mut cw_guard = cw_for_downlink.lock().await;
                    cw_guard
                        .write_all(&fc)
                        .await
                        .map_err(ClientIo::WriteFailed)?;
                    drop(cw_guard);
                    let _ = activity_for_downlink.send(());
                    manager_for_downlink
                        .report_active_traffic(active_index, TransportKind::Tcp)
                        .await;
                    1u64
                } else {
                    0u64
                }
            } else {
                0u64
            };

            let mut chunks_forwarded: u64 = already_forwarded;
            loop {
                let chunk = match downlink_reader.read_chunk().await {
                    Ok(chunk) => chunk,
                    Err(_err) if downlink_reader.closed_cleanly() => {
                        if chunks_forwarded == 0 {
                            debug!(
                                uplink = %name_for_downlink,
                                "upstream closed before sending any data"
                            );
                        }
                        break;
                    },
                    Err(err) => return Err(err),
                };
                if chunk.is_empty() {
                    // An empty decrypted payload is not valid in SS;
                    // treat it as EOF rather than busy-looping.
                    break;
                }
                chunks_forwarded += 1;
                metrics::add_bytes(
                    "tcp",
                    "upstream_to_client",
                    manager_for_downlink.group_name(),
                    &name_for_downlink,
                    chunk.len(),
                );
                let mut cw_guard = cw_for_downlink.lock().await;
                cw_guard
                    .write_all(&chunk)
                    .await
                    .map_err(ClientIo::WriteFailed)?;
                drop(cw_guard);
                let _ = activity_for_downlink.send(());
                manager_for_downlink
                    .report_active_traffic(active_index, TransportKind::Tcp)
                    .await;
            }
            let mut cw_guard = cw_for_downlink.lock().await;
            cw_guard.shutdown().await.context("client shutdown failed")?;
            Ok::<(), anyhow::Error>(())
        };

        let result = drive_tcp_session_tasks(
            uplink,
            downlink,
            Some(IdleGuard::new(activity_rx, timeouts.socks_upstream_idle)),
            Arc::clone(&target_label),
            timeouts.post_client_eof_downstream,
        )
        .await;

        // After `drive_tcp_session_tasks` returns, both spawned tasks
        // have either completed or been aborted; their captured locals
        // (writer, reader) are dropped. To restart the relay we need
        // a fresh transport from `redial_for_mid_session_retry`.
        match result {
            Ok(()) => {
                final_result = Ok(());
                break;
            },
            Err(err) => {
                let retriable = budget > 0
                    && retry_eligible
                    && crate::error_class::is_upstream_runtime_failure(&err);
                if !retriable {
                    final_result = Err(err);
                    break;
                }
                // We are about to consume one budget unit on a redial
                // attempt. Decrement now so any early-bail path inside
                // the retry block does not loop forever on repeated
                // failures.
                budget -= 1;
                debug!(
                    uplink = %active_name,
                    error = %format!("{err:#}"),
                    budget_remaining = budget,
                    "mid-session transport reset; attempting Ack-Prefix retry"
                );

                let connected = match try_mid_session_retry(
                    &uplinks,
                    &active_name,
                    &candidate,
                    &target,
                    ring.as_deref(),
                )
                .await
                {
                    Ok(connected) => connected,
                    Err(retry_err) => {
                        warn!(
                            uplink = %active_name,
                            error = %format!("{retry_err:#}"),
                            "mid-session retry failed; propagating original transport error"
                        );
                        final_result = Err(err);
                        break;
                    },
                };

                metrics::record_mid_session_retry(
                    "tcp",
                    uplinks.group_name(),
                    &active_name,
                    "success",
                );
                debug!(
                    uplink = %active_name,
                    "mid-session retry succeeded; resuming relay on fresh transport"
                );
                let ConnectedTcpUplink { writer: new_writer, reader: new_reader, .. } = connected;
                writer = new_writer;
                reader = new_reader;
                // No first_chunk on subsequent iterations — the replay
                // covers the uplink side; the downlink simply continues
                // reading from the new transport.
                continue;
            },
        }
    }

    // Mirror the original tail behaviour: surface mid-stream upstream
    // transport failures so broken transports (e.g. H3 APPLICATION_CLOSE
    // received after session establishment) trigger the H3→H2 downgrade
    // and flush stale warm-standby connections immediately.
    if let Err(ref err) = final_result {
        if crate::error_class::is_upstream_runtime_failure(err) {
            uplinks
                .report_runtime_failure(active_index, TransportKind::Tcp, err)
                .await;
        } else if crate::error_class::is_ws_closed(err) {
            // Server-initiated WS close mid-stream. We do not set a
            // full runtime-failure cooldown to avoid penalising the
            // uplink for normal per-connection lifetime limits, but we
            // clear the activity timestamp so the probe is not skipped
            // on the next cycle.
            uplinks.report_upstream_close(active_index, TransportKind::Tcp).await;
        }
    }
    final_result
}

/// Performs one mid-session retry attempt. Re-dials the same uplink with
/// the Ack-Prefix capability bit set, validates the server-reported
/// `up_acked` offset, replays the buffered uplink tail starting at that
/// offset, and returns the fresh transport ready for the next relay
/// iteration.
///
/// All non-success paths surface the matching `outcome` value on
/// `outline_ws_rust_uplink_mid_session_retries_total` so the dashboard
/// can attribute each failure to its specific cause without parsing
/// log messages. The success counter is recorded by the caller after
/// this function returns `Ok` so that the metric only fires when the
/// next iteration is actually about to start.
async fn try_mid_session_retry(
    uplinks: &UplinkManager,
    active_name: &Arc<str>,
    candidate: &outline_uplink::UplinkCandidate,
    target: &TargetAddr,
    ring: Option<&Mutex<ClientUpstreamRingBuffer>>,
) -> Result<ConnectedTcpUplink> {
    let group_name = uplinks.group_name();

    let mut connected = match redial_for_mid_session_retry(uplinks, candidate, target).await {
        Ok(c) => c,
        Err(e) => {
            metrics::record_mid_session_retry("tcp", group_name, active_name, "failed_redial");
            return Err(e.context("mid-session redial failed"));
        },
    };

    // v1 simplification: do NOT drive a pre-read against the new
    // reader to surface `upstream_acked_offset()` here. The SS
    // reader recurses past the 14-byte prefix into the first real
    // downlink chunk, which may never arrive on upload-only sessions
    // (SSH `cat | ssh upload`, an HTTP POST that times out). Instead,
    // we replay the FULL buffered tail and rely on the server's
    // idempotent receive path to drop the prefix it has already
    // acked. The cost is up to `buffer_cap` bytes of redundant
    // upload after each retry; the alternative — blocking the entire
    // session on a `read_chunk` that may never return — is worse.
    // v1.1 should rework the API to surface the offset without a
    // blocking read (e.g. plumb a `recv_one_chunk_with_timeout`
    // helper into the SS reader).
    let replay_bytes = match ring {
        Some(r) => {
            let r_guard = r.lock().await;
            // Replaying from `oldest_offset()` covers everything in
            // the buffer; the server's idempotent receive path drops
            // any prefix it has already acked. This is the v1
            // simplification described in the comment above.
            let oldest = r_guard.oldest_offset();
            match r_guard.replay_from(oldest) {
                Ok(bytes) => bytes,
                Err(ReplayError::OffsetEvicted { .. } | ReplayError::OffsetAhead { .. }) => {
                    metrics::record_mid_session_retry(
                        "tcp",
                        group_name,
                        active_name,
                        "failed_replay",
                    );
                    return Err(anyhow!(
                        "mid-session retry: ring buffer cannot satisfy replay from oldest offset"
                    ));
                },
            }
        },
        None => {
            // retry_eligible was false; should not be reached because the
            // outer caller gates on the same condition. Bail defensively.
            return Err(anyhow!(
                "mid-session retry attempted without an active ring buffer"
            ));
        },
    };

    if !replay_bytes.is_empty() {
        if let Err(e) = send_replay_through_writer(&mut connected.writer, &replay_bytes).await {
            metrics::record_mid_session_retry("tcp", group_name, active_name, "failed_replay");
            return Err(e.context("mid-session retry: replay send failed"));
        }
    }

    Ok(connected)
}

/// Sends the buffered uplink tail through the freshly-redialed writer.
/// Wrapped so the metric attribution stays self-contained at one
/// callsite, and so a future change (chunked replay, replay-rate
/// limiting, etc.) only touches one function.
async fn send_replay_through_writer(writer: &mut TcpWriter, replay: &[u8]) -> Result<()> {
    // SHADOWSOCKS_MAX_PAYLOAD is the SS framing limit; the writer
    // already fragments larger chunks internally, but slicing here
    // keeps individual `send_chunk` calls bounded to one AEAD frame
    // and matches the original-send fragmentation pattern so the
    // server sees an identical chunk shape on replay.
    for chunk in replay.chunks(SHADOWSOCKS_MAX_PAYLOAD) {
        writer
            .send_chunk(chunk)
            .await
            .context("mid-session retry: send_chunk failed during replay")?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/pinned_relay.rs"]
mod tests;
