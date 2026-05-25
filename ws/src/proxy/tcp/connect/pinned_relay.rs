use std::future::Future;
use std::pin::Pin;
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

use outline_uplink::{OverflowPolicy, TransportKind, UplinkManager, UplinkTransport};

use super::super::failover::{ActiveTcpUplink, ConnectedTcpUplink, redial_for_mid_session_retry};
use super::super::session::{DriveExit, IdleGuard, UplinkOutcome, drive_tcp_session_tasks};
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
    // Once chunk-0 failover completed and we received the first upstream
    // bytes, this SOCKS TCP session is pinned to the uplink that completed
    // setup. The pinned uplink cannot be migrated transparently — different
    // uplinks usually have different egress IPs, and the upstream server
    // does not know how to resume a session that started elsewhere.
    //
    // In `active_passive` mode (`strict_active_uplink_for(TCP)` is true)
    // the session is also forcibly torn down with TCP RST whenever the
    // manager's active pointer flips away from this session's uplink —
    // mirroring the TUN engine's `should_migrate_tcp_flow` policy so the
    // SOCKS5 ingress reaches the same egress-consistency guarantee.
    //
    // In all other cases the session ends only on a real transport error
    // (optionally re-dialled within the same uplink via the Ack-Prefix
    // Protocol mid-session retry path).
    let active_index = active.index;
    let active_name = Arc::clone(&active.name);
    let candidate = active.candidate.clone();
    let strict_global = uplinks.strict_global_active_uplink();
    let strict_active = strict_global || uplinks.strict_per_uplink_active_uplink();

    let lb_snapshot = uplinks.load_balancing();
    let buffer_cap = lb_snapshot.tcp_mid_session_retry_buffer_bytes;
    let configured_budget = lb_snapshot.tcp_mid_session_retry_budget;
    let overflow_policy = lb_snapshot.tcp_mid_session_retry_overflow_policy;
    let consume_timeout = lb_snapshot.tcp_mid_session_retry_consume_timeout;
    let symmetric_replay_enabled = lb_snapshot.tcp_symmetric_replay_enabled;
    let symmetric_replay_max_bytes = lb_snapshot.tcp_symmetric_replay_max_bytes;
    let keepalive_interval = lb_snapshot.tcp_active_keepalive_interval;
    // Mid-session retry operates on WS-family uplinks (SS-WS and
    // VLESS-WS as of v1.1) — the SS-direct-socket path bypasses the
    // WS layer and raw-QUIC has no Ack-Prefix support, so the
    // orchestrator skips retry for those uplinks rather than
    // dialling a path that would not give us the offset header.
    //
    // Both knobs gate eligibility independently — buffer_bytes=0 OR
    // budget=0 disables retry. This lets operators turn off retry by
    // touching either knob, and lets a future deployment toggle the
    // budget while keeping the buffer warm.
    let retry_eligible = buffer_cap > 0
        && configured_budget > 0
        && matches!(candidate.uplink.transport, UplinkTransport::Ws | UplinkTransport::Vless,);
    let mut budget: u8 = if retry_eligible { configured_budget } else { 0 };

    let ring: Option<Arc<Mutex<ClientUpstreamRingBuffer>>> =
        retry_eligible.then(|| Arc::new(Mutex::new(ClientUpstreamRingBuffer::new(buffer_cap))));

    let client_read = Arc::new(Mutex::new(client_read));
    let client_write = Arc::new(Mutex::new(client_write));
    // Cumulative bytes the downlink task has successfully forwarded to
    // the SOCKS5 client over the lifetime of this session. Survives
    // mid-session retries unchanged — the same `Arc` is cloned into
    // each iteration's downlink closure. Used by the v2 Symmetric
    // Downlink Replay path on retry redial: the orchestrator reads
    // this counter and emits it as `X-Outline-Resume-Down-Acked`,
    // which the server uses to compute `replay_from(offset)` against
    // its parked downlink ring. Always tracked (regardless of whether
    // v2 is configured) so the counter is consistent if v2 is toggled
    // mid-deployment via config reload.
    let client_acked_offset = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Per-iteration owned values. After a successful redial they are
    // replaced with the fresh transport; until that moment, the closures
    // own them by move.
    let mut writer = active.writer;
    let mut reader = active.reader;
    // Tracks which wire of the parent uplink the current transport rides.
    // Carried across mid-session retries so the post-loop
    // `report_runtime_failure_for_wire` attributes the final mid-session
    // error to the wire that was actually live when it died — without this,
    // a mid-session reset on a fallback wire would always be charged
    // against the parent uplink as if every wire had been tried, undoing
    // the per-wire suppression added in `report_runtime_failure_for_wire`.
    let mut current_wire_index: u8 = active.wire_index;
    // The first chunk is what chunk-0 failover already received from the
    // upstream — it must be flushed downstream before we start reading
    // from the new SS reader. Iteration 0 owns it; subsequent iterations
    // do not have one (replay covers the uplink direction; the downlink
    // simply continues from wherever the new server left off).
    let mut first_chunk_for_iter = Some(first_chunk);

    // Final outcome, set once the loop exits.
    let final_result;
    // Set by the strict-active-uplink abort path so the post-loop tail
    // skips runtime-failure reporting (the close is policy-driven, not a
    // transport failure) and force-closes the client socket with RST.
    let mut force_rst_reason: Option<&'static str> = None;

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
                        // reconstruct this byte range. The configured
                        // policy decides whether the active session
                        // limps on (Soft — surfaces `failed_replay` on
                        // any future retry) or dies on the spot (Hard
                        // — guarantees retry-correctness for the rest
                        // of the deployment).
                        metrics::record_mid_session_retry(
                            "tcp",
                            manager_for_uplink.group_name(),
                            &name_for_uplink,
                            "buffer_overflow",
                        );
                        match overflow_policy {
                            outline_uplink::OverflowPolicy::Soft => {
                                debug!(
                                    uplink = %name_for_uplink,
                                    error = ?push_err,
                                    policy = "soft",
                                    "uplink chunk exceeds mid-session retry buffer cap; \
                                     letting the chunk through, future retries will surface \
                                     failed_replay"
                                );
                            },
                            outline_uplink::OverflowPolicy::Hard => {
                                debug!(
                                    uplink = %name_for_uplink,
                                    error = ?push_err,
                                    policy = "hard",
                                    "uplink chunk exceeds mid-session retry buffer cap; \
                                     dropping session per overflow policy"
                                );
                                drop(r_guard);
                                return Err(anyhow::anyhow!(
                                    "mid-session retry buffer overflow on uplink {} \
                                     (chunk_len={}, cap={}); session dropped per \
                                     tcp_mid_session_retry_overflow_policy = \"hard\"",
                                    name_for_uplink,
                                    read,
                                    buffer_cap,
                                ));
                            },
                        }
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
        let acked_for_downlink = Arc::clone(&client_acked_offset);
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
                    cw_guard.write_all(&fc).await.map_err(ClientIo::WriteFailed)?;
                    drop(cw_guard);
                    // Increment AFTER the write succeeds — the v2
                    // counter is the offset of bytes that have actually
                    // reached the SOCKS5 client. A failed write is
                    // accounted for via session teardown, not by
                    // bumping the counter.
                    acked_for_downlink
                        .fetch_add(fc.len() as u64, std::sync::atomic::Ordering::Relaxed);
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
                cw_guard.write_all(&chunk).await.map_err(ClientIo::WriteFailed)?;
                drop(cw_guard);
                // v2 downlink counter: bump after the write completes
                // so the reported offset only ever reflects bytes the
                // SOCKS5 client has observed.
                acked_for_downlink
                    .fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::Relaxed);
                let _ = activity_for_downlink.send(());
                manager_for_downlink
                    .report_active_traffic(active_index, TransportKind::Tcp)
                    .await;
            }
            let mut cw_guard = cw_for_downlink.lock().await;
            cw_guard.shutdown().await.context("client shutdown failed")?;
            Ok::<(), anyhow::Error>(())
        };

        let cancel: Pin<Box<dyn Future<Output = &'static str> + Send>> = if strict_active {
            // In strict `active_passive` mode, watch the manager's active
            // pointer and tear the session down as soon as it points at a
            // different uplink. The session cannot migrate to a different
            // egress in-place, and leaving it on a deactivated uplink
            // breaks egress consistency (different source IP / ASN from
            // the new active uplink).
            Box::pin(watch_active_uplink_switch(uplinks.clone(), active_index, strict_global))
        } else {
            Box::pin(std::future::pending::<&'static str>())
        };

        let result = drive_tcp_session_tasks(
            uplink,
            downlink,
            Some(IdleGuard::new(activity_rx, timeouts.socks_upstream_idle)),
            cancel,
            Arc::clone(&target_label),
            timeouts.post_client_eof_downstream,
        )
        .await;

        // After `drive_tcp_session_tasks` returns, both spawned tasks
        // have either completed or been aborted; their captured locals
        // (writer, reader) are dropped. To restart the relay we need
        // a fresh transport from `redial_for_mid_session_retry`.
        match result {
            Ok(DriveExit::Normal) => {
                final_result = Ok(());
                break;
            },
            Ok(DriveExit::AbortedOnSwitch(reason)) => {
                // Strict mode forcibly tore us down because the active
                // uplink moved off this session. Skip mid-session retry
                // (the whole point is to free the client to reconnect
                // through the new active uplink) and signal the post-
                // loop tail to force-close the client socket with RST.
                force_rst_reason = Some(reason);
                final_result = Err(anyhow!(
                    "SOCKS TCP session aborted: active uplink switched away from {active_name} ({reason})"
                ));
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

                // Snapshot the v2 offset BEFORE the redial — this
                // is the count of downstream bytes the SOCKS5 client
                // has observed across the whole session lifetime; the
                // server uses it to compute `replay_from(offset)` on
                // its parked downlink ring.
                let client_acked_now =
                    client_acked_offset.load(std::sync::atomic::Ordering::Relaxed);
                let (connected, downlink_replay) = match try_mid_session_retry(
                    &uplinks,
                    &active_name,
                    &candidate,
                    &target,
                    ring.as_deref(),
                    consume_timeout,
                    symmetric_replay_enabled,
                    symmetric_replay_max_bytes,
                    client_acked_now,
                    overflow_policy,
                )
                .await
                {
                    Ok(result) => result,
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
                    v2_replay_bytes = downlink_replay.as_ref().map(Vec::len),
                    "mid-session retry succeeded; resuming relay on fresh transport"
                );
                let ConnectedTcpUplink {
                    writer: new_writer,
                    reader: new_reader,
                    wire_index: new_wire_index,
                    ..
                } = connected;
                writer = new_writer;
                reader = new_reader;
                current_wire_index = new_wire_index;
                // v2 replay payload (when the server emitted one)
                // becomes the next iteration's `first_chunk_for_iter`
                // so the downlink task flushes it to the SOCKS5
                // client BEFORE pulling fresh upstream bytes — this
                // is what closes the downstream byte-loss gap.
                first_chunk_for_iter = downlink_replay;
                continue;
            },
        }
    }

    // Strict `active_passive` torn the session down because the active
    // uplink moved off this session — record the abort and force-close
    // the client socket with TCP RST so the client application observes
    // a hard reset and immediately reconnects through the new active
    // uplink. The transport itself was healthy, so do NOT report a
    // runtime failure that would penalise the uplink's probe state.
    if let Some(reason) = force_rst_reason {
        metrics::record_socks_tcp_strict_abort(uplinks.group_name(), &active_name, reason);
        debug!(
            uplink = %active_name,
            reason,
            "aborting SOCKS5 TCP session with RST due to active uplink switch"
        );
        force_client_rst(client_read, client_write);
        return final_result;
    }

    // Mirror the original tail behaviour: surface mid-stream upstream
    // transport failures so broken transports (e.g. H3 APPLICATION_CLOSE
    // received after session establishment) trigger the H3→H2 downgrade
    // and flush stale warm-standby connections immediately.
    if let Err(ref err) = final_result {
        if crate::error_class::is_upstream_runtime_failure(err) {
            uplinks
                .report_runtime_failure_for_wire(
                    active_index,
                    TransportKind::Tcp,
                    current_wire_index,
                    err,
                )
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

/// Watches the manager's active-uplink pointer and resolves with the abort
/// reason once it moves off `pinned_index`. Used as the `cancel` arm of
/// [`drive_tcp_session_tasks`] in strict `active_passive` mode.
///
/// The future never resolves while the active stays at `pinned_index`; if
/// the manager is dropped the future also stops resolving so the data
/// tasks remain the sole authoritative termination signal.
async fn watch_active_uplink_switch(
    uplinks: UplinkManager,
    pinned_index: usize,
    strict_global: bool,
) -> &'static str {
    let mut rx = uplinks.subscribe_active_uplinks();
    loop {
        let snapshot = *rx.borrow_and_update();
        let active = if strict_global { snapshot.global } else { snapshot.tcp };
        if let Some(idx) = active {
            if idx != pinned_index {
                return "global_switch";
            }
        }
        if rx.changed().await.is_err() {
            // Manager dropped (shutdown / config reload). The data tasks
            // will observe their own errors shortly; don't pre-empt them
            // with a strict-abort label that would skew the metric.
            std::future::pending::<()>().await;
            unreachable!();
        }
    }
}

/// Reunite the client TCP halves and close the socket with TCP RST by
/// setting `SO_LINGER {l_onoff=1, l_linger=0}` and dropping the stream.
/// Skips the RST silently if the halves can't be reclaimed (a data task
/// is somehow still holding an `Arc` clone) — falling back to FIN on the
/// implicit drop is acceptable, the strict-abort metric is still
/// recorded by the caller.
fn force_client_rst(
    client_read: Arc<Mutex<OwnedReadHalf>>,
    client_write: Arc<Mutex<OwnedWriteHalf>>,
) {
    let read_half = match Arc::try_unwrap(client_read) {
        Ok(mutex) => mutex.into_inner(),
        Err(_) => return,
    };
    let write_half = match Arc::try_unwrap(client_write) {
        Ok(mutex) => mutex.into_inner(),
        Err(_) => return,
    };
    let Ok(stream) = read_half.reunite(write_half) else {
        return;
    };
    // Use `socket2::SockRef` to set `SO_LINGER` instead of
    // `TcpStream::set_linger` — the tokio wrapper is deprecated because its
    // contract warns of potential blocking on drop, but with `Duration::ZERO`
    // the kernel emits a RST immediately and never waits for FIN ACK, so
    // dropping is non-blocking. Going through `socket2` documents this
    // intent and avoids the deprecation lint.
    let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));
    drop(stream);
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
    consume_timeout: Duration,
    symmetric_replay_enabled: bool,
    symmetric_replay_max_bytes: usize,
    client_acked_offset: u64,
    overflow_policy: OverflowPolicy,
) -> Result<(ConnectedTcpUplink, Option<Vec<u8>>)> {
    let group_name = uplinks.group_name();

    // In strict `active_passive` mode the active pointer may have moved off
    // our pinned uplink between the original transport error and this retry.
    // Re-dialling the now-deactivated uplink would succeed (the upstream is
    // unaffected by our manager's decision) but the relay's next iteration
    // would be aborted immediately by the strict-abort watcher. Skip the
    // wasted dial and let the caller propagate the original transport
    // error — the watcher path will then close the client socket with RST.
    if uplinks.strict_global_active_uplink() || uplinks.strict_per_uplink_active_uplink() {
        let strict_global = uplinks.strict_global_active_uplink();
        let snapshot = uplinks.active_uplinks_snapshot();
        let active = if strict_global { snapshot.global } else { snapshot.tcp };
        if active != Some(candidate.index) {
            metrics::record_mid_session_retry("tcp", group_name, active_name, "failed_redial");
            return Err(anyhow!(
                "mid-session retry skipped: active uplink moved off pinned uplink {active_name} \
                 (active = {active:?}, pinned = {})",
                candidate.index,
            ));
        }
    }

    // Dial whichever wire the manager currently considers active. When a
    // session originally established on a fallback wire (because primary
    // was unhealthy at the time), retrying against the primary URL would
    // almost always fail and the resulting redial error would surface as
    // a runtime failure on the parent uplink — exactly the false flap the
    // active-wire state machine exists to prevent.
    let wire_index = uplinks.active_wire(candidate.index, TransportKind::Tcp);
    let mut connected = match redial_for_mid_session_retry(
        uplinks,
        candidate,
        target,
        wire_index,
        symmetric_replay_enabled,
        client_acked_offset,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            metrics::record_mid_session_retry("tcp", group_name, active_name, "failed_redial");
            return Err(e.context("mid-session redial failed"));
        },
    };

    // v1.1 fast path: drive `consume_ack_prefix_with_timeout` BEFORE
    // the relay loop resumes so the orchestrator knows the exact
    // server-acked offset and the replay can be a precise tail
    // (`replay_from(offset)`) instead of the full buffered backlog.
    // Falls back to "replay everything" only when the negotiation
    // collapsed to "off" (server did not echo the capability) — in
    // that case we have no offset to gate the replay against and the
    // server's idempotent receive path is what guarantees byte-exact
    // semantics.
    //
    // `consume_timeout` is sourced from the group's
    // `tcp_mid_session_retry_consume_timeout_secs` knob (default 5s).
    // It bounds how long we wait for a server that negotiated the
    // capability but failed to actually emit the frame; on timeout
    // the new transport is dropped and the original transport error
    // is surfaced to the caller as a `failed_redial` outcome — the
    // redial itself succeeded but the protocol contract did not.
    let server_acked_offset = match connected
        .reader
        .consume_ack_prefix_with_timeout(consume_timeout)
        .await
    {
        Ok(maybe_offset) => maybe_offset,
        Err(e) => {
            metrics::record_mid_session_retry("tcp", group_name, active_name, "failed_redial");
            return Err(e.context(
                "mid-session retry: server negotiated Ack-Prefix but did not emit a valid \
                 control frame within the timeout",
            ));
        },
    };

    let replay_bytes = match ring {
        Some(r) => {
            let r_guard = r.lock().await;
            // Prefer the precise offset reported by the server; fall
            // back to `oldest_offset()` only when the server did not
            // echo the capability (legacy server, capability disabled
            // for this session, etc.). The fallback path matches the
            // v1 behaviour: replay the full buffered tail and let
            // the server deduplicate.
            let replay_from_offset = match server_acked_offset {
                Some(offset) => offset,
                None => r_guard.oldest_offset(),
            };
            match r_guard.replay_from(replay_from_offset) {
                Ok(bytes) => bytes,
                Err(ReplayError::OffsetEvicted { .. } | ReplayError::OffsetAhead { .. }) => {
                    metrics::record_mid_session_retry(
                        "tcp",
                        group_name,
                        active_name,
                        "failed_replay",
                    );
                    return Err(anyhow!(
                        "mid-session retry: ring buffer cannot satisfy replay from offset \
                         {replay_from_offset} (server-reported: {server_acked_offset:?})"
                    ));
                },
            }
        },
        None => {
            // retry_eligible was false; should not be reached because the
            // outer caller gates on the same condition. Bail defensively.
            return Err(anyhow!("mid-session retry attempted without an active ring buffer"));
        },
    };

    if !replay_bytes.is_empty() {
        if let Err(e) = send_replay_through_writer(&mut connected.writer, &replay_bytes).await {
            metrics::record_mid_session_retry("tcp", group_name, active_name, "failed_replay");
            return Err(e.context("mid-session retry: replay send failed"));
        }
    }

    // v2 Symmetric Downlink Replay: when the server echoed v2 on the
    // resume hit, drive the v2 frame consume here AFTER the v1
    // consume has parked the up_acked offset. Returns the replay
    // payload (or `None` when v2 was not negotiated / collapsed to
    // off / overflow_policy = soft on truncation).
    let downlink_replay_payload = match connected
        .reader
        .consume_downlink_replay_with_timeout(consume_timeout, symmetric_replay_max_bytes)
        .await
    {
        Ok(None) => None,
        Ok(Some(outline_transport::downlink_replay::DownlinkReplayOutcome::Replay(payload))) => {
            metrics::add_bytes("tcp", "downlink_replay", group_name, active_name, payload.len());
            if payload.is_empty() { None } else { Some(payload) }
        },
        Ok(Some(outline_transport::downlink_replay::DownlinkReplayOutcome::Truncated)) => {
            metrics::record_mid_session_retry("tcp", group_name, active_name, "downlink_truncated");
            match overflow_policy {
                OverflowPolicy::Hard => {
                    return Err(anyhow!(
                        "mid-session retry: server signalled REPLAY_TRUNCATED on v2 \
                         downlink replay; tcp_mid_session_retry_overflow_policy = \"hard\" \
                         drops the session"
                    ));
                },
                OverflowPolicy::Soft => {
                    warn!(
                        uplink = %active_name,
                        client_acked_offset,
                        "v2 downlink replay truncated by server ring; downstream stream has \
                         an irrecoverable gap, continuing under overflow_policy = soft"
                    );
                    None
                },
            }
        },
        Err(e) => {
            metrics::record_mid_session_retry("tcp", group_name, active_name, "failed_redial");
            return Err(e.context(
                "mid-session retry: server negotiated v2 Symmetric Downlink Replay but did \
                 not emit a valid frame within the timeout",
            ));
        },
    };
    let _ = symmetric_replay_enabled; // currently informational; gated on echo

    Ok((connected, downlink_replay_payload))
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
