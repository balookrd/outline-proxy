use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use shadowsocks_crypto::SHADOWSOCKS_MAX_PAYLOAD;
use crate::metrics;
use socks5_proto::{SOCKS_STATUS_NOT_ALLOWED, SOCKS_STATUS_SUCCESS, send_reply};

use super::super::DispatchTarget;
use crate::types::{TargetAddr, socket_addr_to_target};
use outline_uplink::TransportKind;
use super::failover::{
    ActiveTcpUplink, MAX_CHUNK0_FAILOVER_BUF, UPSTREAM_RESPONSE_TIMEOUT,
    connect_tcp_uplink, connect_tcp_uplink_fresh,
};
use super::session::{
    IdleWatcher, UplinkTaskResult, SOCKS_UPSTREAM_IDLE_TIMEOUT,
    POST_CLIENT_EOF_DOWNSTREAM_TIMEOUT, drive_tcp_session_tasks,
};

// Direct TCP sessions (bypass-routed) are held open as long as both sides
// keep the connection alive.  Applications such as DNS-over-HTTPS/TLS clients
// open a new TCP+TLS connection per query burst and then abandon the old one
// without sending FIN — the HTTP/2 server keeps its side open.  Without a
// bound these accumulate indefinitely.
//
// DIRECT_IDLE_TIMEOUT closes a direct session once BOTH directions have been
// silent for this long.  Activity in either direction resets the timer.
// 2 minutes is generous for DoH/DoT (a silent connection is always abandoned)
// while still being safe for periodic-push traffic (Telegram, FCM, etc. send
// heartbeats every 30–60 s so their connections will never hit this timeout).
const DIRECT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

pub async fn handle_tcp_connect(
    mut client: TcpStream,
    dispatch: DispatchTarget,
    target: TargetAddr,
    dns_cache: Arc<outline_transport::DnsCache>,
) -> Result<()> {
    let uplinks = match dispatch {
        DispatchTarget::Direct { fwmark } => {
            info!(target = %target, "TCP route: direct connection");
            return handle_tcp_direct(client, target, fwmark, &dns_cache).await;
        }
        DispatchTarget::Drop => {
            info!(target = %target, "TCP route: policy drop");
            return handle_tcp_drop(client, &target).await;
        }
        DispatchTarget::Group { name, manager } => {
            debug!(target = %target, group = %name, "TCP route: dispatching via group");
            manager
        }
    };
    let session = metrics::track_session("tcp");
    let result = async {
        let mut last_error = None;
        let mut selected = None;
        let strict_transport = uplinks.strict_active_uplink_for(TransportKind::Tcp);
        let chunk0_attempt_timeout = uplinks.load_balancing().tcp_chunk0_failover_timeout;
        let mut tried_indexes = std::collections::HashSet::new();
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
        let mut replay_buf: Vec<Vec<u8>> = Vec::with_capacity(8);
        let mut replay_overflow = false;
        let mut client_half_closed = false;
        let mut deferred_phase1_failures: Vec<(usize, String, String)> = Vec::new();
        // Single scratch buffer reused across every phase-1 failover attempt.
        // Hoisted out of the loop so a chunk-0 failover does not re-allocate
        // 64 KiB per retry.
        let mut rbuf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];

        let first_upstream_chunk: Vec<u8> = 'phase1: loop {
            let can_failover = strict_transport
                && !replay_overflow
                && tried_indexes.len() < uplinks.uplinks().len();
            let attempt_timeout = if can_failover {
                chunk0_attempt_timeout
            } else {
                UPSTREAM_RESPONSE_TIMEOUT
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
                                let chunk = rbuf[..n].to_vec();
                                active.writer
                                    .send_chunk(&chunk)
                                    .await
                                    .context("uplink write failed")?;
                                // Treat the timeout as "no response after the last
                                // request activity", not "no response since the
                                // beginning of phase 1". Some protocols do not send
                                // any server bytes until the client has finished
                                // sending the request preface or body.
                                deadline = tokio::time::Instant::now() + attempt_timeout;
                                metrics::add_bytes(
                                    "tcp",
                                    "client_to_upstream",
                                    uplinks.group_name(),
                                    &active.name,
                                    n,
                                );
                                // Do not treat client->upstream bytes during phase 1
                                // as proof that the uplink is healthy yet. A broken
                                // uplink can still accept writes and then reset or stall
                                // before producing the first response byte. Marking it
                                // active here would clear the runtime-failure cooldown and
                                // refresh last_active_tcp on every retry, preventing probe-
                                // driven failover for new connections.
                                if !replay_overflow {
                                    let total: usize = replay_buf.iter().map(|c| c.len()).sum();
                                    if total + n <= MAX_CHUNK0_FAILOVER_BUF {
                                        replay_buf.push(chunk);
                                    } else {
                                        replay_overflow = true;
                                    }
                                }
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
                    return Ok(());
                }
                Ok(chunk) => {
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
                    break 'phase1 chunk;
                }
                Err(ref e) if active.reader.closed_cleanly() => {
                    debug!(
                        uplink = %active.name,
                        error = %format!("{e:#}"),
                        "upstream closed before sending any data (phase 1)"
                    );
                    client_write.shutdown().await.context("client shutdown failed")?;
                    return Ok(());
                }
                Err(e) => {
                    let mut phase1_error = e;
                    if active.source == super::failover::TcpUplinkSource::Standby {
                        debug!(
                            uplink = %active.name,
                            error = %format!("{phase1_error:#}"),
                            "TCP phase-1 failure on warm-standby socket; retrying same uplink with a fresh dial"
                        );
                        match connect_tcp_uplink_fresh(&uplinks, &active.candidate, &target).await {
                            Ok(reconnected) => {
                                active.replace_transport(reconnected);
                                for chunk in &replay_buf {
                                    active.writer
                                        .send_chunk(chunk)
                                        .await
                                        .context("replay to fresh uplink after standby failure failed")?;
                                }
                                if client_half_closed {
                                    active.writer
                                        .close()
                                        .await
                                        .context("fresh uplink half-close after standby failure failed")?;
                                }
                                continue 'phase1;
                            }
                            Err(connect_err) => {
                                phase1_error = connect_err
                                    .context("fresh dial retry after warm-standby phase-1 failure failed");
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
                        error = %error_text,
                        "TCP chunk-0 failure"
                    );

                    if !can_failover {
                        if deferred_phase1_failures.is_empty() {
                            uplinks
                                .report_runtime_failure(
                                    active.index,
                                    TransportKind::Tcp,
                                    &phase1_error,
                                )
                                .await;
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

                    deferred_phase1_failures.push((
                        active.index,
                        active.name.to_string(),
                        error_text,
                    ));

                    let candidates = uplinks
                        .tcp_failover_candidates(&target, active.index)
                        .await;
                    let next = candidates
                        .into_iter()
                        .find(|c| !tried_indexes.contains(&c.index));
                    let Some(next_candidate) = next else {
                        return Err(
                            phase1_error.context("no alternative uplink available for chunk-0 failover")
                        );
                    };
                    tried_indexes.insert(next_candidate.index);

                    let reconnected =
                        match connect_tcp_uplink(&uplinks, &next_candidate, &target).await {
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
                            Some(&target),
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

                    for chunk in &replay_buf {
                        active.writer
                            .send_chunk(chunk)
                            .await
                            .context("replay to failover uplink failed")?;
                    }
                    if client_half_closed {
                        active.writer
                            .close()
                            .await
                            .context("failover uplink half-close failed")?;
                    }
                }
            }
        };

        // Once phase 1 completed and we received the first upstream bytes, this
        // SOCKS TCP session is pinned to the uplink that completed setup.
        // Strict active-uplink reselection only affects new sessions and
        // chunk-0 failover; established TCP tunnels are not migrated
        // transparently and should only end on a real transport error.

        // Phase-1 replay buffer is no longer needed; release memory before the
        // long-lived phase-2 tasks take over.
        drop(replay_buf);

        // Extract from active what the session tasks need; drop the candidate
        // and source fields which are no longer relevant after phase 1.
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
                // a sleep timer. If the timer fires first we send a Shadowsocks
                // keepalive frame (no-op for SS1, 0-length encrypted chunk for
                // SS2022) and loop immediately with a fresh timer.  This defeats
                // upstream proxy / NAT idle-timeout disconnections that otherwise
                // kill long-lived sessions (SSH, etc.) after ~25–30 s of silence.
                let read = if let Some(d) = keepalive_interval {
                    tokio::select! {
                        result = client_read.read(&mut buf) => result.context("client read failed")?,
                        _ = tokio::time::sleep(d) => {
                            writer
                                .send_keepalive()
                                .await
                                .context("upstream TCP keepalive failed")?;
                            continue;
                        }
                    }
                } else {
                    client_read.read(&mut buf).await.context("client read failed")?
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
                    &*name_for_uplink_task,
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
            Ok::<UplinkTaskResult, anyhow::Error>(UplinkTaskResult::Finished)
        };

        let name_for_downlink_task = Arc::clone(&active_name);
        let manager_for_downlink_task = uplinks.clone();
        let downlink = async move {
            metrics::add_bytes(
                "tcp",
                "upstream_to_client",
                manager_for_downlink_task.group_name(),
                &*name_for_downlink_task,
                first_upstream_chunk.len(),
            );
            client_write
                .write_all(&first_upstream_chunk)
                .await
                .context("client write failed")?;
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
                    &*name_for_downlink_task,
                    chunk.len(),
                );
                client_write
                    .write_all(&chunk)
                    .await
                    .context("client write failed")?;
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
            Some(IdleWatcher::new(activity_rx, SOCKS_UPSTREAM_IDLE_TIMEOUT)),
        )
        .await;
        // Report mid-stream upstream transport failures so that broken transports
        // (e.g. H3 APPLICATION_CLOSE received after session establishment) trigger
        // the H3→H2 downgrade and flush stale warm-standby connections immediately,
        // rather than waiting for the next connection attempt to fail.
        // Client-side disconnects and intentional uplink switches are excluded.
        if let Err(ref err) = result {
            if crate::error_text::is_upstream_runtime_failure(err) {
                uplinks
                    .report_runtime_failure(active_index, TransportKind::Tcp, err)
                    .await;
            } else if crate::error_text::is_websocket_closed(err) {
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

async fn handle_tcp_direct(
    mut client: TcpStream,
    target: TargetAddr,
    fwmark: Option<u32>,
    cache: &outline_transport::DnsCache,
) -> Result<()> {
    let addr = match &target {
        TargetAddr::IpV4(ip, port) => SocketAddr::new(std::net::IpAddr::V4(*ip), *port),
        TargetAddr::IpV6(ip, port) => SocketAddr::new(std::net::IpAddr::V6(*ip), *port),
        TargetAddr::Domain(host, port) => outline_transport::resolve_host_with_preference(
            cache,
            host,
            *port,
            &format!("failed to resolve {target}"),
            false,
        )
        .await?
        .first()
        .copied()
        .ok_or_else(|| anyhow!("no address resolved for {target}"))?,
    };

    let upstream = outline_transport::connect_tcp_socket(addr, fwmark)
        .await
        .with_context(|| format!("direct TCP connect to {target} failed"))?;

    let bound_addr = socket_addr_to_target(client.local_addr()?);
    send_reply(&mut client, SOCKS_STATUS_SUCCESS, &bound_addr).await?;

    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    // Activity channel: c2u and u2c signal after every successful read.
    // The idle watcher resets its timer on each token; if the channel is silent
    // for DIRECT_IDLE_TIMEOUT it fires, closing the session.
    //
    // Capacity-1 bounded channel: we only care about "any activity", not how
    // many bytes moved, so a single queued token is enough.  try_send discards
    // the signal when a token is already pending — cheaper than an unbounded
    // channel that accumulates one node per read under high throughput.
    // The watcher exits when both sender halves drop (channel closes → recv → None).
    let (activity_tx, mut activity_rx) = tokio::sync::mpsc::channel::<()>(1);
    let activity_c2u = activity_tx.clone();
    let activity_u2c = activity_tx;

    let c2u = async move {
        let mut buf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];
        loop {
            let read = client_read.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            let _ = activity_c2u.try_send(());
            metrics::add_bytes(
                "tcp",
                "client_to_upstream",
                metrics::DIRECT_GROUP_LABEL,
                metrics::DIRECT_UPLINK_LABEL,
                read,
            );
            upstream_write.write_all(&buf[..read]).await?;
        }
        upstream_write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    let u2c = async move {
        let mut buf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];
        loop {
            let read = upstream_read.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            let _ = activity_u2c.try_send(());
            metrics::add_bytes(
                "tcp",
                "upstream_to_client",
                metrics::DIRECT_GROUP_LABEL,
                metrics::DIRECT_UPLINK_LABEL,
                read,
            );
            client_write.write_all(&buf[..read]).await?;
        }
        client_write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };

    // Idle watcher: loops receiving activity tokens.  Each received token
    // resets the DIRECT_IDLE_TIMEOUT deadline.  If the deadline expires before
    // the next token (no data in either direction), the future returns,
    // signalling that the session should be forcibly closed.  When the channel
    // is closed (both tasks finished normally), recv() returns None and the
    // watcher exits without triggering the idle path.
    let idle_watcher = async move {
        loop {
            match timeout(DIRECT_IDLE_TIMEOUT, activity_rx.recv()).await {
                Ok(Some(())) => continue,
                Ok(None) => return false, // channel closed — tasks completed normally
                Err(_elapsed) => return true, // idle timeout
            }
        }
    };

    // Drive both halves concurrently.
    //
    // When EITHER side errors, abort the other immediately.
    //
    // When the server closes first (u2c Ok), abort c2u — there is nothing
    // more to forward and waiting for the client to also close is not
    // necessary.
    //
    // When the CLIENT closes first (c2u Ok), give the server a bounded window
    // to flush remaining data and send its own FIN.  Without the timeout a
    // server that keeps the connection half-open indefinitely — e.g. a VPN or
    // signalling server — holds two socket FDs (inbound SOCKS + outbound
    // direct) open forever.
    //
    // If neither side closes and no data flows for DIRECT_IDLE_TIMEOUT, the
    // idle watcher fires and we forcibly close both sides.
    let mut c2u_task = tokio::spawn(c2u);
    let mut u2c_task = tokio::spawn(u2c);
    let mut idle_task = tokio::spawn(idle_watcher);

    tokio::select! {
        c2u_done = &mut c2u_task => {
            idle_task.abort();
            let _ = idle_task.await;
            match c2u_done {
                Ok(Ok(())) => {
                    match timeout(POST_CLIENT_EOF_DOWNSTREAM_TIMEOUT, &mut u2c_task).await {
                        Ok(Ok(result)) => result,
                        Ok(Err(e)) => Err(anyhow!("direct TCP u2c task failed: {e}")),
                        Err(_elapsed) => {
                            info!(
                                %target,
                                timeout_secs = POST_CLIENT_EOF_DOWNSTREAM_TIMEOUT.as_secs(),
                                "direct TCP upstream did not close within timeout after client EOF"
                            );
                            u2c_task.abort();
                            let _ = u2c_task.await;
                            Ok(())
                        }
                    }
                }
                Ok(Err(e)) => { u2c_task.abort(); let _ = u2c_task.await; Err(e) }
                Err(e) => { u2c_task.abort(); let _ = u2c_task.await; Err(anyhow!("direct TCP c2u task panicked: {e}")) }
            }
        }
        u2c_done = &mut u2c_task => {
            idle_task.abort();
            let _ = idle_task.await;
            c2u_task.abort();
            let _ = c2u_task.await;
            match u2c_done {
                Ok(result) => result,
                Err(e) => Err(anyhow!("direct TCP u2c task panicked: {e}")),
            }
        }
        idle_done = &mut idle_task => {
            match idle_done {
                Ok(true) => {
                    // Idle timeout — no data in either direction for DIRECT_IDLE_TIMEOUT.
                    info!(
                        %target,
                        timeout_secs = DIRECT_IDLE_TIMEOUT.as_secs(),
                        "direct TCP session idle timeout — closing"
                    );
                    c2u_task.abort();
                    u2c_task.abort();
                    let _ = c2u_task.await;
                    let _ = u2c_task.await;
                    Ok(())
                }
                Ok(false) => {
                    // The idle channel closed — both data tasks already finished.
                    // abort() is a no-op on a completed task; await to collect
                    // their results and propagate any error instead of swallowing it.
                    c2u_task.abort();
                    u2c_task.abort();
                    let c2u_res = c2u_task.await;
                    let u2c_res = u2c_task.await;
                    match (c2u_res, u2c_res) {
                        (Ok(Err(e)), _) => Err(e),
                        (_, Ok(Err(e))) => Err(e),
                        (Err(e), _) if !e.is_cancelled() => {
                            Err(anyhow!("direct TCP c2u task panicked: {e}"))
                        }
                        (_, Err(e)) if !e.is_cancelled() => {
                            Err(anyhow!("direct TCP u2c task panicked: {e}"))
                        }
                        _ => Ok(()),
                    }
                }
                Err(e) => {
                    c2u_task.abort();
                    u2c_task.abort();
                    let _ = c2u_task.await;
                    let _ = u2c_task.await;
                    Err(anyhow!("direct TCP idle watcher panicked: {e}"))
                }
            }
        }
    }
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

        let target = crate::types::TargetAddr::IpV4("1.2.3.4".parse().unwrap(), 80);
        handle_tcp_drop(server_side, &target).await.unwrap();

        // SOCKS5 reply: VER REP RSV ATYP(IPv4) ADDR(4) PORT(2) = 10 bytes
        let mut reply = [0u8; 10];
        client_side.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 5, "VER must be 5");
        assert_eq!(reply[1], SOCKS_STATUS_NOT_ALLOWED, "REP must be 0x02 (not allowed)");
        assert_eq!(reply[2], 0, "RSV must be 0");
        assert_eq!(reply[3], 1, "ATYP must be 1 (IPv4)");
    }

    /// `handle_tcp_direct` must close the session with `Ok(())` once both
    /// directions have been silent for `DIRECT_IDLE_TIMEOUT`.
    ///
    /// Requires the `test-util` tokio feature (added to dev-dependencies).
    /// Time is paused so the 120-second timeout fires without real waiting.
    #[tokio::test(start_paused = true)]
    async fn handle_tcp_direct_closes_session_after_idle_timeout() {
        use std::net::Ipv4Addr;

        // Upstream: accepts but sends nothing (simulates idle server).
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let upstream_task = tokio::spawn(async move {
            let (_stream, _) = upstream_listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });

        // Plumb a loopback pair to act as the SOCKS5 client connection.
        let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_listener_addr = client_listener.local_addr().unwrap();
        let (connect_res, accept_res) = tokio::join!(
            tokio::net::TcpStream::connect(client_listener_addr),
            client_listener.accept()
        );
        let mut client_side = connect_res.unwrap();
        let (server_side, _) = accept_res.unwrap();

        let target = crate::types::TargetAddr::IpV4(Ipv4Addr::LOCALHOST, upstream_port);
        let dns_cache = std::sync::Arc::new(outline_transport::DnsCache::default());
        let direct_task = tokio::spawn(async move {
            handle_tcp_direct(server_side, target, None, &dns_cache).await
        });

        // Drain the 10-byte SOCKS5 SUCCESS reply so the client buffer stays clear.
        let mut socks_reply = [0u8; 10];
        client_side.read_exact(&mut socks_reply).await.unwrap();
        assert_eq!(socks_reply[1], SOCKS_STATUS_SUCCESS, "expected SUCCESS reply");

        // Advance mock time past the idle timeout and yield to let tasks run.
        tokio::time::advance(DIRECT_IDLE_TIMEOUT + Duration::from_secs(1)).await;
        // Multiple yields let the spawned select! arms process the fired timer.
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }

        assert!(
            direct_task.is_finished(),
            "handle_tcp_direct should return after idle timeout"
        );
        let result = direct_task.await.unwrap();
        assert!(result.is_ok(), "handle_tcp_direct must return Ok(()) on idle timeout");

        upstream_task.abort();
        let _ = upstream_task.await;
    }
}
