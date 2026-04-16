use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::crypto::SHADOWSOCKS_MAX_PAYLOAD;
use crate::metrics;
use crate::socks5::{SOCKS_STATUS_NOT_ALLOWED, SOCKS_STATUS_SUCCESS, send_reply};

use super::Dispatch;
use crate::transport::{
    TcpShadowsocksReader, TcpShadowsocksWriter, UpstreamTransportGuard,
    connect_shadowsocks_tcp_with_source,
};
use crate::types::{TargetAddr, UplinkTransport, socket_addr_to_target};
use crate::uplink::{TransportKind, UplinkManager};

const UPSTREAM_RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CHUNK0_FAILOVER_BUF: usize = 32 * 1024;

enum UplinkTaskResult {
    Finished,
    /// Kept in the signature of the drive loop for future use (protocols where
    /// tearing down the upstream side eagerly on client EOF is actually
    /// correct).  Not currently emitted from the SOCKS CONNECT path — see the
    /// comment on client EOF in the uplink task for why we now wait for the
    /// downlink to finish naturally instead.
    #[allow(dead_code)]
    CloseSession,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TcpUplinkSource {
    Standby,
    FreshDial,
    DirectSocket,
}

struct ConnectedTcpUplink {
    writer: TcpShadowsocksWriter,
    reader: TcpShadowsocksReader,
    source: TcpUplinkSource,
}

fn attempted_chunk0_uplink_names(
    deferred_phase1_failures: &[(usize, String, String)],
    active_uplink_name: &str,
) -> Vec<String> {
    let mut attempted = Vec::with_capacity(deferred_phase1_failures.len() + 1);
    for (_, uplink_name, _) in deferred_phase1_failures {
        if attempted.iter().all(|existing| existing != uplink_name) {
            attempted.push(uplink_name.clone());
        }
    }
    if attempted.iter().all(|existing| existing != active_uplink_name) {
        attempted.push(active_uplink_name.to_string());
    }
    attempted
}

async fn drive_tcp_session_tasks<U, D>(uplink: U, downlink: D) -> Result<()>
where
    U: Future<Output = Result<UplinkTaskResult>> + Send + 'static,
    D: Future<Output = Result<()>> + Send + 'static,
{
    let started = tokio::time::Instant::now();
    let mut uplink_task = tokio::spawn(uplink);
    let mut downlink_task = tokio::spawn(downlink);

    tokio::select! {
        joined = &mut downlink_task => {
            let downlink_result = match joined {
                Ok(result) => result,
                Err(error) => Err(anyhow!("SOCKS TCP downlink task failed: {error}")),
            };
            let elapsed_ms = started.elapsed().as_millis();
            match &downlink_result {
                Ok(()) => debug!(
                    target: "outline_ws_rust::session_death",
                    elapsed_ms,
                    winner = "downlink",
                    "downlink finished first, cleanly (server sent Close / upstream EOF)"
                ),
                Err(e) => debug!(
                    target: "outline_ws_rust::session_death",
                    elapsed_ms,
                    winner = "downlink",
                    error = %format!("{e:#}"),
                    "downlink finished first with error"
                ),
            }
            uplink_task.abort();
            let _ = uplink_task.await;
            downlink_result
        }
        joined = &mut uplink_task => {
            let elapsed_ms = started.elapsed().as_millis();
            match joined {
                Ok(Ok(UplinkTaskResult::Finished)) => {
                    debug!(
                        target: "outline_ws_rust::session_death",
                        elapsed_ms,
                        winner = "uplink",
                        outcome = "Finished",
                        "uplink finished first (client EOF over socket transport), awaiting downlink"
                    );
                    match downlink_task.await {
                        Ok(result) => result,
                        Err(error) => Err(anyhow!("SOCKS TCP downlink task failed: {error}")),
                    }
                }
                Ok(Ok(UplinkTaskResult::CloseSession)) => {
                    debug!(
                        target: "outline_ws_rust::session_death",
                        elapsed_ms,
                        winner = "uplink",
                        outcome = "CloseSession",
                        "uplink requested session close (client EOF over websocket-backed transport)"
                    );
                    downlink_task.abort();
                    let _ = downlink_task.await;
                    Ok(())
                }
                Ok(Err(error)) => {
                    debug!(
                        target: "outline_ws_rust::session_death",
                        elapsed_ms,
                        winner = "uplink",
                        outcome = "Error",
                        error = %format!("{error:#}"),
                        "uplink finished first with error"
                    );
                    downlink_task.abort();
                    let _ = downlink_task.await;
                    Err(error)
                }
                Err(error) => {
                    downlink_task.abort();
                    let _ = downlink_task.await;
                    Err(anyhow!("SOCKS TCP uplink task failed: {error}"))
                }
            }
        }
    }
}

pub(super) async fn handle_tcp_connect(
    mut client: TcpStream,
    dispatch: Dispatch,
    target: TargetAddr,
) -> Result<()> {
    let uplinks = match dispatch {
        Dispatch::Direct { fwmark } => {
            info!(target = %target, "TCP route: direct connection");
            return handle_tcp_direct(client, target, fwmark).await;
        },
        Dispatch::Drop => {
            info!(target = %target, "TCP route: policy drop");
            return handle_tcp_drop(client, &target).await;
        },
        Dispatch::Group { name, manager } => {
            debug!(target = %target, group = %name, "TCP route: dispatching via group");
            manager
        },
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
        let mut active_candidate = candidate.clone();
        let selected_uplink_name = candidate.uplink.name.clone();
        uplinks
            .confirm_selected_uplink(TransportKind::Tcp, Some(&target), candidate.index)
            .await;
        metrics::record_uplink_selected("tcp", uplinks.group_name(), &selected_uplink_name);
        info!(
            uplink = %selected_uplink_name,
            weight = candidate.uplink.weight,
            target = %target,
            "selected TCP uplink"
        );
        let selected_index = candidate.index;
        let mut writer = connected.writer;
        let mut reader = connected.reader;
        let mut active_source = connected.source;

        let bound_addr = socket_addr_to_target(client.local_addr()?);
        send_reply(&mut client, SOCKS_STATUS_SUCCESS, &bound_addr).await?;

        let (mut client_read, mut client_write) = client.into_split();
        let mut replay_buf: Vec<Vec<u8>> = Vec::new();
        let mut replay_overflow = false;
        let mut active_index = selected_index;
        let mut active_uplink_name = selected_uplink_name.clone();
        let mut client_half_closed = false;
        let mut deferred_phase1_failures: Vec<(usize, String, String)> = Vec::new();

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
            let mut rbuf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];

            let attempt: Result<Vec<u8>> = loop {
                if client_half_closed {
                    break tokio::time::timeout_at(deadline, reader.read_chunk())
                        .await
                        .map_err(|_| {
                            anyhow!(
                                "upstream did not respond within {}s (chunk 0)",
                                attempt_timeout.as_secs(),
                            )
                        })?;
                }

                tokio::select! {
                    result = reader.read_chunk() => {
                        break result;
                    }
                    n_res = client_read.read(&mut rbuf) => {
                        match n_res {
                            Ok(0) => {
                                writer.close().await.context("uplink half-close failed")?;
                                client_half_closed = true;
                            }
                            Ok(n) => {
                                let chunk = rbuf[..n].to_vec();
                                writer
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
                                    &active_uplink_name,
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
                            recovered_via = %active_uplink_name,
                            "recorded deferred TCP chunk-0 runtime failure after successful failover"
                        );
                    }
                    break 'phase1 chunk;
                }
                Err(ref e) if reader.closed_cleanly => {
                    debug!(
                        uplink = %active_uplink_name,
                        error = %format!("{e:#}"),
                        "upstream closed before sending any data (phase 1)"
                    );
                    client_write.shutdown().await.context("client shutdown failed")?;
                    return Ok(());
                }
                Err(e) => {
                    let mut phase1_error = e;
                    if active_source == TcpUplinkSource::Standby {
                        debug!(
                            uplink = %active_uplink_name,
                            error = %format!("{phase1_error:#}"),
                            "TCP phase-1 failure on warm-standby socket; retrying same uplink with a fresh dial"
                        );
                        match connect_tcp_uplink_fresh(&uplinks, &active_candidate, &target).await {
                            Ok(reconnected) => {
                                writer = reconnected.writer;
                                reader = reconnected.reader;
                                active_source = reconnected.source;
                                for chunk in &replay_buf {
                                    writer
                                        .send_chunk(chunk)
                                        .await
                                        .context("replay to fresh uplink after standby failure failed")?;
                                }
                                if client_half_closed {
                                    writer
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
                    let attempted_uplinks =
                        attempted_chunk0_uplink_names(&deferred_phase1_failures, &active_uplink_name);
                    warn!(
                        uplink = %active_uplink_name,
                        attempted_uplinks = ?attempted_uplinks,
                        target = %target,
                        error = %error_text,
                        "TCP chunk-0 failure"
                    );

                    if !can_failover {
                        if deferred_phase1_failures.is_empty() {
                            uplinks
                                .report_runtime_failure(
                                    active_index,
                                    TransportKind::Tcp,
                                    &phase1_error,
                                )
                                .await;
                        } else {
                            warn!(
                                last_uplink = %active_uplink_name,
                                attempts = attempted_uplinks.len(),
                                attempted_uplinks = ?attempted_uplinks,
                                error = %error_text,
                                "suppressing TCP chunk-0 runtime failure attribution because every attempted uplink stalled before the first response"
                            );
                        }
                        return Err(phase1_error);
                    }

                    deferred_phase1_failures.push((
                        active_index,
                        active_uplink_name.clone(),
                        error_text,
                    ));

                    let candidates = uplinks
                        .tcp_failover_candidates(&target, active_index)
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
                        &active_uplink_name,
                        &next_candidate.uplink.name,
                    );
                    metrics::record_uplink_selected(
                        "tcp",
                        uplinks.group_name(),
                        &next_candidate.uplink.name,
                    );
                    info!(
                        from = %active_uplink_name,
                        to = %next_candidate.uplink.name,
                        "TCP chunk-0 failover"
                    );
                    active_index = next_candidate.index;
                    active_uplink_name = next_candidate.uplink.name.clone();
                    active_candidate = next_candidate.clone();
                    writer = reconnected.writer;
                    reader = reconnected.reader;
                    active_source = reconnected.source;

                    for chunk in &replay_buf {
                        writer
                            .send_chunk(chunk)
                            .await
                            .context("replay to failover uplink failed")?;
                    }
                    if client_half_closed {
                        writer
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
        let uplink_uplink_name = active_uplink_name.clone();
        let uplinks_uplink = uplinks.clone();
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
                        uplink = %uplink_uplink_name,
                        transport_supports_tcp_half_close = writer.supports_half_close(),
                        "client closed SOCKS TCP session; initiating upstream half-close and awaiting downlink"
                    );
                    writer.close().await?;
                    break;
                }
                metrics::add_bytes(
                    "tcp",
                    "client_to_upstream",
                    uplinks_uplink.group_name(),
                    &uplink_uplink_name,
                    read,
                );
                writer.send_chunk(&buf[..read]).await?;
                chunks_sent += 1;
                if chunks_sent == 1 {
                    debug!(uplink = %uplink_uplink_name, "first chunk sent to upstream");
                }
                uplinks_uplink
                    .report_active_traffic(active_index, TransportKind::Tcp)
                    .await;
            }
            Ok::<UplinkTaskResult, anyhow::Error>(UplinkTaskResult::Finished)
        };

        let downlink_uplink_name = active_uplink_name.clone();
        let uplinks_downlink = uplinks.clone();
        let downlink = async move {
            metrics::add_bytes(
                "tcp",
                "upstream_to_client",
                uplinks_downlink.group_name(),
                &downlink_uplink_name,
                first_upstream_chunk.len(),
            );
            client_write
                .write_all(&first_upstream_chunk)
                .await
                .context("client write failed")?;
            uplinks_downlink
                .report_active_traffic(active_index, TransportKind::Tcp)
                .await;

            let mut chunks_forwarded: u64 = 1;
            loop {
                let chunk = match reader.read_chunk().await {
                    Ok(chunk) => chunk,
                    Err(_err) if reader.closed_cleanly => {
                        if chunks_forwarded == 0 {
                            debug!(
                                uplink = %downlink_uplink_name,
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
                    uplinks_downlink.group_name(),
                    &downlink_uplink_name,
                    chunk.len(),
                );
                client_write
                    .write_all(&chunk)
                    .await
                    .context("client write failed")?;
                uplinks_downlink
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
        // the server side has already closed cleanly. Previously `try_join!`
        // waited forever for `uplink` when `downlink` had already reached EOF,
        // which kept the SOCKS5 -> WebSocket transport, its tasks, and the
        // underlying socket alive until the client finally closed too.
        let result = drive_tcp_session_tasks(uplink, downlink).await;
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
) -> Result<()> {
    let addr = match &target {
        TargetAddr::IpV4(ip, port) => SocketAddr::new(std::net::IpAddr::V4(*ip), *port),
        TargetAddr::IpV6(ip, port) => SocketAddr::new(std::net::IpAddr::V6(*ip), *port),
        TargetAddr::Domain(host, port) => crate::transport::resolve_host_with_preference(
            host,
            *port,
            &format!("failed to resolve {target}"),
            false,
        )
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no address resolved for {target}"))?,
    };

    let upstream = crate::transport::connect_tcp_socket(addr, fwmark)
        .await
        .with_context(|| format!("direct TCP connect to {target} failed"))?;

    let bound_addr = socket_addr_to_target(client.local_addr()?);
    send_reply(&mut client, SOCKS_STATUS_SUCCESS, &bound_addr).await?;

    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let c2u = async {
        let mut buf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];
        loop {
            let read = client_read.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            metrics::add_bytes(
                "tcp",
                "client_to_upstream",
                metrics::BYPASS_GROUP_LABEL,
                metrics::BYPASS_UPLINK_LABEL,
                read,
            );
            upstream_write.write_all(&buf[..read]).await?;
        }
        upstream_write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    let u2c = async {
        let mut buf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];
        loop {
            let read = upstream_read.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            metrics::add_bytes(
                "tcp",
                "upstream_to_client",
                metrics::BYPASS_GROUP_LABEL,
                metrics::BYPASS_UPLINK_LABEL,
                read,
            );
            client_write.write_all(&buf[..read]).await?;
        }
        client_write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };

    tokio::try_join!(c2u, u2c).map(|_| ())
}

async fn connect_tcp_uplink(
    uplinks: &UplinkManager,
    candidate: &crate::uplink::UplinkCandidate,
    target: &TargetAddr,
) -> Result<ConnectedTcpUplink> {
    if candidate.uplink.transport == UplinkTransport::Shadowsocks {
        let stream = connect_shadowsocks_tcp_with_source(
            candidate
                .uplink
                .tcp_addr
                .as_ref()
                .ok_or_else(|| anyhow!("uplink {} missing tcp_addr", candidate.uplink.name))?,
            candidate.uplink.fwmark,
            candidate.uplink.ipv6_first,
            "socks_tcp",
        )
        .await?;
        let (writer, reader) =
            do_tcp_ss_setup_socket(stream, &candidate.uplink, target, "socks_tcp").await?;
        return Ok(ConnectedTcpUplink {
            writer,
            reader,
            source: TcpUplinkSource::DirectSocket,
        });
    }

    // Variant A: try a standby pool connection first.  If it turns out to be
    // stale (fails before any server bytes arrive), discard it silently and
    // retry with a fresh on-demand dial — without recording a runtime failure.
    if let Some(ws) = uplinks.try_take_tcp_standby(candidate).await {
        match do_tcp_ss_setup(ws, &candidate.uplink, target, "socks_tcp").await {
            Ok((writer, reader)) => {
                return Ok(ConnectedTcpUplink {
                    writer,
                    reader,
                    source: TcpUplinkSource::Standby,
                });
            },
            Err(e) => {
                debug!(
                    uplink = %candidate.uplink.name,
                    error = %format!("{e:#}"),
                    "stale standby TCP pool connection, retrying with fresh dial"
                );
            },
        }
    }

    connect_tcp_uplink_fresh(uplinks, candidate, target).await
}

async fn connect_tcp_uplink_fresh(
    uplinks: &UplinkManager,
    candidate: &crate::uplink::UplinkCandidate,
    target: &TargetAddr,
) -> Result<ConnectedTcpUplink> {
    let ws = uplinks.connect_tcp_ws_fresh(candidate, "socks_tcp").await?;
    let (writer, reader) = do_tcp_ss_setup(ws, &candidate.uplink, target, "socks_tcp").await?;
    Ok(ConnectedTcpUplink {
        writer,
        reader,
        source: TcpUplinkSource::FreshDial,
    })
}

async fn do_tcp_ss_setup(
    ws_stream: crate::transport::AnyWsStream,
    uplink: &crate::config::UplinkConfig,
    target: &TargetAddr,
    source: &'static str,
) -> Result<(TcpShadowsocksWriter, TcpShadowsocksReader)> {
    let (ws_sink, ws_stream) = ws_stream.split();
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let lifetime = UpstreamTransportGuard::new(source, "tcp");
    let (mut writer, ctrl_tx) =
        TcpShadowsocksWriter::connect(ws_sink, uplink.cipher, &master_key, Arc::clone(&lifetime))
            .await?;
    let request_salt = writer.request_salt().map(|salt| salt.to_vec());
    let reader =
        TcpShadowsocksReader::new(ws_stream, uplink.cipher, &master_key, lifetime, ctrl_tx)
            .with_request_salt(request_salt);
    let target_wire = target.to_wire_bytes()?;
    writer
        .send_chunk(&target_wire)
        .await
        .context("failed to send target address")?;
    debug!(
        uplink = %uplink.name,
        target = %target,
        target_wire_len = target_wire.len(),
        transport = "websocket",
        ss2022 = uplink.cipher.is_ss2022(),
        "sent initial Shadowsocks target header to uplink"
    );
    Ok((writer, reader))
}

async fn do_tcp_ss_setup_socket(
    stream: TcpStream,
    uplink: &crate::config::UplinkConfig,
    target: &TargetAddr,
    source: &'static str,
) -> Result<(TcpShadowsocksWriter, TcpShadowsocksReader)> {
    let (reader_half, writer_half) = stream.into_split();
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let lifetime = UpstreamTransportGuard::new(source, "tcp");
    let mut writer = TcpShadowsocksWriter::connect_socket(
        writer_half,
        uplink.cipher,
        &master_key,
        Arc::clone(&lifetime),
    )?;
    let reader =
        TcpShadowsocksReader::new_socket(reader_half, uplink.cipher, &master_key, lifetime)
            .with_request_salt(writer.request_salt().map(|salt| salt.to_vec()));
    let target_wire = target.to_wire_bytes()?;
    writer
        .send_chunk(&target_wire)
        .await
        .context("failed to send target address")?;
    debug!(
        uplink = %uplink.name,
        target = %target,
        target_wire_len = target_wire.len(),
        transport = "socket",
        ss2022 = uplink.cipher.is_ss2022(),
        "sent initial Shadowsocks target header to uplink"
    );
    Ok((writer, reader))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use tokio::sync::Notify;

    struct DropSignal {
        notify: std::sync::Arc<Notify>,
    }

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.notify.notify_one();
        }
    }

    #[tokio::test]
    async fn drive_tcp_session_tasks_aborts_uplink_when_downlink_finishes_first() {
        let uplink_dropped = std::sync::Arc::new(Notify::new());
        let uplink_dropped_clone = std::sync::Arc::clone(&uplink_dropped);
        let uplink = async move {
            let _drop_signal = DropSignal { notify: uplink_dropped_clone };
            std::future::pending::<()>().await;
            #[allow(unreachable_code)]
            Ok::<UplinkTaskResult, anyhow::Error>(UplinkTaskResult::Finished)
        };
        let downlink = async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok::<(), anyhow::Error>(())
        };

        tokio::time::timeout(Duration::from_secs(1), drive_tcp_session_tasks(uplink, downlink))
            .await
            .expect("driver should return once downlink finishes")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), uplink_dropped.notified())
            .await
            .expect("uplink should be dropped when downlink wins");
    }

    #[tokio::test]
    async fn drive_tcp_session_tasks_waits_for_downlink_after_socket_half_close() {
        let downlink_completed = std::sync::Arc::new(Notify::new());
        let downlink_completed_clone = std::sync::Arc::clone(&downlink_completed);
        let uplink =
            async move { Ok::<UplinkTaskResult, anyhow::Error>(UplinkTaskResult::Finished) };
        let downlink = async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            downlink_completed_clone.notify_one();
            Ok::<(), anyhow::Error>(())
        };

        tokio::time::timeout(Duration::from_secs(1), drive_tcp_session_tasks(uplink, downlink))
            .await
            .expect("driver should wait for downlink after client EOF")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), downlink_completed.notified())
            .await
            .expect("downlink should be allowed to finish");
    }

    #[tokio::test]
    async fn drive_tcp_session_tasks_aborts_downlink_after_websocket_client_eof() {
        let downlink_dropped = std::sync::Arc::new(Notify::new());
        let downlink_dropped_clone = std::sync::Arc::clone(&downlink_dropped);
        let uplink =
            async move { Ok::<UplinkTaskResult, anyhow::Error>(UplinkTaskResult::CloseSession) };
        let downlink = async move {
            let _drop_signal = DropSignal { notify: downlink_dropped_clone };
            std::future::pending::<()>().await;
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };

        tokio::time::timeout(Duration::from_secs(1), drive_tcp_session_tasks(uplink, downlink))
            .await
            .expect("driver should return once websocket-backed client EOF is observed")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), downlink_dropped.notified())
            .await
            .expect("downlink should be aborted after websocket-backed client EOF");
    }

    #[test]
    fn attempted_chunk0_uplink_names_preserves_attempt_order_without_duplicates() {
        let attempted = attempted_chunk0_uplink_names(
            &[
                (0, "nuxt".to_string(), "first".to_string()),
                (1, "aeza".to_string(), "second".to_string()),
                (0, "nuxt".to_string(), "duplicate".to_string()),
            ],
            "aeza",
        );

        assert_eq!(attempted, vec!["nuxt".to_string(), "aeza".to_string()]);
    }
}
