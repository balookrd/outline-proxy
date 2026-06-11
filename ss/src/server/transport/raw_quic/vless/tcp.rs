use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use anyhow::{Context, Result, anyhow};
use metrics::Counter;
use tokio::{
    io::AsyncWriteExt,
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::Notify,
};
use tracing::{debug, info, warn};

use crate::{
    metrics::{AppProtocol, Protocol},
    protocol::vless::{self, AddonResumeResult, VlessUser},
};

use super::super::super::super::{
    connect::connect_tcp_target,
    resumption::{Parked, ParkedTcp, ResumeOutcome, SessionId, TcpProtocolContext},
    scratch::TcpRelayBuf,
    transport::{ResumeContext, VlessWsServerCtx},
};

pub(super) async fn handle_tcp(
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    mut header_buf: Vec<u8>,
    request: vless::VlessRequest,
    user: VlessUser,
    server: &VlessWsServerCtx,
    resume: ResumeContext,
) -> Result<()> {
    let target = request.target.clone();
    let target_display = target.display_host_port();
    debug!(user = user.label(), target = %target_display, "vless raw-quic tcp target");

    // Resolve resume / fresh-connect into a `(reader, writer, guard,
    // resume_result)` tuple. Resume hits skip `connect_tcp_target`
    // entirely; misses fall through to the legacy connect path.
    let user_label = user.label_arc();
    let (up_reader, mut up_writer, upstream_guard, resume_result) =
        match try_attach_parked_tcp(server, &user_label, resume.requested_resume).await {
            ResumeAttempt::Hit { reader, writer, guard } => {
                (reader, writer, guard, Some(AddonResumeResult::Hit))
            },
            ResumeAttempt::Miss(result) => {
                // Fresh connect.
                let connect_started = std::time::Instant::now();
                let upstream = match connect_tcp_target(
                    server.dns_cache.as_ref(),
                    &target,
                    user.fwmark(),
                    server.prefer_ipv4_upstream,
                    server.outbound_ipv6.as_deref(),
                )
                .await
                {
                    Ok(stream) => {
                        server.metrics.record_tcp_connect(
                            Arc::clone(&user_label),
                            Protocol::QuicRaw,
                            AppProtocol::Vless,
                            "success",
                            connect_started.elapsed().as_secs_f64(),
                        );
                        stream
                    },
                    Err(error) => {
                        server.metrics.record_tcp_connect(
                            Arc::clone(&user_label),
                            Protocol::QuicRaw,
                            AppProtocol::Vless,
                            "error",
                            connect_started.elapsed().as_secs_f64(),
                        );
                        let _ = send.reset(quinn::VarInt::from_u32(1));
                        return Err(error).with_context(|| {
                            format!("vless raw-quic upstream connect failed: {target_display}")
                        });
                    },
                };
                let (r, w) = upstream.into_split();
                let guard = server.metrics.open_tcp_upstream_connection(
                    Arc::clone(&user_label),
                    Protocol::QuicRaw,
                    AppProtocol::Vless,
                );
                server.metrics.record_tcp_authenticated_session(
                    Arc::clone(&user_label),
                    Protocol::QuicRaw,
                    AppProtocol::Vless,
                );
                (r, w, guard, result)
            },
        };

    // Build the response header. When resumption is active the
    // `[VERSION, 0x00]` two-byte preamble is replaced with
    // `[VERSION, addons_len, addons...]` carrying the assigned
    // Session ID and (optionally) the resume-attempt result.
    write_vless_tcp_response_header(&mut send, resume.issued_session_id, resume_result).await?;

    let user_counters = server.metrics.user_counters(&user_label);
    let client_to_target = user_counters.tcp_in(AppProtocol::Vless, Protocol::QuicRaw).clone();
    let target_to_client = user_counters.tcp_out(AppProtocol::Vless, Protocol::QuicRaw).clone();

    // Pipe the initial payload (bytes that arrived after the request
    // header in the same chunk) before the relay tasks spin up.
    let leftover: Vec<u8> = header_buf.split_off(request.consumed);
    drop(header_buf);
    if !leftover.is_empty() {
        client_to_target.increment(leftover.len() as u64);
        up_writer
            .write_all(&leftover)
            .await
            .context("failed to forward initial vless payload upstream")?;
    }

    // Spawn upload (client → upstream) and download (upstream → client)
    // as separate tasks, both watching a shared cancel notify. On client
    // EOF (recv returned None) the upload task fires the cancel so the
    // download task can return its harvested upstream reader for
    // park-on-drop. Any error or upstream EOF skips the harvest.
    let cancel = Arc::new(Notify::new());
    let cancel_for_download = Arc::clone(&cancel);
    let upload_task =
        tokio::spawn(run_upload(recv, up_writer, client_to_target, Arc::clone(&cancel)));
    let download_task =
        tokio::spawn(run_download(send, up_reader, target_to_client, cancel_for_download));

    let upload_outcome = upload_task
        .await
        .context("vless raw-quic upload task join failed")??;
    let download_outcome = download_task
        .await
        .context("vless raw-quic download task join failed")??;

    let parked = match (upload_outcome, download_outcome) {
        (UploadOutcome::ClientEofWriter(writer), DownloadOutcome::Cancelled(reader)) => {
            // The upload task hit recv == None (client closed the
            // QUIC stream gracefully) and signalled cancel; the
            // download task replied with its harvested reader. Park.
            try_park_raw_quic_tcp(
                server,
                resume.issued_session_id,
                reader,
                writer,
                Arc::clone(&user_label),
                upstream_guard,
                Arc::from(target_display.as_str()),
            )
        },
        _ => false,
    };
    if !parked {
        debug!(
            user = user.label(),
            target = %target_display,
            "vless raw-quic stream finished without park"
        );
    }
    Ok(())
}

// ── Park / resume helpers ───────────────────────────────────────────────

enum ResumeAttempt {
    Hit {
        reader: OwnedReadHalf,
        writer: OwnedWriteHalf,
        guard: crate::metrics::TcpUpstreamGuard,
    },
    /// No resume happened; second component is the addon-result label
    /// to surface in the response (`None` if no resume was attempted at
    /// all). All non-hit cases are reported externally as
    /// `MissUnknown` to avoid an existence oracle.
    Miss(Option<AddonResumeResult>),
}

async fn try_attach_parked_tcp(
    server: &VlessWsServerCtx,
    user_label: &Arc<str>,
    requested_resume: Option<SessionId>,
) -> ResumeAttempt {
    let Some(id) = requested_resume else {
        return ResumeAttempt::Miss(None);
    };
    match server.orphan_registry.take_for_resume(id, user_label) {
        ResumeOutcome::Hit(Parked::Tcp(parked)) => match parked.protocol_context {
            TcpProtocolContext::Vless => {
                info!(
                    user = %user_label,
                    target = %parked.target_display,
                    "vless raw-quic upstream resumed from orphan registry"
                );
                ResumeAttempt::Hit {
                    reader: parked.upstream_reader,
                    writer: parked.upstream_writer,
                    guard: parked.upstream_guard,
                }
            },
            TcpProtocolContext::Ss(_) => {
                warn!(
                    user = %user_label,
                    "raw-quic resume rejected: parked entry is SS-protocol, not VLESS"
                );
                ResumeAttempt::Miss(Some(AddonResumeResult::MissUnknown))
            },
        },
        ResumeOutcome::Hit(other) => {
            warn!(
                user = %user_label,
                parked_kind = other.kind(),
                "raw-quic resume rejected: cross-shape parked entry"
            );
            ResumeAttempt::Miss(Some(AddonResumeResult::MissUnknown))
        },
        ResumeOutcome::Miss(_) => ResumeAttempt::Miss(Some(AddonResumeResult::MissUnknown)),
    }
}

fn try_park_raw_quic_tcp(
    server: &VlessWsServerCtx,
    issued_session_id: Option<SessionId>,
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    owner: Arc<str>,
    upstream_guard: crate::metrics::TcpUpstreamGuard,
    target_display: Arc<str>,
) -> bool {
    let Some(session_id) = issued_session_id else {
        return false;
    };
    if !server.orphan_registry.enabled() {
        return false;
    }
    let user_counters = server.metrics.user_counters(&owner);
    let parked = ParkedTcp {
        upstream_writer: writer,
        upstream_reader: reader,
        target_display,
        owner: Arc::clone(&owner),
        // Cross-transport with the WS-side VLESS path is the whole
        // point of resuming raw QUIC: store under the same protocol
        // context so a subsequent WS reconnect (`Tcp(Vless)` match)
        // re-attaches transparently.
        protocol_context: TcpProtocolContext::Vless,
        user_counters,
        upstream_guard,
        // Ack-Prefix Protocol counter starts at 0 for VLESS raw-QUIC
        // in v1; control-frame emit on this protocol is a follow-up.
        upstream_bytes_acked: Arc::new(AtomicU64::new(0)),
        // v2 Symmetric Downlink Replay is not active on raw-QUIC for
        // the same reason v1 emit isn't — no HTTP-headers carrier for
        // the negotiation. Field stays `None` here and changes only
        // if/when raw-QUIC gets its own VLESS-Addons-based v2 hook.
        downlink_ring: None,
    };
    debug!(
        user = %owner,
        "parking vless raw-quic tcp upstream into orphan registry"
    );
    server.orphan_registry.park(session_id, Parked::Tcp(parked));
    true
}

async fn write_vless_tcp_response_header(
    send: &mut quinn::SendStream,
    issued_session_id: Option<SessionId>,
    resume_result: Option<AddonResumeResult>,
) -> Result<()> {
    let addons = vless::encode_response_addons(
        issued_session_id.as_ref().map(|id| id.as_bytes()),
        resume_result,
    );
    if addons.is_empty() {
        send.write_all(&[vless::VERSION, 0x00])
            .await
            .context("failed to write vless raw-quic response header")?;
        return Ok(());
    }
    if addons.len() > u8::MAX as usize {
        // Should not happen — Addons block is at most ~20 bytes for
        // the opcodes we emit. Defend the wire format anyway.
        return Err(anyhow!("vless raw-quic response addons too large: {} bytes", addons.len()));
    }
    let mut header = Vec::with_capacity(2 + addons.len());
    header.push(vless::VERSION);
    header.push(addons.len() as u8);
    header.extend_from_slice(&addons);
    send.write_all(&header)
        .await
        .context("failed to write vless raw-quic response header")?;
    Ok(())
}

// ── Relay tasks (with cancel-on-client-EOF) ─────────────────────────────

enum UploadOutcome {
    /// Upload finished due to client EOF (`recv` returned `None`). The
    /// upstream writer half is returned for potential park-on-drop;
    /// the cancel notify has already been fired so the download task
    /// will harvest its reader half. Other termination paths (write
    /// errors, recv errors) propagate as `Err(_)` from `run_upload`.
    ClientEofWriter(OwnedWriteHalf),
}

async fn run_upload(
    mut recv: quinn::RecvStream,
    mut up_writer: OwnedWriteHalf,
    client_to_target: Counter,
    cancel: Arc<Notify>,
) -> Result<UploadOutcome> {
    let mut buf = TcpRelayBuf::take();
    loop {
        match recv.read(&mut *buf).await {
            Ok(Some(0)) => continue,
            Ok(Some(n)) => {
                client_to_target.increment(n as u64);
                if let Err(error) = up_writer.write_all(&buf[..n]).await {
                    let _ = up_writer.shutdown().await;
                    return Err(anyhow!(error).context("failed to write upstream from raw-quic"));
                }
            },
            Ok(None) => {
                // Client closed the QUIC stream — the only path that
                // can end a healthy session. Park-on-drop is potentially
                // applicable; signal the download task to harvest its
                // reader and return ours alongside.
                cancel.notify_one();
                return Ok(UploadOutcome::ClientEofWriter(up_writer));
            },
            Err(error) => {
                let _ = up_writer.shutdown().await;
                return Err(anyhow!(error).context("vless raw-quic recv read failed"));
            },
        }
    }
}

enum DownloadOutcome {
    /// Upstream EOF or send error; reader is consumed.
    Drained,
    /// Cancel notify fired while we were idle in `read`. Reader is
    /// returned for hand-off into the orphan registry.
    Cancelled(OwnedReadHalf),
}

async fn run_download(
    mut send: quinn::SendStream,
    up_reader: OwnedReadHalf,
    target_to_client: Counter,
    cancel: Arc<Notify>,
) -> Result<DownloadOutcome> {
    loop {
        tokio::select! {
            biased;
            _ = cancel.notified() => {
                return Ok(DownloadOutcome::Cancelled(up_reader));
            }
            ready = up_reader.readable() => {
                ready.context("failed to await upstream tcp")?;
                // Allocate from the pool only once data is ready, so an idle
                // session holds no per-direction relay buffer; the buffer
                // returns to the pool before the next park.
                let mut buf = TcpRelayBuf::take();
                let n = match up_reader.try_read(&mut *buf) {
                    Ok(n) => n,
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(error).context("failed to read upstream tcp"),
                };
                if n == 0 {
                    let _ = send.finish();
                    return Ok(DownloadOutcome::Drained);
                }
                target_to_client.increment(n as u64);
                send.write_all(&buf[..n])
                    .await
                    .context("failed to write to raw-quic send stream")?;
            }
        }
    }
}
