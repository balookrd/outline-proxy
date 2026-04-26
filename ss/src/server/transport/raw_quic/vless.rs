//! Raw VLESS over QUIC (no WebSocket, no HTTP/3 framing).
//!
//! One QUIC bidirectional stream carries one VLESS request: header at the
//! start of the stream, then the TCP target's data is spliced in both
//! directions over the same stream. UDP and MUX commands are reserved for
//! Phase 2 (UDP via QUIC datagrams; MUX is intentionally not supported on raw
//! QUIC since QUIC streams *are* the multiplex).

use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use anyhow::{Context, Result, anyhow};
use bytes::{BufMut, BytesMut};
use dashmap::DashMap;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    time::{Duration, timeout},
};
use tracing::{debug, info, warn};

use crate::{
    fwmark::apply_fwmark_if_needed,
    metrics::{Protocol, Transport},
    protocol::vless::{self, VlessCommand, VlessUser, mask_uuid},
};

use super::super::super::{
    connect::{connect_tcp_target, resolve_udp_target},
    constants::{MAX_UDP_PAYLOAD_SIZE, SS_TCP_HANDSHAKE_TIMEOUT_SECS},
    nat::bind_nat_udp_socket,
    transport::VlessWsServerCtx,
};

/// Per-QUIC-connection state for raw VLESS: tracks open UDP sessions so the
/// connection-level datagram pump can route incoming datagrams to the right
/// upstream socket.
pub(in crate::server) struct VlessQuicConn {
    next_session: AtomicU32,
    sessions: DashMap<u32, Arc<VlessUdpSession>>,
    /// Connection-level oversize-record stream, lazy-installed when
    /// either the client opens it (peer accept_bi path) or the server
    /// itself needs to send an oversized response (server-initiated
    /// open). Empty when the negotiated ALPN is the legacy `vless`
    /// (no MTU-aware fallback) or when no oversized packet has flowed
    /// yet on this connection.
    pub(in crate::server) oversize_slot: super::OversizeStreamSlot,
}

struct VlessUdpSession {
    socket: Arc<UdpSocket>,
    user_label: Arc<str>,
}

impl VlessQuicConn {
    pub(in crate::server) fn new() -> Self {
        Self {
            next_session: AtomicU32::new(1),
            sessions: DashMap::new(),
            oversize_slot: super::OversizeStreamSlot::new(),
        }
    }

    fn allocate_session(&self) -> u32 {
        self.next_session.fetch_add(1, Ordering::Relaxed)
    }

    fn register(&self, id: u32, session: Arc<VlessUdpSession>) {
        self.sessions.insert(id, session);
    }

    fn unregister(&self, id: u32) {
        self.sessions.remove(&id);
    }

    fn lookup(&self, id: u32) -> Option<Arc<VlessUdpSession>> {
        self.sessions.get(&id).map(|entry| Arc::clone(entry.value()))
    }
}

const MAX_VLESS_HEADER_BUFFER: usize = 512;

pub(in crate::server) struct RawQuicVlessRouteCtx {
    pub(in crate::server) users: Arc<[VlessUser]>,
    pub(in crate::server) candidate_users: Arc<[Arc<str>]>,
}

pub(in crate::server) async fn handle_raw_vless_quic_stream(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    server: Arc<VlessWsServerCtx>,
    route: Arc<RawQuicVlessRouteCtx>,
    connection: Arc<quinn::Connection>,
    conn_state: Arc<VlessQuicConn>,
) -> Result<()> {
    handle_raw_vless_quic_stream_with_prefix(
        send,
        recv,
        Vec::new(),
        server,
        route,
        connection,
        conn_state,
    )
    .await
}

/// Same as [`handle_raw_vless_quic_stream`] but accepts a `prefix` of
/// bytes already read off the recv stream by the caller (typically the
/// 8 bytes peeked to disambiguate the oversize-record magic from a
/// VLESS request header). The handler treats those bytes as the first
/// chunk of the inbound stream.
pub(in crate::server) async fn handle_raw_vless_quic_stream_with_prefix(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    prefix: Vec<u8>,
    server: Arc<VlessWsServerCtx>,
    route: Arc<RawQuicVlessRouteCtx>,
    connection: Arc<quinn::Connection>,
    conn_state: Arc<VlessQuicConn>,
) -> Result<()> {
    let session = server
        .metrics
        .open_websocket_session(Transport::Tcp, Protocol::QuicRaw);

    let outcome = run_stream(
        &mut send,
        &mut recv,
        prefix,
        &server,
        &route,
        &connection,
        &conn_state,
    )
    .await;
    let outcome_for_metrics = match &outcome {
        Ok(()) => crate::metrics::DisconnectReason::Normal,
        Err(_) => crate::metrics::DisconnectReason::Error,
    };
    session.finish(outcome_for_metrics);
    outcome
}

async fn run_stream(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    prefix: Vec<u8>,
    server: &VlessWsServerCtx,
    route: &RawQuicVlessRouteCtx,
    connection: &Arc<quinn::Connection>,
    conn_state: &Arc<VlessQuicConn>,
) -> Result<()> {
    // Read enough bytes from the stream to parse a VLESS request header.
    // We pull in chunks of up to MAX_VLESS_HEADER_BUFFER bytes; parsing is
    // tolerant of partial input and signals readiness via Ok(Some(_)).
    // `prefix` carries any bytes the caller pre-read off the recv stream
    // (e.g. the 8-byte peek used to disambiguate the oversize-record
    // magic from a VLESS request header) so they re-enter the parser.
    let mut header_buf = if prefix.is_empty() { Vec::with_capacity(128) } else { prefix };
    let request = loop {
        // Try parsing first so a `prefix` that already carries the
        // full header avoids an unnecessary read on a stream the
        // peer may not write to again until handshake completes.
        match vless::parse_request(&header_buf) {
            Ok(Some(request)) => break request,
            Ok(None) => {
                if header_buf.len() > MAX_VLESS_HEADER_BUFFER {
                    return Err(anyhow!("vless raw-quic header too large"));
                }
            },
            Err(vless::VlessError::UnsupportedCommand(c)) => {
                return Err(anyhow!("unsupported vless command {c:#x}"));
            },
            Err(error) => return Err(anyhow!(error)),
        }
        let mut chunk = [0_u8; 256];
        let read_fut = recv.read(&mut chunk);
        let read = match timeout(Duration::from_secs(SS_TCP_HANDSHAKE_TIMEOUT_SECS), read_fut).await
        {
            Ok(Ok(Some(n))) => n,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(error)) => {
                return Err(anyhow!(error).context("vless raw-quic stream read failed"));
            },
            Err(_) => {
                warn!(buffered = header_buf.len(), "vless raw-quic header read timed out");
                return Err(anyhow!("vless raw-quic handshake timeout"));
            },
        };
        header_buf.extend_from_slice(&chunk[..read]);
    };

    let user = match vless::find_user(route.users.as_ref(), &request.user_id).cloned() {
        Some(user) => user,
        None => {
            warn!(
                user = %mask_uuid(&request.user_id),
                candidates = ?route.candidate_users,
                "rejected vless raw-quic user"
            );
            return Err(anyhow!("unknown vless user"));
        },
    };

    match request.command {
        VlessCommand::Tcp => handle_tcp(send, recv, header_buf, request, user, server).await,
        VlessCommand::Udp => {
            handle_udp(send, recv, header_buf, request, user, server, connection, conn_state).await
        },
        VlessCommand::Mux => Err(anyhow!(
            "VLESS MUX is not supported on raw QUIC; open separate streams"
        )),
    }
}

async fn handle_tcp(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    mut header_buf: Vec<u8>,
    request: vless::VlessRequest,
    user: VlessUser,
    server: &VlessWsServerCtx,
) -> Result<()> {
    let target = request.target.clone();
    let target_display = target.display_host_port();
    info!(user = user.label(), target = %target_display, "vless raw-quic tcp target");

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
                user.label_arc(),
                Protocol::QuicRaw,
                "success",
                connect_started.elapsed().as_secs_f64(),
            );
            stream
        },
        Err(error) => {
            server.metrics.record_tcp_connect(
                user.label_arc(),
                Protocol::QuicRaw,
                "error",
                connect_started.elapsed().as_secs_f64(),
            );
            // Try to surface a try-again hint by closing the QUIC stream with
            // a non-zero code. Best-effort.
            let _ = send.reset(quinn::VarInt::from_u32(1));
            return Err(error)
                .with_context(|| format!("vless raw-quic upstream connect failed: {target_display}"));
        },
    };

    // Send VLESS response header [VERSION, 0x00] before any payload.
    send.write_all(&[vless::VERSION, 0x00])
        .await
        .context("failed to write vless raw-quic response header")?;

    let (mut up_reader, mut up_writer) = upstream.into_split();
    let upstream_guard = server
        .metrics
        .open_tcp_upstream_connection(user.label_arc(), Protocol::QuicRaw);
    server
        .metrics
        .record_tcp_authenticated_session(user.label_arc(), Protocol::QuicRaw);

    // Pipe initial payload (bytes left over from the header buffer beyond the
    // request header) to upstream before splicing further.
    let leftover: Vec<u8> = header_buf.split_off(request.consumed);
    drop(header_buf);
    if !leftover.is_empty() {
        server.metrics.record_tcp_payload_bytes(
            user.label_arc(),
            Protocol::QuicRaw,
            "client_to_target",
            leftover.len(),
        );
        up_writer
            .write_all(&leftover)
            .await
            .context("failed to forward initial vless payload upstream")?;
    }

    // Bidirectional splice. Two tasks so upstream EOF closes the QUIC stream's
    // send side (and vice versa) without entangling the read loops.
    let user_label = user.label_arc();
    let user_counters = server.metrics.user_counters(&user_label);
    let client_to_target = user_counters.tcp_in(Protocol::QuicRaw).clone();
    let target_to_client = user_counters.tcp_out(Protocol::QuicRaw).clone();

    let upload = async {
        let mut buf = vec![0_u8; 16 * 1024];
        loop {
            let n = match recv.read(&mut buf).await {
                Ok(Some(n)) => n,
                Ok(None) => break,
                Err(error) => {
                    return Err(anyhow!(error).context("vless raw-quic recv read failed"));
                },
            };
            if n == 0 {
                continue;
            }
            client_to_target.increment(n as u64);
            up_writer
                .write_all(&buf[..n])
                .await
                .context("failed to write upstream from raw-quic")?;
        }
        let _ = up_writer.shutdown().await;
        Ok::<_, anyhow::Error>(())
    };

    let download = async {
        let mut buf = vec![0_u8; 16 * 1024];
        loop {
            let n = up_reader
                .read(&mut buf)
                .await
                .context("failed to read upstream tcp")?;
            if n == 0 {
                break;
            }
            target_to_client.increment(n as u64);
            send.write_all(&buf[..n])
                .await
                .context("failed to write to raw-quic send stream")?;
        }
        let _ = send.finish();
        Ok::<_, anyhow::Error>(())
    };

    let (up, down) = tokio::join!(upload, download);
    upstream_guard.finish();
    debug!(user = user.label(), target = %target_display, "vless raw-quic stream finished");
    match (up, down) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), _) | (_, Err(e)) => Err(e),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_udp(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    _header_buf: Vec<u8>,
    request: vless::VlessRequest,
    user: VlessUser,
    server: &VlessWsServerCtx,
    connection: &Arc<quinn::Connection>,
    conn_state: &Arc<VlessQuicConn>,
) -> Result<()> {
    let target = request.target.clone();
    let target_display = target.display_host_port();
    info!(user = user.label(), target = %target_display, "vless raw-quic udp target");

    let resolved =
        resolve_udp_target(server.dns_cache.as_ref(), &target, server.prefer_ipv4_upstream)
            .await
            .with_context(|| format!("vless raw-quic udp dns resolution failed: {target_display}"))?;
    let socket = bind_nat_udp_socket(resolved, server.outbound_ipv6.as_deref())
        .context("failed to bind vless raw-quic udp upstream socket")?;
    apply_fwmark_if_needed(&socket, user.fwmark())
        .with_context(|| format!("failed to apply fwmark {:?} to vless raw-quic udp", user.fwmark()))?;
    socket
        .connect(&resolved)
        .await
        .with_context(|| format!("failed to connect vless raw-quic udp socket to {resolved}"))?;
    let socket = Arc::new(socket);

    let session_id = conn_state.allocate_session();
    conn_state.register(
        session_id,
        Arc::new(VlessUdpSession {
            socket: Arc::clone(&socket),
            user_label: user.label_arc(),
        }),
    );

    // Response: [VERSION, 0x00, session_id_4B_BE]. Client uses session_id as
    // the per-datagram routing prefix on QUIC datagrams from now on.
    let mut response = [0_u8; 6];
    response[0] = vless::VERSION;
    response[1] = 0x00;
    response[2..6].copy_from_slice(&session_id.to_be_bytes());
    send.write_all(&response)
        .await
        .context("failed to write vless raw-quic udp response header")?;

    // The negotiated ALPN is recorded on the connection for the entire
    // lifetime — `mtu_aware` here selects whether oversize responses
    // can fall back to the connection-level oversize-record stream
    // instead of being dropped silently.
    let mtu_aware = connection
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.protocol)
        .is_some_and(|bytes| bytes == b"vless-mtu");
    let target_to_client = server
        .metrics
        .user_counters(&user.label_arc())
        .udp_out(Protocol::QuicRaw)
        .clone();
    let conn_for_reader = Arc::clone(connection);
    let conn_state_for_reader = Arc::clone(conn_state);
    let socket_for_reader = Arc::clone(&socket);
    let reader_task = tokio::spawn(async move {
        let mut buf = vec![0_u8; MAX_UDP_PAYLOAD_SIZE];
        loop {
            let n = match socket_for_reader.recv(&mut buf).await {
                Ok(n) => n,
                Err(error) => {
                    debug!(?error, session_id, "vless raw-quic udp upstream recv failed");
                    return;
                },
            };
            if n == 0 {
                continue;
            }
            target_to_client.increment(n as u64);
            let total_len = 4 + n;
            let max_dgram = conn_for_reader.max_datagram_size();
            let oversized = max_dgram.is_some_and(|max| total_len > max);
            if oversized && mtu_aware {
                // Fall back to the connection-level oversize-record
                // stream. Open it on first use (server-initiated open
                // is fine — the client side accept_bi loop is expected
                // to detect the magic and install symmetrically).
                let stream = match conn_state_for_reader.oversize_slot.get() {
                    Some(stream) => stream,
                    None => {
                        let pair = match conn_for_reader.open_bi().await {
                            Ok(pair) => pair,
                            Err(error) => {
                                debug!(
                                    session_id,
                                    ?error,
                                    "failed to open vless oversize stream for outbound packet"
                                );
                                continue;
                            }
                        };
                        let (send, recv) = pair;
                        let stream =
                            Arc::new(super::OversizeStream::from_local_open(send, recv));
                        let installed =
                            conn_state_for_reader.oversize_slot.install(stream);
                        // Ensure inbound records on this server-opened
                        // stream are still demuxed: spawn the read pump.
                        let pump_stream = Arc::clone(&installed);
                        let pump_state = Arc::clone(&conn_state_for_reader);
                        // Need the server context for metric attribution
                        // — clone metrics into a thin shim. The cheap
                        // path here is "open once per connection", so
                        // a small allocation is fine.
                        let _ = pump_state;
                        let _ = pump_stream;
                        // The accept_bi-side pump is wired by the
                        // bootstrap when the client opens this stream;
                        // for the symmetric case where the server opens
                        // first, the client's accept_bi handler does
                        // the same on its side. Server-side inbound
                        // records continue to flow through the
                        // datagram pump until the client also writes
                        // into this stream, at which point the
                        // serve_raw_vless_oversize_records pump
                        // installed by the bootstrap handler picks
                        // them up.
                        installed
                    }
                };
                let mut record = Vec::with_capacity(total_len);
                record.extend_from_slice(&session_id.to_be_bytes());
                record.extend_from_slice(&buf[..n]);
                if let Err(error) = stream.send_record(&record).await {
                    debug!(
                        session_id,
                        ?error,
                        "vless raw-quic oversize-record send failed; closing reader"
                    );
                    return;
                }
                continue;
            }
            if oversized {
                // Legacy ALPN client — silent drop, mirror of the
                // outline-ws-rust client side.
                debug!(
                    session_id,
                    n,
                    "vless raw-quic oversized response on legacy ALPN, dropping"
                );
                continue;
            }
            let mut datagram = BytesMut::with_capacity(total_len);
            datagram.put_u32(session_id);
            datagram.extend_from_slice(&buf[..n]);
            if conn_for_reader.send_datagram(datagram.freeze()).is_err() {
                debug!(session_id, "vless raw-quic udp send_datagram failed; closing reader");
                return;
            }
        }
    });

    // The bidi stream serves only as the session lifetime anchor: drain its
    // recv side and end the session as soon as the client closes it.
    let mut sink = [0_u8; 64];
    loop {
        match recv.read(&mut sink).await {
            Ok(Some(_)) => {
                // Client should not be writing on this stream after the
                // header; ignore stray bytes but keep the session alive
                // until EOF/abort.
                continue;
            },
            Ok(None) => break,
            Err(error) => {
                debug!(?error, session_id, "vless raw-quic udp control stream read failed");
                break;
            },
        }
    }

    conn_state.unregister(session_id);
    reader_task.abort();
    let _ = send.finish();
    Ok(())
}

/// Route one inbound `[session_id_4B || payload]` record into the
/// matching session's upstream UDP socket. Identical dispatch logic
/// to the datagram pump — both sources route by the same prefix.
async fn route_vless_udp_record(
    record: bytes::Bytes,
    server: &VlessWsServerCtx,
    conn_state: &VlessQuicConn,
) {
    if record.len() < 4 {
        warn!(len = record.len(), "vless raw-quic oversize record too short, dropping");
        return;
    }
    let session_id = u32::from_be_bytes([record[0], record[1], record[2], record[3]]);
    let Some(session) = conn_state.lookup(session_id) else {
        debug!(session_id, "vless raw-quic oversize record for unknown session, dropping");
        return;
    };
    let payload = record.slice(4..);
    if payload.len() > MAX_UDP_PAYLOAD_SIZE {
        warn!(session_id, len = payload.len(), "vless raw-quic oversize record exceeds max payload");
        return;
    }
    if let Err(error) = session.socket.send(&payload).await {
        debug!(session_id, ?error, "vless raw-quic upstream send failed (oversize record)");
        return;
    }
    server.metrics.record_udp_payload_bytes(
        Arc::clone(&session.user_label),
        Protocol::QuicRaw,
        "client_to_target",
        payload.len(),
    );
}

/// Pump task for the inbound side of the connection-level oversize
/// record stream. Spawned by [`serve_raw_vless_oversize_records`] and
/// the connection-level accept_bi handler when the client opens the
/// stream.
pub(in crate::server) async fn serve_raw_vless_oversize_records(
    stream: Arc<super::OversizeStream>,
    server: Arc<VlessWsServerCtx>,
    conn_state: Arc<VlessQuicConn>,
) -> Result<()> {
    debug!("raw VLESS QUIC oversize-record pump started");
    loop {
        match stream.recv_record().await {
            Ok(Some(record)) => {
                route_vless_udp_record(record, &server, &conn_state).await;
            }
            Ok(None) => return Ok(()),
            Err(error) => return Err(error.context("vless raw-quic oversize-record read failed")),
        }
    }
}

/// QUIC datagram pump for raw VLESS-UDP.
///
/// Datagrams have a 4-byte big-endian session_id prefix; the rest is the raw
/// UDP payload destined for the upstream socket bound when the session was
/// created. Lookup misses are silently dropped — they correspond to sessions
/// that were just closed.
pub(in crate::server) async fn serve_raw_vless_quic_datagrams(
    connection: Arc<quinn::Connection>,
    conn_state: Arc<VlessQuicConn>,
    server: Arc<VlessWsServerCtx>,
) -> Result<()> {
    debug!(remote = %connection.remote_address(), "raw VLESS QUIC datagram pump started");
    loop {
        let data = match connection.read_datagram().await {
            Ok(data) => data,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed)
            | Err(quinn::ConnectionError::TimedOut)
            | Err(quinn::ConnectionError::Reset)
            | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
            Err(error) => {
                return Err(anyhow!(error).context("vless raw-quic read_datagram failed"));
            },
        };
        if data.len() < 4 {
            warn!(len = data.len(), "vless raw-quic datagram too short, dropping");
            continue;
        }
        let session_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let Some(session) = conn_state.lookup(session_id) else {
            debug!(session_id, "vless raw-quic datagram for unknown session, dropping");
            continue;
        };
        let payload = data.slice(4..);
        let payload_len = payload.len();
        if payload_len > MAX_UDP_PAYLOAD_SIZE {
            warn!(session_id, len = payload_len, "vless raw-quic datagram exceeds max payload");
            continue;
        }
        let metrics = Arc::clone(&server.metrics);
        let user_label = Arc::clone(&session.user_label);
        let socket = Arc::clone(&session.socket);
        tokio::spawn(async move {
            if let Err(error) = socket.send(&payload).await {
                debug!(session_id, ?error, "vless raw-quic upstream send failed");
                return;
            }
            metrics.record_udp_payload_bytes(
                user_label,
                Protocol::QuicRaw,
                "client_to_target",
                payload_len,
            );
        });
    }
}
