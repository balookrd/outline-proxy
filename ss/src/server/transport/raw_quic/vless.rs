//! Raw VLESS over QUIC (no WebSocket, no HTTP/3 framing).
//!
//! One QUIC bidirectional stream carries one VLESS request: header at the
//! start of the stream, then the TCP target's data is spliced in both
//! directions over the same stream. UDP and MUX commands are reserved for
//! Phase 2 (UDP via QUIC datagrams; MUX is intentionally not supported on raw
//! QUIC since QUIC streams *are* the multiplex).

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use anyhow::{Context, Result, anyhow};
use bytes::{BufMut, BytesMut};
use parking_lot::RwLock;
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
    sessions: RwLock<HashMap<u32, Arc<VlessUdpSession>>>,
}

struct VlessUdpSession {
    socket: Arc<UdpSocket>,
    user_label: Arc<str>,
}

impl VlessQuicConn {
    pub(in crate::server) fn new() -> Self {
        Self {
            next_session: AtomicU32::new(1),
            sessions: RwLock::new(HashMap::new()),
        }
    }

    fn allocate_session(&self) -> u32 {
        self.next_session.fetch_add(1, Ordering::Relaxed)
    }

    fn register(&self, id: u32, session: Arc<VlessUdpSession>) {
        self.sessions.write().insert(id, session);
    }

    fn unregister(&self, id: u32) {
        self.sessions.write().remove(&id);
    }

    fn lookup(&self, id: u32) -> Option<Arc<VlessUdpSession>> {
        self.sessions.read().get(&id).cloned()
    }
}

const MAX_VLESS_HEADER_BUFFER: usize = 512;

pub(in crate::server) struct RawQuicVlessRouteCtx {
    pub(in crate::server) users: Arc<[VlessUser]>,
    pub(in crate::server) candidate_users: Arc<[Arc<str>]>,
}

pub(in crate::server) async fn handle_raw_vless_quic_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
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
    server: &VlessWsServerCtx,
    route: &RawQuicVlessRouteCtx,
    connection: &Arc<quinn::Connection>,
    conn_state: &Arc<VlessQuicConn>,
) -> Result<()> {
    // Read enough bytes from the stream to parse a VLESS request header.
    // We pull in chunks of up to MAX_VLESS_HEADER_BUFFER bytes; parsing is
    // tolerant of partial input and signals readiness via Ok(Some(_)).
    let mut header_buf = Vec::with_capacity(128);
    let request = loop {
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
        match vless::parse_request(&header_buf) {
            Ok(Some(request)) => break request,
            Ok(None) => {
                if header_buf.len() > MAX_VLESS_HEADER_BUFFER {
                    return Err(anyhow!("vless raw-quic header too large"));
                }
                continue;
            },
            Err(vless::VlessError::UnsupportedCommand(c)) => {
                return Err(anyhow!("unsupported vless command {c:#x}"));
            },
            Err(error) => return Err(anyhow!(error)),
        }
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

    // Bidirectional splice. Use two tasks so each direction gets its own
    // metric counters and so that upstream EOF closes the QUIC stream's send
    // side (and vice versa) without entangling the read loops.
    let metrics_c2t = Arc::clone(&server.metrics);
    let user_c2t = user.label_arc();
    let metrics_t2c = Arc::clone(&server.metrics);
    let user_t2c = user.label_arc();

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
            metrics_c2t.record_tcp_payload_bytes(
                Arc::clone(&user_c2t),
                Protocol::QuicRaw,
                "client_to_target",
                n,
            );
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
            metrics_t2c.record_tcp_payload_bytes(
                Arc::clone(&user_t2c),
                Protocol::QuicRaw,
                "target_to_client",
                n,
            );
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

    let metrics = Arc::clone(&server.metrics);
    let user_label = user.label_arc();
    let conn_for_reader = Arc::clone(connection);
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
            metrics.record_udp_payload_bytes(
                Arc::clone(&user_label),
                Protocol::QuicRaw,
                "target_to_client",
                n,
            );
            let mut datagram = BytesMut::with_capacity(4 + n);
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
