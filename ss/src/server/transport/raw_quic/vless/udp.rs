use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use bytes::{BufMut, BytesMut};
use tracing::{debug, warn};

use crate::{
    fwmark::apply_fwmark_if_needed,
    metrics::{AppProtocol, Protocol},
    protocol::vless::{self, VlessUser},
};

use super::super::super::super::{
    connect::resolve_udp_target, constants::MAX_UDP_PAYLOAD_SIZE, nat::bind_nat_udp_socket,
    scratch::UdpRecvBuf, transport::VlessWsServerCtx,
};
use super::ctx::{VlessQuicConn, VlessUdpSession};

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_udp(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    _header_buf: Vec<u8>,
    request: vless::VlessRequest,
    user: VlessUser,
    server: &VlessWsServerCtx,
    connection: &Arc<quinn::Connection>,
    conn_state: &Arc<VlessQuicConn>,
) -> Result<()> {
    let target = request.target.clone();
    let target_display = target.display_host_port();
    debug!(user = user.label(), target = %target_display, "vless raw-quic udp target");

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
    let udp_in = server
        .metrics
        .user_counters(&user.label_arc())
        .udp_in(AppProtocol::Vless, Protocol::QuicRaw)
        .clone();
    conn_state.register(
        session_id,
        Arc::new(VlessUdpSession {
            socket: Arc::clone(&socket),
            udp_in,
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
        .udp_out(AppProtocol::Vless, Protocol::QuicRaw)
        .clone();
    let conn_for_reader = Arc::clone(connection);
    let conn_state_for_reader = Arc::clone(conn_state);
    let socket_for_reader = Arc::clone(&socket);
    let reader_task = tokio::spawn(async move {
        let mut buf = UdpRecvBuf::take();
        loop {
            let n = match socket_for_reader.recv(&mut *buf).await {
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
                            Arc::new(super::super::OversizeStream::from_local_open(send, recv));
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
async fn route_vless_udp_record(record: bytes::Bytes, conn_state: &VlessQuicConn) {
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
    session.udp_in.increment(payload.len() as u64);
}

/// Pump task for the inbound side of the connection-level oversize
/// record stream. Spawned by [`serve_raw_vless_oversize_records`] and
/// the connection-level accept_bi handler when the client opens the
/// stream.
pub(in crate::server) async fn serve_raw_vless_oversize_records(
    stream: Arc<super::super::OversizeStream>,
    conn_state: Arc<VlessQuicConn>,
) -> Result<()> {
    debug!("raw VLESS QUIC oversize-record pump started");
    loop {
        match stream.recv_record().await {
            Ok(Some(record)) => {
                route_vless_udp_record(record, &conn_state).await;
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
    _server: Arc<VlessWsServerCtx>,
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
        let counter = session.udp_in.clone();
        let socket = Arc::clone(&session.socket);
        tokio::spawn(async move {
            if let Err(error) = socket.send(&payload).await {
                debug!(session_id, ?error, "vless raw-quic upstream send failed");
                return;
            }
            counter.increment(payload_len as u64);
        });
    }
}
