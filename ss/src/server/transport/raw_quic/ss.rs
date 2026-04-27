//! Raw Shadowsocks (AEAD) over QUIC bidirectional streams.
//!
//! One bidi stream = one Shadowsocks TCP session. The client writes a normal
//! Shadowsocks AEAD ciphertext into the QUIC send stream (salt, target
//! address chunk, then payload chunks); we authenticate the user by trying to
//! decrypt the first chunk against every configured key, just like the plain
//! TCP listener does. Streams are spliced bidirectionally; the encryption
//! state machine is identical to the [`crate::server::shadowsocks::tcp`] path.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use tracing::{debug, info, warn};

use crate::{
    crypto::{AeadStreamEncryptor, UserKey},
    metrics::Protocol,
};

use super::super::super::{
    connect::connect_tcp_target,
    nat::{ResponseSender, UdpResponseSender},
    relay::{UpstreamSink, relay_client_to_upstream, relay_upstream_to_client},
    shadowsocks::{SsUdpClientId, SsUdpCtx, handle_ss_udp_packet, ss_tcp_handshake},
    state::Services,
    transport::sink,
};

pub(in crate::server) struct RawQuicSsCtx {
    pub(in crate::server) users: Arc<[UserKey]>,
    pub(in crate::server) services: Arc<Services>,
}

/// Per-QUIC-connection state for raw SS — tracks the lazily-opened
/// oversize-record stream so server→client oversized SS-UDP packets
/// can fall back to it instead of being dropped.
pub(in crate::server) struct SsQuicConn {
    pub(in crate::server) oversize_slot: super::OversizeStreamSlot,
}

impl SsQuicConn {
    pub(in crate::server) fn new() -> Self {
        Self {
            oversize_slot: super::OversizeStreamSlot::new(),
        }
    }
}

#[allow(dead_code)]
pub(in crate::server) async fn handle_raw_ss_quic_stream(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    ctx: Arc<RawQuicSsCtx>,
) -> Result<()> {
    handle_raw_ss_quic_stream_with_prefix(send, recv, Vec::new(), ctx).await
}

/// Same as [`handle_raw_ss_quic_stream`] but accepts a `prefix` of
/// bytes already read off the recv stream by the caller (typically
/// the 8 bytes peeked to disambiguate the oversize-record magic from
/// an SS-TCP request stream's salt). The handler chains the prefix
/// onto the recv side via tokio's read-chain so the SS-AEAD decryptor
/// sees the original byte stream.
pub(in crate::server) async fn handle_raw_ss_quic_stream_with_prefix(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    prefix: Vec<u8>,
    ctx: Arc<RawQuicSsCtx>,
) -> Result<()> {
    let session = ctx
        .services
        .tcp_server
        .metrics
        .open_websocket_session(crate::metrics::Transport::Tcp, Protocol::QuicRaw);

    let outcome = run_stream(&mut send, &mut recv, prefix, &ctx).await;
    let outcome_for_metrics = match &outcome {
        Ok(()) => crate::metrics::DisconnectReason::Normal,
        Err(error) if sink::is_handshake_rejected(error) => {
            crate::metrics::DisconnectReason::HandshakeRejected
        },
        Err(_) => crate::metrics::DisconnectReason::Error,
    };
    session.finish(outcome_for_metrics);
    outcome
}

async fn run_stream(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    prefix: Vec<u8>,
    ctx: &RawQuicSsCtx,
) -> Result<()> {
    // If the caller pre-read bytes off the recv stream (the 8-byte
    // oversize-magic peek that turned out NOT to match), splice them
    // back in front of the stream for the SS handshake decryptor.
    // The chain adapter exposes Cursor(prefix) ++ recv as a single
    // AsyncRead; once the cursor is exhausted, reads pass through
    // to recv directly. The chain's into_inner gives the recv stream
    // back so the subsequent client→upstream relay still drives recv
    // (no copy through chain wrapping after handshake).
    let outcome = if prefix.is_empty() {
        ss_tcp_handshake(recv, ctx.users.clone(), None).await?
    } else {
        use tokio::io::AsyncReadExt;
        let mut chained = std::io::Cursor::new(prefix).chain(&mut *recv);
        ss_tcp_handshake(&mut chained, ctx.users.clone(), None).await?
    };
    let Some(handshake) = outcome else {
        debug!("ss raw-quic stream closed before handshake completed");
        // Probe-resistance: same as the plain-TCP path — sink any further
        // bytes from the peer until the handshake-equivalent timeout (or
        // the byte cap) instead of hanging up immediately, so an active
        // probe cannot fingerprint SS by the close timing. We return an
        // Err carrying [`HandshakeRejectedMarker`] so the session guard
        // attributes the close to `DisconnectReason::HandshakeRejected`.
        sink::sink_async_read(recv).await;
        return Err(anyhow!("ss raw-quic handshake rejected")
            .context(sink::HandshakeRejectedMarker));
    };

    let target_display = handshake.target.display_host_port();
    let connect_started = std::time::Instant::now();
    info!(user = handshake.user.id(), target = %target_display, "ss raw-quic upstream connect");

    let upstream_stream = match connect_tcp_target(
        ctx.services.tcp_server.dns_cache.as_ref(),
        &handshake.target,
        handshake.user.fwmark(),
        ctx.services.tcp_server.prefer_ipv4_upstream,
        ctx.services.tcp_server.outbound_ipv6.as_deref(),
    )
    .await
    {
        Ok(stream) => {
            ctx.services.tcp_server.metrics.record_tcp_connect(
                handshake.user.id_arc(),
                Protocol::QuicRaw,
                "success",
                connect_started.elapsed().as_secs_f64(),
            );
            stream
        },
        Err(error) => {
            ctx.services.tcp_server.metrics.record_tcp_connect(
                handshake.user.id_arc(),
                Protocol::QuicRaw,
                "error",
                connect_started.elapsed().as_secs_f64(),
            );
            warn!(
                user = handshake.user.id(),
                target = %target_display,
                error = %format!("{error:#}"),
                "ss raw-quic upstream connect failed"
            );
            let _ = send.reset(quinn::VarInt::from_u32(1));
            return Err(error)
                .with_context(|| format!("failed to connect to {target_display}"));
        },
    };

    let (upstream_reader, upstream_writer) = upstream_stream.into_split();
    let mut encryptor =
        AeadStreamEncryptor::new(&handshake.user, handshake.decryptor.response_context())?;

    let user_id = handshake.user.id_arc();
    let sink = QuicSsSink {
        send,
        user_id: Arc::clone(&user_id),
        target: target_display,
    };
    let metrics = ctx.services.tcp_server.metrics.clone();
    let relay_user_id = Arc::clone(&user_id);
    let upstream_to_client = async move {
        // Raw SS over QUIC is out of scope for resumption (see
        // docs/SESSION-RESUMPTION.md "Non-Goals"); pass `None` to keep
        // the legacy single-arm read loop and discard the outcome.
        relay_upstream_to_client(
            upstream_reader,
            sink,
            &mut encryptor,
            metrics,
            Protocol::QuicRaw,
            relay_user_id,
            None,
        )
        .await
        .map(|_| ())
    };
    ctx.services
        .tcp_server
        .metrics
        .record_tcp_authenticated_session(Arc::clone(&user_id), Protocol::QuicRaw);
    let upstream_guard = ctx
        .services
        .tcp_server
        .metrics
        .open_tcp_upstream_connection(Arc::clone(&user_id), Protocol::QuicRaw);

    let client_to_upstream = relay_client_to_upstream(
        recv,
        handshake.decryptor,
        handshake.initial_payload,
        upstream_writer,
        ctx.services.tcp_server.metrics.clone(),
        Protocol::QuicRaw,
        Arc::clone(&user_id),
    );

    let (up, down) = tokio::join!(client_to_upstream, upstream_to_client);
    upstream_guard.finish();
    match (up, down) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), _) | (_, Err(e)) => Err(e),
    }
}

struct QuicSsSink<'a> {
    send: &'a mut quinn::SendStream,
    user_id: Arc<str>,
    target: String,
}

impl<'a> UpstreamSink for QuicSsSink<'a> {
    async fn send_ciphertext(&mut self, ciphertext: Bytes) -> Result<()> {
        self.send
            .write_all(&ciphertext)
            .await
            .context("failed to write encrypted ss raw-quic payload")
    }

    async fn close(&mut self) {
        let _ = self.send.finish();
    }

    fn on_first_payload(&mut self, bytes: usize) {
        debug!(
            user = %self.user_id,
            target = %self.target,
            first_payload_bytes = bytes,
            "ss raw-quic received first upstream payload"
        );
    }
}

/// QUIC datagram pump for raw SS-UDP.
///
/// Each incoming QUIC datagram is treated as one Shadowsocks AEAD UDP packet
/// — exactly the wire format the plain UDP listener consumes — and dispatched
/// through the shared NAT layer so per-user state (NAT entries, replay store,
/// metrics) is identical regardless of transport.
pub(in crate::server) async fn serve_raw_ss_quic_datagrams(
    connection: Arc<quinn::Connection>,
    ctx: Arc<super::RawQuicSsCtx>,
    conn_state: Arc<SsQuicConn>,
) -> Result<()> {
    let remote = connection.remote_address();
    debug!(remote = %remote, "raw SS QUIC datagram pump started");
    loop {
        let data = match connection.read_datagram().await {
            Ok(data) => data,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed)
            | Err(quinn::ConnectionError::TimedOut)
            | Err(quinn::ConnectionError::Reset)
            | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
            Err(error) => return Err(anyhow!(error).context("ss raw-quic read_datagram failed")),
        };
        spawn_handle_ss_packet(data, &connection, &ctx, &conn_state, remote);
    }
}

/// Spawn the SS-UDP packet handler with a response sender wired to
/// fall back to the connection-level oversize stream when the reply
/// exceeds `max_datagram_size`. Used by both the datagram pump and
/// the oversize-record pump — they hand identical packets to the
/// same handler, only the inbound transport differs.
fn spawn_handle_ss_packet(
    data: Bytes,
    connection: &Arc<quinn::Connection>,
    ctx: &Arc<super::RawQuicSsCtx>,
    conn_state: &Arc<SsQuicConn>,
    remote: std::net::SocketAddr,
) {
    let conn_for_sender = Arc::clone(connection);
    let conn_state_for_sender = Arc::clone(conn_state);
    let ss_ctx = SsUdpCtx {
        users: Arc::clone(&ctx.users),
        services: Arc::clone(&ctx.services),
    };
    tokio::spawn(async move {
        if let Err(error) = handle_ss_udp_packet(
            &ss_ctx,
            data,
            SsUdpClientId::QuicConnection(remote),
            Protocol::QuicRaw,
            move || {
                UdpResponseSender::new(Arc::new(QuicSsResponseSender {
                    connection: conn_for_sender,
                    conn_state: conn_state_for_sender,
                }))
            },
        )
        .await
        {
            warn!(?error, "ss raw-quic datagram handling failed");
        }
    });
}

/// Pump for inbound SS-AEAD UDP packets that arrive on the
/// connection-level oversize-record stream (instead of QUIC
/// datagrams). Each record is one self-contained SS packet —
/// identical wire format to the datagram path — and is dispatched
/// through the same NAT/handler logic.
pub(in crate::server) async fn serve_raw_ss_oversize_records(
    stream: Arc<super::OversizeStream>,
    connection: Arc<quinn::Connection>,
    ctx: Arc<super::RawQuicSsCtx>,
    conn_state: Arc<SsQuicConn>,
) -> Result<()> {
    let remote = connection.remote_address();
    debug!(remote = %remote, "raw SS QUIC oversize-record pump started");
    loop {
        match stream.recv_record().await {
            Ok(Some(record)) => {
                spawn_handle_ss_packet(record, &connection, &ctx, &conn_state, remote);
            }
            Ok(None) => return Ok(()),
            Err(error) => return Err(error.context("ss raw-quic oversize-record read failed")),
        }
    }
}

struct QuicSsResponseSender {
    connection: Arc<quinn::Connection>,
    conn_state: Arc<SsQuicConn>,
}

impl ResponseSender for QuicSsResponseSender {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        let connection = Arc::clone(&self.connection);
        let conn_state = Arc::clone(&self.conn_state);
        Box::pin(async move {
            // Try the datagram path first: it's the cheap one and
            // covers the common case (SS-AEAD UDP packets are usually
            // small DNS queries / short replies).
            let oversized = connection
                .max_datagram_size()
                .is_some_and(|max| data.len() > max);
            if !oversized {
                if let Err(error) = connection.send_datagram(data) {
                    debug!(?error, "ss raw-quic send_datagram failed");
                    return false;
                }
                return true;
            }
            // Oversized response on an MTU-aware connection — fall
            // back to the oversize-record stream. Open server-side
            // if the client hasn't opened it yet (the client's
            // accept_bi loop installs symmetrically on its side).
            // On legacy `ss` ALPN this path never runs because the
            // client wouldn't have negotiated MTU support, but we
            // still need a heuristic: only attempt open_bi when the
            // negotiated ALPN advertises the fallback. The
            // connection-level handshake_data lookup is cached by
            // quinn so checking on every call is cheap.
            let mtu_aware = connection
                .handshake_data()
                .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|d| d.protocol)
                .is_some_and(|bytes| bytes == b"ss-mtu");
            if !mtu_aware {
                debug!(len = data.len(), "ss raw-quic oversize response on legacy ALPN, dropping");
                return false;
            }
            let stream = match conn_state.oversize_slot.get() {
                Some(stream) => stream,
                None => {
                    let pair = match connection.open_bi().await {
                        Ok(pair) => pair,
                        Err(error) => {
                            debug!(?error, "failed to open ss oversize stream for outbound packet");
                            return false;
                        }
                    };
                    let (send, recv) = pair;
                    let stream = Arc::new(super::OversizeStream::from_local_open(send, recv));
                    conn_state.oversize_slot.install(stream)
                }
            };
            if let Err(error) = stream.send_record(&data).await {
                debug!(?error, "ss raw-quic oversize-record send failed");
                return false;
            }
            true
        })
    }

    fn protocol(&self) -> Protocol {
        Protocol::QuicRaw
    }
}
