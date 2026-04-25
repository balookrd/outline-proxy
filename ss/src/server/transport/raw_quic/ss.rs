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
};

pub(in crate::server) struct RawQuicSsCtx {
    pub(in crate::server) users: Arc<[UserKey]>,
    pub(in crate::server) services: Arc<Services>,
}

pub(in crate::server) async fn handle_raw_ss_quic_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    ctx: Arc<RawQuicSsCtx>,
) -> Result<()> {
    let session = ctx
        .services
        .metrics
        .open_websocket_session(crate::metrics::Transport::Tcp, Protocol::QuicRaw);

    let outcome = run_stream(&mut send, &mut recv, &ctx).await;
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
    ctx: &RawQuicSsCtx,
) -> Result<()> {
    let Some(handshake) = ss_tcp_handshake(recv, ctx.users.clone(), None).await? else {
        debug!("ss raw-quic stream closed before handshake completed");
        return Ok(());
    };

    let target_display = handshake.target.display_host_port();
    let connect_started = std::time::Instant::now();
    info!(user = handshake.user.id(), target = %target_display, "ss raw-quic upstream connect");

    let upstream_stream = match connect_tcp_target(
        ctx.services.dns_cache.as_ref(),
        &handshake.target,
        handshake.user.fwmark(),
        ctx.services.prefer_ipv4_upstream,
        ctx.services.outbound_ipv6.as_deref(),
    )
    .await
    {
        Ok(stream) => {
            ctx.services.metrics.record_tcp_connect(
                handshake.user.id_arc(),
                Protocol::QuicRaw,
                "success",
                connect_started.elapsed().as_secs_f64(),
            );
            stream
        },
        Err(error) => {
            ctx.services.metrics.record_tcp_connect(
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
    let metrics = ctx.services.metrics.clone();
    let relay_user_id = Arc::clone(&user_id);
    let upstream_to_client = async move {
        relay_upstream_to_client(
            upstream_reader,
            sink,
            &mut encryptor,
            metrics,
            Protocol::QuicRaw,
            relay_user_id,
        )
        .await
    };
    ctx.services
        .metrics
        .record_tcp_authenticated_session(Arc::clone(&user_id), Protocol::QuicRaw);
    let upstream_guard = ctx
        .services
        .metrics
        .open_tcp_upstream_connection(Arc::clone(&user_id), Protocol::QuicRaw);

    let client_to_upstream = relay_client_to_upstream(
        recv,
        handshake.decryptor,
        handshake.initial_payload,
        upstream_writer,
        ctx.services.metrics.clone(),
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
        let conn_for_sender = Arc::clone(&connection);
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
                    }))
                },
            )
            .await
            {
                warn!(?error, "ss raw-quic datagram handling failed");
            }
        });
    }
}

struct QuicSsResponseSender {
    connection: Arc<quinn::Connection>,
}

impl ResponseSender for QuicSsResponseSender {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        let connection = Arc::clone(&self.connection);
        Box::pin(async move { connection.send_datagram(data).is_ok() })
    }

    fn protocol(&self) -> Protocol {
        Protocol::QuicRaw
    }
}
