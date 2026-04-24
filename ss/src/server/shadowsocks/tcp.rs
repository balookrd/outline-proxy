use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tracing::{debug, info, warn};

use crate::{
    crypto::{AeadStreamEncryptor, UserKey},
    metrics::{Metrics, Protocol},
    outbound::OutboundIpv6,
};

use super::super::{
    connect::{configure_tcp_stream, connect_tcp_target},
    constants::SS_MAX_CONCURRENT_TCP_CONNECTIONS,
    dns_cache::DnsCache,
    shutdown::ShutdownSignal,
    transport::is_expected_ws_close,
};
use super::handshake::ss_tcp_handshake;

#[allow(clippy::too_many_arguments)]
pub(in super::super) async fn serve_ss_tcp_listener(
    listener: TcpListener,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
    outbound_ipv6: Option<Arc<OutboundIpv6>>,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    let semaphore = Arc::new(Semaphore::new(SS_MAX_CONCURRENT_TCP_CONNECTIONS));
    loop {
        let (stream, peer) = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                debug!("shadowsocks tcp listener stopping on shutdown signal");
                return Ok(());
            }
            res = listener.accept() => match res {
                Ok(v) => v,
                Err(error) => {
                    warn!(?error, "failed to accept shadowsocks tcp connection");
                    continue;
                },
            },
        };
        if let Err(error) = configure_tcp_stream(&stream) {
            warn!(%peer, ?error, "failed to configure shadowsocks tcp connection");
            continue;
        }
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(%peer, "shadowsocks tcp concurrent connection limit reached, dropping connection");
                continue;
            },
        };
        let users = users.clone();
        let metrics = metrics.clone();
        let dns_cache = Arc::clone(&dns_cache);
        let outbound_ipv6 = outbound_ipv6.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_ss_tcp_connection(
                stream,
                users,
                metrics,
                dns_cache,
                prefer_ipv4_upstream,
                outbound_ipv6,
            )
            .await
            {
                if is_expected_ws_close(&error) {
                    debug!(%peer, ?error, "shadowsocks tcp connection closed abruptly");
                } else {
                    warn!(%peer, ?error, "shadowsocks tcp connection terminated with error");
                }
            }
        });
    }
}

async fn handle_ss_tcp_connection(
    socket: TcpStream,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
    outbound_ipv6: Option<Arc<OutboundIpv6>>,
) -> Result<()> {
    let peer_addr = socket.peer_addr().ok();
    let (mut client_reader, client_writer) = socket.into_split();

    let Some(handshake) = ss_tcp_handshake(&mut client_reader, users, peer_addr).await? else {
        return Ok(());
    };

    let target_display = handshake.target.display_host_port();
    let connect_started = std::time::Instant::now();
    debug!(
        peer_addr = ?peer_addr,
        user = handshake.user.id(),
        fwmark = ?handshake.user.fwmark(),
        target = %target_display,
        initial_payload_bytes = handshake.initial_payload.len(),
        "socket tcp starting upstream connect"
    );
    let upstream_stream = match connect_tcp_target(
        dns_cache.as_ref(),
        &handshake.target,
        handshake.user.fwmark(),
        prefer_ipv4_upstream,
        outbound_ipv6.as_deref(),
    )
    .await
    {
        Ok(stream) => {
            metrics.record_tcp_connect(
                handshake.user.id_arc(),
                Protocol::Socket,
                "success",
                connect_started.elapsed().as_secs_f64(),
            );
            stream
        },
        Err(error) => {
            metrics.record_tcp_connect(
                handshake.user.id_arc(),
                Protocol::Socket,
                "error",
                connect_started.elapsed().as_secs_f64(),
            );
            warn!(
                peer_addr = ?peer_addr,
                user = handshake.user.id(),
                fwmark = ?handshake.user.fwmark(),
                target = %target_display,
                connect_duration_ms = connect_started.elapsed().as_millis(),
                error = %format!("{error:#}"),
                "socket tcp upstream connect failed"
            );
            return Err(error).with_context(|| format!("failed to connect to {target_display}"));
        },
    };
    info!(
        peer_addr = ?peer_addr,
        user = handshake.user.id(),
        fwmark = ?handshake.user.fwmark(),
        target = %target_display,
        connect_duration_ms = connect_started.elapsed().as_millis(),
        "socket tcp upstream connected"
    );

    let (upstream_reader, upstream_writer) = upstream_stream.into_split();
    let mut encryptor = AeadStreamEncryptor::new(&handshake.user, handshake.decryptor.response_context())?;

    let user_id = handshake.user.id_arc();
    let sink = SocketSink {
        writer: client_writer,
        user_id: Arc::clone(&user_id),
        peer_addr,
        target: target_display,
    };
    let relay_metrics = metrics.clone();
    let relay_user_id = Arc::clone(&user_id);
    let upstream_to_client = tokio::spawn(async move {
        super::super::relay::relay_upstream_to_client(
            upstream_reader,
            sink,
            &mut encryptor,
            relay_metrics,
            Protocol::Socket,
            relay_user_id,
        )
        .await
    });
    metrics.record_tcp_authenticated_session(Arc::clone(&user_id), Protocol::Socket);
    let upstream_guard = metrics.open_tcp_upstream_connection(Arc::clone(&user_id), Protocol::Socket);

    let relay_result = super::super::relay::relay_client_to_upstream(
        client_reader,
        handshake.decryptor,
        handshake.initial_payload,
        upstream_writer,
        metrics,
        Protocol::Socket,
        user_id,
    )
    .await;

    match relay_result {
        Ok(()) => {
            upstream_to_client
                .await
                .context("socket tcp upstream relay task join failed after client eof")??;
            upstream_guard.finish();
        },
        Err(e) => {
            upstream_to_client.abort();
            return Err(e);
        },
    }
    Ok(())
}

struct SocketSink {
    writer: tokio::net::tcp::OwnedWriteHalf,
    user_id: Arc<str>,
    peer_addr: Option<SocketAddr>,
    target: String,
}

impl super::super::relay::UpstreamSink for SocketSink {
    async fn send_ciphertext(&mut self, ciphertext: Bytes) -> Result<()> {
        self.writer
            .write_all(&ciphertext)
            .await
            .context("failed to write encrypted socket payload")
    }

    async fn close(&mut self) {
        let _ = self.writer.shutdown().await;
    }

    fn on_first_payload(&mut self, bytes: usize) {
        debug!(
            peer_addr = ?self.peer_addr,
            user = %self.user_id,
            target = %self.target,
            first_payload_bytes = bytes,
            "socket tcp received first upstream payload"
        );
    }

    fn on_eof_before_payload(&mut self) {
        debug!(
            peer_addr = ?self.peer_addr,
            user = %self.user_id,
            target = %self.target,
            "socket tcp upstream closed before sending payload"
        );
    }

    fn on_chunk_encrypted(&mut self, plaintext: usize, ciphertext: usize) {
        debug!(
            user = %self.user_id,
            plaintext_bytes = plaintext,
            encrypted_bytes = ciphertext,
            "socket tcp relaying upstream bytes to client"
        );
    }
}
