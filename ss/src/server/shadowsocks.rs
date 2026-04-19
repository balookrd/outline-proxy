use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket, tcp::OwnedReadHalf},
    sync::Semaphore,
    time::{Duration, timeout},
};
use tracing::{debug, info, warn};

use crate::{
    crypto::{
        AeadStreamDecryptor, AeadStreamEncryptor, CryptoError, MAX_CHUNK_SIZE, UserKey,
        decrypt_udp_packet, diagnose_stream_handshake, diagnose_udp_packet,
    },
    metrics::{Metrics, Protocol, Transport},
    nat::{NatKey, NatTable, ResponseSender, UdpResponseSender},
    protocol::{TargetAddr, parse_target_addr},
};

use super::connect::{configure_tcp_stream, connect_tcp_target, resolve_udp_target};
use super::constants::{
    MAX_UDP_PAYLOAD_SIZE, SS_MAX_CONCURRENT_TCP_CONNECTIONS, SS_TCP_HANDSHAKE_TIMEOUT_SECS,
    UDP_MAX_CONCURRENT_RELAY_TASKS,
};
use super::dns_cache::DnsCache;
use super::shutdown::ShutdownSignal;
use super::transport::is_expected_ws_close;

struct DatagramResponseSender {
    socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
}

impl ResponseSender for DatagramResponseSender {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        Box::pin(async move { self.socket.send_to(&data, self.client_addr).await.is_ok() })
    }

    fn protocol(&self) -> Protocol {
        Protocol::Socket
    }
}

pub(super) async fn serve_ss_tcp_listener(
    listener: TcpListener,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
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
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) =
                handle_ss_tcp_connection(stream, users, metrics, dns_cache, prefer_ipv4_upstream)
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

struct SsHandshakeOutcome {
    user: UserKey,
    target: TargetAddr,
    initial_payload: Vec<u8>,
    decryptor: AeadStreamDecryptor,
}

async fn ss_tcp_handshake(
    client_reader: &mut OwnedReadHalf,
    users: Arc<[UserKey]>,
    peer_addr: Option<SocketAddr>,
) -> Result<Option<SsHandshakeOutcome>> {
    let mut decryptor = AeadStreamDecryptor::new(users.clone());
    let mut plaintext_buffer = Vec::with_capacity(MAX_CHUNK_SIZE);

    loop {
        let buffered_before = decryptor.buffered_data().len();
        decryptor.ciphertext_buffer_mut().reserve(MAX_CHUNK_SIZE);
        let read_fut = client_reader.read_buf(decryptor.ciphertext_buffer_mut());

        let read = match timeout(Duration::from_secs(SS_TCP_HANDSHAKE_TIMEOUT_SECS), read_fut).await {
            Ok(result) => result.context("failed to read from shadowsocks client")?,
            Err(_) => {
                let encrypted_buffered = decryptor.buffered_data();
                let handshake_attempts = (!encrypted_buffered.is_empty())
                    .then(|| diagnose_stream_handshake(users.as_ref(), encrypted_buffered));
                let authenticated_user = decryptor.user().map(|u| u.id().to_string());
                warn!(
                    peer_addr = ?peer_addr,
                    encrypted_buffered_bytes = encrypted_buffered.len(),
                    plaintext_buffer_len = plaintext_buffer.len(),
                    authenticated_user = authenticated_user.as_deref(),
                    handshake_attempts = ?handshake_attempts,
                    "socket tcp handshake timed out while waiting for a complete client request"
                );
                return Err(anyhow!(
                    "shadowsocks tcp handshake timed out (encrypted_buffered_bytes={}, plaintext_buffer_len={}, authenticated_user={:?}, handshake_attempts={:?})",
                    encrypted_buffered.len(),
                    plaintext_buffer.len(),
                    authenticated_user,
                    handshake_attempts
                ));
            },
        };

        if read == 0 {
            debug!(peer_addr = ?peer_addr, "socket tcp client closed connection");
            return Ok(None);
        }

        debug!(
            peer_addr = ?peer_addr,
            encrypted_bytes = read,
            buffered_before,
            "socket tcp received encrypted bytes"
        );
        match decryptor.drain_plaintext(&mut plaintext_buffer) {
            Ok(()) => {
                debug!(
                    peer_addr = ?peer_addr,
                    plaintext_buffer_len = plaintext_buffer.len(),
                    buffered_after = decryptor.buffered_data().len(),
                    authenticated_user = decryptor.user().map(|u| u.id()),
                    "socket tcp decrypted client bytes"
                );
            },
            Err(CryptoError::UnknownUser) => {
                debug!(
                    peer_addr = ?peer_addr,
                    buffered = decryptor.buffered_data().len(),
                    attempts = ?diagnose_stream_handshake(users.as_ref(), decryptor.buffered_data()),
                    "socket tcp authentication failed for all configured users"
                );
                return Ok(None);
            },
            Err(error) => return Err(anyhow!(error)),
        }

        let Some((target, consumed)) = parse_target_addr(&plaintext_buffer)? else {
            continue;
        };
        let Some(user) = decryptor.user().cloned() else {
            continue;
        };

        debug!(
            peer_addr = ?peer_addr,
            user = user.id(),
            cipher = user.cipher().as_str(),
            "socket tcp shadowsocks user authenticated"
        );
        debug!(
            peer_addr = ?peer_addr,
            user = user.id(),
            target = %target.display_host_port(),
            initial_payload_bytes = plaintext_buffer.len().saturating_sub(consumed),
            "socket tcp parsed target address"
        );

        plaintext_buffer.drain(..consumed);
        return Ok(Some(SsHandshakeOutcome {
            user,
            target,
            initial_payload: plaintext_buffer,
            decryptor,
        }));
    }
}

async fn handle_ss_tcp_connection(
    socket: TcpStream,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    let peer_addr = socket.peer_addr().ok();
    let (mut client_reader, client_writer) = socket.into_split();

    let Some(handshake) = ss_tcp_handshake(&mut client_reader, users, peer_addr).await? else {
        return Ok(());
    };

    let target_display = handshake.target.display_host_port();
    let connect_started = std::time::Instant::now();
    info!(
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
        super::relay::relay_upstream_to_client(
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

    let relay_result = super::relay::relay_client_to_upstream(
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

impl super::relay::UpstreamSink for SocketSink {
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
        info!(
            peer_addr = ?self.peer_addr,
            user = %self.user_id,
            target = %self.target,
            first_payload_bytes = bytes,
            "socket tcp received first upstream payload"
        );
    }

    fn on_eof_before_payload(&mut self) {
        info!(
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

pub(super) async fn serve_ss_udp_socket(
    socket: Arc<UdpSocket>,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    nat_table: Arc<NatTable>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    let mut in_flight: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
    let mut buffer = vec![0_u8; 65_535];
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                debug!("shadowsocks udp listener stopping on shutdown signal");
                return Ok(());
            }
            Some(()) = in_flight.next(), if !in_flight.is_empty() => {}
            recv = socket.recv_from(&mut buffer) => {
                let (read, client_addr) = match recv {
                    Ok(v) => v,
                    Err(error) => {
                        warn!(?error, "failed to receive shadowsocks udp packet");
                        continue;
                    }
                };
                debug!(
                    client_addr = %client_addr,
                    encrypted_bytes = read,
                    "socket udp received encrypted datagram"
                );
                if in_flight.len() >= UDP_MAX_CONCURRENT_RELAY_TASKS {
                    metrics.record_udp_relay_drop(
                        Transport::Udp,
                        Protocol::Socket,
                        "concurrency_limit",
                    );
                    warn!(%client_addr, "socket udp concurrent relay limit reached, dropping datagram");
                    continue;
                }
                let data = Bytes::copy_from_slice(&buffer[..read]);
                let users = users.clone();
                let metrics = metrics.clone();
                let nat_table = Arc::clone(&nat_table);
                let socket = Arc::clone(&socket);
                let dns_cache = Arc::clone(&dns_cache);
                in_flight.push(async move {
                    if let Err(error) = handle_ss_udp_datagram(
                        nat_table,
                        users,
                        data,
                        client_addr,
                        socket,
                        metrics,
                        dns_cache,
                        prefer_ipv4_upstream,
                    )
                    .await
                    {
                        warn!(%client_addr, ?error, "socket udp datagram relay failed");
                    }
                }.boxed());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_ss_udp_datagram(
    nat_table: Arc<NatTable>,
    users: Arc<[UserKey]>,
    data: Bytes,
    client_addr: SocketAddr,
    outbound_socket: Arc<UdpSocket>,
    metrics: Arc<Metrics>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    let started_at = std::time::Instant::now();
    let packet = match decrypt_udp_packet(users.as_ref(), &data) {
        Ok(packet) => packet,
        Err(CryptoError::UnknownUser) => {
            debug!(
                client_addr = %client_addr,
                encrypted_bytes = data.len(),
                attempts = ?diagnose_udp_packet(users.as_ref(), &data),
                "socket udp authentication failed for all configured users"
            );
            return Ok(());
        },
        Err(error) => return Err(anyhow!(error)),
    };
    let user_id = packet.user.id_arc();
    let Some((target, consumed)) = parse_target_addr(&packet.payload)? else {
        return Err(anyhow!("udp packet is missing a complete target address"));
    };
    let payload = &packet.payload[consumed..];
    let target_display = target.display_host_port();
    metrics.record_client_last_seen(Arc::clone(&user_id));
    debug!(
        user = packet.user.id(),
        cipher = packet.user.cipher().as_str(),
        client_addr = %client_addr,
        plaintext_bytes = payload.len(),
        "socket udp shadowsocks user authenticated"
    );

    let resolved =
        resolve_udp_target(dns_cache.as_ref(), &target, prefer_ipv4_upstream).await?;
    debug!(
        user = packet.user.id(),
        client_addr = %client_addr,
        target = %target_display,
        resolved = %resolved,
        plaintext_bytes = payload.len(),
        "socket udp resolved target"
    );
    info!(
        user = packet.user.id(),
        fwmark = ?packet.user.fwmark(),
        client_addr = %client_addr,
        target = %target_display,
        resolved = %resolved,
        "socket udp datagram relay"
    );

    let nat_key = NatKey {
        user_id: Arc::clone(&user_id),
        fwmark: packet.user.fwmark(),
        target: resolved,
    };
    let entry = nat_table
        .get_or_create(nat_key, &packet.user, packet.session.clone(), Arc::clone(&metrics))
        .await
        .with_context(|| format!("failed to create NAT entry for {resolved}"))?;

    entry
        .register_session(
            UdpResponseSender::new(Arc::new(DatagramResponseSender {
                socket: outbound_socket,
                client_addr,
            })),
            packet.session.clone(),
        )
        .await;

    if payload.len() > MAX_UDP_PAYLOAD_SIZE {
        metrics.record_udp_oversized_datagram_dropped(
            Arc::clone(&user_id),
            Protocol::Socket,
            "client_to_target",
        );
        warn!(
            user = packet.user.id(),
            client_addr = %client_addr,
            target = %resolved,
            plaintext_bytes = payload.len(),
            max_udp_payload_bytes = MAX_UDP_PAYLOAD_SIZE,
            "dropping oversized socket udp datagram before upstream send"
        );
        metrics.record_udp_request(
            Arc::clone(&user_id),
            Protocol::Socket,
            "error",
            started_at.elapsed().as_secs_f64(),
        );
        return Ok(());
    }
    metrics.record_udp_payload_bytes(
        Arc::clone(&user_id),
        Protocol::Socket,
        "client_to_target",
        payload.len(),
    );
    debug!(
        user = packet.user.id(),
        client_addr = %client_addr,
        target = %resolved,
        plaintext_bytes = payload.len(),
        "socket udp relaying datagram to upstream"
    );
    if let Err(error) = entry.socket().send_to(payload, resolved).await {
        metrics.record_udp_request(
            Arc::clone(&user_id),
            Protocol::Socket,
            "error",
            started_at.elapsed().as_secs_f64(),
        );
        return Err(error).with_context(|| format!("failed to send UDP datagram to {resolved}"));
    }
    entry.touch();
    metrics.record_udp_request(
        user_id,
        Protocol::Socket,
        "success",
        started_at.elapsed().as_secs_f64(),
    );

    Ok(())
}
