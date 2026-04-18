use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
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
    protocol::parse_target_addr,
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
                    warn!(
                        %peer,
                        error = %format!("{error:#}"),
                        "shadowsocks tcp connection terminated with error"
                    );
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
) -> Result<()> {
    let peer_addr = socket.peer_addr().ok();
    let (mut client_reader, client_writer) = socket.into_split();
    let mut client_writer = Some(client_writer);
    let mut decryptor = AeadStreamDecryptor::new(users.clone());
    let mut plaintext_buffer = Vec::with_capacity(MAX_CHUNK_SIZE);
    let mut upstream_writer = None;
    let mut upstream_to_client = None;
    let mut authenticated_user = None;
    let mut upstream_guard = None;
    let client_sent_eof;

    loop {
        let buffered_before = decryptor.buffered_data().len();
        decryptor.ciphertext_buffer_mut().reserve(MAX_CHUNK_SIZE);
        let read_fut = client_reader.read_buf(decryptor.ciphertext_buffer_mut());
        let read = if upstream_writer.is_none() {
            match timeout(Duration::from_secs(SS_TCP_HANDSHAKE_TIMEOUT_SECS), read_fut).await {
                Ok(result) => result.context("failed to read from shadowsocks client")?,
                Err(_) => {
                    let encrypted_buffered = decryptor.buffered_data();
                    let handshake_attempts = (!encrypted_buffered.is_empty())
                        .then(|| diagnose_stream_handshake(users.as_ref(), encrypted_buffered));
                    let authenticated_user = decryptor.user().map(|user| user.id().to_string());
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
            }
        } else {
            read_fut.await.context("failed to read from shadowsocks client")?
        };
        if read == 0 {
            debug!(peer_addr = ?peer_addr, "socket tcp client closed connection");
            client_sent_eof = true;
            break;
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
                    authenticated_user = decryptor.user().map(|user| user.id()),
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
                return Err(anyhow!("no configured key matched the incoming socket tcp stream"));
            },
            Err(error) => return Err(anyhow!(error)),
        }

        if upstream_writer.is_none() {
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
            let target_display = target.display_host_port();
            debug!(
                peer_addr = ?peer_addr,
                user = user.id(),
                target = %target_display,
                initial_payload_bytes = plaintext_buffer.len().saturating_sub(consumed),
                "socket tcp parsed target address"
            );
            let connect_started = std::time::Instant::now();
            info!(
                peer_addr = ?peer_addr,
                user = user.id(),
                fwmark = ?user.fwmark(),
                target = %target_display,
                initial_payload_bytes = plaintext_buffer.len().saturating_sub(consumed),
                "socket tcp starting upstream connect"
            );
            let stream = match connect_tcp_target(
                dns_cache.as_ref(),
                &target,
                user.fwmark(),
                prefer_ipv4_upstream,
            )
            .await
            {
                    Ok(stream) => {
                        metrics.record_tcp_connect(
                            user.id_arc(),
                            Protocol::Socket,
                            "success",
                            connect_started.elapsed().as_secs_f64(),
                        );
                        stream
                    },
                    Err(error) => {
                        metrics.record_tcp_connect(
                            user.id_arc(),
                            Protocol::Socket,
                            "error",
                            connect_started.elapsed().as_secs_f64(),
                        );
                        warn!(
                            peer_addr = ?peer_addr,
                            user = user.id(),
                            fwmark = ?user.fwmark(),
                            target = %target_display,
                            connect_duration_ms = connect_started.elapsed().as_millis(),
                            error = %format!("{error:#}"),
                            "socket tcp upstream connect failed"
                        );
                        return Err(error)
                            .with_context(|| format!("failed to connect to {target_display}"));
                    },
                };
            info!(
                peer_addr = ?peer_addr,
                user = user.id(),
                fwmark = ?user.fwmark(),
                target = %target_display,
                connect_duration_ms = connect_started.elapsed().as_millis(),
                "socket tcp upstream connected"
            );

            let (upstream_reader, writer) = stream.into_split();
            let mut encryptor = AeadStreamEncryptor::new(&user, decryptor.response_context())?;
            let client_writer = client_writer
                .take()
                .ok_or_else(|| anyhow!("socket tcp client writer missing"))?;
            let relay_metrics = metrics.clone();
            let user_id = user.id_arc();
            let relay_target_display = target_display.clone();
            upstream_to_client = Some(tokio::spawn(async move {
                relay_upstream_to_socket_client(
                    upstream_reader,
                    client_writer,
                    &mut encryptor,
                    relay_metrics,
                    user_id,
                    peer_addr,
                    relay_target_display,
                )
                .await
            }));
            metrics.record_tcp_authenticated_session(user.id_arc(), Protocol::Socket);
            upstream_guard =
                Some(metrics.open_tcp_upstream_connection(user.id_arc(), Protocol::Socket));
            authenticated_user = Some(user);
            upstream_writer = Some(writer);
            plaintext_buffer.drain(..consumed);
        }

        if let Some(writer) = &mut upstream_writer
            && !plaintext_buffer.is_empty()
        {
            if let Some(user) = &authenticated_user {
                metrics.record_tcp_payload_bytes(
                    user.id_arc(),
                    Protocol::Socket,
                    "client_to_target",
                    plaintext_buffer.len(),
                );
                debug!(
                    peer_addr = ?peer_addr,
                    user = user.id(),
                    plaintext_bytes = plaintext_buffer.len(),
                    "socket tcp relaying plaintext to upstream"
                );
            }
            writer
                .write_all(&plaintext_buffer)
                .await
                .context("failed to write decrypted data upstream")?;
            plaintext_buffer.clear();
        }
    }

    if let Some(mut writer) = upstream_writer {
        writer.shutdown().await.ok();
    }

    if let Some(task) = upstream_to_client {
        if client_sent_eof {
            task.await
                .context("socket tcp upstream relay task join failed after client eof")??;
        } else {
            task.abort();
        }
    }

    if let Some(guard) = upstream_guard {
        guard.finish();
    }
    Ok(())
}

async fn relay_upstream_to_socket_client(
    mut upstream_reader: tokio::net::tcp::OwnedReadHalf,
    mut client_writer: tokio::net::tcp::OwnedWriteHalf,
    encryptor: &mut AeadStreamEncryptor,
    metrics: Arc<Metrics>,
    user_id: Arc<str>,
    peer_addr: Option<SocketAddr>,
    target: String,
) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(MAX_CHUNK_SIZE);
    let mut saw_payload = false;
    loop {
        buffer.clear();
        buffer.reserve(MAX_CHUNK_SIZE);
        let read = upstream_reader
            .read_buf(&mut buffer)
            .await
            .context("failed to read from upstream")?;
        if read == 0 {
            if !saw_payload {
                info!(
                    peer_addr = ?peer_addr,
                    user = %user_id,
                    target = %target,
                    "socket tcp upstream closed before sending payload"
                );
            }
            break;
        }
        if !saw_payload {
            saw_payload = true;
            info!(
                peer_addr = ?peer_addr,
                user = %user_id,
                target = %target,
                first_payload_bytes = read,
                "socket tcp received first upstream payload"
            );
        }

        metrics.record_tcp_payload_bytes(
            Arc::clone(&user_id),
            Protocol::Socket,
            "target_to_client",
            read,
        );
        let ciphertext = encryptor.encrypt_chunk(&buffer)?;
        debug!(
            user = %user_id,
            plaintext_bytes = read,
            encrypted_bytes = ciphertext.len(),
            "socket tcp relaying upstream bytes to client"
        );
        client_writer
            .write_all(&ciphertext)
            .await
            .context("failed to write encrypted socket payload")?;
    }

    client_writer.shutdown().await.ok();
    Ok(())
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
            return Err(anyhow!("no configured key matched the incoming socket udp datagram"));
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
        udp_client_session_id: packet.session.client_session_id(),
    };
    let entry = nat_table
        .get_or_create(nat_key, &packet.user, packet.session.clone(), Arc::clone(&metrics))
        .await
        .with_context(|| format!("failed to create NAT entry for {resolved}"))?;

    entry
        .register_session(UdpResponseSender::new(Arc::new(DatagramResponseSender {
            socket: outbound_socket,
            client_addr,
        })))
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
