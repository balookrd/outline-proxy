//! End-to-end smoke tests for raw VLESS-over-QUIC and raw SS-over-QUIC paths.

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use arc_swap::ArcSwap;
use bytes::{BufMut, Bytes, BytesMut};
use quinn::Endpoint;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sockudo_ws::{
    Config as H3WsConfig, Http3 as H3Transport, WebSocketServer as H3WebSocketServer,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

use super::super::nat::NatTable;
use super::super::shutdown::ShutdownSignal;
use super::super::state::{
    AuthPolicy, RouteRegistry, Services, UdpServices, UserKeySlice,
};
use super::super::{DnsCache, serve_h3_server};
use crate::config::H3Alpn;
use crate::crypto::{AeadStreamDecryptor, AeadStreamEncryptor, UserKey};
use crate::metrics::Metrics;
use crate::protocol::TargetAddr;
use crate::protocol::vless::{COMMAND_TCP, COMMAND_UDP, VERSION, VlessUser, parse_uuid};
use crate::crypto::{decrypt_udp_packet, encrypt_udp_packet};

const VLESS_UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

fn raw_quic_server_tls(alpn: &[&[u8]]) -> Result<(rustls::ServerConfig, CertificateDer<'static>)> {
    super::super::ensure_rustls_provider_installed();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)?;
    tls_config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok((tls_config, cert_der))
}

/// Build a `H3WebSocketServer` that wraps a quinn endpoint with datagrams
/// enabled — required for the raw VLESS/SS UDP paths.
async fn bind_raw_quic_server(
    addr: SocketAddr,
    tls_config: rustls::ServerConfig,
) -> Result<H3WebSocketServer<H3Transport>> {
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|_| anyhow::anyhow!("invalid raw-quic test TLS config"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    let mut transport = quinn::TransportConfig::default();
    transport
        .datagram_receive_buffer_size(Some(1 << 20))
        .datagram_send_buffer_size(1 << 20);
    server_config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    Ok(H3WebSocketServer::<H3Transport>::from_endpoint(
        endpoint,
        H3WsConfig::default(),
    ))
}

fn raw_quic_client_config(
    cert_der: CertificateDer<'static>,
    alpn: &[&[u8]],
) -> Result<quinn::ClientConfig> {
    super::super::ensure_rustls_provider_installed();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der)?;
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();
    tls_config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
}

fn empty_route_registry() -> Arc<ArcSwap<RouteRegistry>> {
    Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: Arc::new(BTreeMap::new()),
    }))
}

fn empty_auth() -> Arc<AuthPolicy> {
    Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(
            Vec::<UserKey>::new().into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    })
}

fn build_services(metrics: Arc<Metrics>) -> Arc<Services> {
    Arc::new(Services::new(
        metrics,
        DnsCache::new(std::time::Duration::from_secs(30)),
        false,
        None,
        UdpServices {
            nat_table: NatTable::new(std::time::Duration::from_secs(300)),
            replay_store: super::super::replay::ReplayStore::new(
                std::time::Duration::from_secs(300),
                0,
            ),
            relay_semaphore: None,
        },
    ))
}

#[tokio::test]
async fn vless_raw_quic_tcp_relay_smoke() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(request)
    });

    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (tls_config, cert_der) = raw_quic_server_tls(&[b"vless"])?;
    let server = bind_raw_quic_server(server_addr, tls_config).await?;
    let addr = server.local_addr()?;

    let config = super::sample_config(addr);
    let metrics = Metrics::new(&config);
    let vless_user = VlessUser::new(VLESS_UUID.into(), None)?;
    let raw_vless_users: Arc<[VlessUser]> = Arc::from(vec![vless_user.clone()].into_boxed_slice());
    let raw_vless_candidates: Arc<[Arc<str>]> =
        Arc::from(vec![vless_user.label_arc()].into_boxed_slice());

    let routes = empty_route_registry();
    let services = build_services(metrics);
    let auth = empty_auth();
    let server_task = tokio::spawn(async move {
        serve_h3_server(
            server,
            routes,
            services,
            auth,
            Arc::from(vec![H3Alpn::Vless].into_boxed_slice()),
            raw_vless_users,
            raw_vless_candidates,
            Arc::from(Vec::<UserKey>::new().into_boxed_slice()),
            ShutdownSignal::never(),
        )
        .await
    });

    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(raw_quic_client_config(cert_der, &[b"vless"])?);
    let connection = endpoint.connect(addr, "localhost")?.await?;
    let (mut send, mut recv) = connection.open_bi().await?;

    let mut payload = Vec::new();
    payload.push(VERSION);
    payload.extend_from_slice(&parse_uuid(VLESS_UUID)?);
    payload.push(0); // option length
    payload.push(COMMAND_TCP);
    payload.extend_from_slice(&upstream_addr.port().to_be_bytes());
    payload.push(0x01); // ipv4
    payload.extend_from_slice(&[127, 0, 0, 1]);
    payload.extend_from_slice(b"ping");
    send.write_all(&payload).await?;

    // Response header [VERSION, 0x00] + b"pong" arrive interleaved on the
    // same stream.
    let mut header = [0_u8; 2];
    recv.read_exact(&mut header).await?;
    assert_eq!(header, [VERSION, 0x00]);

    let mut reply = [0_u8; 4];
    recv.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"pong");

    let _ = send.finish();
    assert_eq!(upstream_task.await??, *b"ping");

    server_task.abort();
    let _ = server_task.await;
    endpoint.close(0_u32.into(), b"done");
    Ok(())
}

#[tokio::test]
async fn ss_raw_quic_tcp_relay_smoke() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(request)
    });

    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (tls_config, cert_der) = raw_quic_server_tls(&[b"ss"])?;
    let server = bind_raw_quic_server(server_addr, tls_config).await?;
    let addr = server.local_addr()?;

    let config = super::sample_config(addr);
    let users = super::super::setup::build_users(&config)?;
    let user = users[0].clone();
    let metrics = Metrics::new(&config);
    let routes = empty_route_registry();
    let services = build_services(metrics);
    let auth = empty_auth();

    let server_task = tokio::spawn(async move {
        serve_h3_server(
            server,
            routes,
            services,
            auth,
            Arc::from(vec![H3Alpn::Ss].into_boxed_slice()),
            Arc::from(Vec::<VlessUser>::new().into_boxed_slice()),
            Arc::from(Vec::<Arc<str>>::new().into_boxed_slice()),
            users,
            ShutdownSignal::never(),
        )
        .await
    });

    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(raw_quic_client_config(cert_der, &[b"ss"])?);
    let connection = endpoint.connect(addr, "localhost")?.await?;
    let (mut send, mut recv) = connection.open_bi().await?;

    // Encrypt SS-AEAD: salt + chunk(target_addr || "ping") on a single QUIC
    // stream — exactly what the plain TCP listener consumes.
    let mut request = TargetAddr::Socket(upstream_addr).encode()?;
    request.extend_from_slice(b"ping");
    let mut encryptor = AeadStreamEncryptor::new(&user, None)?;
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(&request, &mut buf)?;
    send.write_all(&buf).await?;

    // Read encrypted reply; decrypt locally.
    let mut encrypted_reply = vec![0_u8; 256];
    let mut total = 0;
    while total < encrypted_reply.len() {
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            recv.read(&mut encrypted_reply[total..]),
        )
        .await??
        {
            Some(0) | None => break,
            Some(n) => {
                total += n;
                // Try to decrypt what we have; stop once we get the plaintext
                // "pong".
                let mut decryptor =
                    AeadStreamDecryptor::new(Arc::from(vec![user.clone()].into_boxed_slice()));
                decryptor.feed_ciphertext(&encrypted_reply[..total]);
                let mut plaintext = Vec::new();
                if decryptor.drain_plaintext(&mut plaintext).is_ok()
                    && plaintext.windows(4).any(|w| w == b"pong")
                {
                    break;
                }
            },
        }
    }
    let mut decryptor = AeadStreamDecryptor::new(Arc::from(vec![user.clone()].into_boxed_slice()));
    decryptor.feed_ciphertext(&encrypted_reply[..total]);
    let mut plaintext = Vec::new();
    decryptor.drain_plaintext(&mut plaintext)?;
    assert!(plaintext.windows(4).any(|w| w == b"pong"), "unexpected plaintext: {plaintext:?}");
    assert_eq!(upstream_task.await??, *b"ping");

    let _ = send.finish();
    server_task.abort();
    let _ = server_task.await;
    endpoint.close(0_u32.into(), b"done");
    Ok(())
}

fn raw_quic_client_config_with_datagrams(
    cert_der: CertificateDer<'static>,
    alpn: &[&[u8]],
) -> Result<quinn::ClientConfig> {
    let mut config = raw_quic_client_config(cert_der, alpn)?;
    let mut transport = quinn::TransportConfig::default();
    transport
        .datagram_receive_buffer_size(Some(1 << 20))
        .datagram_send_buffer_size(1 << 20);
    config.transport_config(Arc::new(transport));
    Ok(config)
}

#[tokio::test]
async fn vless_raw_quic_udp_relay_smoke() -> Result<()> {
    // Upstream UDP echo: reply with the same bytes back to sender.
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let mut buf = [0_u8; 64];
        let (n, peer) = upstream.recv_from(&mut buf).await?;
        upstream.send_to(&buf[..n], peer).await?;
        Result::<_, anyhow::Error>::Ok(buf[..n].to_vec())
    });

    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (tls_config, cert_der) = raw_quic_server_tls(&[b"vless"])?;
    let server = bind_raw_quic_server(server_addr, tls_config).await?;
    let addr = server.local_addr()?;

    let config = super::sample_config(addr);
    let metrics = Metrics::new(&config);
    let vless_user = VlessUser::new(VLESS_UUID.into(), None)?;
    let raw_vless_users: Arc<[VlessUser]> = Arc::from(vec![vless_user.clone()].into_boxed_slice());
    let raw_vless_candidates: Arc<[Arc<str>]> =
        Arc::from(vec![vless_user.label_arc()].into_boxed_slice());

    let routes = empty_route_registry();
    let services = build_services(metrics);
    let auth = empty_auth();
    let server_task = tokio::spawn(async move {
        serve_h3_server(
            server,
            routes,
            services,
            auth,
            Arc::from(vec![H3Alpn::Vless].into_boxed_slice()),
            raw_vless_users,
            raw_vless_candidates,
            Arc::from(Vec::<UserKey>::new().into_boxed_slice()),
            ShutdownSignal::never(),
        )
        .await
    });

    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(raw_quic_client_config_with_datagrams(cert_der, &[b"vless"])?);
    let connection = endpoint.connect(addr, "localhost")?.await?;

    // Open control bidi stream and send VLESS UDP request header.
    let (mut send, mut recv) = connection.open_bi().await?;
    let mut header = Vec::new();
    header.push(VERSION);
    header.extend_from_slice(&parse_uuid(VLESS_UUID)?);
    header.push(0); // option length
    header.push(COMMAND_UDP);
    header.extend_from_slice(&upstream_addr.port().to_be_bytes());
    header.push(0x01); // ipv4
    header.extend_from_slice(&[127, 0, 0, 1]);
    send.write_all(&header).await?;

    // Response: [VERSION, 0x00, session_id_4B_BE].
    let mut response = [0_u8; 6];
    recv.read_exact(&mut response).await?;
    assert_eq!(response[0], VERSION);
    assert_eq!(response[1], 0x00);
    let session_id = u32::from_be_bytes([response[2], response[3], response[4], response[5]]);

    // Send a UDP datagram via QUIC: [session_id|payload].
    let mut datagram = BytesMut::with_capacity(4 + 4);
    datagram.put_u32(session_id);
    datagram.extend_from_slice(b"ping");
    connection.send_datagram(datagram.freeze())?;

    // Receive echoed datagram back.
    let echoed = tokio::time::timeout(Duration::from_secs(3), connection.read_datagram()).await??;
    assert!(echoed.len() >= 4, "datagram too short: {}", echoed.len());
    assert_eq!(u32::from_be_bytes([echoed[0], echoed[1], echoed[2], echoed[3]]), session_id);
    assert_eq!(&echoed[4..], b"ping");

    assert_eq!(upstream_task.await??, b"ping");

    let _ = send.finish();
    server_task.abort();
    let _ = server_task.await;
    endpoint.close(0_u32.into(), b"done");
    Ok(())
}

/// End-to-end test for the VLESS UDP oversize stream-fallback. Sends a
/// payload that exceeds `Connection::max_datagram_size()` over the
/// connection-level oversize-record stream and verifies the upstream
/// echo arrives back on the same stream (triggered by the server
/// reader-task observing oversize on the response and dispatching to
/// the same OversizeStream rather than QUIC datagrams).
#[tokio::test]
async fn vless_raw_quic_udp_oversize_relay() -> Result<()> {
    // Upstream echo capable of 2 KiB packets — well over the 1200 B
    // default max_datagram_size that initial_mtu=1200 yields, so both
    // directions are forced through the oversize stream.
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let mut buf = [0_u8; 4096];
        let (n, peer) = upstream.recv_from(&mut buf).await?;
        upstream.send_to(&buf[..n], peer).await?;
        Result::<_, anyhow::Error>::Ok(buf[..n].to_vec())
    });

    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    // Server advertises BOTH `vless-mtu` and `vless`; client offers
    // only `vless-mtu` so the negotiated ALPN is unambiguous.
    let (tls_config, cert_der) = raw_quic_server_tls(&[b"vless-mtu", b"vless"])?;
    let server = bind_raw_quic_server(server_addr, tls_config).await?;
    let addr = server.local_addr()?;

    let config = super::sample_config(addr);
    let metrics = Metrics::new(&config);
    let vless_user = VlessUser::new(VLESS_UUID.into(), None)?;
    let raw_vless_users: Arc<[VlessUser]> = Arc::from(vec![vless_user.clone()].into_boxed_slice());
    let raw_vless_candidates: Arc<[Arc<str>]> =
        Arc::from(vec![vless_user.label_arc()].into_boxed_slice());

    let routes = empty_route_registry();
    let services = build_services(metrics);
    let auth = empty_auth();
    let server_task = tokio::spawn(async move {
        serve_h3_server(
            server,
            routes,
            services,
            auth,
            Arc::from(vec![H3Alpn::Vless].into_boxed_slice()),
            raw_vless_users,
            raw_vless_candidates,
            Arc::from(Vec::<UserKey>::new().into_boxed_slice()),
            ShutdownSignal::never(),
        )
        .await
    });

    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(raw_quic_client_config_with_datagrams(
        cert_der,
        &[b"vless-mtu"],
    )?);
    let connection = endpoint.connect(addr, "localhost")?.await?;

    // Step 1: open the control bidi for the UDP session and read the
    // server-allocated session_id (4-byte BE) out of the response
    // header. Identical to the non-oversize smoke test.
    let (mut ctrl_send, mut ctrl_recv) = connection.open_bi().await?;
    let mut header = Vec::new();
    header.push(VERSION);
    header.extend_from_slice(&parse_uuid(VLESS_UUID)?);
    header.push(0); // option length
    header.push(COMMAND_UDP);
    header.extend_from_slice(&upstream_addr.port().to_be_bytes());
    header.push(0x01); // ipv4
    header.extend_from_slice(&[127, 0, 0, 1]);
    ctrl_send.write_all(&header).await?;

    let mut response = [0_u8; 6];
    ctrl_recv.read_exact(&mut response).await?;
    assert_eq!(response[0], VERSION);
    assert_eq!(response[1], 0x00);
    let session_id = u32::from_be_bytes([response[2], response[3], response[4], response[5]]);

    // Step 2: open the connection-level oversize-record stream. Magic
    // prefix (8 bytes) + length-prefixed record carrying
    // [session_id_4B || payload_2048B]. The payload is well above
    // any quinn max_datagram_size we'd see locally, forcing the
    // server reader-task to also use the stream for the echoed
    // response.
    let (mut over_send, mut over_recv) = connection.open_bi().await?;
    over_send.write_all(b"OUTLINE\x01").await?;
    let payload: Vec<u8> = (0..2048u32).map(|i| (i & 0xff) as u8).collect();
    let record_len = (4 + payload.len()) as u16;
    let mut record_frame = Vec::with_capacity(2 + record_len as usize);
    record_frame.extend_from_slice(&record_len.to_be_bytes());
    record_frame.extend_from_slice(&session_id.to_be_bytes());
    record_frame.extend_from_slice(&payload);
    over_send.write_all(&record_frame).await?;

    // Step 3: upstream sees the original payload and echoes it. The
    // task asserts the body it received matches what we sent.
    let upstream_observed = upstream_task.await??;
    assert_eq!(upstream_observed, payload, "upstream payload mismatch");

    // Step 4: read the echoed record back. Server's reader-task on
    // the per-session UDP socket sees a 2048-byte response, observes
    // the oversize condition, and writes the record into the SAME
    // oversize stream (it was installed at accept_bi time on the
    // server side from our open_bi above). The first 8 bytes the
    // server writes are the symmetric magic; subsequent bytes are
    // length-prefixed records.
    let mut server_magic = [0_u8; 8];
    tokio::time::timeout(Duration::from_secs(5), over_recv.read_exact(&mut server_magic)).await??;
    assert_eq!(&server_magic, b"OUTLINE\x01");
    let mut len_buf = [0_u8; 2];
    tokio::time::timeout(Duration::from_secs(5), over_recv.read_exact(&mut len_buf)).await??;
    let echoed_len = u16::from_be_bytes(len_buf) as usize;
    assert_eq!(echoed_len, 4 + payload.len(), "echoed record length mismatch");
    let mut echoed = vec![0_u8; echoed_len];
    tokio::time::timeout(Duration::from_secs(5), over_recv.read_exact(&mut echoed)).await??;
    let echoed_session = u32::from_be_bytes([echoed[0], echoed[1], echoed[2], echoed[3]]);
    assert_eq!(echoed_session, session_id, "echoed session_id mismatch");
    assert_eq!(&echoed[4..], &payload[..], "echoed payload mismatch");

    let _ = ctrl_send.finish();
    let _ = over_send.finish();
    server_task.abort();
    let _ = server_task.await;
    endpoint.close(0_u32.into(), b"done");
    Ok(())
}

#[tokio::test]
async fn ss_raw_quic_udp_relay_smoke() -> Result<()> {
    // UDP echo upstream.
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let mut buf = [0_u8; 64];
        let (n, peer) = upstream.recv_from(&mut buf).await?;
        upstream.send_to(&buf[..n], peer).await?;
        Result::<_, anyhow::Error>::Ok(buf[..n].to_vec())
    });

    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (tls_config, cert_der) = raw_quic_server_tls(&[b"ss"])?;
    let server = bind_raw_quic_server(server_addr, tls_config).await?;
    let addr = server.local_addr()?;

    let config = super::sample_config(addr);
    let users = super::super::setup::build_users(&config)?;
    let user = users[0].clone();
    let metrics = Metrics::new(&config);
    let routes = empty_route_registry();
    let services = build_services(metrics);
    let auth = empty_auth();

    let server_task = tokio::spawn(async move {
        serve_h3_server(
            server,
            routes,
            services,
            auth,
            Arc::from(vec![H3Alpn::Ss].into_boxed_slice()),
            Arc::from(Vec::<VlessUser>::new().into_boxed_slice()),
            Arc::from(Vec::<Arc<str>>::new().into_boxed_slice()),
            users,
            ShutdownSignal::never(),
        )
        .await
    });

    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(raw_quic_client_config_with_datagrams(cert_der, &[b"ss"])?);
    let connection = endpoint.connect(addr, "localhost")?.await?;

    // Build SS-AEAD UDP packet: target_addr | "ping", then encrypt.
    let mut plaintext = TargetAddr::Socket(upstream_addr).encode()?;
    plaintext.extend_from_slice(b"ping");
    let encrypted = encrypt_udp_packet(&user, &plaintext)?;
    connection.send_datagram(Bytes::from(encrypted))?;

    // Receive encrypted reply via QUIC datagram and decrypt.
    let echoed = tokio::time::timeout(Duration::from_secs(3), connection.read_datagram()).await??;
    let packet = decrypt_udp_packet(std::slice::from_ref(&user), &echoed)?;
    let (_, consumed) = crate::protocol::parse_target_addr(&packet.payload)?
        .ok_or_else(|| anyhow::anyhow!("missing target in udp response"))?;
    assert_eq!(&packet.payload[consumed..], b"ping");
    assert_eq!(upstream_task.await??, b"ping");

    server_task.abort();
    let _ = server_task.await;
    endpoint.close(0_u32.into(), b"done");
    Ok(())
}
