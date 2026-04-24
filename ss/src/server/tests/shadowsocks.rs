use std::{net::{Ipv4Addr, SocketAddr}, sync::Arc};

use anyhow::Result;
use bytes::BytesMut;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

use super::super::{DnsCache, SsTcpCtx, SsUdpCtx, build_users, serve_ss_tcp_listener, serve_ss_udp_socket};
use super::super::nat::NatTable;
use super::super::shutdown::ShutdownSignal;
use super::sample_config;
use crate::crypto::{AeadStreamDecryptor, AeadStreamEncryptor, decrypt_udp_packet, encrypt_udp_packet};
use crate::metrics::Metrics;
use crate::protocol::TargetAddr;

#[tokio::test]
async fn plain_shadowsocks_tcp_relay_smoke() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut buf = [0_u8; 16];
        stream.read_exact(&mut buf[..4]).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(buf[..4].to_vec())
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
    let users = build_users(&config)?;
    let user = users[0].clone();
    let metrics = Metrics::new(&config);
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let ctx = SsTcpCtx {
        users,
        metrics,
        dns_cache,
        prefer_ipv4_upstream: false,
        outbound_ipv6: None,
    };
    let server = tokio::spawn(async move {
        serve_ss_tcp_listener(listener, ctx, ShutdownSignal::never()).await
    });

    let mut client = TcpStream::connect(listen_addr).await?;
    let mut request = TargetAddr::Socket(upstream_addr).encode()?;
    request.extend_from_slice(b"ping");
    let mut encryptor = AeadStreamEncryptor::new(&user, None)?;
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(&request, &mut buf)?;
    client.write_all(&buf).await?;

    let mut encrypted_reply = [0_u8; 256];
    let read =
        tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut encrypted_reply))
            .await??;
    assert!(read > 0);

    let mut decryptor = AeadStreamDecryptor::new(Arc::from(vec![user].into_boxed_slice()));
    let mut plaintext = Vec::new();
    decryptor.feed_ciphertext(&encrypted_reply[..read]);
    decryptor.drain_plaintext(&mut plaintext)?;
    assert_eq!(plaintext, b"pong");
    assert_eq!(upstream_task.await??, b"ping");

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn plain_shadowsocks_udp_relay_smoke() -> Result<()> {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let mut buf = [0_u8; 64];
        let (read, peer) = upstream.recv_from(&mut buf).await?;
        upstream.send_to(&buf[..read], peer).await?;
        Result::<_, anyhow::Error>::Ok(buf[..read].to_vec())
    });

    let listener = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
    let listen_addr = listener.local_addr()?;
    let config = sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 3000)));
    let users = build_users(&config)?;
    let user = users[0].clone();
    let metrics = Metrics::new(&config);
    let ctx = SsUdpCtx {
        users,
        metrics,
        nat_table: NatTable::new(std::time::Duration::from_secs(300)),
        replay_store: super::super::replay::ReplayStore::new(std::time::Duration::from_secs(300)),
        dns_cache: DnsCache::new(std::time::Duration::from_secs(30)),
        prefer_ipv4_upstream: false,
    };
    let server = tokio::spawn(async move {
        serve_ss_udp_socket(listener, ctx, ShutdownSignal::never()).await
    });

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let mut plaintext = TargetAddr::Socket(upstream_addr).encode()?;
    plaintext.extend_from_slice(b"ping");
    let ciphertext = encrypt_udp_packet(&user, &plaintext)?;
    client.send_to(&ciphertext, listen_addr).await?;

    let mut encrypted_reply = [0_u8; 256];
    let (read, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(&mut encrypted_reply),
    )
    .await??;

    let packet = decrypt_udp_packet(std::slice::from_ref(&user), &encrypted_reply[..read])?;
    let (target, consumed) = crate::protocol::parse_target_addr(&packet.payload)?
        .ok_or_else(|| anyhow::anyhow!("missing target in udp response"))?;
    assert_eq!(target, TargetAddr::Socket(upstream_addr));
    assert_eq!(&packet.payload[consumed..], b"ping");
    assert_eq!(upstream_task.await??, b"ping");

    server.abort();
    let _ = server.await;
    Ok(())
}
