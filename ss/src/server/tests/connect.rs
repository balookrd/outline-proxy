use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

use super::super::DnsCache;
use super::super::connect::{connect_tcp_addrs, connect_tcp_target, sort_addrs_for_happy_eyeballs};
use crate::protocol::TargetAddr;

#[tokio::test]
async fn tcp_ipv6_loopback_smoke() -> Result<()> {
    let listener = match TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await {
        Ok(listener) => listener,
        Err(error) if ipv6_unavailable(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = [0_u8; 4];
        stream.read_exact(&mut buf).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(buf)
    });

    let target = TargetAddr::Socket(SocketAddr::from((Ipv6Addr::LOCALHOST, addr.port())));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let mut client = connect_tcp_target(dns_cache.as_ref(), &target, None, false, None).await?;
    client.write_all(b"ping").await?;

    let mut reply = [0_u8; 4];
    client.read_exact(&mut reply).await?;

    assert_eq!(&reply, b"pong");
    assert_eq!(server.await??, *b"ping");
    Ok(())
}

#[test]
fn tcp_connect_order_interleaves_ipv4_and_ipv6() {
    let ordered = sort_addrs_for_happy_eyeballs(
        &[
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 2], 443)),
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 443)),
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 11), 443)),
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
        ],
        false,
    );

    assert_eq!(
        ordered,
        vec![
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 443)),
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 2], 443)),
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 11), 443)),
        ]
    );
}

#[tokio::test]
async fn tcp_connect_tries_next_resolved_address() -> Result<()> {
    let blocked_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let blocked_addr = blocked_listener.local_addr()?;
    drop(blocked_listener);

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = [0_u8; 4];
        stream.read_exact(&mut buf).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(buf)
    });

    let mut client = connect_tcp_addrs(&[blocked_addr, addr], None, None).await?;
    client.write_all(b"ping").await?;

    let mut reply = [0_u8; 4];
    client.read_exact(&mut reply).await?;

    assert_eq!(&reply, b"pong");
    assert_eq!(server.await??, *b"ping");
    Ok(())
}

#[tokio::test]
async fn udp_ipv6_loopback_smoke() -> Result<()> {
    let echo = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await {
        Ok(s) => s,
        Err(error) if ipv6_unavailable(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let echo_addr = echo.local_addr()?;
    let server = tokio::spawn(async move {
        let mut buf = [0_u8; 64];
        let (read, peer) = echo.recv_from(&mut buf).await?;
        echo.send_to(&buf[..read], peer).await?;
        Result::<_, anyhow::Error>::Ok(buf[..read].to_vec())
    });

    let client = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await?;
    client.send_to(b"ping", echo_addr).await?;
    let mut buf = [0_u8; 64];
    let (read, source) =
        tokio::time::timeout(std::time::Duration::from_secs(2), client.recv_from(&mut buf))
            .await??;

    assert_eq!(source.ip(), Ipv6Addr::LOCALHOST);
    assert_eq!(&buf[..read], b"ping");
    assert_eq!(server.await??, b"ping");
    Ok(())
}

fn ipv6_unavailable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
    )
}
