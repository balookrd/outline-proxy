use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::AsyncReadExt;

use socks5_proto::SOCKS_REP_SUCCESS;

use super::*;

/// A payload well past the 16 KiB starting read window, so both relay halves
/// have to iterate — and grow — instead of swallowing everything in one read.
const BULK_PAYLOAD_BYTES: usize = 1 << 20;

/// The direct relay reads into an adaptive buffer that starts at
/// [`STREAM_INITIAL_READ_CAPACITY`] rather than reserving the 64 KiB Shadowsocks
/// maximum per read. A stream read is never truncated by a short buffer — the
/// remainder stays in the socket — but only if every read loop keeps draining.
/// Push a payload many times the starting window through both directions and
/// require it back byte-for-byte.
#[tokio::test]
async fn relay_tcp_direct_streams_a_bulk_payload_without_loss() {
    // Upstream: echo everything back, then half-close so the downlink ends.
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream_listener.local_addr().unwrap().port();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let (mut read_half, mut write_half) = stream.split();
        tokio::io::copy(&mut read_half, &mut write_half).await.unwrap();
        write_half.shutdown().await.unwrap();
    });

    let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_listener_addr = client_listener.local_addr().unwrap();
    let (connect_res, accept_res) = tokio::join!(
        tokio::net::TcpStream::connect(client_listener_addr),
        client_listener.accept()
    );
    let client_side = connect_res.unwrap();
    let (server_side, _) = accept_res.unwrap();

    let target = TargetAddr::IpV4(Ipv4Addr::LOCALHOST, upstream_port);
    let dns_cache = std::sync::Arc::new(outline_transport::DnsCache::default());
    let timeouts = TcpTimeouts::DEFAULT;
    let direct_task = tokio::spawn(async move {
        relay_tcp_direct(server_side, target, None, &dns_cache, timeouts).await
    });

    let payload: Vec<u8> = (0..BULK_PAYLOAD_BYTES).map(|i| (i % 251) as u8).collect();
    let (mut client_read, mut client_write) = client_side.into_split();

    // Write and read concurrently: a serial write of the whole payload would
    // deadlock against the echoed bytes filling the socket buffers.
    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        client_write.write_all(&sent).await.unwrap();
        client_write.shutdown().await.unwrap();
    });

    let mut socks_reply = [0u8; 10];
    client_read.read_exact(&mut socks_reply).await.unwrap();
    assert_eq!(socks_reply[1], SOCKS_REP_SUCCESS, "expected SUCCESS reply");

    let mut echoed = Vec::with_capacity(BULK_PAYLOAD_BYTES);
    client_read.read_to_end(&mut echoed).await.unwrap();
    writer.await.unwrap();

    assert_eq!(echoed.len(), payload.len(), "relay truncated the stream");
    assert_eq!(echoed, payload, "relay corrupted the stream");

    assert!(direct_task.await.unwrap().is_ok());
    upstream_task.await.unwrap();
}

/// `relay_tcp_direct` must close the session with `Ok(())` once both
/// directions have been silent for `timeouts.direct_idle`.
///
/// Requires the `test-util` tokio feature (added to dev-dependencies).
/// Time is paused so the 120-second timeout fires without real waiting.
#[tokio::test(start_paused = true)]
async fn relay_tcp_direct_closes_session_after_idle_timeout() {
    // Upstream: accepts but sends nothing (simulates idle server).
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream_listener.local_addr().unwrap().port();
    let upstream_task = tokio::spawn(async move {
        let (_stream, _) = upstream_listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });

    // Plumb a loopback pair to act as the SOCKS5 client connection.
    let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_listener_addr = client_listener.local_addr().unwrap();
    let (connect_res, accept_res) = tokio::join!(
        tokio::net::TcpStream::connect(client_listener_addr),
        client_listener.accept()
    );
    let mut client_side = connect_res.unwrap();
    let (server_side, _) = accept_res.unwrap();

    let target = TargetAddr::IpV4(Ipv4Addr::LOCALHOST, upstream_port);
    let dns_cache = std::sync::Arc::new(outline_transport::DnsCache::default());
    let timeouts = TcpTimeouts::DEFAULT;
    let direct_task = tokio::spawn(async move {
        relay_tcp_direct(server_side, target, None, &dns_cache, timeouts).await
    });

    // Drain the 10-byte SOCKS5 SUCCESS reply so the client buffer stays clear.
    let mut socks_reply = [0u8; 10];
    client_side.read_exact(&mut socks_reply).await.unwrap();
    assert_eq!(socks_reply[1], SOCKS_REP_SUCCESS, "expected SUCCESS reply");

    // Advance mock time past the idle timeout and yield to let tasks run.
    tokio::time::advance(timeouts.direct_idle + Duration::from_secs(1)).await;
    // Multiple yields let the spawned select! arms process the fired timer.
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }

    assert!(direct_task.is_finished(), "relay_tcp_direct should return after idle timeout");
    let result = direct_task.await.unwrap();
    assert!(result.is_ok(), "relay_tcp_direct must return Ok(()) on idle timeout");

    upstream_task.abort();
    let _ = upstream_task.await;
}
