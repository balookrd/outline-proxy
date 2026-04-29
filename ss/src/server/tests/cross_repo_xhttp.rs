//! Cross-repo end-to-end XHTTP integration tests.
//!
//! Drives the real `outline-ws-rust` client crate (sibling repo,
//! pulled in as a dev-dep with a relative-path entry) against the
//! real `outline-ss-rust` server in a single tokio process. A
//! local TCP echo upstream stands in for the VLESS target, and the
//! client's `connect_websocket_with_resume` is the public entry —
//! the same one production callers use.
//!
//! Plain h2 over TCP is used (`http://...` URL): the client picks
//! TLS only when the URL scheme is `https`/`wss`, and the server's
//! axum stack accepts h2 prior-knowledge over plain TCP. Skipping
//! TLS keeps cert plumbing out of scope for these tests; TLS itself
//! is exercised by production deployments.
//!
//! What these tests cover that single-side mocks do not: header
//! capitalisation, edge-case parser behaviour, end-to-end framing.
//! Disagreements between the server's axum routes and the client's
//! `hyper::client::conn::http2` builder surface here.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, bail};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_tungstenite::tungstenite::protocol::Message;
use url::Url;

use outline_transport::{
    DnsCache as ClientDnsCache, TransportMode, TransportStream, connect_websocket_with_resume,
};

use super::xhttp::{build_vless_tcp_handshake, setup_xhttp_server, setup_xhttp_server_with_resumption};
use crate::protocol::vless::VERSION;

/// Drains binary frames from the client stream until the
/// accumulated payload reaches `expected` bytes (or the stream
/// ends). The server-side relay frequently splits the VLESS
/// response header and the first downlink payload into two
/// separate `push_downlink` calls, which surface as two
/// `Message::Binary` frames on the client.
async fn read_binary_until_at_least(
    stream: &mut TransportStream,
    expected: usize,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    while buf.len() < expected {
        match stream.next().await {
            Some(Ok(Message::Binary(bytes))) => buf.extend_from_slice(&bytes),
            Some(Ok(Message::Close(_))) | None => break,
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(other)) => bail!("unexpected message variant: {other:?}"),
            Some(Err(e)) => bail!("stream error: {e}"),
        }
    }
    Ok(buf)
}

#[tokio::test]
async fn cross_repo_xhttp_packet_up_h2_round_trip() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server, _registry) = setup_xhttp_server("/xh").await?;

    // The client picks TLS off `url.scheme()`; `http://` keeps the
    // dial on plain TCP h2, exercising the same `BoxedIo::Plain`
    // branch that the client's own mock test uses.
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("http://{listen_addr}/xh"))?;
    let mut stream = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH2,
        None,
        false,
        "cross-repo-test",
        None,
    )
    .await?;

    let handshake = build_vless_tcp_handshake(upstream_addr, b"ping")?;
    stream.send(Message::Binary(Bytes::from(handshake))).await?;

    let received = read_binary_until_at_least(&mut stream, 6).await?;
    assert_eq!(&received[..2], &[VERSION, 0x00], "vless response header");
    assert_eq!(&received[2..6], b"pong", "echoed payload");

    let upstream_bytes =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&upstream_bytes, b"ping");

    drop(stream);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn cross_repo_xhttp_stream_one_h2_round_trip() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server, _registry) = setup_xhttp_server("/xh").await?;

    // Stream-one is selected entirely by `?mode=stream-one` on the
    // dial URL — no second config knob, both sides parse the query.
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("http://{listen_addr}/xh?mode=stream-one"))?;
    let mut stream = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH2,
        None,
        false,
        "cross-repo-test",
        None,
    )
    .await?;

    let handshake = build_vless_tcp_handshake(upstream_addr, b"ping")?;
    stream.send(Message::Binary(Bytes::from(handshake))).await?;

    let received = read_binary_until_at_least(&mut stream, 6).await?;
    assert_eq!(&received[..2], &[VERSION, 0x00]);
    assert_eq!(&received[2..6], b"pong");

    let upstream_bytes =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&upstream_bytes, b"ping");

    drop(stream);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn cross_repo_xhttp_h2_resume_reattaches_parked_upstream() -> Result<()> {
    // Echo upstream that handles two read/reply rounds on one
    // accepted socket. Resume preserves the upstream across the
    // client A → client B switch; if it didn't, the second client's
    // `read_exact` would never fire (the upstream task only
    // accepts once, and a fresh dial would open a new TCP socket).
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut first = [0_u8; 4];
        stream.read_exact(&mut first).await?;
        stream.write_all(b"pong").await?;
        let mut second = [0_u8; 4];
        stream.read_exact(&mut second).await?;
        stream.write_all(b"ackk").await?;
        Result::<_, anyhow::Error>::Ok((first, second))
    });

    let (listen_addr, server, registry) = setup_xhttp_server_with_resumption("/xh", true).await?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("http://{listen_addr}/xh"))?;

    // ── Client A: capability advertise + first round-trip ──────
    let mut stream_a = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH2,
        None,
        false,
        "cross-repo-resume-a",
        None,
    )
    .await?;
    let token = stream_a
        .issued_session_id()
        .ok_or_else(|| anyhow::anyhow!("client A: server did not surface a resume token"))?;

    let handshake_a = build_vless_tcp_handshake(upstream_addr, b"ping")?;
    stream_a.send(Message::Binary(Bytes::from(handshake_a))).await?;
    let received_a = read_binary_until_at_least(&mut stream_a, 6).await?;
    assert_eq!(&received_a[..2], &[VERSION, 0x00]);
    assert_eq!(&received_a[2..6], b"pong");

    // The client crate has no FIN signal yet, so we drive a
    // graceful uplink-EOF straight on the session: the relay sees
    // EOF, exits, and the cleanup path parks the live upstream
    // into the orphan registry under `token`.
    let session = registry
        .first_session()
        .ok_or_else(|| anyhow::anyhow!("session A missing from registry"))?;
    session.close_uplink();
    // The relay needs a moment to wake from its uplink-park,
    // observe EOF, and shove the upstream into the orphan
    // registry. Without this sleep client B's resume can race
    // the park and miss it.
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(stream_a);

    // ── Client B: dials with the same token, expects reattach ──
    let mut stream_b = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH2,
        None,
        false,
        "cross-repo-resume-b",
        Some(token),
    )
    .await?;
    // Client B mints its own token (the server cannot tell this
    // is a resume until the VLESS handshake confirms ownership);
    // its presence is incidental for this assertion.
    let _issued_b = stream_b.issued_session_id();

    // The handshake target is irrelevant to the resume path —
    // the server uses the parked writer/reader and never reads
    // the target field — but the VLESS parser still needs a
    // syntactically valid one. Pick `helo` so the upstream task
    // can distinguish the two echoes.
    let handshake_b = build_vless_tcp_handshake(upstream_addr, b"helo")?;
    stream_b.send(Message::Binary(Bytes::from(handshake_b))).await?;
    let received_b = read_binary_until_at_least(&mut stream_b, 6).await?;
    assert_eq!(&received_b[..2], &[VERSION, 0x00]);
    assert_eq!(&received_b[2..6], b"ackk", "echo via resumed upstream");

    let (first, second) =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&first, b"ping");
    assert_eq!(&second, b"helo");

    drop(stream_b);
    server.abort();
    Ok(())
}
