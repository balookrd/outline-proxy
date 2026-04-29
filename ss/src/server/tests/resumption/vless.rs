//! VLESS-over-WebSocket resumption tests: a TCP scenario, a UDP
//! scenario, and a Mux scenario. Raw QUIC lives in
//! [`super::raw_quic`].

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Result, bail};
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use super::super::super::setup::VlessUserRoute;
use super::{
    ResumptionTestServer, connect_ws_h1, expect_binary_reply, spawn_echo_target,
    spawn_echo_udp_target, spawn_test_server,
};
use crate::protocol::{
    TargetAddr,
    vless::{
        COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, VERSION as VLESS_VERSION, VlessUser, parse_uuid,
    },
    vless_mux::{
        Network as MuxNetwork, OPTION_DATA, ParsedFrame, SessionStatus, encode_frame, parse_frame,
    },
};

// ── VLESS-specific server fixture ────────────────────────────────────────────

/// VLESS-over-WebSocket fixture mounted on `/vless`. Returns the
/// running server and the parsed `VlessUser` for client-side request
/// construction.
async fn spawn_vless_resumption_server() -> Result<(ResumptionTestServer, VlessUser)> {
    use super::super::sample_config;

    let dummy_listen: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = sample_config(dummy_listen);
    config.session_resumption.enabled = true;
    let vless_user = VlessUser::new("550e8400-e29b-41d4-a716-446655440000".into(), std::sync::Arc::from("test"), None)?;
    let vless_route = VlessUserRoute {
        user: vless_user.clone(),
        ws_path: Arc::from("/vless"),
    };
    let server = spawn_test_server(config, vec![vless_route]).await?;
    Ok((server, vless_user))
}

// ── VLESS request encoding ───────────────────────────────────────────────────

/// Builds a VLESS TCP request: VERSION + UUID + opt_len(0) + cmd(TCP)
/// + port(BE16) + atype(0x01 IPv4) + IPv4 + payload. Mirrors
/// `vless_websocket_tcp_relay_smoke` in `tests/vless.rs`.
fn vless_tcp_request(
    uuid: &str,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Bytes> {
    let mut request = Vec::with_capacity(32 + payload.len());
    request.push(VLESS_VERSION);
    request.extend_from_slice(&parse_uuid(uuid)?);
    request.push(0); // opt_len: no addons
    request.push(COMMAND_TCP);
    request.extend_from_slice(&target.port().to_be_bytes());
    request.push(0x01); // IPv4
    let std::net::IpAddr::V4(ipv4) = target.ip() else {
        bail!("VLESS test request only constructs IPv4 targets");
    };
    request.extend_from_slice(&ipv4.octets());
    request.extend_from_slice(payload);
    Ok(Bytes::from(request))
}

/// Builds a VLESS UDP request: VERSION + UUID + opt_len(0) + cmd(UDP)
/// + port(BE16) + atype(0x01 IPv4) + IPv4. The first datagram payload
/// is appended length-prefixed (`len:u16 + bytes`) — same wire format
/// the server expects for subsequent datagrams.
fn vless_udp_request(uuid: &str, target: SocketAddr, payload: &[u8]) -> Result<Bytes> {
    let mut request = BytesMut::with_capacity(32 + payload.len());
    request.put_u8(VLESS_VERSION);
    request.extend_from_slice(&parse_uuid(uuid)?);
    request.put_u8(0);
    request.put_u8(COMMAND_UDP);
    request.extend_from_slice(&target.port().to_be_bytes());
    request.put_u8(0x01);
    let std::net::IpAddr::V4(ipv4) = target.ip() else {
        bail!("VLESS UDP test request only constructs IPv4 targets");
    };
    request.extend_from_slice(&ipv4.octets());
    request.put_u16(payload.len() as u16);
    request.extend_from_slice(payload);
    Ok(request.freeze())
}

/// Wraps a single UDP datagram in the 2-byte length prefix VLESS uses
/// inside the WebSocket frame stream.
fn vless_udp_datagram(payload: &[u8]) -> Bytes {
    let mut frame = BytesMut::with_capacity(2 + payload.len());
    frame.put_u16(payload.len() as u16);
    frame.extend_from_slice(payload);
    frame.freeze()
}

/// Builds the VLESS handshake bytes for the MUX command. Per mux.cool
/// the request target is the literal `v1.mux.cool` with port 0 — real
/// sub-connection targets ride inside the mux frames that follow.
fn vless_mux_request(uuid: &str) -> Result<Bytes> {
    let mut request = Vec::with_capacity(48);
    request.push(VLESS_VERSION);
    request.extend_from_slice(&parse_uuid(uuid)?);
    request.push(0);
    request.push(COMMAND_MUX);
    request.extend_from_slice(&0_u16.to_be_bytes()); // port = 0
    request.push(0x02); // atype: domain
    let domain = b"v1.mux.cool";
    request.push(domain.len() as u8);
    request.extend_from_slice(domain);
    Ok(Bytes::from(request))
}

/// Builds a mux New frame for `session_id` targeting `target` with an
/// initial TCP payload. Used by the mux resumption test to open
/// sub-connections inside an established VLESS-mux session.
fn vless_mux_new_tcp_frame(session_id: u16, target: SocketAddr, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::new();
    let target_addr = TargetAddr::Socket(target);
    encode_frame(
        &mut buf,
        session_id,
        SessionStatus::New,
        OPTION_DATA,
        Some(MuxNetwork::Tcp),
        Some(&target_addr),
        Some(payload),
    );
    buf.freeze()
}

/// Builds a mux Keep frame carrying additional payload on an existing
/// sub-connection. The target field is omitted because the
/// sub-connection's destination was already pinned at New time.
fn vless_mux_keep_frame(session_id: u16, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::new();
    encode_frame(
        &mut buf,
        session_id,
        SessionStatus::Keep,
        OPTION_DATA,
        None,
        None,
        Some(payload),
    );
    buf.freeze()
}

/// Reads mux frames off the WebSocket until it has captured one
/// inbound frame for each requested `expected_session` ID. Returns a
/// map from session_id to the frame's data payload.
///
/// The caller must specify exactly which session IDs to wait for —
/// the test treats arrival order as undefined because two upstream
/// echoes race on independent TCP sockets.
async fn collect_mux_keep_payloads<S>(
    socket: &mut S,
    expected: &[u16],
) -> Result<std::collections::HashMap<u16, Vec<u8>>>
where
    S: futures_util::Stream<
            Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    let mut payloads: std::collections::HashMap<u16, Vec<u8>> =
        std::collections::HashMap::new();
    while !expected.iter().all(|id| payloads.contains_key(id)) {
        let bytes = expect_binary_reply(socket).await?;
        let ParsedFrame { meta, data, consumed } = parse_frame(&bytes)?
            .ok_or_else(|| anyhow::anyhow!("incomplete mux frame in WS message"))?;
        if consumed != bytes.len() {
            // The server's encode_frame writes one frame per ws-binary
            // message in this codepath; if that ever stops being true
            // the test will flag it loudly.
            bail!(
                "expected exactly one mux frame per WS binary message, got {consumed} of {} bytes",
                bytes.len()
            );
        }
        if meta.status == SessionStatus::Keep
            && let Some(payload) = data
            && expected.contains(&meta.session_id)
            && !payloads.contains_key(&meta.session_id)
        {
            payloads.insert(meta.session_id, payload.to_vec());
        }
    }
    Ok(payloads)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn vless_udp_single_resume_hit_reuses_parked_socket() -> Result<()> {
    let (target_addr, sources) = spawn_echo_udp_target().await?;
    let (server, _user) = spawn_vless_resumption_server().await?;
    let uuid = "550e8400-e29b-41d4-a716-446655440000";

    // Session #1: open VLESS-UDP, send a datagram, expect the standard
    // `[VERSION, 0x00]` response header followed by the echoed
    // length-prefixed payload.
    let (mut socket, issued) = connect_ws_h1(server.listen_addr, "/vless", None, true).await?;
    let session_id =
        issued.ok_or_else(|| anyhow::anyhow!("VLESS UDP server didn't mint Session ID"))?;
    socket
        .send(WsMessage::Binary(vless_udp_request(uuid, target_addr, b"udp1")?))
        .await?;
    let header = expect_binary_reply(&mut socket).await?;
    assert_eq!(header.as_ref(), &[VLESS_VERSION, 0x00]);
    let echoed = expect_binary_reply(&mut socket).await?;
    // Server frames upstream packets the same way: `len:u16 + bytes`.
    assert_eq!(echoed.len(), 2 + 4);
    assert_eq!(&echoed[2..], b"udp1");
    assert_eq!(sources.lock().await.len(), 1);
    socket.close(None).await?;
    drop(socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Session #2: resume. Server re-attaches the parked `UdpSocket`
    // and sends another `[VERSION, 0x00]` so the client parser still
    // sees a clean handshake response. Then we push another datagram
    // through the resumed socket — the echo should arrive from the
    // *same* source port the parked socket was bound to.
    let (mut socket2, _) =
        connect_ws_h1(server.listen_addr, "/vless", Some(session_id), true).await?;
    socket2
        .send(WsMessage::Binary(vless_udp_request(uuid, target_addr, b"udp2")?))
        .await?;
    let header2 = expect_binary_reply(&mut socket2).await?;
    assert_eq!(header2.as_ref(), &[VLESS_VERSION, 0x00]);
    let echoed2 = expect_binary_reply(&mut socket2).await?;
    assert_eq!(&echoed2[2..], b"udp2");

    // Final assertion: the echo target saw datagrams from exactly one
    // source `SocketAddr` across both sessions — the parked socket
    // was the one used on resume, not a freshly bound replacement.
    assert_eq!(
        sources.lock().await.len(),
        1,
        "vless udp resume must reuse the parked upstream socket (one source port observed)"
    );

    // For good measure send a third datagram via Keep-style
    // length-prefixed framing (no VLESS handshake on already-open
    // session) — and verify the source still doesn't multiply.
    socket2
        .send(WsMessage::Binary(vless_udp_datagram(b"udp3")))
        .await?;
    let echoed3 = expect_binary_reply(&mut socket2).await?;
    assert_eq!(&echoed3[2..], b"udp3");
    assert_eq!(sources.lock().await.len(), 1);

    socket2.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn vless_mux_resume_hit_preserves_all_sub_conns() -> Result<()> {
    // Two independent TCP echo targets behind two separate mux
    // sub-connections. After park + resume both sub-conns must still
    // route to their original upstream — neither target's accept
    // counter should grow on the second WS session.
    let (target_a, accepts_a) = spawn_echo_target().await?;
    let (target_b, accepts_b) = spawn_echo_target().await?;
    let (server, _user) = spawn_vless_resumption_server().await?;
    let uuid = "550e8400-e29b-41d4-a716-446655440000";

    // ── Session #1: open mux with sub-conns 1 and 2 ────────────────
    let (mut socket, issued) = connect_ws_h1(server.listen_addr, "/vless", None, true).await?;
    let session_id = issued
        .ok_or_else(|| anyhow::anyhow!("VLESS mux server didn't mint Session ID"))?;

    // Combine the VLESS mux handshake with two mux New frames in a
    // single WS binary message, matching the smoke test's pattern.
    let mut handshake = BytesMut::from(vless_mux_request(uuid)?.as_ref());
    handshake.extend_from_slice(&vless_mux_new_tcp_frame(1, target_a, b"a-ping1"));
    handshake.extend_from_slice(&vless_mux_new_tcp_frame(2, target_b, b"b-ping1"));
    socket.send(WsMessage::Binary(handshake.freeze())).await?;

    // First binary reply is the VLESS handshake response.
    let response_header = expect_binary_reply(&mut socket).await?;
    assert_eq!(response_header.as_ref(), &[VLESS_VERSION, 0x00]);

    // Each upstream echoes its payload back — collect by session ID
    // (order is undefined since sub-conns race independently).
    let echoes = collect_mux_keep_payloads(&mut socket, &[1, 2]).await?;
    assert_eq!(echoes[&1], b"a-ping1");
    assert_eq!(echoes[&2], b"b-ping1");
    assert_eq!(accepts_a.load(Ordering::SeqCst), 1);
    assert_eq!(accepts_b.load(Ordering::SeqCst), 1);

    socket.close(None).await?;
    drop(socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // ── Session #2: resume the mux atomically. Both sub-conns must
    //               still be routed to their original targets. ────
    let (mut socket2, _) =
        connect_ws_h1(server.listen_addr, "/vless", Some(session_id), true).await?;
    socket2
        .send(WsMessage::Binary(vless_mux_request(uuid)?))
        .await?;
    let response_header = expect_binary_reply(&mut socket2).await?;
    assert_eq!(response_header.as_ref(), &[VLESS_VERSION, 0x00]);

    // Probe the resumed sub-conns with fresh Keep payloads. The
    // server should forward each into the parked upstream, and the
    // upstream should echo it straight back.
    socket2
        .send(WsMessage::Binary(vless_mux_keep_frame(1, b"a-ping2")))
        .await?;
    socket2
        .send(WsMessage::Binary(vless_mux_keep_frame(2, b"b-ping2")))
        .await?;
    let echoes = collect_mux_keep_payloads(&mut socket2, &[1, 2]).await?;
    assert_eq!(echoes[&1], b"a-ping2");
    assert_eq!(echoes[&2], b"b-ping2");

    // Critical assertion: no fresh upstream connects on resume.
    assert_eq!(
        accepts_a.load(Ordering::SeqCst),
        1,
        "mux resume must reuse parked TCP sub-conn for target A"
    );
    assert_eq!(
        accepts_b.load(Ordering::SeqCst),
        1,
        "mux resume must reuse parked TCP sub-conn for target B"
    );

    socket2.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn vless_resume_hit_skips_fresh_upstream() -> Result<()> {
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    let std::net::IpAddr::V4(_) = target_addr.ip() else {
        bail!("VLESS resume test requires an IPv4 target");
    };
    let (server, _user) = spawn_vless_resumption_server().await?;
    let uuid = "550e8400-e29b-41d4-a716-446655440000";

    // Session #1: open VLESS-WS, send handshake+payload, expect the
    // standard `[VERSION, 0x00]` response header followed by the
    // echoed payload.
    let (mut socket, issued) = connect_ws_h1(server.listen_addr, "/vless", None, true).await?;
    let session_id =
        issued.ok_or_else(|| anyhow::anyhow!("VLESS server didn't mint Session ID"))?;
    socket
        .send(WsMessage::Binary(vless_tcp_request(
            uuid, target_addr, b"ping",
        )?))
        .await?;
    let response_header = expect_binary_reply(&mut socket).await?;
    assert_eq!(response_header.as_ref(), &[VLESS_VERSION, 0x00]);
    let echoed = expect_binary_reply(&mut socket).await?;
    assert_eq!(echoed.as_ref(), b"ping");
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);
    socket.close(None).await?;
    drop(socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Session #2: resume. Server re-attaches the parked upstream and
    // emits another `[VERSION, 0x00]` so the client parser still sees
    // a valid VLESS handshake response.
    let (mut socket2, _) =
        connect_ws_h1(server.listen_addr, "/vless", Some(session_id), true).await?;
    socket2
        .send(WsMessage::Binary(vless_tcp_request(
            uuid, target_addr, b"pong",
        )?))
        .await?;
    let response_header2 = expect_binary_reply(&mut socket2).await?;
    assert_eq!(response_header2.as_ref(), &[VLESS_VERSION, 0x00]);
    let echoed2 = expect_binary_reply(&mut socket2).await?;
    assert_eq!(echoed2.as_ref(), b"pong");
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        1,
        "VLESS resume hit must reuse the parked upstream"
    );
    socket2.close(None).await?;
    Ok(())
}
