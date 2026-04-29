//! Shadowsocks resumption tests — five SS-TCP scenarios plus two
//! SS-UDP scenarios. All exercise the WebSocket fast path; raw QUIC
//! lives in [`super::raw_quic`].

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::atomic::Ordering,
    time::Duration,
};

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use super::super::super::resumption::SessionId;
use super::{
    ResumptionTestServer, connect_ws_h1, connect_ws_h2, expect_binary_reply, spawn_echo_target,
    spawn_echo_udp_target, spawn_test_server,
};
use crate::config::UserEntry;
use crate::crypto::{AeadStreamEncryptor, UserKey, encrypt_udp_packet};
use crate::protocol::TargetAddr;

// ── SS-specific server fixtures ──────────────────────────────────────────────

/// Single-user SS-over-WebSocket fixture: returns a running server and
/// the bob `UserKey` used by clients to encrypt SS-AEAD traffic.
async fn spawn_ss_resumption_server(
    config_mutator: impl FnOnce(&mut crate::config::Config),
) -> Result<(ResumptionTestServer, UserKey)> {
    use super::super::super::build_user_routes;
    use super::super::sample_config;

    // sample_config picks 0.0.0.0 — but we'll override `listen` after
    // bind anyway. The address here is only used to validate the
    // config schema.
    let dummy_listen: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = sample_config(dummy_listen);
    config.session_resumption.enabled = true;
    config_mutator(&mut config);
    let user = build_user_routes(&config)?[0].user.clone();
    let server = spawn_test_server(config, Vec::new()).await?;
    Ok((server, user))
}

/// Two-user SS-over-WebSocket fixture sharing the same default `/tcp`
/// path. Returns `(server, alice, bob)`. Used by the owner-mismatch
/// test to demonstrate that a Session ID issued to one user cannot be
/// claimed by the other even when they sit on the same route.
async fn spawn_ss_two_user_server() -> Result<(ResumptionTestServer, UserKey, UserKey)> {
    use super::super::super::build_user_routes;
    use super::super::sample_config_with_users;

    let dummy_listen: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = sample_config_with_users(
        dummy_listen,
        vec![
            UserEntry {
                id: "alice".into(),
                password: Some("secret-a".into()),
                fwmark: None,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                vless_id: None,
                ws_path_vless: None,
                xhttp_path_vless: None,
                enabled: None,
            },
            UserEntry {
                id: "bob".into(),
                password: Some("secret-b".into()),
                fwmark: None,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                vless_id: None,
                ws_path_vless: None,
                xhttp_path_vless: None,
                enabled: None,
            },
        ],
    );
    config.session_resumption.enabled = true;
    let routes = build_user_routes(&config)?;
    let alice = routes
        .iter()
        .find(|r| r.user.id() == "alice")
        .map(|r| r.user.clone())
        .ok_or_else(|| anyhow::anyhow!("missing alice"))?;
    let bob = routes
        .iter()
        .find(|r| r.user.id() == "bob")
        .map(|r| r.user.clone())
        .ok_or_else(|| anyhow::anyhow!("missing bob"))?;
    let server = spawn_test_server(config, Vec::new()).await?;
    Ok((server, alice, bob))
}

// ── SS-specific request encoding ─────────────────────────────────────────────

/// Encrypts a single SS-AEAD chunk: target address followed by
/// `payload`. Each invocation uses a fresh encryptor (and therefore
/// a fresh random salt), matching what a real client would do for
/// every new SS session — including the resume case, where the
/// server consumes the target bytes but ignores their value.
fn ss_handshake_frame(user: &UserKey, target: SocketAddr, payload: &[u8]) -> Result<Bytes> {
    let mut plaintext = TargetAddr::Socket(target).encode()?;
    plaintext.extend_from_slice(payload);
    let mut encryptor = AeadStreamEncryptor::new(user, None)?;
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(&plaintext, &mut buf)?;
    Ok(buf.freeze())
}

// ── SS-TCP tests ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn ss_resume_hit_skips_fresh_upstream() -> Result<()> {
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    let (server, user) = spawn_ss_resumption_server(|_| {}).await?;

    // Session #1: capable, no resume → minted ID, fresh upstream.
    let (mut socket, issued) = connect_ws_h1(server.listen_addr, "/tcp", None, true).await?;
    let session_id = issued.ok_or_else(|| {
        anyhow::anyhow!("server did not issue X-Outline-Session despite Resume-Capable")
    })?;
    socket
        .send(WsMessage::Binary(ss_handshake_frame(&user, target_addr, b"ping1")?))
        .await?;
    let _reply = expect_binary_reply(&mut socket).await?;
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);

    socket.close(None).await?;
    drop(socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Session #2: capable + resume. Should re-attach to parked
    // upstream — counter must remain 1.
    let (mut socket2, _) =
        connect_ws_h1(server.listen_addr, "/tcp", Some(session_id), true).await?;
    socket2
        .send(WsMessage::Binary(ss_handshake_frame(&user, target_addr, b"ping2")?))
        .await?;
    let _reply2 = expect_binary_reply(&mut socket2).await?;
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        1,
        "resume hit must reuse parked upstream"
    );

    socket2.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn ss_resume_with_unknown_id_falls_through_to_fresh() -> Result<()> {
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    let (server, user) = spawn_ss_resumption_server(|_| {}).await?;

    // Bogus ID never minted → miss → fresh connect.
    let bogus = SessionId::from_bytes([0xDE; 16]);
    let (mut socket, _) = connect_ws_h1(server.listen_addr, "/tcp", Some(bogus), true).await?;
    socket
        .send(WsMessage::Binary(ss_handshake_frame(&user, target_addr, b"hello")?))
        .await?;
    let _reply = expect_binary_reply(&mut socket).await?;
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);

    socket.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn ss_resume_owner_mismatch_does_not_leak_session_to_other_user() -> Result<()> {
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    let (server, alice, bob) = spawn_ss_two_user_server().await?;

    // Alice opens, gets a Session ID, closes — server parks under alice.
    let (mut alice_socket, alice_issued) =
        connect_ws_h1(server.listen_addr, "/tcp", None, true).await?;
    let alice_id = alice_issued
        .ok_or_else(|| anyhow::anyhow!("server didn't mint Session ID for Alice"))?;
    alice_socket
        .send(WsMessage::Binary(ss_handshake_frame(&alice, target_addr, b"a-ping")?))
        .await?;
    let _ = expect_binary_reply(&mut alice_socket).await?;
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);
    alice_socket.close(None).await?;
    drop(alice_socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Bob attempts to claim Alice's parked session. Owner-check rejects
    // it; the relay falls through to a fresh connect to upstream. The
    // parked entry is left in the registry for Alice to reclaim later.
    let (mut bob_socket, _) =
        connect_ws_h1(server.listen_addr, "/tcp", Some(alice_id), true).await?;
    bob_socket
        .send(WsMessage::Binary(ss_handshake_frame(&bob, target_addr, b"b-ping")?))
        .await?;
    let _ = expect_binary_reply(&mut bob_socket).await?;
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        2,
        "owner mismatch must NOT hand Alice's parked upstream to Bob"
    );
    bob_socket.close(None).await?;
    drop(bob_socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Alice can still reclaim her parked session — owner-mismatch
    // must have re-inserted it instead of evicting.
    let (mut alice_socket2, _) =
        connect_ws_h1(server.listen_addr, "/tcp", Some(alice_id), true).await?;
    alice_socket2
        .send(WsMessage::Binary(ss_handshake_frame(&alice, target_addr, b"a-resume")?))
        .await?;
    let _ = expect_binary_reply(&mut alice_socket2).await?;
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        2,
        "Alice should still be able to resume her own parked session"
    );
    alice_socket2.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn ss_resume_across_h1_to_h2_transport_switch() -> Result<()> {
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    let (server, user) = spawn_ss_resumption_server(|_| {}).await?;

    // Session #1 over HTTP/1.
    let (mut h1_socket, h1_issued) = connect_ws_h1(server.listen_addr, "/tcp", None, true).await?;
    let session_id = h1_issued
        .ok_or_else(|| anyhow::anyhow!("HTTP/1 server didn't mint Session ID"))?;
    h1_socket
        .send(WsMessage::Binary(ss_handshake_frame(&user, target_addr, b"h1-ping")?))
        .await?;
    let _ = expect_binary_reply(&mut h1_socket).await?;
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);
    h1_socket.close(None).await?;
    drop(h1_socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Session #2 over HTTP/2 — the cross-transport path the feature
    // is designed for. Server should re-attach the parked upstream.
    let (mut h2_socket, h2_outcome) =
        connect_ws_h2(server.listen_addr, "/tcp", Some(session_id), true).await?;
    assert!(
        h2_outcome.issued_session_id.is_some(),
        "H2 reply must still echo a Session ID even on resume"
    );
    h2_socket
        .send(WsMessage::Binary(ss_handshake_frame(&user, target_addr, b"h2-ping")?))
        .await?;
    let _ = expect_binary_reply(&mut h2_socket).await?;
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        1,
        "resume across H1→H2 must reuse the parked upstream"
    );
    h2_socket.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn ss_resume_after_ttl_expiry_falls_through_to_fresh() -> Result<()> {
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    // Force a short TTL so we don't have to wait for the default 30 s.
    let (server, user) = spawn_ss_resumption_server(|cfg| {
        cfg.session_resumption.orphan_ttl_tcp_secs = 1;
    })
    .await?;

    // Session #1: dial, park.
    let (mut socket, issued) = connect_ws_h1(server.listen_addr, "/tcp", None, true).await?;
    let session_id = issued.ok_or_else(|| anyhow::anyhow!("server didn't mint a Session ID"))?;
    socket
        .send(WsMessage::Binary(ss_handshake_frame(&user, target_addr, b"hi")?))
        .await?;
    let _ = expect_binary_reply(&mut socket).await?;
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);
    socket.close(None).await?;
    drop(socket);

    // Wait past the per-kind TTL. `take_for_resume` checks the
    // deadline directly; we don't need the periodic sweeper to run.
    tokio::time::sleep(Duration::from_millis(1_300)).await;

    let (mut socket2, _) =
        connect_ws_h1(server.listen_addr, "/tcp", Some(session_id), true).await?;
    socket2
        .send(WsMessage::Binary(ss_handshake_frame(&user, target_addr, b"hi-again")?))
        .await?;
    let _ = expect_binary_reply(&mut socket2).await?;
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        2,
        "expired entry must be ignored and the relay must open a fresh upstream"
    );
    socket2.close(None).await?;
    Ok(())
}

// ── SS-UDP tests ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn ss_udp_resume_across_h1_to_h2_transport_switch() -> Result<()> {
    // Cross-transport variant of `ss_udp_resume_hit_reattaches_parked_nat_entry`:
    // park the SS-UDP NAT entry on an HTTP/1 stream, then resume it
    // through an HTTP/2 (RFC 8441) Extended CONNECT stream. The
    // upstream NAT entry must be re-pointed at the H2 sender — no
    // fresh ephemeral port allocation.
    //
    // This is the original motivating scenario for the whole feature
    // (intermittent UDP path between two VMs forces clients to drop
    // QUIC / H3 and fall back to TCP-based H2 transport while the
    // session continues).
    let (target_addr, sources) = spawn_echo_udp_target().await?;
    let (server, user) = spawn_ss_resumption_server(|_| {}).await?;

    // Session #1 over HTTP/1.
    let (mut h1_socket, h1_issued) = connect_ws_h1(server.listen_addr, "/udp", None, true).await?;
    let session_id = h1_issued
        .ok_or_else(|| anyhow::anyhow!("HTTP/1 SS-UDP server didn't mint Session ID"))?;
    let mut plaintext = TargetAddr::Socket(target_addr).encode()?;
    plaintext.extend_from_slice(b"udp-h1");
    let ciphertext = encrypt_udp_packet(&user, &plaintext)?;
    h1_socket.send(WsMessage::Binary(ciphertext.into())).await?;
    let _ = expect_binary_reply(&mut h1_socket).await?;
    assert_eq!(sources.lock().await.len(), 1);

    h1_socket.close(None).await?;
    drop(h1_socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Session #2 over HTTP/2 on the same /udp path.
    let (mut h2_socket, h2_outcome) =
        connect_ws_h2(server.listen_addr, "/udp", Some(session_id), true).await?;
    assert!(
        h2_outcome.issued_session_id.is_some(),
        "H2 SS-UDP reply must still echo a Session ID even on resume"
    );

    let mut plaintext = TargetAddr::Socket(target_addr).encode()?;
    plaintext.extend_from_slice(b"udp-h2");
    let ciphertext = encrypt_udp_packet(&user, &plaintext)?;
    h2_socket.send(WsMessage::Binary(ciphertext.into())).await?;
    let _ = expect_binary_reply(&mut h2_socket).await?;

    assert_eq!(
        sources.lock().await.len(),
        1,
        "ss-udp resume across H1→H2 must reuse the parked NAT entry — fresh source port indicates miss"
    );

    h2_socket.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn ss_udp_resume_hit_reattaches_parked_nat_entry() -> Result<()> {
    // SS UDP through WebSocket: each client packet is an independent
    // SS-AEAD-encrypted datagram carrying its own target inline. The
    // server lazy-creates one NAT entry per `(user, fwmark, target)`
    // and registers this WS stream as the active outbound responder.
    // On resume, every NAT key the parked stream owned is re-pointed
    // at the new sender — without re-binding any upstream socket.
    //
    // The probe is the upstream socket's view of unique source
    // addresses: one parked NAT entry stays at cardinality 1 across
    // the reconnect, while a missed resume would cause the server to
    // bind a fresh ephemeral socket on the second packet (cardinality
    // 2).
    let (target_addr, sources) = spawn_echo_udp_target().await?;
    let (server, user) = spawn_ss_resumption_server(|_| {}).await?;

    // ── Session #1: dial /udp, push one encrypted datagram, expect
    //               an encrypted reply back. ──────────────────────
    let (mut socket, issued) = connect_ws_h1(server.listen_addr, "/udp", None, true).await?;
    let session_id = issued
        .ok_or_else(|| anyhow::anyhow!("ss-udp server didn't mint Session ID"))?;

    let mut plaintext = TargetAddr::Socket(target_addr).encode()?;
    plaintext.extend_from_slice(b"udp1");
    let ciphertext = encrypt_udp_packet(&user, &plaintext)?;
    socket.send(WsMessage::Binary(ciphertext.into())).await?;

    let _reply = expect_binary_reply(&mut socket).await?;
    assert_eq!(sources.lock().await.len(), 1);

    socket.close(None).await?;
    drop(socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // ── Session #2: resume. Server's `attempt_ss_udp_resume` must
    //               re-point the parked NAT entry at the new
    //               outbound channel before this packet is sent
    //               upstream — so the source port stays the same. ──
    let (mut socket2, _) =
        connect_ws_h1(server.listen_addr, "/udp", Some(session_id), true).await?;
    let mut plaintext = TargetAddr::Socket(target_addr).encode()?;
    plaintext.extend_from_slice(b"udp2");
    let ciphertext = encrypt_udp_packet(&user, &plaintext)?;
    socket2.send(WsMessage::Binary(ciphertext.into())).await?;
    let _reply = expect_binary_reply(&mut socket2).await?;

    assert_eq!(
        sources.lock().await.len(),
        1,
        "ss-udp resume must reuse the parked NAT entry — exactly one upstream source observed"
    );

    socket2.close(None).await?;
    Ok(())
}
