//! Cross-protocol session resumption: one account reached over two proxy
//! protocols.
//!
//! A single `[[users]]` entry carries both a `password` (Shadowsocks) and a
//! `vless_id` (VLESS), and both wires park and resume under that entry's `id`.
//! A client whose uplink rerolls its active wire — `shuffle_wires` over a set
//! mixing `ss_ws` / `ss_xhttp` with `vless_ws` / `vless_xhttp` — therefore
//! presents the same Session ID under whichever protocol it landed on. The
//! session has to survive that, exactly as it survives an H1 → H2 transport
//! switch within one protocol.
//!
//! The load-bearing signal is the echo target's accept counter, as everywhere
//! else in this directory: `1` means the parked upstream was reattached, `2`
//! means the server gave up and dialled afresh.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Result, bail};
use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use super::super::super::setup::VlessUserRoute;
use super::{
    ResumptionTestServer, connect_ws_h1, expect_binary_reply, spawn_echo_target, spawn_test_server,
    ss::ss_handshake_frame, vless::vless_tcp_request,
};
use crate::config::UserEntry;
use crate::crypto::UserKey;
use crate::protocol::vless::{VERSION as VLESS_VERSION, VlessUser};

const BOB_UUID: &str = "550e8400-e29b-41d4-a716-446655440000";
const ALICE_UUID: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

/// A user entry reachable over both protocols: SS on `/tcp` (the sample
/// config's default path) and VLESS on `/vless`. This is the fleet's shape —
/// one person, four wires, two protocols.
fn dual_protocol_user(id: &str, password: &str, vless_id: &str) -> UserEntry {
    UserEntry {
        id: id.into(),
        password: Some(password.into()),
        fwmark: None,
        method: None,
        ws_path_tcp: None,
        ws_path_udp: None,
        ws_path_ss: None,
        vless_id: Some(vless_id.into()),
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        enabled: None,
        aliases: None,
    }
}

/// Boots a server whose `users` are `entries`, with every VLESS-capable entry
/// mounted on `/vless` under **its own config id** as the accounting label —
/// which is what `build_vless_user_routes` does in production, and what makes
/// the SS and VLESS legs of one account share an owner label.
async fn spawn_dual_protocol_server(
    entries: Vec<UserEntry>,
) -> Result<(ResumptionTestServer, Vec<UserKey>)> {
    use super::super::super::build_user_routes;
    use super::super::sample_config_with_users;

    let dummy_listen: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = sample_config_with_users(dummy_listen, entries);
    config.session_resumption.enabled = true;

    let vless_routes = config
        .users
        .iter()
        .filter_map(|entry| entry.vless_id.as_ref().map(|id| (entry, id)))
        .map(|(entry, vless_id)| -> Result<VlessUserRoute> {
            Ok(VlessUserRoute {
                user: VlessUser::new(
                    vless_id.clone(),
                    Arc::from(entry.id.as_str()),
                    entry.fwmark,
                    entry.build_ip_aliases()?,
                )?,
                ws_path: Arc::from("/vless"),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let ss_users = build_user_routes(&config)?
        .iter()
        .map(|route| route.user.clone())
        .collect();
    let server = spawn_test_server(config, vless_routes).await?;
    Ok((server, ss_users))
}

fn metric(rendered: &str, needle: &str) -> u64 {
    rendered
        .lines()
        .filter(|line| line.starts_with(needle))
        .filter_map(|line| line.rsplit(' ').next())
        .filter_map(|value| value.parse::<f64>().ok())
        .map(|value| value as u64)
        .sum()
}

/// The wire reroll that `shuffle_wires` performs: park over Shadowsocks, come
/// back over VLESS with the same Session ID and the same account.
///
/// Nothing in a parked byte-stream session belongs to the protocol that minted
/// it — the upstream socket halves, the acked-byte counter and the downlink
/// replay ring are all protocol-neutral, and the response framing each carrier
/// owes its client is the carrier's own business. So the park must be handed
/// over, not refused.
#[tokio::test]
async fn an_ss_park_resumes_on_a_vless_carrier() -> Result<()> {
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    let std::net::IpAddr::V4(_) = target_addr.ip() else {
        bail!("the VLESS request builder only encodes IPv4 targets");
    };
    let (server, users) =
        spawn_dual_protocol_server(vec![dual_protocol_user("bob", "secret-b", BOB_UUID)]).await?;
    let bob = users[0].clone();

    // Session #1 rides the SS wire and parks when the carrier goes away.
    let (mut socket, issued) = connect_ws_h1(server.listen_addr, "/tcp", None, true).await?;
    let session_id = issued.ok_or_else(|| anyhow::anyhow!("SS leg did not mint a Session ID"))?;
    socket
        .send(WsMessage::Binary(ss_handshake_frame(&bob, target_addr, b"ping")?))
        .await?;
    let _reply = expect_binary_reply(&mut socket).await?;
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);

    socket.close(None).await?;
    drop(socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Session #2 rides the VLESS wire of the same account, same id.
    let (mut socket2, _) =
        connect_ws_h1(server.listen_addr, "/vless", Some(session_id), true).await?;
    socket2
        .send(WsMessage::Binary(vless_tcp_request(BOB_UUID, target_addr, b"pong")?))
        .await?;
    let response_header = expect_binary_reply(&mut socket2).await?;
    assert_eq!(
        response_header.as_ref(),
        &[VLESS_VERSION, 0x00],
        "the resuming carrier owes its client a VLESS response header, whichever protocol parked \
         the session"
    );
    let echoed = expect_binary_reply(&mut socket2).await?;
    assert_eq!(echoed.as_ref(), b"pong");
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        1,
        "a VLESS carrier must reattach to the account's SS-parked upstream, not dial a fresh one"
    );

    let rendered = server.metrics.render_prometheus();
    assert_eq!(
        metric(&rendered, "outline_ss_orphan_resume_hit_total{kind=\"tcp\"}"),
        1,
        "{rendered}"
    );
    // Observable as its own series: an operator who sees continuity working
    // should be able to tell how much of it is crossing protocols, and a fleet
    // that suddenly stops crossing them has changed something.
    assert_eq!(
        metric(
            &rendered,
            "outline_ss_orphan_resume_cross_protocol_total{parked=\"ss\",resumed=\"vless\"}"
        ),
        1,
        "{rendered}"
    );

    socket2.close(None).await?;
    Ok(())
}

/// The same reroll in the other direction: park over VLESS, come back over
/// Shadowsocks. Symmetric on the fleet, so symmetric here.
#[tokio::test]
async fn a_vless_park_resumes_on_an_ss_carrier() -> Result<()> {
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    let std::net::IpAddr::V4(_) = target_addr.ip() else {
        bail!("the VLESS request builder only encodes IPv4 targets");
    };
    let (server, users) =
        spawn_dual_protocol_server(vec![dual_protocol_user("bob", "secret-b", BOB_UUID)]).await?;
    let bob = users[0].clone();

    let (mut socket, issued) = connect_ws_h1(server.listen_addr, "/vless", None, true).await?;
    let session_id =
        issued.ok_or_else(|| anyhow::anyhow!("VLESS leg did not mint a Session ID"))?;
    socket
        .send(WsMessage::Binary(vless_tcp_request(BOB_UUID, target_addr, b"ping")?))
        .await?;
    assert_eq!(expect_binary_reply(&mut socket).await?.as_ref(), &[VLESS_VERSION, 0x00]);
    assert_eq!(expect_binary_reply(&mut socket).await?.as_ref(), b"ping");
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);

    socket.close(None).await?;
    drop(socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    let (mut socket2, _) =
        connect_ws_h1(server.listen_addr, "/tcp", Some(session_id), true).await?;
    socket2
        .send(WsMessage::Binary(ss_handshake_frame(&bob, target_addr, b"pong")?))
        .await?;
    let _reply = expect_binary_reply(&mut socket2).await?;
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        1,
        "an SS carrier must reattach to the account's VLESS-parked upstream, not dial a fresh one"
    );

    let rendered = server.metrics.render_prometheus();
    assert_eq!(
        metric(&rendered, "outline_ss_orphan_resume_hit_total{kind=\"tcp\"}"),
        1,
        "{rendered}"
    );
    assert_eq!(
        metric(
            &rendered,
            "outline_ss_orphan_resume_cross_protocol_total{parked=\"vless\",resumed=\"ss\"}"
        ),
        1,
        "{rendered}"
    );

    socket2.close(None).await?;
    Ok(())
}

/// Negative control. Dropping the protocol check must not drop the identity
/// check with it: the owner check is now the only thing standing between a
/// parked session and a carrier that asks for it, so a *different* account
/// presenting the id has to miss and dial its own upstream.
///
/// Without it the two tests above would pass for the wrong reason — a resume
/// that hits for anybody is not a resume that hits for the right body.
#[tokio::test]
async fn a_vless_carrier_of_another_account_still_cannot_take_the_park() -> Result<()> {
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    let std::net::IpAddr::V4(_) = target_addr.ip() else {
        bail!("the VLESS request builder only encodes IPv4 targets");
    };
    let (server, users) = spawn_dual_protocol_server(vec![
        dual_protocol_user("bob", "secret-b", BOB_UUID),
        dual_protocol_user("alice", "secret-a", ALICE_UUID),
    ])
    .await?;
    let bob = users
        .iter()
        .find(|user| user.id() == "bob")
        .ok_or_else(|| anyhow::anyhow!("missing bob"))?
        .clone();

    // Bob parks over SS.
    let (mut socket, issued) = connect_ws_h1(server.listen_addr, "/tcp", None, true).await?;
    let session_id = issued.ok_or_else(|| anyhow::anyhow!("SS leg did not mint a Session ID"))?;
    socket
        .send(WsMessage::Binary(ss_handshake_frame(&bob, target_addr, b"ping")?))
        .await?;
    let _reply = expect_binary_reply(&mut socket).await?;
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);

    socket.close(None).await?;
    drop(socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Alice presents bob's id over VLESS. Different account, so: miss.
    let (mut socket2, _) =
        connect_ws_h1(server.listen_addr, "/vless", Some(session_id), true).await?;
    socket2
        .send(WsMessage::Binary(vless_tcp_request(ALICE_UUID, target_addr, b"pong")?))
        .await?;
    assert_eq!(expect_binary_reply(&mut socket2).await?.as_ref(), &[VLESS_VERSION, 0x00]);
    assert_eq!(expect_binary_reply(&mut socket2).await?.as_ref(), b"pong");
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        2,
        "another account presenting the id must be served a fresh upstream, never bob's park"
    );

    let rendered = server.metrics.render_prometheus();
    assert_eq!(
        metric(&rendered, "outline_ss_orphan_resume_hit_total{kind=\"tcp\"}"),
        0,
        "{rendered}"
    );
    assert_eq!(
        metric(&rendered, "outline_ss_orphan_resume_cross_protocol_total"),
        0,
        "a miss is not a crossing: nothing was handed over{rendered}"
    );

    socket2.close(None).await?;
    Ok(())
}
