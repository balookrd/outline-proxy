use std::collections::HashMap;
use std::time::Duration;

use outline_wire::cluster::ShardId;
use tokio::io::AsyncWriteExt;

use super::super::endpoint::{MeshEndpoint, accept_relay};
use super::super::frame::{CarrierKind, OpenHeader};
use super::super::tls::MeshIdentity;
use super::*;

fn identity(psk: &[u8]) -> MeshIdentity {
    MeshIdentity::derive(psk).unwrap()
}

fn header() -> OpenHeader {
    OpenHeader {
        carrier: CarrierKind::VlessTcp,
        session_id: [9u8; 16],
        resume_capable: false,
        ack_prefix: false,
        symmetric_replay: false,
        client_down_acked: 0,
        path: "/vless".to_string(),
        peer_addr: None,
    }
}

fn loopback() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

#[tokio::test]
async fn open_relay_reaches_the_home_for_its_shard() {
    let psk = b"mesh-pool-psk";
    let shard = ShardId::new(3).unwrap();
    let home = MeshEndpoint::bind(loopback(), &identity(psk)).unwrap();
    let home_addr = home.local_addr().unwrap();
    let edge = MeshEndpoint::bind(loopback(), &identity(psk)).unwrap();

    let mut peers = HashMap::new();
    peers.insert(shard, home_addr);
    let pool = MeshPeerPool::new(edge, peers, 8);

    let server = async {
        let conn = home.accept().await.unwrap().unwrap();
        let (hdr, mut stream) = accept_relay(&conn).await.unwrap();
        let mut buf = [0u8; 3];
        stream.recv.read_exact(&mut buf).await.unwrap();
        stream.send.write_all(&buf).await.unwrap();
        stream.send.shutdown().await.unwrap();
        let mut drain = [0u8; 16];
        while let Ok(Some(_)) = stream.recv.read(&mut drain).await {}
        hdr.session_id
    };

    let client = async {
        let mut relay = pool.open_relay(shard, &header()).await.unwrap();
        relay.stream.send.write_all(b"abc").await.unwrap();
        let mut echo = [0u8; 3];
        relay.stream.recv.read_exact(&mut echo).await.unwrap();
        relay.stream.send.shutdown().await.unwrap();
        echo
    };

    let (sid, echo) = tokio::join!(server, client);
    assert_eq!(&echo, b"abc");
    assert_eq!(sid, [9u8; 16]);
}

#[tokio::test]
async fn open_relay_unknown_shard_errors() {
    let edge = MeshEndpoint::bind(loopback(), &identity(b"psk")).unwrap();
    let pool = MeshPeerPool::new(edge, HashMap::new(), 8);
    assert!(pool.open_relay(ShardId::new(1).unwrap(), &header()).await.is_err());
}

#[tokio::test]
async fn a_stalled_dial_does_not_block_relays_to_other_shards() {
    let psk = b"mesh-pool-stall-psk";
    let live = ShardId::new(1).unwrap();
    let stalled = ShardId::new(2).unwrap();

    let home = MeshEndpoint::bind(loopback(), &identity(psk)).unwrap();
    let home_addr = home.local_addr().unwrap();
    let edge = MeshEndpoint::bind(loopback(), &identity(psk)).unwrap();

    // A plain UDP socket that never answers QUIC: the dial to it hangs in the
    // handshake until the mesh idle timeout (30s), which is what a dead peer
    // looks like from the edge. Kept bound for the whole test so the datagrams
    // are absorbed rather than answered with ICMP unreachable.
    let _blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let stalled_addr = _blackhole.local_addr().unwrap();

    let mut peers = HashMap::new();
    peers.insert(live, home_addr);
    peers.insert(stalled, stalled_addr);
    let pool = Arc::new(MeshPeerPool::new(edge, peers, 8));

    let server = tokio::spawn(async move {
        let conn = home.accept().await.unwrap().unwrap();
        let _ = accept_relay(&conn).await;
        // Hold the connection open until the test drops the task.
        std::future::pending::<()>().await;
    });

    let hung = tokio::spawn({
        let pool = Arc::clone(&pool);
        async move { pool.open_relay(stalled, &header()).await.map(|_| ()) }
    });
    // Let the stalled dial get as far as the handshake.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let relay = tokio::time::timeout(Duration::from_secs(5), pool.open_relay(live, &header()))
        .await
        .expect("a hung dial to one shard must not stall relays to another shard");
    assert!(relay.is_ok(), "relay to the reachable shard failed: {:?}", relay.err());

    hung.abort();
    server.abort();
}

#[tokio::test]
async fn open_relay_respects_the_stream_cap() {
    // Cap 0: the permit acquisition fails before any dial is attempted, so a
    // configured-but-unreachable peer still yields a prompt cap error.
    let edge = MeshEndpoint::bind(loopback(), &identity(b"psk")).unwrap();
    let mut peers = HashMap::new();
    peers.insert(ShardId::new(1).unwrap(), "127.0.0.1:9".parse().unwrap());
    let pool = MeshPeerPool::new(edge, peers, 0);
    assert!(pool.open_relay(ShardId::new(1).unwrap(), &header()).await.is_err());
}
