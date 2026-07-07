use std::collections::HashMap;

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
async fn open_relay_respects_the_stream_cap() {
    // Cap 0: the permit acquisition fails before any dial is attempted, so a
    // configured-but-unreachable peer still yields a prompt cap error.
    let edge = MeshEndpoint::bind(loopback(), &identity(b"psk")).unwrap();
    let mut peers = HashMap::new();
    peers.insert(ShardId::new(1).unwrap(), "127.0.0.1:9".parse().unwrap());
    let pool = MeshPeerPool::new(edge, peers, 0);
    assert!(pool.open_relay(ShardId::new(1).unwrap(), &header()).await.is_err());
}
