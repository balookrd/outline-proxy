use std::time::Duration;

use tokio::io::AsyncWriteExt;

use super::super::frame::{CarrierKind, OpenHeader};
use super::super::tls::MeshIdentity;
use super::*;

fn identity(psk: &[u8]) -> MeshIdentity {
    MeshIdentity::derive(psk).unwrap()
}

fn header() -> OpenHeader {
    OpenHeader {
        carrier: CarrierKind::SsTcp,
        session_id: [7u8; 16],
        resume_capable: true,
        ack_prefix: false,
        symmetric_replay: false,
        client_down_acked: 0,
        path: "/tcp".to_string(),
        peer_addr: None,
    }
}

fn loopback() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

#[tokio::test]
async fn relay_round_trips_open_header_and_payload() {
    let psk = b"mesh-endpoint-psk";
    let home = MeshEndpoint::bind(loopback(), &identity(psk)).unwrap();
    let home_addr = home.local_addr().unwrap();
    let edge = MeshEndpoint::bind(loopback(), &identity(psk)).unwrap();

    // Home: accept one relay, echo its payload, then drain to EOF so the FIN
    // is delivered before the connection drops.
    let server = async {
        let conn = home.accept().await.unwrap().unwrap();
        let (hdr, mut stream) = accept_relay(&conn).await.unwrap();
        let mut buf = [0u8; 5];
        stream.recv.read_exact(&mut buf).await.unwrap();
        stream.send.write_all(&buf).await.unwrap();
        stream.send.shutdown().await.unwrap();
        let mut drain = [0u8; 16];
        while let Ok(Some(_)) = stream.recv.read(&mut drain).await {}
        hdr
    };

    let client = async {
        let conn = edge.connect(home_addr).await.unwrap();
        let mut stream = open_relay_stream(&conn, &header()).await.unwrap();
        stream.send.write_all(b"01234").await.unwrap();
        let mut echo = [0u8; 5];
        stream.recv.read_exact(&mut echo).await.unwrap();
        stream.send.shutdown().await.unwrap();
        echo
    };

    let (hdr, echo) = tokio::join!(server, client);
    assert_eq!(&echo, b"01234", "payload must round-trip through the relay");
    assert_eq!(hdr.carrier, CarrierKind::SsTcp);
    assert_eq!(hdr.session_id, [7u8; 16]);
    assert!(hdr.resume_capable);
    assert_eq!(hdr.path, "/tcp");
}

#[tokio::test]
async fn rejects_peer_with_a_different_psk() {
    let home = MeshEndpoint::bind(loopback(), &identity(b"home-psk")).unwrap();
    let home_addr = home.local_addr().unwrap();
    let edge = MeshEndpoint::bind(loopback(), &identity(b"a-different-psk")).unwrap();

    // The home must accept() for its side of the handshake to progress; the
    // dialer pins the home cert to its own PSK-derived fingerprint, which a
    // home built from a different PSK cannot match, so both sides fail.
    let server = tokio::time::timeout(Duration::from_secs(5), home.accept());
    let client = tokio::time::timeout(Duration::from_secs(5), edge.connect(home_addr));
    let (_server, client) = tokio::join!(server, client);
    assert!(
        matches!(client, Ok(Err(_))),
        "dialer must reject the home cert on PSK mismatch: {client:?}",
    );
}
