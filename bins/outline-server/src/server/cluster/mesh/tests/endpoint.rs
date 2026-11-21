use std::time::Duration;

use tokio::io::AsyncWriteExt;

use super::super::frame::{MeshFraming, MeshProtocol, OpenHeader};
use super::super::tls::MeshIdentity;
use super::*;

fn identity(psk: &[u8]) -> MeshIdentity {
    MeshIdentity::derive(psk).unwrap()
}

fn header() -> OpenHeader {
    OpenHeader {
        framing: MeshFraming::Tcp,
        protocol: MeshProtocol::Ss,
        session_id: [7u8; 16],
        resume_capable: true,
        ack_prefix: false,
        symmetric_replay: false,
        client_down_acked: 0,
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
    assert_eq!(hdr.framing, MeshFraming::Tcp);
    assert_eq!(hdr.protocol, MeshProtocol::Ss);
    assert_eq!(hdr.session_id, [7u8; 16]);
    assert!(hdr.resume_capable);
}

/// A peer whose OPEN this build cannot parse — a straggler still sending the
/// retired v4 header — is refused *explicitly*, with a reset on both halves,
/// rather than left to quinn's drop semantics. That is what turns version skew
/// into a lost resume the edge can act on immediately instead of a stream that
/// hangs until a timeout.
#[tokio::test]
async fn a_v4_open_is_refused_with_a_reset() {
    let psk = b"mesh-endpoint-v4-psk";
    let home = MeshEndpoint::bind(loopback(), &identity(psk)).unwrap();
    let home_addr = home.local_addr().unwrap();
    let edge = MeshEndpoint::bind(loopback(), &identity(psk)).unwrap();

    let server = async {
        let conn = home.accept().await.unwrap().unwrap();
        let refused = matches!(accept_relay(&conn).await, Err(AcceptRelayError::Stream(_)));
        // Handed back so `join!` keeps the connection alive until the client has
        // read its half: dropping it here would close the whole connection and
        // the dialer would see that instead of the per-stream reset.
        (refused, conn)
    };

    let client = async {
        let conn = edge.connect(home_addr).await.unwrap();
        // A well-formed frame of this build, re-stamped with the retired
        // version byte: exactly what a node on an older build puts on the wire.
        let mut open = header().encode();
        open[0] = 4;
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&(open.len() as u32).to_be_bytes()).await.unwrap();
        send.write_all(&open).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64))
            .await
            .expect("the home must answer a v4 OPEN, not leave it hanging")
            .expect_err("the home must reset a relay stream it cannot parse")
    };

    let ((refused, _conn), error) = tokio::join!(server, client);
    assert!(refused, "an unparsable OPEN is a per-stream failure, not a connection one");
    let abort = quinn::VarInt::from_u32(CloseReason::Abort.code());
    assert!(
        matches!(
            error,
            quinn::ReadToEndError::Read(quinn::ReadError::Reset(code)) if code == abort
        ),
        "expected an Abort reset, got {error:?}",
    );
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
