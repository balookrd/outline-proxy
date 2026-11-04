//! Tests for the pure client-start shaping decision in [`crate::ws_stream`].

use super::shapes_client_start_for;
use crate::xhttp::XhttpSubmode;

#[test]
fn plain_ws_carriers_shape_the_client_start() {
    // Http1 / H2 carry no XHTTP submode.
    assert!(shapes_client_start_for(false, None));
}

#[test]
fn h3_never_shapes() {
    assert!(!shapes_client_start_for(true, None));
    // XHTTP over h3 is h3 too, whatever the submode.
    assert!(!shapes_client_start_for(true, Some(XhttpSubmode::StreamOne)));
    assert!(!shapes_client_start_for(true, Some(XhttpSubmode::PacketUp)));
}

#[test]
fn xhttp_packet_up_does_not_shape() {
    assert!(!shapes_client_start_for(false, Some(XhttpSubmode::PacketUp)));
}

#[test]
fn xhttp_stream_one_on_tcp_shapes() {
    assert!(shapes_client_start_for(false, Some(XhttpSubmode::StreamOne)));
}

/// The method on a live carrier, not just the pure decision: a real `ws_h1`
/// dial to a loopback server lands on `Http1` and shapes its start.
#[tokio::test]
async fn a_dialed_ws_h1_carrier_shapes_the_client_start() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
    use url::Url;

    use crate::{DnsCache, TransportDialOptions, TransportMode, connect_transport};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(socket.read(&mut byte).await.unwrap(), 1);
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let key = head
            .lines()
            .find_map(|l| {
                let (n, v) = l.split_once(": ")?;
                n.eq_ignore_ascii_case("sec-websocket-key").then_some(v.to_owned())
            })
            .unwrap();
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\
             sec-websocket-accept: {}\r\n\r\n",
            derive_accept_key(key.as_bytes())
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        // Hold the socket until the client has looked at the carrier.
        let _ = socket.read(&mut byte).await;
    });

    let url = Url::parse(&format!("ws://localhost:{port}/ws")).unwrap();
    let cache = DnsCache::default();
    let stream =
        connect_transport(TransportDialOptions::new(&cache, &url, TransportMode::WsH1, "test"))
            .await
            .unwrap();
    assert!(matches!(stream, crate::TransportStream::Http1 { .. }));
    assert!(stream.shapes_client_start());
    drop(stream);
    server.await.unwrap();
}
