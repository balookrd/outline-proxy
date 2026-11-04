use std::sync::Arc;

use quinn::{AsyncUdpSocket, Runtime, TokioRuntime};

use super::NoGsoUdpSocket;

fn tokio_socket() -> Arc<dyn AsyncUdpSocket> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    TokioRuntime.wrap_udp_socket(socket).expect("wrap")
}

#[tokio::test]
async fn caps_transmit_segments_at_one() {
    let wrapped = NoGsoUdpSocket::new(tokio_socket());
    assert_eq!(wrapped.max_transmit_segments(), 1);
}

#[tokio::test]
async fn delegates_everything_but_transmit_segments() {
    let inner = tokio_socket();
    let wrapped = NoGsoUdpSocket::new(Arc::clone(&inner));
    assert_eq!(wrapped.local_addr().unwrap(), inner.local_addr().unwrap());
    // Receive-side GRO stays as the host probed it.
    assert_eq!(wrapped.max_receive_segments(), inner.max_receive_segments());
    assert_eq!(wrapped.may_fragment(), inner.may_fragment());
}

/// Smoke test: a real QUIC endpoint runs on the wrapper and its Initial goes
/// out. (Loopback re-segments GSO in the kernel, so the receiver cannot tell
/// GSO from plain sends; the cap itself is pinned by the tests above.)
#[tokio::test]
async fn quic_endpoint_on_wrapper_sends_initial() {
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("peer");
    let peer_addr = peer.local_addr().unwrap();

    let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
    let socket: Arc<dyn AsyncUdpSocket> = Arc::new(NoGsoUdpSocket::new(tokio_socket()));
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        crate::quic::h3_endpoint_config(),
        None,
        socket,
        runtime,
    )
    .expect("endpoint");
    let _connecting = endpoint
        .connect_with(crate::quic::h3_quic_client_config(), peer_addr, "example.com")
        .expect("connect");

    let mut buf = vec![0u8; 65_535];
    let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(5), peer.recv_from(&mut buf))
        .await
        .expect("an Initial arrives")
        .expect("recv");
    assert!(n <= 1500, "datagram of {n} bytes exceeds one MTU");
    assert_eq!(buf[0] & 0x80, 0x80, "first datagram is a QUIC long-header packet");
}
