use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::UdpSocket;

use outline_transport::{UdpSessionTransport, UdpWsTransport};
use shadowsocks_crypto::CipherKind;

use super::*;

#[tokio::test]
async fn replacing_active_udp_transport_closes_previous_reader() {
    let old_transport = Arc::new(UdpSessionTransport::Ss(
        UdpWsTransport::from_socket(
            UdpSocket::bind(("127.0.0.1", 0)).await.unwrap(),
            CipherKind::Chacha20IetfPoly1305,
            "password",
            "test_old",
        )
        .unwrap(),
    ));
    let new_transport = Arc::new(UdpSessionTransport::Ss(
        UdpWsTransport::from_socket(
            UdpSocket::bind(("127.0.0.1", 0)).await.unwrap(),
            CipherKind::Chacha20IetfPoly1305,
            "password",
            "test_new",
        )
        .unwrap(),
    ));
    let active_transport = ArcSwap::from_pointee(ActiveUdpTransport {
        index: 1,
        uplink_name: Arc::from("old"),
        transport: Arc::clone(&old_transport),
    });

    let reader_transport = Arc::clone(&old_transport);
    let read_task = tokio::spawn(async move { reader_transport.read_packet().await });

    let previous_transport = replace_active_udp_transport_if_current(
        &active_transport,
        1,
        ActiveUdpTransport {
            index: 2,
            uplink_name: Arc::from("new"),
            transport: Arc::clone(&new_transport),
        },
    )
    .expect("active transport should be replaced");
    close_udp_transport(previous_transport, "test_replace").await;

    let error = tokio::time::timeout(Duration::from_secs(1), async {
        read_task.await.unwrap().unwrap_err()
    })
    .await
    .unwrap();
    assert!(format!("{error:#}").contains("udp transport closed"));
    assert_eq!(active_transport.load().index, 2);
}
