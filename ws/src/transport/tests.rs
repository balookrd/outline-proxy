use super::*;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};

#[tokio::test]
async fn tcp_writer_splits_large_aead_payload_into_multiple_chunks() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 128 * 1024];
        let mut total = 0usize;
        loop {
            let read = stream.read(&mut buf[total..]).await.unwrap();
            if read == 0 {
                break;
            }
            total += read;
        }
        total
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let (_reader_half, writer_half) = stream.into_split();
    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher.derive_master_key("password").unwrap();
    let lifetime = UpstreamTransportGuard::new("test", "tcp");
    let mut writer =
        TcpShadowsocksWriter::connect_socket(writer_half, cipher, &master_key, lifetime).unwrap();
    let payload = vec![0x42; 40_000];

    writer.send_chunk(&payload).await.unwrap();
    writer.close().await.unwrap();

    let total = server.await.unwrap();
    assert!(total > payload.len());
}

#[tokio::test]
async fn udp_socket_transport_close_wakes_blocked_reader() {
    let transport = Arc::new(
        UdpWsTransport::from_socket(
            UdpSocket::bind(("127.0.0.1", 0)).await.unwrap(),
            CipherKind::Chacha20IetfPoly1305,
            "password",
            "test",
        )
        .unwrap(),
    );
    let reader_transport = Arc::clone(&transport);
    let read_task = tokio::spawn(async move { reader_transport.read_packet().await });

    transport.close().await.unwrap();

    let error = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        read_task.await.unwrap().unwrap_err()
    })
    .await
    .unwrap();
    assert!(format!("{error:#}").contains("udp transport closed"));
}

#[tokio::test]
async fn connect_tcp_socket_enables_nodelay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
    });

    let stream = connect_tcp_socket(addr, None).await.unwrap();
    assert!(stream.nodelay().unwrap());

    drop(stream);
    server.await.unwrap();
}
