use super::*;

#[test]
fn safari_fingerprint_gets_safari_table() {
    assert_eq!(for_fingerprint(Some(TlsFingerprint::Safari)), &SAFARI);
}

#[test]
fn chromium_firefox_and_none_share_chromium_table() {
    for fp in [Some(TlsFingerprint::Chromium), Some(TlsFingerprint::Firefox), None] {
        assert_eq!(for_fingerprint(fp), &CHROMIUM, "{fp:?}");
    }
}

#[test]
fn idle_timeout_outlives_keepalive() {
    // Keep-alive PING is jittered over 8..=12 s; idle must stay > 2x that.
    for p in [&CHROMIUM, &SAFARI] {
        assert!(p.idle_timeout > Duration::from_secs(24), "{}", p.name);
    }
}

fn loopback() -> std::net::SocketAddr {
    (std::net::Ipv4Addr::LOCALHOST, 0).into()
}

/// A client endpoint with zero-length CIDs keeps its connection when its
/// local address changes mid-connection (NAT rebinding): the server still
/// routes by its own 8-byte CID and validates the new path.
#[tokio::test]
async fn zero_length_cid_connection_survives_client_rebind() {
    use std::net::UdpSocket;
    use std::sync::Arc;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
    ));
    let server = quinn::Endpoint::server(server_config, loopback()).unwrap();
    let server_addr = server.local_addr().unwrap();

    let echo = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let msg = recv.read_to_end(64).await.unwrap();
            send.write_all(&msg).await.unwrap();
            send.finish().unwrap();
        }
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
    ));

    let socket = UdpSocket::bind(loopback()).unwrap();
    let client = quinn::Endpoint::new(
        CHROMIUM.endpoint_config(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    let conn = client
        .connect_with(client_config, server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    async fn roundtrip(conn: &quinn::Connection, msg: &[u8]) -> Vec<u8> {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(msg).await.unwrap();
        send.finish().unwrap();
        recv.read_to_end(64).await.unwrap()
    }

    assert_eq!(roundtrip(&conn, b"before").await, b"before");
    client.rebind(UdpSocket::bind(loopback()).unwrap()).unwrap();
    assert_eq!(roundtrip(&conn, b"after").await, b"after");

    conn.close(0u32.into(), b"done");
    echo.abort();
}
