use super::*;

#[test]
fn safari_fingerprint_gets_safari_table() {
    assert_eq!(for_fingerprint(Some(TlsFingerprint::Safari)), &SAFARI);
}

#[test]
fn chromium_and_none_get_chromium_table() {
    for fp in [Some(TlsFingerprint::Chromium), None] {
        assert_eq!(for_fingerprint(fp), &CHROMIUM, "{fp:?}");
    }
}

#[test]
fn firefox_fingerprint_gets_firefox_table() {
    assert_eq!(for_fingerprint(Some(TlsFingerprint::Firefox)), &FIREFOX);
}

#[test]
fn stream_windows_largest_and_uniform() {
    assert_eq!(StreamWindows::uniform(7).largest(), 7);
    assert_eq!(FIREFOX.stream_receive_windows.largest(), 12_582_912);
}

#[test]
fn idle_timeout_outlives_keepalive() {
    // Keep-alive PING is jittered over 8..=12 s; idle must stay > 2x that.
    for p in [&CHROMIUM, &FIREFOX, &SAFARI] {
        assert!(p.idle_timeout > Duration::from_secs(24), "{}", p.name);
    }
}

use crate::quic::loopback;

/// A client endpoint with zero-length CIDs keeps its connection when its
/// local address changes mid-connection (NAT rebinding): the server still
/// routes by its own 8-byte CID and validates the new path.
#[tokio::test]
async fn zero_length_cid_connection_survives_client_rebind() {
    use std::net::UdpSocket;

    let lb = loopback::Loopback::new();
    let server = lb.server.clone();
    let echo = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let msg = recv.read_to_end(64).await.unwrap();
            send.write_all(&msg).await.unwrap();
            send.finish().unwrap();
        }
    });

    let (client, conn) = lb
        .connect(CHROMIUM.endpoint_config(), quinn::TransportConfig::default())
        .await;

    async fn roundtrip(conn: &quinn::Connection, msg: &[u8]) -> Vec<u8> {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(msg).await.unwrap();
        send.finish().unwrap();
        recv.read_to_end(64).await.unwrap()
    }

    assert_eq!(roundtrip(&conn, b"before").await, b"before");
    client.rebind(UdpSocket::bind(loopback::loopback()).unwrap()).unwrap();
    assert_eq!(roundtrip(&conn, b"after").await, b"after");

    conn.close(0u32.into(), b"done");
    echo.abort();
}

#[test]
fn profile_options_match_measured_browsers() {
    let c = &CHROMIUM.options;
    assert!(!c.advertise_min_ack_delay && c.grease_parameter);
    assert!(c.advertise_idle_timeout && c.advertise_max_udp_payload_size);
    assert_eq!(c.datagram_frame_size, Some(65_536));
    assert!(c.version_information.is_some());
    assert_eq!(c.extra_parameters, &[(0x3128, &b"ORIG"[..])]);

    let s = &SAFARI.options;
    assert!(!s.advertise_min_ack_delay && !s.grease_parameter);
    assert!(!s.advertise_idle_timeout && !s.advertise_max_udp_payload_size);
    assert_eq!(s.datagram_frame_size, None);
    assert!(s.version_information.is_none());
    assert_eq!(s.extra_parameters, &[(0xff08_0808, &[0x09][..])]);
}
