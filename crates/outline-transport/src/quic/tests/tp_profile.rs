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

#[test]
fn neqo_initial_dcid_len_follows_the_neqo_rule() {
    let lens: Vec<usize> = (0..=u8::MAX).map(|v| InitialDcidLen::Neqo.draw(v)).collect();
    assert_eq!(lens.iter().min(), Some(&8));
    assert_eq!(lens.iter().max(), Some(&20));
    // v = 0x88: 5 + (0x88 & 0x08) = 13, the length in the Firefox capture.
    assert_eq!(InitialDcidLen::Neqo.draw(0x88), 13);
    // Low nibble AND high nibble below 4 clamps to the minimum.
    assert_eq!(InitialDcidLen::Neqo.draw(0x00), 8);
    assert_eq!(InitialDcidLen::Neqo.draw(0xff), 20);
    let eights = lens.iter().filter(|len| **len == 8).count();
    assert!(eights > lens.len() / 2, "8 must be the most common length, got {eights}/256");
}

#[test]
fn fixed_initial_dcid_len_ignores_the_random_byte() {
    for v in [0u8, 0x88, 0xff] {
        assert_eq!(InitialDcidLen::Fixed(8).draw(v), 8);
    }
}

#[test]
fn initial_dcid_provider_yields_the_profile_length() {
    let chromium = CHROMIUM.initial_dst_cid_provider();
    let firefox = FIREFOX.initial_dst_cid_provider();
    let mut firefox_lens = std::collections::BTreeSet::new();
    for _ in 0..512 {
        assert_eq!(chromium().len(), 8);
        let len = firefox().len();
        assert!((8..=20).contains(&len), "firefox DCID length {len} out of range");
        firefox_lens.insert(len);
    }
    assert!(firefox_lens.len() > 1, "firefox DCID length never varied");
    // Two draws of random bytes differ.
    assert_ne!(chromium(), chromium());
}

/// Spin bits (`0x20` of the first byte) of the short-header packets a client
/// with profile `tp` sends over a few round trips, as an on-path observer
/// reads them.
async fn observed_spin_bits(tp: &'static QuicTpProfile) -> Vec<bool> {
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
    let (relay, first_bytes, tap) = loopback::tap_uplink(lb.addr).await;

    let transport = super::super::tls_config::build_h3_transport(
        tp,
        super::super::tls_config::RuntimeWindows::current(tp),
    );
    let (_client, conn) = lb.connect_via(relay, tp.endpoint_config(), transport).await;
    // Sequential round trips: each makes the client send short-header packets
    // after it has seen fresh ones from the server, which is what would flip a
    // working spin bit.
    for round in 0u8..24 {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&[round]).await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), [round]);
    }
    conn.close(0u32.into(), b"done");
    echo.abort();
    tap.abort();

    // Long-header packets (Initial, Handshake) have the top bit set and carry
    // no spin bit.
    let bits: Vec<bool> = first_bytes
        .lock()
        .iter()
        .filter(|byte| **byte & 0x80 == 0)
        .map(|byte| byte & 0x20 != 0)
        .collect();
    assert!(bits.len() >= 24, "only {} short-header packets observed", bits.len());
    bits
}

/// Chromium never spins: every short-header packet carries a zero spin bit.
/// With quinn's default the bit would either flip once per round trip or be
/// drawn at random per packet, so two dozen zeros in a row do not happen by
/// chance.
#[tokio::test]
async fn chromium_profile_sends_a_zero_spin_bit() {
    let bits = observed_spin_bits(&CHROMIUM).await;
    assert!(bits.iter().all(|bit| !bit), "spin bit set in {bits:?}");
}

/// Firefox (neqo) puts a random bit in every packet: both values show up.
#[tokio::test]
async fn firefox_profile_sends_a_random_spin_bit() {
    let bits = observed_spin_bits(&FIREFOX).await;
    assert!(bits.iter().any(|bit| *bit), "spin bit never set in {} packets", bits.len());
    assert!(bits.iter().any(|bit| !bit), "spin bit always set in {} packets", bits.len());
}

#[test]
fn profiles_carry_the_measured_spin_bit_behaviour() {
    use super::super::vendored::SpinBit;
    assert_eq!(CHROMIUM.spin_bit, SpinBit::Zero);
    assert_eq!(FIREFOX.spin_bit, SpinBit::Random);
    assert_eq!(SAFARI.spin_bit, SpinBit::Spinning);
}
