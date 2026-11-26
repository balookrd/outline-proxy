//! SS2022-UDP downlink replay protection.
//!
//! `decrypt_udp_bytes` now holds a single session lock across the whole
//! read-decrypt-update path (it used to take the mutex twice per
//! datagram). This test drives real server→client SS2022-UDP AES
//! datagrams through `read_packet` and asserts the replay window still
//! rejects an exact duplicate and a reordered (lower) packet id, accepts
//! forward progress, and resets per server session — i.e. the lock merge
//! left the replay semantics untouched.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use outline_wire::ss2022::Ss2022Error;
use parking_lot::Mutex;
use shadowsocks_crypto::CipherKind;
use tokio::sync::Notify;

use super::UdpWsTransport;
use crate::carrier_padding::CarrierPadding;
use crate::frame_io::DatagramChannel;

/// Datagram channel that hands back a pre-queued sequence of inbound
/// datagrams (one per `recv_datagram`) and records every uplink send. Shared
/// with the other datagram-channel tests of the crate (e.g. the HTTP/3
/// datagram channel, which uses it as its stream fallback).
#[derive(Default)]
pub(crate) struct MockChannel {
    inbound: Mutex<VecDeque<Bytes>>,
    /// Every datagram handed to `send_datagram`, in order.
    pub(crate) sent: Mutex<Vec<Bytes>>,
    pub(crate) closed: AtomicBool,
    /// When set, an empty queue waits for the next `push` (or `close`) instead
    /// of reporting EOF, like a live carrier with nothing to deliver yet.
    wait_when_empty: bool,
    pushed: Notify,
}

impl MockChannel {
    /// A channel whose empty queue waits instead of reporting EOF.
    #[cfg_attr(not(feature = "h3"), allow(dead_code))]
    pub(crate) fn waiting() -> Self {
        Self { wait_when_empty: true, ..Self::default() }
    }

    pub(crate) fn push(&self, packet: Vec<u8>) {
        self.inbound.lock().push_back(Bytes::from(packet));
        self.pushed.notify_one();
    }
}

#[async_trait]
impl DatagramChannel for MockChannel {
    async fn send_datagram(&self, data: Bytes) -> Result<()> {
        self.sent.lock().push(data);
        Ok(())
    }
    async fn recv_datagram(&self) -> Result<Option<Bytes>> {
        loop {
            if let Some(packet) = self.inbound.lock().pop_front() {
                return Ok(Some(packet));
            }
            if !self.wait_when_empty || self.closed.load(Ordering::SeqCst) {
                return Ok(None);
            }
            self.pushed.notified().await;
        }
    }
    fn try_recv_datagram(&self) -> Result<Option<Bytes>> {
        Ok(self.inbound.lock().pop_front())
    }
    async fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.pushed.notify_one();
    }
}

/// Builds a server→client SS2022-UDP AES datagram the client will accept:
/// the plaintext is a real response body (echoing `client_session_id`),
/// the separate header carries the server session/packet ids, and the
/// whole thing is sealed with the same master key the transport derives.
/// Reproduces `encrypt_udp_packet_2022_aes` from the crypto crate, which
/// is not part of its public surface.
fn build_server_aes_packet(
    cipher: CipherKind,
    master_key: &[u8],
    server_session_id: u64,
    packet_id: u64,
    client_session_id: u64,
    target_wire: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    use outline_wire::ss2022::{
        encode_udp_separate_header, udp_nonce_from_separate_header, write_udp_response_body,
    };
    use shadowsocks_crypto::{derive_subkey, encrypt_into, encrypt_udp_separate_header};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut plaintext = Vec::new();
    write_udp_response_body(
        &mut plaintext,
        now,
        &client_session_id.to_be_bytes(),
        target_wire,
        payload,
    );

    let separate_header = encode_udp_separate_header(&server_session_id.to_be_bytes(), packet_id);
    let nonce = udp_nonce_from_separate_header(&separate_header);
    let key = derive_subkey(cipher, master_key, &separate_header[..8]).unwrap();
    let encrypted_header =
        encrypt_udp_separate_header(cipher, master_key, &separate_header).unwrap();

    let mut packet = Vec::new();
    packet.extend_from_slice(&encrypted_header);
    encrypt_into(cipher, &key[..cipher.key_len()], &nonce, &plaintext, &mut packet).unwrap();
    packet
}

// The UDP transport holds the master key for the whole session and derives a
// subkey from it per datagram. The stored copy must carry zeroize-on-drop
// semantics so a closed session leaves no key material behind.
#[test]
fn udp_transport_master_key_is_zeroizing() {
    let transport = UdpWsTransport::from_channel(
        Arc::new(MockChannel::default()),
        CipherKind::Aes256Gcm2022,
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
        "test",
        CarrierPadding::disabled(),
    )
    .unwrap();
    let ty = std::any::type_name_of_val(&transport.master_key);
    assert!(
        ty.contains("zeroize::Zeroizing<"),
        "UDP transport master key must be wrapped in Zeroizing, got `{ty}`"
    );
}

fn is_replay_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<Ss2022Error>(),
            Some(Ss2022Error::DuplicateOrOutOfOrderUdpPacket)
        )
    })
}

#[tokio::test]
async fn ss2022_udp_replay_protection_rejects_duplicate_and_reorder() {
    let cipher = CipherKind::Aes256Gcm2022;
    // SS2022 keys the master key from a base64-encoded PSK of the cipher's
    // key length (32 bytes for AES-256).
    let password = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    let master_key = cipher.derive_master_key(password).unwrap();

    let channel = Arc::new(MockChannel::default());
    let transport = UdpWsTransport::from_channel(
        channel.clone(),
        cipher,
        password,
        "test",
        CarrierPadding::disabled(),
    )
    .unwrap();

    // The transport echoes its own client session id in every uplink and
    // requires the server to echo it back; read it so the crafted server
    // packets pass the client-session check.
    let client_session_id = transport.ss2022.as_ref().unwrap().client_session_id;

    // A fixed SOCKS5 target prefix — `read_packet` returns `target || payload`.
    let target = [1_u8, 127, 0, 0, 1, 0, 53];
    let packet = |sid: u64, pid: u64, data: &[u8]| {
        build_server_aes_packet(cipher, &master_key, sid, pid, client_session_id, &target, data)
    };
    let expect_tail = |data: &[u8]| {
        let mut tail = target.to_vec();
        tail.extend_from_slice(data);
        tail
    };

    // Fresh packet (session 0xAA, id 5) is accepted and yields target||payload.
    channel.push(packet(0xAA, 5, b"first"));
    let out = transport.read_packet().await.unwrap();
    assert_eq!(out.as_ref(), expect_tail(b"first").as_slice());

    // Exact duplicate (same session, same id) is rejected.
    channel.push(packet(0xAA, 5, b"dup"));
    let err = transport.read_packet().await.unwrap_err();
    assert!(is_replay_error(&err), "duplicate packet must be rejected: {err:#}");

    // Reordered packet (same session, lower id 3 within sliding window) is accepted.
    channel.push(packet(0xAA, 3, b"reordered"));
    let out = transport.read_packet().await.unwrap();
    assert_eq!(out.as_ref(), expect_tail(b"reordered").as_slice());

    // Duplicate of the reordered packet is rejected.
    channel.push(packet(0xAA, 3, b"reordered_dup"));
    let err = transport.read_packet().await.unwrap_err();
    assert!(is_replay_error(&err), "duplicate reordered packet must be rejected: {err:#}");

    // Forward progress (id 6 > 5) is accepted.
    channel.push(packet(0xAA, 6, b"second"));
    let out = transport.read_packet().await.unwrap();
    assert_eq!(out.as_ref(), expect_tail(b"second").as_slice());

    // A packet from a different server session is rejected (prevents session rollback/hijack).
    channel.push(packet(0xBB, 1, b"newsess"));
    let err = transport.read_packet().await.unwrap_err();
    assert!(is_replay_error(&err), "different server session must be rejected: {err:#}");

    // A packet far behind the window (e.g. forward to 200, then receive 5) is rejected.
    channel.push(packet(0xAA, 200, b"advanced"));
    let out = transport.read_packet().await.unwrap();
    assert_eq!(out.as_ref(), expect_tail(b"advanced").as_slice());

    channel.push(packet(0xAA, 2, b"too_old"));
    let err = transport.read_packet().await.unwrap_err();
    assert!(is_replay_error(&err), "packet outside replay window must be rejected: {err:#}");
}

// The classifier that keeps a corrupt datagram off the carrier-descent path
// must recognise the errors `read_packet` *actually* produces, not just
// hand-built ones: this is the seam where a changed error type would silently
// re-enable the misattribution (a payload error read as a carrier fault caps
// `xhttp_h3 → xhttp_h2` and stamps an uplink cooldown).
#[tokio::test]
async fn read_packet_payload_failures_classify_as_payload_integrity() {
    let cipher = CipherKind::Aes256Gcm2022;
    let password = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    let master_key = cipher.derive_master_key(password).unwrap();

    let channel = Arc::new(MockChannel::default());
    let transport = UdpWsTransport::from_channel(
        channel.clone(),
        cipher,
        password,
        "test",
        CarrierPadding::disabled(),
    )
    .unwrap();
    let client_session_id = transport.ss2022.as_ref().unwrap().client_session_id;
    let target = [1_u8, 127, 0, 0, 1, 0, 53];

    // A datagram far too short to hold even the SS2022 separate header.
    channel.push(vec![0_u8; 4]);
    let err = transport.read_packet().await.unwrap_err();
    assert_eq!(
        crate::payload_integrity_cause(&err),
        Some("packet_too_short"),
        "a truncated datagram must classify as a payload error: {err:#}",
    );

    // A full-length datagram whose ciphertext does not authenticate.
    let mut corrupt = build_server_aes_packet(
        cipher,
        &master_key,
        0xAA,
        1,
        client_session_id,
        &target,
        b"payload",
    );
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xFF;
    channel.push(corrupt);
    let err = transport.read_packet().await.unwrap_err();
    assert_eq!(
        crate::payload_integrity_cause(&err),
        Some("decrypt_failed"),
        "a datagram that fails AEAD open must classify as a payload error: {err:#}",
    );

    // Replay rejection travels the same route.
    channel.push(build_server_aes_packet(
        cipher,
        &master_key,
        0xAA,
        5,
        client_session_id,
        &target,
        b"first",
    ));
    transport.read_packet().await.unwrap();
    channel.push(build_server_aes_packet(
        cipher,
        &master_key,
        0xAA,
        5,
        client_session_id,
        &target,
        b"dup",
    ));
    let err = transport.read_packet().await.unwrap_err();
    assert_eq!(
        crate::payload_integrity_cause(&err),
        Some("udp_out_of_order"),
        "a replayed datagram must classify as a payload error: {err:#}",
    );
}

/// SS-UDP offers UDP over HTTP/3 datagrams on `ws_h3` dials only (xhttp is a
/// separate step); every other carrier keeps the plain stream.
#[test]
fn only_h3_ss_udp_dials_offer_h3_datagrams() {
    use crate::config::TransportMode;
    assert!(super::udp_datagram_requested(TransportMode::WsH3));
    assert!(super::udp_datagram_requested(TransportMode::XhttpH3));
    for mode in
        [TransportMode::WsH1, TransportMode::WsH2, TransportMode::XhttpH1, TransportMode::XhttpH2]
    {
        assert!(!super::udp_datagram_requested(mode), "{mode:?}");
    }
}

#[tokio::test]
async fn try_read_packet_drains_ss2022_burst_without_dropping_under_concurrent_sends() {
    let cipher = CipherKind::Aes256Gcm2022;
    let password = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    let master_key = cipher.derive_master_key(password).unwrap();

    let channel = Arc::new(MockChannel::waiting());
    let transport = Arc::new(
        UdpWsTransport::from_channel(
            channel.clone(),
            cipher,
            password,
            "test",
            CarrierPadding::disabled(),
        )
        .unwrap(),
    );
    let client_session_id = transport.ss2022.as_ref().unwrap().client_session_id;
    let target = [1_u8, 127, 0, 0, 1, 1, 187];

    const TOTAL_DOWNLINK: usize = 200;
    for seq in 0..TOTAL_DOWNLINK {
        let payload = format!("pkt-{seq:04}");
        channel.push(build_server_aes_packet(
            cipher,
            &master_key,
            0x55,
            seq as u64,
            client_session_id,
            &target,
            payload.as_bytes(),
        ));
    }

    // Concurrent uplink sends simulate steady ACKs while the downlink reader
    // drains the burst using the blocking read + try_read_packet batch pattern.
    let sender = {
        let transport = Arc::clone(&transport);
        tokio::spawn(async move {
            let mut tx_payload = target.to_vec();
            tx_payload.extend_from_slice(b"ack");
            for _ in 0..200 {
                transport.send_packet(&tx_payload).await.unwrap();
                tokio::task::yield_now().await;
            }
        })
    };

    let mut received = Vec::with_capacity(TOTAL_DOWNLINK);
    while received.len() < TOTAL_DOWNLINK {
        let first = transport.read_packet().await.unwrap();
        received.push(first);
        while received.len() < TOTAL_DOWNLINK {
            match transport.try_read_packet().unwrap() {
                Some(next) => received.push(next),
                None => break,
            }
        }
        tokio::task::yield_now().await;
    }

    assert!(
        transport.try_read_packet().unwrap().is_none(),
        "queue must be empty after draining all packets"
    );
    sender.await.unwrap();
    assert_eq!(received.len(), TOTAL_DOWNLINK);
    for (seq, pkt) in received.iter().enumerate() {
        let expected_tail = format!("pkt-{seq:04}");
        assert!(pkt.ends_with(expected_tail.as_bytes()), "mismatch at index {seq}");
    }
    assert_eq!(channel.sent.lock().len(), 200);
}

#[tokio::test]
async fn try_read_packet_skips_padding_cover_frames_and_returns_none_when_empty() {
    use outline_wire::padding::PaddingScheme;

    let cipher = CipherKind::Aes256Gcm2022;
    let password = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    let master_key = cipher.derive_master_key(password).unwrap();
    let padding = CarrierPadding {
        scheme: PaddingScheme::new(0, 64),
        cover: false,
        cover_jitter_min_ms: 0,
        cover_jitter_max_ms: 0,
    };

    let channel = Arc::new(MockChannel::waiting());
    let transport =
        UdpWsTransport::from_channel(channel.clone(), cipher, password, "test", padding).unwrap();
    let client_session_id = transport.ss2022.as_ref().unwrap().client_session_id;
    let target = [1_u8, 127, 0, 0, 1, 1, 187];

    // Push a cover frame (real_len = 0) followed by a real padded datagram.
    let cover_frame = outline_wire::padding_frames::CoverParams::new(padding.scheme, true, 0, 0)
        .unwrap()
        .frame(&mut rand::rng())
        .to_vec();
    channel.push(cover_frame);
    let raw = build_server_aes_packet(
        cipher,
        &master_key,
        0x77,
        1,
        client_session_id,
        &target,
        b"hello-padded",
    );
    let mut framed = Vec::with_capacity(raw.len() + 8);
    crate::carrier_padding::frame_datagram_into(
        padding.scheme,
        &raw,
        None,
        &mut rand::rng(),
        &mut framed,
    );
    channel.push(framed);

    let got = transport
        .try_read_packet()
        .unwrap()
        .expect("try_read_packet must skip cover frame and return the real datagram");
    assert!(got.ends_with(b"hello-padded"));
    assert!(
        transport.try_read_packet().unwrap().is_none(),
        "empty queue must yield Ok(None) without error"
    );

    // Ensure blocking read_packet still works normally after try_read_packet returned None.
    let second = build_server_aes_packet(
        cipher,
        &master_key,
        0x77,
        2,
        client_session_id,
        &target,
        b"after-empty",
    );
    let mut second_framed = Vec::with_capacity(second.len() + 8);
    crate::carrier_padding::frame_datagram_into(
        padding.scheme,
        &second,
        None,
        &mut rand::rng(),
        &mut second_framed,
    );
    channel.push(second_framed);
    let got2 = transport.read_packet().await.unwrap();
    assert!(got2.ends_with(b"after-empty"));
}
