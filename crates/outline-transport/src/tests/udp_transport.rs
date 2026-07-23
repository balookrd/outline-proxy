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

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use outline_wire::ss2022::Ss2022Error;
use parking_lot::Mutex;
use shadowsocks_crypto::CipherKind;

use super::UdpWsTransport;
use crate::carrier_padding::CarrierPadding;
use crate::frame_io::DatagramChannel;

/// Datagram channel that hands back a pre-queued sequence of inbound
/// datagrams (one per `recv_datagram`). Uplink sends are discarded.
#[derive(Default)]
struct MockChannel {
    inbound: Mutex<VecDeque<Bytes>>,
}

impl MockChannel {
    fn push(&self, packet: Vec<u8>) {
        self.inbound.lock().push_back(Bytes::from(packet));
    }
}

#[async_trait]
impl DatagramChannel for MockChannel {
    async fn send_datagram(&self, _data: Bytes) -> Result<()> {
        Ok(())
    }
    async fn recv_datagram(&self) -> Result<Option<Bytes>> {
        Ok(self.inbound.lock().pop_front())
    }
    async fn close(&self) {}
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
    let client_session_id = transport.ss2022.as_ref().unwrap().lock().await.client_session_id;

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

    // Reorder (same session, lower id 3 <= last-seen 5) is rejected.
    channel.push(packet(0xAA, 3, b"old"));
    let err = transport.read_packet().await.unwrap_err();
    assert!(is_replay_error(&err), "reordered packet must be rejected: {err:#}");

    // Forward progress (id 6 > 5) is accepted.
    channel.push(packet(0xAA, 6, b"second"));
    let out = transport.read_packet().await.unwrap();
    assert_eq!(out.as_ref(), expect_tail(b"second").as_slice());

    // A new server session resets the per-session window: id 1 is accepted
    // even though it is below the previous session's high-water mark.
    channel.push(packet(0xBB, 1, b"newsess"));
    let out = transport.read_packet().await.unwrap();
    assert_eq!(out.as_ref(), expect_tail(b"newsess").as_slice());

    // A duplicate within the new session is rejected.
    channel.push(packet(0xBB, 1, b"newdup"));
    let err = transport.read_packet().await.unwrap_err();
    assert!(is_replay_error(&err), "duplicate in new session must be rejected: {err:#}");
}
