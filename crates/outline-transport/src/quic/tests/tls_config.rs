//! Diagnostic: decrypt a real QUIC Initial packet exactly as a censor sees it.
//!
//! Drives a **real** `quinn` handshake (sans-IO, no sockets) through our
//! production [`super::h3_quic_client_config`], captures the first Initial
//! datagram(s), and decrypts them with the well-known v1 Initial salt — exactly
//! what a DPI box does after observing the packet. The decrypted payload
//! exposes the QUIC transport parameters quinn actually encodes and the
//! ClientHello key shares, letting us assert the H3 carrier's on-wire shape
//! (post-quantum key share present, `max_datagram_frame_size` absent for the Safari
//! profile only).
//!
//! Pure computation: `quinn-proto` is a sans-IO core, so no UDP socket is ever
//! bound.

use std::sync::Arc;
use std::time::Instant;

use ring::{aead, hmac};

use crate::quic::loopback;
use crate::tests::client_hello::{
    Reader, cert_compression_algs, cipher_suites, ech_outer, extension, extension_types,
    extensions, is_grease_u16, ja4, key_share_entries, key_share_groups, sha256_hex12,
    supported_versions, u16_list_ext,
};

/// QUIC v1 Initial salt (RFC 9001 §5.2) — public and fixed, which is exactly
/// why a censor can decrypt any Initial it sees.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// QUIC variable-length integers on the shared ClientHello cursor.
trait QuicVarint {
    fn varint(&mut self) -> u64;
}

impl QuicVarint for Reader<'_> {
    /// QUIC variable-length integer (RFC 9000 §16): the two high bits of the
    /// first byte give the length (1/2/4/8), the rest is the value.
    fn varint(&mut self) -> u64 {
        let first = self.b[self.i];
        let len = 1usize << (first >> 6);
        let mut v = u64::from(first & 0x3f);
        self.i += 1;
        for _ in 1..len {
            v = (v << 8) | u64::from(self.b[self.i]);
            self.i += 1;
        }
        v
    }
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&k, msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// HKDF-Expand-Label (RFC 8446 §7.1) with an empty context, single-block
/// output (`len <= 32`, true for every Initial secret/key/iv/hp).
fn hkdf_expand_label(prk: &[u8; 32], label: &str, len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0); // empty context
    info.push(0x01); // HKDF-Expand T(1) counter
    hmac_sha256(prk, &info)[..len].to_vec()
}

/// Client Initial AEAD/HP keys derived from the destination connection id,
/// per RFC 9001 §5.2. AES-128-GCM + AES-128 header protection for v1.
struct InitialKeys {
    key: Vec<u8>,
    iv: Vec<u8>,
    hp: Vec<u8>,
}

fn client_initial_keys(dcid: &[u8]) -> InitialKeys {
    let initial_secret = hmac_sha256(&INITIAL_SALT_V1, dcid); // HKDF-Extract
    let client_secret: [u8; 32] = hkdf_expand_label(&initial_secret, "client in", 32)
        .try_into()
        .unwrap();
    InitialKeys {
        key: hkdf_expand_label(&client_secret, "quic key", 16),
        iv: hkdf_expand_label(&client_secret, "quic iv", 12),
        hp: hkdf_expand_label(&client_secret, "quic hp", 16),
    }
}

/// Parse + decrypt a client Initial datagram the way a censor would: parse the
/// long header for the DCID, derive the v1 Initial keys, strip header
/// protection, then AEAD-open the payload. Returns the decrypted Initial
/// payload (CRYPTO + PADDING frames).
fn decrypt_client_initial(dgram: &[u8]) -> Vec<u8> {
    assert_eq!(dgram[0] & 0xf0, 0xc0, "expected a long-header Initial packet");

    // Long header: first byte, 4-byte version, DCID, SCID, token, length.
    let mut r = Reader::new(dgram);
    let _first = r.u8();
    r.take(4); // version
    let dcil = r.u8() as usize;
    let dcid = r.take(dcil).to_vec();
    let scil = r.u8() as usize;
    r.take(scil); // scid
    let token_len = r.varint() as usize;
    r.take(token_len); // empty for a client Initial
    let length_field = r.varint();
    let pn_offset = r.i;

    let keys = client_initial_keys(&dcid);

    // Remove header protection (RFC 9001 §5.4): the sample starts four bytes
    // after the packet-number field, regardless of the (still-hidden) pn len.
    let sample = &dgram[pn_offset + 4..pn_offset + 4 + 16];
    let hp = aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &keys.hp).unwrap();
    let mask = hp.new_mask(sample).unwrap();

    let first_unmasked = dgram[0] ^ (mask[0] & 0x0f); // long header masks low 4 bits
    let pn_len = ((first_unmasked & 0x03) + 1) as usize;
    let mut pn_bytes = dgram[pn_offset..pn_offset + pn_len].to_vec();
    for (i, b) in pn_bytes.iter_mut().enumerate() {
        *b ^= mask[1 + i];
    }
    let mut pn = 0u64;
    for b in &pn_bytes {
        pn = (pn << 8) | u64::from(*b);
    }

    // AEAD associated data is the header in its unprotected form.
    let mut aad = dgram[0..pn_offset + pn_len].to_vec();
    aad[0] = first_unmasked;
    aad[pn_offset..pn_offset + pn_len].copy_from_slice(&pn_bytes);

    // Nonce = iv XOR left-padded packet number.
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&keys.iv);
    let pnb = pn.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pnb[i];
    }

    // Ciphertext spans from the end of the packet number to the end of the
    // Initial packet (length counts pn + payload + tag).
    let ct_start = pn_offset + pn_len;
    let ct_end = pn_offset + length_field as usize;
    let mut ct = dgram[ct_start..ct_end].to_vec();

    let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &keys.key).unwrap();
    let opener = aead::LessSafeKey::new(unbound);
    let plaintext = opener
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad.as_slice()),
            &mut ct,
        )
        .expect("Initial AEAD decryption failed");

    plaintext.to_vec()
}

/// Extract the CRYPTO segments (offset + bytes) from an Initial payload. Client
/// Initials carry only CRYPTO + PADDING (+ the odd PING), so the frame grammar
/// here is intentionally tiny. A large ClientHello — a post-quantum key share
/// pushes it past the 1200-byte Initial — is split across several Initials, so
/// CRYPTO is returned per-segment and reassembled by the caller rather than
/// assumed contiguous in one packet.
fn parse_crypto_segments(payload: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut r = Reader::new(payload);
    let mut crypto = Vec::new();
    while r.remaining() > 0 {
        match r.u8() {
            0x00 => {}, // PADDING
            0x01 => {}, // PING
            0x06 => {
                let offset = r.varint();
                let len = r.varint() as usize;
                crypto.push((offset, r.take(len).to_vec()));
            },
            other => panic!("unexpected frame type 0x{other:02x} in client Initial"),
        }
    }
    crypto
}

/// Concatenate CRYPTO segments (collected across one or more Initials) into the
/// handshake byte stream, ordered by offset. Outline's first flight is a single
/// in-order CRYPTO stream, so contiguous concatenation is sufficient.
fn reassemble_crypto(segments: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut ordered = segments.to_vec();
    ordered.sort_by_key(|(offset, _)| *offset);
    let mut out: Vec<u8> = Vec::new();
    for (offset, data) in ordered {
        let offset = offset as usize;
        if offset <= out.len() {
            let already = out.len() - offset;
            if already < data.len() {
                out.extend_from_slice(&data[already..]);
            }
        }
        // A gap (offset > out.len()) cannot occur for an in-order first flight;
        // leaving it unfilled keeps `crypto_complete` false so the capture loop
        // polls for the next Initial.
    }
    out
}

/// True once `ch` holds a complete handshake message: the 4-byte header plus
/// the 24-bit declared body length.
fn crypto_complete(ch: &[u8]) -> bool {
    if ch.len() < 4 {
        return false;
    }
    let body = ((ch[1] as usize) << 16) | ((ch[2] as usize) << 8) | ch[3] as usize;
    ch.len() >= 4 + body
}

/// Ordered transport-parameter ids from the `quic_transport_parameters`
/// extension (0x0039).
fn transport_param_ids_from_clienthello(ch: &[u8]) -> Vec<u64> {
    let data = extension(ch, 0x0039)
        .expect("no quic_transport_parameters (0x0039) extension in ClientHello");
    let mut pr = Reader::new(data);
    let mut ids = Vec::new();
    while pr.remaining() > 0 {
        let id = pr.varint();
        let len = pr.varint() as usize;
        pr.take(len);
        ids.push(id);
    }
    ids
}

/// `(id, raw value)` pairs from the `quic_transport_parameters` extension
/// (0x0039), in wire order.
fn transport_params_from_clienthello(ch: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let data = extension(ch, 0x0039)
        .expect("no quic_transport_parameters (0x0039) extension in ClientHello");
    let mut pr = Reader::new(data);
    let mut params = Vec::new();
    while pr.remaining() > 0 {
        let id = pr.varint();
        let len = pr.varint() as usize;
        params.push((id, pr.take(len).to_vec()));
    }
    params
}

/// Decodes a QUIC varint that fills the whole slice (a TP integer value).
fn varint_value(bytes: &[u8]) -> u64 {
    let mut r = Reader::new(bytes);
    let v = r.varint();
    assert_eq!(r.remaining(), 0, "trailing bytes after TP varint");
    v
}

/// RFC 9000 section 18.1 reserved ids `31 * N + 27`.
fn is_grease_tp(id: u64) -> bool {
    id >= 27 && (id - 27).is_multiple_of(31)
}

fn tp_value(tp: &[(u64, Vec<u8>)], id: u64) -> Option<&[u8]> {
    tp.iter().find(|(i, _)| *i == id).map(|(_, v)| v.as_slice())
}

/// Drive `config` through a sans-IO `quinn` client and capture the whole client
/// Initial flight (no socket bound), decrypting each Initial with the v1 salt
/// and reassembling the CRYPTO stream into the ClientHello. A fixed endpoint rng
/// `seed` keeps the DCID and the connection rng (parameter order, GREASE version)
/// reproducible; vary it to observe per-connection randomness.
fn capture_clienthello(
    config: quinn::ClientConfig,
    endpoint_config: quinn::EndpointConfig,
    seed: [u8; 32],
) -> Vec<u8> {
    let mut endpoint =
        quinn_proto::Endpoint::new(Arc::new(endpoint_config), None, false, Some(seed));
    let now = Instant::now();
    let remote = "203.0.113.1:443".parse().unwrap();
    let (_handle, mut conn) = endpoint
        .connect(now, config, remote, "www.example.com")
        .expect("sans-IO connect");

    let mut segments: Vec<(u64, Vec<u8>)> = Vec::new();
    // A post-quantum ClientHello spans two Initials; eight is ample headroom.
    for _ in 0..8 {
        let mut buf = Vec::new();
        let Some(transmit) = conn.poll_transmit(now, 1, &mut buf) else {
            break;
        };
        let dgram = &buf[..transmit.size];
        // Stop at the first non-Initial long-header packet.
        if dgram[0] & 0xf0 != 0xc0 {
            break;
        }
        let payload = decrypt_client_initial(dgram);
        segments.extend(parse_crypto_segments(&payload));
        if crypto_complete(&reassemble_crypto(&segments)) {
            break;
        }
    }

    let clienthello = reassemble_crypto(&segments);
    assert!(crypto_complete(&clienthello), "captured ClientHello CRYPTO is incomplete");
    clienthello
}

/// Regression for the H3 carrier config. The H3 QUIC config picks up the dial
/// fingerprint (PQ key share on the wire); the Safari profile leaves QUIC datagrams off
/// like Apple does, so `max_datagram_frame_size` (0x20) is absent.
#[tokio::test]
async fn h3_safari_config_has_no_datagram_param() {
    use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};

    let safari = with_dial_fingerprint(Some(TlsFingerprint::Safari), async {
        capture_clienthello(super::h3_quic_client_config(), super::h3_endpoint_config(), [0x11; 32])
    })
    .await;
    assert!(
        key_share_groups(&safari).contains(&0x11ec),
        "fingerprint scope must reach the H3 config (MLKEM768 key share)"
    );
    let has_datagram_param = transport_param_ids_from_clienthello(&safari).contains(&0x20);
    assert!(
        !has_datagram_param,
        "Safari profile must not advertise max_datagram_frame_size (0x20)"
    );
}

/// Chromium-profile H3 Initial carries exactly Chrome 156's transport parameters
/// (measured 2026-10-29).
#[tokio::test]
async fn h3_chromium_transport_params_match_chrome() {
    use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};
    use std::collections::BTreeSet;

    let ch = with_dial_fingerprint(Some(TlsFingerprint::Chromium), async {
        capture_clienthello(super::h3_quic_client_config(), super::h3_endpoint_config(), [0x11; 32])
    })
    .await;
    let tp = transport_params_from_clienthello(&ch);

    let ids: BTreeSet<u64> = tp.iter().map(|(id, _)| *id).filter(|id| !is_grease_tp(*id)).collect();
    assert_eq!(
        ids,
        BTreeSet::from([0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0f, 0x11, 0x20, 0x3128]),
        "unexpected transport-parameter set"
    );
    assert!(tp.iter().any(|(id, _)| is_grease_tp(*id)), "Chrome sends a GREASE parameter");
    // BTreeSet hides duplicates: the raw count is the set plus one GREASE entry.
    assert_eq!(tp.len(), ids.len() + 1, "duplicate or extra transport parameters");

    let int = |id| varint_value(tp_value(&tp, id).expect("parameter missing"));
    assert_eq!(int(0x01), 30_000, "max_idle_timeout");
    assert_eq!(int(0x03), 1472, "max_udp_payload_size");
    assert_eq!(int(0x04), 15_728_640, "initial_max_data");
    for id in [0x05, 0x06, 0x07] {
        assert_eq!(int(id), 6_291_456, "initial_max_stream_data {id:#x}");
    }
    assert_eq!(int(0x08), 100, "initial_max_streams_bidi");
    assert_eq!(int(0x09), 103, "initial_max_streams_uni");
    assert_eq!(tp_value(&tp, 0x0f), Some(&[][..]), "zero-length initial_source_connection_id");
    assert_eq!(int(0x20), 65_536, "max_datagram_frame_size");
    assert_eq!(tp_value(&tp, 0x3128), Some(&b"ORIG"[..]), "google_connection_options");
    let vi = tp_value(&tp, 0x11).expect("version_information");
    assert_eq!(vi.len(), 12);
    assert_eq!(&vi[..4], &[0, 0, 0, 1], "chosen version v1");
    let others = [
        u32::from_be_bytes(vi[4..8].try_into().unwrap()),
        u32::from_be_bytes(vi[8..12].try_into().unwrap()),
    ];
    assert!(others.contains(&1), "v1 among other_versions");
    assert!(
        others.iter().any(|v| *v & 0x0f0f_0f0f == 0x0a0a_0a0a),
        "GREASE version among other_versions"
    );
}

/// Firefox-profile H3 Initial carries Firefox 159's transport parameters in its fixed
/// order (measured 2026-10-29); only the source CID and the GREASE version vary.
#[tokio::test]
async fn h3_firefox_transport_params_match_firefox_159() {
    use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};

    for seed in [[0x11; 32], [0x22; 32]] {
        let ch = with_dial_fingerprint(Some(TlsFingerprint::Firefox), async {
            capture_clienthello(super::h3_quic_client_config(), super::h3_endpoint_config(), seed)
        })
        .await;
        let tp = transport_params_from_clienthello(&ch);
        let ids: Vec<u64> = tp.iter().map(|(id, _)| *id).collect();
        assert_eq!(
            ids,
            [
                0x01,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x0b,
                0x0e,
                0x0f,
                0x11,
                0x1d,
                0xff02_de1a,
                0x20
            ],
            "Firefox order"
        );
        let int = |id| varint_value(tp_value(&tp, id).expect("parameter missing"));
        assert_eq!(int(0x01), 30_000, "max_idle_timeout");
        assert_eq!(int(0x04), 25_165_824, "initial_max_data");
        assert_eq!(int(0x05), 12_582_912, "initial_max_stream_data_bidi_local");
        assert_eq!(int(0x06), 1_048_576, "initial_max_stream_data_bidi_remote");
        assert_eq!(int(0x07), 1_048_576, "initial_max_stream_data_uni");
        assert_eq!(int(0x08), 100, "initial_max_streams_bidi");
        assert_eq!(int(0x09), 100, "initial_max_streams_uni");
        assert_eq!(int(0x0b), 20, "max_ack_delay");
        assert_eq!(int(0x0e), 8, "active_connection_id_limit");
        assert_eq!(int(0x20), 65_535, "max_datagram_frame_size");
        assert_eq!(tp_value(&tp, 0x0f).map(<[u8]>::len), Some(3), "3-byte source CID");
        assert_eq!(tp_value(&tp, 0x1d), Some(&[][..]), "empty 0x1d");
        assert_eq!(tp_value(&tp, 0xff02_de1a), Some(&[0x43, 0xe8][..]), "draft min_ack_delay");
        let vi = tp_value(&tp, 0x11).expect("version_information");
        assert_eq!(vi.len(), 16);
        assert_eq!(&vi[..4], &[0, 0, 0, 1], "chosen version v1");
        let grease = u32::from_be_bytes(vi[4..8].try_into().unwrap());
        assert_eq!(grease & 0x0f0f_0f0f, 0x0a0a_0a0a, "GREASE version first");
        assert_eq!(&vi[8..], &[0x6b, 0x33, 0x43, 0xcf, 0, 0, 0, 1], "v2 then v1");
    }
}

/// Apple writes a fixed sequence rotated per connection, `0xff080808` always last.
#[tokio::test]
async fn h3_safari_order_is_rotated_apple_sequence() {
    use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};

    const APPLE: [u64; 7] = [0x04, 0x05, 0x06, 0x07, 0x09, 0x0e, 0x0f];
    let mut starts = std::collections::BTreeSet::new();
    for seed in 0..16u8 {
        let ch = with_dial_fingerprint(Some(TlsFingerprint::Safari), async move {
            capture_clienthello(
                super::h3_quic_client_config(),
                super::h3_endpoint_config(),
                [seed; 32],
            )
        })
        .await;
        let ids: Vec<u64> = transport_params_from_clienthello(&ch)
            .iter()
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(ids.last(), Some(&0xff08_0808), "Apple's private parameter is last");
        let start = APPLE
            .iter()
            .position(|id| *id == ids[0])
            .expect("starts with an Apple id");
        let mut rotated = APPLE;
        rotated.rotate_left(start);
        assert_eq!(ids[..APPLE.len()], rotated, "seed {seed}");
        starts.insert(start);
    }
    assert!(starts.len() > 1, "rotation never moved: {starts:?}");
}

/// The runtime stream window never falls below the largest advertised one.
#[test]
fn runtime_stream_window_covers_largest_advertised() {
    let fx = super::RuntimeWindows::current(&super::super::tp_profile::FIREFOX);
    assert!(fx.stream >= 12_582_912, "{fx:?}");
}

/// Safari (64, zero-length CIDs) and Firefox (8, 3-byte CIDs) profiles keep a healthy
/// connection to a quinn server that issues its 8 CIDs.
#[tokio::test]
async fn browser_profiles_accept_server_cids() {
    for tp in [&super::super::tp_profile::SAFARI, &super::super::tp_profile::FIREFOX] {
        let lb = loopback::Loopback::new();
        let server = lb.server.clone();
        let echo = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let msg = recv.read_to_end(64).await.unwrap();
            send.write_all(&msg).await.unwrap();
            send.finish().unwrap();
            conn.closed().await
        });
        let transport = super::build_h3_transport(tp, super::RuntimeWindows::current(tp));
        let (_ep, conn) = lb.connect(tp.endpoint_config(), transport).await;
        // Wait until the server has issued its NEW_CONNECTION_ID frames.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while conn.stats().frame_rx.new_connection_id < 7 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{}: timed out waiting for NEW_CONNECTION_ID frames, got {}",
                tp.name,
                conn.stats().frame_rx.new_connection_id
            )
        });
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"ping").await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"ping", "{}", tp.name);
        assert!(conn.close_reason().is_none(), "{}: {:?}", tp.name, conn.close_reason());
        assert!(conn.stats().frame_rx.new_connection_id >= 7, "{}", tp.name);
        conn.close(0u32.into(), b"done");
        echo.abort();
    }
}

/// Safari-profile H3 Initial follows Apple's Network.framework set: no idle timeout,
/// no max_udp_payload_size, no GREASE parameter, private 0xff080808, no bidi streams, 8 uni,
/// 16 MiB / 2 MiB windows, empty source CID, `active_connection_id_limit = 64`.
#[tokio::test]
async fn h3_safari_transport_params_match_apple() {
    use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};
    use std::collections::BTreeSet;

    let ch = with_dial_fingerprint(Some(TlsFingerprint::Safari), async {
        capture_clienthello(super::h3_quic_client_config(), super::h3_endpoint_config(), [0x11; 32])
    })
    .await;
    let tp = transport_params_from_clienthello(&ch);
    let ids: BTreeSet<u64> = tp.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, BTreeSet::from([0x04, 0x05, 0x06, 0x07, 0x09, 0x0e, 0x0f, 0xff08_0808]));
    assert_eq!(tp.len(), 8, "duplicate or extra transport parameters");
    assert!(!tp.iter().any(|(id, _)| is_grease_tp(*id)), "Apple sends no GREASE parameter");
    assert_eq!(tp_value(&tp, 0xff08_0808), Some(&[0x09][..]));
    let int = |id| tp_value(&tp, id).map(varint_value);
    assert_eq!(int(0x04), Some(16_777_216), "initial_max_data");
    for id in [0x05, 0x06, 0x07] {
        assert_eq!(int(id), Some(2_097_152), "initial_max_stream_data {id:#x}");
    }
    assert_eq!(int(0x09), Some(8), "initial_max_streams_uni");
    assert_eq!(int(0x0e), Some(64), "active_connection_id_limit");
    assert_eq!(tp_value(&tp, 0x0f), Some(&[][..]), "zero-length initial_source_connection_id");
}

/// Runtime windows never reach the Initial: with 32 MiB / 256 MiB granted after the
/// handshake, the Safari profile still advertises Apple's 2 MiB / 16 MiB.
#[tokio::test]
async fn runtime_windows_do_not_change_advertised_parameters() {
    use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};

    let runtime = super::RuntimeWindows { stream: 32 << 20, connection: 256 << 20 };
    let ch = with_dial_fingerprint(Some(TlsFingerprint::Safari), async {
        let mut config = super::h3_quic_client_config();
        config.transport_config(Arc::new(super::build_h3_transport(
            &super::super::tp_profile::SAFARI,
            runtime,
        )));
        capture_clienthello(config, super::h3_endpoint_config(), [0x11; 32])
    })
    .await;
    let tp = transport_params_from_clienthello(&ch);
    let int = |id| tp_value(&tp, id).map(varint_value);
    assert_eq!(int(0x04), Some(16_777_216), "initial_max_data");
    for id in [0x05, 0x06, 0x07] {
        assert_eq!(int(id), Some(2_097_152), "initial_max_stream_data {id:#x}");
    }
}

/// Bytes the server manages to write on one client-opened stream while the client
/// has read a single byte and then stalls for 1 s.
async fn written_before_stall(lb: &loopback::Loopback, transport: quinn::TransportConfig) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};

    let written = Arc::new(AtomicU64::new(0));
    let server_written = Arc::clone(&written);
    let server = lb.server.clone();
    let task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let mut hello = [0u8; 1];
        recv.read_exact(&mut hello).await.unwrap();
        let chunk = vec![0u8; 64 * 1024];
        loop {
            if send.write_all(&chunk).await.is_err() {
                break;
            }
            server_written.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
    });

    let (_ep, conn) = lb.connect(quinn::EndpointConfig::default(), transport).await;
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"h").await.unwrap();
    let mut first = [0u8; 1];
    recv.read_exact(&mut first).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    let total = written.load(Ordering::Relaxed);
    conn.close(0u32.into(), b"done");
    task.abort();
    total
}

#[tokio::test]
async fn stream_window_grows_past_advertised_after_first_read() {
    let lb = loopback::Loopback::new();
    let advertised = 2u32 << 20;

    let mut split = quinn::TransportConfig::default();
    split.stream_receive_window(quinn::VarInt::from_u32(8 << 20));
    super::super::vendored::set_advertised_stream_receive_window(&mut split, advertised);
    split.receive_window(quinn::VarInt::from_u32(64 << 20));
    let grown = written_before_stall(&lb, split).await;
    eprintln!("stream growth: split window wrote {grown} bytes");
    assert!(grown > 6 << 20, "runtime window not granted: {grown} bytes");

    let mut same = quinn::TransportConfig::default();
    same.stream_receive_window(quinn::VarInt::from_u32(advertised));
    same.receive_window(quinn::VarInt::from_u32(64 << 20));
    let capped = written_before_stall(&lb, same).await;
    eprintln!("stream growth: control wrote {capped} bytes");
    assert!(
        capped <= u64::from(advertised) + (64 << 10),
        "control not capped: {capped} bytes"
    );
}

/// Total bytes the server writes across four client-opened streams while the client
/// has read one byte per stream and stalls for 1 s. `raise` is applied right after
/// the handshake.
async fn written_across_streams(
    lb: &loopback::Loopback,
    raise: Option<super::RuntimeWindows>,
) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};

    let mut transport = quinn::TransportConfig::default();
    transport.receive_window(quinn::VarInt::from_u32(16 << 20));
    transport.stream_receive_window(quinn::VarInt::from_u32(8 << 20));

    let written = Arc::new(AtomicU64::new(0));
    let server = lb.server.clone();
    let server_written = Arc::clone(&written);
    let task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        // Answer every stream with one byte first and only then start the bulk writers:
        // with a large server send window the first stream would otherwise drain the whole
        // connection credit before the later streams get their first byte.
        let mut streams = Vec::new();
        for _ in 0..4 {
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let mut hello = [0u8; 1];
            recv.read_exact(&mut hello).await.unwrap();
            send.write_all(b"k").await.unwrap();
            streams.push((send, recv));
        }
        let mut writers = Vec::new();
        for (mut send, recv) in streams {
            let counter = Arc::clone(&server_written);
            writers.push(tokio::spawn(async move {
                let _recv = recv;
                let chunk = vec![0u8; 64 * 1024];
                while send.write_all(&chunk).await.is_ok() {
                    counter.fetch_add(chunk.len() as u64, Ordering::Relaxed);
                }
            }));
        }
        // Hold the writer handles until the test aborts this task.
        let _writers = writers;
        std::future::pending::<()>().await;
    });

    let (_ep, conn) = lb.connect(quinn::EndpointConfig::default(), transport).await;
    if let Some(runtime) = raise {
        super::raise_receive_window(&conn, runtime);
    }
    let mut recvs = Vec::new();
    for _ in 0..4 {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"h").await.unwrap();
        let mut first = [0u8; 1];
        recv.read_exact(&mut first).await.unwrap();
        recvs.push((send, recv));
    }
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    let total = written.load(Ordering::Relaxed);
    conn.close(0u32.into(), b"done");
    task.abort();
    total
}

#[tokio::test]
async fn connection_window_raised_after_handshake() {
    let lb = loopback::Loopback::new();

    let raised = written_across_streams(
        &lb,
        Some(super::RuntimeWindows { stream: 8 << 20, connection: 64 << 20 }),
    )
    .await;
    eprintln!("connection growth: raised wrote {raised} bytes");
    assert!(raised > 18 << 20, "connection window not raised: {raised} bytes");

    let control = written_across_streams(&lb, None).await;
    eprintln!("connection growth: control wrote {control} bytes");
    assert!(control <= (16 << 20) + (64 << 10), "control not capped: {control} bytes");
}

/// The extra parameter's position and the GREASE version change from connection to
/// connection, as in Chrome.
#[tokio::test]
async fn chromium_extras_and_grease_version_vary_per_connection() {
    use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};
    use std::collections::BTreeSet;

    let mut positions = BTreeSet::new();
    let mut grease_versions = BTreeSet::new();
    let mut extra_before_vi = BTreeSet::new();
    let mut v1_first = BTreeSet::new();
    for i in 0..16u8 {
        let ch = with_dial_fingerprint(Some(TlsFingerprint::Chromium), async {
            capture_clienthello(
                super::h3_quic_client_config(),
                super::h3_endpoint_config(),
                [i.wrapping_add(1); 32],
            )
        })
        .await;
        let tp = transport_params_from_clienthello(&ch);
        let extra_pos = tp.iter().position(|(id, _)| *id == 0x3128).unwrap();
        positions.insert(extra_pos);
        extra_before_vi.insert(extra_pos < tp.iter().position(|(id, _)| *id == 0x11).unwrap());
        let vi = tp_value(&tp, 0x11).unwrap();
        v1_first.insert(vi[4..8] == [0, 0, 0, 1]);
        for chunk in vi[4..].chunks(4) {
            let v = u32::from_be_bytes(chunk.try_into().unwrap());
            if v != 1 {
                grease_versions.insert(v);
            }
        }
    }
    assert!(positions.len() > 1, "extra parameter always at the same position");
    assert!(grease_versions.len() > 1, "GREASE version never changes");
    assert_eq!(extra_before_vi.len(), 2, "0x3128 / 0x11 relative order never changes");
    assert_eq!(v1_first.len(), 2, "other_versions order never changes");
}

/// A profile that omits `max_idle_timeout` from the wire still enforces its local idle
/// timer: an idle connection closes with `TimedOut` after ~500 ms.
#[tokio::test]
async fn safari_local_idle_timeout_applies_without_advertisement() {
    use std::time::Duration;

    let lb = loopback::Loopback::new();
    let server = lb.server.clone();
    let accepted = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        // Keep the server side alive (it never sends anything) until the test ends.
        conn.closed().await;
    });

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_millis(500).try_into().unwrap()));
    super::super::vendored::apply_browser_tp_options(
        &mut transport,
        &super::super::tp_profile::SAFARI.options,
    );
    let (_endpoint, conn) = lb
        .connect(super::super::tp_profile::SAFARI.endpoint_config(), transport)
        .await;

    let started = Instant::now();
    let err = tokio::time::timeout(Duration::from_secs(5), conn.closed())
        .await
        .expect("connection must close on local idle within 5 s");
    assert!(matches!(err, quinn::ConnectionError::TimedOut), "unexpected close: {err:?}");
    assert!(
        started.elapsed() >= Duration::from_millis(400),
        "closed too early: {:?}",
        started.elapsed()
    );
    accepted.abort();
}

/// Without any patch option the client Initial keeps upstream's shape: shuffled order,
/// `active_connection_id_limit = 5` for 8-byte CIDs, no `max_ack_delay`, no
/// `version_information`.
#[tokio::test]
async fn default_transport_keeps_upstream_parameter_shape() {
    let mut orders = std::collections::BTreeSet::new();
    for seed in 1..=8u8 {
        let mut config = super::h3_quic_client_config();
        config.transport_config(Arc::new(quinn::TransportConfig::default()));
        let ch = capture_clienthello(config, quinn::EndpointConfig::default(), [seed; 32]);
        let tp = transport_params_from_clienthello(&ch);
        assert_eq!(tp_value(&tp, 0x0e).map(varint_value), Some(5), "active_connection_id_limit");
        assert!(tp_value(&tp, 0x0b).is_none(), "default max_ack_delay is not written");
        assert!(tp_value(&tp, 0x11).is_none(), "no version_information by default");
        orders.insert(tp.iter().map(|(id, _)| *id).collect::<Vec<_>>());
    }
    assert!(orders.len() > 1, "default order must stay shuffled");
}

/// `Fixed` writes the listed ids in order, extras included; `Rotated` rotates only the
/// ids quinn writes itself and keeps listed extras after them.
#[tokio::test]
async fn listed_orders_shape_the_initial() {
    use super::super::vendored::{BrowserTpOptions, TpOrder, apply_browser_tp_options};

    let base = super::super::tp_profile::SAFARI.options;
    let capture = |order: TpOrder, seed: u8| {
        let mut transport = quinn::TransportConfig::default();
        // Safari's own 0x0e would join the order; keep the id set the assertions list.
        let opts = BrowserTpOptions {
            order,
            active_connection_id_limit: None,
            ..base
        };
        apply_browser_tp_options(&mut transport, &opts);
        transport.max_concurrent_bidi_streams(0u32.into());
        let mut config = super::h3_quic_client_config();
        config.transport_config(Arc::new(transport));
        let ch = capture_clienthello(
            config,
            super::super::tp_profile::SAFARI.endpoint_config(),
            [seed; 32],
        );
        transport_params_from_clienthello(&ch)
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>()
    };

    // 0x0f is listed first, the extra in the middle, 0x04 after it; 0x05..0x07, 0x09
    // are unlisted and follow in upstream order.
    let fixed = capture(TpOrder::Fixed(&[0x0f, 0xff08_0808, 0x04]), 1);
    assert_eq!(fixed, [0x0f, 0xff08_0808, 0x04, 0x05, 0x06, 0x07, 0x09]);

    const SEQ: [u64; 6] = [0x04, 0x05, 0x06, 0x07, 0x09, 0x0f];
    let mut starts = std::collections::BTreeSet::new();
    for seed in 0..16u8 {
        let ids =
            capture(TpOrder::Rotated(&[0x04, 0x05, 0x06, 0x07, 0x09, 0x0f, 0xff08_0808]), seed);
        assert_eq!(ids.last(), Some(&0xff08_0808), "listed extra stays after the rotation");
        let start = SEQ
            .iter()
            .position(|id| *id == ids[0])
            .expect("starts with a listed id");
        let mut rotated = SEQ;
        rotated.rotate_left(start);
        assert_eq!(ids[..SEQ.len()], rotated, "seed {seed}");
        starts.insert(start);
    }
    assert!(starts.len() > 1, "rotation never moved: {starts:?}");

    // A listed extra that is NOT last still follows the known ids in a rotation, also
    // when the draw is a shift of 0.
    let mut starts = std::collections::BTreeSet::new();
    for seed in 0..64u8 {
        let ids =
            capture(TpOrder::Rotated(&[0x04, 0xff08_0808, 0x05, 0x06, 0x07, 0x09, 0x0f]), seed);
        assert_eq!(ids.last(), Some(&0xff08_0808), "extra after the rotation, seed {seed}");
        let start = SEQ
            .iter()
            .position(|id| *id == ids[0])
            .expect("starts with a listed id");
        let mut rotated = SEQ;
        rotated.rotate_left(start);
        assert_eq!(ids[..SEQ.len()], rotated, "seed {seed}");
        starts.insert(start);
    }
    assert!(starts.contains(&0), "no seed drew shift 0: {starts:?}");
}

/// `version_information` follows the configured slots; `max_ack_delay` is advertised.
#[tokio::test]
async fn version_information_form_and_max_ack_delay_are_written() {
    use super::super::vendored::{
        BrowserTpOptions, VersionInfo, VersionSlot, apply_browser_tp_options,
    };

    let mut transport = quinn::TransportConfig::default();
    apply_browser_tp_options(
        &mut transport,
        &BrowserTpOptions {
            version_information: Some(VersionInfo {
                other_versions: &[
                    VersionSlot::Grease,
                    VersionSlot::Version(0x6b33_43cf),
                    VersionSlot::Version(1),
                ],
                shuffle: false,
            }),
            max_ack_delay_ms: 20,
            ..super::super::tp_profile::CHROMIUM.options
        },
    );
    let mut config = super::h3_quic_client_config();
    config.transport_config(Arc::new(transport));
    let ch = capture_clienthello(config, quinn::EndpointConfig::default(), [7; 32]);
    let tp = transport_params_from_clienthello(&ch);
    assert_eq!(tp_value(&tp, 0x0b).map(varint_value), Some(20), "max_ack_delay");
    let vi = tp_value(&tp, 0x11).expect("version_information");
    assert_eq!(vi.len(), 16);
    assert_eq!(&vi[..4], &[0, 0, 0, 1], "chosen version v1");
    let grease = u32::from_be_bytes(vi[4..8].try_into().unwrap());
    assert_eq!(grease & 0x0f0f_0f0f, 0x0a0a_0a0a, "GREASE version first");
    assert_eq!(&vi[8..], &[0x6b, 0x33, 0x43, 0xcf, 0, 0, 0, 1], "v2 then v1");
}

/// A client that advertises more CIDs than quinn's old 5-entry queue (64, like Apple)
/// accepts the 8 our server issues instead of failing with CONNECTION_ID_LIMIT_ERROR.
#[tokio::test]
async fn advertised_cid_limit_above_queue_capacity_accepts_server_cids() {
    use super::super::vendored::{BrowserTpOptions, apply_browser_tp_options};

    let lb = loopback::Loopback::new();
    let server = lb.server.clone();
    let echo = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let msg = recv.read_to_end(64).await.unwrap();
        send.write_all(&msg).await.unwrap();
        send.finish().unwrap();
        conn.closed().await
    });

    let mut transport = quinn::TransportConfig::default();
    apply_browser_tp_options(
        &mut transport,
        &BrowserTpOptions {
            active_connection_id_limit: Some(64),
            ..super::super::tp_profile::CHROMIUM.options
        },
    );
    let (_ep, conn) = lb.connect(quinn::EndpointConfig::default(), transport).await;
    // Wait until the server has issued its NEW_CONNECTION_ID frames.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while conn.stats().frame_rx.new_connection_id < 7 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "timed out waiting for NEW_CONNECTION_ID frames, got {}",
            conn.stats().frame_rx.new_connection_id
        )
    });
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(64).await.unwrap(), b"ping");
    assert!(conn.close_reason().is_none(), "{:?}", conn.close_reason());
    assert!(
        conn.stats().frame_rx.new_connection_id >= 7,
        "server issued {} CIDs",
        conn.stats().frame_rx.new_connection_id
    );
    conn.close(0u32.into(), b"done");
    echo.abort();
}

#[derive(Debug, Clone, Copy)]
enum Opened {
    ClientBidi,
    ServerBidi,
    ServerUni,
}

/// Bytes the server writes on one stream that the client never reads, within 1 s.
async fn server_writes_unread(
    lb: &loopback::Loopback,
    transport: quinn::TransportConfig,
    opened: Opened,
) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};

    let written = Arc::new(AtomicU64::new(0));
    let server_written = Arc::clone(&written);
    let server = lb.server.clone();
    let task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let mut send = match opened {
            Opened::ClientBidi => {
                let (send, mut recv) = conn.accept_bi().await.unwrap();
                let mut hello = [0u8; 1];
                recv.read_exact(&mut hello).await.unwrap();
                send
            },
            Opened::ServerBidi => conn.open_bi().await.unwrap().0,
            Opened::ServerUni => conn.open_uni().await.unwrap(),
        };
        let chunk = vec![0u8; 64 * 1024];
        while send.write_all(&chunk).await.is_ok() {
            server_written.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
    });

    let (_ep, conn) = lb.connect(quinn::EndpointConfig::default(), transport).await;
    // Kept alive: dropping a RecvStream sends STOP_SENDING.
    let _client_stream = match opened {
        Opened::ClientBidi => {
            let (mut send, recv) = conn.open_bi().await.unwrap();
            send.write_all(b"h").await.unwrap();
            Some((send, recv))
        },
        Opened::ServerBidi | Opened::ServerUni => None,
    };
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    let total = written.load(Ordering::Relaxed);
    conn.close(0u32.into(), b"done");
    task.abort();
    total
}

/// Each new receive stream starts with the credit of its own class.
#[tokio::test]
async fn stream_credit_follows_stream_direction() {
    const LOCAL: u32 = 256 << 10;
    const REMOTE: u32 = 1 << 20;
    const UNI: u32 = 2 << 20;
    const SLACK: u64 = 64 << 10;

    let lb = loopback::Loopback::new();
    let transport = || {
        let mut t = quinn::TransportConfig::default();
        t.stream_receive_window(quinn::VarInt::from_u32(UNI));
        t.receive_window(quinn::VarInt::from_u32(64 << 20));
        super::super::vendored::set_advertised_stream_receive_windows(&mut t, LOCAL, REMOTE, UNI);
        t
    };
    for (opened, window) in
        [(Opened::ClientBidi, LOCAL), (Opened::ServerBidi, REMOTE), (Opened::ServerUni, UNI)]
    {
        let written = server_writes_unread(&lb, transport(), opened).await;
        eprintln!("{opened:?}: {written} bytes");
        let window = u64::from(window);
        assert!(
            written + SLACK >= window && written <= window + SLACK,
            "{opened:?} wrote {written}, expected about {window}"
        );
    }
}

/// Per-direction windows reach the Initial as three different parameters.
#[tokio::test]
async fn per_direction_windows_are_advertised() {
    let mut transport = quinn::TransportConfig::default();
    super::super::vendored::set_advertised_stream_receive_windows(
        &mut transport,
        12_582_912,
        1_048_576,
        524_288,
    );
    let mut config = super::h3_quic_client_config();
    config.transport_config(Arc::new(transport));
    let ch = capture_clienthello(config, quinn::EndpointConfig::default(), [3; 32]);
    let tp = transport_params_from_clienthello(&ch);
    let int = |id| tp_value(&tp, id).map(varint_value);
    assert_eq!(int(0x05), Some(12_582_912), "bidi_local");
    assert_eq!(int(0x06), Some(1_048_576), "bidi_remote");
    assert_eq!(int(0x07), Some(524_288), "uni");
}

// ---------------------------------------------------------------------------
// rustls patch "client-hello-shape" (gate: `crate::tls_vendored`)
// ---------------------------------------------------------------------------

#[test]
fn ja4_helper_reproduces_measured_chrome_hash() {
    // JA4_r of the Chrome 156 capture -> its JA4 c-part.
    let c = "000a,000d,001b,002b,002d,0033,0039,44cd,ca34,fe0d_0403,0804,0401,0503,0805,0501,0806,0601,0201";
    assert_eq!(sha256_hex12(c), "178839b6cec1");
    assert_eq!(sha256_hex12("1301,1302,1303"), "55b375c5d22e");
}

/// Capture the Initial ClientHello of a QUIC client config built from `tls`.
fn capture_with_tls(tls: rustls::ClientConfig, seed: u8) -> Vec<u8> {
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    capture_clienthello(
        quinn::ClientConfig::new(Arc::new(quic)),
        quinn::EndpointConfig::default(),
        [seed; 32],
    )
}

/// aws-lc-rs default provider with the post-quantum hybrid leading, as browsers (and our
/// fingerprint providers) offer it; this crate does not enable `prefer-post-quantum`.
fn pq_first_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::aws_lc_rs::kx_group;
    rustls::crypto::CryptoProvider {
        kx_groups: vec![
            kx_group::X25519MLKEM768,
            kx_group::X25519,
            kx_group::SECP256R1,
            kx_group::SECP384R1,
        ],
        ..rustls::crypto::aws_lc_rs::default_provider()
    }
}

fn aws_lc_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(pq_first_provider())
}

fn finish_tls13(
    builder: rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>,
    roots: Arc<rustls::RootCertStore>,
) -> rustls::ClientConfig {
    let mut tls = builder.with_root_certificates(roots).with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls
}

/// TLS 1.3-only aws-lc-rs client config (ALPN h3) trusting `roots`.
fn tls13_config_with_roots(roots: Arc<rustls::RootCertStore>) -> rustls::ClientConfig {
    finish_tls13(
        rustls::ClientConfig::builder_with_provider(aws_lc_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap(),
        roots,
    )
}

fn tls13_config() -> rustls::ClientConfig {
    tls13_config_with_roots(Arc::new(rustls::RootCertStore::empty()))
}

/// Like [`tls13_config_with_roots`], offering GREASE ECH (X25519 / HKDF-SHA256 / AES-128).
fn tls13_ech_grease_config(roots: Arc<rustls::RootCertStore>) -> rustls::ClientConfig {
    use rustls::client::{EchGreaseConfig, EchMode};
    let placeholder = rustls::crypto::hpke::HpkePublicKey(vec![0x42; 32]);
    let mode = EchMode::Grease(EchGreaseConfig::new(
        rustls::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128,
        placeholder,
    ));
    finish_tls13(
        rustls::ClientConfig::builder_with_provider(aws_lc_provider())
            .with_ech(mode)
            .unwrap(),
        roots,
    )
}

/// The full shape: omissions, a raw extension, GREASE, a fixed order and an extra
/// `secp256r1` key share.
fn full_shape() -> crate::tls_vendored::ClientHelloShape {
    use crate::tls_vendored::{ClientHelloShape, ExtensionOrder};
    ClientHelloShape {
        omit_extended_master_secret: true,
        omit_ec_point_formats: true,
        omit_status_request: false,
        extra_extensions: vec![(18, vec![])],
        grease: true,
        extension_order: ExtensionOrder::Fixed(vec![0, 10, 16, 5, 13, 18, 51, 45, 43, 57]),
        extra_key_share_groups: vec![rustls::NamedGroup::secp256r1],
        ech_grease_payload_lengths: vec![],
        wire_cipher_suites: vec![],
        advertise_tls12: false,
        grease_signature_algorithms: false,
        alps: vec![],
    }
}

#[tokio::test]
async fn default_shape_keeps_upstream_extensions() {
    let ch = capture_with_tls(tls13_config(), 1);
    let mut ids = extension_types(&ch);
    ids.sort();
    assert_eq!(ids, [0, 5, 10, 11, 13, 16, 23, 43, 45, 51, 57]);
    assert_eq!(ja4(&ch)[..10], *"q13d0311h3");
    assert!(!cipher_suites(&ch).iter().any(|c| is_grease_u16(*c)));
    assert_eq!(key_share_groups(&ch), [0x11ec, 0x1d]);
}

/// An explicit `ExtensionOrder::Upstream` shape with nothing else set encodes the same
/// extension set as no shape at all.
#[tokio::test]
async fn empty_shape_matches_upstream_set() {
    use crate::tls_vendored::{ClientHelloShape, set_client_hello_shape};
    let mut tls = tls13_config();
    set_client_hello_shape(&mut tls, ClientHelloShape::default());
    let ch = capture_with_tls(tls, 1);
    let mut ids = extension_types(&ch);
    ids.sort();
    assert_eq!(ids, [0, 5, 10, 11, 13, 16, 23, 43, 45, 51, 57]);
    assert_eq!(cipher_suites(&ch), cipher_suites(&capture_with_tls(tls13_config(), 1)));
}

#[tokio::test]
async fn shape_omits_adds_and_greases() {
    use crate::tls_vendored::{ClientHelloShape, ExtensionOrder, set_client_hello_shape};
    let mut tls = tls13_config();
    set_client_hello_shape(
        &mut tls,
        ClientHelloShape {
            omit_extended_master_secret: true,
            omit_ec_point_formats: true,
            omit_status_request: false,
            extra_extensions: vec![(18, vec![])],
            grease: true,
            extension_order: ExtensionOrder::Fixed(vec![0, 10, 16, 5, 13, 18, 51, 45, 43, 57]),
            extra_key_share_groups: vec![],
            ech_grease_payload_lengths: vec![],
            wire_cipher_suites: vec![],
            advertise_tls12: false,
            grease_signature_algorithms: false,
            alps: vec![],
        },
    );
    let mut first_greases = std::collections::BTreeSet::new();
    for seed in 0..8u8 {
        let ch = capture_with_tls(tls.clone(), seed);
        let exts = extensions(&ch);
        let ids = extension_types(&ch);
        assert!(is_grease_u16(ids[0]) && is_grease_u16(*ids.last().unwrap()), "{ids:x?}");
        assert_ne!(ids[0], *ids.last().unwrap(), "two distinct GREASE extensions");
        assert_eq!(ids[1..ids.len() - 1], [0, 10, 16, 5, 13, 18, 51, 45, 43, 57]);
        assert_eq!(exts[0].1, [0u8; 0], "first GREASE extension is empty");
        assert_eq!(exts.last().unwrap().1, [0u8], "last GREASE extension is one zero byte");
        assert_eq!(extension(&ch, 18), Some(&[][..]), "raw SCT extension");
        first_greases.insert(ids[0]);

        let ciphers = cipher_suites(&ch);
        assert!(is_grease_u16(ciphers[0]), "{ciphers:x?}");
        assert!(!ciphers[1..].iter().any(|c| is_grease_u16(*c)));
        let groups = u16_list_ext(&ch, 10);
        assert!(is_grease_u16(groups[0]), "{groups:x?}");
        assert!(!groups[1..].iter().any(|g| is_grease_u16(*g)));
        // key_share: GREASE entry with a 1-byte key first, then the upstream shares.
        let shares = key_share_entries(&ch);
        assert_eq!(shares[0], (groups[0], 1), "GREASE share uses the GREASE group, key 00");
        assert_eq!(shares[1..].iter().map(|(g, _)| *g).collect::<Vec<_>>(), [0x11ec, 0x1d]);
        // supported_versions: GREASE first.
        let versions = supported_versions(&ch);
        assert!(is_grease_u16(versions[0]), "{versions:x?}");
        assert_eq!(versions[1..], [0x0304]);
        assert_eq!(ja4(&ch)[..10], *"q13d0310h3", "GREASE is not counted");
    }
    assert!(first_greases.len() > 1, "GREASE values are drawn per connection");
}

#[tokio::test]
async fn extra_key_share_and_shuffled_ech() {
    use crate::tls_vendored::{ClientHelloShape, ExtensionOrder, set_client_hello_shape};
    let empty = || Arc::new(rustls::RootCertStore::empty());

    // Upstream order keeps ECH last; ShuffledWithEch moves it around.
    let upstream = tls13_ech_grease_config(empty());
    for seed in 0..16u8 {
        let ids = extension_types(&capture_with_tls(upstream.clone(), seed));
        assert_eq!(*ids.last().unwrap(), 0xfe0d, "upstream keeps ECH last: {ids:x?}");
    }

    let mut tls = tls13_ech_grease_config(empty());
    set_client_hello_shape(
        &mut tls,
        ClientHelloShape {
            extension_order: ExtensionOrder::ShuffledWithEch,
            extra_key_share_groups: vec![rustls::NamedGroup::secp256r1],
            ..ClientHelloShape::default()
        },
    );
    let mut ech_positions = std::collections::BTreeSet::new();
    for seed in 0..16u8 {
        let ch = capture_with_tls(tls.clone(), seed);
        assert_eq!(key_share_groups(&ch), [0x11ec, 0x1d, 0x17]);
        let p256 = key_share_entries(&ch)[2];
        assert_eq!(p256, (0x17, 65), "uncompressed P-256 point");
        let ids = extension_types(&ch);
        let pos = ids.iter().position(|e| *e == 0xfe0d).expect("GREASE ECH sent");
        ech_positions.insert(ids.len() - 1 - pos);
    }
    assert!(ech_positions.iter().any(|p| *p != 0), "0xfe0d is not always last");
}

/// GREASE ECH payload length (`ech_grease_payload_lengths`): empty keeps rustls' sizing
/// from the padded inner hello, one value is used as-is, several are drawn per connection.
#[tokio::test]
async fn ech_grease_payload_lengths_shape_the_payload() {
    use crate::tls_vendored::{ClientHelloShape, set_client_hello_shape};
    let empty = || Arc::new(rustls::RootCertStore::empty());
    let shaped = |lengths: Vec<u16>| {
        let mut tls = tls13_ech_grease_config(empty());
        set_client_hello_shape(
            &mut tls,
            ClientHelloShape {
                ech_grease_payload_lengths: lengths,
                ..ClientHelloShape::default()
            },
        );
        tls
    };
    let payload =
        |tls: &rustls::ClientConfig, seed: u8| ech_outer(&capture_with_tls(tls.clone(), seed)).3;

    let upstream = tls13_ech_grease_config(empty());
    let default_shape = shaped(vec![]);
    let fixed = shaped(vec![240]);
    let several = shaped(vec![176, 208, 240]);
    let mut drawn = std::collections::BTreeSet::new();
    for seed in 0..16u8 {
        let up = payload(&upstream, seed);
        // Upstream: padded inner hello (multiple of 32) plus the 16-byte tag.
        assert_eq!((up - 16) % 32, 0, "{up}");
        assert!(up > 240, "inner hello with 240 bytes of name padding: {up}");
        assert_eq!(payload(&default_shape, seed), up, "empty list keeps upstream sizing");
        assert_eq!(payload(&fixed, seed), 240);
        let p = payload(&several, seed);
        assert!([176, 208, 240].contains(&p), "{p}");
        drawn.insert(p);
    }
    assert!(drawn.len() >= 2, "{drawn:?}");
}

/// A GREASE ECH payload length from the shape survives a HelloRetryRequest (the
/// extension is carried forward, not rebuilt) and the handshake completes.
#[tokio::test]
async fn ech_grease_payload_length_survives_hello_retry_request() {
    use rustls::crypto::aws_lc_rs::kx_group;
    let lb = loopback::Loopback::with_server_tls(server_with_groups(vec![kx_group::SECP384R1]));
    let mut tls = tls13_ech_grease_config(lb.roots());
    let mut shape = full_shape();
    shape.ech_grease_payload_lengths = vec![176, 208, 240];
    crate::tls_vendored::set_client_hello_shape(&mut tls, shape);
    echo_with_tls(&lb, tls).await;
}

/// `secp521r1` from the gate is offered in supported_groups when put in the provider.
#[tokio::test]
async fn secp521r1_is_offered_from_the_provider() {
    let mut provider = pq_first_provider();
    provider.kx_groups.push(crate::tls_vendored::secp521r1());
    let tls = finish_tls13(
        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap(),
        Arc::new(rustls::RootCertStore::empty()),
    );
    let ch = capture_with_tls(tls, 1);
    assert_eq!(*u16_list_ext(&ch, 10).last().unwrap(), 0x19);
    assert!(
        !rustls::crypto::aws_lc_rs::DEFAULT_KX_GROUPS
            .iter()
            .any(|g| g.name() == rustls::NamedGroup::secp521r1)
    );
    assert!(
        !rustls::crypto::aws_lc_rs::ALL_KX_GROUPS
            .iter()
            .any(|g| g.name() == rustls::NamedGroup::secp521r1)
    );
}

/// Server config builder over aws-lc-rs restricted to `groups`.
fn server_with_groups(
    groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
) -> rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier> {
    let provider = rustls::crypto::CryptoProvider {
        kx_groups: groups,
        ..rustls::crypto::aws_lc_rs::default_provider()
    };
    rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
}

/// Handshakes `tls` with `lb`, echoes one message and returns the client's stats.
async fn echo_with_tls(
    lb: &loopback::Loopback,
    tls: rustls::ClientConfig,
) -> quinn::ConnectionStats {
    let server = lb.server.clone();
    let echo = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let msg = recv.read_to_end(64).await.unwrap();
        send.write_all(&msg).await.unwrap();
        send.finish().unwrap();
        conn.closed().await
    });
    let quic = Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap());
    let (_ep, conn) = lb
        .connect_with_tls(quic, quinn::EndpointConfig::default(), quinn::TransportConfig::default())
        .await;
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(64).await.unwrap(), b"ping");
    assert!(conn.close_reason().is_none(), "{:?}", conn.close_reason());
    let stats = conn.stats();
    conn.close(0u32.into(), b"done");
    echo.abort();
    stats
}

/// The full shape (GREASE everywhere, raw extension, fixed order, extra key share, GREASE
/// ECH) completes a handshake with the rustls server and carries data.
#[tokio::test]
async fn shaped_client_handshakes_with_rustls_server() {
    let lb = loopback::Loopback::new();
    let mut tls = tls13_ech_grease_config(lb.roots());
    crate::tls_vendored::set_client_hello_shape(&mut tls, full_shape());
    echo_with_tls(&lb, tls).await;
}

/// A server limited to the extra share's group completes the exchange with that share,
/// without a HelloRetryRequest: the client sends exactly as many CRYPTO frames as against a
/// server that takes the first share, and fewer than the same client without the extra
/// share (which does go through HRR). Also covers `secp521r1` as an extra share.
#[tokio::test]
async fn extra_key_share_avoids_hello_retry_request() {
    use rustls::crypto::aws_lc_rs::kx_group;
    // A lost packet makes the client retransmit CRYPTO frames, which would skew the
    // comparison below; fail loudly instead of reporting a misleading inequality.
    let crypto_frames = |run: &str, s: quinn::ConnectionStats| {
        assert_eq!(
            s.path.lost_packets, 0,
            "{run}: packet loss in a loopback run makes CRYPTO frame counts incomparable"
        );
        s.frame_tx.crypto
    };

    for (group, name) in [
        (kx_group::SECP256R1, rustls::NamedGroup::secp256r1),
        (crate::tls_vendored::secp521r1(), rustls::NamedGroup::secp521r1),
    ] {
        let mut provider = pq_first_provider();
        if !provider.kx_groups.iter().any(|g| g.name() == name) {
            provider.kx_groups.push(group);
        }
        let provider = Arc::new(provider);
        let client = |roots, extra: bool| {
            let mut tls = finish_tls13(
                rustls::ClientConfig::builder_with_provider(provider.clone())
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .unwrap(),
                roots,
            );
            let mut shape = full_shape();
            shape.extra_key_share_groups = if extra { vec![name] } else { vec![] };
            crate::tls_vendored::set_client_hello_shape(&mut tls, shape);
            tls
        };

        let baseline_lb = loopback::Loopback::new();
        let baseline = crypto_frames(
            "baseline",
            echo_with_tls(&baseline_lb, client(baseline_lb.roots(), true)).await,
        );

        let restricted = loopback::Loopback::with_server_tls(server_with_groups(vec![group]));
        let with_extra = crypto_frames(
            "extra share",
            echo_with_tls(&restricted, client(restricted.roots(), true)).await,
        );
        let restricted = loopback::Loopback::with_server_tls(server_with_groups(vec![group]));
        let with_hrr = crypto_frames(
            "HRR control",
            echo_with_tls(&restricted, client(restricted.roots(), false)).await,
        );

        eprintln!(
            "{name:?}: client CRYPTO frames baseline={baseline} extra={with_extra} hrr={with_hrr}"
        );
        assert_eq!(with_extra, baseline, "{name:?}: no HRR with the extra share");
        assert!(with_hrr > with_extra, "{name:?}: HRR control {with_hrr} vs {with_extra}");
    }
}

/// A shaped ClientHello survives a HelloRetryRequest (server only on `secp384r1`): GREASE
/// and the extra share are handled on the second hello and the handshake completes.
#[tokio::test]
async fn shaped_client_survives_hello_retry_request() {
    use rustls::crypto::aws_lc_rs::kx_group;
    let lb = loopback::Loopback::with_server_tls(server_with_groups(vec![kx_group::SECP384R1]));
    let mut tls = tls13_config_with_roots(lb.roots());
    crate::tls_vendored::set_client_hello_shape(&mut tls, full_shape());
    echo_with_tls(&lb, tls).await;
}

/// After a server picks plain `x25519`, upstream's session store hints that group and the
/// next hello to the same server drops the `X25519MLKEM768` share (it then fits in fewer
/// CRYPTO frames). `NoKxHintStore` keeps both shares, so the second dial sends as many
/// CRYPTO frames as the first.
#[tokio::test]
async fn no_kx_hint_store_keeps_post_quantum_share_on_later_dials() {
    use rustls::crypto::aws_lc_rs::kx_group;
    let crypto_frames = |run: &str, s: quinn::ConnectionStats| {
        assert_eq!(s.path.lost_packets, 0, "{run}: loss makes CRYPTO frame counts incomparable");
        s.frame_tx.crypto
    };
    let lb = loopback::Loopback::with_server_tls(server_with_groups(vec![kx_group::X25519]));
    let client = || {
        finish_tls13(
            rustls::ClientConfig::builder_with_provider(Arc::new(pq_first_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap(),
            lb.roots(),
        )
    };

    // Control: upstream's in-memory store applies the hint on the second dial.
    let upstream = client();
    let first = crypto_frames("upstream 1", echo_with_tls(&lb, upstream.clone()).await);
    let second = crypto_frames("upstream 2", echo_with_tls(&lb, upstream).await);
    assert!(second < first, "control: hinted hello should shrink ({first} -> {second})");

    let mut patched = client();
    patched.resumption =
        rustls::client::Resumption::store(Arc::new(crate::tls_hello::NoKxHintStore::new()));
    let first = crypto_frames("no hint 1", echo_with_tls(&lb, patched.clone()).await);
    let second = crypto_frames("no hint 2", echo_with_tls(&lb, patched).await);
    assert_eq!(second, first, "the second hello keeps the X25519MLKEM768 share");
}

// ---------------------------------------------------------------------------
// Browser QUIC TLS profiles (`quic/tls_profile.rs`), measured 2026-10-29
// ---------------------------------------------------------------------------

/// Chrome 156 `trust_anchors` (0xca34) body from the measurements.
const CHROME_156_TRUST_ANCHORS_HEX: &str = "00b80582df1302010582df1302060582df13020d0582df13020e0582df13020f0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c9b2d010808839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c08839a648c9b2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d679090404d679090504d679090604d679090704d679090804d679090a04d679090b04d679090c04d679090d04d679090f";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The production H3 ClientHello under the dial fingerprint `fp` for endpoint seed `seed`.
async fn h3_clienthello(fp: crate::fingerprint_profile::TlsFingerprint, seed: u8) -> Vec<u8> {
    crate::fingerprint_profile::with_dial_fingerprint(Some(fp), async move {
        capture_clienthello(super::h3_quic_client_config(), super::h3_endpoint_config(), [seed; 32])
    })
    .await
}

fn sorted(mut v: Vec<u16>) -> Vec<u16> {
    v.sort_unstable();
    v
}

#[tokio::test]
async fn h3_chromium_clienthello_matches_chrome_156() {
    use crate::fingerprint_profile::TlsFingerprint;
    let anchors = unhex(CHROME_156_TRUST_ANCHORS_HEX);
    assert_eq!(anchors.len(), 186);
    let mut ech_from_end = std::collections::BTreeSet::new();
    let mut orders = std::collections::BTreeSet::new();
    let mut payloads = std::collections::BTreeSet::new();
    for seed in 0..16u8 {
        let ch = h3_clienthello(TlsFingerprint::Chromium, seed).await;
        assert_eq!(ja4(&ch), "q13d0312h3_55b375c5d22e_178839b6cec1");
        let ids = extension_types(&ch);
        assert_eq!(sorted(ids.clone()), [0, 10, 13, 16, 27, 43, 45, 51, 57, 17613, 51764, 65037]);
        assert_eq!(cipher_suites(&ch), [0x1301, 0x1302, 0x1303]);
        assert_eq!(u16_list_ext(&ch, 10), [0x11ec, 0x1d, 0x17, 0x18]);
        assert_eq!(key_share_groups(&ch), [0x11ec, 0x1d]);
        assert_eq!(supported_versions(&ch), [0x0304]);
        assert_eq!(
            u16_list_ext(&ch, 13),
            [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201]
        );
        assert_eq!(cert_compression_algs(&ch), [2], "brotli");
        assert_eq!(extension(&ch, 17613), Some(&[0x00, 0x03, 0x02, b'h', b'3'][..]));
        assert_eq!(extension(&ch, 51764), Some(&anchors[..]));
        let (kdf, aead, enc, payload) = ech_outer(&ch);
        assert_eq!((kdf, aead, enc), (1, 1, 32));
        assert!([176, 208, 240].contains(&payload), "ECH payload {payload}");
        let ech_len = extension(&ch, 0xfe0d).unwrap().len();
        assert!([218, 250, 282].contains(&ech_len), "ECH extension length {ech_len}");
        payloads.insert(payload);
        let pos = ids.iter().position(|e| *e == 0xfe0d).unwrap();
        ech_from_end.insert(ids.len() - 1 - pos);
        orders.insert(ids);
    }
    assert!(ech_from_end.iter().any(|p| *p != 0), "ECH is not always last");
    assert!(payloads.len() >= 2, "ECH payload length is drawn per connection: {payloads:?}");
    assert!(orders.len() > 1, "extension order varies per connection");
}

#[tokio::test]
async fn h3_safari_clienthello_matches_apple() {
    use crate::fingerprint_profile::TlsFingerprint;
    for seed in 0..8u8 {
        let ch = h3_clienthello(TlsFingerprint::Safari, seed).await;
        assert_eq!(ja4(&ch), "q13d0311h3_55b375c5d22e_f2a83c8e78ae");
        let exts = extensions(&ch);
        let ids = extension_types(&ch);
        assert!(is_grease_u16(ids[0]) && is_grease_u16(ids[ids.len() - 1]), "{ids:x?}");
        assert_eq!(ids[1..ids.len() - 1], [0, 10, 16, 5, 13, 18, 51, 45, 43, 57, 27]);
        assert_eq!(exts[0].1, [0u8; 0], "first GREASE extension is empty");
        assert_eq!(exts[exts.len() - 1].1, [0u8], "last GREASE extension is 00");

        let ciphers = cipher_suites(&ch);
        assert!(is_grease_u16(ciphers[0]), "{ciphers:x?}");
        assert_eq!(ciphers[1..], [0x1302, 0x1303, 0x1301]);
        let groups = u16_list_ext(&ch, 10);
        assert!(is_grease_u16(groups[0]), "{groups:x?}");
        assert_eq!(groups[1..], [0x11ec, 0x1d, 0x17, 0x18, 0x19]);
        let shares = key_share_entries(&ch);
        assert!(is_grease_u16(shares[0].0) && shares[0].1 == 1, "{shares:x?}");
        assert_eq!(
            key_share_entries(&ch)[1..]
                .iter()
                .map(|(g, _)| *g)
                .collect::<Vec<_>>(),
            [0x11ec, 0x1d]
        );
        let versions = supported_versions(&ch);
        assert!(is_grease_u16(versions[0]), "{versions:x?}");
        assert_eq!(versions[1..], [0x0304]);
        assert_eq!(
            u16_list_ext(&ch, 13),
            [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201]
        );
        assert_eq!(cert_compression_algs(&ch), [1], "zlib");
        assert_eq!(extension(&ch, 18), Some(&[][..]), "empty SCT");
        assert!(extension(&ch, 0xfe0d).is_none(), "Apple sends no ECH");
    }
}

#[tokio::test]
async fn h3_firefox_clienthello_matches_firefox_159() {
    use crate::fingerprint_profile::TlsFingerprint;
    let mut orders = std::collections::BTreeSet::new();
    for seed in 0..8u8 {
        let ch = h3_clienthello(TlsFingerprint::Firefox, seed).await;
        assert_eq!(ja4(&ch), "q13d0315h3_55b375c5d22e_dc5437974b47");
        let ids = extension_types(&ch);
        assert_eq!(
            sorted(ids.clone()),
            [0, 5, 10, 13, 16, 23, 27, 28, 34, 43, 45, 51, 57, 65037, 65281]
        );
        assert_eq!(*ids.last().unwrap(), 0xfe0d, "ECH last: {ids:x?}");
        assert_eq!(cipher_suites(&ch), [0x1301, 0x1303, 0x1302]);
        assert_eq!(u16_list_ext(&ch, 10), [0x11ec, 0x1d, 0x17, 0x18, 0x19]);
        assert_eq!(key_share_groups(&ch), [0x11ec, 0x1d, 0x17]);
        assert_eq!(supported_versions(&ch), [0x0304]);
        assert_eq!(
            u16_list_ext(&ch, 13),
            [
                0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
                0x0201
            ]
        );
        assert_eq!(cert_compression_algs(&ch), [1, 3, 2], "zlib, zstd, brotli");
        assert_eq!(extension(&ch, 28), Some(&[0x40, 0x01][..]));
        assert_eq!(
            extension(&ch, 34),
            Some(&[0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03][..])
        );
        assert_eq!(extension(&ch, 65281), Some(&[0x00][..]));
        assert_eq!(ech_outer(&ch), (1, 1, 32, 240));
        assert_eq!(extension(&ch, 0xfe0d).unwrap().len(), 282);
        orders.insert(ids);
    }
    assert!(orders.len() > 1, "extension order varies per connection");
}

/// UDP payload length of the first client Initial datagram.
fn first_initial_len(config: quinn::ClientConfig, endpoint_config: quinn::EndpointConfig) -> usize {
    let mut endpoint =
        quinn_proto::Endpoint::new(Arc::new(endpoint_config), None, false, Some([7; 32]));
    let now = Instant::now();
    let (_handle, mut conn) = endpoint
        .connect(now, config, "203.0.113.1:443".parse().unwrap(), "www.example.com")
        .expect("sans-IO connect");
    let mut buf = Vec::new();
    conn.poll_transmit(now, 1, &mut buf).expect("first Initial").size
}

#[tokio::test]
async fn h3_initial_datagram_stays_1200_for_every_profile() {
    use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};
    for (fp, want) in [
        (TlsFingerprint::Chromium, 1200),
        (TlsFingerprint::Firefox, 1200),
        (TlsFingerprint::Safari, 1200),
    ] {
        let len = with_dial_fingerprint(Some(fp), async {
            first_initial_len(super::h3_quic_client_config(), super::h3_endpoint_config())
        })
        .await;
        assert_eq!(len, want, "{fp:?}");
    }
}
