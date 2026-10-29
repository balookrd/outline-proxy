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

/// QUIC v1 Initial salt (RFC 9001 §5.2) — public and fixed, which is exactly
/// why a censor can decrypt any Initial it sees.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Minimal cursor over a byte slice for QUIC/TLS parsing.
struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn u8(&mut self) -> u8 {
        let v = self.b[self.i];
        self.i += 1;
        v
    }
    fn u16(&mut self) -> u16 {
        let v = u16::from_be_bytes([self.b[self.i], self.b[self.i + 1]]);
        self.i += 2;
        v
    }
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        s
    }
    fn remaining(&self) -> usize {
        self.b.len() - self.i
    }
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

/// Return the raw data of ClientHello extension `want_type`, if present.
fn clienthello_extension(ch: &[u8], want_type: u16) -> Option<&[u8]> {
    let mut r = Reader::new(ch);
    assert_eq!(r.u8(), 0x01, "expected ClientHello handshake");
    r.take(3); // 24-bit handshake length
    r.take(2); // legacy_version
    r.take(32); // random
    let sid_len = r.u8() as usize;
    r.take(sid_len); // session id (empty for QUIC)
    let cs_len = r.u16() as usize;
    r.take(cs_len); // cipher suites
    let comp_len = r.u8() as usize;
    r.take(comp_len); // compression methods
    let ext_total = r.u16() as usize;
    let ext_end = r.i + ext_total;
    while r.i < ext_end {
        let ext_type = r.u16();
        let ext_len = r.u16() as usize;
        let ext_data = r.take(ext_len);
        if ext_type == want_type {
            return Some(ext_data);
        }
    }
    None
}

/// Ordered transport-parameter ids from the `quic_transport_parameters`
/// extension (0x0039).
fn transport_param_ids_from_clienthello(ch: &[u8]) -> Vec<u64> {
    let data = clienthello_extension(ch, 0x0039)
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
    let data = clienthello_extension(ch, 0x0039)
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

/// Named groups offered in the `key_share` extension (0x0033), in order. Used
/// to confirm the post-quantum `X25519MLKEM768` (0x11ec) share is on the wire.
fn key_share_groups(ch: &[u8]) -> Vec<u16> {
    let Some(data) = clienthello_extension(ch, 0x0033) else {
        return Vec::new();
    };
    let mut r = Reader::new(data);
    let list_len = r.u16() as usize; // client_shares vector length
    let end = r.i + list_len;
    let mut groups = Vec::new();
    while r.i < end {
        let group = r.u16();
        let ke_len = r.u16() as usize;
        r.take(ke_len);
        groups.push(group);
    }
    groups
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

/// Firefox-profile H3 Initial is the Chromium set minus Google's private
/// `google_connection_options` (0x3128), which neqo never sends.
#[tokio::test]
async fn h3_firefox_initial_has_no_google_connection_options() {
    use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};

    let ch = with_dial_fingerprint(Some(TlsFingerprint::Firefox), async {
        capture_clienthello(super::h3_quic_client_config(), super::h3_endpoint_config(), [0x11; 32])
    })
    .await;
    let tp = transport_params_from_clienthello(&ch);
    assert!(!tp.iter().any(|(id, _)| *id == 0x3128), "Firefox must not send 0x3128");
    assert!(tp.iter().any(|(id, _)| *id == 0x11), "version_information still sent");
    assert!(tp.iter().any(|(id, _)| *id == 0x20), "max_datagram_frame_size still sent");
}

/// Safari-profile H3 Initial follows Apple's Network.framework set: no idle timeout,
/// no max_udp_payload_size, no GREASE parameter, private 0xff080808, no bidi streams, 8 uni,
/// 16 MiB / 2 MiB windows, empty source CID. Only Apple's `active_connection_id_limit`
/// (0x0e) is missing (documented residual).
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
    assert_eq!(ids, BTreeSet::from([0x04, 0x05, 0x06, 0x07, 0x09, 0x0f, 0xff08_0808]));
    assert_eq!(tp.len(), 7, "duplicate or extra transport parameters");
    assert!(!tp.iter().any(|(id, _)| is_grease_tp(*id)), "Apple sends no GREASE parameter");
    assert_eq!(tp_value(&tp, 0xff08_0808), Some(&[0x09][..]));
    let int = |id| tp_value(&tp, id).map(varint_value);
    assert_eq!(int(0x04), Some(16_777_216), "initial_max_data");
    for id in [0x05, 0x06, 0x07] {
        assert_eq!(int(id), Some(2_097_152), "initial_max_stream_data {id:#x}");
    }
    assert_eq!(int(0x09), Some(8), "initial_max_streams_uni");
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
