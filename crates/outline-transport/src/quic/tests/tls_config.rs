//! Diagnostic: decrypt a real QUIC Initial packet exactly as a censor sees it.
//!
//! Drives a **real** `quinn` handshake (sans-IO, no sockets) through our
//! production [`super::h3_quic_client_config`], captures the first Initial
//! datagram(s), and decrypts them with the well-known v1 Initial salt — exactly
//! what a DPI box does after observing the packet. The decrypted payload
//! exposes the QUIC transport parameters quinn actually encodes and the
//! ClientHello key shares, letting us assert the H3 carrier's on-wire shape
//! (post-quantum key share present, `max_datagram_frame_size` absent).
//!
//! Pure computation: `quinn-proto` is a sans-IO core, so no UDP socket is ever
//! bound.

use std::sync::Arc;
use std::time::Instant;

use ring::{aead, hmac};

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
/// seed keeps the DCID stable run-to-run; the transport-param jitter still
/// varies per process (that is the thing we want to observe).
fn capture_clienthello(config: quinn::ClientConfig) -> Vec<u8> {
    let endpoint_config = Arc::new(quinn_proto::EndpointConfig::default());
    let mut endpoint = quinn_proto::Endpoint::new(endpoint_config, None, false, Some([0x11; 32]));
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

/// Regression for the H3 carrier config (level A). The H3 QUIC config picks up
/// the dial fingerprint (PQ key share on the wire), but leaves QUIC datagrams
/// off, so the H3 Initial does not advertise `max_datagram_frame_size` (0x20),
/// a transport-parameter tell a browser's HTTP/3 stack would not emit.
#[tokio::test]
async fn h3_config_carries_fingerprint_without_datagram_param() {
    use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};

    let chromium = with_dial_fingerprint(Some(TlsFingerprint::Chromium), async {
        capture_clienthello(super::h3_quic_client_config())
    })
    .await;
    assert!(
        key_share_groups(&chromium).contains(&0x11ec),
        "fingerprint scope must reach the H3 config (MLKEM768 key share)"
    );
    let has_datagram_param = transport_param_ids_from_clienthello(&chromium).contains(&0x20);
    assert!(
        !has_datagram_param,
        "H3 config must not advertise max_datagram_frame_size (0x20) — datagrams stay off"
    );
}
