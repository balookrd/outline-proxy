//! Diagnostic: dump a real QUIC Initial packet exactly as a censor sees it.
//!
//! Step 1 (`tls_fingerprint::dump_quic_clienthello_wire`) serialises the
//! ClientHello at the rustls layer with a placeholder for the QUIC
//! transport-parameters extension. This step closes that gap: it drives a
//! **real** `quinn` handshake (sans-IO, no sockets) through our production
//! [`super::quic_client_config`], captures the first Initial datagram, and
//! decrypts it with the well-known v1 Initial salt — exactly what a DPI box
//! does after observing the packet. The decrypted payload exposes the layer
//! step 1 cannot reach: the QUIC transport parameters quinn actually encodes
//! (ids, order, values, the per-process jitter from commit 6575d39, and
//! whether any GREASE parameter is present), the PADDING up to 1200 bytes,
//! the version, and the DCID/SCID lengths.
//!
//! Run with `--nocapture` to see the `QUIC-INITIAL` report. Pure computation:
//! `quinn-proto` is a sans-IO core, so no UDP socket is ever bound.

use std::sync::Arc;
use std::time::Instant;

use ring::{aead, hmac};

use crate::quic::ALPN_VLESS;

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

/// Decoded shape of the captured Initial datagram.
struct DecodedInitial {
    version: u32,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    length_field: u64,
    pn_len: usize,
    pn: u64,
    /// Decrypted Initial payload (CRYPTO + PADDING frames).
    payload: Vec<u8>,
}

/// Parse + decrypt a client Initial datagram the way a censor would: parse the
/// long header for the DCID, derive the v1 Initial keys, strip header
/// protection, then AEAD-open the payload.
fn decrypt_client_initial(dgram: &[u8]) -> DecodedInitial {
    assert_eq!(dgram[0] & 0xf0, 0xc0, "expected a long-header Initial packet");

    // Long header: first byte, 4-byte version, DCID, SCID, token, length.
    let mut r = Reader::new(dgram);
    let _first = r.u8();
    let version = u32::from_be_bytes(r.take(4).try_into().unwrap());
    let dcil = r.u8() as usize;
    let dcid = r.take(dcil).to_vec();
    let scil = r.u8() as usize;
    let scid = r.take(scil).to_vec();
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

    DecodedInitial {
        version,
        dcid,
        scid,
        length_field,
        pn_len,
        pn,
        payload: plaintext.to_vec(),
    }
}

/// Reassemble the CRYPTO stream (offset 0) from an Initial payload and count
/// the PADDING/PING frames around it. Client Initials carry only CRYPTO +
/// PADDING (+ the odd PING), so the frame grammar here is intentionally tiny.
fn parse_initial_frames(payload: &[u8]) -> (Vec<u8>, usize, usize) {
    let mut r = Reader::new(payload);
    let mut crypto = Vec::new();
    let mut padding = 0usize;
    let mut ping = 0usize;
    while r.remaining() > 0 {
        match r.u8() {
            0x00 => padding += 1,
            0x01 => ping += 1,
            0x06 => {
                let _offset = r.varint();
                let len = r.varint() as usize;
                crypto.extend_from_slice(r.take(len));
            },
            other => panic!("unexpected frame type 0x{other:02x} in client Initial"),
        }
    }
    (crypto, padding, ping)
}

/// Human name for a QUIC transport parameter id (RFC 9000 §18.2 + RFC 9221),
/// flagging the reserved GREASE pattern `31*N + 27`.
fn transport_param_name(id: u64) -> &'static str {
    match id {
        0x00 => "original_destination_connection_id",
        0x01 => "max_idle_timeout",
        0x02 => "stateless_reset_token",
        0x03 => "max_udp_payload_size",
        0x04 => "initial_max_data",
        0x05 => "initial_max_stream_data_bidi_local",
        0x06 => "initial_max_stream_data_bidi_remote",
        0x07 => "initial_max_stream_data_uni",
        0x08 => "initial_max_streams_bidi",
        0x09 => "initial_max_streams_uni",
        0x0a => "ack_delay_exponent",
        0x0b => "max_ack_delay",
        0x0c => "disable_active_migration",
        0x0d => "preferred_address",
        0x0e => "active_connection_id_limit",
        0x0f => "initial_source_connection_id",
        0x10 => "retry_source_connection_id",
        0x20 => "max_datagram_frame_size",
        id if id >= 27 && (id - 27) % 31 == 0 => "GREASE",
        _ => "unknown",
    }
}

/// True for parameters whose value is a single QUIC varint (so we can print a
/// decimal); the rest (connection ids, reset token, empty flags) print as hex.
fn is_integer_param(id: u64) -> bool {
    matches!(
        id,
        0x01 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0a | 0x0b | 0x0e | 0x20
    )
}

/// Extract the `quic_transport_parameters` extension (0x0039) from a
/// ClientHello and split it into ordered `(id, value)` pairs.
fn transport_params_from_clienthello(ch: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut r = Reader::new(ch);
    assert_eq!(r.u8(), 0x01, "expected ClientHello handshake");
    let _len = r.take(3); // 24-bit handshake length
    let _legacy_version = r.u16();
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
        if ext_type == 0x0039 {
            let mut pr = Reader::new(ext_data);
            let mut params = Vec::new();
            while pr.remaining() > 0 {
                let id = pr.varint();
                let len = pr.varint() as usize;
                params.push((id, pr.take(len).to_vec()));
            }
            return params;
        }
    }
    panic!("no quic_transport_parameters (0x0039) extension in ClientHello");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn dump_quic_initial_wire() {
    // Production raw-QUIC client config (jitter + initial_mtu 1400), dialed
    // outside any fingerprint scope exactly like the real raw-QUIC path.
    let config = super::quic_client_config(ALPN_VLESS);

    // Sans-IO QUIC client: no socket is bound. A fixed endpoint rng seed keeps
    // the DCID/SCID stable run-to-run (the transport-param jitter still varies
    // per process — that is the thing we want to observe).
    let endpoint_config = Arc::new(quinn_proto::EndpointConfig::default());
    let mut endpoint = quinn_proto::Endpoint::new(endpoint_config, None, false, Some([0x11; 32]));
    let now = Instant::now();
    let remote = "203.0.113.1:443".parse().unwrap();
    let (_handle, mut conn) = endpoint
        .connect(now, config, remote, "www.example.com")
        .expect("sans-IO connect");

    let mut buf = Vec::new();
    let transmit = conn
        .poll_transmit(now, 1, &mut buf)
        .expect("client must emit a first Initial");
    let dgram = &buf[..transmit.size];

    let decoded = decrypt_client_initial(dgram);
    assert_eq!(decoded.version, 0x0000_0001, "expected QUIC v1");
    let (clienthello, padding, ping) = parse_initial_frames(&decoded.payload);
    let params = transport_params_from_clienthello(&clienthello);

    eprintln!("QUIC-INITIAL rawquic-vless");
    eprintln!(
        "  datagram: {} bytes (padded for anti-amplification), version=0x{:08x}",
        dgram.len(),
        decoded.version
    );
    eprintln!(
        "  dcid={} ({}B)  scid={} ({}B)",
        hex(&decoded.dcid),
        decoded.dcid.len(),
        hex(&decoded.scid),
        decoded.scid.len()
    );
    eprintln!(
        "  length_field={}  pn_len={}  pn={}",
        decoded.length_field, decoded.pn_len, decoded.pn
    );
    eprintln!("  frames: crypto={}B  padding={padding}  ping={ping}", clienthello.len());
    eprintln!("  transport_parameters ({} in wire order):", params.len());
    for (id, value) in &params {
        let name = transport_param_name(*id);
        if value.is_empty() {
            eprintln!("    0x{id:02x} {name} = (present, empty)");
        } else if is_integer_param(*id) {
            let v = Reader::new(value).varint();
            eprintln!("    0x{id:02x} {name} = {v}");
        } else {
            eprintln!("    0x{id:02x} {name} = 0x{}", hex(value));
        }
    }
    // The decrypted ClientHello, for the same external JA3/JA4 parser as step 1.
    eprintln!("  clienthello_hex: {}", hex(&clienthello));
}
