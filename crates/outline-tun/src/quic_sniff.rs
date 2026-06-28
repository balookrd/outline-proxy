//! QUIC Initial-packet sniffing: recover the destination host from the TLS
//! `ClientHello` carried (encrypted) inside a QUIC Initial packet.
//!
//! A QUIC Initial is "encrypted" with keys derived from a *published* salt and
//! the client's Destination Connection ID (RFC 9001 §5.2 / RFC 9369 §3.3 for
//! QUIC v2), so any on-path observer can decrypt it — that is exactly what
//! Xray's QUIC sniffer does. We:
//!
//! 1. parse the long header and locate the protected packet-number field,
//! 2. remove header protection (AES-ECB mask) to learn the packet number length,
//! 3. AEAD-decrypt the payload (AES-128-GCM),
//! 4. reassemble the `CRYPTO` frames into the TLS handshake byte stream, and
//! 5. hand that to [`crate::sniff::parse_client_hello`] for the SNI.
//!
//! Every step is bounds-checked and returns gracefully on malformed or
//! non-Initial input — this parses untrusted datagrams off the wire, so it must
//! never panic. Only the first UDP datagram of a flow is inspected; a
//! `ClientHello` that spans multiple datagrams (large post-quantum key shares)
//! is reported `Incomplete` and the flow falls back to dialling by IP.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, Payload};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::sniff::SniffOutcome;

/// QUIC v1 (RFC 9001) Initial salt.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
/// QUIC v2 (RFC 9369) Initial salt.
const INITIAL_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

const VERSION_V1: u32 = 0x0000_0001;
const VERSION_V2: u32 = 0x6b33_43cf;

/// Per-version key-derivation labels (they changed between v1 and v2).
struct InitialLabels {
    salt: &'static [u8; 20],
    key: &'static [u8],
    iv: &'static [u8],
    hp: &'static [u8],
}

/// Client Initial AEAD + header-protection keys (RFC 9001 §5.2).
pub(crate) struct InitialKeys {
    pub(crate) key: [u8; 16],
    pub(crate) iv: [u8; 12],
    pub(crate) hp: [u8; 16],
}

fn labels_for_version(version: u32) -> Option<InitialLabels> {
    match version {
        VERSION_V1 => Some(InitialLabels {
            salt: &INITIAL_SALT_V1,
            key: b"quic key",
            iv: b"quic iv",
            hp: b"quic hp",
        }),
        VERSION_V2 => Some(InitialLabels {
            salt: &INITIAL_SALT_V2,
            key: b"quicv2 key",
            iv: b"quicv2 iv",
            hp: b"quicv2 hp",
        }),
        _ => None,
    }
}

/// Derive the client Initial AEAD key / IV and header-protection key from the
/// (public) version salt and the client's Destination Connection ID.
pub(crate) fn derive_initial_secrets(version: u32, dcid: &[u8]) -> Option<InitialKeys> {
    let labels = labels_for_version(version)?;
    let extract = Hkdf::<Sha256>::new(Some(labels.salt), dcid);
    let mut client_secret = [0u8; 32];
    hkdf_expand_label(&extract, b"client in", &mut client_secret)?;
    let client = Hkdf::<Sha256>::from_prk(&client_secret).ok()?;
    let mut keys = InitialKeys {
        key: [0u8; 16],
        iv: [0u8; 12],
        hp: [0u8; 16],
    };
    hkdf_expand_label(&client, labels.key, &mut keys.key)?;
    hkdf_expand_label(&client, labels.iv, &mut keys.iv)?;
    hkdf_expand_label(&client, labels.hp, &mut keys.hp)?;
    Some(keys)
}

/// Try to recover the SNI from the first UDP datagram of a QUIC connection.
pub(crate) fn sniff_quic_sni(datagram: &[u8]) -> SniffOutcome {
    match decrypt_initial_crypto(datagram) {
        Some(crypto) => match reassemble_crypto(&crypto) {
            Some(handshake) => crate::sniff::parse_client_hello(&handshake),
            None => SniffOutcome::Incomplete,
        },
        None => SniffOutcome::NotMatched,
    }
}

/// Decrypt the Initial packet payload and return the plaintext (QUIC frames).
/// Returns `None` for anything that is not a decryptable v1/v2 Initial.
fn decrypt_initial_crypto(datagram: &[u8]) -> Option<Vec<u8>> {
    // Long header form (0x80) + fixed bit (0x40) must be set.
    let first = *datagram.first()?;
    if first & 0xc0 != 0xc0 {
        return None;
    }
    let version = u32::from_be_bytes([
        *datagram.get(1)?,
        *datagram.get(2)?,
        *datagram.get(3)?,
        *datagram.get(4)?,
    ]);
    // Long-header packet type lives in bits 0x30. Initial is 0b00 for v1 and
    // 0b01 for v2 (the type numbering was permuted in RFC 9369).
    let packet_type = (first & 0x30) >> 4;
    let expected_initial = if version == VERSION_V2 { 0b01 } else { 0b00 };
    if packet_type != expected_initial {
        return None;
    }

    // Connection IDs.
    let mut pos = 5usize;
    let dcid_len = usize::from(*datagram.get(pos)?);
    pos += 1;
    if dcid_len > 20 {
        return None; // RFC 9000 caps CIDs at 20 bytes.
    }
    let dcid = datagram.get(pos..pos + dcid_len)?;
    pos += dcid_len;
    let scid_len = usize::from(*datagram.get(pos)?);
    pos += 1;
    if scid_len > 20 {
        return None;
    }
    pos += scid_len;
    // Token (Initial-only): length is a varint.
    let (token_len, n) = read_varint(datagram.get(pos..)?)?;
    pos += n;
    pos = pos.checked_add(usize::try_from(token_len).ok()?)?;
    // Length of the remainder (packet number + protected payload).
    let (remainder_len, n) = read_varint(datagram.get(pos..)?)?;
    pos += n;
    let remainder_len = usize::try_from(remainder_len).ok()?;
    let pn_offset = pos;
    // The protected region must hold the declared remainder.
    let protected = datagram.get(pn_offset..pn_offset.checked_add(remainder_len)?)?;

    // Derive Initial secrets from the (public) salt and the client DCID.
    let InitialKeys { key, iv, hp } = derive_initial_secrets(version, dcid)?;

    // Header protection: sample 16 bytes starting 4 bytes into the protected
    // region (RFC 9001 §5.4.2 — sample offset assumes a 4-byte PN field).
    let sample = datagram.get(pn_offset + 4..pn_offset + 4 + 16)?;
    let mask = header_protection_mask(&hp, sample);
    let unprotected_first = first ^ (mask[0] & 0x0f);
    let pn_len = usize::from(unprotected_first & 0x03) + 1;

    // Reconstruct the packet number bytes.
    let mut pn_bytes = [0u8; 4];
    let mut pn_value: u64 = 0;
    for i in 0..pn_len {
        let b = protected.get(i)? ^ mask[1 + i];
        pn_bytes[i] = b;
        pn_value = (pn_value << 8) | u64::from(b);
    }

    // AAD is the header with the unprotected first byte and packet number;
    // ciphertext (incl. the 16-byte GCM tag) is the rest of the protected region.
    let header_len = pn_offset + pn_len;
    let mut aad = datagram.get(..header_len)?.to_vec();
    aad[0] = unprotected_first;
    aad[pn_offset..header_len].copy_from_slice(&pn_bytes[..pn_len]);
    let ciphertext = protected.get(pn_len..)?;
    if ciphertext.len() < 16 {
        return None;
    }

    // Nonce = iv XOR left-padded packet number.
    let mut nonce = iv;
    let pn_be = pn_value.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn_be[i];
    }

    let cipher = Aes128Gcm::new_from_slice(&key).ok()?;
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad: &aad })
        .ok()
}

/// AES-128-ECB single-block encryption of the sample → header-protection mask.
fn header_protection_mask(hp_key: &[u8; 16], sample: &[u8]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(hp_key));
    let mut block = GenericArray::clone_from_slice(sample);
    cipher.encrypt_block(&mut block);
    let mut mask = [0u8; 16];
    mask.copy_from_slice(&block);
    mask
}

/// HKDF-Expand-Label (RFC 8446 §7.1) with the empty context QUIC uses.
fn hkdf_expand_label(hk: &Hkdf<Sha256>, label: &[u8], out: &mut [u8]) -> Option<()> {
    let mut info = Vec::with_capacity(4 + 6 + label.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    let full_len = 6 + label.len();
    info.push(u8::try_from(full_len).ok()?);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0); // zero-length context
    hk.expand(&info, out).ok()
}

/// Walk the decrypted QUIC frames and reassemble the `CRYPTO` stream into a
/// contiguous buffer starting at offset 0. Returns `None` if there is a gap
/// before the data we have (i.e. the `ClientHello` prefix is not all present).
fn reassemble_crypto(frames: &[u8]) -> Option<Vec<u8>> {
    let mut pieces: Vec<(u64, &[u8])> = Vec::new();
    let mut pos = 0usize;
    while pos < frames.len() {
        let (frame_type, n) = read_varint(&frames[pos..])?;
        pos += n;
        match frame_type {
            0x00 => {}, // PADDING (single byte, already consumed)
            0x01 => {}, // PING
            0x02 | 0x03 => {
                // ACK: largest, delay, range_count, first_range, then ranges.
                let (_largest, a) = read_varint(frames.get(pos..)?)?;
                pos += a;
                let (_delay, b) = read_varint(frames.get(pos..)?)?;
                pos += b;
                let (range_count, c) = read_varint(frames.get(pos..)?)?;
                pos += c;
                let (_first, d) = read_varint(frames.get(pos..)?)?;
                pos += d;
                for _ in 0..range_count {
                    let (_gap, g) = read_varint(frames.get(pos..)?)?;
                    pos += g;
                    let (_len, l) = read_varint(frames.get(pos..)?)?;
                    pos += l;
                }
                if frame_type == 0x03 {
                    // ECN counts: ECT0, ECT1, CE.
                    for _ in 0..3 {
                        let (_v, e) = read_varint(frames.get(pos..)?)?;
                        pos += e;
                    }
                }
            },
            0x06 => {
                // CRYPTO: offset, length, data.
                let (offset, a) = read_varint(frames.get(pos..)?)?;
                pos += a;
                let (length, b) = read_varint(frames.get(pos..)?)?;
                pos += b;
                let length = usize::try_from(length).ok()?;
                let data = frames.get(pos..pos.checked_add(length)?)?;
                pos += length;
                pieces.push((offset, data));
            },
            _ => {
                // Any other frame type in an Initial is unexpected; stop here
                // and reassemble whatever CRYPTO we have gathered so far.
                break;
            },
        }
    }

    if pieces.is_empty() {
        return None;
    }
    pieces.sort_by_key(|(offset, _)| *offset);
    let mut out = Vec::new();
    let mut next: u64 = 0;
    for (offset, data) in pieces {
        if offset > next {
            break; // gap — the ClientHello prefix is incomplete
        }
        let skip = (next - offset) as usize;
        if let Some(slice) = data.get(skip..) {
            out.extend_from_slice(slice);
            next += slice.len() as u64;
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Decode a QUIC variable-length integer (RFC 9000 §16). Returns the value and
/// the number of bytes consumed, or `None` if the buffer is too short.
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(..len)?;
    let mut value = u64::from(first & 0x3f);
    for &b in &bytes[1..] {
        value = (value << 8) | u64::from(b);
    }
    Some((value, len))
}

/// Test-only QUIC Initial packet construction, shared between this module's
/// unit tests and the UDP-engine end-to-end sniffing tests.
#[cfg(test)]
pub(crate) mod test_vectors {
    use aes::Aes128;
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    use aes_gcm::Aes128Gcm;
    use aes_gcm::aead::{Aead, Payload};

    use super::{VERSION_V2, derive_initial_secrets};

    /// A bare TLS `ClientHello` handshake message (no record layer, as QUIC
    /// CRYPTO carries it) advertising a single `server_name` extension.
    pub(crate) fn client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut sni_ext = Vec::new();
        let entry_len = 1 + 2 + name.len();
        sni_ext.extend_from_slice(&(entry_len as u16).to_be_bytes());
        sni_ext.push(0x00);
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0x00);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut hs = vec![0x01];
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);
        hs
    }

    pub(crate) fn push_varint(out: &mut Vec<u8>, value: u64) {
        if value < 64 {
            out.push(value as u8);
        } else {
            out.push(0x40 | (value >> 8) as u8);
            out.push(value as u8);
        }
    }

    pub(crate) fn push_crypto_frame(out: &mut Vec<u8>, offset: u64, data: &[u8]) {
        out.push(0x06);
        push_varint(out, offset);
        push_varint(out, data.len() as u64);
        out.extend_from_slice(data);
    }

    /// Build an encrypted QUIC Initial datagram carrying `handshake` in a single
    /// CRYPTO frame.
    pub(crate) fn build_initial(version: u32, dcid: &[u8], handshake: &[u8]) -> Vec<u8> {
        let mut frames = Vec::new();
        push_crypto_frame(&mut frames, 0, handshake);
        build_initial_from_frames(version, dcid, &frames)
    }

    /// Build an encrypted QUIC Initial datagram from pre-assembled QUIC frames.
    pub(crate) fn build_initial_from_frames(version: u32, dcid: &[u8], frames: &[u8]) -> Vec<u8> {
        let keys = derive_initial_secrets(version, dcid).unwrap();

        let mut plaintext = frames.to_vec();
        if plaintext.len() < 64 {
            plaintext.resize(64, 0x00); // PADDING frames
        }

        let first: u8 = if version == VERSION_V2 { 0xd0 } else { 0xc0 };
        let mut header = vec![first];
        header.extend_from_slice(&version.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0x00); // SCID length
        header.push(0x00); // token length (varint 0)
        let length = 1 + plaintext.len() + 16; // pn(1) + plaintext + tag
        push_varint(&mut header, length as u64);
        let pn_offset = header.len();
        header.push(0x00); // packet number = 0 (1 byte)

        let aad = header.clone();
        let nonce = keys.iv; // pn = 0 → nonce = iv
        let cipher = Aes128Gcm::new_from_slice(&keys.key).unwrap();
        let ciphertext = cipher
            .encrypt(aes_gcm::Nonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &aad })
            .unwrap();

        let mut packet = header;
        packet.extend_from_slice(&ciphertext);

        let sample: [u8; 16] = packet[pn_offset + 4..pn_offset + 4 + 16].try_into().unwrap();
        let aes = Aes128::new(GenericArray::from_slice(&keys.hp));
        let mut block = GenericArray::clone_from_slice(&sample);
        aes.encrypt_block(&mut block);
        packet[0] ^= block[0] & 0x0f;
        packet[pn_offset] ^= block[1];
        packet
    }
}

#[cfg(test)]
#[path = "tests/quic_sniff.rs"]
mod tests;
