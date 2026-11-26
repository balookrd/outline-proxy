use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit as BlockKeyInit};
use aes::{Aes128, Aes256};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::AeadInOut;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

use outline_wire::ss2022::{
    Ss2022HeaderError, build_udp_request_body, encode_udp_separate_header,
    parse_chacha_udp_response_body, parse_udp_response_body, udp_nonce_from_separate_header,
};

use crate::cipher_kind::CipherKind;
use crate::error::{CryptoError, Result};

use super::aead::{SHADOWSOCKS_TAG_LEN, decrypt, encrypt_into};
use super::keys::derive_subkey;

#[cfg(test)]
pub(crate) use outline_wire::ss2022::SS2022_UDP_SERVER_TYPE as SS2022_UDP_SERVER_PACKET;

const CIPHER_XCHACHA: &str = "xchacha20-poly1305";
const CIPHER_AES_128_SS2022: &str = "aes-128 ss2022";
const CIPHER_AES_256_SS2022: &str = "aes-256 ss2022";

const ERR_REQUIRES_2022: &str = "ss2022 UDP framing requires a 2022 cipher";
const ERR_REQUIRES_2022_CHACHA: &str = "ss2022 chacha UDP framing requires a 2022 chacha cipher";
const ERR_SEPARATE_HEADER_AES_ONLY: &str =
    "UDP separate header is only defined for ss2022 AES methods";
const ERR_SS2022_INVALID_BODY: &str = "invalid ss2022 UDP server packet body";
const ERR_SS2022_INVALID_SERVER_TYPE: &str = "invalid ss2022 UDP server packet type";
const ERR_SS2022_CLIENT_SESSION_MISMATCH: &str = "ss2022 UDP client session id mismatch";

fn unix_now_secs() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| CryptoError::ClockBeforeEpoch)
}

/// Collapses wire-layer response-body errors into [`CryptoError`], keeping
/// the timestamp-skew and session-mismatch cases distinguishable.
fn map_response_body_err(err: Ss2022HeaderError) -> CryptoError {
    match err {
        Ss2022HeaderError::TimestampSkew { skew_secs } => {
            CryptoError::Ss2022TimestampSkew { skew_secs: skew_secs as i64 }
        },
        Ss2022HeaderError::InvalidResponseType(_) => {
            CryptoError::Protocol(ERR_SS2022_INVALID_SERVER_TYPE)
        },
        Ss2022HeaderError::ClientSessionMismatch => {
            CryptoError::Protocol(ERR_SS2022_CLIENT_SESSION_MISMATCH)
        },
        _ => CryptoError::Protocol(ERR_SS2022_INVALID_BODY),
    }
}

/// Validates that an SS2022 timestamp is within the acceptable clock-skew window.
/// Timestamps outside ±30 s of the current time are rejected to prevent replay attacks.
pub fn validate_ss2022_timestamp(timestamp_secs: u64) -> Result<()> {
    let now = unix_now_secs()?;
    outline_wire::ss2022::validate_timestamp(timestamp_secs, now).map_err(|_| {
        CryptoError::Ss2022TimestampSkew {
            skew_secs: now.abs_diff(timestamp_secs) as i64,
        }
    })
}

pub fn encrypt_udp_packet_2022(
    cipher: CipherKind,
    master_key: &[u8],
    session_id: u64,
    packet_id: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if !cipher.is_ss2022() {
        return Err(CryptoError::Protocol(ERR_REQUIRES_2022));
    }

    let session_id_bytes = session_id.to_be_bytes();
    let chacha_session = cipher.is_ss2022_chacha().then_some((&session_id_bytes, packet_id));
    let plaintext = build_udp_request_body(chacha_session, unix_now_secs()?, payload);
    if cipher.is_ss2022_chacha() {
        return encrypt_udp_packet_2022_chacha(cipher, master_key, &plaintext);
    }
    encrypt_udp_packet_2022_aes(cipher, master_key, session_id, packet_id, &plaintext)
}

pub(crate) fn encrypt_udp_packet_2022_aes(
    cipher: CipherKind,
    master_key: &[u8],
    session_id: u64,
    packet_id: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let separate_header = encode_udp_separate_header(&session_id.to_be_bytes(), packet_id);
    let nonce = udp_nonce_from_separate_header(&separate_header);

    let key = derive_subkey(cipher, master_key, &separate_header[..8])?;
    let encrypted_header = encrypt_udp_separate_header(cipher, master_key, &separate_header)?;

    // Encrypt the body straight into the packet after the 16-byte header rather
    // than into a throwaway `Vec` that is then copied in — the ciphertext is a
    // full datagram payload, so the second copy scaled with UDP throughput.
    let mut packet = Vec::with_capacity(16 + plaintext.len() + SHADOWSOCKS_TAG_LEN);
    packet.extend_from_slice(&encrypted_header);
    encrypt_into(cipher, &key[..cipher.key_len()], &nonce, plaintext, &mut packet)?;
    Ok(packet)
}

pub fn decrypt_udp_packet_2022(
    cipher: CipherKind,
    master_key: &[u8],
    expected_client_session_id: u64,
    packet: &[u8],
) -> Result<(u64, u64, Vec<u8>)> {
    if !cipher.is_ss2022() {
        return Err(CryptoError::Protocol(ERR_REQUIRES_2022));
    }
    if cipher.is_ss2022_chacha() {
        return decrypt_udp_packet_2022_chacha(
            cipher,
            master_key,
            expected_client_session_id,
            packet,
        );
    }
    decrypt_udp_packet_2022_aes(cipher, master_key, expected_client_session_id, packet)
}

/// `0` historically means "do not check the echoed client session id";
/// the wire-layer parsers express the same with `None`.
fn expected_session_bytes(expected_client_session_id: u64) -> Option<[u8; 8]> {
    (expected_client_session_id != 0).then(|| expected_client_session_id.to_be_bytes())
}

fn decrypt_udp_packet_2022_aes(
    cipher: CipherKind,
    master_key: &[u8],
    expected_client_session_id: u64,
    packet: &[u8],
) -> Result<(u64, u64, Vec<u8>)> {
    if packet.len() < 16 + SHADOWSOCKS_TAG_LEN {
        return Err(CryptoError::UdpPacketTooShort);
    }

    let mut encrypted_header = [0u8; 16];
    encrypted_header.copy_from_slice(&packet[..16]);
    let separate_header = decrypt_udp_separate_header(cipher, master_key, &encrypted_header)?;

    let nonce = udp_nonce_from_separate_header(&separate_header);
    let key = derive_subkey(cipher, master_key, &separate_header[..8])?;
    let plaintext = decrypt(cipher, &key[..cipher.key_len()], &nonce, &packet[16..])?;

    let mut session_bytes = [0u8; 8];
    session_bytes.copy_from_slice(&separate_header[..8]);
    let session_id = u64::from_be_bytes(session_bytes);

    let mut packet_id_bytes = [0u8; 8];
    packet_id_bytes.copy_from_slice(&separate_header[8..]);
    let packet_id = u64::from_be_bytes(packet_id_bytes);

    let expected = expected_session_bytes(expected_client_session_id);
    let payload = parse_udp_response_body(&plaintext, expected.as_ref(), unix_now_secs()?)
        .map_err(map_response_body_err)?;
    Ok((session_id, packet_id, payload.to_vec()))
}

/// Pre-initialised AES-128 / AES-256 ECB cipher for SS2022 UDP separate headers.
pub enum AesHeaderCipher {
    Aes128(Aes128),
    Aes256(Aes256),
}

impl AesHeaderCipher {
    pub fn new(cipher: CipherKind, master_key: &[u8]) -> Result<Self> {
        match cipher {
            CipherKind::Aes128Gcm2022 => Aes128::new_from_slice(master_key)
                .map(Self::Aes128)
                .map_err(|_| CryptoError::InvalidKey { cipher: CIPHER_AES_128_SS2022 }),
            CipherKind::Aes256Gcm2022 => Aes256::new_from_slice(master_key)
                .map(Self::Aes256)
                .map_err(|_| CryptoError::InvalidKey { cipher: CIPHER_AES_256_SS2022 }),
            _ => Err(CryptoError::Protocol(ERR_SEPARATE_HEADER_AES_ONLY)),
        }
    }

    pub fn encrypt_header(&self, header: &[u8; 16]) -> [u8; 16] {
        let mut block = *header;
        match self {
            Self::Aes128(cipher) => cipher.encrypt_block((&mut block).into()),
            Self::Aes256(cipher) => cipher.encrypt_block((&mut block).into()),
        }
        block
    }

    pub fn decrypt_header(&self, header: &[u8; 16]) -> Result<[u8; 16]> {
        let mut block = *header;
        match self {
            Self::Aes128(cipher) => cipher.decrypt_block((&mut block).into()),
            Self::Aes256(cipher) => cipher.decrypt_block((&mut block).into()),
        }
        Ok(block)
    }
}

/// Pre-initialised XChaCha20-Poly1305 cipher for SS2022 UDP packets.
pub struct XChaChaCipher(XChaCha20Poly1305);

impl XChaChaCipher {
    pub fn new(master_key: &[u8]) -> Result<Self> {
        XChaCha20Poly1305::new_from_slice(master_key)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey { cipher: CIPHER_XCHACHA })
    }

    pub fn seal_in_place_separate_tag(
        &self,
        nonce: &[u8; 24],
        in_out: &mut [u8],
    ) -> Result<[u8; SHADOWSOCKS_TAG_LEN]> {
        let tag = self
            .0
            .encrypt_inout_detached(nonce.into(), b"", in_out.into())
            .map_err(|_| CryptoError::EncryptFailed { cipher: CIPHER_XCHACHA })?;
        Ok(tag.into())
    }

    pub fn decrypt_detached_in_place(&self, nonce: &[u8; 24], buf: &mut [u8]) -> Result<usize> {
        if buf.len() < SHADOWSOCKS_TAG_LEN {
            return Err(CryptoError::ShortCiphertext);
        }
        let split_at = buf.len() - SHADOWSOCKS_TAG_LEN;
        let mut tag_arr = [0u8; SHADOWSOCKS_TAG_LEN];
        tag_arr.copy_from_slice(&buf[split_at..]);
        self.0
            .decrypt_inout_detached(
                nonce.into(),
                b"",
                (&mut buf[..split_at]).into(),
                (&tag_arr).into(),
            )
            .map_err(|_| CryptoError::DecryptFailed { cipher: CIPHER_XCHACHA })?;
        Ok(split_at)
    }
}

pub fn encrypt_udp_separate_header(
    cipher: CipherKind,
    master_key: &[u8],
    header: &[u8; 16],
) -> Result<[u8; 16]> {
    Ok(AesHeaderCipher::new(cipher, master_key)?.encrypt_header(header))
}

pub fn decrypt_udp_separate_header(
    cipher: CipherKind,
    master_key: &[u8],
    header: &[u8; 16],
) -> Result<[u8; 16]> {
    AesHeaderCipher::new(cipher, master_key)?.decrypt_header(header)
}

pub(crate) fn encrypt_udp_packet_2022_chacha(
    cipher: CipherKind,
    master_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if !cipher.is_ss2022_chacha() {
        return Err(CryptoError::Protocol(ERR_REQUIRES_2022_CHACHA));
    }
    let mut nonce = [0u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    seal_xchacha_packet(master_key, &nonce, plaintext)
}

/// Builds `nonce || ciphertext || tag` for an SS2022 chacha UDP packet under
/// the given nonce. Split out of [`encrypt_udp_packet_2022_chacha`] so the
/// known-answer tests can pin the XChaCha20-Poly1305 output.
pub(crate) fn seal_xchacha_packet(
    master_key: &[u8],
    nonce: &[u8; 24],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaChaCipher::new(master_key)?;

    // Encrypt in place inside the final packet (nonce prefix + plaintext region)
    // instead of into a throwaway `buffer` that is then copied in — the second
    // copy was a full datagram payload, scaling with UDP throughput.
    let mut packet = Vec::with_capacity(nonce.len() + plaintext.len() + SHADOWSOCKS_TAG_LEN);
    packet.extend_from_slice(nonce);
    packet.extend_from_slice(plaintext);
    let tag = cipher.seal_in_place_separate_tag(nonce, &mut packet[nonce.len()..])?;
    packet.extend_from_slice(&tag);
    Ok(packet)
}

fn decrypt_udp_packet_2022_chacha(
    cipher: CipherKind,
    master_key: &[u8],
    expected_client_session_id: u64,
    packet: &[u8],
) -> Result<(u64, u64, Vec<u8>)> {
    if !cipher.is_ss2022_chacha() {
        return Err(CryptoError::Protocol(ERR_REQUIRES_2022_CHACHA));
    }
    if packet.len() < 24 + SHADOWSOCKS_TAG_LEN {
        return Err(CryptoError::UdpPacketTooShort);
    }

    let (nonce, rest) = packet
        .split_first_chunk::<24>()
        .ok_or(CryptoError::UdpPacketTooShort)?;
    let mut buffer = rest.to_vec();
    let cipher = XChaChaCipher::new(master_key)?;
    let plaintext_len = cipher.decrypt_detached_in_place(nonce, &mut buffer)?;
    buffer.truncate(plaintext_len);

    let expected = expected_session_bytes(expected_client_session_id);
    let response = parse_chacha_udp_response_body(&buffer, expected.as_ref(), unix_now_secs()?)
        .map_err(map_response_body_err)?;
    Ok((
        u64::from_be_bytes(response.server_session_id),
        response.packet_id,
        response.addressed_payload.to_vec(),
    ))
}
