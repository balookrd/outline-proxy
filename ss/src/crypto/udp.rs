use std::cell::RefCell;

use aes::cipher::{BlockDecrypt, BlockEncrypt, generic_array::GenericArray};
use chacha20poly1305::{XNonce, aead::AeadInPlace as _};
use ring::{
    aead::{Aad, LessSafeKey, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};

use super::{
    error::CryptoError,
    primitives::{
        MAX_SUBKEY_LEN, SS2022_UDP_SEPARATE_HEADER_LEN, SS2022_UDP_SERVER_TYPE, TAG_LEN,
        XNONCE_LEN, cipher_algorithm, derive_subkey, nonce_zero,
        parse_ss2022_chacha_udp_request_body, parse_ss2022_udp_request_body, ss2022_udp_nonce,
    },
    user_key::{AesHeaderCipher, UserKey},
};
use crate::{clock, config::CipherKind, protocol::TargetAddr};

thread_local! {
    static DECRYPT_SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn with_scratch<F, R>(src: &[u8], f: F) -> R
where
    F: FnOnce(&mut Vec<u8>) -> R,
{
    DECRYPT_SCRATCH.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        buf.extend_from_slice(src);
        f(&mut buf)
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdpCipherMode {
    Legacy,
    Aes2022 { client_session_id: [u8; 8] },
    Chacha2022 { client_session_id: [u8; 8] },
}

pub struct UdpPacket {
    pub user: UserKey,
    pub payload: Vec<u8>,
    pub session: UdpCipherMode,
    /// SS-2022 per-session monotonic packet counter; `None` for legacy cipher.
    /// Used by the replay filter to reject duplicates within a sliding window.
    pub packet_id: Option<u64>,
}

pub fn decrypt_udp_packet(users: &[UserKey], packet: &[u8]) -> Result<UdpPacket, CryptoError> {
    decrypt_udp_packet_with_hint(users, packet, None).map(|(packet, _)| packet)
}

pub fn decrypt_udp_packet_with_hint(
    users: &[UserKey],
    packet: &[u8],
    preferred_user_index: Option<usize>,
) -> Result<(UdpPacket, usize), CryptoError> {
    if packet.len() < TAG_LEN {
        return Err(CryptoError::PacketTooShort);
    }

    if let Some(index) = preferred_user_index.filter(|&index| index < users.len())
        && let Some(udp_packet) = try_decrypt_udp_packet_for_user(&users[index], packet)?
    {
        return Ok((udp_packet, index));
    }

    for (index, user) in users.iter().enumerate() {
        if Some(index) == preferred_user_index {
            continue;
        }
        if let Some(udp_packet) = try_decrypt_udp_packet_for_user(user, packet)? {
            return Ok((udp_packet, index));
        }
    }

    Err(CryptoError::UnknownUser)
}

fn try_decrypt_udp_packet_for_user(
    user: &UserKey,
    packet: &[u8],
) -> Result<Option<UdpPacket>, CryptoError> {
    if user.cipher() == CipherKind::Chacha20Poly13052022 {
        if packet.len() < XNONCE_LEN + TAG_LEN {
            return Ok(None);
        }

        let (nonce_bytes, ciphertext) = packet.split_at(XNONCE_LEN);
        let cipher = user.xchacha_cipher()?;
        let parsed = with_scratch(ciphertext, |buf| {
            if cipher
                .decrypt_in_place(XNonce::from_slice(nonce_bytes), b"", buf)
                .is_err()
            {
                return Ok(None);
            }
            parse_ss2022_chacha_udp_request_body(buf).map(Some)
        })?;
        if let Some((payload, client_session_id, packet_id)) = parsed {
            return Ok(Some(UdpPacket {
                user: user.clone(),
                payload,
                session: UdpCipherMode::Chacha2022 { client_session_id },
                packet_id: Some(packet_id),
            }));
        }
        return Ok(None);
    }

    if user.cipher().is_2022_aes() {
        if packet.len() < SS2022_UDP_SEPARATE_HEADER_LEN + TAG_LEN {
            return Ok(None);
        }

        let (encrypted_header, ciphertext) = packet.split_at(SS2022_UDP_SEPARATE_HEADER_LEN);
        let separate_header = decrypt_ss2022_separate_header(user, encrypted_header)?;
        let client_session_id = separate_header[..8]
            .try_into()
            .map_err(|_| CryptoError::InvalidHeader)?;
        let packet_id = u64::from_be_bytes(
            separate_header[8..16]
                .try_into()
                .map_err(|_| CryptoError::InvalidHeader)?,
        );
        let mut subkey = [0_u8; MAX_SUBKEY_LEN];
        let key_len =
            derive_subkey(user.cipher(), user.master_key(), &separate_header[..8], &mut subkey)?;
        let algorithm = cipher_algorithm(user.cipher());
        let key = UnboundKey::new(algorithm, &subkey[..key_len]).map_err(|_| CryptoError::Cipher)?;
        let less_safe = LessSafeKey::new(key);
        let nonce = ss2022_udp_nonce(&separate_header)?;
        let payload = with_scratch(ciphertext, |buf| {
            match less_safe.open_in_place(nonce, Aad::empty(), buf) {
                Ok(body) => parse_ss2022_udp_request_body(body).map(Some),
                Err(_) => Ok(None),
            }
        })?;
        if let Some(payload) = payload {
            return Ok(Some(UdpPacket {
                user: user.clone(),
                payload,
                session: UdpCipherMode::Aes2022 { client_session_id },
                packet_id: Some(packet_id),
            }));
        }
        return Ok(None);
    }

    let salt_len = user.cipher().salt_len();
    if packet.len() < salt_len + TAG_LEN {
        return Ok(None);
    }

    let (salt, ciphertext) = packet.split_at(salt_len);
    let mut subkey = [0_u8; MAX_SUBKEY_LEN];
    let key_len = derive_subkey(user.cipher(), user.master_key(), salt, &mut subkey)?;
    let algorithm = cipher_algorithm(user.cipher());
    let key = UnboundKey::new(algorithm, &subkey[..key_len]).map_err(|_| CryptoError::Cipher)?;
    let less_safe = LessSafeKey::new(key);
    let plaintext = with_scratch(ciphertext, |buf| {
        less_safe
            .open_in_place(nonce_zero(), Aad::empty(), buf)
            .ok()
            .map(|slice| slice.to_vec())
    });
    if let Some(plaintext) = plaintext {
        return Ok(Some(UdpPacket {
            user: user.clone(),
            payload: plaintext,
            session: UdpCipherMode::Legacy,
            packet_id: None,
        }));
    }

    Ok(None)
}

#[cfg(test)]
pub fn encrypt_udp_packet(user: &UserKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut salt = vec![0_u8; user.cipher().salt_len()];
    SystemRandom::new().fill(&mut salt).map_err(|_| CryptoError::Random)?;

    let mut subkey = [0_u8; MAX_SUBKEY_LEN];
    let key_len = derive_subkey(user.cipher(), user.master_key(), &salt, &mut subkey)?;
    let algorithm = cipher_algorithm(user.cipher());
    let key = UnboundKey::new(algorithm, &subkey[..key_len]).map_err(|_| CryptoError::Cipher)?;
    let less_safe = LessSafeKey::new(key);

    let mut output = salt;
    let mut ciphertext = plaintext.to_vec();
    less_safe
        .seal_in_place_append_tag(nonce_zero(), Aad::empty(), &mut ciphertext)
        .map_err(|_| CryptoError::Cipher)?;
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn encrypt_udp_packet_for_response(
    user: &UserKey,
    source: &TargetAddr,
    payload: &[u8],
    session: &UdpCipherMode,
    server_session_id: Option<[u8; 8]>,
    packet_id: u64,
) -> Result<Vec<u8>, CryptoError> {
    match session {
        UdpCipherMode::Legacy => {
            let header = source.encode().map_err(|_| CryptoError::InvalidHeader)?;
            let salt_len = user.cipher().salt_len();
            let plaintext_len = header.len() + payload.len();
            let mut packet = Vec::with_capacity(salt_len + plaintext_len + TAG_LEN);
            packet.resize(salt_len, 0);
            SystemRandom::new()
                .fill(&mut packet[..salt_len])
                .map_err(|_| CryptoError::Random)?;
            packet.extend_from_slice(&header);
            packet.extend_from_slice(payload);

            let mut subkey = [0_u8; MAX_SUBKEY_LEN];
            let key_len =
                derive_subkey(user.cipher(), user.master_key(), &packet[..salt_len], &mut subkey)?;
            let algorithm = cipher_algorithm(user.cipher());
            let key =
                UnboundKey::new(algorithm, &subkey[..key_len]).map_err(|_| CryptoError::Cipher)?;
            let less_safe = LessSafeKey::new(key);
            let tag = less_safe
                .seal_in_place_separate_tag(
                    nonce_zero(),
                    Aad::empty(),
                    &mut packet[salt_len..],
                )
                .map_err(|_| CryptoError::Cipher)?;
            packet.extend_from_slice(tag.as_ref());
            Ok(packet)
        },
        UdpCipherMode::Aes2022 { client_session_id } => {
            let server_session_id = server_session_id.ok_or(CryptoError::InvalidHeader)?;
            let target = source.encode().map_err(|_| CryptoError::InvalidHeader)?;
            let body_len = 1 + 8 + 8 + 2 + target.len() + payload.len();

            let mut separate_header = [0_u8; SS2022_UDP_SEPARATE_HEADER_LEN];
            separate_header[..8].copy_from_slice(&server_session_id);
            separate_header[8..].copy_from_slice(&packet_id.to_be_bytes());
            let encrypted_header = encrypt_ss2022_separate_header(user, &separate_header)?;

            let mut packet =
                Vec::with_capacity(SS2022_UDP_SEPARATE_HEADER_LEN + body_len + TAG_LEN);
            packet.extend_from_slice(&encrypted_header);
            let body_start = packet.len();
            packet.push(SS2022_UDP_SERVER_TYPE);
            packet.extend_from_slice(&clock::current_unix_secs().to_be_bytes());
            packet.extend_from_slice(client_session_id);
            packet.extend_from_slice(&0_u16.to_be_bytes());
            packet.extend_from_slice(&target);
            packet.extend_from_slice(payload);

            let mut subkey = [0_u8; MAX_SUBKEY_LEN];
            let key_len =
                derive_subkey(user.cipher(), user.master_key(), &server_session_id, &mut subkey)?;
            let algorithm = cipher_algorithm(user.cipher());
            let key =
                UnboundKey::new(algorithm, &subkey[..key_len]).map_err(|_| CryptoError::Cipher)?;
            let less_safe = LessSafeKey::new(key);
            let tag = less_safe
                .seal_in_place_separate_tag(
                    ss2022_udp_nonce(&separate_header)?,
                    Aad::empty(),
                    &mut packet[body_start..],
                )
                .map_err(|_| CryptoError::Cipher)?;
            packet.extend_from_slice(tag.as_ref());
            Ok(packet)
        },
        UdpCipherMode::Chacha2022 { client_session_id } => {
            let server_session_id = server_session_id.ok_or(CryptoError::InvalidHeader)?;
            let target = source.encode().map_err(|_| CryptoError::InvalidHeader)?;
            let body_len = 8 + 8 + 1 + 8 + 8 + 2 + target.len() + payload.len();

            let mut nonce = [0_u8; XNONCE_LEN];
            SystemRandom::new().fill(&mut nonce).map_err(|_| CryptoError::Random)?;

            let mut packet = Vec::with_capacity(XNONCE_LEN + body_len + TAG_LEN);
            packet.extend_from_slice(&nonce);
            let body_start = packet.len();
            packet.extend_from_slice(&server_session_id);
            packet.extend_from_slice(&packet_id.to_be_bytes());
            packet.push(SS2022_UDP_SERVER_TYPE);
            packet.extend_from_slice(&clock::current_unix_secs().to_be_bytes());
            packet.extend_from_slice(client_session_id);
            packet.extend_from_slice(&0_u16.to_be_bytes());
            packet.extend_from_slice(&target);
            packet.extend_from_slice(payload);

            let tag = user
                .xchacha_cipher()?
                .encrypt_in_place_detached(
                    XNonce::from_slice(&nonce),
                    b"",
                    &mut packet[body_start..],
                )
                .map_err(|_| CryptoError::Cipher)?;
            packet.extend_from_slice(tag.as_slice());
            Ok(packet)
        },
    }
}

fn encrypt_ss2022_separate_header(
    user: &UserKey,
    separate_header: &[u8; SS2022_UDP_SEPARATE_HEADER_LEN],
) -> Result<[u8; SS2022_UDP_SEPARATE_HEADER_LEN], CryptoError> {
    let mut block = GenericArray::clone_from_slice(separate_header);
    match user.aes_header_cipher()? {
        AesHeaderCipher::Aes128(c) => c.encrypt_block(&mut block),
        AesHeaderCipher::Aes256(c) => c.encrypt_block(&mut block),
    }
    let mut out = [0_u8; SS2022_UDP_SEPARATE_HEADER_LEN];
    out.copy_from_slice(&block);
    Ok(out)
}

pub(super) fn decrypt_ss2022_separate_header(
    user: &UserKey,
    encrypted: &[u8],
) -> Result<[u8; SS2022_UDP_SEPARATE_HEADER_LEN], CryptoError> {
    let mut block = GenericArray::clone_from_slice(encrypted);
    match user.aes_header_cipher()? {
        AesHeaderCipher::Aes128(c) => c.decrypt_block(&mut block),
        AesHeaderCipher::Aes256(c) => c.decrypt_block(&mut block),
    }
    let mut out = [0_u8; SS2022_UDP_SEPARATE_HEADER_LEN];
    out.copy_from_slice(&block);
    Ok(out)
}
