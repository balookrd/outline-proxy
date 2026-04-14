use aes::{
    Aes128, Aes256, cipher::BlockDecrypt, cipher::BlockEncrypt, cipher::KeyInit,
    cipher::generic_array::GenericArray,
};
use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::AeadInPlace as _};
use ring::{
    aead::{Aad, LessSafeKey, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};

use super::{
    error::CryptoError,
    primitives::{
        SS2022_UDP_SEPARATE_HEADER_LEN, SS2022_UDP_SERVER_TYPE, TAG_LEN, XNONCE_LEN,
        cipher_algorithm, current_unix_secs, derive_subkey, nonce_zero,
        parse_ss2022_chacha_udp_request_body, parse_ss2022_udp_request_body, ss2022_udp_nonce,
    },
    user_key::UserKey,
};
use crate::{config::CipherKind, protocol::TargetAddr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdpSession {
    Legacy,
    Aes2022 { client_session_id: [u8; 8] },
    Chacha2022 { client_session_id: [u8; 8] },
}

impl UdpSession {
    pub fn client_session_id(&self) -> Option<[u8; 8]> {
        match self {
            Self::Legacy => None,
            Self::Aes2022 { client_session_id } | Self::Chacha2022 { client_session_id } => {
                Some(*client_session_id)
            },
        }
    }
}

pub struct UdpPacket {
    pub user: UserKey,
    pub payload: Vec<u8>,
    pub session: UdpSession,
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

    if let Some(index) = preferred_user_index.filter(|&index| index < users.len()) {
        match try_decrypt_udp_packet_for_user(&users[index], packet)? {
            Some(udp_packet) => return Ok((udp_packet, index)),
            None => {},
        }
    }

    for (index, user) in users.iter().enumerate() {
        if Some(index) == preferred_user_index {
            continue;
        }
        match try_decrypt_udp_packet_for_user(user, packet)? {
            Some(udp_packet) => return Ok((udp_packet, index)),
            None => {},
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
        let cipher = XChaCha20Poly1305::new_from_slice(user.master_key())
            .map_err(|_| CryptoError::Cipher)?;
        let mut candidate = ciphertext.to_vec();
        if cipher
            .decrypt_in_place(XNonce::from_slice(nonce_bytes), b"", &mut candidate)
            .is_ok()
        {
            let (payload, client_session_id) = parse_ss2022_chacha_udp_request_body(&candidate)?;
            return Ok(Some(UdpPacket {
                user: user.clone(),
                payload,
                session: UdpSession::Chacha2022 { client_session_id },
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
        let session_key = derive_subkey(user.cipher(), user.master_key(), &separate_header[..8])?;
        let algorithm = cipher_algorithm(user.cipher());
        let key = UnboundKey::new(algorithm, &session_key).map_err(|_| CryptoError::Cipher)?;
        let less_safe = LessSafeKey::new(key);
        let mut candidate = ciphertext.to_vec();
        let nonce = ss2022_udp_nonce(&separate_header)?;
        if let Ok(body) = less_safe.open_in_place(nonce, Aad::empty(), &mut candidate) {
            let payload = parse_ss2022_udp_request_body(body)?;
            return Ok(Some(UdpPacket {
                user: user.clone(),
                payload,
                session: UdpSession::Aes2022 { client_session_id },
            }));
        }
        return Ok(None);
    }

    let salt_len = user.cipher().salt_len();
    if packet.len() < salt_len + TAG_LEN {
        return Ok(None);
    }

    let (salt, ciphertext) = packet.split_at(salt_len);
    let session_key = derive_subkey(user.cipher(), user.master_key(), salt)?;
    let algorithm = cipher_algorithm(user.cipher());
    let key = UnboundKey::new(algorithm, &session_key).map_err(|_| CryptoError::Cipher)?;
    let less_safe = LessSafeKey::new(key);
    let mut candidate = ciphertext.to_vec();
    if let Ok(plaintext) = less_safe.open_in_place(nonce_zero(), Aad::empty(), &mut candidate) {
        return Ok(Some(UdpPacket {
            user: user.clone(),
            payload: plaintext.to_vec(),
            session: UdpSession::Legacy,
        }));
    }

    Ok(None)
}

pub fn encrypt_udp_packet(user: &UserKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut salt = vec![0_u8; user.cipher().salt_len()];
    SystemRandom::new().fill(&mut salt).map_err(|_| CryptoError::Random)?;

    let session_key = derive_subkey(user.cipher(), user.master_key(), &salt)?;
    let algorithm = cipher_algorithm(user.cipher());
    let key = UnboundKey::new(algorithm, &session_key).map_err(|_| CryptoError::Cipher)?;
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
    session: &UdpSession,
    server_session_id: Option<[u8; 8]>,
    packet_id: u64,
) -> Result<Vec<u8>, CryptoError> {
    match session {
        UdpSession::Legacy => {
            let mut plaintext = source.encode().map_err(|_| CryptoError::InvalidHeader)?;
            plaintext.extend_from_slice(payload);
            encrypt_udp_packet(user, &plaintext)
        },
        UdpSession::Aes2022 { client_session_id } => {
            let server_session_id = server_session_id.ok_or(CryptoError::InvalidHeader)?;
            let target = source.encode().map_err(|_| CryptoError::InvalidHeader)?;
            let mut body = Vec::with_capacity(1 + 8 + 8 + 2 + target.len() + payload.len());
            body.push(SS2022_UDP_SERVER_TYPE);
            body.extend_from_slice(&current_unix_secs().to_be_bytes());
            body.extend_from_slice(client_session_id);
            body.extend_from_slice(&0_u16.to_be_bytes());
            body.extend_from_slice(&target);
            body.extend_from_slice(payload);

            let mut separate_header = [0_u8; SS2022_UDP_SEPARATE_HEADER_LEN];
            separate_header[..8].copy_from_slice(&server_session_id);
            separate_header[8..].copy_from_slice(&packet_id.to_be_bytes());
            let session_key = derive_subkey(user.cipher(), user.master_key(), &server_session_id)?;
            let algorithm = cipher_algorithm(user.cipher());
            let key = UnboundKey::new(algorithm, &session_key).map_err(|_| CryptoError::Cipher)?;
            let less_safe = LessSafeKey::new(key);
            less_safe
                .seal_in_place_append_tag(
                    ss2022_udp_nonce(&separate_header)?,
                    Aad::empty(),
                    &mut body,
                )
                .map_err(|_| CryptoError::Cipher)?;

            let encrypted_header = encrypt_ss2022_separate_header(user, &separate_header)?;
            let mut packet = encrypted_header.to_vec();
            packet.extend_from_slice(&body);
            Ok(packet)
        },
        UdpSession::Chacha2022 { client_session_id } => {
            let server_session_id = server_session_id.ok_or(CryptoError::InvalidHeader)?;
            let target = source.encode().map_err(|_| CryptoError::InvalidHeader)?;
            let mut body = Vec::with_capacity(8 + 8 + 1 + 8 + 8 + 2 + target.len() + payload.len());
            body.extend_from_slice(&server_session_id);
            body.extend_from_slice(&packet_id.to_be_bytes());
            body.push(SS2022_UDP_SERVER_TYPE);
            body.extend_from_slice(&current_unix_secs().to_be_bytes());
            body.extend_from_slice(client_session_id);
            body.extend_from_slice(&0_u16.to_be_bytes());
            body.extend_from_slice(&target);
            body.extend_from_slice(payload);

            let mut nonce = [0_u8; XNONCE_LEN];
            SystemRandom::new()
                .fill(&mut nonce)
                .map_err(|_| CryptoError::Random)?;
            let cipher = XChaCha20Poly1305::new_from_slice(user.master_key())
                .map_err(|_| CryptoError::Cipher)?;
            cipher
                .encrypt_in_place(XNonce::from_slice(&nonce), b"", &mut body)
                .map_err(|_| CryptoError::Cipher)?;

            let mut packet = nonce.to_vec();
            packet.extend_from_slice(&body);
            Ok(packet)
        },
    }
}

fn encrypt_ss2022_separate_header(
    user: &UserKey,
    separate_header: &[u8; SS2022_UDP_SEPARATE_HEADER_LEN],
) -> Result<[u8; SS2022_UDP_SEPARATE_HEADER_LEN], CryptoError> {
    let mut block = GenericArray::clone_from_slice(separate_header);
    match user.cipher() {
        CipherKind::Aes128Gcm2022 => {
            let cipher =
                Aes128::new_from_slice(user.master_key()).map_err(|_| CryptoError::Cipher)?;
            cipher.encrypt_block(&mut block);
        },
        CipherKind::Aes256Gcm2022 => {
            let cipher =
                Aes256::new_from_slice(user.master_key()).map_err(|_| CryptoError::Cipher)?;
            cipher.encrypt_block(&mut block);
        },
        _ => return Err(CryptoError::InvalidHeader),
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
    match user.cipher() {
        CipherKind::Aes128Gcm2022 => {
            let cipher =
                Aes128::new_from_slice(user.master_key()).map_err(|_| CryptoError::Cipher)?;
            cipher.decrypt_block(&mut block);
        },
        CipherKind::Aes256Gcm2022 => {
            let cipher =
                Aes256::new_from_slice(user.master_key()).map_err(|_| CryptoError::Cipher)?;
            cipher.decrypt_block(&mut block);
        },
        _ => return Err(CryptoError::InvalidHeader),
    }
    let mut out = [0_u8; SS2022_UDP_SEPARATE_HEADER_LEN];
    out.copy_from_slice(&block);
    Ok(out)
}
