use chacha20poly1305::{XNonce, aead::AeadInPlace as _};
use ring::aead::Aad;

use super::{
    error::CryptoError,
    primitives::{
        LEGACY_MAX_CHUNK_SIZE, SS2022_REQUEST_FIXED_HEADER_LEN, SS2022_UDP_SEPARATE_HEADER_LEN,
        TAG_LEN, XNONCE_LEN, build_session_key, nonce_zero,
        parse_ss2022_chacha_udp_request_body, parse_ss2022_udp_request_body, ss2022_udp_nonce,
        try_open_fixed_header, validate_ss2022_request_fixed_header,
    },
    udp::decrypt_ss2022_separate_header,
    user_key::UserKey,
};
use crate::config::CipherKind;

fn format_build_key_error(user: &UserKey, err: CryptoError) -> String {
    match err {
        CryptoError::KeyDerivation => {
            format!("{}:{} subkey_error({})", user.id(), user.cipher().as_str(), err)
        },
        _ => format!("{}:{} key_init_failed", user.id(), user.cipher().as_str()),
    }
}

pub fn diagnose_stream_handshake(users: &[UserKey], buffer: &[u8]) -> Vec<String> {
    users
        .iter()
        .map(|user| {
            if user.cipher().is_2022() {
                let salt_len = user.cipher().salt_len();
                let fixed_len = SS2022_REQUEST_FIXED_HEADER_LEN + TAG_LEN;
                if buffer.len() < salt_len + fixed_len {
                    return format!(
                        "{}:{} insufficient_data(buffer={}, need={})",
                        user.id(),
                        user.cipher().as_str(),
                        buffer.len(),
                        salt_len + fixed_len
                    );
                }
                let salt = &buffer[..salt_len];
                let mut candidate = buffer[salt_len..salt_len + fixed_len].to_vec();
                let less_safe = match build_session_key(user.cipher(), user.master_key(), salt) {
                    Ok(key) => key,
                    Err(error) => return format_build_key_error(user, error),
                };
                match try_open_fixed_header(
                    &less_safe,
                    nonce_zero(),
                    &mut candidate,
                    SS2022_REQUEST_FIXED_HEADER_LEN,
                ) {
                    Ok(header) => match validate_ss2022_request_fixed_header(header) {
                        Ok(header_len) => format!(
                            "{}:{} header_ok(header_len={})",
                            user.id(),
                            user.cipher().as_str(),
                            header_len
                        ),
                        Err(error) => format!(
                            "{}:{} header_invalid({})",
                            user.id(),
                            user.cipher().as_str(),
                            error
                        ),
                    },
                    Err(CryptoError::InvalidHeader) => {
                        format!("{}:{} invalid_header_len", user.id(), user.cipher().as_str())
                    },
                    Err(_) => format!("{}:{} auth_failed", user.id(), user.cipher().as_str()),
                }
            } else {
                let salt_len = user.cipher().salt_len();
                if buffer.len() < salt_len {
                    return format!(
                        "{}:{} insufficient_data(buffer={}, need_salt={})",
                        user.id(),
                        user.cipher().as_str(),
                        buffer.len(),
                        salt_len
                    );
                }
                if buffer.len() < salt_len + 2 + TAG_LEN {
                    return format!(
                        "{}:{} insufficient_data(buffer={}, need_header={})",
                        user.id(),
                        user.cipher().as_str(),
                        buffer.len(),
                        salt_len + 2 + TAG_LEN
                    );
                }

                let salt = &buffer[..salt_len];
                let less_safe = match build_session_key(user.cipher(), user.master_key(), salt) {
                    Ok(key) => key,
                    Err(error) => return format_build_key_error(user, error),
                };
                let mut candidate = buffer[salt_len..salt_len + 2 + TAG_LEN].to_vec();
                match try_open_fixed_header(&less_safe, nonce_zero(), &mut candidate, 2) {
                    Ok(plaintext_len) => {
                        let chunk_len =
                            u16::from_be_bytes([plaintext_len[0], plaintext_len[1]]) as usize;
                        if chunk_len <= LEGACY_MAX_CHUNK_SIZE {
                            format!(
                                "{}:{} header_ok(chunk_len={})",
                                user.id(),
                                user.cipher().as_str(),
                                chunk_len
                            )
                        } else {
                            format!(
                                "{}:{} invalid_chunk_len({})",
                                user.id(),
                                user.cipher().as_str(),
                                chunk_len
                            )
                        }
                    },
                    Err(CryptoError::InvalidHeader) => {
                        format!("{}:{} invalid_header_len", user.id(), user.cipher().as_str())
                    },
                    Err(_) => format!("{}:{} auth_failed", user.id(), user.cipher().as_str()),
                }
            }
        })
        .collect()
}

pub fn diagnose_udp_packet(users: &[UserKey], packet: &[u8]) -> Vec<String> {
    users
        .iter()
        .map(|user| {
            if user.cipher() == CipherKind::Chacha20Poly13052022 {
                if packet.len() < XNONCE_LEN + TAG_LEN {
                    return format!(
                        "{}:{} insufficient_data(packet={}, need={})",
                        user.id(),
                        user.cipher().as_str(),
                        packet.len(),
                        XNONCE_LEN + TAG_LEN
                    );
                }
                let (nonce, ciphertext) = packet.split_at(XNONCE_LEN);
                let cipher = match user.xchacha_cipher() {
                    Ok(cipher) => cipher,
                    Err(_) => {
                        return format!("{}:{} key_init_failed", user.id(), user.cipher().as_str());
                    },
                };
                let mut candidate = ciphertext.to_vec();
                match cipher.decrypt_in_place(XNonce::from_slice(nonce), b"", &mut candidate) {
                    Ok(()) => match parse_ss2022_chacha_udp_request_body(&candidate) {
                        Ok((plaintext, _, _)) => format!(
                            "{}:{} packet_ok(payload_len={})",
                            user.id(),
                            user.cipher().as_str(),
                            plaintext.len()
                        ),
                        Err(error) => format!(
                            "{}:{} header_invalid({})",
                            user.id(),
                            user.cipher().as_str(),
                            error
                        ),
                    },
                    Err(_) => format!("{}:{} auth_failed", user.id(), user.cipher().as_str()),
                }
            } else if user.cipher().is_2022_aes() {
                if packet.len() < SS2022_UDP_SEPARATE_HEADER_LEN + TAG_LEN {
                    return format!(
                        "{}:{} insufficient_data(packet={}, need={})",
                        user.id(),
                        user.cipher().as_str(),
                        packet.len(),
                        SS2022_UDP_SEPARATE_HEADER_LEN + TAG_LEN
                    );
                }
                let (encrypted_header, ciphertext) =
                    packet.split_at(SS2022_UDP_SEPARATE_HEADER_LEN);
                let separate_header = match decrypt_ss2022_separate_header(user, encrypted_header) {
                    Ok(header) => header,
                    Err(_) => {
                        return format!(
                            "{}:{} separate_header_auth_failed",
                            user.id(),
                            user.cipher().as_str()
                        );
                    },
                };
                let less_safe =
                    match build_session_key(user.cipher(), user.master_key(), &separate_header[..8])
                    {
                        Ok(key) => key,
                        Err(error) => return format_build_key_error(user, error),
                    };
                let mut candidate = ciphertext.to_vec();
                match less_safe.open_in_place(
                    ss2022_udp_nonce(&separate_header).unwrap_or_else(|_| nonce_zero()),
                    Aad::empty(),
                    &mut candidate,
                ) {
                    Ok(body) => match parse_ss2022_udp_request_body(body) {
                        Ok(plaintext) => format!(
                            "{}:{} packet_ok(payload_len={})",
                            user.id(),
                            user.cipher().as_str(),
                            plaintext.len()
                        ),
                        Err(error) => format!(
                            "{}:{} header_invalid({})",
                            user.id(),
                            user.cipher().as_str(),
                            error
                        ),
                    },
                    Err(_) => format!("{}:{} auth_failed", user.id(), user.cipher().as_str()),
                }
            } else {
                let salt_len = user.cipher().salt_len();
                if packet.len() < salt_len + TAG_LEN {
                    return format!(
                        "{}:{} insufficient_data(packet={}, need={})",
                        user.id(),
                        user.cipher().as_str(),
                        packet.len(),
                        salt_len + TAG_LEN
                    );
                }

                let (salt, ciphertext) = packet.split_at(salt_len);
                let less_safe = match build_session_key(user.cipher(), user.master_key(), salt) {
                    Ok(key) => key,
                    Err(error) => return format_build_key_error(user, error),
                };
                let mut candidate = ciphertext.to_vec();
                match less_safe.open_in_place(nonce_zero(), Aad::empty(), &mut candidate) {
                    Ok(plaintext) => format!(
                        "{}:{} packet_ok(payload_len={})",
                        user.id(),
                        user.cipher().as_str(),
                        plaintext.len()
                    ),
                    Err(_) => format!("{}:{} auth_failed", user.id(), user.cipher().as_str()),
                }
            }
        })
        .collect()
}
