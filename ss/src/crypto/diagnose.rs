use chacha20poly1305::{XNonce, aead::AeadInPlace as _};
use ring::aead::{Aad, LessSafeKey, UnboundKey};

use super::{
    primitives::{
        LEGACY_MAX_CHUNK_SIZE, MAX_SUBKEY_LEN, SS2022_REQUEST_FIXED_HEADER_LEN,
        SS2022_UDP_SEPARATE_HEADER_LEN, TAG_LEN, XNONCE_LEN, cipher_algorithm, derive_subkey,
        nonce_zero, parse_ss2022_chacha_udp_request_body, parse_ss2022_udp_request_body,
        ss2022_udp_nonce, validate_ss2022_request_fixed_header,
    },
    udp::decrypt_ss2022_separate_header,
    user_key::UserKey,
};
use crate::config::CipherKind;

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
                let mut subkey = [0_u8; MAX_SUBKEY_LEN];
                let key_len = match derive_subkey(
                    user.cipher(),
                    user.master_key(),
                    salt,
                    &mut subkey,
                ) {
                    Ok(n) => n,
                    Err(error) => {
                        return format!(
                            "{}:{} subkey_error({})",
                            user.id(),
                            user.cipher().as_str(),
                            error
                        );
                    },
                };
                let algorithm = cipher_algorithm(user.cipher());
                let key = match UnboundKey::new(algorithm, &subkey[..key_len]) {
                    Ok(key) => key,
                    Err(_) => {
                        return format!("{}:{} key_init_failed", user.id(), user.cipher().as_str());
                    },
                };
                let less_safe = LessSafeKey::new(key);
                match less_safe.open_in_place(nonce_zero(), Aad::empty(), &mut candidate) {
                    Ok(header) if header.len() == SS2022_REQUEST_FIXED_HEADER_LEN => {
                        match validate_ss2022_request_fixed_header(header) {
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
                        }
                    },
                    Ok(header) => format!(
                        "{}:{} invalid_header_len({})",
                        user.id(),
                        user.cipher().as_str(),
                        header.len()
                    ),
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
                let encrypted_len = &buffer[salt_len..salt_len + 2 + TAG_LEN];
                let mut subkey = [0_u8; MAX_SUBKEY_LEN];
                let key_len = match derive_subkey(
                    user.cipher(),
                    user.master_key(),
                    salt,
                    &mut subkey,
                ) {
                    Ok(n) => n,
                    Err(error) => {
                        return format!(
                            "{}:{} subkey_error({})",
                            user.id(),
                            user.cipher().as_str(),
                            error
                        );
                    },
                };
                let algorithm = cipher_algorithm(user.cipher());
                let key = match UnboundKey::new(algorithm, &subkey[..key_len]) {
                    Ok(key) => key,
                    Err(_) => {
                        return format!("{}:{} key_init_failed", user.id(), user.cipher().as_str());
                    },
                };
                let less_safe = LessSafeKey::new(key);
                let mut candidate = encrypted_len.to_vec();
                match less_safe.open_in_place(nonce_zero(), Aad::empty(), &mut candidate) {
                    Ok(plaintext_len) if plaintext_len.len() == 2 => {
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
                    Ok(plaintext_len) => format!(
                        "{}:{} invalid_header_len({})",
                        user.id(),
                        user.cipher().as_str(),
                        plaintext_len.len()
                    ),
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
                let mut subkey = [0_u8; MAX_SUBKEY_LEN];
                let key_len = match derive_subkey(
                    user.cipher(),
                    user.master_key(),
                    &separate_header[..8],
                    &mut subkey,
                ) {
                    Ok(n) => n,
                    Err(error) => {
                        return format!(
                            "{}:{} subkey_error({})",
                            user.id(),
                            user.cipher().as_str(),
                            error
                        );
                    },
                };
                let algorithm = cipher_algorithm(user.cipher());
                let key = match UnboundKey::new(algorithm, &subkey[..key_len]) {
                    Ok(key) => key,
                    Err(_) => {
                        return format!("{}:{} key_init_failed", user.id(), user.cipher().as_str());
                    },
                };
                let less_safe = LessSafeKey::new(key);
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
                let mut subkey = [0_u8; MAX_SUBKEY_LEN];
                let key_len = match derive_subkey(
                    user.cipher(),
                    user.master_key(),
                    salt,
                    &mut subkey,
                ) {
                    Ok(n) => n,
                    Err(error) => {
                        return format!(
                            "{}:{} subkey_error({})",
                            user.id(),
                            user.cipher().as_str(),
                            error
                        );
                    },
                };
                let algorithm = cipher_algorithm(user.cipher());
                let key = match UnboundKey::new(algorithm, &subkey[..key_len]) {
                    Ok(key) => key,
                    Err(_) => {
                        return format!("{}:{} key_init_failed", user.id(), user.cipher().as_str());
                    },
                };
                let less_safe = LessSafeKey::new(key);
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
