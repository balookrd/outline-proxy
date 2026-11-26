//! Shadowsocks AEAD crypto primitives (classic + 2022) extracted into a
//! standalone crate so they can be unit-tested and reused independently of
//! the main binary.

mod aead;
mod cipher_kind;
mod error;
mod keys;
mod ss2022_udp;
mod udp;

pub use error::{CryptoError, Result};

#[cfg(test)]
mod tests;

pub use aead::{
    AeadCipher, LEGACY_MAX_PAYLOAD_LEN, MAX_STREAM_NONCE_COUNTER, SHADOWSOCKS_MAX_PAYLOAD,
    SHADOWSOCKS_NONCE_LEN, SHADOWSOCKS_TAG_LEN, SHADOWSOCKS_XNONCE_LEN, StreamNonce, decrypt,
    encrypt, encrypt_into, increment_nonce,
};
pub use cipher_kind::CipherKind;
pub use keys::{SHADOWSOCKS_2022_INFO, SHADOWSOCKS_INFO, derive_subkey, evp_bytes_to_key};
pub use ss2022_udp::{
    AesHeaderCipher, XChaChaCipher, decrypt_udp_packet_2022, decrypt_udp_separate_header,
    encrypt_udp_packet_2022, encrypt_udp_separate_header, validate_ss2022_timestamp,
};
pub use udp::{decrypt_udp_packet, encrypt_udp_packet};
