use hkdf::Hkdf;
use sha1::Sha1;

use crate::cipher_kind::CipherKind;
use crate::error::{CryptoError, Result};

// Master-key derivation (`CipherKind::derive_master_key`, EVP_BytesToKey)
// lives in `outline-wire` next to the cipher enum itself.
pub use outline_wire::evp_bytes_to_key;

pub const SHADOWSOCKS_INFO: &[u8] = b"ss-subkey";
pub const SHADOWSOCKS_2022_INFO: &str = "shadowsocks 2022 session subkey";

/// Derives a session subkey from `master_key` and `salt`.
///
/// The active portion of the returned array is `&result[..cipher.key_len()]`;
/// bytes beyond that index are zeroed padding.  All supported ciphers have
/// `key_len() ≤ 32`, so the full key fits on the stack with no heap allocation.
pub fn derive_subkey(cipher: CipherKind, master_key: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let mut subkey = [0u8; 32];
    let key_len = cipher.key_len();
    if cipher.is_ss2022() {
        let mut key_material = Vec::with_capacity(master_key.len() + salt.len());
        key_material.extend_from_slice(master_key);
        key_material.extend_from_slice(salt);
        let derived = blake3::derive_key(SHADOWSOCKS_2022_INFO, &key_material);
        subkey[..key_len].copy_from_slice(&derived[..key_len]);
    } else {
        let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
        hk.expand(SHADOWSOCKS_INFO, &mut subkey[..key_len])
            .map_err(|_| CryptoError::HkdfExpandFailed)?;
    }
    Ok(subkey)
}
