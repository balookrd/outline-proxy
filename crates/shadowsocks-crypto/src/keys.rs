use hkdf::Hkdf;
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::cipher_kind::CipherKind;
use crate::error::{CryptoError, Result};

// Master-key derivation (`CipherKind::derive_master_key`, EVP_BytesToKey)
// lives in `outline-wire` next to the cipher enum itself, as do the two
// subkey-derivation constants shared verbatim with the server.
pub use outline_wire::SS_SUBKEY_INFO as SHADOWSOCKS_INFO;
pub use outline_wire::evp_bytes_to_key;
pub use outline_wire::ss2022::SS2022_SUBKEY_CONTEXT as SHADOWSOCKS_2022_INFO;

/// Derives a session subkey from `master_key` and `salt`.
///
/// The active portion of the returned array is `&result[..cipher.key_len()]`;
/// bytes beyond that index are zeroed padding.  All supported ciphers have
/// `key_len() ≤ 32`, so the full key fits on the stack with no heap allocation.
///
/// The array is wrapped in [`Zeroizing`] so each caller's stack copy is wiped
/// on drop instead of lingering in a reclaimed frame.  It derefs to
/// `[u8; 32]`, so `&subkey[..cipher.key_len()]` still works unchanged.
pub fn derive_subkey(
    cipher: CipherKind,
    master_key: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut subkey = Zeroizing::new([0u8; 32]);
    let key_len = cipher.key_len();
    if cipher.is_ss2022() {
        outline_wire::ss2022::ss2022_session_subkey_into(master_key, salt, &mut subkey[..key_len]);
    } else {
        let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
        hk.expand(SHADOWSOCKS_INFO, &mut subkey[..key_len])
            .map_err(|_| CryptoError::HkdfExpandFailed)?;
    }
    Ok(subkey)
}

#[cfg(test)]
#[path = "tests/keys.rs"]
mod tests;
