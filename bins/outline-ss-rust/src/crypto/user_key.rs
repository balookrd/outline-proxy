use std::{
    fmt,
    net::IpAddr,
    sync::{Arc, OnceLock},
};

use aes::{Aes128, Aes256, cipher::KeyInit};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::XChaCha20Poly1305;
use outline_net::IpAliasTable;
use outline_wire::MasterKeyError;
use subtle::ConstantTimeEq;

use super::error::CryptoError;
use crate::config::CipherKind;

#[allow(clippy::large_enum_variant)]
pub(super) enum AesHeaderCipher {
    Aes128(Aes128),
    Aes256(Aes256),
}

struct CachedCiphers {
    xchacha: OnceLock<XChaCha20Poly1305>,
    aes_header: OnceLock<AesHeaderCipher>,
}

#[derive(Clone)]
pub struct UserKey {
    id: Arc<str>,
    log_label: Arc<str>,
    cipher: CipherKind,
    master_key: Arc<[u8]>,
    fwmark: Option<u32>,
    /// Source-IP → alias table for accounting relabeling (metrics/NAT/logs).
    /// `None` for the common case of no aliases. See [`Self::effective_label`].
    aliases: Option<Arc<IpAliasTable>>,
    ciphers: Arc<CachedCiphers>,
}

impl fmt::Debug for UserKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserKey").field("id", &self.id).finish()
    }
}

impl UserKey {
    pub fn new(
        id: impl Into<String>,
        password: &str,
        fwmark: Option<u32>,
        cipher: CipherKind,
        aliases: Option<Arc<IpAliasTable>>,
    ) -> Result<Self, CryptoError> {
        let id: Arc<str> = Arc::from(id.into());
        let log_label: Arc<str> = Arc::from(format!("{}:{}", id, cipher.as_str()).as_str());
        Ok(Self {
            id,
            log_label,
            cipher,
            master_key: Arc::from(password_to_master_key(password, cipher)?),
            fwmark,
            aliases,
            ciphers: Arc::new(CachedCiphers {
                xchacha: OnceLock::new(),
                aes_header: OnceLock::new(),
            }),
        })
    }

    pub(super) fn xchacha_cipher(&self) -> Result<&XChaCha20Poly1305, CryptoError> {
        if let Some(c) = self.ciphers.xchacha.get() {
            return Ok(c);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.master_key())
            .map_err(|_| CryptoError::Cipher)?;
        Ok(self.ciphers.xchacha.get_or_init(|| cipher))
    }

    pub(super) fn aes_header_cipher(&self) -> Result<&AesHeaderCipher, CryptoError> {
        if let Some(c) = self.ciphers.aes_header.get() {
            return Ok(c);
        }
        let cipher = match self.cipher {
            CipherKind::Aes128Gcm2022 => AesHeaderCipher::Aes128(
                Aes128::new_from_slice(self.master_key()).map_err(|_| CryptoError::Cipher)?,
            ),
            CipherKind::Aes256Gcm2022 => AesHeaderCipher::Aes256(
                Aes256::new_from_slice(self.master_key()).map_err(|_| CryptoError::Cipher)?,
            ),
            _ => return Err(CryptoError::InvalidHeader),
        };
        Ok(self.ciphers.aes_header.get_or_init(|| cipher))
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn id_arc(&self) -> Arc<str> {
        Arc::clone(&self.id)
    }

    /// Effective accounting label for a client whose source IP is `peer`: the
    /// matching alias when `peer` falls into one of this user's configured
    /// subnets, otherwise the base config id. A `None` peer or no match falls
    /// back to the base id. Accounting only (metrics/NAT/logs) — never
    /// authentication, which always keys on the decrypting [`Self::id`].
    pub fn effective_label(&self, peer: Option<IpAddr>) -> Arc<str> {
        peer.and_then(|ip| self.aliases.as_ref().and_then(|t| t.resolve(ip)))
            .unwrap_or_else(|| self.id_arc())
    }

    pub fn log_label(&self) -> Arc<str> {
        Arc::clone(&self.log_label)
    }

    pub fn fwmark(&self) -> Option<u32> {
        self.fwmark
    }

    pub fn cipher(&self) -> CipherKind {
        self.cipher
    }

    pub fn matches_password(&self, password: &str) -> Result<bool, CryptoError> {
        if self.cipher.is_ss2022() {
            let Ok(decoded) = STANDARD.decode(password.as_bytes()) else {
                return Ok(false);
            };
            return Ok(self.master_key().ct_eq(&decoded).into());
        }
        let derived = password_to_master_key(password, self.cipher)?;
        Ok(self.master_key().ct_eq(&derived).into())
    }

    pub(super) fn master_key(&self) -> &[u8] {
        self.master_key.as_ref()
    }
}

fn password_to_master_key(password: &str, cipher: CipherKind) -> Result<Vec<u8>, CryptoError> {
    // outline-wire's EVP stretch happily derives a key from an empty
    // password; the server rejects those up front.
    if !cipher.is_ss2022() && password.is_empty() {
        return Err(CryptoError::EmptyPassword);
    }
    cipher.derive_master_key(password).map_err(|error| match error {
        MasterKeyError::InvalidBase64Psk(_) => CryptoError::InvalidBase64Key,
        MasterKeyError::PskLengthMismatch { got, expected } => CryptoError::InvalidPskLength {
            cipher: cipher.as_str(),
            expected,
            actual: got,
        },
    })
}

#[cfg(test)]
#[path = "tests/user_key.rs"]
mod tests;
