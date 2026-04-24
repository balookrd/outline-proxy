use std::{
    fmt,
    sync::{Arc, OnceLock},
};

use aes::{Aes128, Aes256, cipher::KeyInit};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::XChaCha20Poly1305;
use md5::{Digest as _, Md5};
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
    ) -> Result<Self, CryptoError> {
        let id: Arc<str> = Arc::from(id.into());
        let log_label: Arc<str> = Arc::from(format!("{}:{}", &id, cipher.as_str()).as_str());
        Ok(Self {
            id,
            log_label,
            cipher,
            master_key: Arc::from(password_to_master_key(password, cipher)?),
            fwmark,
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
        if self.cipher.is_2022() {
            let Ok(decoded) = STANDARD.decode(password.as_bytes()) else {
                return Ok(false);
            };
            return Ok(self.master_key().ct_eq(&decoded).into());
        }
        let derived = bytes_to_key(password.as_bytes(), self.cipher.key_len())?;
        Ok(self.master_key().ct_eq(&derived).into())
    }

    pub(super) fn master_key(&self) -> &[u8] {
        self.master_key.as_ref()
    }
}

fn password_to_master_key(password: &str, cipher: CipherKind) -> Result<Vec<u8>, CryptoError> {
    if cipher.is_2022() {
        let key = STANDARD
            .decode(password.as_bytes())
            .map_err(|_| CryptoError::InvalidBase64Key)?;
        if key.len() != cipher.key_len() {
            return Err(CryptoError::InvalidPskLength {
                cipher: cipher.as_str(),
                expected: cipher.key_len(),
                actual: key.len(),
            });
        }
        Ok(key)
    } else {
        bytes_to_key(password.as_bytes(), cipher.key_len())
    }
}

fn bytes_to_key(password: &[u8], key_len: usize) -> Result<Vec<u8>, CryptoError> {
    if password.is_empty() {
        return Err(CryptoError::EmptyPassword);
    }

    let mut key = Vec::with_capacity(key_len);
    let mut previous = [0u8; 16];
    let mut has_previous = false;
    while key.len() < key_len {
        let mut hasher = Md5::new();
        if has_previous {
            hasher.update(previous);
        }
        hasher.update(password);
        previous = hasher.finalize().into();
        has_previous = true;
        key.extend_from_slice(&previous);
    }
    key.truncate(key_len);
    Ok(key)
}
