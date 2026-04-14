use std::{fmt, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use md5::{Digest as _, Md5};

use super::error::CryptoError;
use crate::config::CipherKind;

#[derive(Clone)]
pub struct UserKey {
    id: Arc<str>,
    cipher: CipherKind,
    master_key: Arc<[u8]>,
    fwmark: Option<u32>,
    ws_path_tcp: Arc<str>,
    ws_path_udp: Arc<str>,
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
        ws_path_tcp: impl Into<String>,
        ws_path_udp: impl Into<String>,
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            id: Arc::from(id.into()),
            cipher,
            master_key: Arc::from(password_to_master_key(password, cipher)?),
            fwmark,
            ws_path_tcp: Arc::from(ws_path_tcp.into()),
            ws_path_udp: Arc::from(ws_path_udp.into()),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn id_arc(&self) -> Arc<str> {
        Arc::clone(&self.id)
    }

    pub fn fwmark(&self) -> Option<u32> {
        self.fwmark
    }

    pub fn cipher(&self) -> CipherKind {
        self.cipher
    }

    pub fn ws_path_tcp(&self) -> &str {
        &self.ws_path_tcp
    }

    pub fn ws_path_udp(&self) -> &str {
        &self.ws_path_udp
    }

    pub fn matches_password(&self, password: &str) -> Result<bool, CryptoError> {
        let derived = password_to_master_key(password, self.cipher)?;
        Ok(self.master_key() == derived.as_slice())
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
    let mut previous = Vec::new();
    while key.len() < key_len {
        let mut material = Vec::with_capacity(previous.len() + password.len());
        if !previous.is_empty() {
            material.extend_from_slice(&previous);
        }
        material.extend_from_slice(password);
        previous = Md5::digest(&material).to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(key_len);
    Ok(key)
}
