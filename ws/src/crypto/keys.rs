use anyhow::{Context, Result, bail};
use base64::Engine;
use hkdf::Hkdf;
use sha1::Sha1;

use crate::types::CipherKind;

pub const SHADOWSOCKS_INFO: &[u8] = b"ss-subkey";
pub const SHADOWSOCKS_2022_INFO: &str = "shadowsocks 2022 session subkey";

impl CipherKind {
    pub fn derive_master_key(self, password: &str) -> Result<Vec<u8>> {
        if self.is_ss2022() {
            let key = base64::engine::general_purpose::STANDARD
                .decode(password)
                .context("failed to decode ss2022 PSK as base64")?;
            if key.len() != self.key_len() {
                bail!(
                    "invalid ss2022 PSK length for {self}: expected {} bytes, got {}",
                    self.key_len(),
                    key.len()
                );
            }
            Ok(key)
        } else {
            Ok(evp_bytes_to_key(password.as_bytes(), self.key_len()))
        }
    }
}

pub fn derive_subkey(cipher: CipherKind, master_key: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    let mut subkey = vec![0u8; cipher.key_len()];
    if cipher.is_ss2022() {
        let mut key_material = Vec::with_capacity(master_key.len() + salt.len());
        key_material.extend_from_slice(master_key);
        key_material.extend_from_slice(salt);
        let derived = blake3::derive_key(SHADOWSOCKS_2022_INFO, &key_material);
        subkey.copy_from_slice(&derived[..cipher.key_len()]);
    } else {
        let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
        hk.expand(SHADOWSOCKS_INFO, &mut subkey)
            .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;
    }
    Ok(subkey)
}

pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev = Vec::new();

    while key.len() < key_len {
        let mut input = Vec::with_capacity(prev.len() + password.len());
        input.extend_from_slice(&prev);
        input.extend_from_slice(password);
        prev = md5::compute(input).0.to_vec();
        key.extend_from_slice(&prev);
    }

    key.truncate(key_len);
    key
}
