use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Shadowsocks AEAD cipher selection shared by server config, client uplink
/// config and the SS2022 framing code. Serde names match the canonical
/// Shadowsocks method strings; the `aes128-gcm`/`aes256-gcm` aliases keep
/// historical client configs loading.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum CipherKind {
    #[cfg_attr(feature = "clap", value(name = "aes-128-gcm"))]
    #[serde(rename = "aes-128-gcm", alias = "aes128-gcm")]
    Aes128Gcm,
    #[cfg_attr(feature = "clap", value(name = "aes-256-gcm"))]
    #[serde(rename = "aes-256-gcm", alias = "aes256-gcm")]
    Aes256Gcm,
    #[cfg_attr(feature = "clap", value(name = "chacha20-ietf-poly1305"))]
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,
    #[cfg_attr(feature = "clap", value(name = "2022-blake3-aes-128-gcm"))]
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Aes128Gcm2022,
    #[cfg_attr(feature = "clap", value(name = "2022-blake3-aes-256-gcm"))]
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Aes256Gcm2022,
    #[cfg_attr(feature = "clap", value(name = "2022-blake3-chacha20-poly1305"))]
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Chacha20Poly13052022,
}

impl CipherKind {
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes128Gcm2022 => 16,
            Self::Aes256Gcm
            | Self::Chacha20IetfPoly1305
            | Self::Aes256Gcm2022
            | Self::Chacha20Poly13052022 => 32,
        }
    }

    pub const fn salt_len(self) -> usize {
        self.key_len()
    }

    pub const fn is_ss2022(self) -> bool {
        matches!(self, Self::Aes128Gcm2022 | Self::Aes256Gcm2022 | Self::Chacha20Poly13052022)
    }

    pub const fn is_ss2022_aes(self) -> bool {
        matches!(self, Self::Aes128Gcm2022 | Self::Aes256Gcm2022)
    }

    pub const fn is_ss2022_chacha(self) -> bool {
        matches!(self, Self::Chacha20Poly13052022)
    }

    /// Maximum payload bytes a single AEAD chunk may carry: the classic
    /// Shadowsocks length mask is 14 bits, SS2022 allows the full u16.
    pub const fn max_payload_len(self) -> usize {
        if self.is_ss2022() { 0xffff } else { 0x3fff }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
            Self::Aes128Gcm2022 => "2022-blake3-aes-128-gcm",
            Self::Aes256Gcm2022 => "2022-blake3-aes-256-gcm",
            Self::Chacha20Poly13052022 => "2022-blake3-chacha20-poly1305",
        }
    }
}

#[derive(Debug, Error)]
pub enum MasterKeyError {
    #[error("failed to decode ss2022 PSK as base64")]
    InvalidBase64Psk(#[from] base64::DecodeError),
    #[error("ss2022 PSK length mismatch: got {got}, expected {expected}")]
    PskLengthMismatch { got: usize, expected: usize },
}

impl CipherKind {
    /// Materializes the master key from the configured secret: SS2022
    /// methods take a base64 PSK of exactly `key_len()` bytes, classic
    /// methods stretch the password via OpenSSL's EVP_BytesToKey.
    ///
    /// The key is returned inside [`Zeroizing`] so the buffer is wiped when
    /// the last owner drops it — a master key outlives the call that derives
    /// it (transports, user tables), and freed pages must not keep it
    /// readable in a core dump or swap. `Zeroizing<Vec<u8>>` derefs to
    /// `Vec<u8>`/`[u8]`, so callers passing `&master_key` are unaffected.
    pub fn derive_master_key(self, password: &str) -> Result<Zeroizing<Vec<u8>>, MasterKeyError> {
        if self.is_ss2022() {
            use base64::Engine;
            // Wrapped before the length check so a rejected PSK is wiped too.
            let key = Zeroizing::new(base64::engine::general_purpose::STANDARD.decode(password)?);
            if key.len() != self.key_len() {
                return Err(MasterKeyError::PskLengthMismatch {
                    got: key.len(),
                    expected: self.key_len(),
                });
            }
            Ok(key)
        } else {
            Ok(evp_bytes_to_key(password.as_bytes(), self.key_len()))
        }
    }
}

/// HKDF-SHA1 `info` string for classic (pre-2022) Shadowsocks AEAD session
/// subkeys. The exact bytes are wire-compatibility-critical; both ends feed
/// this to their respective HKDF backends.
pub const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";

/// Bytes an MD5 digest contributes per round of the stretch below.
const MD5_BLOCK_LEN: usize = 16;

/// OpenSSL's EVP_BytesToKey (MD5, no salt): the classic Shadowsocks
/// password-to-key stretch.
///
/// Every buffer here holds key material — the running digest `prev` is a
/// key block, and `input` carries the password — so all of them, including
/// the MD5 output itself, are wiped on the way out. The returned key is
/// [`Zeroizing`] for the same reason as [`CipherKind::derive_master_key`].
///
/// The output is sized to whole MD5 blocks up front: `Zeroizing` can only
/// wipe the allocation it still owns, so a grow part-way through the loop
/// would strand an unwiped copy of the earlier blocks in the freed one.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Zeroizing<Vec<u8>> {
    let mut key =
        Zeroizing::new(Vec::with_capacity(key_len.div_ceil(MD5_BLOCK_LEN) * MD5_BLOCK_LEN));
    let mut prev = Zeroizing::new(Vec::new());

    while key.len() < key_len {
        let mut input = Zeroizing::new(Vec::with_capacity(prev.len() + password.len()));
        input.extend_from_slice(&prev);
        input.extend_from_slice(password);
        let mut digest = md5::compute(&*input);
        // Assigning through `prev` drops (and wipes) the previous block.
        prev = Zeroizing::new(digest.0.to_vec());
        digest.0.zeroize();
        key.extend_from_slice(&prev);
    }

    key.truncate(key_len);
    key
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("unsupported cipher: {0}")]
pub struct UnknownCipherError(pub String);

impl std::str::FromStr for CipherKind {
    type Err = UnknownCipherError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" => Ok(Self::Chacha20IetfPoly1305),
            "2022-blake3-aes-128-gcm" => Ok(Self::Aes128Gcm2022),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aes256Gcm2022),
            "2022-blake3-chacha20-poly1305" => Ok(Self::Chacha20Poly13052022),
            _ => Err(UnknownCipherError(s.to_string())),
        }
    }
}

impl fmt::Display for CipherKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
#[path = "tests/cipher.rs"]
mod tests;
