use std::fmt;

use anyhow::{Result, bail};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize)]
pub enum CipherKind {
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,
    #[serde(rename = "aes-128-gcm", alias = "aes128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-256-gcm", alias = "aes256-gcm")]
    Aes256Gcm,
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Aes128Gcm2022,
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Aes256Gcm2022,
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Chacha20Poly13052022,
}

impl CipherKind {
    pub fn key_len(self) -> usize {
        match self {
            Self::Chacha20IetfPoly1305 => 32,
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
            Self::Aes128Gcm2022 => 16,
            Self::Aes256Gcm2022 => 32,
            Self::Chacha20Poly13052022 => 32,
        }
    }

    pub fn salt_len(self) -> usize {
        self.key_len()
    }

    pub fn is_ss2022(self) -> bool {
        matches!(self, Self::Aes128Gcm2022 | Self::Aes256Gcm2022 | Self::Chacha20Poly13052022)
    }

    pub fn is_ss2022_aes(self) -> bool {
        matches!(self, Self::Aes128Gcm2022 | Self::Aes256Gcm2022)
    }

    pub fn is_ss2022_chacha(self) -> bool {
        matches!(self, Self::Chacha20Poly13052022)
    }

    pub fn max_payload_len(self) -> usize {
        if self.is_ss2022() { 0xffff } else { 0x3fff }
    }
}

impl std::str::FromStr for CipherKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "chacha20-ietf-poly1305" => Ok(Self::Chacha20IetfPoly1305),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "2022-blake3-aes-128-gcm" => Ok(Self::Aes128Gcm2022),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aes256Gcm2022),
            "2022-blake3-chacha20-poly1305" => Ok(Self::Chacha20Poly13052022),
            _ => bail!("unsupported cipher: {s}"),
        }
    }
}

impl fmt::Display for CipherKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Aes128Gcm2022 => "2022-blake3-aes-128-gcm",
            Self::Aes256Gcm2022 => "2022-blake3-aes-256-gcm",
            Self::Chacha20Poly13052022 => "2022-blake3-chacha20-poly1305",
        };
        f.write_str(value)
    }
}
