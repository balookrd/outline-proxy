use serde::Deserialize;
use thiserror::Error;

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum, Deserialize)]
pub enum CipherKind {
    #[value(name = "aes-128-gcm")]
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[value(name = "aes-256-gcm")]
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[value(name = "chacha20-ietf-poly1305")]
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,
    #[value(name = "2022-blake3-aes-128-gcm")]
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Aes128Gcm2022,
    #[value(name = "2022-blake3-aes-256-gcm")]
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Aes256Gcm2022,
    #[value(name = "2022-blake3-chacha20-poly1305")]
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

    pub const fn is_2022(self) -> bool {
        matches!(self, Self::Aes128Gcm2022 | Self::Aes256Gcm2022 | Self::Chacha20Poly13052022)
    }

    pub const fn is_2022_aes(self) -> bool {
        matches!(self, Self::Aes128Gcm2022 | Self::Aes256Gcm2022)
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserEntry {
    pub id: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub fwmark: Option<u32>,
    #[serde(default)]
    pub method: Option<CipherKind>,
    #[serde(default)]
    pub ws_path_tcp: Option<String>,
    #[serde(default)]
    pub ws_path_udp: Option<String>,
    #[serde(default)]
    pub vless_id: Option<String>,
    #[serde(default)]
    pub vless_ws_path: Option<String>,
}

impl UserEntry {
    pub fn effective_method(&self, default: CipherKind) -> CipherKind {
        self.method.unwrap_or(default)
    }

    pub fn effective_ws_path_tcp<'a>(&'a self, default: &'a str) -> &'a str {
        self.ws_path_tcp.as_deref().unwrap_or(default)
    }

    pub fn effective_ws_path_udp<'a>(&'a self, default: &'a str) -> &'a str {
        self.ws_path_udp.as_deref().unwrap_or(default)
    }

    pub fn effective_vless_ws_path<'a>(&'a self, default: Option<&'a str>) -> Option<&'a str> {
        self.vless_ws_path.as_deref().or(default)
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configure at least one key via password or [[users]] with password/vless_id")]
    MissingUsers,
    #[error("duplicate user id: {0}")]
    DuplicateUserId(String),
}
