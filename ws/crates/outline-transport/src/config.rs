//! Small data types that both the transport layer and the main binary's
//! config parser need. Extracted from `outline_ws_rust::types` so the
//! transport crate stays decoupled from the main binary.

use std::fmt;
use std::net::SocketAddr;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum TransportMode {
    /// WebSocket over HTTP/1.1 (RFC 6455). Aliases `http1` and `h1`
    /// remain accepted for backward compatibility with configs
    /// written before the rename.
    #[default]
    #[serde(alias = "http1", alias = "h1")]
    WsH1,
    /// WebSocket over HTTP/2 (RFC 8441). Alias `h2` for compat.
    #[serde(alias = "h2")]
    WsH2,
    /// WebSocket over HTTP/3 (RFC 9220). Alias `h3` for compat.
    #[serde(alias = "h3")]
    WsH3,
    /// Raw QUIC: no WebSocket framing, no HTTP/3. Pairs with the
    /// outline-ss-rust server's matching `outline-quic` ALPN. TCP-like
    /// sessions ride a fresh bidi stream; UDP-like sessions use QUIC
    /// datagrams (RFC 9221). Available only when the `quic` feature is
    /// enabled at build time.
    Quic,
    /// VLESS over XHTTP packet-up, carried on HTTP/2. Pairs with the
    /// server's `xhttp_path_vless` listener. Useful behind CDNs that
    /// block WebSocket upgrades.
    XhttpH2,
    /// VLESS over XHTTP packet-up, carried on HTTP/3. Same as
    /// `xhttp_h2` but on the QUIC endpoint.
    XhttpH3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAddr {
    host: String,
    port: u16,
}

impl ServerAddr {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl std::str::FromStr for TransportMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "ws_h1" | "http1" | "h1" => Ok(Self::WsH1),
            "ws_h2" | "h2" => Ok(Self::WsH2),
            "ws_h3" | "h3" => Ok(Self::WsH3),
            "quic" => Ok(Self::Quic),
            "xhttp_h2" => Ok(Self::XhttpH2),
            "xhttp_h3" => Ok(Self::XhttpH3),
            _ => bail!("unsupported transport mode: {s}"),
        }
    }
}

impl std::str::FromStr for ServerAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(match addr {
                SocketAddr::V4(v4) => Self {
                    host: v4.ip().to_string(),
                    port: v4.port(),
                },
                SocketAddr::V6(v6) => Self {
                    host: v6.ip().to_string(),
                    port: v6.port(),
                },
            });
        }

        if let Some(rest) = s.strip_prefix('[') {
            let end = rest
                .find(']')
                .ok_or_else(|| anyhow!("invalid server address: missing closing ']' in {s}"))?;
            let host = &rest[..end];
            let remainder = &rest[end + 1..];
            let port = remainder
                .strip_prefix(':')
                .ok_or_else(|| anyhow!("invalid server address: missing port in {s}"))?
                .parse::<u16>()
                .with_context(|| format!("invalid server port in {s}"))?;
            return Ok(Self { host: host.to_string(), port });
        }

        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("invalid server address: expected host:port, got {s}"))?;
        if host.is_empty() {
            bail!("invalid server address: missing host in {s}");
        }
        Ok(Self {
            host: host.to_string(),
            port: port
                .parse::<u16>()
                .with_context(|| format!("invalid server port in {s}"))?,
        })
    }
}

impl<'de> Deserialize<'de> for ServerAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for TransportMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::WsH1 => "ws_h1",
            Self::WsH2 => "ws_h2",
            Self::WsH3 => "ws_h3",
            Self::Quic => "quic",
            Self::XhttpH2 => "xhttp_h2",
            Self::XhttpH3 => "xhttp_h3",
        };
        f.write_str(value)
    }
}

impl fmt::Display for ServerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
