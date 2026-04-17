//! Small data types that both the transport layer and the main binary's
//! config parser need. Extracted from `outline_ws_rust::types` so the
//! transport crate stays decoupled from the main binary.

use std::fmt;
use std::net::SocketAddr;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum WsTransportMode {
    #[default]
    Http1,
    H2,
    H3,
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

impl std::str::FromStr for WsTransportMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "http1" => Ok(Self::Http1),
            "h2" => Ok(Self::H2),
            "h3" => Ok(Self::H3),
            _ => bail!("unsupported websocket transport mode: {s}"),
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

impl fmt::Display for WsTransportMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Http1 => "http1",
            Self::H2 => "h2",
            Self::H3 => "h3",
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
