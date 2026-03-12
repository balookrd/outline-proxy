use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

pub const SOCKS_ATYP_IPV4: u8 = 0x01;
pub const SOCKS_ATYP_DOMAIN: u8 = 0x03;
pub const SOCKS_ATYP_IPV6: u8 = 0x04;

#[derive(Clone, Copy, Debug, Deserialize)]
pub enum CipherKind {
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,
    #[serde(rename = "aes-128-gcm", alias = "aes128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-256-gcm", alias = "aes256-gcm")]
    Aes256Gcm,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WsTransportMode {
    Http1,
    H2,
    H3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    IpV4(Ipv4Addr, u16),
    IpV6(Ipv6Addr, u16),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Self::IpV4(addr, port) => {
                out.push(SOCKS_ATYP_IPV4);
                out.extend_from_slice(&addr.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Self::IpV6(addr, port) => {
                out.push(SOCKS_ATYP_IPV6);
                out.extend_from_slice(&addr.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Self::Domain(host, port) => {
                let len: u8 = host
                    .len()
                    .try_into()
                    .context("domain name is too long for SOCKS5")?;
                out.push(SOCKS_ATYP_DOMAIN);
                out.push(len);
                out.extend_from_slice(host.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(out)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<(Self, usize)> {
        let atyp = *bytes
            .first()
            .ok_or_else(|| anyhow!("empty address buffer"))?;
        match atyp {
            SOCKS_ATYP_IPV4 => {
                if bytes.len() < 7 {
                    bail!("short IPv4 address");
                }
                let host = Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]);
                let port = u16::from_be_bytes([bytes[5], bytes[6]]);
                Ok((Self::IpV4(host, port), 7))
            }
            SOCKS_ATYP_IPV6 => {
                if bytes.len() < 19 {
                    bail!("short IPv6 address");
                }
                let mut raw = [0u8; 16];
                raw.copy_from_slice(&bytes[1..17]);
                let port = u16::from_be_bytes([bytes[17], bytes[18]]);
                Ok((Self::IpV6(Ipv6Addr::from(raw), port), 19))
            }
            SOCKS_ATYP_DOMAIN => {
                let len = *bytes
                    .get(1)
                    .ok_or_else(|| anyhow!("short domain address"))?
                    as usize;
                if bytes.len() < 2 + len + 2 {
                    bail!("short domain address");
                }
                let host = String::from_utf8(bytes[2..2 + len].to_vec())
                    .context("domain is not valid UTF-8")?;
                let port = u16::from_be_bytes([bytes[2 + len], bytes[2 + len + 1]]);
                Ok((Self::Domain(host, port), 2 + len + 2))
            }
            _ => bail!("unsupported address type: {atyp}"),
        }
    }
}

impl CipherKind {
    pub fn key_len(self) -> usize {
        match self {
            Self::Chacha20IetfPoly1305 => 32,
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }

    pub fn salt_len(self) -> usize {
        self.key_len()
    }
}

impl Default for WsTransportMode {
    fn default() -> Self {
        Self::Http1
    }
}

impl std::str::FromStr for CipherKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "chacha20-ietf-poly1305" => Ok(Self::Chacha20IetfPoly1305),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            _ => bail!("unsupported cipher: {s}"),
        }
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

impl fmt::Display for CipherKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
        };
        f.write_str(value)
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

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IpV4(ip, port) => write!(f, "{ip}:{port}"),
            Self::IpV6(ip, port) => write!(f, "[{ip}]:{port}"),
            Self::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

pub fn socket_addr_to_target(addr: SocketAddr) -> TargetAddr {
    match addr {
        SocketAddr::V4(v4) => TargetAddr::IpV4(*v4.ip(), v4.port()),
        SocketAddr::V6(v6) => TargetAddr::IpV6(*v6.ip(), v6.port()),
    }
}
