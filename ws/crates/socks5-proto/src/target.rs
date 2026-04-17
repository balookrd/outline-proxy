use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::{Result, Socks5Error};

pub const SOCKS_ATYP_IPV4: u8 = 0x01;
pub const SOCKS_ATYP_DOMAIN: u8 = 0x03;
pub const SOCKS_ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
            },
            Self::IpV6(addr, port) => {
                out.push(SOCKS_ATYP_IPV6);
                out.extend_from_slice(&addr.octets());
                out.extend_from_slice(&port.to_be_bytes());
            },
            Self::Domain(host, port) => {
                let len: u8 = host.len().try_into().map_err(|_| Socks5Error::DomainTooLong)?;
                out.push(SOCKS_ATYP_DOMAIN);
                out.push(len);
                out.extend_from_slice(host.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            },
        }
        Ok(out)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<(Self, usize)> {
        let atyp = *bytes.first().ok_or(Socks5Error::EmptyAddressBuffer)?;
        match atyp {
            SOCKS_ATYP_IPV4 => {
                if bytes.len() < 7 {
                    return Err(Socks5Error::ShortAddress { kind: "IPv4" });
                }
                let host = Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]);
                let port = u16::from_be_bytes([bytes[5], bytes[6]]);
                Ok((Self::IpV4(host, port), 7))
            },
            SOCKS_ATYP_IPV6 => {
                if bytes.len() < 19 {
                    return Err(Socks5Error::ShortAddress { kind: "IPv6" });
                }
                let mut raw = [0u8; 16];
                raw.copy_from_slice(&bytes[1..17]);
                let port = u16::from_be_bytes([bytes[17], bytes[18]]);
                Ok((Self::IpV6(Ipv6Addr::from(raw), port), 19))
            },
            SOCKS_ATYP_DOMAIN => {
                let len = *bytes.get(1).ok_or(Socks5Error::ShortAddress { kind: "domain" })?
                    as usize;
                if bytes.len() < 2 + len + 2 {
                    return Err(Socks5Error::ShortAddress { kind: "domain" });
                }
                let host = String::from_utf8(bytes[2..2 + len].to_vec())
                    .map_err(|_| Socks5Error::DomainNotUtf8)?;
                let port = u16::from_be_bytes([bytes[2 + len], bytes[2 + len + 1]]);
                Ok((Self::Domain(host, port), 2 + len + 2))
            },
            _ => Err(Socks5Error::UnsupportedAddressType(atyp)),
        }
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
