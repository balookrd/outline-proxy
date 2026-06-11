use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;

pub const SOCKS_ATYP_IPV4: u8 = 0x01;
pub const SOCKS_ATYP_DOMAIN: u8 = 0x03;
pub const SOCKS_ATYP_IPV6: u8 = 0x04;

/// Target address in the SOCKS5 ATYP wire shape, shared by Shadowsocks,
/// SOCKS5 and (with its own ATYP numbering) VLESS framing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    IpV4(Ipv4Addr, u16),
    IpV6(Ipv6Addr, u16),
    Domain(String, u16),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TargetAddrError {
    #[error("empty address buffer")]
    EmptyBuffer,
    #[error("short {kind} address")]
    ShortAddress { kind: &'static str },
    #[error("unsupported address type: {0:#x}")]
    UnsupportedAddressType(u8),
    #[error("domain too long")]
    DomainTooLong,
    #[error("domain is not valid UTF-8")]
    DomainNotUtf8,
}

enum ParseOutcome {
    Complete(TargetAddr, usize),
    /// Not enough bytes yet to know; `kind` names the parse stage for
    /// strict callers that surface it as a hard error.
    Incomplete {
        kind: &'static str,
    },
}

fn parse_inner(bytes: &[u8]) -> Result<ParseOutcome, TargetAddrError> {
    let Some((&atyp, rest)) = bytes.split_first() else {
        return Ok(ParseOutcome::Incomplete { kind: "address" });
    };
    match atyp {
        SOCKS_ATYP_IPV4 => {
            if rest.len() < 6 {
                return Ok(ParseOutcome::Incomplete { kind: "IPv4" });
            }
            let host = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            Ok(ParseOutcome::Complete(TargetAddr::IpV4(host, port), 7))
        },
        SOCKS_ATYP_IPV6 => {
            if rest.len() < 18 {
                return Ok(ParseOutcome::Incomplete { kind: "IPv6" });
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&rest[..16]);
            let port = u16::from_be_bytes([rest[16], rest[17]]);
            Ok(ParseOutcome::Complete(TargetAddr::IpV6(Ipv6Addr::from(octets), port), 19))
        },
        SOCKS_ATYP_DOMAIN => {
            let Some((&len, rest)) = rest.split_first() else {
                return Ok(ParseOutcome::Incomplete { kind: "domain" });
            };
            let len = len as usize;
            if rest.len() < len + 2 {
                return Ok(ParseOutcome::Incomplete { kind: "domain" });
            }
            let host = std::str::from_utf8(&rest[..len])
                .map_err(|_| TargetAddrError::DomainNotUtf8)?
                .to_owned();
            let port = u16::from_be_bytes([rest[len], rest[len + 1]]);
            Ok(ParseOutcome::Complete(TargetAddr::Domain(host, port), 2 + len + 2))
        },
        other => Err(TargetAddrError::UnsupportedAddressType(other)),
    }
}

impl TargetAddr {
    /// Encodes into the SOCKS5 ATYP wire shape.
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, TargetAddrError> {
        let mut out = Vec::new();
        match self {
            Self::IpV4(addr, port) => {
                out.reserve_exact(7);
                out.push(SOCKS_ATYP_IPV4);
                out.extend_from_slice(&addr.octets());
                out.extend_from_slice(&port.to_be_bytes());
            },
            Self::IpV6(addr, port) => {
                out.reserve_exact(19);
                out.push(SOCKS_ATYP_IPV6);
                out.extend_from_slice(&addr.octets());
                out.extend_from_slice(&port.to_be_bytes());
            },
            Self::Domain(host, port) => {
                let len: u8 = host.len().try_into().map_err(|_| TargetAddrError::DomainTooLong)?;
                out.reserve_exact(2 + host.len() + 2);
                out.push(SOCKS_ATYP_DOMAIN);
                out.push(len);
                out.extend_from_slice(host.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            },
        }
        Ok(out)
    }

    /// Strict decode from a complete buffer: truncated input is an error.
    /// Returns the address and the number of bytes consumed.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<(Self, usize), TargetAddrError> {
        if bytes.is_empty() {
            return Err(TargetAddrError::EmptyBuffer);
        }
        match parse_inner(bytes)? {
            ParseOutcome::Complete(addr, consumed) => Ok((addr, consumed)),
            ParseOutcome::Incomplete { kind } => Err(TargetAddrError::ShortAddress { kind }),
        }
    }

    /// The socket address when the target is a literal IP, `None` for
    /// domains. Lets connect paths grab a ready `SocketAddr` without
    /// matching both IP variants.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::IpV4(addr, port) => Some(SocketAddr::from((*addr, *port))),
            Self::IpV6(addr, port) => Some(SocketAddr::from((*addr, *port))),
            Self::Domain(..) => None,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::IpV4(_, port) | Self::IpV6(_, port) | Self::Domain(_, port) => *port,
        }
    }
}

/// Incremental decode from a stream head: `Ok(None)` means the buffer does
/// not yet hold a complete address — read more bytes and retry.
pub fn parse_target_addr(input: &[u8]) -> Result<Option<(TargetAddr, usize)>, TargetAddrError> {
    match parse_inner(input)? {
        ParseOutcome::Complete(addr, consumed) => Ok(Some((addr, consumed))),
        ParseOutcome::Incomplete { .. } => Ok(None),
    }
}

pub fn socket_addr_to_target(addr: SocketAddr) -> TargetAddr {
    match addr {
        SocketAddr::V4(v4) => TargetAddr::IpV4(*v4.ip(), v4.port()),
        SocketAddr::V6(v6) => TargetAddr::IpV6(*v6.ip(), v6.port()),
    }
}

impl From<SocketAddr> for TargetAddr {
    fn from(addr: SocketAddr) -> Self {
        socket_addr_to_target(addr)
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

#[cfg(test)]
#[path = "tests/target.rs"]
mod tests;
