use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;

pub mod vless;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Socket(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn display_host_port(&self) -> String {
        match self {
            Self::Socket(addr) => addr.to_string(),
            Self::Domain(host, port) => format!("{host}:{port}"),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        match self {
            Self::Socket(SocketAddr::V4(addr)) => {
                let mut out = Vec::with_capacity(7);
                out.push(0x01);
                out.extend_from_slice(&addr.ip().octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
                Ok(out)
            },
            Self::Socket(SocketAddr::V6(addr)) => {
                let mut out = Vec::with_capacity(19);
                out.push(0x04);
                out.extend_from_slice(&addr.ip().octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
                Ok(out)
            },
            Self::Domain(host, port) => {
                let host_bytes = host.as_bytes();
                let len =
                    u8::try_from(host_bytes.len()).map_err(|_| ProtocolError::InvalidDomain)?;
                let mut out = Vec::with_capacity(1 + 1 + host_bytes.len() + 2);
                out.push(0x03);
                out.push(len);
                out.extend_from_slice(host_bytes);
                out.extend_from_slice(&port.to_be_bytes());
                Ok(out)
            },
        }
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("unsupported address type: {0:#x}")]
    UnsupportedAddressType(u8),
    #[error("invalid domain name")]
    InvalidDomain,
}

pub fn parse_target_addr(input: &[u8]) -> Result<Option<(TargetAddr, usize)>, ProtocolError> {
    let Some((&atyp, rest)) = input.split_first() else {
        return Ok(None);
    };

    match atyp {
        0x01 => {
            if rest.len() < 6 {
                return Ok(None);
            }
            let host = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            Ok(Some((TargetAddr::Socket(SocketAddr::from((host, port))), 7)))
        },
        0x03 => {
            let Some((&len, rest)) = rest.split_first() else {
                return Ok(None);
            };
            let len = len as usize;
            if rest.len() < len + 2 {
                return Ok(None);
            }
            let host =
                std::str::from_utf8(&rest[..len]).map_err(|_| ProtocolError::InvalidDomain)?;
            let port = u16::from_be_bytes([rest[len], rest[len + 1]]);
            Ok(Some((TargetAddr::Domain(host.to_owned(), port), 1 + 1 + len + 2)))
        },
        0x04 => {
            if rest.len() < 18 {
                return Ok(None);
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&rest[..16]);
            let host = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([rest[16], rest[17]]);
            Ok(Some((TargetAddr::Socket(SocketAddr::from((host, port))), 19)))
        },
        other => Err(ProtocolError::UnsupportedAddressType(other)),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{TargetAddr, parse_target_addr};

    #[test]
    fn parses_ipv4_target() {
        let bytes = [0x01, 127, 0, 0, 1, 0x1f, 0x90];
        let parsed = parse_target_addr(&bytes).unwrap();
        assert_eq!(
            parsed,
            Some((
                TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 8080))),
                bytes.len()
            ))
        );
    }

    #[test]
    fn parses_domain_target() {
        let bytes =
            [0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0, 80];
        let parsed = parse_target_addr(&bytes).unwrap();
        assert_eq!(parsed, Some((TargetAddr::Domain("example.com".into(), 80), bytes.len())));
    }

    #[test]
    fn returns_none_for_partial_address() {
        let bytes = [0x03, 0x0b, b'e', b'x'];
        let parsed = parse_target_addr(&bytes).unwrap();
        assert_eq!(parsed, None);
    }

    #[test]
    fn parses_ipv6_target() {
        let bytes = [0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb];
        let parsed = parse_target_addr(&bytes).unwrap();
        assert_eq!(
            parsed,
            Some((
                TargetAddr::Socket(SocketAddr::from((
                    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                    443
                ))),
                bytes.len()
            ))
        );
    }

    #[test]
    fn encodes_ipv6_target() {
        let target = TargetAddr::Socket(SocketAddr::from((
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            443,
        )));
        let encoded = target.encode().unwrap();

        assert_eq!(
            encoded,
            vec![0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb,]
        );
    }

    proptest::proptest! {
        // parse_target_addr must never panic on arbitrary byte input —
        // it only ever returns Ok(None), Ok(Some(..)), or Err.
        #[test]
        fn parse_target_addr_never_panics(input: Vec<u8>) {
            let _ = parse_target_addr(&input);
        }

        // Round-trip: encode() → parse_target_addr() must recover the original
        // address and report exactly the encoded length as consumed bytes.
        #[test]
        fn encode_parse_roundtrip_ipv4(ip: u32, port: u16) {
            let addr = TargetAddr::Socket(SocketAddr::from((Ipv4Addr::from(ip), port)));
            let bytes = addr.encode().unwrap();
            let (parsed, consumed) = parse_target_addr(&bytes).unwrap().unwrap();
            proptest::prop_assert_eq!(parsed, addr);
            proptest::prop_assert_eq!(consumed, bytes.len());
        }

        #[test]
        fn encode_parse_roundtrip_ipv6(octets: [u8; 16], port: u16) {
            let addr = TargetAddr::Socket(SocketAddr::from((Ipv6Addr::from(octets), port)));
            let bytes = addr.encode().unwrap();
            let (parsed, consumed) = parse_target_addr(&bytes).unwrap().unwrap();
            proptest::prop_assert_eq!(parsed, addr);
            proptest::prop_assert_eq!(consumed, bytes.len());
        }
    }
}
