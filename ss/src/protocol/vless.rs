use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use thiserror::Error;

use super::TargetAddr;

pub const VERSION: u8 = 0x00;
pub const COMMAND_TCP: u8 = 0x01;
pub const COMMAND_UDP: u8 = 0x02;
pub const COMMAND_MUX: u8 = 0x03;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    Tcp,
    Udp,
    Mux,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessRequest {
    pub user_id: [u8; 16],
    pub command: VlessCommand,
    pub target: TargetAddr,
    pub consumed: usize,
}

#[derive(Debug, Clone)]
pub struct VlessUser {
    id: [u8; 16],
    label: Arc<str>,
    fwmark: Option<u32>,
}

impl VlessUser {
    pub fn new(id: String, fwmark: Option<u32>) -> Result<Self, VlessError> {
        let parsed = parse_uuid(&id)?;
        Ok(Self {
            id: parsed,
            label: Arc::from(mask_uuid(&parsed)),
            fwmark,
        })
    }

    pub const fn id_bytes(&self) -> &[u8; 16] {
        &self.id
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn label_arc(&self) -> Arc<str> {
        Arc::clone(&self.label)
    }

    pub const fn fwmark(&self) -> Option<u32> {
        self.fwmark
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VlessError {
    #[error("invalid vless version: {0:#x}")]
    InvalidVersion(u8),
    #[error("unsupported vless command: {0:#x}")]
    UnsupportedCommand(u8),
    #[error("unsupported vless address type: {0:#x}")]
    UnsupportedAddressType(u8),
    #[error("invalid vless domain name")]
    InvalidDomain,
    #[error("invalid vless uuid")]
    InvalidUuid,
}

pub fn parse_request(input: &[u8]) -> Result<Option<VlessRequest>, VlessError> {
    if input.len() < 1 + 16 + 1 {
        return Ok(None);
    }
    let version = input[0];
    if version != VERSION {
        return Err(VlessError::InvalidVersion(version));
    }

    let mut user_id = [0_u8; 16];
    user_id.copy_from_slice(&input[1..17]);

    let opt_len = input[17] as usize;
    let command_offset = 18 + opt_len;
    if input.len() < command_offset + 1 + 2 + 1 {
        return Ok(None);
    }

    let command = match input[command_offset] {
        COMMAND_TCP => VlessCommand::Tcp,
        COMMAND_UDP => VlessCommand::Udp,
        COMMAND_MUX => VlessCommand::Mux,
        other => return Err(VlessError::UnsupportedCommand(other)),
    };

    let port_offset = command_offset + 1;
    let port = u16::from_be_bytes([input[port_offset], input[port_offset + 1]]);
    let atyp_offset = port_offset + 2;
    let atyp = input[atyp_offset];
    let addr_offset = atyp_offset + 1;

    let (target, consumed) = match atyp {
        0x01 => {
            if input.len() < addr_offset + 4 {
                return Ok(None);
            }
            let host = Ipv4Addr::new(
                input[addr_offset],
                input[addr_offset + 1],
                input[addr_offset + 2],
                input[addr_offset + 3],
            );
            (TargetAddr::Socket(SocketAddr::from((host, port))), addr_offset + 4)
        },
        0x02 => {
            if input.len() < addr_offset + 1 {
                return Ok(None);
            }
            let len = input[addr_offset] as usize;
            let domain_offset = addr_offset + 1;
            if input.len() < domain_offset + len {
                return Ok(None);
            }
            let host = std::str::from_utf8(&input[domain_offset..domain_offset + len])
                .map_err(|_| VlessError::InvalidDomain)?;
            (TargetAddr::Domain(host.to_owned(), port), domain_offset + len)
        },
        0x03 => {
            if input.len() < addr_offset + 16 {
                return Ok(None);
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&input[addr_offset..addr_offset + 16]);
            (
                TargetAddr::Socket(SocketAddr::from((Ipv6Addr::from(octets), port))),
                addr_offset + 16,
            )
        },
        other => return Err(VlessError::UnsupportedAddressType(other)),
    };

    Ok(Some(VlessRequest { user_id, command, target, consumed }))
}

pub fn find_user<'a>(users: &'a [VlessUser], user_id: &[u8; 16]) -> Option<&'a VlessUser> {
    users.iter().find(|user| user.id_bytes() == user_id)
}

pub fn parse_uuid(input: &str) -> Result<[u8; 16], VlessError> {
    let mut hex = [0_u8; 32];
    let mut len = 0;
    for byte in input.bytes() {
        if byte == b'-' {
            continue;
        }
        if len == hex.len() || !byte.is_ascii_hexdigit() {
            return Err(VlessError::InvalidUuid);
        }
        hex[len] = byte;
        len += 1;
    }
    if len != hex.len() {
        return Err(VlessError::InvalidUuid);
    }

    let mut out = [0_u8; 16];
    for i in 0..16 {
        out[i] = (hex_value(hex[i * 2])? << 4) | hex_value(hex[i * 2 + 1])?;
    }
    Ok(out)
}

pub fn mask_uuid(id: &[u8; 16]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}-...", id[0], id[1], id[2], id[3])
}

fn hex_value(byte: u8) -> Result<u8, VlessError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(VlessError::InvalidUuid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn request_prefix(command: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(VERSION);
        bytes.extend_from_slice(&parse_uuid(UUID).unwrap());
        bytes.push(0);
        bytes.push(command);
        bytes
    }

    #[test]
    fn parse_vless_ipv4_tcp_request() {
        let mut bytes = request_prefix(COMMAND_TCP);
        bytes.extend_from_slice(&443_u16.to_be_bytes());
        bytes.push(0x01);
        bytes.extend_from_slice(&[127, 0, 0, 1]);

        let parsed = parse_request(&bytes).unwrap().unwrap();
        assert_eq!(parsed.user_id, parse_uuid(UUID).unwrap());
        assert_eq!(
            parsed.target,
            TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 443)))
        );
        assert_eq!(parsed.consumed, bytes.len());
    }

    #[test]
    fn parse_vless_domain_tcp_request() {
        let mut bytes = request_prefix(COMMAND_TCP);
        bytes.extend_from_slice(&80_u16.to_be_bytes());
        bytes.push(0x02);
        bytes.push(11);
        bytes.extend_from_slice(b"example.com");

        let parsed = parse_request(&bytes).unwrap().unwrap();
        assert_eq!(parsed.target, TargetAddr::Domain("example.com".to_owned(), 80));
        assert_eq!(parsed.consumed, bytes.len());
    }

    #[test]
    fn parse_vless_ipv6_tcp_request() {
        let mut bytes = request_prefix(COMMAND_TCP);
        bytes.extend_from_slice(&8443_u16.to_be_bytes());
        bytes.push(0x03);
        let ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        bytes.extend_from_slice(&ip.octets());

        let parsed = parse_request(&bytes).unwrap().unwrap();
        assert_eq!(parsed.target, TargetAddr::Socket(SocketAddr::from((ip, 8443))));
        assert_eq!(parsed.consumed, bytes.len());
    }

    #[test]
    fn reject_unknown_uuid() {
        let known = VlessUser::new(UUID.to_owned(), None).unwrap();
        let unknown = parse_uuid("650e8400-e29b-41d4-a716-446655440000").unwrap();
        assert!(find_user(&[known], &unknown).is_none());
    }

    #[test]
    fn parse_vless_udp_request() {
        let mut bytes = request_prefix(COMMAND_UDP);
        bytes.extend_from_slice(&53_u16.to_be_bytes());
        bytes.push(0x01);
        bytes.extend_from_slice(&[1, 1, 1, 1]);

        let parsed = parse_request(&bytes).unwrap().unwrap();
        assert_eq!(parsed.command, VlessCommand::Udp);
        assert_eq!(
            parsed.target,
            TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)))
        );
        assert_eq!(parsed.consumed, bytes.len());
    }

    #[test]
    fn reject_unknown_command() {
        let mut bytes = request_prefix(0x04);
        bytes.extend_from_slice(&53_u16.to_be_bytes());
        bytes.push(0x01);
        bytes.extend_from_slice(&[1, 1, 1, 1]);

        assert_eq!(parse_request(&bytes).unwrap_err(), VlessError::UnsupportedCommand(0x04));
    }

    #[test]
    fn parse_vless_mux_request() {
        let mut bytes = request_prefix(COMMAND_MUX);
        bytes.extend_from_slice(&666_u16.to_be_bytes());
        bytes.push(0x02);
        let domain = b"v1.mux.cool";
        bytes.push(domain.len() as u8);
        bytes.extend_from_slice(domain);

        let parsed = parse_request(&bytes).unwrap().unwrap();
        assert_eq!(parsed.command, VlessCommand::Mux);
        assert_eq!(parsed.consumed, bytes.len());
    }

    #[test]
    fn reject_invalid_version() {
        let mut bytes = request_prefix(COMMAND_TCP);
        bytes[0] = 0x01;
        bytes.extend_from_slice(&443_u16.to_be_bytes());
        bytes.push(0x01);
        bytes.extend_from_slice(&[127, 0, 0, 1]);

        assert_eq!(parse_request(&bytes).unwrap_err(), VlessError::InvalidVersion(0x01));
    }
}
