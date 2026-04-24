use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{BufMut, BytesMut};
use thiserror::Error;

use super::TargetAddr;

pub const SESSION_STATUS_NEW: u8 = 0x01;
pub const SESSION_STATUS_KEEP: u8 = 0x02;
pub const SESSION_STATUS_END: u8 = 0x03;
pub const SESSION_STATUS_KEEPALIVE: u8 = 0x04;

pub const OPTION_DATA: u8 = 0x01;
pub const OPTION_ERROR: u8 = 0x02;

pub const NETWORK_TCP: u8 = 0x01;
pub const NETWORK_UDP: u8 = 0x02;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

pub const GLOBAL_ID_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    New,
    Keep,
    End,
    KeepAlive,
}

impl SessionStatus {
    fn from_u8(v: u8) -> Result<Self, MuxError> {
        match v {
            SESSION_STATUS_NEW => Ok(Self::New),
            SESSION_STATUS_KEEP => Ok(Self::Keep),
            SESSION_STATUS_END => Ok(Self::End),
            SESSION_STATUS_KEEPALIVE => Ok(Self::KeepAlive),
            other => Err(MuxError::UnknownStatus(other)),
        }
    }

    pub const fn as_u8(self) -> u8 {
        match self {
            Self::New => SESSION_STATUS_NEW,
            Self::Keep => SESSION_STATUS_KEEP,
            Self::End => SESSION_STATUS_END,
            Self::KeepAlive => SESSION_STATUS_KEEPALIVE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    fn from_nibble(v: u8) -> Result<Self, MuxError> {
        match v {
            NETWORK_TCP => Ok(Self::Tcp),
            NETWORK_UDP => Ok(Self::Udp),
            other => Err(MuxError::UnknownNetwork(other)),
        }
    }

    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Tcp => NETWORK_TCP,
            Self::Udp => NETWORK_UDP,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameMeta {
    pub session_id: u16,
    pub status: SessionStatus,
    pub option: u8,
    /// Present when `status == New` (the sub-connection target) or when a
    /// `Keep` frame carries an XUDP per-packet address override.
    pub target: Option<TargetAddr>,
    /// Present when `status == New` (the sub-connection network type).
    pub network: Option<Network>,
    /// Present when `status == New && network == Udp` (XUDP idempotency key).
    pub global_id: Option<[u8; GLOBAL_ID_LEN]>,
}

impl FrameMeta {
    pub const fn has_data(&self) -> bool {
        self.option & OPTION_DATA != 0
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MuxError {
    #[error("mux meta too short")]
    MetaTooShort,
    #[error("mux meta trailing bytes")]
    MetaTrailing,
    #[error("unknown mux session status: {0:#x}")]
    UnknownStatus(u8),
    #[error("unknown mux network: {0:#x}")]
    UnknownNetwork(u8),
    #[error("unknown mux address type: {0:#x}")]
    UnknownAddressType(u8),
    #[error("invalid mux domain")]
    InvalidDomain,
    #[error("mux data length exceeds maximum: {0}")]
    DataTooLarge(usize),
}

/// Maximum payload a single frame is allowed to carry. Matches xray-core's
/// 16 KiB ceiling on mux.cool payload frames.
pub const MAX_FRAME_DATA_SIZE: usize = 16 * 1024;

pub struct ParsedFrame<'a> {
    pub meta: FrameMeta,
    pub data: Option<&'a [u8]>,
    pub consumed: usize,
}

/// Attempt to parse one mux frame from the head of `input`.
/// Returns `Ok(None)` when the buffer does not yet contain a full frame.
pub fn parse_frame(input: &[u8]) -> Result<Option<ParsedFrame<'_>>, MuxError> {
    if input.len() < 2 {
        return Ok(None);
    }
    let meta_len = u16::from_be_bytes([input[0], input[1]]) as usize;
    if meta_len < 4 {
        return Err(MuxError::MetaTooShort);
    }
    if input.len() < 2 + meta_len {
        return Ok(None);
    }
    let meta_bytes = &input[2..2 + meta_len];
    let (meta, meta_consumed) = parse_meta(meta_bytes)?;
    if meta_consumed != meta_len {
        return Err(MuxError::MetaTrailing);
    }

    let mut cursor = 2 + meta_len;
    let data = if meta.has_data() {
        if input.len() < cursor + 2 {
            return Ok(None);
        }
        let data_len = u16::from_be_bytes([input[cursor], input[cursor + 1]]) as usize;
        if data_len > MAX_FRAME_DATA_SIZE {
            return Err(MuxError::DataTooLarge(data_len));
        }
        cursor += 2;
        if input.len() < cursor + data_len {
            return Ok(None);
        }
        let slice = &input[cursor..cursor + data_len];
        cursor += data_len;
        Some(slice)
    } else {
        None
    };

    Ok(Some(ParsedFrame { meta, data, consumed: cursor }))
}

fn parse_meta(meta: &[u8]) -> Result<(FrameMeta, usize), MuxError> {
    if meta.len() < 4 {
        return Err(MuxError::MetaTooShort);
    }
    let session_id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = SessionStatus::from_u8(meta[2])?;
    let option = meta[3];
    let mut cursor = 4;

    let mut target = None;
    let mut network = None;
    let mut global_id = None;

    match status {
        SessionStatus::New => {
            let (addr, net, used) = parse_target(&meta[cursor..])?;
            cursor += used;
            target = Some(addr);
            network = Some(net);
            if net == Network::Udp {
                if meta.len() < cursor + GLOBAL_ID_LEN {
                    return Err(MuxError::MetaTooShort);
                }
                let mut gid = [0_u8; GLOBAL_ID_LEN];
                gid.copy_from_slice(&meta[cursor..cursor + GLOBAL_ID_LEN]);
                cursor += GLOBAL_ID_LEN;
                global_id = Some(gid);
            }
        },
        SessionStatus::Keep => {
            if cursor < meta.len() {
                let (addr, _net, used) = parse_target(&meta[cursor..])?;
                cursor += used;
                target = Some(addr);
            }
        },
        SessionStatus::End | SessionStatus::KeepAlive => {},
    }

    Ok((FrameMeta { session_id, status, option, target, network, global_id }, cursor))
}

fn parse_target(input: &[u8]) -> Result<(TargetAddr, Network, usize), MuxError> {
    if input.len() < 3 {
        return Err(MuxError::MetaTooShort);
    }
    let port = u16::from_be_bytes([input[0], input[1]]);
    let type_byte = input[2];
    let net = Network::from_nibble(type_byte >> 4)?;
    let atyp = type_byte & 0x0F;
    let rest = &input[3..];
    let (addr, used) = match atyp {
        ATYP_IPV4 => {
            if rest.len() < 4 {
                return Err(MuxError::MetaTooShort);
            }
            let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            (TargetAddr::Socket(SocketAddr::from((ip, port))), 4)
        },
        ATYP_DOMAIN => {
            if rest.is_empty() {
                return Err(MuxError::MetaTooShort);
            }
            let len = rest[0] as usize;
            if rest.len() < 1 + len {
                return Err(MuxError::MetaTooShort);
            }
            let host = std::str::from_utf8(&rest[1..1 + len])
                .map_err(|_| MuxError::InvalidDomain)?;
            (TargetAddr::Domain(host.to_owned(), port), 1 + len)
        },
        ATYP_IPV6 => {
            if rest.len() < 16 {
                return Err(MuxError::MetaTooShort);
            }
            let mut oct = [0_u8; 16];
            oct.copy_from_slice(&rest[..16]);
            (TargetAddr::Socket(SocketAddr::from((Ipv6Addr::from(oct), port))), 16)
        },
        other => return Err(MuxError::UnknownAddressType(other)),
    };
    Ok((addr, net, 3 + used))
}

/// Encode a frame into `out`.
/// `target` is written into the meta when `status == New` (together with
/// `network`) or when the caller wants to emit an XUDP per-packet address
/// on a `Keep` frame (`network` is ignored in that case).
pub fn encode_frame(
    out: &mut BytesMut,
    session_id: u16,
    status: SessionStatus,
    option: u8,
    network: Option<Network>,
    target: Option<&TargetAddr>,
    data: Option<&[u8]>,
) {
    let mut meta = BytesMut::with_capacity(32);
    meta.put_u16(session_id);
    meta.put_u8(status.as_u8());
    meta.put_u8(option);

    match status {
        SessionStatus::New => {
            let net = network.expect("New frame requires network");
            let addr = target.expect("New frame requires target");
            write_target(&mut meta, addr, net);
        },
        SessionStatus::Keep => {
            if let Some(addr) = target {
                write_target(&mut meta, addr, network.unwrap_or(Network::Udp));
            }
        },
        SessionStatus::End | SessionStatus::KeepAlive => {},
    }

    out.put_u16(meta.len() as u16);
    out.extend_from_slice(&meta);

    if option & OPTION_DATA != 0
        && let Some(d) = data
    {
        out.put_u16(d.len() as u16);
        out.extend_from_slice(d);
    }
}

fn write_target(out: &mut BytesMut, addr: &TargetAddr, net: Network) {
    match addr {
        TargetAddr::Socket(SocketAddr::V4(a)) => {
            out.put_u16(a.port());
            out.put_u8((net.as_u8() << 4) | ATYP_IPV4);
            out.extend_from_slice(&a.ip().octets());
        },
        TargetAddr::Socket(SocketAddr::V6(a)) => {
            out.put_u16(a.port());
            out.put_u8((net.as_u8() << 4) | ATYP_IPV6);
            out.extend_from_slice(&a.ip().octets());
        },
        TargetAddr::Domain(host, port) => {
            out.put_u16(*port);
            out.put_u8((net.as_u8() << 4) | ATYP_DOMAIN);
            let bytes = host.as_bytes();
            // Caller is responsible for ensuring domain length fits in u8.
            out.put_u8(bytes.len().min(u8::MAX as usize) as u8);
            out.extend_from_slice(&bytes[..bytes.len().min(u8::MAX as usize)]);
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_target(a: u8, b: u8, c: u8, d: u8, port: u16) -> TargetAddr {
        TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(a, b, c, d), port)))
    }

    #[test]
    fn parses_new_tcp_frame() {
        let mut out = BytesMut::new();
        encode_frame(
            &mut out,
            7,
            SessionStatus::New,
            OPTION_DATA,
            Some(Network::Tcp),
            Some(&ipv4_target(1, 2, 3, 4, 80)),
            Some(b"hello"),
        );

        let parsed = parse_frame(&out).unwrap().unwrap();
        assert_eq!(parsed.meta.session_id, 7);
        assert_eq!(parsed.meta.status, SessionStatus::New);
        assert_eq!(parsed.meta.network, Some(Network::Tcp));
        assert_eq!(parsed.meta.target, Some(ipv4_target(1, 2, 3, 4, 80)));
        assert_eq!(parsed.meta.global_id, None);
        assert_eq!(parsed.data, Some(b"hello".as_ref()));
        assert_eq!(parsed.consumed, out.len());
    }

    #[test]
    fn parses_new_udp_with_global_id() {
        let mut out = BytesMut::new();
        let mut meta = BytesMut::new();
        meta.put_u16(3);
        meta.put_u8(SESSION_STATUS_NEW);
        meta.put_u8(OPTION_DATA);
        meta.put_u16(53);
        meta.put_u8((NETWORK_UDP << 4) | ATYP_IPV4);
        meta.extend_from_slice(&[1, 1, 1, 1]);
        meta.extend_from_slice(&[0xAA; GLOBAL_ID_LEN]);
        out.put_u16(meta.len() as u16);
        out.extend_from_slice(&meta);
        out.put_u16(4);
        out.extend_from_slice(b"ping");

        let parsed = parse_frame(&out).unwrap().unwrap();
        assert_eq!(parsed.meta.network, Some(Network::Udp));
        assert_eq!(parsed.meta.global_id, Some([0xAA; GLOBAL_ID_LEN]));
        assert_eq!(parsed.meta.target, Some(ipv4_target(1, 1, 1, 1, 53)));
        assert_eq!(parsed.data, Some(b"ping".as_ref()));
    }

    #[test]
    fn parses_keep_without_address() {
        let mut out = BytesMut::new();
        encode_frame(&mut out, 9, SessionStatus::Keep, OPTION_DATA, None, None, Some(b"abc"));

        let parsed = parse_frame(&out).unwrap().unwrap();
        assert_eq!(parsed.meta.status, SessionStatus::Keep);
        assert_eq!(parsed.meta.target, None);
        assert_eq!(parsed.data, Some(b"abc".as_ref()));
    }

    #[test]
    fn parses_keep_with_xudp_address() {
        let mut out = BytesMut::new();
        encode_frame(
            &mut out,
            4,
            SessionStatus::Keep,
            OPTION_DATA,
            Some(Network::Udp),
            Some(&ipv4_target(8, 8, 8, 8, 53)),
            Some(b"q"),
        );

        let parsed = parse_frame(&out).unwrap().unwrap();
        assert_eq!(parsed.meta.target, Some(ipv4_target(8, 8, 8, 8, 53)));
        assert_eq!(parsed.data, Some(b"q".as_ref()));
    }

    #[test]
    fn parses_end_frame_without_data() {
        let mut out = BytesMut::new();
        encode_frame(&mut out, 12, SessionStatus::End, 0, None, None, None);

        let parsed = parse_frame(&out).unwrap().unwrap();
        assert_eq!(parsed.meta.status, SessionStatus::End);
        assert_eq!(parsed.data, None);
        assert_eq!(parsed.consumed, out.len());
    }

    #[test]
    fn returns_none_for_partial() {
        let input = [0x00, 0x04, 0x00, 0x01];
        assert!(parse_frame(&input).unwrap().is_none());
    }

    #[test]
    fn returns_none_for_partial_data() {
        let mut out = BytesMut::new();
        encode_frame(
            &mut out,
            1,
            SessionStatus::Keep,
            OPTION_DATA,
            None,
            None,
            Some(b"abcdef"),
        );
        let truncated = &out[..out.len() - 2];
        assert!(parse_frame(truncated).unwrap().is_none());
    }

    #[test]
    fn rejects_short_meta() {
        let input = [0x00, 0x00];
        assert!(matches!(parse_frame(&input), Err(MuxError::MetaTooShort)));
    }

    #[test]
    fn parses_domain_target() {
        let mut out = BytesMut::new();
        let addr = TargetAddr::Domain("example.com".to_owned(), 443);
        encode_frame(
            &mut out,
            2,
            SessionStatus::New,
            OPTION_DATA,
            Some(Network::Tcp),
            Some(&addr),
            Some(b"."),
        );
        let parsed = parse_frame(&out).unwrap().unwrap();
        assert_eq!(parsed.meta.target, Some(addr));
    }
}
