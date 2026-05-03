//! VLESS protocol constants + request/response header (de)serialization.

use socks5_proto::TargetAddr;

use crate::resumption::SessionId;

pub(super) const VLESS_VERSION: u8 = 0x00;
pub(super) const VLESS_CMD_TCP: u8 = 0x01;
pub(super) const VLESS_CMD_UDP: u8 = 0x02;

/// VLESS Addons opcode: client advertises resumption support.
/// Length 1, value `0x01`.
const ADDON_TAG_RESUME_CAPABLE: u8 = 0x10;
/// VLESS Addons opcode: client requests resumption of the named
/// Session ID. Length 16.
const ADDON_TAG_RESUME_ID: u8 = 0x11;
/// Server response opcode: assigned Session ID. Length 16. Tag is the
/// same as `RESUME_CAPABLE` but lives in the response Addons block,
/// per docs/SESSION-RESUMPTION.md.
const ADDON_TAG_SESSION_ID: u8 = 0x10;
pub(super) const VLESS_ATYP_IPV4: u8 = 0x01;
pub(super) const VLESS_ATYP_DOMAIN: u8 = 0x02;
pub(super) const VLESS_ATYP_IPV6: u8 = 0x03;

pub(super) const MAX_VLESS_UDP_PAYLOAD: usize = 64 * 1024;

/// Build the standard VLESS UDP request header. Exposed so transports
/// that bypass the WebSocket layer (raw QUIC) can write it directly to
/// the underlying control stream.
pub fn build_vless_udp_request_header(uuid: &[u8; 16], target: &TargetAddr) -> Vec<u8> {
    build_request_header(uuid, VLESS_CMD_UDP, target, &[])
}

/// Build the standard VLESS TCP request header. Same exposure rationale.
pub fn build_vless_tcp_request_header(uuid: &[u8; 16], target: &TargetAddr) -> Vec<u8> {
    build_request_header(uuid, VLESS_CMD_TCP, target, &[])
}

/// Build a VLESS TCP request header with the resumption Addons opcodes
/// populated. `resume_capable=true` advertises support so a feature-
/// enabled server mints a Session ID; `resume_id` (when set) asks the
/// server to re-attach a parked upstream. Used by the raw-QUIC client
/// path; WS-based callers get the same result via the
/// `X-Outline-*` HTTP headers.
pub fn build_vless_tcp_request_header_with_resume(
    uuid: &[u8; 16],
    target: &TargetAddr,
    resume_capable: bool,
    resume_id: Option<&[u8; 16]>,
) -> Vec<u8> {
    let addons = encode_request_addons(resume_capable, resume_id);
    build_request_header(uuid, VLESS_CMD_TCP, target, &addons)
}

fn encode_request_addons(resume_capable: bool, resume_id: Option<&[u8; 16]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(if resume_capable { 3 } else { 0 } + if resume_id.is_some() { 18 } else { 0 });
    if resume_capable {
        out.push(ADDON_TAG_RESUME_CAPABLE);
        out.push(1);
        out.push(0x01);
    }
    if let Some(id) = resume_id {
        out.push(ADDON_TAG_RESUME_ID);
        out.push(16);
        out.extend_from_slice(id);
    }
    out
}

/// Walk a server response Addons block and pull out the assigned
/// `SESSION_ID` opcode (`0x10`, length 16). Returns `None` if the
/// block is empty / unknown tags only / a feature-disabled server
/// emitted the legacy zero-length Addons. The `RESUME_RESULT` opcode
/// is recognised but currently discarded — callers infer hit/miss
/// from observable side-effects (counter on the upstream target).
pub(super) fn parse_response_addons_session_id(block: &[u8]) -> Option<SessionId> {
    let mut i = 0;
    while i + 2 <= block.len() {
        let tag = block[i];
        let len = block[i + 1] as usize;
        let value_start = i + 2;
        let value_end = value_start + len;
        if value_end > block.len() {
            return None;
        }
        let value = &block[value_start..value_end];
        if tag == ADDON_TAG_SESSION_ID
            && let Ok(arr) = <[u8; 16]>::try_from(value)
        {
            return Some(SessionId::from_bytes(arr));
        }
        i = value_end;
    }
    None
}

pub(super) fn build_request_header(
    uuid: &[u8; 16],
    command: u8,
    target: &TargetAddr,
    addons: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 1 + addons.len() + 1 + 2 + 1 + 256);
    out.push(VLESS_VERSION);
    out.extend_from_slice(uuid);
    out.push(addons.len() as u8); // addons_len
    out.extend_from_slice(addons);
    out.push(command);
    match target {
        TargetAddr::IpV4(addr, port) => {
            out.extend_from_slice(&port.to_be_bytes());
            out.push(VLESS_ATYP_IPV4);
            out.extend_from_slice(&addr.octets());
        },
        TargetAddr::IpV6(addr, port) => {
            out.extend_from_slice(&port.to_be_bytes());
            out.push(VLESS_ATYP_IPV6);
            out.extend_from_slice(&addr.octets());
        },
        TargetAddr::Domain(host, port) => {
            out.extend_from_slice(&port.to_be_bytes());
            out.push(VLESS_ATYP_DOMAIN);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        },
    }
    out
}
