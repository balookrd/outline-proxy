//! VLESS protocol constants + request/response header (de)serialization.
//!
//! The wire layout itself lives in `outline-wire` (shared with the server);
//! this module keeps the historical client-facing names and wraps the
//! response-addons walk into the transport's [`SessionId`] type.

use anyhow::Result;
use socks5_proto::TargetAddr;

use crate::resumption::SessionId;

pub(super) use outline_wire::vless::build_request_header;
#[cfg(test)]
pub(super) use outline_wire::vless::{
    ATYP_DOMAIN as VLESS_ATYP_DOMAIN, ATYP_IPV4 as VLESS_ATYP_IPV4,
};
pub(super) use outline_wire::vless::{
    COMMAND_TCP as VLESS_CMD_TCP, COMMAND_UDP as VLESS_CMD_UDP, VERSION as VLESS_VERSION,
};

pub(super) const MAX_VLESS_UDP_PAYLOAD: usize = 64 * 1024;

/// Build the standard VLESS UDP request header. Exposed so transports
/// that bypass the WebSocket layer (raw QUIC) can write it directly to
/// the underlying control stream. Fails on a target whose domain does not
/// fit the header's `u8` length prefix.
pub fn build_vless_udp_request_header(uuid: &[u8; 16], target: &TargetAddr) -> Result<Vec<u8>> {
    build_request_header(uuid, VLESS_CMD_UDP, target, &[]).map_err(Into::into)
}

/// Build the standard VLESS TCP request header. Same exposure rationale.
pub fn build_vless_tcp_request_header(uuid: &[u8; 16], target: &TargetAddr) -> Result<Vec<u8>> {
    build_request_header(uuid, VLESS_CMD_TCP, target, &[]).map_err(Into::into)
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
) -> Result<Vec<u8>> {
    let addons = outline_wire::vless::encode_request_addons(resume_capable, resume_id);
    build_request_header(uuid, VLESS_CMD_TCP, target, &addons).map_err(Into::into)
}

/// Walk a server response Addons block and pull out the assigned
/// `SESSION_ID` opcode (`0x10`, length 16). Returns `None` if the
/// block is empty / unknown tags only / a feature-disabled server
/// emitted the legacy zero-length Addons. The `RESUME_RESULT` opcode
/// is recognised but currently discarded — callers infer hit/miss
/// from observable side-effects (counter on the upstream target).
pub(super) fn parse_response_addons_session_id(block: &[u8]) -> Option<SessionId> {
    outline_wire::vless::parse_response_addons_session_id(block).map(SessionId::from_bytes)
}
