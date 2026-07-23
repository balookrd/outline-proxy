//! VLESS request/response header layouts, Addons TLV codec and UUID helpers.
//!
//! VLESS uses its own ATYP numbering (`0x01` IPv4, `0x02` domain, `0x03`
//! IPv6) — distinct from the SOCKS5 shape in [`crate::target`].

use thiserror::Error;

use crate::target::TargetAddr;

pub const VERSION: u8 = 0x00;
pub const COMMAND_TCP: u8 = 0x01;
pub const COMMAND_UDP: u8 = 0x02;
pub const COMMAND_MUX: u8 = 0x03;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x02;
pub const ATYP_IPV6: u8 = 0x03;

// ── Resumption Addons opcodes ────────────────────────────────────────────────
//
// The negotiation rides inside the VLESS request / response Addons section
// (the `opt_len`-prefixed TLV block immediately after the user UUID) when no
// HTTP headers are available — that is, on raw QUIC. Tags chosen to mirror
// the spec table in `docs/SESSION-RESUMPTION.md`. Standard VLESS clients
// (sing-box, v2ray-core) parse `opt_len` and walk past unknown opcodes, so
// the addition is wire-compatible with everything that does not actively
// care about resumption.

/// Request opcode: client advertises that it supports resumption and would
/// like the server to mint a Session ID. Length 1, value `0x01`.
pub const ADDON_TAG_RESUME_CAPABLE: u8 = 0x10;
/// Request opcode: client asks the server to resume a previously-parked
/// session. Length 16, value = the Session ID bytes the server returned
/// earlier.
pub const ADDON_TAG_RESUME_ID: u8 = 0x11;
/// Response opcode: the Session ID the server has assigned to the
/// just-established session (either freshly minted or echoed on a hit).
/// Length 16.
pub const ADDON_TAG_SESSION_ID: u8 = 0x10;
/// Response opcode: outcome of a resume attempt. Length 1, value
/// `0x00` hit / `0x01` miss-expired / `0x02` miss-unknown / `0x03` miss-owner /
/// `0x04` miss-capacity. Externally `miss-owner` is squashed to `miss-unknown`
/// to avoid an existence oracle.
pub const ADDON_TAG_RESUME_RESULT: u8 = 0x11;

/// Wire-level outcome of a resume attempt. Values match the encoding of
/// [`ADDON_TAG_RESUME_RESULT`] so callers can plumb the same byte from
/// the registry's `ResumeMiss` to the response addon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddonResumeResult {
    Hit = 0x00,
    MissUnknown = 0x02,
}

impl AddonResumeResult {
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    Tcp,
    Udp,
    Mux,
}

/// Decoded resumption-related opcodes from a VLESS request's Addons
/// section. Defaults to "no opt-in advertised, no resume requested" so
/// any path that ignores resumption keeps the same semantics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VlessRequestAddons {
    /// Client advertised `RESUME_CAPABLE` (tag `0x10`, value `0x01`).
    pub resume_capable: bool,
    /// Client requested resumption of the named Session ID (tag `0x11`,
    /// value 16 bytes). `None` when the opcode is absent.
    pub resume_id: Option<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessRequest {
    pub user_id: [u8; 16],
    pub command: VlessCommand,
    pub target: TargetAddr,
    pub consumed: usize,
    /// Resumption-related opcodes parsed from the Addons block.
    /// Empty for clients that do not advertise resumption — those see
    /// the same wire behaviour as before.
    pub addons: VlessRequestAddons,
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
    #[error("vless domain too long: {0} bytes")]
    DomainTooLong(usize),
    #[error("vless addons block too long: {0} bytes")]
    AddonsTooLong(usize),
}

/// Server half: parse a client request header. `Ok(None)` means the buffer
/// does not yet hold a complete header — read more bytes and retry.
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
    // Need the Addons block plus the command byte before we can decide
    // how the rest of the header is shaped (Mux carries no address).
    if input.len() < command_offset + 1 {
        return Ok(None);
    }

    // Walk the Addons block. Unknown tags are skipped (forward-compat
    // with future opcodes); the only failure mode is a length field
    // that runs past the declared `opt_len`, in which case we treat
    // the block as truncated and ask for more bytes.
    let addons = parse_request_addons(&input[18..18 + opt_len]);

    let command = match input[command_offset] {
        COMMAND_TCP => VlessCommand::Tcp,
        COMMAND_UDP => VlessCommand::Udp,
        COMMAND_MUX => VlessCommand::Mux,
        other => return Err(VlessError::UnsupportedCommand(other)),
    };

    // The Mux carrier (mux.cool / XUDP) has no per-carrier destination:
    // both Xray-core and sing-box write `version | uuid | addons |
    // command` and then start the mux frame stream immediately, skipping
    // the port+atyp+address that TCP/UDP requests carry. The sub-stream
    // targets travel inside each mux frame, so there is nothing to parse
    // here — emit a placeholder target the Mux handler ignores and hand
    // the remaining bytes (the first mux frame) back via `consumed`.
    if command == VlessCommand::Mux {
        return Ok(Some(VlessRequest {
            user_id,
            command,
            target: TargetAddr::IpV4(std::net::Ipv4Addr::UNSPECIFIED, 0),
            consumed: command_offset + 1,
            addons,
        }));
    }

    let port_offset = command_offset + 1;
    if input.len() < port_offset + 2 + 1 {
        return Ok(None);
    }
    let port = u16::from_be_bytes([input[port_offset], input[port_offset + 1]]);
    let atyp_offset = port_offset + 2;
    let atyp = input[atyp_offset];
    let addr_offset = atyp_offset + 1;

    let (target, consumed) = match atyp {
        ATYP_IPV4 => {
            if input.len() < addr_offset + 4 {
                return Ok(None);
            }
            let host = std::net::Ipv4Addr::new(
                input[addr_offset],
                input[addr_offset + 1],
                input[addr_offset + 2],
                input[addr_offset + 3],
            );
            (TargetAddr::IpV4(host, port), addr_offset + 4)
        },
        ATYP_DOMAIN => {
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
        ATYP_IPV6 => {
            if input.len() < addr_offset + 16 {
                return Ok(None);
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&input[addr_offset..addr_offset + 16]);
            (TargetAddr::IpV6(std::net::Ipv6Addr::from(octets), port), addr_offset + 16)
        },
        other => return Err(VlessError::UnsupportedAddressType(other)),
    };

    Ok(Some(VlessRequest {
        user_id,
        command,
        target,
        consumed,
        addons,
    }))
}

/// Walks a VLESS request Addons TLV block and pulls out the
/// resumption-related opcodes. Unknown tags are silently skipped
/// (forward-compat with future VLESS additions).
fn parse_request_addons(block: &[u8]) -> VlessRequestAddons {
    let mut addons = VlessRequestAddons::default();
    let mut i = 0;
    while i + 2 <= block.len() {
        let tag = block[i];
        let len = block[i + 1] as usize;
        let value_start = i + 2;
        let value_end = value_start + len;
        if value_end > block.len() {
            break; // Truncated TLV — ignore the trailing bytes.
        }
        let value = &block[value_start..value_end];
        match tag {
            ADDON_TAG_RESUME_CAPABLE => {
                addons.resume_capable = value == [0x01];
            },
            ADDON_TAG_RESUME_ID => {
                if let Ok(arr) = <[u8; 16]>::try_from(value) {
                    addons.resume_id = Some(arr);
                }
            },
            _ => {},
        }
        i = value_end;
    }
    addons
}

/// Client half: encodes the request Addons block advertising resumption
/// support and/or requesting a resume. Returns the raw block bytes (no
/// length prefix).
pub fn encode_request_addons(resume_capable: bool, resume_id: Option<&[u8; 16]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        if resume_capable { 3 } else { 0 } + if resume_id.is_some() { 18 } else { 0 },
    );
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

/// Server half: encodes a VLESS response Addons block carrying the
/// `SESSION_ID` and `RESUME_RESULT` opcodes. Either may be `None`,
/// in which case it is omitted. Returns the raw block bytes (no
/// length prefix); callers prepend `addons.len() as u8` when
/// writing into a response header.
pub fn encode_response_addons(
    session_id: Option<&[u8; 16]>,
    resume_result: Option<AddonResumeResult>,
) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(id) = session_id {
        out.push(ADDON_TAG_SESSION_ID);
        out.push(16);
        out.extend_from_slice(id);
    }
    if let Some(result) = resume_result {
        out.push(ADDON_TAG_RESUME_RESULT);
        out.push(1);
        out.push(result.as_byte());
    }
    out
}

/// Client half: walks a server response Addons block and pulls out the
/// assigned `SESSION_ID` opcode (`0x10`, length 16). Returns `None` if the
/// block is empty / unknown tags only / a feature-disabled server emitted
/// the legacy zero-length Addons. The `RESUME_RESULT` opcode is recognised
/// but currently discarded — callers infer hit/miss from observable
/// side-effects.
pub fn parse_response_addons_session_id(block: &[u8]) -> Option<[u8; 16]> {
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
            return Some(arr);
        }
        i = value_end;
    }
    None
}

/// Client half: builds a request header (`version | uuid | addons | command
/// | port | atyp | address`) in the VLESS ATYP numbering. The `port | atyp |
/// address` tail is omitted for the Mux command, which carries no per-carrier
/// destination (matching Xray-core and sing-box, and the parser above).
///
/// Both the Addons block and the domain ride behind a `u8` length, so either
/// one past 255 bytes is rejected rather than truncated into a header the
/// peer would parse as garbage — same contract as
/// [`TargetAddr::to_wire_bytes`](crate::target::TargetAddr::to_wire_bytes).
pub fn build_request_header(
    uuid: &[u8; 16],
    command: u8,
    target: &TargetAddr,
    addons: &[u8],
) -> Result<Vec<u8>, VlessError> {
    let addons_len: u8 = addons
        .len()
        .try_into()
        .map_err(|_| VlessError::AddonsTooLong(addons.len()))?;

    let mut out = Vec::with_capacity(1 + 16 + 1 + addons.len() + 1 + 2 + 1 + 256);
    out.push(VERSION);
    out.extend_from_slice(uuid);
    out.push(addons_len);
    out.extend_from_slice(addons);
    out.push(command);
    if command == COMMAND_MUX {
        return Ok(out);
    }
    match target {
        TargetAddr::IpV4(addr, port) => {
            out.extend_from_slice(&port.to_be_bytes());
            out.push(ATYP_IPV4);
            out.extend_from_slice(&addr.octets());
        },
        TargetAddr::IpV6(addr, port) => {
            out.extend_from_slice(&port.to_be_bytes());
            out.push(ATYP_IPV6);
            out.extend_from_slice(&addr.octets());
        },
        TargetAddr::Domain(host, port) => {
            let host_len: u8 = host
                .len()
                .try_into()
                .map_err(|_| VlessError::DomainTooLong(host.len()))?;
            out.extend_from_slice(&port.to_be_bytes());
            out.push(ATYP_DOMAIN);
            out.push(host_len);
            out.extend_from_slice(host.as_bytes());
        },
    }
    Ok(out)
}

/// Parse a VLESS UUID in hex/dashed form into 16 raw bytes.
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

/// `{first_4_hex}-...` — enough to correlate logs without exposing the key.
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
#[path = "tests/vless.rs"]
mod tests;
