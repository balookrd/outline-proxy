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

#[derive(Debug, Clone)]
pub struct VlessUser {
    id: [u8; 16],
    label: Arc<str>,
    fwmark: Option<u32>,
}

impl VlessUser {
    /// Build a VLESS user from its UUID and the human-readable account
    /// label coming from `config.users[].id` (e.g. `alice-mom`,
    /// `aeza`). The label is what surfaces in `user="..."` Prometheus
    /// labels — using the masked UUID instead pollutes the dashboard's
    /// `User` template variable with two parallel namespaces (raw IDs
    /// for SS, masked UUIDs for VLESS) that can't be cross-referenced.
    pub fn new(id: String, label: Arc<str>, fwmark: Option<u32>) -> Result<Self, VlessError> {
        let parsed = parse_uuid(&id)?;
        Ok(Self { id: parsed, label, fwmark })
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

/// Encodes a VLESS response Addons block carrying the
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
#[path = "tests/vless.rs"]
mod tests;
