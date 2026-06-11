//! Shadowsocks-2022 header layouts (TCP request/response, UDP bodies).
//!
//! Pure framing only: callers AEAD-open ciphertext before parsing and seal
//! plaintext after building. The current time arrives as a parameter so the
//! server can feed its cached coarse clock and tests stay deterministic.

use thiserror::Error;

use crate::cipher::CipherKind;
use crate::target::{TargetAddr, TargetAddrError, parse_target_addr};

pub const SS2022_TCP_REQUEST_TYPE: u8 = 0;
pub const SS2022_TCP_RESPONSE_TYPE: u8 = 1;
pub const SS2022_UDP_CLIENT_TYPE: u8 = 0;
pub const SS2022_UDP_SERVER_TYPE: u8 = 1;
pub const SS2022_AEAD_TAG_LEN: usize = 16;
pub const SS2022_REQUEST_FIXED_HEADER_LEN: usize = 11;
pub const SS2022_REQUEST_FIXED_CIPHERTEXT_LEN: usize =
    SS2022_REQUEST_FIXED_HEADER_LEN + SS2022_AEAD_TAG_LEN;
pub const SS2022_UDP_SEPARATE_HEADER_LEN: usize = 16;
pub const SS2022_UDP_NONCE_LEN: usize = 12;
pub const SS2022_MAX_PADDING_LEN: usize = 900;
/// Maximum allowed clock skew for SS2022 timestamp validation (seconds).
pub const SS2022_MAX_TIME_DIFF_SECS: u64 = 30;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Ss2022HeaderError {
    #[error("invalid ss2022 header")]
    Invalid,
    #[error("ss2022 timestamp outside replay window: skew {skew_secs}s")]
    TimestampSkew { skew_secs: u64 },
    #[error("invalid ss2022 response header length: {0}")]
    InvalidResponseLength(usize),
    #[error("invalid ss2022 response header type: {0}")]
    InvalidResponseType(u8),
    #[error("ss2022 response header request salt mismatch")]
    RequestSaltMismatch,
    #[error(transparent)]
    Target(#[from] TargetAddrError),
}

/// Rejects timestamps outside ±[`SS2022_MAX_TIME_DIFF_SECS`] of `now` to
/// bound replay windows.
pub fn validate_timestamp(timestamp: u64, now_unix_secs: u64) -> Result<(), Ss2022HeaderError> {
    let skew_secs = now_unix_secs.abs_diff(timestamp);
    if skew_secs > SS2022_MAX_TIME_DIFF_SECS {
        return Err(Ss2022HeaderError::TimestampSkew { skew_secs });
    }
    Ok(())
}

/// Server half: validates the decrypted 11-byte fixed request header
/// (`type | timestamp | variable-header length`) and returns the declared
/// variable-header length.
pub fn validate_request_fixed_header(
    header: &[u8],
    now_unix_secs: u64,
) -> Result<usize, Ss2022HeaderError> {
    if header.len() != SS2022_REQUEST_FIXED_HEADER_LEN {
        return Err(Ss2022HeaderError::Invalid);
    }
    if header[0] != SS2022_TCP_REQUEST_TYPE {
        return Err(Ss2022HeaderError::Invalid);
    }
    let timestamp =
        u64::from_be_bytes(header[1..9].try_into().map_err(|_| Ss2022HeaderError::Invalid)?);
    validate_timestamp(timestamp, now_unix_secs)?;
    Ok(u16::from_be_bytes([header[9], header[10]]) as usize)
}

/// Decoded SS2022 variable request header: the target plus whatever initial
/// payload followed the padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ss2022Request<'a> {
    pub target: TargetAddr,
    pub payload: &'a [u8],
}

/// Server half: parses the decrypted variable request header
/// (`target | padding_len | padding | initial payload`). Per spec the
/// request must carry either padding or initial payload — a header with
/// neither is rejected.
pub fn parse_request_variable_header(
    header: &[u8],
) -> Result<Ss2022Request<'_>, Ss2022HeaderError> {
    let Some((target, consumed)) = parse_target_addr(header)? else {
        return Err(Ss2022HeaderError::Invalid);
    };
    if header.len() < consumed + 2 {
        return Err(Ss2022HeaderError::Invalid);
    }
    let padding_len = u16::from_be_bytes([header[consumed], header[consumed + 1]]) as usize;
    if padding_len > SS2022_MAX_PADDING_LEN {
        return Err(Ss2022HeaderError::Invalid);
    }
    if header.len() < consumed + 2 + padding_len {
        return Err(Ss2022HeaderError::Invalid);
    }

    let payload = &header[consumed + 2 + padding_len..];
    if padding_len == 0 && payload.is_empty() {
        return Err(Ss2022HeaderError::Invalid);
    }
    Ok(Ss2022Request { target, payload })
}

/// Client half: builds the plaintext fixed + variable request headers.
/// `padding` is caller-supplied random bytes (length goes on the wire).
pub fn build_request_header(
    target: &TargetAddr,
    now_unix_secs: u64,
    padding: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Ss2022HeaderError> {
    let target = target.to_wire_bytes()?;
    if padding.len() > SS2022_MAX_PADDING_LEN {
        return Err(Ss2022HeaderError::Invalid);
    }
    let variable_len = target.len() + 2 + padding.len();

    let mut fixed = Vec::with_capacity(SS2022_REQUEST_FIXED_HEADER_LEN);
    fixed.push(SS2022_TCP_REQUEST_TYPE);
    fixed.extend_from_slice(&now_unix_secs.to_be_bytes());
    fixed.extend_from_slice(&(variable_len as u16).to_be_bytes());

    let mut variable = Vec::with_capacity(variable_len);
    variable.extend_from_slice(&target);
    variable.extend_from_slice(&(padding.len() as u16).to_be_bytes());
    variable.extend_from_slice(padding);
    Ok((fixed, variable))
}

/// Client half: validates the decrypted response header
/// (`type | timestamp | request salt | first chunk length`) and returns the
/// declared first-chunk length.
pub fn parse_response_header(
    cipher: CipherKind,
    request_salt: &[u8],
    plaintext: &[u8],
    now_unix_secs: u64,
) -> Result<usize, Ss2022HeaderError> {
    let expected_len = 1 + 8 + cipher.salt_len() + 2;
    if plaintext.len() != expected_len {
        return Err(Ss2022HeaderError::InvalidResponseLength(plaintext.len()));
    }
    if plaintext[0] != SS2022_TCP_RESPONSE_TYPE {
        return Err(Ss2022HeaderError::InvalidResponseType(plaintext[0]));
    }
    let timestamp =
        u64::from_be_bytes(plaintext[1..9].try_into().map_err(|_| Ss2022HeaderError::Invalid)?);
    validate_timestamp(timestamp, now_unix_secs)?;

    let salt_end = 9 + cipher.salt_len();
    if &plaintext[9..salt_end] != request_salt {
        return Err(Ss2022HeaderError::RequestSaltMismatch);
    }
    Ok(u16::from_be_bytes([plaintext[salt_end], plaintext[salt_end + 1]]) as usize)
}

/// Server half: parses a decrypted AES-path UDP request body
/// (`type | timestamp | padding_len | padding | target | payload`; the
/// session/packet ids live in the separate header).
pub fn parse_udp_request_body(
    body: &[u8],
    now_unix_secs: u64,
) -> Result<Ss2022Request<'_>, Ss2022HeaderError> {
    if body.len() < 1 + 8 + 2 {
        return Err(Ss2022HeaderError::Invalid);
    }
    if body[0] != SS2022_UDP_CLIENT_TYPE {
        return Err(Ss2022HeaderError::Invalid);
    }
    let timestamp =
        u64::from_be_bytes(body[1..9].try_into().map_err(|_| Ss2022HeaderError::Invalid)?);
    validate_timestamp(timestamp, now_unix_secs)?;
    let padding_len = u16::from_be_bytes([body[9], body[10]]) as usize;
    let body = &body[11..];
    if body.len() < padding_len {
        return Err(Ss2022HeaderError::Invalid);
    }

    let body = &body[padding_len..];
    let Some((target, consumed)) = parse_target_addr(body)? else {
        return Err(Ss2022HeaderError::Invalid);
    };
    Ok(Ss2022Request { target, payload: &body[consumed..] })
}

/// Decoded ChaCha-path UDP request: ids ride in the plaintext, not in a
/// separate header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ss2022ChachaUdpRequest<'a> {
    pub target: TargetAddr,
    pub payload: &'a [u8],
    pub client_session_id: [u8; 8],
    pub packet_id: u64,
}

/// Server half: parses a decrypted ChaCha-path UDP request body
/// (`session_id | packet_id | type | timestamp | padding_len | padding |
/// target | payload`).
pub fn parse_chacha_udp_request_body(
    body: &[u8],
    now_unix_secs: u64,
) -> Result<Ss2022ChachaUdpRequest<'_>, Ss2022HeaderError> {
    if body.len() < 8 + 8 + 1 + 8 + 2 {
        return Err(Ss2022HeaderError::Invalid);
    }
    let client_session_id = body[..8].try_into().map_err(|_| Ss2022HeaderError::Invalid)?;
    let packet_id =
        u64::from_be_bytes(body[8..16].try_into().map_err(|_| Ss2022HeaderError::Invalid)?);
    let body = &body[16..];
    if body[0] != SS2022_UDP_CLIENT_TYPE {
        return Err(Ss2022HeaderError::Invalid);
    }
    let timestamp =
        u64::from_be_bytes(body[1..9].try_into().map_err(|_| Ss2022HeaderError::Invalid)?);
    validate_timestamp(timestamp, now_unix_secs)?;
    let padding_len = u16::from_be_bytes([body[9], body[10]]) as usize;
    let body = &body[11..];
    if body.len() < padding_len {
        return Err(Ss2022HeaderError::Invalid);
    }
    let body = &body[padding_len..];
    let Some((target, consumed)) = parse_target_addr(body)? else {
        return Err(Ss2022HeaderError::Invalid);
    };
    Ok(Ss2022ChachaUdpRequest {
        target,
        payload: &body[consumed..],
        client_session_id,
        packet_id,
    })
}

/// Extracts the 12-byte AEAD nonce from an AES-path UDP separate header
/// (bytes 4..16: the low half of the session id plus the packet id).
pub fn udp_nonce_from_separate_header(
    separate_header: &[u8],
) -> Result<[u8; SS2022_UDP_NONCE_LEN], Ss2022HeaderError> {
    if separate_header.len() != SS2022_UDP_SEPARATE_HEADER_LEN {
        return Err(Ss2022HeaderError::Invalid);
    }
    let mut nonce = [0_u8; SS2022_UDP_NONCE_LEN];
    nonce.copy_from_slice(&separate_header[4..16]);
    Ok(nonce)
}

#[cfg(test)]
#[path = "tests/ss2022.rs"]
mod tests;
