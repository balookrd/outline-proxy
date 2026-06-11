use ring::aead::Nonce;

use super::{error::CryptoError, primitives::NONCE_LEN};
use crate::{clock, protocol::parse_target_addr};

pub(super) const SS2022_TCP_REQUEST_TYPE: u8 = 0;
pub(super) const SS2022_TCP_RESPONSE_TYPE: u8 = 1;
pub(super) const SS2022_UDP_CLIENT_TYPE: u8 = 0;
pub(super) const SS2022_UDP_SERVER_TYPE: u8 = 1;
pub(super) const SS2022_REQUEST_FIXED_HEADER_LEN: usize = 11;
pub(super) const SS2022_REQUEST_FIXED_CIPHERTEXT_LEN: usize =
    SS2022_REQUEST_FIXED_HEADER_LEN + super::primitives::TAG_LEN;
pub(super) const SS2022_UDP_SEPARATE_HEADER_LEN: usize = 16;
pub(super) const SS2022_MAX_PADDING_LEN: usize = 900;
pub(super) const SS2022_MAX_TIME_DIFF_SECS: u64 = 30;

#[inline]
pub(super) fn ss2022_udp_nonce(separate_header: &[u8]) -> Result<Nonce, CryptoError> {
    if separate_header.len() != SS2022_UDP_SEPARATE_HEADER_LEN {
        return Err(CryptoError::InvalidHeader);
    }
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(&separate_header[4..16]);
    Ok(Nonce::assume_unique_for_key(nonce))
}

fn validate_timestamp(timestamp: u64) -> Result<(), CryptoError> {
    let now = clock::current_unix_secs();
    if now.abs_diff(timestamp) > SS2022_MAX_TIME_DIFF_SECS {
        return Err(CryptoError::InvalidTimestamp);
    }
    Ok(())
}

pub(super) fn validate_ss2022_request_fixed_header(header: &[u8]) -> Result<usize, CryptoError> {
    if header.len() != SS2022_REQUEST_FIXED_HEADER_LEN {
        return Err(CryptoError::InvalidHeader);
    }
    if header[0] != SS2022_TCP_REQUEST_TYPE {
        return Err(CryptoError::InvalidHeader);
    }
    let timestamp =
        u64::from_be_bytes(header[1..9].try_into().map_err(|_| CryptoError::InvalidHeader)?);
    validate_timestamp(timestamp)?;
    Ok(u16::from_be_bytes([header[9], header[10]]) as usize)
}

pub(super) fn parse_ss2022_request_header(header: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let Some((target, consumed)) =
        parse_target_addr(header).map_err(|_| CryptoError::InvalidHeader)?
    else {
        return Err(CryptoError::InvalidHeader);
    };
    if header.len() < consumed + 2 {
        return Err(CryptoError::InvalidHeader);
    }
    let padding_len = u16::from_be_bytes([header[consumed], header[consumed + 1]]) as usize;
    if padding_len > SS2022_MAX_PADDING_LEN {
        return Err(CryptoError::InvalidHeader);
    }
    if header.len() < consumed + 2 + padding_len {
        return Err(CryptoError::InvalidHeader);
    }

    let payload = &header[consumed + 2 + padding_len..];
    if padding_len == 0 && payload.is_empty() {
        return Err(CryptoError::InvalidHeader);
    }

    let mut output = target.encode().map_err(|_| CryptoError::InvalidHeader)?;
    output.extend_from_slice(payload);
    Ok(output)
}

pub(super) fn parse_ss2022_udp_request_body(body: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if body.len() < 1 + 8 + 2 {
        return Err(CryptoError::InvalidHeader);
    }
    if body[0] != SS2022_UDP_CLIENT_TYPE {
        return Err(CryptoError::InvalidHeader);
    }
    let timestamp =
        u64::from_be_bytes(body[1..9].try_into().map_err(|_| CryptoError::InvalidHeader)?);
    validate_timestamp(timestamp)?;
    let padding_len = u16::from_be_bytes([body[9], body[10]]) as usize;
    let body = &body[11..];
    if body.len() < padding_len {
        return Err(CryptoError::InvalidHeader);
    }

    let body = &body[padding_len..];
    let Some((target, consumed)) =
        parse_target_addr(body).map_err(|_| CryptoError::InvalidHeader)?
    else {
        return Err(CryptoError::InvalidHeader);
    };
    let mut output = target.encode().map_err(|_| CryptoError::InvalidHeader)?;
    output.extend_from_slice(&body[consumed..]);
    Ok(output)
}

pub(super) fn parse_ss2022_chacha_udp_request_body(
    body: &[u8],
) -> Result<(Vec<u8>, [u8; 8], u64), CryptoError> {
    if body.len() < 8 + 8 + 1 + 8 + 2 {
        return Err(CryptoError::InvalidHeader);
    }
    let client_session_id = body[..8].try_into().map_err(|_| CryptoError::InvalidHeader)?;
    let packet_id =
        u64::from_be_bytes(body[8..16].try_into().map_err(|_| CryptoError::InvalidHeader)?);
    let body = &body[16..];
    if body[0] != SS2022_UDP_CLIENT_TYPE {
        return Err(CryptoError::InvalidHeader);
    }
    let timestamp =
        u64::from_be_bytes(body[1..9].try_into().map_err(|_| CryptoError::InvalidHeader)?);
    validate_timestamp(timestamp)?;
    let padding_len = u16::from_be_bytes([body[9], body[10]]) as usize;
    let body = &body[11..];
    if body.len() < padding_len {
        return Err(CryptoError::InvalidHeader);
    }
    let body = &body[padding_len..];
    let Some((target, consumed)) =
        parse_target_addr(body).map_err(|_| CryptoError::InvalidHeader)?
    else {
        return Err(CryptoError::InvalidHeader);
    };
    let mut output = target.encode().map_err(|_| CryptoError::InvalidHeader)?;
    output.extend_from_slice(&body[consumed..]);
    Ok((output, client_session_id, packet_id))
}
