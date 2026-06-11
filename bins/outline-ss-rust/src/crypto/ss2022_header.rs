//! SS2022 header parsing, re-exported from `outline-wire` with the server's
//! conventions applied on top: the cached coarse clock feeds the timestamp
//! check, errors collapse into [`CryptoError`], and parsed targets are
//! re-encoded so downstream relay code keeps consuming
//! `SOCKS5 address || payload` byte strings.

use ring::aead::Nonce;

#[cfg(test)]
pub(super) use outline_wire::ss2022::SS2022_TCP_REQUEST_TYPE;
pub(super) use outline_wire::ss2022::{
    SS2022_REQUEST_FIXED_CIPHERTEXT_LEN, SS2022_REQUEST_FIXED_HEADER_LEN, SS2022_TCP_RESPONSE_TYPE,
    SS2022_UDP_SEPARATE_HEADER_LEN, SS2022_UDP_SERVER_TYPE,
};
use outline_wire::ss2022::{Ss2022HeaderError, Ss2022Request};

use super::error::CryptoError;
use crate::clock;

impl From<Ss2022HeaderError> for CryptoError {
    fn from(err: Ss2022HeaderError) -> Self {
        match err {
            Ss2022HeaderError::TimestampSkew { .. } => CryptoError::InvalidTimestamp,
            _ => CryptoError::InvalidHeader,
        }
    }
}

#[inline]
pub(super) fn ss2022_udp_nonce(separate_header: &[u8]) -> Result<Nonce, CryptoError> {
    let nonce = outline_wire::ss2022::udp_nonce_from_separate_header(separate_header)?;
    Ok(Nonce::assume_unique_for_key(nonce))
}

pub(super) fn validate_ss2022_request_fixed_header(header: &[u8]) -> Result<usize, CryptoError> {
    Ok(outline_wire::ss2022::validate_request_fixed_header(
        header,
        clock::current_unix_secs(),
    )?)
}

fn encode_target_and_payload(request: Ss2022Request<'_>) -> Result<Vec<u8>, CryptoError> {
    let mut output = request
        .target
        .to_wire_bytes()
        .map_err(|_| CryptoError::InvalidHeader)?;
    output.extend_from_slice(request.payload);
    Ok(output)
}

pub(super) fn parse_ss2022_request_header(header: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encode_target_and_payload(outline_wire::ss2022::parse_request_variable_header(header)?)
}

pub(super) fn parse_ss2022_udp_request_body(body: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encode_target_and_payload(outline_wire::ss2022::parse_udp_request_body(
        body,
        clock::current_unix_secs(),
    )?)
}

pub(super) fn parse_ss2022_chacha_udp_request_body(
    body: &[u8],
) -> Result<(Vec<u8>, [u8; 8], u64), CryptoError> {
    let request =
        outline_wire::ss2022::parse_chacha_udp_request_body(body, clock::current_unix_secs())?;
    let client_session_id = request.client_session_id;
    let packet_id = request.packet_id;
    let output = encode_target_and_payload(Ss2022Request {
        target: request.target,
        payload: request.payload,
    })?;
    Ok((output, client_session_id, packet_id))
}
