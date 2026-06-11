use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use outline_ss2022::Ss2022Error;
use outline_wire::ss2022::Ss2022HeaderError;
use shadowsocks_crypto::CipherKind;

pub(super) struct Ss2022TcpReaderState {
    pub request_salt: [u8; 32],
    pub response_header_read: bool,
}

pub(super) fn parse_ss2022_response_header(
    cipher: CipherKind,
    request_salt: &[u8],
    plaintext: &[u8],
) -> Result<usize> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs();
    outline_wire::ss2022::parse_response_header(cipher, request_salt, plaintext, now).map_err(
        |err| match err {
            // Keep the typed marker enum in the anyhow chain: uplink error
            // classification downcasts to Ss2022Error.
            Ss2022HeaderError::InvalidResponseLength(len) => {
                anyhow::Error::new(Ss2022Error::InvalidResponseHeaderLength(len))
            },
            Ss2022HeaderError::InvalidResponseType(ty) => {
                anyhow::Error::new(Ss2022Error::InvalidResponseHeaderType(ty))
            },
            Ss2022HeaderError::RequestSaltMismatch => {
                anyhow::Error::new(Ss2022Error::RequestSaltMismatch)
            },
            other => anyhow::Error::new(other),
        },
    )
}
