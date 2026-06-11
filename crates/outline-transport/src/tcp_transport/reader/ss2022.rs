use anyhow::{Result, bail};
use outline_ss2022::Ss2022Error;
use shadowsocks_crypto::{CipherKind, validate_ss2022_timestamp};

pub(super) struct Ss2022TcpReaderState {
    pub request_salt: [u8; 32],
    pub response_header_read: bool,
}

pub(super) fn parse_ss2022_response_header(
    cipher: CipherKind,
    request_salt: &[u8],
    plaintext: &[u8],
) -> Result<usize> {
    let expected_len = 1 + 8 + cipher.salt_len() + 2;
    if plaintext.len() != expected_len {
        bail!(Ss2022Error::InvalidResponseHeaderLength(plaintext.len()));
    }
    if plaintext[0] != 1 {
        bail!(Ss2022Error::InvalidResponseHeaderType(plaintext[0]));
    }
    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&plaintext[1..9]);
    validate_ss2022_timestamp(u64::from_be_bytes(timestamp_bytes))?;

    let request_salt_start = 9;
    let request_salt_end = request_salt_start + cipher.salt_len();
    if &plaintext[request_salt_start..request_salt_end] != request_salt {
        bail!(Ss2022Error::RequestSaltMismatch);
    }

    Ok(u16::from_be_bytes([plaintext[request_salt_end], plaintext[request_salt_end + 1]]) as usize)
}
