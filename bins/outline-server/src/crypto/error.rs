use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("password must not be empty")]
    EmptyPassword,
    #[error("failed to decode base64 pre-shared key")]
    InvalidBase64Key,
    #[error("invalid pre-shared key length for {cipher}: expected {expected} bytes, got {actual}")]
    InvalidPskLength {
        cipher: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("failed to derive session key")]
    KeyDerivation,
    #[error("unsupported chunk size {0}")]
    InvalidChunkSize(usize),
    #[error("invalid encrypted length header")]
    InvalidLengthHeader,
    #[error("invalid shadowsocks 2022 header")]
    InvalidHeader,
    #[error("invalid shadowsocks 2022 timestamp")]
    InvalidTimestamp,
    #[error("missing shadowsocks 2022 response context")]
    MissingResponseContext,
    #[error("cipher error")]
    Cipher,
    #[error("packet too short")]
    PacketTooShort,
    #[error("no configured key matched the incoming data")]
    UnknownUser,
    #[error("AEAD nonce counter exhausted, session must be rotated")]
    NonceExhausted,
}

impl From<shadowsocks_crypto::CryptoError> for CryptoError {
    fn from(err: shadowsocks_crypto::CryptoError) -> Self {
        use shadowsocks_crypto::CryptoError as Sc;
        match err {
            Sc::InvalidLengthHeader => Self::InvalidLengthHeader,
            Sc::InvalidChunkSize(n) => Self::InvalidChunkSize(n),
            Sc::InvalidHeaderLength => Self::InvalidHeader,
            Sc::NonceOverflow => Self::NonceExhausted,
            Sc::HkdfExpandFailed => Self::KeyDerivation,
            _ => Self::Cipher,
        }
    }
}
