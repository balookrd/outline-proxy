/// Typed error returned by the shadowsocks crypto primitives.
///
/// Variants are grouped by concern:
/// * [`CryptoError::InvalidKey`], [`CryptoError::EncryptFailed`],
///   [`CryptoError::DecryptFailed`] carry the cipher family name, so the
///   caller can still render a precise message while matching on the
///   variant programmatically.
/// * [`CryptoError::Protocol`] is a catch-all for specific SS2022 framing
///   violations whose messages are diagnostic but not worth promoting to
///   their own variants. The string is `&'static str` (no allocation).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("invalid {cipher} key")]
    InvalidKey { cipher: &'static str },

    #[error("{cipher} encryption failed")]
    EncryptFailed { cipher: &'static str },

    #[error("{cipher} decryption failed")]
    DecryptFailed { cipher: &'static str },

    #[error("ciphertext is shorter than AEAD tag")]
    ShortCiphertext,

    #[error(
        "AEAD nonce overflow: nonce wrapped to zero — close this connection \
         to prevent (key, nonce) reuse"
    )]
    NonceOverflow,

    #[error("unsupported cipher: {0}")]
    UnsupportedCipher(String),

    #[error("failed to decode ss2022 PSK as base64")]
    InvalidBase64Psk(#[from] base64::DecodeError),

    #[error("ss2022 PSK length mismatch: got {got}, expected {expected}")]
    Ss2022PskLengthMismatch { got: usize, expected: usize },

    #[error("HKDF expansion failed")]
    HkdfExpandFailed,

    #[error("system clock is before unix epoch")]
    ClockBeforeEpoch,

    #[error("ss2022 timestamp skew exceeds window: {skew_secs}s")]
    Ss2022TimestampSkew { skew_secs: i64 },

    #[error("UDP packet is too short")]
    UdpPacketTooShort,

    #[error("{0}")]
    Protocol(&'static str),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
