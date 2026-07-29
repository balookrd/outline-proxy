mod diagnose;
mod error;
mod primitives;
mod session_cache;
mod ss2022_header;
mod stream;
mod udp;
mod user_key;

#[cfg(test)]
mod tests;

pub use diagnose::{diagnose_stream_handshake, diagnose_udp_packet};
pub use error::CryptoError;
pub use primitives::MAX_CHUNK_SIZE;
pub use session_cache::SessionKeyCache;
/// Named only by tests that build an SS-2022 encryptor directly; production
/// code always receives one from `AeadStreamDecryptor::response_context`.
#[cfg(test)]
pub use stream::StreamResponseContext;
pub use stream::{AeadStreamDecryptor, AeadStreamEncryptor};
pub use udp::{
    UdpCipherMode, UdpPacket, decrypt_udp_packet_with_hint, encrypt_udp_packet_for_response,
};

#[cfg(test)]
pub use udp::{decrypt_udp_packet, encrypt_udp_packet};
pub use user_key::UserKey;
