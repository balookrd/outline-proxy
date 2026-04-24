mod diagnose;
mod error;
mod primitives;
mod stream;
mod udp;
mod user_key;

#[cfg(test)]
mod tests;

pub use diagnose::{diagnose_stream_handshake, diagnose_udp_packet};
pub use error::CryptoError;
pub use primitives::MAX_CHUNK_SIZE;
pub use stream::{AeadStreamDecryptor, AeadStreamEncryptor};
pub use udp::{
    UdpCipherMode, decrypt_udp_packet, decrypt_udp_packet_with_hint,
    encrypt_udp_packet_for_response,
};

#[cfg(test)]
pub use udp::encrypt_udp_packet;
pub use user_key::UserKey;
