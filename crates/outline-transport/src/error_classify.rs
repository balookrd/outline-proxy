use std::io::{self, ErrorKind};

use anyhow::Error;
use outline_wire::ss2022::Ss2022Error;
use shadowsocks_crypto::CryptoError;

use crate::find_typed;

const TRANSPORT_DISCONNECT_STRINGS: &[&str] = &[
    "connection reset by peer",
    "broken pipe",
    // Tokio's UnexpectedEof message when the remote side closes before the
    // full buffer is filled.
    "early eof",
];

pub fn find_io_error_kind(error: &Error) -> Option<ErrorKind> {
    error
        .chain()
        .find_map(|e| e.downcast_ref::<io::Error>())
        .map(|e| e.kind())
}

pub fn is_transport_level_disconnect(error: &Error) -> bool {
    if let Some(kind) = find_io_error_kind(error) {
        return matches!(
            kind,
            ErrorKind::ConnectionReset
                | ErrorKind::BrokenPipe
                | ErrorKind::UnexpectedEof
                | ErrorKind::ConnectionAborted
        );
    }
    contains_any(&lower_error(error), TRANSPORT_DISCONNECT_STRINGS)
}

pub fn lower_error(error: &Error) -> String {
    format!("{error:#}").to_ascii_lowercase()
}

pub fn contains_any(text: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| text.contains(pattern))
}

/// Classify an error as a *payload-integrity* failure — the bytes that
/// arrived could not be turned back into a datagram — and return a
/// low-cardinality cause label for it. `None` means the error is not about
/// the payload.
///
/// This is the data-plane half of the "descend a carrier only on evidence
/// about the carrier" invariant that the probe split
/// (`carrier_ok` vs `transport_ok`) established for the probe half. An AEAD
/// open failure, a truncated datagram, or an SS2022 replay/reorder rejection
/// all describe *content*: the carrier delivered something, it just wasn't
/// intact. Charging them to the carrier caps `xhttp_h3 → xhttp_h2` and stamps
/// an uplink cooldown, i.e. it demotes a healthy QUIC carrier to UDP-over-TCP
/// — a fix that cannot address corruption and costs the user throughput.
/// (Field measurement: 682 cap windows in 16 h on one node — 69.6 % of the
/// time degraded — driven by a ~0.1 % corrupt-datagram rate.)
///
/// Deliberately typed-only, with no string fallback: `"decryption failed"`
/// also appears in TLS/QUIC handshake errors, which *are* carrier faults, and
/// a false positive here silently disables failover.
///
/// Encrypt-side failures are excluded on purpose — those are ours, and never
/// describe a datagram that arrived corrupt.
pub fn payload_integrity_cause(error: &Error) -> Option<&'static str> {
    if let Some(crypto) = find_typed::<CryptoError>(error) {
        match crypto {
            CryptoError::DecryptFailed { .. } => return Some("decrypt_failed"),
            CryptoError::UdpPacketTooShort => return Some("packet_too_short"),
            _ => {},
        }
    }
    if let Some(Ss2022Error::DuplicateOrOutOfOrderUdpPacket) = find_typed::<Ss2022Error>(error) {
        return Some("udp_out_of_order");
    }
    None
}

#[cfg(test)]
#[path = "tests/error_classify.rs"]
mod tests;
