//! Browser-shaped QUIC transport parameters for the H3 carrier.
//!
//! The client's transport parameters ride the Initial packet, whose keys any
//! passive observer derives from the destination connection id, so quinn's
//! defaults (8 MiB / 64 MiB windows, an 8-byte source CID, `grease_quic_bit`,
//! `min_ack_delay`) identify this client regardless of the TLS fingerprint.
//! Each family below mirrors values captured from the real browser
//! (Chrome 156 and Apple's Network.framework on macOS 27, 2026-10-29). Only
//! what quinn's public API can express is set here.

use std::time::Duration;

use crate::fingerprint_profile::TlsFingerprint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuicTpProfile {
    pub(crate) name: &'static str,
    /// `max_idle_timeout` (0x01). quinn uses the same value locally, so it
    /// also bounds how long a silently dead path survives.
    pub(crate) idle_timeout: Duration,
    /// `initial_max_data` (0x04).
    pub(crate) receive_window: u32,
    /// `initial_max_stream_data_{bidi_local,bidi_remote,uni}` (0x05-0x07).
    pub(crate) stream_receive_window: u32,
    /// `initial_max_streams_bidi` (0x08); 0 leaves it unsent.
    pub(crate) max_bidi_streams: u32,
    /// `initial_max_streams_uni` (0x09).
    pub(crate) max_uni_streams: u32,
    /// Zero-length source CID: both browsers send an empty
    /// `initial_source_connection_id` and, as a consequence, no
    /// `active_connection_id_limit`. Safe here because every H3 dial owns its
    /// endpoint and socket, so there is nothing to demultiplex by CID.
    pub(crate) zero_length_cid: bool,
    /// `grease_quic_bit` (0x2ab2) - neither browser sends it.
    pub(crate) grease_quic_bit: bool,
}

/// Chrome 156 (Edge and other Blink clients share the stack).
pub(crate) const CHROMIUM: QuicTpProfile = QuicTpProfile {
    name: "chromium",
    idle_timeout: Duration::from_secs(30),
    receive_window: 15_728_640,
    stream_receive_window: 6_291_456,
    max_bidi_streams: 100,
    max_uni_streams: 103,
    zero_length_cid: true,
    grease_quic_bit: false,
};

/// Apple Network.framework (Safari). Apple omits `max_idle_timeout`; quinn
/// would then fall back to the server's 120 s for dead-path detection, so the
/// 30 s budget stays on the wire until the parameter can be split from the
/// local timer.
pub(crate) const SAFARI: QuicTpProfile = QuicTpProfile {
    name: "safari",
    idle_timeout: Duration::from_secs(30),
    receive_window: 16_777_216,
    stream_receive_window: 2_097_152,
    max_bidi_streams: 0,
    max_uni_streams: 8,
    zero_length_cid: true,
    grease_quic_bit: false,
};

/// Firefox has not been measured yet and shares the Chromium table; with no
/// dial fingerprint the client still looks like the most common browser.
pub(crate) fn for_fingerprint(fp: Option<TlsFingerprint>) -> &'static QuicTpProfile {
    match fp {
        Some(TlsFingerprint::Safari) => &SAFARI,
        Some(TlsFingerprint::Chromium | TlsFingerprint::Firefox) | None => &CHROMIUM,
    }
}

impl QuicTpProfile {
    pub(crate) fn endpoint_config(&self) -> quinn::EndpointConfig {
        let mut config = quinn::EndpointConfig::default();
        config.grease_quic_bit(self.grease_quic_bit);
        if self.zero_length_cid {
            config.cid_generator(|| Box::new(ZeroLengthCid));
        }
        config
    }
}

/// Issues empty connection ids, which quinn treats as "route by remote
/// address" and which keeps `active_connection_id_limit` off the wire.
struct ZeroLengthCid;

impl quinn::ConnectionIdGenerator for ZeroLengthCid {
    fn generate_cid(&mut self) -> quinn::ConnectionId {
        quinn::ConnectionId::new(&[])
    }

    fn cid_len(&self) -> usize {
        0
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

#[cfg(test)]
#[path = "tests/tp_profile.rs"]
mod tests;
