//! Browser-shaped QUIC transport parameters for the H3 carrier.
//!
//! The client's transport parameters ride the Initial packet, whose keys any
//! passive observer derives from the destination connection id, so quinn's
//! defaults (8 MiB / 64 MiB windows, an 8-byte source CID, `grease_quic_bit`,
//! `min_ack_delay`) identify this client regardless of the TLS fingerprint.
//! Each family below mirrors values captured from the real browser
//! (Chrome 156 and Apple's Network.framework on macOS 27, 2026-10-29).
//! Everything except two Safari residuals is matched: `active_connection_id_limit
//! = 64` and the parameter order (see `SAFARI`).

use std::time::Duration;

use super::vendored::BrowserTpOptions;
use crate::fingerprint_profile::TlsFingerprint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuicTpProfile {
    pub(crate) name: &'static str,
    /// `max_idle_timeout` (0x01) and the local idle timer, so it also bounds
    /// how long a silently dead path survives. Not sent when
    /// `options.advertise_idle_timeout` is false.
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
    /// Parameter-set shaping done by the vendored quinn-proto patch: which
    /// parameters are sent at all, `version_information`, datagram size and
    /// the browser's private extras.
    pub(crate) options: BrowserTpOptions,
}

/// Chrome 156 (Edge and other Blink clients share the stack). The full
/// parameter set matches the capture: GREASE parameter, `version_information`
/// with a per-connection GREASE version, `max_datagram_frame_size = 65536`,
/// `google_connection_options = "ORIG"`, no `min_ack_delay`, random order.
pub(crate) const CHROMIUM: QuicTpProfile = QuicTpProfile {
    name: "chromium",
    idle_timeout: Duration::from_secs(30),
    receive_window: 15_728_640,
    stream_receive_window: 6_291_456,
    max_bidi_streams: 100,
    max_uni_streams: 103,
    zero_length_cid: true,
    grease_quic_bit: false,
    options: BrowserTpOptions {
        advertise_min_ack_delay: false,
        grease_parameter: true,
        advertise_idle_timeout: true,
        advertise_max_udp_payload_size: true,
        datagram_frame_size: Some(65_536),
        version_information: true,
        // google_connection_options = "ORIG"
        extra_parameters: &[(0x3128, b"ORIG")],
    },
};

/// Apple Network.framework (Safari). Apple omits `max_idle_timeout` and
/// `max_udp_payload_size`; the 30 s `idle_timeout` still applies locally.
/// Residual differences: (1) Apple sends `active_connection_id_limit = 64`,
/// which we cannot do - quinn's remote CID queue holds 5 entries while our
/// server issues up to 8, so advertising 64 would end in
/// `CONNECTION_ID_LIMIT_ERROR`. (2) Parameter order: Apple writes a fixed
/// cyclic sequence (0x04, 0x05, 0x06, 0x07, 0x09, 0x0e, 0x0f) rotated to a
/// different start per connection, with `0xff080808` always last; we shuffle
/// all parameters randomly (upstream quinn behaviour).
pub(crate) const SAFARI: QuicTpProfile = QuicTpProfile {
    name: "safari",
    idle_timeout: Duration::from_secs(30),
    receive_window: 16_777_216,
    stream_receive_window: 2_097_152,
    max_bidi_streams: 0,
    max_uni_streams: 8,
    zero_length_cid: true,
    grease_quic_bit: false,
    options: BrowserTpOptions {
        advertise_min_ack_delay: false,
        grease_parameter: false,
        // Apple omits it; the 30 s `idle_timeout` above still applies locally.
        advertise_idle_timeout: false,
        advertise_max_udp_payload_size: false,
        datagram_frame_size: None,
        version_information: false,
        // Apple's private parameter, value 0x09 as captured on macOS 27.
        extra_parameters: &[(0xff08_0808, &[0x09])],
    },
};

/// Firefox: unmeasured. Differs from [`CHROMIUM`] only by omitting Google's
/// private `google_connection_options` (0x3128), which neqo never sends.
pub(crate) const FIREFOX: QuicTpProfile = QuicTpProfile {
    name: "firefox",
    options: BrowserTpOptions {
        extra_parameters: &[],
        ..CHROMIUM.options
    },
    ..CHROMIUM
};

/// With no dial fingerprint the client still looks like the most common browser.
pub(crate) fn for_fingerprint(fp: Option<TlsFingerprint>) -> &'static QuicTpProfile {
    match fp {
        Some(TlsFingerprint::Safari) => &SAFARI,
        Some(TlsFingerprint::Firefox) => &FIREFOX,
        Some(TlsFingerprint::Chromium) | None => &CHROMIUM,
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
