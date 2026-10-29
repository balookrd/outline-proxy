//! Browser-shaped QUIC transport parameters for the H3 carrier.
//!
//! The client's transport parameters ride the Initial packet, whose keys any
//! passive observer derives from the destination connection id, so quinn's
//! defaults (8 MiB / 64 MiB windows, an 8-byte source CID, `grease_quic_bit`,
//! `min_ack_delay`) identify this client regardless of the TLS fingerprint.
//! Each family mirrors a capture of the real browser (Chrome 156, Apple's
//! Network.framework on macOS 27 and Firefox 159, 2026-10-29), parameter order
//! included.

use std::time::Duration;

use super::vendored::{BrowserTpOptions, TpOrder, VersionInfo, VersionSlot};
use crate::fingerprint_profile::TlsFingerprint;

/// `initial_max_stream_data_{bidi_local,bidi_remote,uni}` (0x05-0x07).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StreamWindows {
    pub(crate) bidi_local: u32,
    pub(crate) bidi_remote: u32,
    pub(crate) uni: u32,
}

impl StreamWindows {
    pub(crate) const fn uniform(window: u32) -> Self {
        Self {
            bidi_local: window,
            bidi_remote: window,
            uni: window,
        }
    }

    pub(crate) fn largest(&self) -> u32 {
        self.bidi_local.max(self.bidi_remote).max(self.uni)
    }
}

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
    pub(crate) stream_receive_windows: StreamWindows,
    /// `initial_max_streams_bidi` (0x08); 0 leaves it unsent.
    pub(crate) max_bidi_streams: u32,
    /// `initial_max_streams_uni` (0x09).
    pub(crate) max_uni_streams: u32,
    /// Length of the client's source CIDs. 0 (Chrome, Apple) sends an empty
    /// `initial_source_connection_id` and, unless
    /// `options.active_connection_id_limit` says otherwise, no
    /// `active_connection_id_limit`. Safe here because every H3 dial owns its
    /// endpoint and socket, so there is nothing to demultiplex by CID.
    pub(crate) source_cid_len: usize,
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
    stream_receive_windows: StreamWindows::uniform(6_291_456),
    max_bidi_streams: 100,
    max_uni_streams: 103,
    source_cid_len: 0,
    grease_quic_bit: false,
    options: BrowserTpOptions {
        advertise_min_ack_delay: false,
        grease_parameter: true,
        advertise_idle_timeout: true,
        advertise_max_udp_payload_size: true,
        datagram_frame_size: Some(65_536),
        version_information: Some(VersionInfo {
            other_versions: &[VersionSlot::Version(1), VersionSlot::Grease],
            shuffle: true,
        }),
        // google_connection_options = "ORIG"
        extra_parameters: &[(0x3128, b"ORIG")],
        order: TpOrder::Shuffled,
        active_connection_id_limit: None,
        max_ack_delay_ms: 25,
    },
};

/// Apple Network.framework (Safari). Apple omits `max_idle_timeout` and
/// `max_udp_payload_size`; the 30 s `idle_timeout` still applies locally. Parameters
/// follow Apple's fixed sequence rotated to a different start per connection, with
/// `0xff080808` always last. `active_connection_id_limit = 64` is advertised while
/// quinn holds at most 8 remote CIDs - exactly what our server issues.
pub(crate) const SAFARI: QuicTpProfile = QuicTpProfile {
    name: "safari",
    idle_timeout: Duration::from_secs(30),
    receive_window: 16_777_216,
    stream_receive_windows: StreamWindows::uniform(2_097_152),
    max_bidi_streams: 0,
    max_uni_streams: 8,
    source_cid_len: 0,
    grease_quic_bit: false,
    options: BrowserTpOptions {
        advertise_min_ack_delay: false,
        grease_parameter: false,
        // Apple omits it; the 30 s `idle_timeout` above still applies locally.
        advertise_idle_timeout: false,
        advertise_max_udp_payload_size: false,
        datagram_frame_size: None,
        version_information: None,
        // Apple's private parameter, value 0x09 as captured on macOS 27.
        extra_parameters: &[(0xff08_0808, &[0x09])],
        order: TpOrder::Rotated(&[0x04, 0x05, 0x06, 0x07, 0x09, 0x0e, 0x0f, 0xff08_0808]),
        active_connection_id_limit: Some(64),
        max_ack_delay_ms: 25,
    },
};

/// Firefox 159 (neqo), measured 2026-10-29: fixed parameter order, per-direction stream
/// windows, a 3-byte source CID, `max_ack_delay = 20` (also our local ACK timer),
/// `version_information` offering a GREASE version, QUIC v2 and v1, an empty 0x1d and
/// neqo's draft `min_ack_delay` 0xff02de1a = 1000 us. The client only speaks v1; our
/// quinn server ignores `version_information`, a server doing compatible version
/// negotiation (RFC 9368) might pick the advertised v2.
pub(crate) const FIREFOX: QuicTpProfile = QuicTpProfile {
    name: "firefox",
    idle_timeout: Duration::from_secs(30),
    receive_window: 25_165_824,
    stream_receive_windows: StreamWindows {
        bidi_local: 12_582_912,
        bidi_remote: 1_048_576,
        uni: 1_048_576,
    },
    max_bidi_streams: 100,
    max_uni_streams: 100,
    source_cid_len: 3,
    grease_quic_bit: false,
    options: BrowserTpOptions {
        advertise_min_ack_delay: false,
        grease_parameter: false,
        advertise_idle_timeout: true,
        advertise_max_udp_payload_size: false,
        datagram_frame_size: Some(65_535),
        version_information: Some(VersionInfo {
            other_versions: &[
                VersionSlot::Grease,
                VersionSlot::Version(0x6b33_43cf),
                VersionSlot::Version(1),
            ],
            shuffle: false,
        }),
        extra_parameters: &[(0x1d, &[]), (0xff02_de1a, &[0x43, 0xe8])],
        order: TpOrder::Fixed(&[
            0x01,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0b,
            0x0e,
            0x0f,
            0x11,
            0x1d,
            0xff02_de1a,
            0x20,
        ]),
        active_connection_id_limit: Some(8),
        max_ack_delay_ms: 20,
    },
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
        let len = self.source_cid_len;
        config.cid_generator(move || Box::new(quinn_proto::RandomConnectionIdGenerator::new(len)));
        config
    }
}

#[cfg(test)]
#[path = "tests/tp_profile.rs"]
mod tests;
