//! Server-side carrier padding: process-wide config wired at startup, a
//! per-path resolver the transport handlers call at handshake time, and the
//! encode helper the WS / XHTTP downlink writers use.
//!
//! Unlike the client (always "ours", so padding is a single process-wide
//! scheme — see `outline_transport::carrier_padding`), the server pads
//! **per-path**: only the carrier paths listed in `[padding] paths` are
//! framed, so third-party clients (Happ, Outline, xray, sing-box) on other
//! paths keep the plain Shadowsocks-over-WS / XHTTP wire. The path-level
//! decision is made by [`scheme_for_path`] when a connection is accepted; the
//! global only holds the policy (enabled + path list).
//!
//! Gating is config-synchronised: there is no on-wire capability bit. A path
//! that pads must be matched by a client that also enabled padding, or the
//! padded frames get fed straight into the Shadowsocks decryptor and fail —
//! both ends opt in together (see `outline-wire`'s `padding` module).

use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use outline_wire::early_shape::{EarlyShaper, ShapeDirection};
#[cfg(test)]
use outline_wire::padding::PADDING_FRAME_HEADER_LEN;
use outline_wire::padding::PaddingScheme;
use rand::Rng;

// Frame construction is shared with the client (`outline_wire::padding_frames`)
// so the uplink and the downlink of one connection are sized by the same code.
#[cfg(test)]
pub(in crate::server) use outline_wire::padding_frames::H2_DATA_PAYLOAD_MAX;
use outline_wire::padding_frames::draw_jitter;
pub(in crate::server) use outline_wire::padding_frames::{
    H2_WS_SERVER_HEADER_LEN as H2_WS_HEADER_LEN, draw_in, even_piece_lens, frame_payload_into,
};

use super::throughput_monitor::ThrottleDetectParams;
use crate::config::PaddingConfig;
use crate::metrics::Protocol;

static PADDING: OnceLock<PaddingConfig> = OnceLock::new();

/// Wire the process-wide padding policy at startup. First call wins;
/// subsequent calls are ignored (mirrors the client's `init_carrier_padding`
/// and the other server-side startup knobs).
pub(crate) fn init(cfg: PaddingConfig) {
    let _ = PADDING.set(cfg);
}

/// The padding scheme a connection on `path` should use. Returns
/// [`PaddingScheme::disabled`] (no framing — plain wire) when padding is off
/// globally or this path is not in the configured set, so the unpadded carrier
/// carries no padding frames. Read by every transport upgrade handler.
pub(in crate::server) fn scheme_for_path(path: &str) -> PaddingScheme {
    PADDING
        .get()
        .map(|p| p.scheme_for_path(path))
        .unwrap_or_else(PaddingScheme::disabled)
}

/// Idle cover-traffic parameters for a path, or `None` when cover is off (not
/// requested, padding disabled, or this path is unpadded). When `Some`, the
/// downlink writer emits a pad-only frame after each idle gap drawn uniformly
/// from `[jitter_min_ms, jitter_max_ms]`, so a quiet tunnel still produces
/// random-sized writes at irregular intervals.
#[derive(Clone, Copy, Debug)]
pub(in crate::server) struct CoverParams {
    pub scheme: PaddingScheme,
    pub jitter_min_ms: u64,
    pub jitter_max_ms: u64,
}

impl CoverParams {
    /// Draws one idle gap before the next cover frame.
    pub(in crate::server) fn next_gap(&self) -> Duration {
        draw_jitter(self.jitter_min_ms, self.jitter_max_ms)
    }

    /// Builds one pad-only cover frame (`real_len = 0`): the peer's decoder
    /// recovers no payload and drops it transparently.
    pub(in crate::server) fn frame(&self) -> Vec<u8> {
        let mut out = Vec::new();
        frame_payload_into(self.scheme, &[], &mut rand::rng(), &mut out);
        out
    }
}

/// Resolves cover parameters for `path`: `Some` only when cover is enabled,
/// padding is on, and this path is in the configured set (so cover never fires
/// on an unpadded third-party path).
pub(in crate::server) fn cover_for_path(path: &str) -> Option<CoverParams> {
    let p = PADDING.get()?;
    (p.cover_enabled() && p.applies_to(path)).then(|| CoverParams {
        scheme: p.scheme(),
        jitter_min_ms: p.cover_jitter_min_ms,
        jitter_max_ms: p.cover_jitter_max_ms,
    })
}

/// Resolves downstream-throttle detection parameters for `path`: `Some` only
/// when the detector is enabled AND this path actually pads (the control notice
/// rides a cover frame, which an unpadded path never carries, and a
/// padding-unaware client could not decode anyway). `None` keeps the carrier
/// unmonitored. Read once per VLESS carrier at relay start.
pub(in crate::server) fn throttle_params_for_path(path: &str) -> Option<ThrottleDetectParams> {
    let p = PADDING.get()?;
    if !p.throttle_detect_enabled || !p.scheme_for_path(path).is_enabled() {
        return None;
    }
    Some(ThrottleDetectParams {
        enabled: true,
        ratio: p.throttle_ratio_percent as f64 / 100.0,
        window: Duration::from_secs(p.throttle_window_secs.max(1)),
        sustain_windows: p.throttle_sustain_windows.max(1),
        min_in_bytes_per_sec: p.throttle_min_bytes_per_sec,
        signal_cooldown: Duration::from_secs(p.throttle_signal_cooldown_secs.max(1)),
    })
}

/// Frames one discrete downlink message for `scheme`, or returns it unchanged
/// when padding is disabled. Used by the message-oriented downlink paths where
/// each buffer is framed individually rather than streamed through one
/// `ChannelSink` (the SS-TCP downlink):
///
/// - **VLESS** emits several distinct downlink messages (the `[VERSION, 0x00]`
///   response header, the v1 ack-prefix / v2 replay control frames, the relay
///   payload, and UDP records). The client's streaming decoder treats the whole
///   direction as one framed byte stream, so EVERY downlink buffer must be
///   framed the same way or the decoder desyncs on the first unframed message.
/// - **SS-UDP** emits one encrypted datagram per upstream packet; each is framed
///   individually so the datagram size no longer tracks the SS payload (the
///   client decodes each one back before SS decryption).
///
/// Callers route each downlink buffer through here before `make_binary`.
pub(in crate::server) fn frame_downlink_message(scheme: PaddingScheme, bytes: Bytes) -> Bytes {
    if scheme.is_enabled() {
        let mut out = Vec::with_capacity(bytes.len() + 8);
        frame_payload_into(scheme, &bytes, &mut rand::rng(), &mut out);
        out.into()
    } else {
        bytes
    }
}

/// The frame `record` takes as one HTTP/3 datagram of `room` payload bytes: the
/// record itself on an unpadded path, else one padding frame whose pad is cut to
/// what is left. `None` when even the bare record does not fit — the caller
/// sends it on the stream, framed as usual.
pub(in crate::server) fn frame_datagram_message(
    scheme: PaddingScheme,
    record: &Bytes,
    room: usize,
) -> Option<Bytes> {
    outline_wire::padding_frames::try_frame_datagram(scheme, record, room, &mut rand::rng())
}

/// How many data bytes one downlink message may carry on `protocol` so the
/// whole message — WS header, padding framing at the scheme's largest pad, the
/// caller's `inner_overhead` (34 per SS AEAD chunk, 8 per VLESS-mux data frame,
/// 0 for plain VLESS) and the data — fits one h2 DATA frame of
/// [`H2_DATA_PAYLOAD_MAX`] bytes. `None` on every non-h2 carrier (h1 has no
/// DATA framing, h3 / socket keep their wire) and when the budget leaves less
/// than `MIN_H2_PLAINTEXT_CAP`. The cap is applied before early shaping,
/// whose pieces are never larger than their input.
pub(in crate::server) fn h2_plaintext_cap(
    protocol: Protocol,
    scheme: PaddingScheme,
    inner_overhead: usize,
) -> Option<usize> {
    matches!(protocol, Protocol::Http2 | Protocol::XhttpH2)
        .then(|| {
            outline_wire::padding_frames::h2_record_payload_cap(
                H2_WS_HEADER_LEN,
                scheme,
                inner_overhead,
            )
        })
        .flatten()
}

/// One discrete downlink message (a resume control / replay frame) as the
/// messages it goes out as: a single framed message off h2, and on an h2
/// carrier evenly cut pieces that each fit one h2 DATA frame of one TLS record
/// (see [`h2_plaintext_cap`]), each framed for `scheme`. Only for byte-stream
/// payloads (VLESS TCP), where message boundaries carry no meaning.
pub(in crate::server) fn capped_downlink_messages(
    protocol: Protocol,
    scheme: PaddingScheme,
    bytes: Bytes,
) -> Vec<Bytes> {
    outline_wire::padding_frames::h2_capped_messages(
        scheme,
        h2_plaintext_cap(protocol, scheme, 0),
        bytes,
        &mut rand::rng(),
    )
}

/// Whether the first downlink messages of a TCP session on `protocol` are cut
/// into the early-shape pieces: h1/h2 carriers only (the inner TLS flight
/// there is what a record-size classifier sees), padded or not. H3 / socket
/// carriers keep their wire.
pub(in crate::server) fn shape_eligible(protocol: Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Http1 | Protocol::Http2 | Protocol::XhttpH1 | Protocol::XhttpH2
    )
}

/// A fresh server-side shaper when `protocol` qualifies, else `None`. The
/// server never sends cover frames.
pub(in crate::server) fn new_server_shaper(protocol: Protocol) -> Option<EarlyShaper> {
    shape_eligible(protocol).then(|| {
        EarlyShaper::new(ShapeDirection::ServerToClient, false, &mut draw_in(&mut rand::rng()))
    })
}

/// Cuts one downlink buffer into the messages the early-shape plan asks for:
/// lead-in pad-only cover frames first (none for `ServerToClient`), then one
/// padded message per piece. The h2 cap is applied by the callers on this
/// side, so the shared planner runs without one.
pub(in crate::server) fn shaped_messages<R: Rng>(
    scheme: PaddingScheme,
    shaper: &mut EarlyShaper,
    data: &[u8],
    rng: &mut R,
) -> Vec<Vec<u8>> {
    outline_wire::padding_frames::shaped_messages(scheme, shaper, data, None, rng)
}

#[cfg(test)]
#[path = "tests/carrier_padding.rs"]
mod tests;
