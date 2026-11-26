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

// Frame construction is shared with the client (`outline_wire::padding_frames`)
// so the uplink and the downlink of one connection are sized by the same code.
#[cfg(test)]
pub(in crate::server) use outline_wire::padding_frames::H2_DATA_PAYLOAD_MAX;
#[cfg(test)]
pub(in crate::server) use outline_wire::padding_frames::frame_payload_into;
pub(in crate::server) use outline_wire::padding_frames::{
    CoverParams, H2_WS_SERVER_HEADER_LEN as H2_WS_HEADER_LEN, draw_in, even_piece_lens,
    frame_message,
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

/// Resolves cover parameters for `path`: `Some` only when cover is enabled,
/// padding is on, and this path is in the configured set (so cover never fires
/// on an unpadded third-party path).
pub(in crate::server) fn cover_for_path(path: &str) -> Option<CoverParams> {
    let p = PADDING.get()?;
    CoverParams::new(
        p.scheme(),
        p.cover_enabled() && p.applies_to(path),
        p.cover_jitter_min_ms,
        p.cover_jitter_max_ms,
    )
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

#[cfg(test)]
#[path = "tests/carrier_padding.rs"]
mod tests;
