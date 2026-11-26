//! Carrier-padding configuration for the client's WS / XHTTP dials, plus the
//! framing helper the transports call on the hot path.
//!
//! Padding is resolved per dial. A global `[padding]` block sets the scheme
//! parameters (range, cover, jitter) and a default on/off flag; each
//! `[[outline.uplinks]]` may override the on/off decision with
//! `padding = true/false`. The effective value for a dial is the per-uplink
//! override when present, else the global default — exactly the
//! override/fallback shape of [`crate::fingerprint_profile`]'s per-uplink
//! strategy. Parameters are wired once at startup via [`init_carrier_padding`];
//! the per-uplink override is a dial-scoped task-local set by
//! [`with_uplink_padding_override`] (the uplink manager wraps each dial). The
//! transports read the resolved value via [`effective_carrier_padding`].
//! Default is off, so a build that never opts in puts no padding frames on
//! the wire (early-session shaping on h1/h2 is separate and needs no padding).
//!
//! Gating is config-synchronised, like session resumption: there is no on-wire
//! capability bit. The server must enable padding on the matching path or it
//! will feed our padded frames straight into its decryptor and fail — so both
//! ends opt in together (see `outline-wire`'s `padding` module). Because the
//! client knob is per-uplink, an operator can pad their own servers while
//! leaving a VLESS uplink to a third-party server unpadded.

use std::sync::OnceLock;

use outline_wire::padding::PaddingScheme;
use rand::Rng;

// Frame construction is shared with the server (`outline_wire::padding_frames`)
// so the uplink and the downlink of one connection are sized by the same code.
#[cfg(test)]
pub(crate) use outline_wire::padding_frames::H2_DATA_PAYLOAD_MAX;
#[cfg(test)]
use outline_wire::padding_frames::draw_pad;
pub(crate) use outline_wire::padding_frames::{
    CoverParams, H2_WS_CLIENT_HEADER_LEN, draw_in, frame_payload_into,
};

/// Resolved carrier-padding knobs for this process. `Copy` so the transport
/// layers can stash a snapshot per connection without sharing state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CarrierPadding {
    /// Range of pad bytes drawn per frame. [`PaddingScheme::disabled`] means
    /// no framing at all — the transport leaves writes untouched.
    pub scheme: PaddingScheme,
    /// Emit idle cover frames (`real_len = 0`, pad only) on a quiet link.
    pub cover: bool,
    /// Jitter floor / ceiling (ms) between cover frames. Each idle gap is a
    /// fresh uniform draw in `[min, max]`.
    pub cover_jitter_min_ms: u64,
    pub cover_jitter_max_ms: u64,
}

impl CarrierPadding {
    /// The off switch: no framing, no cover. The wire stays identical to the
    /// unpadded carrier.
    pub const fn disabled() -> Self {
        Self {
            scheme: PaddingScheme::disabled(),
            cover: false,
            cover_jitter_min_ms: 0,
            cover_jitter_max_ms: 0,
        }
    }

    /// Whether any framing happens at all. The transports key "frame or not"
    /// off this so a disabled scheme costs nothing on the hot path.
    pub const fn is_enabled(&self) -> bool {
        self.scheme.is_enabled()
    }

    /// Whether to emit idle cover frames: padding on *and* cover requested.
    pub const fn cover_enabled(&self) -> bool {
        self.scheme.is_enabled() && self.cover
    }

    /// Builds [`CoverParams`] when both padding and cover traffic are enabled.
    pub(crate) const fn cover_params(&self) -> Option<CoverParams> {
        CoverParams::new(
            self.scheme,
            self.cover,
            self.cover_jitter_min_ms,
            self.cover_jitter_max_ms,
        )
    }
}

impl Default for CarrierPadding {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Process-wide padding *parameters* (scheme range, cover, jitter). Held
/// independently of the on/off decision so a per-uplink override can turn
/// padding on for one uplink even when the global default is off — the scheme
/// here is always built from `min_bytes..max_bytes`, never collapsed to
/// disabled just because the global default is off.
static PADDING: OnceLock<CarrierPadding> = OnceLock::new();

/// Whether padding is on by default — the global `[padding] enabled`. A dial
/// without a per-uplink override falls back to this (mirrors how
/// `fingerprint_profile` falls back to the process-wide strategy).
static DEFAULT_ON: OnceLock<bool> = OnceLock::new();

/// Whether the client reacts to a server-initiated downstream-throttle signal
/// by penalising the current uplink and migrating away. Off by default; gated
/// independently of padding params (the signal still rides padding cover
/// frames, so the carrier must also have padding on for one to ever arrive).
static REACT_TO_THROTTLE: OnceLock<bool> = OnceLock::new();

tokio::task_local! {
    /// Per-uplink padding on/off for the current dial, set by
    /// [`with_uplink_padding_override`]. When a dial runs inside this scope,
    /// [`effective_carrier_padding`] reads it instead of [`DEFAULT_ON`], so a
    /// single uplink can opt in (or out) without flipping the process-wide
    /// default. Same propagation as `fingerprint_profile`'s overrides: it
    /// follows the awaited dial future but not freshly-spawned tasks — and the
    /// transport reads it inline while constructing the connection.
    static UPLINK_PADDING_OVERRIDE: bool;
}

/// Wire the process-wide padding parameters and default at startup. First call
/// wins; subsequent calls are silently ignored, mirroring
/// [`crate::init_fingerprint_profile_strategy`] and `init_h2_window_sizes`.
/// `padding` carries the scheme range / cover / jitter (built from the config
/// regardless of `enabled`); `default_on` is the global `enabled` flag used
/// when a dial pins no per-uplink override.
pub fn init_carrier_padding(padding: CarrierPadding, default_on: bool) {
    let _ = PADDING.set(padding);
    let _ = DEFAULT_ON.set(default_on);
}

/// The global `[padding] enabled` default an uplink inherits when it pins no
/// per-uplink override. Mirrors the fallback inside [`effective_carrier_padding`]
/// — the control/topology layer reads it to render each uplink's *effective*
/// padding state on the dashboard (`per-uplink override` ?? this default).
/// `false` before [`init_carrier_padding`] runs.
pub fn carrier_padding_default_on() -> bool {
    DEFAULT_ON.get().copied().unwrap_or(false)
}

/// Wire the client's reaction to server downstream-throttle signals. First
/// call wins, like [`init_carrier_padding`]. `false` (the default) keeps the
/// client inert: signals are still decoded but ignored.
pub fn init_react_to_throttle(enabled: bool) {
    let _ = REACT_TO_THROTTLE.set(enabled);
}

/// Whether the client should act on a server downstream-throttle signal.
/// `false` before [`init_react_to_throttle`] runs.
pub fn react_to_throttle_enabled() -> bool {
    REACT_TO_THROTTLE.get().copied().unwrap_or(false)
}

/// Run `f` with `on` as the per-uplink padding decision for every dial inside
/// it. Wrap the whole dial future so the transport sees it while building the
/// connection. Used by the uplink manager (`dial_in_uplink_scope`) to honour a
/// `[[outline.uplinks]] padding = true/false` knob; when the uplink pins no
/// value the manager does not enter this scope and the dial inherits
/// [`DEFAULT_ON`].
pub async fn with_uplink_padding_override<F>(on: bool, f: F) -> F::Output
where
    F: std::future::Future,
{
    UPLINK_PADDING_OVERRIDE.scope(on, f).await
}

/// The padding config the current dial should use: the per-uplink override
/// when one is in scope, else the global default ([`DEFAULT_ON`]). Returns the
/// stored parameters when on, [`CarrierPadding::disabled`] when off — so a
/// disabled dial puts no padding frames on the wire. Read by the WS /
/// XHTTP transports (and the VLESS-UDP transport) when they construct a
/// connection.
pub(crate) fn effective_carrier_padding() -> CarrierPadding {
    let on = UPLINK_PADDING_OVERRIDE
        .try_with(|v| *v)
        .unwrap_or_else(|_| DEFAULT_ON.get().copied().unwrap_or(false));
    if on {
        PADDING.get().copied().unwrap_or_default()
    } else {
        CarrierPadding::disabled()
    }
}

/// Frames one datagram-bound payload. When it fits `room` (the channel's
/// [`crate::frame_io::DatagramChannel::datagram_room`]) unpadded, the pad is
/// cut to what is left, so padding never pushes a packet onto the stream;
/// otherwise the frame is the stream's own (full-range pad) — it will ride the
/// stream anyway.
pub(crate) fn frame_datagram_into<R: Rng>(
    scheme: PaddingScheme,
    data: &[u8],
    room: Option<usize>,
    rng: &mut R,
    out: &mut Vec<u8>,
) {
    if let Some(room) = room
        && outline_wire::padding_frames::try_frame_datagram_into(scheme, data, room, rng, out)
    {
        return;
    }
    frame_payload_into(scheme, data, rng, out);
}

/// How many stream bytes one uplink message may carry on an h2 carrier so the
/// whole message — WS header, padding framing at the scheme's largest pad and
/// the data — fits one h2 DATA frame of [`H2_DATA_PAYLOAD_MAX`] bytes, i.e. one
/// TLS record. The data is the already encrypted / encoded stream (SS AEAD
/// chunks, VLESS bytes), which the server reads as a stream, so a cut needs no
/// inner overhead. `None` when the budget leaves less than
/// `MIN_H2_PLAINTEXT_CAP`. Callers apply it only on h2 carriers (see
/// `TransportStream::caps_h2_uplink`).
pub(crate) fn h2_uplink_cap(scheme: PaddingScheme) -> Option<usize> {
    outline_wire::padding_frames::h2_record_payload_cap(H2_WS_CLIENT_HEADER_LEN, scheme, 0)
}

#[cfg(test)]
#[path = "tests/carrier_padding.rs"]
mod tests;
