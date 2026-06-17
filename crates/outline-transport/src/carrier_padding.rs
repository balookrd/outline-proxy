//! Process-wide carrier-padding configuration for the client's WS / XHTTP
//! dials, plus the framing helper the transports call on the hot path.
//!
//! The client is always "ours", so unlike the server (which pads per-path so
//! third-party clients on other paths keep the plain wire) the knob here is a
//! single process-wide value: padding is either on for every dial or off for
//! all of them. That mirrors [`crate::fingerprint_profile`] — wired once at
//! startup via [`init_carrier_padding`], read back by the transport layers via
//! [`carrier_padding`]. Default is disabled, so a build that never calls
//! `init` leaves the wire byte-for-byte identical to the unpadded carrier.
//!
//! Gating is config-synchronised, like session resumption: there is no on-wire
//! capability bit. The server must enable padding on the matching path or it
//! will feed our padded frames straight into its Shadowsocks decryptor and
//! fail — so both ends opt in together (see `outline-wire`'s `padding` module).

use std::sync::OnceLock;
use std::time::Duration;

use outline_wire::padding::{MAX_PADDING_SEGMENT, PaddingScheme, encode_frame_into};
use rand::{Rng, RngCore};

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

    /// Draws one idle gap before the next cover frame, uniform in the
    /// configured jitter range. Called by the WS writer task to re-arm its
    /// cover timer after each gap or real write.
    pub(crate) fn cover_gap(&self) -> Duration {
        draw_jitter(self.cover_jitter_min_ms, self.cover_jitter_max_ms)
    }

    /// Builds one pad-only cover frame (`real_len = 0`): the server's decoder
    /// recovers no payload and drops it transparently.
    pub(crate) fn cover_frame(&self) -> Vec<u8> {
        let mut out = Vec::new();
        frame_payload_into(self.scheme, &[], &mut rand::rng(), &mut out);
        out
    }
}

/// Uniform random gap in `[min_ms, max_ms]` (inclusive). `max < min` collapses
/// to `min` (the `+ 1` keeps the upper bound reachable).
fn draw_jitter(min_ms: u64, max_ms: u64) -> Duration {
    let span = max_ms.saturating_sub(min_ms).saturating_add(1);
    Duration::from_millis(min_ms + rand::rng().random::<u64>() % span)
}

impl Default for CarrierPadding {
    fn default() -> Self {
        Self::disabled()
    }
}

static PADDING: OnceLock<CarrierPadding> = OnceLock::new();

/// Wire the process-wide padding config at startup. First call wins;
/// subsequent calls are silently ignored, mirroring
/// [`crate::init_fingerprint_profile_strategy`] and `init_h2_window_sizes`.
pub fn init_carrier_padding(padding: CarrierPadding) {
    let _ = PADDING.set(padding);
}

/// The process-wide padding config set by [`init_carrier_padding`], or the
/// disabled default when nothing was wired (tests, deployments that never opt
/// in). Read by the WS / XHTTP transports when they construct a connection.
pub fn carrier_padding() -> CarrierPadding {
    PADDING.get().copied().unwrap_or_default()
}

/// Frames `data` into `out` as one or more padding frames, drawing pad from
/// `rng`. `data` is split to the `u16` segment ceiling first (a coalesced
/// large SS write can exceed it); only the final frame carries pad, so one
/// transport write produces one random-sized tail regardless of how many
/// segments it took. An empty `data` still emits a single pad-only frame.
///
/// Caller must have checked [`PaddingScheme::is_enabled`] — a disabled scheme
/// would draw zero pad and uselessly wrap every write in a 4-byte header.
pub(crate) fn frame_payload_into<R: RngCore>(
    scheme: PaddingScheme,
    data: &[u8],
    rng: &mut R,
    out: &mut Vec<u8>,
) {
    debug_assert!(scheme.is_enabled(), "frame_payload_into called with a disabled scheme");
    let mut chunks = data.chunks(MAX_PADDING_SEGMENT).peekable();
    if chunks.peek().is_none() {
        // Empty payload (e.g. a future cover write routed through here): one
        // pad-only frame so the wire still carries a random-sized record.
        let pad = draw_pad(scheme, rng);
        encode_frame_into(out, &[], &pad).expect("empty real + bounded pad cannot overflow u16");
        return;
    }
    while let Some(chunk) = chunks.next() {
        let pad = if chunks.peek().is_none() {
            draw_pad(scheme, rng)
        } else {
            Vec::new()
        };
        // chunk is bounded by MAX_PADDING_SEGMENT and pad by the u16 scheme
        // ceiling, so neither segment can overflow the frame length field.
        encode_frame_into(out, chunk, &pad).expect("bounded segments cannot overflow u16");
    }
}

/// Draws a fresh pad buffer of random length in the scheme's range. Contents
/// are random bytes (never inspected on decode); length is what matters.
fn draw_pad<R: RngCore>(scheme: PaddingScheme, rng: &mut R) -> Vec<u8> {
    let n = scheme.pad_len(rng.random::<u16>()) as usize;
    let mut pad = vec![0u8; n];
    rng.fill_bytes(&mut pad);
    pad
}

#[cfg(test)]
#[path = "tests/carrier_padding.rs"]
mod tests;
