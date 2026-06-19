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
//! Default is off, so a build that never opts in leaves the wire byte-for-byte
//! identical to the unpadded carrier.
//!
//! Gating is config-synchronised, like session resumption: there is no on-wire
//! capability bit. The server must enable padding on the matching path or it
//! will feed our padded frames straight into its decryptor and fail — so both
//! ends opt in together (see `outline-wire`'s `padding` module). Because the
//! client knob is per-uplink, an operator can pad their own servers while
//! leaving a VLESS uplink to a third-party server unpadded.

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
/// disabled dial leaves the wire byte-for-byte identical. Read by the WS /
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
