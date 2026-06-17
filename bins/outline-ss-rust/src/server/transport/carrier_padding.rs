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

use outline_wire::padding::{MAX_PADDING_SEGMENT, PaddingScheme, encode_frame_into};
use rand::{Rng, RngCore};

use crate::config::PaddingConfig;

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
/// stays byte-for-byte identical. Read by every transport upgrade handler.
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

/// Uniform random gap in `[min_ms, max_ms]` (inclusive). `max < min` collapses
/// to `min` (the `+ 1` keeps the upper bound reachable).
fn draw_jitter(min_ms: u64, max_ms: u64) -> Duration {
    let span = max_ms.saturating_sub(min_ms).saturating_add(1);
    Duration::from_millis(min_ms + rand::rng().random::<u64>() % span)
}

/// Frames `data` into `out` as one or more padding frames, drawing pad from
/// `rng`. `data` is split to the `u16` segment ceiling first; only the final
/// frame carries pad, so one downlink write produces one random-sized tail
/// regardless of how many segments it took. An empty `data` still emits a
/// single pad-only frame (the cover-frame shape).
///
/// Mirrors the client's `outline_transport::carrier_padding::frame_payload_into`
/// — the two sides must agree on the framing or the round-trip breaks. Caller
/// must have checked [`PaddingScheme::is_enabled`].
pub(in crate::server) fn frame_payload_into<R: RngCore>(
    scheme: PaddingScheme,
    data: &[u8],
    rng: &mut R,
    out: &mut Vec<u8>,
) {
    debug_assert!(scheme.is_enabled(), "frame_payload_into called with a disabled scheme");
    let mut chunks = data.chunks(MAX_PADDING_SEGMENT).peekable();
    if chunks.peek().is_none() {
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
        encode_frame_into(out, chunk, &pad).expect("bounded segments cannot overflow u16");
    }
}

/// Draws a fresh pad buffer of random length in the scheme's range. Contents
/// are random bytes (never inspected on decode); only the length matters.
fn draw_pad<R: RngCore>(scheme: PaddingScheme, rng: &mut R) -> Vec<u8> {
    let n = scheme.pad_len(rng.random::<u16>()) as usize;
    let mut pad = vec![0u8; n];
    rng.fill_bytes(&mut pad);
    pad
}

#[cfg(test)]
#[path = "tests/carrier_padding.rs"]
mod tests;
