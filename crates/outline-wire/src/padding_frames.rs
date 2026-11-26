//! Padding-frame construction shared by both ends of a padded carrier.
//!
//! [`crate::padding`] defines the frame codec; this module is what draws pad
//! lengths and cuts a write into framed messages. The client shapes the
//! uplink and the server the downlink with the same code, so the two
//! directions of one connection cannot drift apart in how they are sized:
//! before this module each side carried its own copy.

use std::time::Duration;

use bytes::Bytes;
use rand::{Rng, RngExt};

use crate::early_shape::EarlyShaper;
use crate::padding::{
    MAX_PADDING_SEGMENT, PADDING_FRAME_HEADER_LEN, PaddingScheme, datagram_pad_budget,
    encode_frame_into,
};

/// Uniform random gap in `[min_ms, max_ms]` (inclusive). `max < min` collapses
/// to `min` (the `+ 1` keeps the upper bound reachable).
pub fn draw_jitter(min_ms: u64, max_ms: u64) -> Duration {
    let span = max_ms.saturating_sub(min_ms).saturating_add(1);
    Duration::from_millis(min_ms + rand::rng().random::<u64>() % span)
}

/// Frames `data` into `out` as one or more padding frames, drawing pad from
/// `rng`. `data` is split to the `u16` segment ceiling first (a coalesced
/// large SS write can exceed it); only the final frame carries pad, so one
/// transport write produces one random-sized tail regardless of how many
/// segments it took. An empty `data` still emits a single pad-only frame.
///
/// Caller must have checked [`PaddingScheme::is_enabled`] — a disabled scheme
/// would draw zero pad and uselessly wrap every write in a 4-byte header.
pub fn frame_payload_into<R: Rng + ?Sized>(
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
pub fn draw_pad<R: Rng + ?Sized>(scheme: PaddingScheme, rng: &mut R) -> Vec<u8> {
    let n = scheme.pad_len(rng.random::<u16>()) as usize;
    let mut pad = vec![0u8; n];
    rng.fill_bytes(&mut pad);
    pad
}

/// Adapts `rng` to the `draw(lo, hi)` callback the early-shape planner takes
/// (uniform in `lo..=hi`).
pub fn draw_in(rng: &mut impl RngExt) -> impl FnMut(usize, usize) -> usize + '_ {
    move |lo, hi| rng.random_range(lo..=hi)
}

/// Largest h2 DATA payload that leaves in one TLS record together with its
/// 9-byte frame header: a 16384-byte record minus that header. h2 cuts a bigger
/// write into 16384-byte frames (the server's `SETTINGS_MAX_FRAME_SIZE`), and
/// each such frame (16393 B with its header) leaves as a full 16384 record plus
/// a 9-byte one — the 16401 + 26 wire pair real browsers almost never produce.
pub const H2_DATA_PAYLOAD_MAX: usize = 16384 - 9;

/// Below this many data bytes per message the cap is not worth applying (a huge
/// configured pad range would otherwise shrink every message to a few bytes);
/// Each side's cap function returns `None` then and the uncapped sizing stays.
pub const MIN_H2_PLAINTEXT_CAP: usize = 1024;

/// Piece lengths that cut `len` bytes into the fewest pieces of at most `cap`
/// bytes, as even as possible (they differ by at most one byte). Unlike a greedy
/// `cap, cap, …, rest` cut there is no small remainder piece: a small message
/// next to a full DATA frame is what h2 coalesces into one write that spills a
/// full TLS record plus a small one. `len == 0` yields one empty piece.
pub fn even_piece_lens(len: usize, cap: usize) -> impl Iterator<Item = usize> {
    let cap = cap.max(1);
    let n = len.div_ceil(cap).max(1);
    let (base, extra) = (len / n, len % n);
    (0..n).map(move |i| base + usize::from(i < extra))
}

/// Cuts one encrypted frame into the messages the early-shape plan asks for:
/// lead-in pad-only cover frames first, then one padded message per piece.
/// Each returned buffer is a ready `Message::Binary` payload. Past the shaping
/// window (or for a small frame) this is a single ordinary padded message.
/// With a disabled scheme the pieces are plain slices (no framing, no covers).
/// With `h2_cap` set (h2 carriers) a planned piece longer than the cap — the
/// part of a large write past the window's byte budget — is cut further into
/// even pieces of at most `h2_cap` bytes; pieces inside the window are far
/// below it and stay as planned.
pub fn shaped_messages<R: Rng>(
    scheme: PaddingScheme,
    shaper: &mut EarlyShaper,
    frame: &[u8],
    h2_cap: Option<usize>,
    rng: &mut R,
) -> Vec<Vec<u8>> {
    let plan = shaper.plan(frame.len(), &mut draw_in(rng));
    let pieces: Vec<usize> = match h2_cap {
        Some(cap) => plan
            .pieces
            .iter()
            .flat_map(|&len| even_piece_lens(len, cap))
            .collect(),
        None => plan.pieces,
    };
    let mut msgs = Vec::with_capacity(plan.covers.len() + pieces.len());
    for pad_len in plan.covers {
        let mut pad = vec![0u8; pad_len.min(usize::from(u16::MAX))];
        rng.fill_bytes(&mut pad);
        let mut out = Vec::with_capacity(pad.len() + 4);
        encode_frame_into(&mut out, &[], &pad).expect("bounded cover pad cannot overflow u16");
        msgs.push(out);
    }
    let mut offset = 0;
    for len in pieces {
        let piece = &frame[offset..offset + len];
        offset += len;
        if scheme.is_enabled() {
            let mut out = Vec::with_capacity(len + 8);
            frame_payload_into(scheme, piece, rng, &mut out);
            msgs.push(out);
        } else {
            // Unpadded path: plain slices of the stream, no framing.
            msgs.push(piece.to_vec());
        }
    }
    msgs
}

/// WebSocket header in front of a server->client binary message of 126..=65535 B (no mask).
pub const H2_WS_SERVER_HEADER_LEN: usize = 4;

/// WebSocket header in front of a client->server binary message of 126..=65535 B (with 4 B mask).
pub const H2_WS_CLIENT_HEADER_LEN: usize = 8;

/// Maximum data bytes per message on an HTTP/2 carrier so WS header + largest
/// padding + `inner_overhead` + data fit in a single `H2_DATA_PAYLOAD_MAX` TLS record.
pub fn h2_record_payload_cap(
    ws_header_len: usize,
    scheme: PaddingScheme,
    inner_overhead: usize,
) -> Option<usize> {
    let padding = if scheme.is_enabled() {
        PADDING_FRAME_HEADER_LEN + usize::from(scheme.max_pad())
    } else {
        0
    };
    H2_DATA_PAYLOAD_MAX
        .checked_sub(ws_header_len + padding + inner_overhead)
        .filter(|cap| *cap >= MIN_H2_PLAINTEXT_CAP)
}

/// Frames one message under `scheme`, returning `bytes` unchanged (zero-copy)
/// when `scheme` is disabled.
pub fn frame_message<R: Rng + ?Sized>(scheme: PaddingScheme, bytes: Bytes, rng: &mut R) -> Bytes {
    if !scheme.is_enabled() {
        return bytes;
    }
    let mut out = Vec::with_capacity(bytes.len() + 8);
    frame_payload_into(scheme, &bytes, rng, &mut out);
    Bytes::from(out)
}

/// Parameters controlling periodic cover traffic on a padded carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoverParams {
    pub scheme: PaddingScheme,
    pub jitter_min_ms: u64,
    pub jitter_max_ms: u64,
}

impl CoverParams {
    /// Builds cover parameters when both `scheme` and `cover` are enabled.
    pub const fn new(
        scheme: PaddingScheme,
        cover: bool,
        jitter_min_ms: u64,
        jitter_max_ms: u64,
    ) -> Option<Self> {
        if scheme.is_enabled() && cover {
            Some(Self { scheme, jitter_min_ms, jitter_max_ms })
        } else {
            None
        }
    }

    /// Draws the next cover interval uniformly in `[jitter_min_ms, jitter_max_ms]`.
    pub fn next_gap<R: Rng + ?Sized>(&self, rng: &mut R) -> Duration {
        let span = self
            .jitter_max_ms
            .saturating_sub(self.jitter_min_ms)
            .saturating_add(1);
        Duration::from_millis(self.jitter_min_ms + rng.random::<u64>() % span)
    }

    /// Builds one pad-only cover frame (`real_len = 0`).
    pub fn frame<R: Rng + ?Sized>(&self, rng: &mut R) -> Bytes {
        frame_message(self.scheme, Bytes::new(), rng)
    }
}

/// Result of [`OutboundFramer::frame`], avoiding a `Vec` allocation on the
/// single-frame fast path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundFrames {
    Single(Bytes),
    Multi(Vec<Bytes>),
}

/// Iterator over [`OutboundFrames`].
pub enum OutboundFramesIter {
    Single(Option<Bytes>),
    Multi(std::vec::IntoIter<Bytes>),
}

impl Iterator for OutboundFramesIter {
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Single(item) => item.take(),
            Self::Multi(iter) => iter.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Single(item) => {
                let n = usize::from(item.is_some());
                (n, Some(n))
            },
            Self::Multi(iter) => iter.size_hint(),
        }
    }
}

impl ExactSizeIterator for OutboundFramesIter {}

impl IntoIterator for OutboundFrames {
    type Item = Bytes;
    type IntoIter = OutboundFramesIter;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::Single(frame) => OutboundFramesIter::Single(Some(frame)),
            Self::Multi(frames) => OutboundFramesIter::Multi(frames.into_iter()),
        }
    }
}

/// Stateful outbound framer applying optional [`EarlyShaper`], HTTP/2 cap, and
/// [`PaddingScheme`] in a single pipeline.
#[derive(Debug)]
pub struct OutboundFramer {
    scheme: PaddingScheme,
    shaper: Option<EarlyShaper>,
    h2_cap: Option<usize>,
}

impl OutboundFramer {
    /// Creates a new framer with optional early-session shaper and HTTP/2 cap.
    pub fn new(scheme: PaddingScheme, shaper: Option<EarlyShaper>, h2_cap: Option<usize>) -> Self {
        Self { scheme, shaper, h2_cap }
    }

    /// Updates the HTTP/2 per-message payload cap.
    pub fn set_h2_cap(&mut self, h2_cap: Option<usize>) {
        self.h2_cap = h2_cap;
    }

    /// Returns the configured [`PaddingScheme`].
    pub const fn scheme(&self) -> PaddingScheme {
        self.scheme
    }

    /// Frames `payload` through early shaping (while active), then optional
    /// HTTP/2 capping, then padding. Automatically clears `shaper` once its
    /// window is exhausted.
    pub fn frame<R: Rng>(&mut self, payload: Bytes, rng: &mut R) -> OutboundFrames {
        if let Some(shaper) = self.shaper.as_mut() {
            let msgs = shaped_messages(self.scheme, shaper, &payload, self.h2_cap, rng);
            if !shaper.is_active() {
                self.shaper = None;
            }
            return OutboundFrames::Multi(msgs.into_iter().map(Bytes::from).collect());
        }
        if let Some(cap) = self.h2_cap.filter(|&c| payload.len() > c) {
            return OutboundFrames::Multi(h2_capped_messages(self.scheme, Some(cap), payload, rng));
        }
        OutboundFrames::Single(frame_message(self.scheme, payload, rng))
    }
}

/// Cuts `frame` into even pieces of at most `cap` bytes (when `cap` is `Some`
/// and `frame.len() > cap`), framing each piece under `scheme` when enabled or
/// returning zero-copy `Bytes` slices when disabled.
pub fn h2_capped_messages<R: Rng + ?Sized>(
    scheme: PaddingScheme,
    cap: Option<usize>,
    mut frame: Bytes,
    rng: &mut R,
) -> Vec<Bytes> {
    match cap {
        Some(c) if frame.len() > c => even_piece_lens(frame.len(), c)
            .map(|len| frame_message(scheme, frame.split_to(len), rng))
            .collect(),
        _ => vec![frame_message(scheme, frame, rng)],
    }
}

/// Appends one padded datagram frame into `out` when `data` fits `room`
/// (capping pad to the remaining room). Returns `false` without modifying `out`
/// when `data` cannot fit as a padded datagram.
pub fn try_frame_datagram_into<R: Rng + ?Sized>(
    scheme: PaddingScheme,
    data: &[u8],
    room: usize,
    rng: &mut R,
    out: &mut Vec<u8>,
) -> bool {
    let Some(budget) = datagram_pad_budget(room, data.len()) else {
        return false;
    };
    let mut pad = vec![0u8; scheme.pad_len_capped(rng.random::<u16>(), budget) as usize];
    rng.fill_bytes(&mut pad);
    encode_frame_into(out, data, &pad).expect("datagram-sized segments cannot overflow u16");
    true
}

/// Frames one datagram payload to fit within `room` bytes, returning zero-copy
/// `record.clone()` when `scheme` is disabled and `record.len() <= room`.
pub fn try_frame_datagram<R: Rng + ?Sized>(
    scheme: PaddingScheme,
    record: &Bytes,
    room: usize,
    rng: &mut R,
) -> Option<Bytes> {
    if !scheme.is_enabled() {
        return (record.len() <= room).then(|| record.clone());
    }
    let budget = datagram_pad_budget(room, record.len())?;
    let mut out = Vec::with_capacity(PADDING_FRAME_HEADER_LEN + record.len() + budget);
    try_frame_datagram_into(scheme, record, room, rng, &mut out).then(|| Bytes::from(out))
}

#[cfg(test)]
#[path = "tests/padding_frames.rs"]
mod tests;
