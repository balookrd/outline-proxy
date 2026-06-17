//! Symmetric application-layer padding for the WS / XHTTP carriers.
//!
//! Wraps each already-encrypted Shadowsocks chunk in a length-delimited frame
//! `real_len | pad_len | real | pad` so that the size of the buffer handed to
//! the outer TLS record layer no longer tracks the size of the Shadowsocks
//! payload. That breaks the record-size correlation "proxy-inside-TLS" /
//! TLS-in-TLS classifiers key on — the same goal AnyTLS's padding scheme
//! pursues, reached by hardening the carriers we already ship instead of
//! adopting a second proxy protocol.
//!
//! Pure framing, mirroring [`crate::ss2022`]: this crate hosts no RNG and no
//! clock, so the caller supplies both the padding bytes and the random draw
//! that sizes them (the transport layers own the rng). Lengths are big-endian
//! `u16`, matching the rest of the wire vocabulary; a `real`/`pad` segment is
//! therefore capped at 65535 bytes, comfortably above a single Shadowsocks
//! AEAD chunk (≤ 0x3FFF) — callers that hand over more must split first.
//!
//! Gating is config-synchronised, like session resumption: there is no
//! on-wire capability bit. A peer that has not enabled the scheme simply
//! never frames its writes and never decodes — so both ends must opt in
//! together, and a half-rolled-out pair must not turn it on. A `real_len = 0`
//! frame carries pad only (a cover / keepalive write that the decoder yields
//! nothing for).

use thiserror::Error;

/// Bytes of fixed header in front of every padding frame: `real_len:u16` +
/// `pad_len:u16`, both big-endian.
pub const PADDING_FRAME_HEADER_LEN: usize = 4;

/// Largest `real` or `pad` segment a single frame can carry (the `u16` length
/// ceiling). Exposed so the transport layers can chunk to it before framing.
pub const MAX_PADDING_SEGMENT: usize = u16::MAX as usize;

/// Framing error. Only the encoder can fail, and only when a caller hands it
/// a segment that overflows the `u16` length field — the streaming decoder
/// reads nothing but lengths it wrote itself, so it is infallible by
/// construction.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PaddingError {
    #[error("padding frame real segment too large: {0} bytes (max {MAX_PADDING_SEGMENT})")]
    RealTooLarge(usize),
    #[error("padding frame pad segment too large: {0} bytes (max {MAX_PADDING_SEGMENT})")]
    PadTooLarge(usize),
}

/// How much pad to draw per frame. A closed range `[min, max]` in bytes; the
/// transport picks an actual count by feeding one random `u16` to
/// [`PaddingScheme::pad_len`]. `max == 0` means disabled — the scheme adds no
/// bytes and the transport should skip framing entirely (so the wire stays
/// byte-for-byte identical to the unpadded carrier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaddingScheme {
    min_pad: u16,
    max_pad: u16,
}

impl PaddingScheme {
    /// Builds a scheme over `[min_pad, max_pad]`. A `max_pad` below `min_pad`
    /// is clamped up to `min_pad`, so the range is always well-formed and a
    /// fixed-size scheme is expressed as `new(n, n)`.
    pub const fn new(min_pad: u16, max_pad: u16) -> Self {
        let max_pad = if max_pad < min_pad { min_pad } else { max_pad };
        Self { min_pad, max_pad }
    }

    /// The off switch: no padding, transport leaves writes unframed.
    pub const fn disabled() -> Self {
        Self { min_pad: 0, max_pad: 0 }
    }

    /// Whether this scheme ever adds bytes. `false` for [`Self::disabled`]
    /// (and any `new(0, 0)`); the transport keys "frame or not" off this.
    pub const fn is_enabled(self) -> bool {
        self.max_pad > 0
    }

    /// Maps one caller-supplied random `u16` uniformly onto `[min, max]`.
    /// Deterministic in `rand` (the crate carries no rng), matching the
    /// `encode_kind_first_byte(rand_byte, …)` shape in [`crate::xhttp`].
    pub fn pad_len(self, rand: u16) -> u16 {
        let span = (self.max_pad - self.min_pad) as u32 + 1;
        self.min_pad + (rand as u32 % span) as u16
    }
}

/// Frames `real` with `pad` into `out`: `real_len | pad_len | real | pad`.
/// `pad` is caller-drawn random bytes (length goes on the wire; contents are
/// never inspected on decode). Appends to `out` so a caller can frame several
/// chunks back-to-back into one transport write.
pub fn encode_frame_into(out: &mut Vec<u8>, real: &[u8], pad: &[u8]) -> Result<(), PaddingError> {
    if real.len() > MAX_PADDING_SEGMENT {
        return Err(PaddingError::RealTooLarge(real.len()));
    }
    if pad.len() > MAX_PADDING_SEGMENT {
        return Err(PaddingError::PadTooLarge(pad.len()));
    }
    out.reserve(PADDING_FRAME_HEADER_LEN + real.len() + pad.len());
    out.extend_from_slice(&(real.len() as u16).to_be_bytes());
    out.extend_from_slice(&(pad.len() as u16).to_be_bytes());
    out.extend_from_slice(real);
    out.extend_from_slice(pad);
    Ok(())
}

/// Phase of the streaming decode. Held across `push` calls so input may be
/// split at any byte boundary (h2 / h3 DATA frames carry no relation to our
/// frame edges).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeState {
    /// Filling the 4-byte length header (see `header_filled`).
    Header,
    /// Copying out the real segment; `pad` is the pad count that follows it.
    Real { real_rem: usize, pad: usize },
    /// Discarding the pad segment.
    Pad { pad_rem: usize },
}

/// Streaming inverse of [`encode_frame_into`]: feed it whatever bytes arrive,
/// it appends recovered Shadowsocks payload to `out` and silently drops pad.
/// One instance lives per connection direction. Infallible — it only ever
/// reads lengths the peer's encoder wrote.
#[derive(Debug, Clone)]
pub struct PaddingDecoder {
    state: DecodeState,
    header: [u8; PADDING_FRAME_HEADER_LEN],
    header_filled: usize,
}

impl Default for PaddingDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl PaddingDecoder {
    pub const fn new() -> Self {
        Self {
            state: DecodeState::Header,
            header: [0; PADDING_FRAME_HEADER_LEN],
            header_filled: 0,
        }
    }

    /// Consumes all of `input`, appending recovered real payload to `out`.
    pub fn push(&mut self, mut input: &[u8], out: &mut Vec<u8>) {
        while !input.is_empty() {
            match self.state {
                DecodeState::Header => {
                    let need = PADDING_FRAME_HEADER_LEN - self.header_filled;
                    let take = need.min(input.len());
                    self.header[self.header_filled..self.header_filled + take]
                        .copy_from_slice(&input[..take]);
                    self.header_filled += take;
                    input = &input[take..];
                    if self.header_filled == PADDING_FRAME_HEADER_LEN {
                        self.header_filled = 0;
                        let real = u16::from_be_bytes([self.header[0], self.header[1]]) as usize;
                        let pad = u16::from_be_bytes([self.header[2], self.header[3]]) as usize;
                        self.state = next_after_header(real, pad);
                    }
                },
                DecodeState::Real { real_rem, pad } => {
                    let take = real_rem.min(input.len());
                    out.extend_from_slice(&input[..take]);
                    input = &input[take..];
                    let real_rem = real_rem - take;
                    self.state = if real_rem > 0 {
                        DecodeState::Real { real_rem, pad }
                    } else if pad > 0 {
                        DecodeState::Pad { pad_rem: pad }
                    } else {
                        DecodeState::Header
                    };
                },
                DecodeState::Pad { pad_rem } => {
                    let take = pad_rem.min(input.len());
                    input = &input[take..];
                    let pad_rem = pad_rem - take;
                    self.state = if pad_rem > 0 {
                        DecodeState::Pad { pad_rem }
                    } else {
                        DecodeState::Header
                    };
                },
            }
        }
    }

    /// Whether the decoder sits on a frame boundary (no partial frame
    /// buffered). A clean end-of-stream should land here; mid-frame means the
    /// peer was cut off. Useful for close-reason classification.
    pub fn is_at_frame_boundary(&self) -> bool {
        matches!(self.state, DecodeState::Header) && self.header_filled == 0
    }
}

/// The state a freshly parsed header transitions into: real segment first if
/// any, else straight to pad, else an empty frame that yields nothing and
/// returns to header.
fn next_after_header(real: usize, pad: usize) -> DecodeState {
    if real > 0 {
        DecodeState::Real { real_rem: real, pad }
    } else if pad > 0 {
        DecodeState::Pad { pad_rem: pad }
    } else {
        DecodeState::Header
    }
}

#[cfg(test)]
#[path = "tests/padding.rs"]
mod tests;
