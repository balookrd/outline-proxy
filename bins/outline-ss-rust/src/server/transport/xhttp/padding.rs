//! Response-side `X-Padding` and browser-mimic header shaping.
//!
//! XHTTP without padding has a recognisable size signature on the
//! first response (status line + tiny body). Real CDN-hosted SSE
//! / streaming endpoints look very different on the wire: variable
//! response length, long-lived `text/event-stream` content type,
//! anti-caching headers. The helpers here add those traits so
//! passive DPI cannot trivially fingerprint our XHTTP from a few
//! TLS records.
//!
//! What we do **not** do here:
//! * we do not validate the client's `X-Padding` — the spec lets
//!   the client send any opaque value, and a strict server check
//!   would itself become a fingerprint;
//! * we do not inject masquerade payload into the response body —
//!   that needs end-to-end coordination with the client framer
//!   and is therefore wired in `handlers` / `h3`, not here.

use axum::http::{HeaderName, HeaderValue};
use ring::rand::{SecureRandom, SystemRandom};

use super::PADDING_HEADER;

/// Bounds on the random `X-Padding` length, in bytes. Lower bound
/// is large enough to not stand out next to a real `Sec-*` header;
/// upper bound is small enough to fit in a single HTTP/2 HEADERS
/// frame and not bloat every response above 4 KiB.
const PADDING_MIN_LEN: usize = 100;
const PADDING_MAX_LEN: usize = 1024;

/// Builds an `X-Padding` header with a random ASCII-alphanumeric
/// value. Length is uniformly chosen in [`PADDING_MIN_LEN`,
/// `PADDING_MAX_LEN`]. Returns `None` if the platform RNG fails —
/// in that case the caller should still send the response without
/// the padding header rather than 500 the request.
pub(in crate::server) fn generate_padding_header() -> Option<(HeaderName, HeaderValue)> {
    let rng = SystemRandom::new();
    let mut len_bytes = [0_u8; 2];
    rng.fill(&mut len_bytes).ok()?;
    let span = u16::from_le_bytes(len_bytes) as usize % (PADDING_MAX_LEN - PADDING_MIN_LEN + 1);
    let len = PADDING_MIN_LEN + span;

    let mut raw = vec![0_u8; len];
    rng.fill(&mut raw).ok()?;
    // Restrict to URL-safe alphanumeric so the value is always a
    // valid HTTP header value (`HeaderValue::from_bytes` rejects
    // CTLs and most non-ASCII). Mapping 0..255 → 0..62 by modulo
    // is fine here — the bias is negligible and the alphabet is
    // visible-only ASCII anyway.
    const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for byte in raw.iter_mut() {
        *byte = ALPHABET[(*byte as usize) % ALPHABET.len()];
    }
    let value = HeaderValue::from_bytes(&raw).ok()?;
    Some((HeaderName::from_static(PADDING_HEADER), value))
}

/// Returns the static set of headers we want every XHTTP GET
/// response to carry, in addition to `X-Padding`. Mimics the
/// shape of a long-lived browser-streamed event source so a
/// passive observer cannot cheaply tell our GET apart from any
/// number of legitimate SSE / chat / sports-score endpoints.
pub(in crate::server) fn masquerade_response_headers() -> [(HeaderName, HeaderValue); 4] {
    [
        (
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/event-stream"),
        ),
        (
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("no-store, no-cache, must-revalidate"),
        ),
        (HeaderName::from_static("pragma"), HeaderValue::from_static("no-cache")),
        // Disables nginx buffering for upstreams behind a reverse
        // proxy — also disables Cloudflare's "Smart Edge" buffering
        // for chunked responses, which is why XHTTP needs it.
        (HeaderName::from_static("x-accel-buffering"), HeaderValue::from_static("no")),
    ]
}

/// Header set for a 200 response on a POST upload (which has no
/// long-lived body). Content-type is `application/octet-stream`
/// because real upload endpoints often answer with a tiny binary
/// ack rather than JSON or HTML.
pub(in crate::server) fn post_response_headers() -> [(HeaderName, HeaderValue); 2] {
    [
        (
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/octet-stream"),
        ),
        (HeaderName::from_static("cache-control"), HeaderValue::from_static("no-store")),
    ]
}
