//! Browser-shaped HTTP/2 surface of the TCP carriers (`ws_h2`, `xhttp_h2`).
//!
//! A passive observer of an h2 connection (after TLS termination, or a DPI
//! that fingerprints the cleartext-equivalent shape, the "Akamai" h2
//! fingerprint) sees the client SETTINGS (ids, order, values), the
//! connection-level WINDOW_UPDATE right after them, and the order of the
//! request headers. Stock `hyper`/`h2` advertises its own values
//! (`2:0, 4:2097152, 5:16384, 6:16384`, connection window 5 MiB), which no
//! browser sends. This module shapes what `hyper::client::conn::http2::Builder`
//! lets us shape, per browser family of the dial's fingerprint profile
//! ([`crate::fingerprint_profile::current_dial_fingerprint`], `None` ⇒
//! Chromium, exactly like the TLS ClientHello):
//!
//! * SETTINGS values ([`h2_shape`], applied by [`apply_h2_shape`]);
//! * the connection window (hence the connection WINDOW_UPDATE increment);
//! * the order of the profile's regular request headers ([`h2_header_order`]).
//!
//! What stays different from the browsers (needs a vendored `h2`, which the
//! owner declined):
//! * `h2` writes SETTINGS in id order 1,2,3,4,5,6 — Safari's `4` before `3`
//!   cannot be reproduced, and SETTINGS `9` (NO_RFC7540_PRIORITIES, Safari)
//!   is not supported at all;
//! * `hyper` always sends `MAX_HEADER_LIST_SIZE` (6): Firefox and Safari omit
//!   it, we send hyper's default 16384 for them;
//! * pseudo-header order is always `m,s,a,p` (Chrome `m,a,s,p`, Firefox
//!   `m,p,a,s`, Safari `m,s,p,a`), no priority flag on HEADERS, and the first
//!   request stream is 1 (Firefox opens with 3);
//! * the Chrome and Firefox header order was measured on a navigation request
//!   and is applied to the XHR/CORS and WebSocket presets too (fetch / WS
//!   order not measured);
//! * SETTINGS_INITIAL_WINDOW_SIZE (4) and the connection WINDOW_UPDATE are
//!   deliberately NOT browser values: they are the per-carrier defaults
//!   ([`carrier_windows`], the pre-series values: `ws_h2` 8 MiB / 32 MiB,
//!   `xhttp_h2` 2 MiB / 5 MiB, hyper's former defaults). h2 windows are visible
//!   only to the TLS terminator (our server), not to an on-path DPI, and the
//!   browser windows halve `ws_h2` multiplex throughput at 300 ms RTT (see
//!   [`h2_shape`]);
//! * windows an operator sets in `[h2]` override the carrier defaults.

use std::sync::OnceLock;

use hyper::client::conn::http2;

use crate::fingerprint_profile::TlsFingerprint;

use self::BrowserHeader as B;

/// SETTINGS one browser family advertises on an HTTP/2 connection, except
/// the initial stream window and the connection window (see
/// [`carrier_windows`]). `None` means "do not send this SETTINGS id" — except
/// `max_header_list_size`, where `None` means hyper's default (16384), since
/// hyper always sends id 6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct H2Shape {
    /// SETTINGS_HEADER_TABLE_SIZE (1).
    pub(crate) header_table_size: Option<u32>,
    /// SETTINGS_MAX_FRAME_SIZE (5).
    pub(crate) max_frame_size: Option<u32>,
    /// SETTINGS_MAX_HEADER_LIST_SIZE (6); `None` = hyper's default 16384
    /// (hyper cannot omit it).
    pub(crate) max_header_list_size: Option<u32>,
    /// SETTINGS_MAX_CONCURRENT_STREAMS (3).
    pub(crate) max_concurrent_streams: Option<u32>,
}

/// HTTP/2 carrier a connection is built for; selects the default windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum H2Carrier {
    Ws,
    Xhttp,
}

/// `(initial stream window, connection window)` of a carrier, for every
/// browser family. These are the values the carriers advertised before the
/// browser shaping (`ws_h2` 8 MiB / 32 MiB; `xhttp_h2` hyper's 2 MiB / 5 MiB;
/// the connection WINDOW_UPDATE is the window minus 65535). Deliberately NOT
/// the browsers' windows — see [`h2_shape`].
pub(crate) const fn carrier_windows(carrier: H2Carrier) -> (u32, u32) {
    match carrier {
        H2Carrier::Ws => (8_388_608, 33_554_432),
        H2Carrier::Xhttp => (2_097_152, 5_242_880),
    }
}

/// HTTP/2 shape for the browser family `fp` (`None` ⇒ Chromium, the same
/// default the TLS ClientHello uses). Values measured 2026-10-30 against
/// Chrome 156, Firefox 159 and Apple URLSession (macOS 27):
///
/// | family   | SETTINGS on the wire, besides id 4 (ours) |
/// |----------|-------------------------------------------|
/// | Chromium | `1:65536, 2:0, 6:262144`                  |
/// | Firefox  | `1:65536, 2:0, 5:16384, 6:16384`          |
/// | Safari   | `2:0, 3:100, 6:16384`                     |
///
/// Chromium matches Chrome exactly apart from the windows. Firefox deviates
/// in `6:16384` (hyper always sends it; Firefox omits it). Safari deviates in
/// order (`3` before `4`, Safari sends `4` first), in `6:16384` (Safari omits
/// it) and in the missing `9:1` (unsupported by `h2`). `2:0` is hyper's own
/// (push off).
///
/// Windows are NOT browser-shaped (owner decision): SETTINGS_INITIAL_WINDOW_SIZE
/// (4) and the connection WINDOW_UPDATE come from [`carrier_windows`]. They are
/// visible only to the TLS terminator (our server on the fleet), not to an
/// on-path DPI, and browser windows cost throughput. Measured 2026-10-30
/// (ignored `ws_h2_multiplex_throughput` test: hyper h2 server → delay proxy at
/// 300 ms RTT → client, 4 concurrent 48 MiB downloads over ONE connection,
/// release build, 3 runs):
///
/// | windows (stream / connection)        | aggregate MB/s | per flow MB/s |
/// |--------------------------------------|----------------|---------------|
/// | Chromium 6291456 / 15728640          | 36.0 - 40.7    | 9.0 - 10.2    |
/// | ws_h2 default 8388608 / 33554432     | 71.5 - 72.2    | 17.9 - 18.1   |
///
/// The 15 MiB browser connection window (~52 MB/s at 300 ms) halves multiplex
/// throughput. A bare Firefox 128 KiB stream window is far worse (single
/// stream, `firefox_stream_window_throughput`: 2.0 vs 79-81 MB/s at 50 ms), and
/// Firefox's real per-stream WINDOW_UPDATE to ~12.5 MiB cannot be sent by
/// hyper, so no browser stream window is used.
pub(crate) fn h2_shape(fp: Option<TlsFingerprint>) -> H2Shape {
    match fp.unwrap_or(TlsFingerprint::Chromium) {
        TlsFingerprint::Chromium => H2Shape {
            header_table_size: Some(65_536),
            max_frame_size: None,
            max_header_list_size: Some(262_144),
            max_concurrent_streams: None,
        },
        TlsFingerprint::Firefox => H2Shape {
            header_table_size: Some(65_536),
            max_frame_size: Some(16_384),
            max_header_list_size: None,
            max_concurrent_streams: None,
        },
        TlsFingerprint::Safari => H2Shape {
            header_table_size: None,
            max_frame_size: None,
            max_header_list_size: None,
            max_concurrent_streams: Some(100),
        },
    }
}

/// Windows the operator set in `[h2]`, as `(stream, connection)`; each
/// overrides the carrier's default window independently. `(None, None)` =
/// carrier defaults.
pub(crate) type OperatorWindows = (Option<u32>, Option<u32>);

/// Configure `builder` with `shape` and the `carrier`'s default windows,
/// letting the operator's `[h2]` windows win. Also pins `adaptive_window(false)`
/// (hyper's default, made explicit): with BDP probing on, hyper would
/// advertise the RFC 65535 windows instead of the configured ones.
pub(crate) fn apply_h2_shape<E: Clone>(
    builder: &mut http2::Builder<E>,
    shape: &H2Shape,
    carrier: H2Carrier,
    operator: OperatorWindows,
) {
    let (default_stream, default_connection) = carrier_windows(carrier);
    let (stream, connection) = operator;
    builder
        .adaptive_window(false)
        .initial_stream_window_size(stream.unwrap_or(default_stream))
        .initial_connection_window_size(connection.unwrap_or(default_connection))
        .header_table_size(shape.header_table_size)
        // `None` clears hyper's default `Some(16384)`, so id 5 is not sent.
        .max_frame_size(shape.max_frame_size)
        .max_concurrent_streams(shape.max_concurrent_streams);
    if let Some(size) = shape.max_header_list_size {
        builder.max_header_list_size(size);
    }
}

// ── Operator windows ([h2]) ───────────────────────────────────────────────────

static H2_OPERATOR_STREAM_WINDOW: OnceLock<Option<u32>> = OnceLock::new();
static H2_OPERATOR_CONNECTION_WINDOW: OnceLock<Option<u32>> = OnceLock::new();

/// Wire the `[h2]` window overrides from config. `None` keeps the value of
/// the carrier's default ([`carrier_windows`]); `Some` overrides it on every
/// HTTP/2 carrier (`ws_h2` and `xhttp_h2`). First call wins; must run before
/// the first outbound h2 connection.
pub fn init_h2_window_sizes(stream: Option<u32>, connection: Option<u32>) {
    H2_OPERATOR_STREAM_WINDOW.get_or_init(|| stream);
    H2_OPERATOR_CONNECTION_WINDOW.get_or_init(|| connection);
}

/// The `[h2]` window overrides wired by [`init_h2_window_sizes`].
pub(crate) fn operator_windows() -> OperatorWindows {
    (
        H2_OPERATOR_STREAM_WINDOW.get().copied().flatten(),
        H2_OPERATOR_CONNECTION_WINDOW.get().copied().flatten(),
    )
}

/// Configure a fresh client `builder` for the current dial: the shape of the
/// dial-scoped browser family, the carrier's default windows and the
/// operator's `[h2]` windows.
pub(crate) fn apply_dial_h2_shape<E: Clone>(builder: &mut http2::Builder<E>, carrier: H2Carrier) {
    let shape = h2_shape(crate::fingerprint_profile::current_dial_fingerprint());
    apply_h2_shape(builder, &shape, carrier, operator_windows());
}

// ── Header order ──────────────────────────────────────────────────────────────

/// A browser identification header a [`crate::fingerprint_profile::Profile`]
/// contributes to a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BrowserHeader {
    UserAgent,
    Accept,
    AcceptLanguage,
    AcceptEncoding,
    SecChUa,
    SecChUaMobile,
    SecChUaPlatform,
    SecFetchSite,
    SecFetchMode,
    SecFetchDest,
}

/// Historical insertion order of [`crate::fingerprint_profile::apply`]
/// (h1 and h3 carriers). Also Safari's order on h2: its real header order was
/// not measured, so the profile keeps the current one.
pub(crate) const LEGACY_HEADER_ORDER: &[BrowserHeader] = &[
    B::UserAgent,
    B::Accept,
    B::AcceptLanguage,
    B::AcceptEncoding,
    B::SecChUa,
    B::SecChUaMobile,
    B::SecChUaPlatform,
    B::SecFetchSite,
    B::SecFetchMode,
    B::SecFetchDest,
];

/// Chrome and Firefox orders below were measured on a navigation request and
/// are applied to the XHR/CORS and WebSocket presets too; the fetch / WebSocket
/// header order was not measured.
///
/// Chrome 156 (measured): `sec-ch-ua`, `-mobile`, `-platform`, `user-agent`,
/// `accept`, `sec-fetch-site`, `-mode`, `-dest`, `accept-encoding`,
/// `accept-language` (navigation-only headers we do not send left out).
const CHROMIUM_HEADER_ORDER: &[BrowserHeader] = &[
    B::SecChUa,
    B::SecChUaMobile,
    B::SecChUaPlatform,
    B::UserAgent,
    B::Accept,
    B::SecFetchSite,
    B::SecFetchMode,
    B::SecFetchDest,
    B::AcceptEncoding,
    B::AcceptLanguage,
];

/// Firefox 159 (measured): `user-agent`, `accept`, `accept-language`,
/// `accept-encoding`, `sec-fetch-dest`, `-mode`, `-site`. No client hints.
const FIREFOX_HEADER_ORDER: &[BrowserHeader] = &[
    B::UserAgent,
    B::Accept,
    B::AcceptLanguage,
    B::AcceptEncoding,
    B::SecFetchDest,
    B::SecFetchMode,
    B::SecFetchSite,
    // Never emitted for Firefox profiles (no client hints); listed so the
    // table covers every header.
    B::SecChUa,
    B::SecChUaMobile,
    B::SecChUaPlatform,
];

/// Order in which the profile headers of a browser family are inserted on an
/// h2 request. `hyper`/`h2` encode regular headers in `HeaderMap` iteration
/// (= insertion) order, so this is the order on the wire. Carrier-specific
/// headers (`sec-websocket-*`, `x-outline-*`) are inserted after these.
pub(crate) fn h2_header_order(fp: TlsFingerprint) -> &'static [BrowserHeader] {
    match fp {
        TlsFingerprint::Chromium => CHROMIUM_HEADER_ORDER,
        TlsFingerprint::Firefox => FIREFOX_HEADER_ORDER,
        TlsFingerprint::Safari => LEGACY_HEADER_ORDER,
    }
}

#[cfg(test)]
#[path = "tests/h2_profile.rs"]
mod tests;
