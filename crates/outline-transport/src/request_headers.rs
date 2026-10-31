//! Browser request headers of the carriers, per request kind and HTTP version.
//!
//! A carrier request is one of three things a page really makes: `xhttp`'s
//! downlink GET is a `fetch()` GET, its uplink POST a `fetch()` POST, and the
//! `ws_*` carriers open a WebSocket (HTTP/1.1 upgrade, or an extended CONNECT
//! on h2 / h3). Chrome and Firefox send a different header set, order and
//! values for each kind, and a different one again on HTTP/1.1 than on h2.
//! [`browser_headers`] lays out the profile browser's headers for the
//! request the carrier actually makes, with the carrier's own protocol
//! headers (`Host`, `Content-Length`, `Sec-WebSocket-Key`) at the position
//! the browser puts them; the carrier's custom headers (`X-Outline-*`,
//! `X-Xhttp-Fin`) are appended by the caller afterwards, the way a page's
//! custom headers trail the browser's own.
//!
//! Measured against Chrome 156 and Firefox 159 (2026-10-30) and Safari 27.0.1
//! (2026-10-31) on macOS, same-origin requests (page served by the same
//! server):
//!
//! * Chromium (Chrome, Edge), Firefox and Safari follow their measured tables
//!   exactly, h1 and h2 separately. Safari's fetch GET and POST differ in
//!   order, so it has a table per request kind; Safari 27 opens a WebSocket
//!   over h2 as an RFC 8441 extended CONNECT.
//! * **HTTP/3** (Chrome 156, Firefox 159 measured): Chromium sends exactly the
//!   h2 headers, so it uses the h2 table. Firefox's fetch is the h2 set minus
//!   `te: trailers` plus `alt-used: <authority>` right before
//!   `sec-fetch-dest` (an `alt-used` on port 443 written without the port is
//!   an assumption). Firefox's WebSocket did not go over h3 (kept on the h2
//!   table), and Safari's h3 is not measured (assumed to be its h2 tables).
//! * No profile ([`crate::fingerprint_profile::Strategy::None`]): no browser
//!   headers at all, only the protocol headers the request needs.
//!
//! Deliberate gaps against the browsers:
//! * xhttp's POST body is binary, so there is no `Content-Type`. This is
//!   measured, not a gap: a `fetch()` POST with a binary body sends none in
//!   Chrome, Firefox and Safari on h1, h2 and h3 alike
//!   (`text/plain;charset=UTF-8` appears only for a string body).
//! * `Referer` is the site root (`<origin>/`): the carrier has no page path.
//! * `Sec-WebSocket-Extensions` offers `permessage-deflate` like the
//!   browsers, but this client does not implement it, so it relies on the
//!   server never accepting it. That holds by code, not by build features
//!   (cargo feature unification turns `sockudo-ws`'s default
//!   `permessage-deflate` on in workspace builds): the h3 upgrade answers
//!   with `build_extended_connect_response(_, None)` (no extensions), the
//!   server's `sockudo-ws` `Config` keeps the default
//!   `compression: Compression::Disabled`, and axum's `WebSocketUpgrade`
//!   never echoes the header. A handshake response that does accept an
//!   extension is rejected by the client rather than misread.
//! * HTTP/1.1 header case is the browser's ([`h1_wire_name`]): `ws_h1`
//!   writes the request bytes itself, and `xhttp_h1` hands hyper a per-name
//!   case map through the patched hyper API (`crate::hyper_vendored`).

use std::borrow::Cow;

use http::{HeaderMap, HeaderName, HeaderValue, header};

use crate::fingerprint_profile::{Profile, TlsFingerprint};

/// What the carrier request is, in browser terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestKind {
    /// `fetch(url)` — xhttp's downlink GET.
    FetchGet,
    /// `fetch(url, { method: 'POST', body })` — xhttp's uplink / stream-one POST.
    FetchPost,
    /// `new WebSocket(url)` — the `ws_*` carriers.
    WebSocket,
}

/// HTTP version the request goes out on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HttpVersion {
    H1,
    H2,
    /// Chromium and Safari use their h2 tables; Firefox's fetch has its own
    /// (see the module docs).
    #[cfg_attr(not(feature = "h3"), allow(dead_code))]
    H3,
}

/// Carrier-owned header values that sit at a browser position. Each is
/// emitted only where the request's table has a slot for it.
#[derive(Clone, Debug, Default)]
pub(crate) struct CarrierSlots {
    /// `Host` — HTTP/1.1 only (h2 / h3 carry `:authority`).
    pub(crate) host: Option<HeaderValue>,
    /// `Content-Length` of a POST with a known body size. On h2 / h3 it is
    /// emitted only when a browser profile is set, at the browser's
    /// position; otherwise hyper appends its own on h2, as before.
    pub(crate) content_length: Option<HeaderValue>,
    /// `Sec-WebSocket-Key` of an HTTP/1.1 upgrade.
    pub(crate) websocket_key: Option<HeaderValue>,
}

/// One header of a request table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    Host,
    Connection,
    Upgrade,
    ContentLength,
    SecChUa,
    SecChUaMobile,
    SecChUaPlatform,
    UserAgent,
    Accept,
    Origin,
    Referer,
    SecFetchSite,
    SecFetchMode,
    SecFetchDest,
    AcceptEncoding,
    AcceptLanguage,
    Priority,
    Te,
    AltUsed,
    Pragma,
    CacheControl,
    SecWebSocketVersion,
    SecWebSocketKey,
    SecWebSocketExtensions,
}

use Field as F;

// ── Chromium (Chrome 156; Edge shares the Chromium network stack) ────────────
//
// Fetch tables cover GET and POST: `Content-Length` and `Origin` are emitted
// for a POST only (and `Content-Type`, which Chrome puts between `sec-ch-ua`
// and `sec-ch-ua-mobile`, is never sent — see the module docs).

const CHROMIUM_FETCH_H1: &[Field] = &[
    F::Host,
    F::Connection,
    F::ContentLength,
    F::SecChUaPlatform,
    F::UserAgent,
    F::SecChUa,
    F::SecChUaMobile,
    F::Accept,
    F::Origin,
    F::SecFetchSite,
    F::SecFetchMode,
    F::SecFetchDest,
    F::Referer,
    F::AcceptEncoding,
    F::AcceptLanguage,
];

const CHROMIUM_FETCH_H2: &[Field] = &[
    F::ContentLength,
    F::SecChUaPlatform,
    F::UserAgent,
    F::SecChUa,
    F::SecChUaMobile,
    F::Accept,
    F::Origin,
    F::SecFetchSite,
    F::SecFetchMode,
    F::SecFetchDest,
    F::Referer,
    F::AcceptEncoding,
    F::AcceptLanguage,
    F::Priority,
];

/// Chrome's WebSocket requests carry no client hints, no `Sec-Fetch-*` and
/// no `Accept`.
const CHROMIUM_WS_H1: &[Field] = &[
    F::Host,
    F::Connection,
    F::Pragma,
    F::CacheControl,
    F::UserAgent,
    F::Upgrade,
    F::Origin,
    F::SecWebSocketVersion,
    F::AcceptEncoding,
    F::AcceptLanguage,
    F::SecWebSocketKey,
    F::SecWebSocketExtensions,
];

const CHROMIUM_WS_H2: &[Field] = &[
    F::Pragma,
    F::CacheControl,
    F::UserAgent,
    F::Origin,
    F::SecWebSocketVersion,
    F::AcceptEncoding,
    F::AcceptLanguage,
    F::SecWebSocketExtensions,
];

// ── Firefox 159 ───────────────────────────────────────────────────────────────

const FIREFOX_FETCH_H1: &[Field] = &[
    F::Host,
    F::UserAgent,
    F::Accept,
    F::AcceptLanguage,
    F::AcceptEncoding,
    F::Referer,
    F::ContentLength,
    F::Origin,
    F::Connection,
    F::SecFetchDest,
    F::SecFetchMode,
    F::SecFetchSite,
    F::Priority,
];

const FIREFOX_FETCH_H2: &[Field] = &[
    F::UserAgent,
    F::Accept,
    F::AcceptLanguage,
    F::AcceptEncoding,
    F::Referer,
    F::ContentLength,
    F::Origin,
    F::SecFetchDest,
    F::SecFetchMode,
    F::SecFetchSite,
    F::Priority,
    F::Te,
];

/// Firefox 159 over h3: the h2 set without `te`, plus `alt-used` (the
/// authority the connection was reached through) before `sec-fetch-dest`.
const FIREFOX_FETCH_H3: &[Field] = &[
    F::UserAgent,
    F::Accept,
    F::AcceptLanguage,
    F::AcceptEncoding,
    F::Referer,
    F::ContentLength,
    F::Origin,
    F::AltUsed,
    F::SecFetchDest,
    F::SecFetchMode,
    F::SecFetchSite,
    F::Priority,
];

const FIREFOX_WS_H1: &[Field] = &[
    F::Host,
    F::UserAgent,
    F::Accept,
    F::AcceptLanguage,
    F::AcceptEncoding,
    F::SecWebSocketVersion,
    F::Origin,
    F::SecWebSocketExtensions,
    F::SecWebSocketKey,
    F::Connection,
    F::SecFetchDest,
    F::SecFetchMode,
    F::SecFetchSite,
    F::Pragma,
    F::CacheControl,
    F::Upgrade,
];

const FIREFOX_WS_H2: &[Field] = &[
    F::UserAgent,
    F::Accept,
    F::AcceptLanguage,
    F::AcceptEncoding,
    F::SecWebSocketVersion,
    F::Origin,
    F::SecWebSocketExtensions,
    F::SecFetchDest,
    F::SecFetchMode,
    F::SecFetchSite,
    F::Pragma,
    F::CacheControl,
];

// ── Safari 27.0.1 (2026-10-31) ────────────────────────────────────────────────
//
// GET and POST differ in order, hence a table per fetch kind.

const SAFARI_FETCH_GET_H1: &[Field] = &[
    F::Host,
    F::SecFetchDest,
    F::UserAgent,
    F::Accept,
    F::Referer,
    F::SecFetchSite,
    F::SecFetchMode,
    F::AcceptLanguage,
    F::Priority,
    F::AcceptEncoding,
    F::Connection,
];

const SAFARI_FETCH_POST_H1: &[Field] = &[
    F::Host,
    F::Accept,
    F::Origin,
    F::SecFetchSite,
    F::SecFetchMode,
    F::UserAgent,
    F::Referer,
    F::SecFetchDest,
    F::ContentLength,
    F::AcceptLanguage,
    F::Priority,
    F::AcceptEncoding,
    F::Connection,
];

const SAFARI_FETCH_GET_H2: &[Field] = &[
    F::SecFetchDest,
    F::UserAgent,
    F::Accept,
    F::Referer,
    F::SecFetchSite,
    F::SecFetchMode,
    F::AcceptLanguage,
    F::Priority,
    F::AcceptEncoding,
];

const SAFARI_FETCH_POST_H2: &[Field] = &[
    F::Accept,
    F::Origin,
    F::SecFetchSite,
    F::SecFetchMode,
    F::UserAgent,
    F::Referer,
    F::SecFetchDest,
    F::ContentLength,
    F::AcceptLanguage,
    F::Priority,
    F::AcceptEncoding,
];

const SAFARI_WS_H1: &[Field] = &[
    F::Host,
    F::Origin,
    F::Pragma,
    F::SecFetchSite,
    F::SecWebSocketVersion,
    F::SecFetchMode,
    F::UserAgent,
    F::SecWebSocketExtensions,
    F::CacheControl,
    F::SecFetchDest,
    F::Accept,
    F::AcceptLanguage,
    F::Priority,
    F::AcceptEncoding,
    F::SecWebSocketKey,
    F::Connection,
    F::Upgrade,
];

const SAFARI_WS_H2: &[Field] = &[
    F::Origin,
    F::Pragma,
    F::SecFetchSite,
    F::SecWebSocketVersion,
    F::SecFetchMode,
    F::UserAgent,
    F::SecWebSocketExtensions,
    F::CacheControl,
    F::SecFetchDest,
    F::Accept,
    F::AcceptLanguage,
    F::Priority,
    F::AcceptEncoding,
];

// ── No profile: protocol headers only ─────────────────────────────────────────

const BARE_FETCH_H1: &[Field] = &[F::Host, F::ContentLength];
const BARE_FETCH_H2: &[Field] = &[];
const BARE_WS_H1: &[Field] =
    &[F::Host, F::Connection, F::Upgrade, F::SecWebSocketVersion, F::SecWebSocketKey];
const BARE_WS_H2: &[Field] = &[F::SecWebSocketVersion];

fn table(
    family: Option<TlsFingerprint>,
    kind: RequestKind,
    version: HttpVersion,
) -> &'static [Field] {
    let ws = kind == RequestKind::WebSocket;
    let h1 = version == HttpVersion::H1;
    match (family, ws, h1) {
        (Some(TlsFingerprint::Chromium), false, true) => CHROMIUM_FETCH_H1,
        (Some(TlsFingerprint::Chromium), false, false) => CHROMIUM_FETCH_H2,
        (Some(TlsFingerprint::Chromium), true, true) => CHROMIUM_WS_H1,
        (Some(TlsFingerprint::Chromium), true, false) => CHROMIUM_WS_H2,
        (Some(TlsFingerprint::Firefox), false, true) => FIREFOX_FETCH_H1,
        (Some(TlsFingerprint::Firefox), false, false) if version == HttpVersion::H3 => {
            FIREFOX_FETCH_H3
        },
        (Some(TlsFingerprint::Firefox), false, false) => FIREFOX_FETCH_H2,
        (Some(TlsFingerprint::Firefox), true, true) => FIREFOX_WS_H1,
        (Some(TlsFingerprint::Firefox), true, false) => FIREFOX_WS_H2,
        (Some(TlsFingerprint::Safari), false, true) => match kind {
            RequestKind::FetchPost => SAFARI_FETCH_POST_H1,
            _ => SAFARI_FETCH_GET_H1,
        },
        (Some(TlsFingerprint::Safari), false, false) => match kind {
            RequestKind::FetchPost => SAFARI_FETCH_POST_H2,
            _ => SAFARI_FETCH_GET_H2,
        },
        (Some(TlsFingerprint::Safari), true, true) => SAFARI_WS_H1,
        (Some(TlsFingerprint::Safari), true, false) => SAFARI_WS_H2,
        (None, false, true) => BARE_FETCH_H1,
        (None, false, false) => BARE_FETCH_H2,
        (None, true, true) => BARE_WS_H1,
        (None, true, false) => BARE_WS_H2,
    }
}

/// `scheme://authority` of the site the request claims to come from
/// (same-origin: the carrier's own server). `authority` is `host[:port]`
/// without the scheme's default port, as a browser writes it.
pub(crate) fn web_origin(secure: bool, authority: &str) -> String {
    let scheme = if secure { "https" } else { "http" };
    format!("{scheme}://{authority}")
}

/// [`web_origin`] of a request URI (`https://host:443/path` →
/// `https://host`). `ws`/`wss` map to `http`/`https`. `None` when the URI
/// has no authority.
pub(crate) fn web_origin_of_uri(uri: &http::Uri) -> Option<String> {
    let authority = uri.authority()?;
    let secure = matches!(uri.scheme_str(), Some("https" | "wss"));
    let default_port = if secure { 443 } else { 80 };
    let authority = match authority.port_u16() {
        Some(port) if port != default_port => format!("{}:{port}", authority.host()),
        _ => authority.host().to_owned(),
    };
    Some(web_origin(secure, &authority))
}

/// Append to `headers` the request headers `profile`'s browser sends for a
/// `kind` request over `version`, in its order, with the carrier's `slots`
/// at the browser's positions. `origin` is [`web_origin`] of the request's
/// own authority (`Origin` / `Referer`). `profile = None` emits only the
/// protocol headers the request needs (no browser identity at all).
///
/// `hyper`/`h2`/`h3` encode regular headers in `HeaderMap` insertion order,
/// so this is the order on the wire; call it on an empty map and append the
/// carrier's custom headers afterwards.
pub(crate) fn browser_headers(
    profile: Option<&Profile>,
    kind: RequestKind,
    version: HttpVersion,
    origin: &str,
    slots: &CarrierSlots,
    headers: &mut HeaderMap,
) {
    let family = profile.map(|p| p.tls);
    for field in table(family, kind, version) {
        if let Some((name, value)) = field_value(*field, profile, kind, origin, slots) {
            headers.insert(name, value);
        }
    }
}

fn field_value(
    field: Field,
    profile: Option<&Profile>,
    kind: RequestKind,
    origin: &str,
    slots: &CarrierSlots,
) -> Option<(HeaderName, HeaderValue)> {
    let ws = kind == RequestKind::WebSocket;
    let family = profile.map(|p| p.tls);
    let st = HeaderValue::from_static;
    let pair = |name: HeaderName, value: HeaderValue| Some((name, value));
    match field {
        F::Host => pair(header::HOST, slots.host.clone()?),
        F::Connection => pair(header::CONNECTION, st(if ws { "Upgrade" } else { "keep-alive" })),
        F::Upgrade => pair(header::UPGRADE, st("websocket")),
        F::ContentLength => {
            if kind != RequestKind::FetchPost {
                return None;
            }
            pair(header::CONTENT_LENGTH, slots.content_length.clone()?)
        },
        F::SecChUa => pair(HeaderName::from_static("sec-ch-ua"), st(profile?.sec_ch_ua?)),
        F::SecChUaMobile => {
            pair(HeaderName::from_static("sec-ch-ua-mobile"), st(profile?.sec_ch_ua_mobile?))
        },
        F::SecChUaPlatform => {
            pair(HeaderName::from_static("sec-ch-ua-platform"), st(profile?.sec_ch_ua_platform?))
        },
        F::UserAgent => pair(header::USER_AGENT, st(profile?.user_agent)),
        F::Accept => pair(header::ACCEPT, st("*/*")),
        F::Origin => {
            if kind == RequestKind::FetchGet {
                return None;
            }
            pair(header::ORIGIN, HeaderValue::try_from(origin).ok()?)
        },
        F::Referer => {
            if ws {
                return None;
            }
            pair(header::REFERER, HeaderValue::try_from(format!("{origin}/")).ok()?)
        },
        F::SecFetchSite => pair(HeaderName::from_static("sec-fetch-site"), st("same-origin")),
        F::SecFetchMode => pair(
            HeaderName::from_static("sec-fetch-mode"),
            st(if ws { "websocket" } else { "cors" }),
        ),
        F::SecFetchDest => {
            // Firefox sends `empty` for a WebSocket too; Safari sends
            // `websocket` (measured).
            let dest = if ws && family == Some(TlsFingerprint::Safari) {
                "websocket"
            } else {
                "empty"
            };
            pair(HeaderName::from_static("sec-fetch-dest"), st(dest))
        },
        F::AcceptEncoding => pair(header::ACCEPT_ENCODING, st(profile?.accept_encoding)),
        F::AcceptLanguage => pair(header::ACCEPT_LANGUAGE, st(profile?.accept_language)),
        F::Priority => {
            let value = match family? {
                TlsFingerprint::Chromium => "u=1, i",
                TlsFingerprint::Firefox => "u=4",
                TlsFingerprint::Safari => "u=3, i",
            };
            pair(HeaderName::from_static("priority"), st(value))
        },
        F::Te => pair(header::TE, st("trailers")),
        F::AltUsed => {
            let authority = origin.split_once("://").map_or(origin, |(_, rest)| rest);
            pair(HeaderName::from_static("alt-used"), HeaderValue::try_from(authority).ok()?)
        },
        F::Pragma => pair(header::PRAGMA, st("no-cache")),
        F::CacheControl => pair(header::CACHE_CONTROL, st("no-cache")),
        F::SecWebSocketVersion => pair(header::SEC_WEBSOCKET_VERSION, st("13")),
        F::SecWebSocketKey => pair(header::SEC_WEBSOCKET_KEY, slots.websocket_key.clone()?),
        F::SecWebSocketExtensions => {
            let value = match family? {
                TlsFingerprint::Chromium => "permessage-deflate; client_max_window_bits",
                TlsFingerprint::Firefox => "permessage-deflate",
                TlsFingerprint::Safari => "permessage-deflate",
            };
            pair(header::SEC_WEBSOCKET_EXTENSIONS, st(value))
        },
    }
}

/// Whether an HTTP/1.1 request of this profile should be written in the
/// browser's header case. Every profile: yes. No profile keeps the
/// historical case (lowercase, apart from the names the HTTP stack spells
/// itself).
pub(crate) fn h1_browser_case(profile: Option<&Profile>) -> bool {
    profile.is_some()
}

/// The name of `name` as `profile`'s browser writes it on HTTP/1.1 — for
/// `ws_h1`, which writes the request bytes itself, and `xhttp_h1`'s hyper case
/// map (`crate::hyper_vendored`).
///
/// * Chromium: client hints (`sec-ch-ua*`) lowercase, every other name in
///   its canonical case (`User-Agent`, `Sec-WebSocket-Key`, `X-Outline-Resume`).
/// * Firefox, Safari: canonical case throughout.
/// * No profile: the case tungstenite used to write (`Host`,
///   `Connection`, `Upgrade`, `Sec-WebSocket-Version`, `Sec-WebSocket-Key`,
///   `Origin`, `Sec-WebSocket-Protocol`; everything else lowercase).
pub(crate) fn h1_wire_name<'a>(name: &'a HeaderName, profile: Option<&Profile>) -> Cow<'a, str> {
    let lower = name.as_str();
    if !h1_browser_case(profile) {
        return match lower {
            "host" => Cow::Borrowed("Host"),
            "connection" => Cow::Borrowed("Connection"),
            "upgrade" => Cow::Borrowed("Upgrade"),
            "sec-websocket-version" => Cow::Borrowed("Sec-WebSocket-Version"),
            "sec-websocket-key" => Cow::Borrowed("Sec-WebSocket-Key"),
            "sec-websocket-protocol" => Cow::Borrowed("Sec-WebSocket-Protocol"),
            "origin" => Cow::Borrowed("Origin"),
            _ => Cow::Borrowed(lower),
        };
    }
    if profile.map(|p| p.tls) == Some(TlsFingerprint::Chromium) && lower.starts_with("sec-ch-ua") {
        return Cow::Borrowed(lower);
    }
    Cow::Owned(canonical_case(lower))
}

/// `user-agent` → `User-Agent`; the `websocket` segment of a `sec-websocket-*`
/// name is `WebSocket`, as every browser spells it.
fn canonical_case(lower: &str) -> String {
    let websocket = lower.starts_with("sec-websocket-");
    let mut out = String::with_capacity(lower.len());
    for (i, segment) in lower.split('-').enumerate() {
        if i > 0 {
            out.push('-');
        }
        if websocket && i == 1 {
            out.push_str("WebSocket");
            continue;
        }
        let mut chars = segment.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.push_str(chars.as_str());
        }
    }
    out
}

/// Serialise an HTTP/1.1 request head: request line, then `headers` in map
/// order, each name in [`h1_wire_name`] case.
pub(crate) fn encode_h1_request_head(
    method: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    profile: Option<&Profile>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1024);
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(path_and_query.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in headers {
        out.extend_from_slice(h1_wire_name(name, profile).as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

#[cfg(test)]
#[path = "tests/request_headers.rs"]
mod tests;
