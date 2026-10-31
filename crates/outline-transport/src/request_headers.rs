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
//! Measured 2026-10-30 against Chrome 156 and Firefox 159 on macOS, same-origin
//! requests (page served by the same server):
//!
//! * Chromium (Chrome, Edge) and Firefox follow their measured tables
//!   exactly, h1 and h2 separately.
//! * **HTTP/3 uses the h2 table** (not measured: Chromium and Gecko build the
//!   h3 header list with the same code as the h2 one).
//! * **Safari is not aligned**: URLSession is not Safari, so its order and
//!   values stay what they were (navigation `Accept`, historical order,
//!   `Sec-Fetch-Dest: websocket` on WebSocket).
//! * No profile ([`crate::fingerprint_profile::Strategy::None`]): no browser
//!   headers at all, only the protocol headers the request needs.
//!
//! Deliberate gaps against the browsers:
//! * xhttp's POST body is binary, so there is no `Content-Type` (a browser
//!   `fetch()` with an `ArrayBuffer` body sends none either; the measured
//!   `text/plain;charset=UTF-8` belongs to a string body).
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
//! * HTTP/1.1 header case is the browser's only where we write the request
//!   ourselves (`ws_h1`, [`h1_wire_name`]); on `xhttp_h1` hyper can only
//!   Title-Case every name, so Chrome's lowercase `sec-ch-ua*` go out as
//!   `Sec-Ch-Ua*`.

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
    /// Uses the h2 table (not measured; see the module docs).
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
    /// emitted only for the aligned families (Chromium, Firefox), at the
    /// browser's position; otherwise hyper appends its own on h2, as before.
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

// ── Safari (not aligned: the historical order and values) ─────────────────────

const SAFARI_FETCH_H1: &[Field] = &[
    F::Host,
    F::ContentLength,
    F::UserAgent,
    F::Accept,
    F::AcceptLanguage,
    F::AcceptEncoding,
    F::SecFetchSite,
    F::SecFetchMode,
    F::SecFetchDest,
];

const SAFARI_FETCH_H2: &[Field] = &[
    F::UserAgent,
    F::Accept,
    F::AcceptLanguage,
    F::AcceptEncoding,
    F::SecFetchSite,
    F::SecFetchMode,
    F::SecFetchDest,
];

/// The five headers tungstenite used to write first, then the profile's.
const SAFARI_WS_H1: &[Field] = &[
    F::Host,
    F::Connection,
    F::Upgrade,
    F::SecWebSocketVersion,
    F::SecWebSocketKey,
    F::UserAgent,
    F::Accept,
    F::AcceptLanguage,
    F::AcceptEncoding,
    F::SecFetchSite,
    F::SecFetchMode,
    F::SecFetchDest,
];

const SAFARI_WS_H2: &[Field] = &[
    F::UserAgent,
    F::Accept,
    F::AcceptLanguage,
    F::AcceptEncoding,
    F::SecFetchSite,
    F::SecFetchMode,
    F::SecFetchDest,
    F::SecWebSocketVersion,
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
        (Some(TlsFingerprint::Firefox), false, false) => FIREFOX_FETCH_H2,
        (Some(TlsFingerprint::Firefox), true, true) => FIREFOX_WS_H1,
        (Some(TlsFingerprint::Firefox), true, false) => FIREFOX_WS_H2,
        (Some(TlsFingerprint::Safari), false, true) => SAFARI_FETCH_H1,
        (Some(TlsFingerprint::Safari), false, false) => SAFARI_FETCH_H2,
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
        F::Accept => {
            let value = match family {
                // Not aligned: Safari keeps its navigation `Accept`.
                Some(TlsFingerprint::Safari) => profile?.accept,
                _ => "*/*",
            };
            pair(header::ACCEPT, st(value))
        },
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
            // Firefox sends `empty` for a WebSocket too; Safari keeps the
            // historical `websocket` (not aligned).
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
                TlsFingerprint::Safari => return None,
            };
            pair(HeaderName::from_static("priority"), st(value))
        },
        F::Te => pair(header::TE, st("trailers")),
        F::Pragma => pair(header::PRAGMA, st("no-cache")),
        F::CacheControl => pair(header::CACHE_CONTROL, st("no-cache")),
        F::SecWebSocketVersion => pair(header::SEC_WEBSOCKET_VERSION, st("13")),
        F::SecWebSocketKey => pair(header::SEC_WEBSOCKET_KEY, slots.websocket_key.clone()?),
        F::SecWebSocketExtensions => {
            let value = match family? {
                TlsFingerprint::Chromium => "permessage-deflate; client_max_window_bits",
                TlsFingerprint::Firefox => "permessage-deflate",
                TlsFingerprint::Safari => return None,
            };
            pair(header::SEC_WEBSOCKET_EXTENSIONS, st(value))
        },
    }
}

/// Whether an HTTP/1.1 request of this profile should be written in the
/// browser's header case. Chromium and Firefox: yes. Safari and no profile
/// keep the historical case (lowercase, apart from the names the HTTP stack
/// spells itself).
pub(crate) fn h1_browser_case(profile: Option<&Profile>) -> bool {
    matches!(profile.map(|p| p.tls), Some(TlsFingerprint::Chromium | TlsFingerprint::Firefox))
}

/// The name of `name` as `profile`'s browser writes it on HTTP/1.1 — for the
/// requests whose bytes we write ourselves (`ws_h1`).
///
/// * Chromium: client hints (`sec-ch-ua*`) lowercase, every other name in
///   its canonical case (`User-Agent`, `Sec-WebSocket-Key`, `X-Outline-Resume`).
/// * Firefox: canonical case throughout.
/// * Safari / no profile: the case tungstenite used to write (`Host`,
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
