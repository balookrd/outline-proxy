//! Tests for [`crate::request_headers`]: the per browser × request kind ×
//! HTTP version tables against the measured browser requests
//! ([`crate::tests::measured_browser_headers`]), the Safari snapshot, the
//! no-profile case and the HTTP/1.1 header case. The headers as they really
//! leave the HTTP stacks are checked in `tests/h2_profile.rs` (h2, decoded by
//! a hyper server), `tests/ws_h1.rs` (`ws_h1` raw bytes) and
//! `xhttp/tests/post_headers.rs` (`xhttp_h1` raw bytes through hyper).

use http::{HeaderMap, HeaderName, HeaderValue};

use super::{
    CarrierSlots, HttpVersion, RequestKind, browser_headers, canonical_case,
    encode_h1_request_head, h1_wire_name, web_origin, web_origin_of_uri,
};
use crate::fingerprint_profile::{PROFILES, Profile, TlsFingerprint};
use crate::tests::{
    MEASURED_AUTHORITY, MEASURED_CONTENT_LENGTH, MEASURED_ORIGIN, MEASURED_WS_KEY, MeasuredKind,
    header_pairs, lowercased, measured_browser_headers, measured_profiles,
};

const KINDS: [(RequestKind, MeasuredKind); 3] = [
    (RequestKind::FetchGet, MeasuredKind::FetchGet),
    (RequestKind::FetchPost, MeasuredKind::FetchPost),
    (RequestKind::WebSocket, MeasuredKind::WebSocket),
];

/// The slots every carrier fills for this request (the h2/h3 call sites pass
/// `Content-Length` for a packet-up POST too; the tables decide where it goes).
fn slots(kind: RequestKind, version: HttpVersion) -> CarrierSlots {
    let h1 = version == HttpVersion::H1;
    CarrierSlots {
        host: h1.then(|| HeaderValue::from_static(MEASURED_AUTHORITY)),
        content_length: (kind == RequestKind::FetchPost)
            .then(|| HeaderValue::from_static(MEASURED_CONTENT_LENGTH)),
        websocket_key: (h1 && kind == RequestKind::WebSocket)
            .then(|| HeaderValue::from_static(MEASURED_WS_KEY)),
    }
}

fn render(
    profile: Option<&Profile>,
    kind: RequestKind,
    version: HttpVersion,
) -> Vec<(String, String)> {
    let mut headers = HeaderMap::new();
    browser_headers(profile, kind, version, MEASURED_ORIGIN, &slots(kind, version), &mut headers);
    header_pairs(&headers)
}

#[test]
fn chromium_and_firefox_follow_the_measured_requests() {
    for profile in measured_profiles() {
        for (kind, measured) in KINDS {
            for version in [HttpVersion::H1, HttpVersion::H2, HttpVersion::H3] {
                let h1 = version == HttpVersion::H1;
                // h3 uses the h2 table (not measured).
                let expected = lowercased(measured_browser_headers(profile, measured, h1));
                assert_eq!(
                    render(Some(profile), kind, version),
                    expected,
                    "profile={} kind={kind:?} version={version:?}",
                    profile.name
                );
            }
        }
    }
}

#[test]
fn chrome_websocket_carries_no_client_hints_fetch_metadata_or_accept() {
    let chrome = PROFILES.iter().find(|p| p.tls == TlsFingerprint::Chromium).unwrap();
    for version in [HttpVersion::H1, HttpVersion::H2, HttpVersion::H3] {
        let names: Vec<String> = render(Some(chrome), RequestKind::WebSocket, version)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        for absent in ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "accept", "referer"] {
            assert!(!names.iter().any(|n| n == absent), "{absent} on {version:?}: {names:?}");
        }
        assert!(!names.iter().any(|n| n.starts_with("sec-fetch-")), "{version:?}: {names:?}");
    }
}

/// Safari is not aligned: its header set, order and values are exactly the
/// historical ones (navigation `Accept`, `Sec-Fetch-Dest: websocket` on a
/// WebSocket, no `Origin`/`Referer`/`Priority`/`Pragma`, no
/// `Sec-WebSocket-Extensions`).
#[test]
fn safari_keeps_the_historical_headers() {
    let safari = PROFILES.iter().find(|p| p.tls == TlsFingerprint::Safari).unwrap();
    let identity = |mode: &str, dest: &str| -> Vec<(String, String)> {
        [
            ("user-agent", safari.user_agent),
            ("accept", safari.accept),
            ("accept-language", safari.accept_language),
            ("accept-encoding", safari.accept_encoding),
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-mode", mode),
            ("sec-fetch-dest", dest),
        ]
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
    };
    let pair = |n: &str, v: &str| (n.to_owned(), v.to_owned());

    // h1 fetch: Host, (Content-Length), identity.
    let mut get = vec![pair("host", MEASURED_AUTHORITY)];
    get.extend(identity("cors", "empty"));
    assert_eq!(render(Some(safari), RequestKind::FetchGet, HttpVersion::H1), get);
    let mut post = vec![pair("host", MEASURED_AUTHORITY), pair("content-length", "4")];
    post.extend(identity("cors", "empty"));
    assert_eq!(render(Some(safari), RequestKind::FetchPost, HttpVersion::H1), post);

    // h2/h3 fetch: identity only (hyper appends `content-length` on h2).
    for version in [HttpVersion::H2, HttpVersion::H3] {
        for kind in [RequestKind::FetchGet, RequestKind::FetchPost] {
            assert_eq!(render(Some(safari), kind, version), identity("cors", "empty"), "{kind:?}");
        }
    }

    // h1 WebSocket: tungstenite's five, then identity.
    let mut ws = vec![
        pair("host", MEASURED_AUTHORITY),
        pair("connection", "Upgrade"),
        pair("upgrade", "websocket"),
        pair("sec-websocket-version", "13"),
        pair("sec-websocket-key", MEASURED_WS_KEY),
    ];
    ws.extend(identity("websocket", "websocket"));
    assert_eq!(render(Some(safari), RequestKind::WebSocket, HttpVersion::H1), ws);

    // h2/h3 WebSocket: identity, then `sec-websocket-version`.
    let mut ws = identity("websocket", "websocket");
    ws.push(pair("sec-websocket-version", "13"));
    for version in [HttpVersion::H2, HttpVersion::H3] {
        assert_eq!(render(Some(safari), RequestKind::WebSocket, version), ws);
    }
}

/// `Strategy::None`: no browser header at all, only what the protocol needs.
#[test]
fn no_profile_emits_only_protocol_headers() {
    let pair = |n: &str, v: &str| (n.to_owned(), v.to_owned());
    assert_eq!(
        render(None, RequestKind::FetchGet, HttpVersion::H1),
        vec![pair("host", MEASURED_AUTHORITY)]
    );
    assert_eq!(
        render(None, RequestKind::FetchPost, HttpVersion::H1),
        vec![pair("host", MEASURED_AUTHORITY), pair("content-length", "4")]
    );
    assert_eq!(
        render(None, RequestKind::WebSocket, HttpVersion::H1),
        vec![
            pair("host", MEASURED_AUTHORITY),
            pair("connection", "Upgrade"),
            pair("upgrade", "websocket"),
            pair("sec-websocket-version", "13"),
            pair("sec-websocket-key", MEASURED_WS_KEY),
        ]
    );
    for version in [HttpVersion::H2, HttpVersion::H3] {
        assert!(render(None, RequestKind::FetchGet, version).is_empty());
        // hyper appends its own `content-length` on h2, as before.
        assert!(render(None, RequestKind::FetchPost, version).is_empty());
        assert_eq!(
            render(None, RequestKind::WebSocket, version),
            vec![pair("sec-websocket-version", "13")]
        );
    }
}

#[test]
fn origin_omits_the_default_port() {
    assert_eq!(web_origin(true, "example.test"), "https://example.test");
    assert_eq!(web_origin(false, "example.test:8080"), "http://example.test:8080");
    let origin = |uri: &str| web_origin_of_uri(&uri.parse().unwrap()).unwrap();
    assert_eq!(origin("https://example.test:443/ws"), "https://example.test");
    assert_eq!(origin("https://example.test:8443/ws"), "https://example.test:8443");
    assert_eq!(origin("wss://example.test/ws"), "https://example.test");
    assert_eq!(origin("http://example.test:80/ws"), "http://example.test");
    assert_eq!(origin("https://[::1]:443/ws"), "https://[::1]");
    assert_eq!(origin("https://[::1]:8443/ws"), "https://[::1]:8443");
}

#[test]
fn h1_name_case_follows_the_browser() {
    let chrome = PROFILES.iter().find(|p| p.tls == TlsFingerprint::Chromium).unwrap();
    let firefox = PROFILES.iter().find(|p| p.tls == TlsFingerprint::Firefox).unwrap();
    let safari = PROFILES.iter().find(|p| p.tls == TlsFingerprint::Safari).unwrap();
    let name = |s: &'static str| HeaderName::from_static(s);
    let case = |n: &'static str, p: Option<&Profile>| h1_wire_name(&name(n), p).into_owned();

    assert_eq!(case("sec-ch-ua", Some(chrome)), "sec-ch-ua");
    assert_eq!(case("sec-ch-ua-platform", Some(chrome)), "sec-ch-ua-platform");
    assert_eq!(case("user-agent", Some(chrome)), "User-Agent");
    assert_eq!(case("sec-websocket-key", Some(chrome)), "Sec-WebSocket-Key");
    assert_eq!(case("sec-websocket-extensions", Some(firefox)), "Sec-WebSocket-Extensions");
    assert_eq!(case("sec-fetch-dest", Some(firefox)), "Sec-Fetch-Dest");
    assert_eq!(case("x-outline-resume-capable", Some(firefox)), "X-Outline-Resume-Capable");

    // Safari / no profile: the case tungstenite used to write.
    for profile in [Some(safari), None] {
        assert_eq!(case("host", profile), "Host");
        assert_eq!(case("sec-websocket-key", profile), "Sec-WebSocket-Key");
        assert_eq!(case("origin", profile), "Origin");
        assert_eq!(case("user-agent", profile), "user-agent");
        assert_eq!(case("x-outline-resume-capable", profile), "x-outline-resume-capable");
    }
    assert_eq!(canonical_case("cache-control"), "Cache-Control");
    assert_eq!(canonical_case("te"), "Te");
}

#[test]
fn h1_request_head_is_written_in_map_order_and_browser_case() {
    for profile in measured_profiles() {
        let mut headers = HeaderMap::new();
        browser_headers(
            Some(profile),
            RequestKind::WebSocket,
            HttpVersion::H1,
            MEASURED_ORIGIN,
            &slots(RequestKind::WebSocket, HttpVersion::H1),
            &mut headers,
        );
        let head = encode_h1_request_head("GET", "/ws?x=1", &headers, Some(profile));
        let mut expected = String::from("GET /ws?x=1 HTTP/1.1\r\n");
        for (name, value) in measured_browser_headers(profile, MeasuredKind::WebSocket, true) {
            expected.push_str(&format!("{name}: {value}\r\n"));
        }
        expected.push_str("\r\n");
        assert_eq!(String::from_utf8(head).unwrap(), expected, "{}", profile.name);
    }
}

/// `:authority` of the WebSocket CONNECTs leaves out the default port, like
/// a browser; a non-default port stays. `Origin` follows the same authority.
#[test]
fn websocket_connect_authority_omits_the_default_port() {
    use crate::h2::websocket_h2_target_uri;
    let authority = |uri: &str| uri.parse::<http::Uri>().unwrap().authority().unwrap().to_string();
    assert_eq!(
        authority(&websocket_h2_target_uri(true, "example.test", 443, "/ws")),
        "example.test"
    );
    assert_eq!(
        authority(&websocket_h2_target_uri(true, "example.test", 8443, "/ws")),
        "example.test:8443"
    );
    assert_eq!(
        authority(&websocket_h2_target_uri(false, "example.test", 80, "/ws")),
        "example.test"
    );
    assert_eq!(
        authority(&websocket_h2_target_uri(false, "example.test", 443, "/ws")),
        "example.test:443"
    );
    assert_eq!(authority(&websocket_h2_target_uri(true, "::1", 443, "/ws")), "[::1]");
    assert_eq!(authority(&websocket_h2_target_uri(true, "::1", 8443, "/ws")), "[::1]:8443");

    // The request built on it carries the same authority in `Origin`.
    let chrome = PROFILES.iter().find(|p| p.tls == TlsFingerprint::Chromium).unwrap();
    for (port, origin) in [(443, "https://example.test"), (8443, "https://example.test:8443")] {
        let uri = websocket_h2_target_uri(true, "example.test", port, "/ws");
        let request = crate::h2::build_websocket_connect_request(
            &uri,
            &crate::dial_plan::DialResumeOptions::default(),
            Some(chrome),
        )
        .unwrap();
        assert_eq!(request.headers().get(http::header::ORIGIN).unwrap(), origin);
    }

    #[cfg(feature = "h3")]
    {
        use crate::h3::websocket_h3_target_uri;
        let uri = websocket_h3_target_uri("example.test", 443, "/ws").unwrap();
        assert_eq!(uri.authority().unwrap(), "example.test");
        assert_eq!(web_origin_of_uri(&uri).unwrap(), "https://example.test");
        let uri = websocket_h3_target_uri("example.test", 8443, "/ws").unwrap();
        assert_eq!(uri.authority().unwrap(), "example.test:8443");
        assert_eq!(web_origin_of_uri(&uri).unwrap(), "https://example.test:8443");
        assert_eq!(
            websocket_h3_target_uri("::1", 443, "/ws")
                .unwrap()
                .authority()
                .unwrap(),
            "[::1]"
        );
    }
}

/// xhttp's authority (used for `:authority`, h1 `Host`, `Origin` and
/// `Referer`) leaves out the default port too.
#[test]
fn xhttp_authority_omits_the_default_port() {
    for (use_tls, port, expected) in [
        (true, 443, "example.test"),
        (true, 8443, "example.test:8443"),
        (false, 80, "example.test"),
        (false, 8080, "example.test:8080"),
    ] {
        assert_eq!(crate::xhttp::authority_for(use_tls, "example.test", port), expected);
    }
    #[cfg(feature = "h3")]
    {
        assert_eq!(crate::xhttp::authority_for(true, "example.test", 443), "example.test");
    }
    // IPv6 hosts arrive bracketed from the URL; the port rule is the same.
    assert_eq!(crate::xhttp::authority_for(true, "[::1]", 443), "[::1]");
    assert_eq!(crate::xhttp::authority_for(true, "[::1]", 8443), "[::1]:8443");
    assert_eq!(crate::xhttp::authority_for(false, "[::1]", 80), "[::1]");
    assert_eq!(crate::xhttp::authority_for(false, "[::1]", 8080), "[::1]:8080");
}
