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
                // h3 uses the h2 table, except Firefox's fetch (see
                // `firefox_h3_fetch_*`).
                if version == HttpVersion::H3
                    && profile.tls == TlsFingerprint::Firefox
                    && kind != RequestKind::WebSocket
                {
                    continue;
                }
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

/// Chrome 156 over h3 sends exactly the h2 headers, in the h2 order.
#[test]
fn chromium_h3_equals_chromium_h2() {
    let chrome = PROFILES.iter().find(|p| p.tls == TlsFingerprint::Chromium).unwrap();
    for (kind, _) in KINDS {
        assert_eq!(
            render(Some(chrome), kind, HttpVersion::H3),
            render(Some(chrome), kind, HttpVersion::H2),
            "kind={kind:?}"
        );
    }
}

/// Firefox 159 over h3: the h2 fetch headers without `te: trailers`, with
/// `alt-used: <authority>` right before `sec-fetch-dest`.
#[test]
fn firefox_h3_fetch_drops_te_and_adds_alt_used() {
    let firefox = PROFILES.iter().find(|p| p.tls == TlsFingerprint::Firefox).unwrap();
    for (kind, measured) in [
        (RequestKind::FetchGet, MeasuredKind::FetchGet),
        (RequestKind::FetchPost, MeasuredKind::FetchPost),
    ] {
        let mut expected: Vec<(String, String)> =
            lowercased(measured_browser_headers(firefox, measured, false))
                .into_iter()
                .filter(|(n, _)| n != "te")
                .collect();
        let at = expected.iter().position(|(n, _)| n == "sec-fetch-dest").unwrap();
        expected.insert(at, ("alt-used".into(), MEASURED_AUTHORITY.into()));
        let got = render(Some(firefox), kind, HttpVersion::H3);
        assert_eq!(got, expected, "kind={kind:?}");
        assert!(got.iter().all(|(n, _)| n != "te"));
        // h2 is unchanged: still `te: trailers`, no `alt-used`.
        let h2 = render(Some(firefox), kind, HttpVersion::H2);
        assert!(h2.contains(&("te".to_owned(), "trailers".to_owned())), "{h2:?}");
        assert!(h2.iter().all(|(n, _)| n != "alt-used"), "{h2:?}");
    }
}

#[test]
fn alt_used_is_the_origin_authority_without_default_port() {
    let firefox = PROFILES.iter().find(|p| p.tls == TlsFingerprint::Firefox).unwrap();
    let alt_used = |origin: &str| {
        let mut headers = HeaderMap::new();
        browser_headers(
            Some(firefox),
            RequestKind::FetchGet,
            HttpVersion::H3,
            origin,
            &CarrierSlots::default(),
            &mut headers,
        );
        headers.get("alt-used").map(|v| v.to_str().unwrap().to_owned())
    };
    assert_eq!(alt_used("https://example.test").as_deref(), Some("example.test"));
    assert_eq!(alt_used("https://example.test:8443").as_deref(), Some("example.test:8443"));
    assert_eq!(alt_used("https://[::1]").as_deref(), Some("[::1]"));
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

/// Safari 27.0.1: fetch GET and POST have their own orders; the values are
/// the measured ones (`Accept: */*`, `Priority: u=3, i`, `Sec-Fetch-Dest:
/// websocket` and `Sec-WebSocket-Extensions: permessage-deflate` on a
/// WebSocket, `Sec-Fetch-Dest: empty` on fetch). h3 uses the h2 tables.
#[test]
fn safari_follows_its_measured_tables() {
    let safari = PROFILES.iter().find(|p| p.tls == TlsFingerprint::Safari).unwrap();
    let names = |kind, version| -> Vec<String> {
        render(Some(safari), kind, version)
            .into_iter()
            .map(|(n, _)| n)
            .collect()
    };
    let list = |s: &str| s.split(", ").map(str::to_owned).collect::<Vec<_>>();
    assert_eq!(
        names(RequestKind::FetchGet, HttpVersion::H1),
        list(
            "host, sec-fetch-dest, user-agent, accept, referer, sec-fetch-site, sec-fetch-mode, \
             accept-language, priority, accept-encoding, connection"
        )
    );
    assert_eq!(
        names(RequestKind::FetchPost, HttpVersion::H1),
        list(
            "host, accept, origin, sec-fetch-site, sec-fetch-mode, user-agent, referer, \
             sec-fetch-dest, content-length, accept-language, priority, accept-encoding, \
             connection"
        )
    );
    assert_eq!(
        names(RequestKind::WebSocket, HttpVersion::H1),
        list(
            "host, origin, pragma, sec-fetch-site, sec-websocket-version, sec-fetch-mode, \
             user-agent, sec-websocket-extensions, cache-control, sec-fetch-dest, accept, \
             accept-language, priority, accept-encoding, sec-websocket-key, connection, upgrade"
        )
    );
    for version in [HttpVersion::H2, HttpVersion::H3] {
        assert_eq!(
            names(RequestKind::FetchGet, version),
            list(
                "sec-fetch-dest, user-agent, accept, referer, sec-fetch-site, sec-fetch-mode, \
                 accept-language, priority, accept-encoding"
            )
        );
        assert_eq!(
            names(RequestKind::FetchPost, version),
            list(
                "accept, origin, sec-fetch-site, sec-fetch-mode, user-agent, referer, \
                 sec-fetch-dest, content-length, accept-language, priority, accept-encoding"
            )
        );
        assert_eq!(
            names(RequestKind::WebSocket, version),
            list(
                "origin, pragma, sec-fetch-site, sec-websocket-version, sec-fetch-mode, \
                 user-agent, sec-websocket-extensions, cache-control, sec-fetch-dest, accept, \
                 accept-language, priority, accept-encoding"
            )
        );
    }

    let value = |kind, version, name: &str| -> String {
        render(Some(safari), kind, version)
            .into_iter()
            .find(|(n, _)| n == name)
            .unwrap()
            .1
    };
    for version in [HttpVersion::H1, HttpVersion::H2] {
        for kind in [RequestKind::FetchGet, RequestKind::FetchPost, RequestKind::WebSocket] {
            assert_eq!(value(kind, version, "accept"), "*/*");
            assert_eq!(value(kind, version, "priority"), "u=3, i");
        }
        assert_eq!(
            value(RequestKind::WebSocket, version, "sec-websocket-extensions"),
            "permessage-deflate"
        );
        assert_eq!(value(RequestKind::WebSocket, version, "sec-fetch-dest"), "websocket");
        assert_eq!(value(RequestKind::FetchGet, version, "sec-fetch-dest"), "empty");
        assert_eq!(value(RequestKind::FetchPost, version, "sec-fetch-dest"), "empty");
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

    // Safari: canonical case throughout, like Firefox.
    assert_eq!(case("user-agent", Some(safari)), "User-Agent");
    assert_eq!(case("sec-fetch-dest", Some(safari)), "Sec-Fetch-Dest");
    assert_eq!(case("sec-websocket-key", Some(safari)), "Sec-WebSocket-Key");
    assert_eq!(case("x-outline-resume-capable", Some(safari)), "X-Outline-Resume-Capable");

    // No profile: the case tungstenite used to write.
    assert_eq!(case("host", None), "Host");
    assert_eq!(case("sec-websocket-key", None), "Sec-WebSocket-Key");
    assert_eq!(case("origin", None), "Origin");
    assert_eq!(case("user-agent", None), "user-agent");
    assert_eq!(case("x-outline-resume-capable", None), "x-outline-resume-capable");
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
