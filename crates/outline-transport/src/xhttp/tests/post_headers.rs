//! Request headers of the xhttp carriers: the per-session POST template
//! (`build_post_headers` / `build_post_template`, cloned per POST with its
//! `Content-Length` set in place) and the `xhttp_h1` requests as hyper really
//! writes them (raw bytes through `spawn_h1`), against the measured browser
//! requests (`crate::tests::measured_browser_headers`). The h2 requests are
//! checked on the wire in `tests/h2_profile.rs`.

use bytes::Bytes;
use http::{HeaderMap, Method, Request, Version, header};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::fingerprint_profile::{PROFILES, Profile, TlsFingerprint};
use crate::request_headers::{CarrierSlots, HttpVersion, RequestKind};
use crate::resumption::SessionId;
use crate::tests::{
    MEASURED_ORIGIN, MeasuredKind, header_pairs, lowercased, measured_browser_headers,
};
use crate::xhttp::{RequestBody, SessionRequest, XhttpTarget};

fn target() -> XhttpTarget {
    XhttpTarget {
        scheme: "https".to_string(),
        authority: "example.test:8443".to_string(),
        base_path: "/xh".to_string(),
        session_id: "abcDEF123456".to_string(),
    }
}

/// Every profile in the pool, plus the no-profile (`Strategy::None`) case.
fn profile_cases() -> Vec<Option<&'static Profile>> {
    let mut cases: Vec<Option<&'static Profile>> = vec![None];
    cases.extend(PROFILES.iter().map(Some));
    cases
}

fn is_measured(profile: Option<&Profile>) -> bool {
    matches!(profile.map(|p| p.tls), Some(TlsFingerprint::Chromium | TlsFingerprint::Firefox))
}

/// Browser part of a request for the unmeasured cases (Safari, no profile),
/// as `request_headers` renders it (pinned by its own snapshot test).
fn unmeasured(
    profile: Option<&Profile>,
    kind: RequestKind,
    version: HttpVersion,
    slots: &CarrierSlots,
) -> Vec<(String, String)> {
    let mut headers = HeaderMap::new();
    crate::request_headers::browser_headers(
        profile,
        kind,
        version,
        MEASURED_ORIGIN,
        slots,
        &mut headers,
    );
    header_pairs(&headers)
}

fn udp_records() -> (String, String) {
    (super::UDP_RECORDS_HEADER.to_owned(), super::UDP_RECORDS_ENABLED.to_owned())
}

// ── POST template ─────────────────────────────────────────────────────────────

#[test]
fn post_templates_follow_the_browser_fetch_post() {
    let target = target();
    for profile in profile_cases() {
        for datagram_records in [false, true] {
            let h1 = super::h1::build_post_headers(&target, datagram_records, profile).unwrap();
            let h2 = super::h2::build_post_headers(MEASURED_ORIGIN, datagram_records, profile);
            #[cfg(feature = "h3")]
            let h3 = super::h3::build_post_headers(MEASURED_ORIGIN, datagram_records, profile);
            for (version, base) in [
                (HttpVersion::H1, &h1),
                (HttpVersion::H2, &h2),
                #[cfg(feature = "h3")]
                (HttpVersion::H3, &h3),
            ] {
                let mut headers = base.clone();
                super::set_post_content_length(&mut headers, 4);
                let h1v = version == HttpVersion::H1;
                let mut expected = match profile {
                    Some(p) if is_measured(profile) => {
                        lowercased(measured_browser_headers(p, MeasuredKind::FetchPost, h1v))
                    },
                    _ => unmeasured(
                        profile,
                        RequestKind::FetchPost,
                        version,
                        &CarrierSlots {
                            host: h1v.then(|| http::HeaderValue::from_static("example.test:8443")),
                            content_length: Some(http::HeaderValue::from_static("4")),
                            websocket_key: None,
                        },
                    ),
                };
                if datagram_records {
                    expected.push(udp_records());
                }
                assert_eq!(
                    header_pairs(&headers),
                    expected,
                    "profile={:?} version={version:?} records={datagram_records}",
                    profile.map(|p| p.name)
                );
                assert_eq!(h1v, headers.contains_key(header::HOST), "host only on h1");
            }
        }
    }
}

/// Setting a POST's length keeps the header's position, so every POST of a
/// session has the same wire order; a template without the header (h2/h3
/// under Safari or no profile) stays without it.
#[test]
fn post_length_is_set_in_place() {
    for profile in profile_cases() {
        let base = super::h2::build_post_headers(MEASURED_ORIGIN, false, profile);
        for len in [0_usize, 5, 45_678] {
            let mut headers = base.clone();
            super::set_post_content_length(&mut headers, len);
            let names = |h: &HeaderMap| h.keys().map(|n| n.as_str().to_owned()).collect::<Vec<_>>();
            assert_eq!(names(&headers), names(&base));
            if let Some(v) = headers.get(header::CONTENT_LENGTH) {
                assert_eq!(v, &len.to_string());
            }
        }
    }
}

#[test]
fn uri_seq_prefix_reproduces_legacy_full_uri() {
    for authority in ["example.com", "example.com:8443"] {
        let mut target = target();
        target.authority = authority.to_owned();
        let prefix = target.uri_seq_prefix();
        for seq in [0_u64, 1, 42, u64::MAX] {
            // Legacy `full_uri_with_seq` formula, reproduced inline.
            let legacy = format!(
                "{}://{}{}/{}/{seq}",
                target.scheme, target.authority, target.base_path, target.session_id,
            );
            assert_eq!(format!("{prefix}{seq}"), legacy, "URI prefix drift (seq={seq})");
        }
        // h1's origin-form twin is the same path without scheme and host.
        assert_eq!(
            format!("{}://{}{}", target.scheme, authority, target.origin_form_seq_prefix()),
            prefix
        );
        assert_eq!(target.origin_form_path(), "/xh/abcDEF123456");
    }
}

// ── xhttp_h1 on the wire ──────────────────────────────────────────────────────

/// Send `request` through `spawn_h1` (the carrier's real hyper h1 client) to
/// an in-memory server and return the raw request head it received.
async fn h1_wire_head(profile: Option<&Profile>, request: Request<RequestBody>) -> String {
    let (client_io, mut server_io) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            assert_eq!(server_io.read(&mut byte).await.unwrap(), 1);
            buf.push(byte[0]);
        }
        let head = String::from_utf8(buf).unwrap();
        let body_len = head
            .lines()
            .find_map(|l| {
                let (n, v) = l.split_once(": ")?;
                n.eq_ignore_ascii_case("content-length")
                    .then(|| v.parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        let mut body = vec![0u8; body_len];
        server_io.read_exact(&mut body).await.unwrap();
        server_io
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
        head
    });
    let browser_case = crate::request_headers::h1_browser_case(profile);
    let mut send = super::h1::spawn_h1(TokioIo::new(client_io), browser_case)
        .await
        .unwrap();
    send.ready().await.unwrap();
    let response = send.send_request(request).await.unwrap();
    assert!(response.status().is_success());
    server.await.unwrap()
}

/// hyper Title-Cases every name; this is the case it writes.
fn hyper_title_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper = true;
    for c in name.chars() {
        out.push(if upper {
            c.to_ascii_uppercase()
        } else {
            c.to_ascii_lowercase()
        });
        upper = c == '-';
    }
    out
}

/// The measured h1 request head, with the one case deviation hyper forces:
/// Chrome's lowercase client hints come out Title-Cased (hyper's per-name case
/// map is private; it can only Title-Case every name). Carrier headers follow,
/// Title-Cased.
fn expected_h1_head(
    profile: &Profile,
    kind: MeasuredKind,
    request_line: &str,
    carrier: &[(String, String)],
) -> String {
    let mut out = format!("{request_line}\r\n");
    for (name, value) in measured_browser_headers(profile, kind, true) {
        let name = if name.starts_with("sec-ch-ua") {
            hyper_title_case(&name)
        } else {
            name
        };
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    for (name, value) in carrier {
        out.push_str(&format!("{}: {value}\r\n", hyper_title_case(name)));
    }
    out.push_str("\r\n");
    out
}

/// Without an aligned profile, hyper writes lowercase names, as before.
fn expected_lowercase_head(
    request_line: &str,
    browser: Vec<(String, String)>,
    carrier: &[(String, String)],
) -> String {
    let mut out = format!("{request_line}\r\n");
    for (name, value) in browser.iter().chain(carrier) {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    out
}

#[tokio::test]
async fn xhttp_h1_get_is_the_browser_fetch_get() {
    let target = target();
    let id = SessionId::from_bytes([7; 16]);
    let carrier: Vec<(String, String)> = vec![
        ("x-outline-resume-capable".into(), "1".into()),
        ("x-outline-resume".into(), id.to_hex()),
        ("x-outline-resume-ack-prefix".into(), "1".into()),
        udp_records(),
    ];
    for profile in profile_cases() {
        // What `open_h1_get` sends.
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(target.origin_form_path())
            .version(Version::HTTP_11)
            .body(super::empty_request_body())
            .unwrap();
        let origin = target.web_origin();
        *request.headers_mut() = super::build_session_request_headers(
            SessionRequest {
                profile,
                kind: RequestKind::FetchGet,
                version: HttpVersion::H1,
                origin: &origin,
                host: Some(&target.authority),
            },
            Some(id),
            true,
            false,
            0,
            true,
        )
        .unwrap();
        let head = h1_wire_head(profile, request).await;
        let line = "GET /xh/abcDEF123456 HTTP/1.1";
        let expected = match profile {
            Some(p) if is_measured(profile) => {
                expected_h1_head(p, MeasuredKind::FetchGet, line, &carrier)
            },
            _ => expected_lowercase_head(
                line,
                unmeasured(
                    profile,
                    RequestKind::FetchGet,
                    HttpVersion::H1,
                    &CarrierSlots {
                        host: Some(http::HeaderValue::from_static("example.test:8443")),
                        ..Default::default()
                    },
                ),
                &carrier,
            ),
        };
        assert_eq!(head, expected, "profile={:?}", profile.map(|p| p.name));
    }
}

#[tokio::test]
async fn xhttp_h1_post_is_the_browser_fetch_post() {
    let target = target();
    let carrier = vec![udp_records()];
    for profile in profile_cases() {
        // What `post_one` sends for a 4-byte frame with seq 0.
        let mut headers = super::h1::build_post_headers(&target, true, profile).unwrap();
        super::set_post_content_length(&mut headers, 4);
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(format!("{}0", target.origin_form_seq_prefix()))
            .version(Version::HTTP_11)
            .body(super::full_request_body(Bytes::from_static(b"data")))
            .unwrap();
        *request.headers_mut() = headers;
        let head = h1_wire_head(profile, request).await;
        let line = "POST /xh/abcDEF123456/0 HTTP/1.1";
        let expected = match profile {
            Some(p) if is_measured(profile) => {
                expected_h1_head(p, MeasuredKind::FetchPost, line, &carrier)
            },
            _ => expected_lowercase_head(
                line,
                unmeasured(
                    profile,
                    RequestKind::FetchPost,
                    HttpVersion::H1,
                    &CarrierSlots {
                        host: Some(http::HeaderValue::from_static("example.test:8443")),
                        content_length: Some(http::HeaderValue::from_static("4")),
                        websocket_key: None,
                    },
                ),
                &carrier,
            ),
        };
        assert_eq!(head, expected, "profile={:?}", profile.map(|p| p.name));
    }
}
