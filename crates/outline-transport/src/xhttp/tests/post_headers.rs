//! Request headers of the xhttp carriers: the per-session POST template
//! (`build_post_headers` / `build_post_template`, cloned per POST with its
//! `Content-Length` set in place) and the `xhttp_h1` requests as hyper really
//! writes them (`get_request` / `post_request` sent through `spawn_h1`, raw
//! bytes, header case included), against the measured browser
//! requests (`crate::tests::measured_browser_headers`). The h2 requests are
//! checked on the wire in `tests/h2_profile.rs`.

use bytes::Bytes;
use http::{HeaderMap, HeaderName, Request, header};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::fingerprint_profile::{PROFILES, Profile, TlsFingerprint};
use crate::request_headers::{CarrierSlots, HttpVersion, RequestKind};
use crate::resumption::SessionId;
use crate::tests::{
    MEASURED_AUTHORITY, MEASURED_ORIGIN, MeasuredKind, header_pairs, lowercased,
    measured_browser_headers,
};
use crate::xhttp::{RequestBody, XhttpTarget};

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
    profile.is_some()
}

/// Browser part of a request for the unmeasured case (no profile),
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
                        let mut rows =
                            lowercased(measured_browser_headers(p, MeasuredKind::FetchPost, h1v));
                        // Firefox over h3: no `te`, `alt-used` before `sec-fetch-dest`.
                        if version == HttpVersion::H3 && p.tls == TlsFingerprint::Firefox {
                            rows.retain(|(n, _)| n != "te");
                            let at = rows.iter().position(|(n, _)| n == "sec-fetch-dest").unwrap();
                            rows.insert(at, ("alt-used".into(), MEASURED_AUTHORITY.into()));
                        }
                        rows
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
/// without a profile) stays without it.
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

/// A name as the browser writes it on HTTP/1.1 (`request_headers::h1_wire_name`).
fn wire_name(name: &str, profile: &Profile) -> String {
    let name = HeaderName::from_bytes(name.as_bytes()).unwrap();
    crate::request_headers::h1_wire_name(&name, Some(profile)).into_owned()
}

/// The measured h1 request head, byte for byte: names in the browser's case
/// (Chrome's `sec-ch-ua*` lowercase, every other name canonical). Carrier
/// headers follow, in the case the browser would give them (canonical).
fn expected_h1_head(
    profile: &Profile,
    kind: MeasuredKind,
    request_line: &str,
    carrier: &[(String, String)],
) -> String {
    let mut out = format!("{request_line}\r\n");
    for (name, value) in measured_browser_headers(profile, kind, true) {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    for (name, value) in carrier {
        out.push_str(&format!("{}: {value}\r\n", wire_name(name, profile)));
    }
    out.push_str("\r\n");
    out
}

/// The case rule spelled out, independent of the measured tables: Chromium
/// writes its client hints lowercase and every other name canonically;
/// Firefox and Safari write every name canonically; without a profile every
/// name stays lowercase.
fn assert_browser_case(head: &str, profile: Option<&Profile>) {
    let names: Vec<&str> = head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(": ").map(|(n, _)| n))
        .collect();
    assert!(!names.is_empty());
    for name in names {
        let lower = name.to_ascii_lowercase();
        let canonical: String = lower
            .split('-')
            .map(|seg| {
                let mut seg = seg.to_owned();
                seg[..1].make_ascii_uppercase();
                seg
            })
            .collect::<Vec<_>>()
            .join("-");
        let want = match profile {
            None => lower.clone(),
            Some(p) if p.tls == TlsFingerprint::Chromium && lower.starts_with("sec-ch-ua") => {
                lower.clone()
            },
            Some(_) => canonical,
        };
        assert_eq!(name, want, "profile={:?}", profile.map(|p| p.name));
    }
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
        let request =
            super::h1::get_request(&target, Some(id), true, false, 0, true, profile).unwrap();
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
        assert_browser_case(&head, profile);
    }
}

#[tokio::test]
async fn xhttp_h1_post_is_the_browser_fetch_post() {
    let target = target();
    let carrier = vec![udp_records()];
    for profile in profile_cases() {
        // What `post_one` sends for a 4-byte frame with seq 0.
        let base = super::h1::build_post_headers(&target, true, profile).unwrap();
        let request = super::h1::post_request(
            &target.origin_form_seq_prefix(),
            &base,
            0,
            Bytes::from_static(b"data"),
            profile,
        )
        .unwrap();
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
        assert_browser_case(&head, profile);
    }
}
