//! Fingerprint-preservation regression for the per-session POST
//! template (`build_post_headers` + `uri_seq_prefix`).
//!
//! The uplink driver used to rebuild the whole POST request on every
//! frame: a fresh `Request::builder`, a `format!`-ed absolute URI, and
//! a full `fingerprint_profile::apply` pass (~11 header inserts). That
//! pass is now hoisted to one per session and cloned per POST. The
//! anti-DPI surface is the exact header set AND order on the wire, so
//! these tests pin the new path to produce a byte-identical header map
//! (and URL) to the old per-POST construction for every profile — a
//! `HeaderMap::clone` preserves iteration order, and h1's placeholder
//! `Content-Length` keeps its slot when overwritten in place.

use http::{HeaderMap, HeaderValue, Method, Request, Version, header};

use crate::fingerprint_profile::{PROFILES, Profile, SecFetchPreset, apply};
use crate::xhttp::XhttpTarget;

fn target(authority: &str) -> XhttpTarget {
    XhttpTarget {
        scheme: "https".to_string(),
        authority: authority.to_string(),
        base_path: "/xh".to_string(),
        session_id: "abcDEF123456".to_string(),
    }
}

/// (name, value-bytes) pairs in `HeaderMap` iteration order — the order
/// hyper / h3 serialise onto the wire.
fn header_lines(headers: &HeaderMap) -> Vec<(String, Vec<u8>)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect()
}

/// Every profile in the pool, plus the no-profile (`Strategy::None`)
/// case which the default deployments run.
fn profile_cases() -> Vec<Option<&'static Profile>> {
    let mut cases: Vec<Option<&'static Profile>> = vec![None];
    cases.extend(PROFILES.iter().map(Some));
    cases
}

#[test]
fn h2_post_headers_match_legacy_per_post_build() {
    for authority in ["example.com", "example.com:8443"] {
        let target = target(authority);
        for profile in profile_cases() {
            // Legacy path: builder Host header, then `apply` on the body req.
            let mut legacy: Request<()> = Request::builder()
                .method(Method::POST)
                .uri("https://example.com/xh/abcDEF123456/0")
                .version(Version::HTTP_2)
                .header(header::HOST, authority)
                .body(())
                .unwrap();
            if let Some(profile) = profile {
                apply(profile, legacy.headers_mut(), SecFetchPreset::XhrCors);
            }

            // New path: base headers cloned per POST (no per-POST delta on h2).
            let base = super::h2::build_post_headers(&target, profile).unwrap();

            assert_eq!(
                header_lines(legacy.headers()),
                header_lines(&base),
                "h2 POST header order/set drifted (authority={authority}, profile={:?})",
                profile.map(|p| p.name),
            );
        }
    }
}

#[test]
fn h1_post_headers_match_legacy_per_post_build() {
    for authority in ["example.com", "example.com:8443"] {
        let target = target(authority);
        for profile in profile_cases() {
            for content_length in [0_usize, 5, 45_678] {
                // Legacy path: builder Host + Content-Length, then `apply`.
                let mut legacy: Request<()> = Request::builder()
                    .method(Method::POST)
                    .uri("https://example.com/xh/abcDEF123456/0")
                    .version(Version::HTTP_11)
                    .header(header::HOST, authority)
                    .header(header::CONTENT_LENGTH, content_length)
                    .body(())
                    .unwrap();
                if let Some(profile) = profile {
                    apply(profile, legacy.headers_mut(), SecFetchPreset::XhrCors);
                }

                // New path: clone the placeholder base, overwrite Content-Length.
                let base = super::h1::build_post_headers(&target, profile).unwrap();
                let mut new_headers = base.clone();
                new_headers.insert(header::CONTENT_LENGTH, HeaderValue::from(content_length));

                assert_eq!(
                    header_lines(legacy.headers()),
                    header_lines(&new_headers),
                    "h1 POST header order/set drifted \
                     (authority={authority}, len={content_length}, profile={:?})",
                    profile.map(|p| p.name),
                );
            }
        }
    }
}

#[cfg(feature = "h3")]
#[test]
fn h3_post_headers_match_legacy_per_post_build() {
    for profile in profile_cases() {
        // Legacy path: apply-only, no Host header (authority is `:authority`).
        let mut legacy: Request<()> = Request::builder()
            .method(Method::POST)
            .uri("https://example.com/xh/abcDEF123456/0")
            .version(Version::HTTP_3)
            .body(())
            .unwrap();
        if let Some(profile) = profile {
            apply(profile, legacy.headers_mut(), SecFetchPreset::XhrCors);
        }

        let base = super::h3::build_post_headers(profile);

        assert_eq!(
            header_lines(legacy.headers()),
            header_lines(&base),
            "h3 POST header order/set drifted (profile={:?})",
            profile.map(|p| p.name),
        );
    }
}

#[test]
fn uri_seq_prefix_reproduces_legacy_full_uri() {
    for authority in ["example.com", "example.com:8443"] {
        let target = target(authority);
        let prefix = target.uri_seq_prefix();
        for seq in [0_u64, 1, 42, u64::MAX] {
            // Legacy `full_uri_with_seq` formula, reproduced inline.
            let legacy = format!(
                "{}://{}{}/{}/{seq}",
                target.scheme, target.authority, target.base_path, target.session_id,
            );
            assert_eq!(format!("{prefix}{seq}"), legacy, "URI prefix drift (seq={seq})");
        }
    }
}
