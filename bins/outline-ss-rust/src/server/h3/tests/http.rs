//! Unit tests for the path parser used by the HTTP/3 XHTTP
//! dispatcher. Each case pins one wire shape — the matcher must
//! recognise both the legacy `<base>/<id>` URL (header-based seq)
//! and the xray / sing-box default `<base>/<id>/<seq>` URL, and
//! reject every other shape so the request falls through to 404 /
//! fallback.

use std::collections::BTreeSet;

use super::match_xhttp_path;

fn paths(entries: &[&str]) -> BTreeSet<String> {
    entries.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn matches_base_slash_id_with_no_seq() {
    let xhttp_paths = paths(&["/xh"]);
    let got = match_xhttp_path("/xh/abc-123", &xhttp_paths).expect("expected match");
    assert_eq!(got.0.as_ref(), "/xh");
    assert_eq!(got.1.as_deref(), Some("abc-123"));
    assert_eq!(got.2, None);
}

#[test]
fn matches_base_slash_id_slash_seq() {
    let xhttp_paths = paths(&["/xh"]);
    let got = match_xhttp_path("/xh/abc-123/42", &xhttp_paths).expect("expected match");
    assert_eq!(got.0.as_ref(), "/xh");
    assert_eq!(got.1.as_deref(), Some("abc-123"));
    assert_eq!(got.2, Some(42));
}

#[test]
fn matches_bare_base_with_no_session() {
    // xray sends `<base>` (no trailing slash) for stream-one when
    // path normalisation does not add one. Caller mints a fresh
    // server-side session id.
    let xhttp_paths = paths(&["/xh"]);
    let got = match_xhttp_path("/xh", &xhttp_paths).expect("expected match");
    assert_eq!(got.0.as_ref(), "/xh");
    assert_eq!(got.1, None);
    assert_eq!(got.2, None);
}

#[test]
fn matches_base_with_trailing_slash_no_session() {
    // xray's path normaliser typically emits `<base>/` even when
    // the configured path has no trailing slash; both shapes must
    // collapse to the same sessionless stream-one route.
    let xhttp_paths = paths(&["/xh"]);
    let got = match_xhttp_path("/xh/", &xhttp_paths).expect("expected match");
    assert_eq!(got.0.as_ref(), "/xh");
    assert_eq!(got.1, None);
    assert_eq!(got.2, None);
}

#[test]
fn rejects_non_numeric_seq_segment() {
    // `<base>/<id>/<not-a-number>` must NOT match — falling through
    // to 404 is the right move so a malformed URL does not silently
    // create a session through the GET branch.
    let xhttp_paths = paths(&["/xh"]);
    assert!(match_xhttp_path("/xh/abc-123/not-a-number", &xhttp_paths).is_none());
}

#[test]
fn rejects_extra_path_segments_after_seq() {
    // `<base>/<id>/<seq>/extra` must not match — the wire shape has
    // exactly three components after the base.
    let xhttp_paths = paths(&["/xh"]);
    assert!(match_xhttp_path("/xh/abc/0/extra", &xhttp_paths).is_none());
}

#[test]
fn rejects_empty_id_with_seq_segment() {
    let xhttp_paths = paths(&["/xh"]);
    // `<base>//<seq>` (empty id, has seq) — the `split_once` would
    // hand back an empty `id`, which we reject. (`<base>/` is the
    // sessionless stream-one shape and is matched separately.)
    assert!(match_xhttp_path("/xh//42", &xhttp_paths).is_none());
}

#[test]
fn rejects_empty_seq_segment() {
    // `<base>/<id>/` (trailing slash, empty seq) is uplink-shaped
    // but has no parseable seq — must not match.
    let xhttp_paths = paths(&["/xh"]);
    assert!(match_xhttp_path("/xh/abc/", &xhttp_paths).is_none());
}

#[test]
fn rejects_path_outside_base() {
    let xhttp_paths = paths(&["/xh"]);
    // Different base entirely.
    assert!(match_xhttp_path("/other/abc", &xhttp_paths).is_none());
}

#[test]
fn picks_first_matching_base_when_multiple_configured() {
    // Multiple xhttp bases — the matcher walks the set in BTree
    // order; either the `/a` or `/a/b` base could prefix `/a/b/c`,
    // but only `/a/b` produces a valid `<id>` segment ("c"). The
    // matcher must not return false matches for `/a` here, which
    // would parse "b" as the session id.
    let xhttp_paths = paths(&["/a", "/a/b"]);
    let got = match_xhttp_path("/a/b/c", &xhttp_paths).expect("expected match");
    // `/a` matches first in BTree order and produces id="b" with
    // tail="c". `c` parses as u64? No — "c" is not numeric, so the
    // `/a` arm rejects. `/a/b` is the next entry and produces
    // id="c", path_seq=None. That is the expected behaviour.
    assert_eq!(got.0.as_ref(), "/a/b");
    assert_eq!(got.1.as_deref(), Some("c"));
    assert_eq!(got.2, None);
}

#[test]
fn picks_path_seq_over_plain_id_when_both_could_match() {
    // `/a` matches with id="b", tail="0" (parseable u64) → this
    // arm wins via the iterator. The matcher returns
    // (base="/a", id="b", seq=0). Pins down the BTree-order rule so
    // a future refactor that re-orders the scan does not silently
    // change which entry wins.
    let xhttp_paths = paths(&["/a", "/a/b"]);
    let got = match_xhttp_path("/a/b/0", &xhttp_paths).expect("expected match");
    assert_eq!(got.0.as_ref(), "/a");
    assert_eq!(got.1.as_deref(), Some("b"));
    assert_eq!(got.2, Some(0));
}
