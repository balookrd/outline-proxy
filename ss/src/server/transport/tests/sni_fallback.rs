//! Unit coverage for [`super::super::sni_fallback::SniLookup`]. The
//! e2e dispatch path lives in `src/server/tests/sni_fallback.rs`; here
//! we just probe the routing-table semantics in isolation.

use crate::config::{SniBackend, SniFallbackConfig, SniMatcher};

use super::super::sni_fallback::{SniLookup, SniRoute};

fn exact(name: &str) -> SniMatcher {
    SniMatcher::Exact(name.to_ascii_lowercase())
}

/// `pattern` is `*.foo.example` form; we strip the leading `*` and
/// reuse the `Wildcard.suffix` invariant (a leading dot followed by
/// the literal suffix) directly, matching what `SniMatcher::parse`
/// emits.
fn wildcard(pattern: &str) -> SniMatcher {
    let suffix = pattern
        .to_ascii_lowercase()
        .strip_prefix('*')
        .expect("test wildcard must start with `*`")
        .to_owned();
    SniMatcher::Wildcard { suffix }
}

fn cfg(
    local: Vec<SniMatcher>,
    backends: Vec<SniBackend>,
    allow_no_sni: bool,
) -> SniFallbackConfig {
    SniFallbackConfig {
        match_sni: local,
        allow_no_sni,
        max_client_hello_bytes: 8192,
        backends,
    }
}

fn backend(authority: &str, matchers: Vec<SniMatcher>) -> SniBackend {
    SniBackend {
        authority: authority.to_owned(),
        match_sni: matchers,
        proxy_protocol: None,
    }
}

#[test]
fn exact_local_match_routes_to_local() {
    let lookup = SniLookup::build(&cfg(
        vec![exact("ours.example")],
        vec![backend("up:443", vec![])],
        false,
    ));
    assert_eq!(lookup.lookup(Some("ours.example")), Some(SniRoute::Local));
}

#[test]
fn exact_backend_match_routes_to_backend() {
    let lookup = SniLookup::build(&cfg(
        vec![exact("ours.example")],
        vec![
            backend("first:443", vec![exact("foreign.example")]),
            backend("catchall:443", vec![]),
        ],
        false,
    ));
    assert_eq!(
        lookup.lookup(Some("foreign.example")),
        Some(SniRoute::Backend(0))
    );
}

#[test]
fn exact_match_wins_over_wildcard_in_other_list() {
    // Backend's wildcard `*.example` would subsume `ours.example`, but
    // the exact local entry is more specific intent and must win.
    let lookup = SniLookup::build(&cfg(
        vec![exact("ours.example")],
        vec![backend("up:443", vec![wildcard("*.example")])],
        false,
    ));
    assert_eq!(lookup.lookup(Some("ours.example")), Some(SniRoute::Local));
}

#[test]
fn wildcard_falls_back_after_exact_miss() {
    let lookup = SniLookup::build(&cfg(
        vec![wildcard("*.ours.example")],
        vec![backend("catchall:443", vec![])],
        false,
    ));
    assert_eq!(lookup.lookup(Some("api.ours.example")), Some(SniRoute::Local));
    // Two-label-deep wildcard still wins as Local because `Wildcard`
    // semantics enforce single-label-left, so unrelated names fall
    // through to the catch-all backend.
    assert_eq!(
        lookup.lookup(Some("a.b.ours.example")),
        Some(SniRoute::Backend(0))
    );
}

#[test]
fn local_exact_wins_over_backend_exact_collision() {
    // Both lists declare the same SNI. Local is inserted first, so
    // local wins on collision (mirrors the historical priority where
    // `sni_matches_ours` ran before `find_backend`).
    let lookup = SniLookup::build(&cfg(
        vec![exact("shared.example")],
        vec![backend("up:443", vec![exact("shared.example")])],
        false,
    ));
    assert_eq!(
        lookup.lookup(Some("shared.example")),
        Some(SniRoute::Local)
    );
}

#[test]
fn first_backend_wins_among_backends() {
    let lookup = SniLookup::build(&cfg(
        vec![exact("ours.example")],
        vec![
            backend("first:443", vec![exact("dup.example")]),
            backend("second:443", vec![exact("dup.example")]),
        ],
        false,
    ));
    assert_eq!(
        lookup.lookup(Some("dup.example")),
        Some(SniRoute::Backend(0))
    );
}

#[test]
fn no_sni_routes_per_allow_flag() {
    let with_allow = SniLookup::build(&cfg(
        vec![exact("ours.example")],
        vec![backend("catchall:443", vec![])],
        true,
    ));
    assert_eq!(with_allow.lookup(None), Some(SniRoute::Local));

    let without_allow = SniLookup::build(&cfg(
        vec![exact("ours.example")],
        vec![backend("catchall:443", vec![])],
        false,
    ));
    assert_eq!(without_allow.lookup(None), Some(SniRoute::Backend(0)));
}

#[test]
fn unmatched_sni_falls_through_to_catch_all() {
    let lookup = SniLookup::build(&cfg(
        vec![exact("ours.example")],
        vec![
            backend("named:443", vec![exact("known.example")]),
            backend("catchall:443", vec![]),
        ],
        false,
    ));
    assert_eq!(
        lookup.lookup(Some("nobody-claims-this.example")),
        Some(SniRoute::Backend(1))
    );
}

#[test]
fn backend_exact_overrides_local_wildcard() {
    // Mirrors the operator's `[sni_fallback]` config: local owns the
    // whole `*.beerloga.su` apex via wildcard, but `px.beerloga.su` is
    // explicitly carved out to a backend. Exact-first lookup means the
    // carve-out wins for that single host while everything else under
    // the apex still terminates locally; truly foreign SNIs hit the
    // catch-all.
    let lookup = SniLookup::build(&cfg(
        vec![wildcard("*.beerloga.su")],
        vec![
            backend("127.0.0.1:10443", vec![exact("px.beerloga.su")]),
            backend("127.0.0.1:11443", vec![]),
        ],
        false,
    ));
    assert_eq!(
        lookup.lookup(Some("px.beerloga.su")),
        Some(SniRoute::Backend(0))
    );
    assert_eq!(
        lookup.lookup(Some("cloud.beerloga.su")),
        Some(SniRoute::Local)
    );
    assert_eq!(
        lookup.lookup(Some("something.else.com")),
        Some(SniRoute::Backend(1))
    );
}

#[test]
fn unmatched_sni_without_catch_all_returns_none() {
    let lookup = SniLookup::build(&cfg(
        vec![exact("ours.example")],
        vec![backend("named:443", vec![exact("known.example")])],
        false,
    ));
    assert_eq!(lookup.lookup(Some("nobody-claims-this.example")), None);
}
