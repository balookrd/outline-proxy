//! Unit coverage for [`super::super::sni_fallback::SniLookup`] and the
//! [`super::super::sni_fallback::peek_sni`] failure classification. The
//! e2e dispatch path lives in `src/server/tests/sni_fallback.rs`; here
//! we just probe the routing-table semantics in isolation.

use crate::config::{SniBackend, SniFallbackConfig, SniMatcher};

use super::super::sni_fallback::{SniLookup, SniPeekFailure, SniRoute, peek_sni};

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

fn cfg(local: Vec<SniMatcher>, backends: Vec<SniBackend>, allow_no_sni: bool) -> SniFallbackConfig {
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
    let lookup =
        SniLookup::build(&cfg(vec![exact("ours.example")], vec![backend("up:443", vec![])], false));
    assert_eq!(lookup.lookup(Some("ours.example")), Some(SniRoute::Local));
}

#[test]
fn exact_backend_match_routes_to_backend() {
    let lookup = SniLookup::build(&cfg(
        vec![exact("ours.example")],
        vec![backend("first:443", vec![exact("foreign.example")]), backend("catchall:443", vec![])],
        false,
    ));
    assert_eq!(lookup.lookup(Some("foreign.example")), Some(SniRoute::Backend(0)));
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
    assert_eq!(lookup.lookup(Some("a.b.ours.example")), Some(SniRoute::Backend(0)));
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
    assert_eq!(lookup.lookup(Some("shared.example")), Some(SniRoute::Local));
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
    assert_eq!(lookup.lookup(Some("dup.example")), Some(SniRoute::Backend(0)));
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
        vec![backend("named:443", vec![exact("known.example")]), backend("catchall:443", vec![])],
        false,
    ));
    assert_eq!(lookup.lookup(Some("nobody-claims-this.example")), Some(SniRoute::Backend(1)));
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
    assert_eq!(lookup.lookup(Some("px.beerloga.su")), Some(SniRoute::Backend(0)));
    assert_eq!(lookup.lookup(Some("cloud.beerloga.su")), Some(SniRoute::Local));
    assert_eq!(lookup.lookup(Some("something.else.com")), Some(SniRoute::Backend(1)));
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

// ── peek_sni failure classification ──────────────────────────────────────────
//
// The bucket decides the log level: `peer_closed` is routine background
// traffic on a public port (TCP liveness probes, scanners) and must stay at
// debug, while anything we could not parse has to keep warning. Getting this
// wrong in either direction is a real cost — one buries the journal, the
// other hides the signal.

/// Feeds `payload` to `peek_sni` over a real loopback TCP pair, closing the
/// client half afterwards so the server side sees EOF rather than blocking.
async fn peek_failure_for(payload: &[u8], max_bytes: usize) -> SniPeekFailure {
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener addr");

    let payload = payload.to_vec();
    let client = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.expect("connect to listener");
        if !payload.is_empty() {
            stream.write_all(&payload).await.expect("write payload");
        }
        // Half-close: the peek loop must observe EOF, not hang.
        stream.shutdown().await.expect("shutdown client half");
    });

    let (mut inbound, _) = listener.accept().await.expect("accept");
    let error = peek_sni(&mut inbound, max_bytes)
        .await
        .err()
        .expect("peek must not succeed on a non-ClientHello stream");
    client.await.expect("client task");
    error.failure
}

#[tokio::test]
async fn a_connection_closed_before_any_byte_is_peer_closed() {
    // The bare-TCP liveness probe: connect, then drop. This is the shape
    // that produced ~1 400 warn lines an hour per server before the demotion.
    assert_eq!(peek_failure_for(b"", 8192).await, SniPeekFailure::PeerClosed);
}

#[tokio::test]
async fn a_truncated_client_hello_is_also_peer_closed() {
    // A TLS record header that never gets its body: the peer still walked
    // away mid-handshake, so it belongs in the routine bucket.
    let record_header_only = [0x16, 0x03, 0x01, 0x00, 0x40];
    assert_eq!(peek_failure_for(&record_header_only, 8192).await, SniPeekFailure::PeerClosed);
}

#[tokio::test]
async fn bytes_that_are_not_tls_at_all_are_malformed() {
    // A plain HTTP request onto the TLS port — rustls rejects the record
    // layer outright, which is exactly the case that must keep warning.
    assert_eq!(
        peek_failure_for(b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n", 8192).await,
        SniPeekFailure::Malformed,
    );
}

#[tokio::test]
async fn a_handshake_past_the_cap_is_oversized() {
    // A well-formed record header followed by more body than
    // `max_client_hello_bytes` allows: the peek bails before the codec
    // gets a chance to call it malformed.
    let mut payload = vec![0x16, 0x03, 0x01, 0x10, 0x00];
    payload.resize(600, 0);
    assert_eq!(peek_failure_for(&payload, 256).await, SniPeekFailure::Oversized);
}

#[test]
fn peer_closed_is_the_only_bucket_demoted_below_warn() {
    // Locks the log-level policy: adding a bucket must be a deliberate
    // decision about whether operators get a line per occurrence.
    assert!(!SniPeekFailure::PeerClosed.is_noteworthy());
    assert!(SniPeekFailure::ReadFailed.is_noteworthy());
    assert!(SniPeekFailure::Oversized.is_noteworthy());
    assert!(SniPeekFailure::Malformed.is_noteworthy());
}

#[test]
fn every_failure_bucket_has_a_stable_metric_label() {
    // These become `outline_ss_sni_peek_failed_total{reason=...}`; renaming
    // one silently breaks whatever dashboard or alert reads it.
    assert_eq!(SniPeekFailure::PeerClosed.as_str(), "peer_closed");
    assert_eq!(SniPeekFailure::ReadFailed.as_str(), "read_failed");
    assert_eq!(SniPeekFailure::Oversized.as_str(), "oversized");
    assert_eq!(SniPeekFailure::Malformed.as_str(), "malformed");
}
