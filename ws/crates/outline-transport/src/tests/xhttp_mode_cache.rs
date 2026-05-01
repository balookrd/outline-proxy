//! Unit tests for the per-host XHTTP downgrade cache.
//!
//! Sibling of the in-line `ws_mode_cache` tests in
//! `crates/outline-transport/src/tests/mod.rs` — same shape, scoped
//! to the XHTTP family. Each test parses a unique URL so the
//! process-global cache map cannot bleed state across concurrent
//! tests sharing a `host:port`.

use url::Url;

use crate::config::TransportMode;
use crate::xhttp_mode_cache::{effective_mode, gc, record_failure, record_success};

#[tokio::test]
async fn no_entry_passes_requested_mode_through_unchanged() {
    let url: Url = "https://no-entry.test:443/xhttp".parse().unwrap();
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH3).await,
        TransportMode::XhttpH3,
    );
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH2).await,
        TransportMode::XhttpH2,
    );
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH1).await,
        TransportMode::XhttpH1,
    );
}

#[tokio::test]
async fn record_failure_xhttp_h3_caps_subsequent_dials_to_xhttp_h2() {
    let url: Url = "https://record-h3-fail.test:443/xhttp".parse().unwrap();
    record_failure(&url, TransportMode::XhttpH3).await;
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH3).await,
        TransportMode::XhttpH2,
        "h3 failure must clamp the next h3 dial to h2",
    );
    // Lower-rank requests pass through — the cap is a ceiling, not a floor.
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH1).await,
        TransportMode::XhttpH1,
    );
}

#[tokio::test]
async fn record_failure_xhttp_h2_caps_subsequent_dials_to_xhttp_h1() {
    let url: Url = "https://record-h2-fail.test:443/xhttp".parse().unwrap();
    record_failure(&url, TransportMode::XhttpH2).await;
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH3).await,
        TransportMode::XhttpH1,
        "h2 failure caps the chain at h1, so even an h3 request lands at h1",
    );
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH2).await,
        TransportMode::XhttpH1,
    );
}

#[tokio::test]
async fn multi_step_failure_converges_downward_and_never_raises() {
    // Mirror of the per-uplink multi-step convergence test in
    // outline-uplink: the cache must lower the cap from h2 to h1
    // when the second failure on the same host arrives, and a later
    // higher-rank failure (h3) inside the active window must not
    // raise the cap back to h2.
    let url: Url = "https://multi-step.test:443/xhttp".parse().unwrap();
    record_failure(&url, TransportMode::XhttpH3).await;
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH3).await,
        TransportMode::XhttpH2,
    );
    record_failure(&url, TransportMode::XhttpH2).await;
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH3).await,
        TransportMode::XhttpH1,
    );
    record_failure(&url, TransportMode::XhttpH3).await;
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH3).await,
        TransportMode::XhttpH1,
        "a late higher-rank failure must not raise the cap back",
    );
}

#[tokio::test]
async fn record_failure_outside_xhttp_family_is_noop() {
    let url: Url = "https://wrong-family.test:443/xhttp".parse().unwrap();
    record_failure(&url, TransportMode::WsH3).await;
    record_failure(&url, TransportMode::WsH2).await;
    record_failure(&url, TransportMode::Quic).await;
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH3).await,
        TransportMode::XhttpH3,
        "WS / QUIC failures must not seed the XHTTP cache",
    );
}

#[tokio::test]
async fn effective_mode_passes_through_non_xhttp_requests() {
    // Even if the cache has an XHTTP cap entry, a non-XHTTP request
    // must pass through unchanged — the cache is single-family.
    let url: Url = "https://passthrough.test:443/xhttp".parse().unwrap();
    record_failure(&url, TransportMode::XhttpH3).await;
    assert_eq!(
        effective_mode(&url, TransportMode::WsH3).await,
        TransportMode::WsH3,
    );
    assert_eq!(
        effective_mode(&url, TransportMode::Quic).await,
        TransportMode::Quic,
    );
}

#[tokio::test]
async fn record_success_clears_cap_when_succeeded_meets_or_exceeds_cap() {
    let url: Url = "https://success-clears.test:443/xhttp".parse().unwrap();
    record_failure(&url, TransportMode::XhttpH3).await;
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH3).await,
        TransportMode::XhttpH2,
    );
    record_success(&url, TransportMode::XhttpH3).await;
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH3).await,
        TransportMode::XhttpH3,
        "successful h3 dial must drop the clamp so the next dial is not held back",
    );
}

#[tokio::test]
async fn record_success_keeps_cap_when_succeeded_is_below_cap() {
    let url: Url = "https://success-below.test:443/xhttp".parse().unwrap();
    record_failure(&url, TransportMode::XhttpH3).await;
    // Cap is now h2. A successful h1 dial does not prove h2/h3 work,
    // so the clamp must remain in place.
    record_success(&url, TransportMode::XhttpH1).await;
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH3).await,
        TransportMode::XhttpH2,
        "an h1 success must not clear an h2 cap",
    );
}

#[tokio::test]
async fn record_success_outside_xhttp_family_is_noop() {
    // A WS-family success on the same host must not clear an XHTTP
    // cap — the chains are independent and prove nothing about each
    // other's reachability.
    let url: Url = "https://success-cross-family.test:443/xhttp".parse().unwrap();
    record_failure(&url, TransportMode::XhttpH3).await;
    record_success(&url, TransportMode::WsH3).await;
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH3).await,
        TransportMode::XhttpH2,
        "a WS success must leave the XHTTP cap intact",
    );
}

#[tokio::test]
async fn gc_is_safe_to_call_with_active_entries() {
    // The cache TTL defaults to 60 s, so a freshly-recorded entry
    // is guaranteed to be in the future when `gc` runs. Smoke-test
    // that gc does not panic and does not strip live entries.
    let url: Url = "https://gc-keeps-live.test:443/xhttp".parse().unwrap();
    record_failure(&url, TransportMode::XhttpH3).await;
    gc().await;
    assert_eq!(
        effective_mode(&url, TransportMode::XhttpH3).await,
        TransportMode::XhttpH2,
        "gc must not evict entries that have not yet expired",
    );
}
