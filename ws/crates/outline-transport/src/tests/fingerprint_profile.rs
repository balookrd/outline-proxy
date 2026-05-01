//! Unit tests for [`crate::fingerprint_profile`].
//!
//! Tests use [`select_with_strategy`] instead of [`select`] so the
//! process-wide `OnceLock` strategy is not poisoned by the suite —
//! a `select` test would force the global into one value and leak
//! that into every subsequent test in the same `cargo test` binary.

use std::str::FromStr;

use http::{HeaderValue, header};
use url::Url;

use crate::fingerprint_profile::{
    PROFILES, SecFetchPreset, Strategy, apply, select_with_strategy,
};

#[test]
fn pool_is_non_empty_and_contains_chrome_firefox_safari() {
    assert!(!PROFILES.is_empty(), "pool must have at least one profile");
    assert!(
        PROFILES.iter().any(|p| p.name.starts_with("chrome")),
        "pool must include a chrome identity"
    );
    assert!(
        PROFILES.iter().any(|p| p.name.starts_with("firefox")),
        "pool must include a firefox identity"
    );
    assert!(
        PROFILES.iter().any(|p| p.name.starts_with("safari")),
        "pool must include a safari identity"
    );
}

#[test]
fn select_with_none_strategy_returns_none() {
    let url = Url::parse("wss://example.test/x").unwrap();
    assert!(select_with_strategy(&url, Strategy::None).is_none());
}

#[test]
fn select_with_per_host_stable_returns_same_profile_for_same_host() {
    let url = Url::parse("wss://stable-host.test:443/path").unwrap();
    let a = select_with_strategy(&url, Strategy::PerHostStable).expect("some");
    let b = select_with_strategy(&url, Strategy::PerHostStable).expect("some");
    assert_eq!(a.name, b.name);
}

#[test]
fn select_with_per_host_stable_ignores_path_and_query() {
    // Path/query are not part of the cache key — two URLs with the
    // same authority but different paths must land on the same
    // profile so a single peer never sees two identities for two
    // dials to the same host.
    let url_a = Url::parse("wss://same-host.test:443/foo").unwrap();
    let url_b = Url::parse("wss://same-host.test:443/bar?mode=stream-one").unwrap();
    let a = select_with_strategy(&url_a, Strategy::PerHostStable).unwrap();
    let b = select_with_strategy(&url_b, Strategy::PerHostStable).unwrap();
    assert_eq!(a.name, b.name);
}

#[test]
fn select_with_per_host_stable_varies_across_hosts() {
    // With six profiles a single random hostname pair has 1/6 chance
    // of colliding; a small sweep makes the test reliably hit the
    // "different profile" case at least once.
    let url1 = Url::parse("wss://alpha.test:443/").unwrap();
    let p1 = select_with_strategy(&url1, Strategy::PerHostStable).unwrap();
    let mut found_different = false;
    for tag in ["beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota"] {
        let url2 = Url::parse(&format!("wss://{tag}.test:443/")).unwrap();
        let p2 = select_with_strategy(&url2, Strategy::PerHostStable).unwrap();
        if p2.name != p1.name {
            found_different = true;
            break;
        }
    }
    assert!(
        found_different,
        "per-host-stable selector should produce >1 distinct profile across many hostnames"
    );
}

#[test]
fn apply_inserts_user_agent_and_accept_language() {
    let mut headers = http::HeaderMap::new();
    let profile = &PROFILES[0];
    apply(profile, &mut headers, SecFetchPreset::WebsocketUpgrade);
    assert_eq!(
        headers.get(header::USER_AGENT).unwrap(),
        profile.user_agent
    );
    assert_eq!(
        headers.get(header::ACCEPT_LANGUAGE).unwrap(),
        profile.accept_language
    );
    assert_eq!(
        headers.get(header::ACCEPT_ENCODING).unwrap(),
        profile.accept_encoding
    );
}

#[test]
fn apply_websocket_preset_sets_websocket_dest() {
    let mut headers = http::HeaderMap::new();
    apply(&PROFILES[0], &mut headers, SecFetchPreset::WebsocketUpgrade);
    assert_eq!(headers.get("sec-fetch-mode").unwrap(), "websocket");
    assert_eq!(headers.get("sec-fetch-dest").unwrap(), "websocket");
    assert_eq!(headers.get("sec-fetch-site").unwrap(), "same-origin");
}

#[test]
fn apply_xhr_preset_sets_empty_dest() {
    let mut headers = http::HeaderMap::new();
    apply(&PROFILES[0], &mut headers, SecFetchPreset::XhrCors);
    assert_eq!(headers.get("sec-fetch-mode").unwrap(), "cors");
    assert_eq!(headers.get("sec-fetch-dest").unwrap(), "empty");
    assert_eq!(headers.get("sec-fetch-site").unwrap(), "same-origin");
}

#[test]
fn apply_omits_sec_ch_ua_for_firefox_profile() {
    // Firefox does not advertise Client Hints by default — the absence
    // is the signature, so the apply helper must NOT inject placeholder
    // values when the profile leaves the field as None.
    let firefox = PROFILES
        .iter()
        .find(|p| p.name.starts_with("firefox"))
        .expect("firefox profile present");
    assert!(firefox.sec_ch_ua.is_none());
    let mut headers = http::HeaderMap::new();
    apply(firefox, &mut headers, SecFetchPreset::WebsocketUpgrade);
    assert!(headers.get("sec-ch-ua").is_none());
    assert!(headers.get("sec-ch-ua-mobile").is_none());
    assert!(headers.get("sec-ch-ua-platform").is_none());
}

#[test]
fn apply_emits_sec_ch_ua_for_chrome_profile() {
    let chrome = PROFILES
        .iter()
        .find(|p| p.name.starts_with("chrome"))
        .expect("chrome profile present");
    let mut headers = http::HeaderMap::new();
    apply(chrome, &mut headers, SecFetchPreset::WebsocketUpgrade);
    assert!(headers.get("sec-ch-ua").is_some());
    assert_eq!(headers.get("sec-ch-ua-mobile").unwrap(), "?0");
    assert!(headers.get("sec-ch-ua-platform").is_some());
}

#[test]
fn apply_preserves_caller_supplied_accept_value() {
    // A future XHTTP path may want to pin Accept to mirror what xray
    // emits on a specific submode; apply() must not clobber a value
    // the caller has already chosen.
    let mut headers = http::HeaderMap::new();
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/octet-stream"),
    );
    apply(&PROFILES[0], &mut headers, SecFetchPreset::XhrCors);
    assert_eq!(
        headers.get(header::ACCEPT).unwrap(),
        "application/octet-stream"
    );
}

#[test]
fn strategy_from_str_accepts_documented_aliases() {
    assert_eq!(Strategy::from_str("").unwrap(), Strategy::None);
    assert_eq!(Strategy::from_str("off").unwrap(), Strategy::None);
    assert_eq!(Strategy::from_str("none").unwrap(), Strategy::None);
    assert_eq!(Strategy::from_str("DISABLED").unwrap(), Strategy::None);
    assert_eq!(Strategy::from_str("stable").unwrap(), Strategy::PerHostStable);
    assert_eq!(
        Strategy::from_str("per_host_stable").unwrap(),
        Strategy::PerHostStable,
    );
    assert_eq!(
        Strategy::from_str("per-host-stable").unwrap(),
        Strategy::PerHostStable,
    );
    assert_eq!(Strategy::from_str("random").unwrap(), Strategy::Random);
}

#[test]
fn strategy_from_str_rejects_unknown_aliases() {
    assert!(Strategy::from_str("perma").is_err());
    assert!(Strategy::from_str("rotate").is_err());
}

#[test]
fn note_first_use_returns_true_only_on_first_call() {
    // Hostname is unique per test so the process-global dedup set is
    // not poisoned by other tests in this binary.
    let url: Url = "wss://note-first-use-once.test:443/".parse().unwrap();
    let profile = &PROFILES[0];
    assert!(crate::fingerprint_profile::note_first_use(&url, profile));
    assert!(!crate::fingerprint_profile::note_first_use(&url, profile));
    assert!(!crate::fingerprint_profile::note_first_use(&url, profile));
}

#[test]
fn note_first_use_treats_distinct_profiles_as_distinct_entries() {
    // Same host, different profile — both must log on first use,
    // because operators rotating the strategy at startup should see
    // both identities pop up in logs without per-process restart.
    let url: Url = "wss://note-first-use-profiles.test:443/".parse().unwrap();
    let p1 = &PROFILES[0];
    let p2 = PROFILES
        .iter()
        .find(|p| p.name != p1.name)
        .expect("pool has at least two profiles");
    assert!(crate::fingerprint_profile::note_first_use(&url, p1));
    assert!(crate::fingerprint_profile::note_first_use(&url, p2));
    assert!(!crate::fingerprint_profile::note_first_use(&url, p1));
    assert!(!crate::fingerprint_profile::note_first_use(&url, p2));
}

#[test]
fn note_first_use_treats_distinct_hosts_as_distinct_entries() {
    let url1: Url = "wss://note-first-use-host-a.test:443/".parse().unwrap();
    let url2: Url = "wss://note-first-use-host-b.test:443/".parse().unwrap();
    let profile = &PROFILES[0];
    assert!(crate::fingerprint_profile::note_first_use(&url1, profile));
    assert!(crate::fingerprint_profile::note_first_use(&url2, profile));
    assert!(!crate::fingerprint_profile::note_first_use(&url1, profile));
    assert!(!crate::fingerprint_profile::note_first_use(&url2, profile));
}

#[test]
fn note_first_use_treats_distinct_ports_as_distinct_entries() {
    // Two URLs with the same host but different ports are different
    // peers — `ws_mode_cache` keys them apart, so the deduper should
    // mirror that to keep log granularity consistent.
    let url1: Url = "wss://note-first-use-port.test:443/".parse().unwrap();
    let url2: Url = "wss://note-first-use-port.test:8443/".parse().unwrap();
    let profile = &PROFILES[0];
    assert!(crate::fingerprint_profile::note_first_use(&url1, profile));
    assert!(crate::fingerprint_profile::note_first_use(&url2, profile));
}
