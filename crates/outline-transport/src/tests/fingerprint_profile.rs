//! Unit tests for [`crate::fingerprint_profile`].
//!
//! Tests use [`select_with_strategy`] instead of [`select`] so the
//! process-wide `OnceLock` strategy is not poisoned by the suite —
//! a `select` test would force the global into one value and leak
//! that into every subsequent test in the same `cargo test` binary.

use std::str::FromStr;

use url::Url;

use crate::fingerprint_profile::{
    PROFILES, Profile, ProfileOs, Strategy, TlsFingerprint, host_os, pool_for,
    select_with_strategy, select_with_strategy_for_os,
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
    // A single hostname pair can collide on the same profile (the host OS
    // pool is small); a sweep makes the test reliably hit the "different
    // profile" case at least once.
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
fn strategy_from_str_accepts_documented_aliases() {
    assert_eq!(Strategy::from_str("").unwrap(), Strategy::None);
    assert_eq!(Strategy::from_str("off").unwrap(), Strategy::None);
    assert_eq!(Strategy::from_str("none").unwrap(), Strategy::None);
    assert_eq!(Strategy::from_str("DISABLED").unwrap(), Strategy::None);
    // The bare `stable` alias intentionally maps to ProcessStable —
    // that's the safer recommended default, and operators carrying
    // older configs get the better behaviour automatically. Those
    // who *specifically* want the per-host split must spell
    // `per_host_stable` in full.
    assert_eq!(Strategy::from_str("stable").unwrap(), Strategy::ProcessStable);
    assert_eq!(Strategy::from_str("process").unwrap(), Strategy::ProcessStable,);
    assert_eq!(Strategy::from_str("process_stable").unwrap(), Strategy::ProcessStable,);
    assert_eq!(Strategy::from_str("process-stable").unwrap(), Strategy::ProcessStable,);
    assert_eq!(Strategy::from_str("per_host_stable").unwrap(), Strategy::PerHostStable,);
    assert_eq!(Strategy::from_str("per-host-stable").unwrap(), Strategy::PerHostStable,);
    assert_eq!(Strategy::from_str("per-host").unwrap(), Strategy::PerHostStable,);
    assert_eq!(Strategy::from_str("random").unwrap(), Strategy::Random);
}

#[test]
fn strategy_from_str_rejects_unknown_aliases() {
    assert!(Strategy::from_str("perma").is_err());
    assert!(Strategy::from_str("rotate").is_err());
}

#[test]
fn strategy_as_str_round_trips_through_from_str() {
    // Wire-format contract: snapshot field, Prometheus label, and TOML
    // alias all use this exact set. Renaming a variant here is a
    // breaking change for the Prometheus consumer, so the round-trip
    // test fails if the canonical token drifts.
    for s in Strategy::ALL.iter().copied() {
        let parsed = Strategy::from_str(s.as_str())
            .unwrap_or_else(|e| panic!("{} did not round-trip: {e}", s.as_str()));
        assert_eq!(parsed, s);
    }
    assert_eq!(Strategy::None.as_str(), "none");
    assert_eq!(Strategy::PerHostStable.as_str(), "per_host_stable");
    assert_eq!(Strategy::ProcessStable.as_str(), "process_stable");
    assert_eq!(Strategy::Random.as_str(), "random");
}

#[test]
fn select_with_process_stable_returns_same_profile_across_hosts() {
    // ProcessStable is the whole-process identity strategy: all
    // dials in this binary, regardless of dial URL, must land on
    // the same profile — that's the entire point compared to
    // PerHostStable, where a single source IP would otherwise leak
    // multiple browser identities to a global on-path observer.
    let url_a: Url = "wss://aeza.example.com/SECRET/tcp".parse().unwrap();
    let url_b: Url = "wss://senko.example.com:8443/different/path".parse().unwrap();
    let url_c: Url = "https://nuxt.example.com:443/xhttp".parse().unwrap();
    let pa = select_with_strategy(&url_a, Strategy::ProcessStable).unwrap();
    let pb = select_with_strategy(&url_b, Strategy::ProcessStable).unwrap();
    let pc = select_with_strategy(&url_c, Strategy::ProcessStable).unwrap();
    assert_eq!(pa.name, pb.name);
    assert_eq!(pa.name, pc.name);
}

#[test]
fn read_hostname_returns_something_on_typical_systems() {
    // The seed source for ProcessStable across restarts. Linux /
    // macOS / Windows test runners always have a hostname set —
    // `gethostname(2)` returns the current value; an empty result
    // would silently push ProcessStable into the per-restart-random
    // fallback, which is what we want to catch.
    //
    // Container CI without a hostname IS possible (e.g.
    // `docker run --hostname=""`), in which case the assertion
    // would fail meaningfully — operators should explicitly set a
    // hostname there for stability. Local dev never hits that.
    let h = crate::fingerprint_profile::read_hostname()
        .expect("gethostname must succeed on the test runner");
    assert!(!h.is_empty(), "hostname should not be empty");
    // Sanity: trimmed string, no embedded NULs.
    assert!(!h.contains('\0'), "hostname must be NUL-trimmed: {h:?}");
}

#[test]
fn select_with_process_stable_is_idempotent_within_process() {
    // Repeated calls within one process must hit the cached
    // OnceLock-backed index — calling twice in a row must not flip
    // the picked profile. (Tests can't validate cross-process
    // stability, only within-process; the cross-restart guarantee
    // is documented behaviour driven by `$HOSTNAME` seeding.)
    let url: Url = "wss://example.com/SECRET/tcp".parse().unwrap();
    let first = select_with_strategy(&url, Strategy::ProcessStable).unwrap();
    for _ in 0..16 {
        let again = select_with_strategy(&url, Strategy::ProcessStable).unwrap();
        assert_eq!(first.name, again.name);
    }
}

#[test]
fn current_strategy_returns_default_when_init_was_skipped() {
    // The OnceLock can only be set once per process; the binary tests
    // never call `init_strategy`, so this should always read the
    // default. If a future change starts populating it as a side
    // effect of importing the module, snapshot consumers (Prometheus
    // and the dashboard JSON) would silently flip — catch that here.
    assert_eq!(crate::fingerprint_profile::current_strategy(), Strategy::None);
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

#[tokio::test]
async fn dial_fingerprint_scope_sets_and_clears() {
    use crate::fingerprint_profile::{
        TlsFingerprint, current_dial_fingerprint, with_dial_fingerprint,
    };
    // Outside any scope the dial path sees no fingerprint (default provider).
    assert_eq!(current_dial_fingerprint(), None);
    // Inside the scope it reads exactly what was pushed...
    with_dial_fingerprint(Some(TlsFingerprint::Firefox), async {
        assert_eq!(current_dial_fingerprint(), Some(TlsFingerprint::Firefox));
    })
    .await;
    // ...and the scope does not leak past the awaited future.
    assert_eq!(current_dial_fingerprint(), None);
}

#[tokio::test]
async fn client_config_cached_per_fingerprint() {
    use std::sync::Arc;

    use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};
    use crate::tls::build_client_config;
    // Same (fingerprint, ALPN) returns the cached Arc; a different family
    // builds a distinct config (that browser's ClientHello). Every build goes
    // through `builder_with_provider`, so no process-default crypto provider
    // is needed.
    let chromium_a = with_dial_fingerprint(Some(TlsFingerprint::Chromium), async {
        build_client_config(&[b"h2"])
    })
    .await;
    let chromium_b = with_dial_fingerprint(Some(TlsFingerprint::Chromium), async {
        build_client_config(&[b"h2"])
    })
    .await;
    let firefox = with_dial_fingerprint(Some(TlsFingerprint::Firefox), async {
        build_client_config(&[b"h2"])
    })
    .await;
    assert!(Arc::ptr_eq(&chromium_a, &chromium_b), "same fingerprint+ALPN must be cached");
    assert!(
        !Arc::ptr_eq(&chromium_a, &firefox),
        "different fingerprint must build a distinct config"
    );
}

#[test]
fn profile_pool_must_be_refreshed_at_least_every_refresh_period() {
    // The pool's UA / Sec-CH-UA strings encode specific browser-major
    // versions. They go stale fast — Chrome ships ~6 majors per year,
    // so a year-old "Chrome 130" looks like an old client to any DPI
    // with a current-version whitelist. This test fails once the
    // last refresh is older than `REFRESH_PERIOD_SECS` so a routine
    // `cargo test` run nags the operator before that detection
    // window opens. To unblock: update each `user_agent` /
    // `sec_ch_ua` to the latest stable release, bump
    // `PROFILES_REFRESHED_AT_UNIX` to the current Unix timestamp.
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is before UNIX epoch")
        .as_secs();
    let refreshed = crate::fingerprint_profile::PROFILES_REFRESHED_AT_UNIX;
    let period = crate::fingerprint_profile::REFRESH_PERIOD_SECS;
    assert!(
        now <= refreshed.saturating_add(period),
        "PROFILES has not been refreshed in {} days (limit {} days). \
         Update the UA strings to current Chrome/Firefox/Safari/Edge releases, \
         bump PROFILES_REFRESHED_AT_UNIX, and re-run.",
        now.saturating_sub(refreshed) / 86_400,
        period / 86_400,
    );
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

#[tokio::test]
async fn task_local_override_supersedes_default_global() {
    // Default global strategy is `None` until `init_strategy` is
    // called (which the test binary never does). A per-call
    // task-local override must therefore flip select() from None
    // to Some without touching the global.
    let url: Url = "wss://task-local-override.example/".parse().unwrap();
    let outer = crate::fingerprint_profile::select(&url);
    let inner =
        crate::fingerprint_profile::with_strategy_override(Strategy::PerHostStable, async {
            crate::fingerprint_profile::select(&url)
        })
        .await;
    let after = crate::fingerprint_profile::select(&url);
    assert!(outer.is_none(), "no scope, default global is None");
    assert!(inner.is_some(), "task-local override applies inside the scope");
    assert!(after.is_none(), "scope drops on `.await` completion");
}

#[tokio::test]
async fn task_local_none_override_disables_inside_scope() {
    // Useful inversion: an uplink that explicitly opts OUT of
    // fingerprint diversification (e.g. to keep a byte-identical
    // xray-style wire shape) wraps its dial in
    // `with_strategy_override(Strategy::None, …)`. Verify the inner
    // select() returns None even if a higher-priority scope or future
    // global default would otherwise pick a profile.
    let url: Url = "wss://task-local-none-override.example/".parse().unwrap();
    let inner = crate::fingerprint_profile::with_strategy_override(Strategy::None, async {
        crate::fingerprint_profile::select(&url)
    })
    .await;
    assert!(inner.is_none(), "explicit None override disables selection");
}

#[tokio::test]
async fn nested_task_local_override_uses_innermost_value() {
    // Inner scope wins over outer scope — that's what tokio's
    // `task_local!::scope` already guarantees, but the test pins the
    // contract so a future refactor that swaps the storage primitive
    // does not silently change semantics.
    let url: Url = "wss://nested-override.example/".parse().unwrap();
    let inner =
        crate::fingerprint_profile::with_strategy_override(Strategy::PerHostStable, async {
            crate::fingerprint_profile::with_strategy_override(Strategy::None, async {
                crate::fingerprint_profile::select(&url)
            })
            .await
        })
        .await;
    assert!(inner.is_none(), "innermost override wins");
}

/// A `random` dial picks once: inside one `with_dial_profile` scope every
/// header-profile lookup returns the pinned profile and the TLS family (and so
/// the ClientHello config and the HTTP/2 shape) is that profile's — never a
/// ClientHello of one browser with headers of another.
#[tokio::test]
async fn random_dial_scope_pins_one_profile_for_tls_and_headers() {
    use std::collections::HashSet;
    use std::sync::Arc;

    use crate::fingerprint_profile::{
        current_dial_fingerprint, select, with_dial_profile, with_strategy_override,
    };
    use crate::h2_profile::h2_shape;
    use crate::tls::{build_client_config, build_client_config_for};

    let url: Url = "wss://random-dial-pin.example/ws".parse().unwrap();
    let pool_len = pool_for(host_os()).count();
    let picked = with_strategy_override(Strategy::Random, async {
        let mut picked = HashSet::new();
        for _ in 0..200 {
            let name = with_dial_profile(&url, async {
                let pinned = select(&url).expect("random always picks a profile");
                assert_eq!(current_dial_fingerprint(), Some(pinned.tls));
                for _ in 0..16 {
                    let again = select(&url).expect("pinned profile");
                    assert!(std::ptr::eq(again, pinned), "{} vs {}", again.name, pinned.name);
                    assert_eq!(current_dial_fingerprint(), Some(pinned.tls));
                }
                assert_eq!(h2_shape(current_dial_fingerprint()), h2_shape(Some(pinned.tls)));
                assert!(Arc::ptr_eq(
                    &build_client_config(&[b"h2"]),
                    &build_client_config_for(Some(pinned.tls), &[b"h2"]),
                ));
                pinned.name
            })
            .await;
            picked.insert(name);
        }
        picked
    })
    .await;
    // The pin is per dial, not per process: across dials `random` still
    // varies whenever the host pool has more than one profile.
    if pool_len > 1 {
        assert!(picked.len() > 1, "random must still vary across dials: {picked:?}");
    }
}

/// Outside a dial scope `select` keeps its unpinned behaviour: under `random`
/// consecutive calls pick independently.
#[tokio::test]
async fn select_outside_dial_scope_is_not_pinned() {
    use std::collections::HashSet;

    use crate::fingerprint_profile::{current_dial_fingerprint, select, with_strategy_override};

    if pool_for(host_os()).count() < 2 {
        return;
    }
    let url: Url = "wss://random-unpinned.example/".parse().unwrap();
    let picked: HashSet<_> = with_strategy_override(Strategy::Random, async {
        (0..200).map(|_| select(&url).expect("random picks").name).collect()
    })
    .await;
    assert!(picked.len() > 1, "unscoped random select must vary: {picked:?}");
    assert_eq!(current_dial_fingerprint(), None);
}

/// A dial under a `None` strategy pins "no profile": no headers, and the TLS
/// family stays unset (Chromium hello / shape).
#[tokio::test]
async fn dial_scope_without_profile_pins_none() {
    use crate::fingerprint_profile::{
        current_dial_fingerprint, select, with_dial_profile, with_strategy_override,
    };

    let url: Url = "wss://dial-pin-none.example/".parse().unwrap();
    let (profile, fp) = with_strategy_override(Strategy::None, async {
        with_dial_profile(&url, async { (select(&url), current_dial_fingerprint()) }).await
    })
    .await;
    assert!(profile.is_none());
    assert_eq!(fp, None);
}

const ALL_OS: [ProfileOs; 3] = [ProfileOs::MacOs, ProfileOs::Linux, ProfileOs::Android];

fn names(os: ProfileOs) -> Vec<&'static str> {
    pool_for(os).map(|p| p.name).collect()
}

fn by_name(name: &str) -> &'static Profile {
    PROFILES
        .iter()
        .find(|p| p.name == name)
        .unwrap_or_else(|| panic!("no profile {name}"))
}

#[test]
fn per_os_pools_have_the_decided_members() {
    assert_eq!(
        names(ProfileOs::MacOs),
        ["chrome-156-macos", "firefox-159-macos", "safari-27-macos"]
    );
    assert_eq!(names(ProfileOs::Linux), ["chrome-156-linux", "firefox-159-linux"]);
    assert_eq!(names(ProfileOs::Android), ["chrome-156-android"]);
}

#[test]
fn linux_and_android_pools_have_no_safari() {
    for os in [ProfileOs::Linux, ProfileOs::Android] {
        assert!(pool_for(os).all(|p| p.tls != TlsFingerprint::Safari), "{os:?}");
    }
}

#[test]
fn selection_stays_inside_the_requested_os_pool() {
    for os in ALL_OS {
        for i in 0..50 {
            let url = Url::parse(&format!("wss://host-{i}.test:443/")).unwrap();
            let p = select_with_strategy_for_os(&url, Strategy::PerHostStable, os).unwrap();
            assert_eq!(p.os, os, "per_host_stable {os:?} -> {}", p.name);
        }
        let url = Url::parse("wss://process.test/").unwrap();
        let p = select_with_strategy_for_os(&url, Strategy::ProcessStable, os).unwrap();
        assert_eq!(p.os, os);
        for _ in 0..200 {
            let p = select_with_strategy_for_os(&url, Strategy::Random, os).unwrap();
            assert_eq!(p.os, os, "random {os:?} -> {}", p.name);
        }
        assert!(select_with_strategy_for_os(&url, Strategy::None, os).is_none());
    }
}

#[test]
fn default_selection_uses_the_host_os_pool() {
    let url = Url::parse("wss://host-os.test/").unwrap();
    for s in [Strategy::PerHostStable, Strategy::ProcessStable, Strategy::Random] {
        assert_eq!(select_with_strategy(&url, s).unwrap().os, host_os());
    }
}

#[test]
fn host_os_matches_the_compile_target() {
    #[cfg(target_os = "macos")]
    assert_eq!(host_os(), ProfileOs::MacOs);
    #[cfg(target_os = "linux")]
    assert_eq!(host_os(), ProfileOs::Linux);
    #[cfg(target_os = "windows")]
    assert_eq!(host_os(), ProfileOs::Linux);
    #[cfg(target_os = "android")]
    assert_eq!(host_os(), ProfileOs::Android);
}

#[test]
fn profile_names_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for p in PROFILES {
        assert!(seen.insert(p.name), "duplicate profile name {}", p.name);
    }
}

#[test]
fn user_agent_and_client_hints_agree_with_profile_os() {
    for p in PROFILES {
        let marker = match p.os {
            ProfileOs::MacOs => "Macintosh",
            ProfileOs::Linux => "X11; Linux",
            ProfileOs::Android => "Linux; Android",
        };
        assert!(p.user_agent.contains(marker), "{}: UA lacks {marker}", p.name);
        if let Some(platform) = p.sec_ch_ua_platform {
            let want = match p.os {
                ProfileOs::MacOs => "\"macOS\"",
                ProfileOs::Linux => "\"Linux\"",
                ProfileOs::Android => "\"Android\"",
            };
            assert_eq!(platform, want, "{}", p.name);
        }
        let mobile = if p.os == ProfileOs::Android { "?1" } else { "?0" };
        if p.sec_ch_ua.is_some() {
            assert_eq!(p.sec_ch_ua_mobile, Some(mobile), "{}", p.name);
        }
    }
}

const CHROME_UA_TAIL: &str = "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0";
const CHROME_HINTS: &str =
    "\"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"156\", \"Google Chrome\";v=\"156\"";

#[test]
fn chrome_156_values_match_the_measurement() {
    let ua = |os: &str, tail: &str| format!("Mozilla/5.0 ({os}) {CHROME_UA_TAIL} {tail}");
    for (name, os_part, tail) in [
        ("chrome-156-macos", "Macintosh; Intel Mac OS X 10_15_7", "Safari/537.36"),
        ("chrome-156-linux", "X11; Linux x86_64", "Safari/537.36"),
        ("chrome-156-android", "Linux; Android 10; K", "Mobile Safari/537.36"),
    ] {
        let p = by_name(name);
        assert_eq!(p.user_agent, ua(os_part, tail), "{name}");
        assert_eq!(p.accept_language, "en-US,en;q=0.9", "{name}");
        assert_eq!(p.accept_encoding, "gzip, deflate, br, zstd", "{name}");
        assert_eq!(p.sec_ch_ua, Some(CHROME_HINTS), "{name}");
        assert_eq!(p.tls, TlsFingerprint::Chromium, "{name}");
    }
}

#[test]
fn firefox_159_values_match_the_measurement() {
    for (name, ua) in [
        (
            "firefox-159-macos",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:159.0) Gecko/20100101 Firefox/159.0",
        ),
        (
            "firefox-159-linux",
            "Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0",
        ),
    ] {
        let p = by_name(name);
        assert_eq!(p.user_agent, ua, "{name}");
        assert_eq!(p.accept_language, "en-US,en;q=0.9", "{name}");
        assert_eq!(p.accept_encoding, "gzip, deflate, br, zstd", "{name}");
        assert!(p.sec_ch_ua.is_none(), "{name}");
        assert_eq!(p.tls, TlsFingerprint::Firefox, "{name}");
    }
}

#[test]
fn safari_27_values() {
    let p = by_name("safari-27-macos");
    assert_eq!(
        p.user_agent,
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0.1 Safari/605.1.15"
    );
    assert_eq!(p.accept_encoding, "gzip, deflate, br, zstd");
    assert_eq!(p.tls, TlsFingerprint::Safari);
}
