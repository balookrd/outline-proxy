//! Per-host browser fingerprint profile pool used to diversify the
//! HTTP-layer surface of WS / XHTTP dials.
//!
//! Without a profile the dial path advertises no `User-Agent`, no
//! `Accept-Language`, no `Sec-Fetch-*` — a regex-DPI rule like
//! "WS upgrade missing User-Agent" trivially separates this client
//! from real browser traffic. A profile mixes in the headers a
//! representative browser would send for the equivalent navigation,
//! and a per-host-stable selector makes the choice deterministic per
//! `(host, port)` so a single observer sees a single identity per
//! peer instead of a per-dial reshuffle (which is itself a signal).
//!
//! The pool is process-wide and opt-in: callers wire a `Strategy`
//! at startup via [`init_strategy`]. The default is [`Strategy::None`]
//! — no headers are added, wire shape stays byte-identical to the
//! pre-profile builds. Cross-transport session-resumption headers
//! (`X-Outline-Resume*`) are inserted by the dial sites independently
//! of this module; they ride on top of whatever profile is active.
//!
//! What this module does NOT do:
//! * It does not touch TLS ClientHello or ALPN ordering — both of
//!   those are owned by `crate::tls` and the per-carrier TLS configs.
//!   Diversifying them is a separate, costlier pass that would need
//!   a uTLS-style stack (`boring`/BoringSSL) instead of vanilla
//!   rustls.
//! * It does not touch HTTP/2 SETTINGS or QUIC transport-parameters
//!   ordering. Those are owned by `hyper`/`h2` and `quinn` and have
//!   their own (largely closed) fingerprint surface.

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{OnceLock, RwLock};

use anyhow::{Result, bail};
use http::{HeaderMap, HeaderValue, header};
use url::Url;

/// How the dial path picks a profile from [`PROFILES`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Strategy {
    /// No profile applied — current process behaves as if this
    /// module did not exist. Default so existing deployments keep
    /// the exact wire shape they had before the knob landed.
    #[default]
    None,
    /// Same profile for the same `(host, port)` for the lifetime
    /// of the process. An on-path observer sees one identity per
    /// peer instead of a per-dial reshuffle.
    PerHostStable,
    /// Fresh random profile on every dial. Useful when probing or
    /// when a peer-stable identity is undesirable (testing).
    Random,
}

impl std::str::FromStr for Strategy {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "off" | "none" | "disabled" => Ok(Self::None),
            "stable" | "per_host_stable" | "per-host-stable" | "per-host" => {
                Ok(Self::PerHostStable)
            },
            "random" => Ok(Self::Random),
            other => bail!("unknown fingerprint profile strategy: {other}"),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Strategy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// A single browser identity. Values are `&'static` so the whole
/// pool is a single `const` table — selection is a hash-and-index,
/// no allocation, no string copies.
#[derive(Clone, Copy, Debug)]
pub struct Profile {
    pub name: &'static str,
    pub user_agent: &'static str,
    pub accept: &'static str,
    pub accept_language: &'static str,
    pub accept_encoding: &'static str,
    /// Client Hints. `None` for browsers that do not emit them
    /// (Firefox, Safari) — leaving the header off is itself the
    /// signature.
    pub sec_ch_ua: Option<&'static str>,
    pub sec_ch_ua_mobile: Option<&'static str>,
    pub sec_ch_ua_platform: Option<&'static str>,
}

/// UNIX seconds-since-epoch when [`PROFILES`] was last reviewed
/// against current browser releases. Used by the accompanying
/// staleness test in `tests/fingerprint_profile.rs`: once the value
/// is more than [`REFRESH_PERIOD_SECS`] in the past, `cargo test`
/// nags the operator into bumping the UA strings before they age
/// past detection (a DPI rule with a whitelist of current versions
/// reads "Chrome 130 in 2027" as an obvious old client and starts
/// re-detecting this binary). To refresh: update each `user_agent`
/// and `sec_ch_ua` field in the table below, bump the constant to
/// the current `date +%s`, then re-run the suite.
pub const PROFILES_REFRESHED_AT_UNIX: u64 = 1_777_593_600; // 2026-05-01 00:00 UTC

/// Maximum tolerated age of [`PROFILES`] before the staleness test
/// fails. Six months is short enough to keep up with browser-major
/// drift (Chrome ships ~6 majors per year) and long enough that
/// regular contributors are not woken up by the nag.
pub const REFRESH_PERIOD_SECS: u64 = 180 * 24 * 60 * 60;

/// Pool of representative browser identities. Six entries spread
/// across the three Chromium-derived UAs (Chrome × 2 OS, Edge × 1)
/// and the two non-Chromium UAs (Firefox × 2 OS, Safari × 1) so a
/// per-host-stable selector lands on a Chromium identity for ~⅔ of
/// peers and a Gecko/WebKit identity for the remaining ⅓ — matching
/// rough real-world browser-share, which is what a passive observer
/// expects to see across many independent peers.
pub const PROFILES: &[Profile] = &[
    Profile {
        name: "chrome-130-windows",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: Some("\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\""),
        sec_ch_ua_mobile: Some("?0"),
        sec_ch_ua_platform: Some("\"Windows\""),
    },
    Profile {
        name: "chrome-130-macos",
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: Some("\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\""),
        sec_ch_ua_mobile: Some("?0"),
        sec_ch_ua_platform: Some("\"macOS\""),
    },
    Profile {
        name: "firefox-130-windows",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language: "en-US,en;q=0.5",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: None,
        sec_ch_ua_mobile: None,
        sec_ch_ua_platform: None,
    },
    Profile {
        name: "firefox-130-macos",
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:130.0) Gecko/20100101 Firefox/130.0",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language: "en-US,en;q=0.5",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: None,
        sec_ch_ua_mobile: None,
        sec_ch_ua_platform: None,
    },
    Profile {
        name: "safari-17-macos",
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language: "en-US,en;q=0.9",
        // Safari does not advertise `zstd` even on Sonoma — keep the
        // list short so the profile reads as Safari rather than
        // Chrome-with-different-UA.
        accept_encoding: "gzip, deflate, br",
        sec_ch_ua: None,
        sec_ch_ua_mobile: None,
        sec_ch_ua_platform: None,
    },
    Profile {
        name: "edge-130-windows",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: Some("\"Chromium\";v=\"130\", \"Microsoft Edge\";v=\"130\", \"Not?A_Brand\";v=\"99\""),
        sec_ch_ua_mobile: Some("?0"),
        sec_ch_ua_platform: Some("\"Windows\""),
    },
];

static STRATEGY: OnceLock<Strategy> = OnceLock::new();

/// Wire the strategy at startup. First call wins; subsequent calls
/// are silently ignored to mirror the shape of [`crate::init_h2_window_sizes`]
/// and [`crate::init_downgrade_ttl`].
pub fn init_strategy(strategy: Strategy) {
    let _ = STRATEGY.set(strategy);
}

fn current_strategy() -> Strategy {
    STRATEGY.get().copied().unwrap_or_default()
}

tokio::task_local! {
    /// Per-call strategy override. When the dial path runs inside a
    /// task whose parent established this scope, [`select`] reads
    /// the override instead of the global [`init_strategy`] value —
    /// callers like the uplink manager use this to pin one uplink
    /// to a specific profile (or to none) without flipping the
    /// process-wide knob. Inheritance is the standard tokio
    /// `task_local` behaviour: scopes propagate into the future
    /// awaited inside [`with_strategy_override`], but not into
    /// freshly-spawned `tokio::spawn` children — which is exactly
    /// what we want, because the dial entry-point is the only place
    /// that calls [`select`].
    static STRATEGY_OVERRIDE: Strategy;
}

/// Run `f` with [`select`] honouring `strategy` instead of the
/// process-wide [`init_strategy`] value. Designed for the uplink
/// manager: per-uplink dial calls wrap their `connect_*` await in
/// this scope so a single uplink can pin its own profile without
/// affecting siblings on the same `host:port`.
pub async fn with_strategy_override<F>(strategy: Strategy, f: F) -> F::Output
where
    F: std::future::Future,
{
    STRATEGY_OVERRIDE.scope(strategy, f).await
}

/// Strategy [`select`] should consult: the task-local override when
/// one is in scope, otherwise the global `init_strategy` value (or
/// the default if neither was set).
fn current_effective_strategy() -> Strategy {
    STRATEGY_OVERRIDE
        .try_with(|s| *s)
        .unwrap_or_else(|_| current_strategy())
}

/// Returns the profile selected for `url` under the active strategy,
/// or `None` when fingerprint diversification is disabled. Logs the
/// (host, port, profile.name) triple at `info` the first time each
/// distinct combination is observed in the current process — useful
/// for operators verifying that the strategy actually engaged and for
/// correlating dial failures with a specific profile choice.
pub fn select(url: &Url) -> Option<&'static Profile> {
    let profile = select_with_strategy(url, current_effective_strategy())?;
    note_first_use(url, profile);
    Some(profile)
}

/// Process-wide log dedup for [`select`]. Returns `true` when the
/// `(host, port, profile.name)` triple is being logged for the first
/// time in this process, `false` for every subsequent call. Logging
/// happens as a side effect; the bool return value lets unit tests
/// drive the deduper without depending on tracing-test plumbing.
pub(crate) fn note_first_use(url: &Url, profile: &'static Profile) -> bool {
    static LOGGED: OnceLock<RwLock<HashSet<(String, u16, &'static str)>>> = OnceLock::new();
    let map = LOGGED.get_or_init(|| RwLock::new(HashSet::new()));
    let host = url.host_str().unwrap_or_default().to_owned();
    let port = url.port_or_known_default().unwrap_or(0);
    let key = (host, port, profile.name);
    // Fast path: read lock is enough when the entry is already there,
    // so the hot dial path costs at most one shared read after the
    // first observation per host.
    if map
        .read()
        .expect("fingerprint-profile log set lock poisoned")
        .contains(&key)
    {
        return false;
    }
    let inserted = map
        .write()
        .expect("fingerprint-profile log set lock poisoned")
        .insert(key);
    if inserted {
        tracing::info!(
            host = %url.host_str().unwrap_or_default(),
            port = url.port_or_known_default().unwrap_or(0),
            profile = profile.name,
            "fingerprint profile bound to host"
        );
    }
    inserted
}

/// Variant of [`select`] that ignores the process-wide
/// [`init_strategy`] and uses `strategy` directly. Exposed so unit
/// tests can drive the selector without poisoning the global
/// `OnceLock`.
pub fn select_with_strategy(url: &Url, strategy: Strategy) -> Option<&'static Profile> {
    match strategy {
        Strategy::None => None,
        Strategy::PerHostStable => Some(&PROFILES[host_index(url)]),
        Strategy::Random => Some(&PROFILES[rand::random::<usize>() % PROFILES.len()]),
    }
}

fn host_index(url: &Url) -> usize {
    let host = url.host_str().unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or(0);
    let mut hasher = DefaultHasher::new();
    host.hash(&mut hasher);
    port.hash(&mut hasher);
    (hasher.finish() as usize) % PROFILES.len()
}

/// Sec-Fetch-* triplet variant. The values browsers send depend on
/// the request kind: a WebSocket upgrade gets `mode=websocket,dest=websocket`,
/// an XHR/fetch carrying a body gets `mode=cors,dest=empty`. Picking
/// the wrong triplet for the carrier is itself a fingerprint, so the
/// caller specifies which one matches the request being built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecFetchPreset {
    WebsocketUpgrade,
    XhrCors,
}

impl SecFetchPreset {
    fn site(self) -> &'static str {
        "same-origin"
    }
    fn mode(self) -> &'static str {
        match self {
            Self::WebsocketUpgrade => "websocket",
            Self::XhrCors => "cors",
        }
    }
    fn dest(self) -> &'static str {
        match self {
            Self::WebsocketUpgrade => "websocket",
            Self::XhrCors => "empty",
        }
    }
}

/// Append the profile's identification headers to `headers`.
///
/// Headers already present (`Accept` is the only realistic case —
/// some XHTTP carriers may want to pin a specific value to mirror
/// xray's wire shape) are left untouched. Everything else is
/// inserted unconditionally; the caller is expected to pass a
/// freshly-built `HeaderMap` that does not yet carry browser-style
/// identity headers.
pub fn apply(profile: &Profile, headers: &mut HeaderMap, sec_fetch: SecFetchPreset) {
    headers.insert(header::USER_AGENT, HeaderValue::from_static(profile.user_agent));
    if !headers.contains_key(header::ACCEPT) {
        headers.insert(header::ACCEPT, HeaderValue::from_static(profile.accept));
    }
    headers.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static(profile.accept_language));
    headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static(profile.accept_encoding));
    if let Some(v) = profile.sec_ch_ua {
        headers.insert("sec-ch-ua", HeaderValue::from_static(v));
    }
    if let Some(v) = profile.sec_ch_ua_mobile {
        headers.insert("sec-ch-ua-mobile", HeaderValue::from_static(v));
    }
    if let Some(v) = profile.sec_ch_ua_platform {
        headers.insert("sec-ch-ua-platform", HeaderValue::from_static(v));
    }
    headers.insert("sec-fetch-site", HeaderValue::from_static(sec_fetch.site()));
    headers.insert("sec-fetch-mode", HeaderValue::from_static(sec_fetch.mode()));
    headers.insert("sec-fetch-dest", HeaderValue::from_static(sec_fetch.dest()));
}

#[cfg(test)]
#[path = "tests/fingerprint_profile.rs"]
mod tests;
