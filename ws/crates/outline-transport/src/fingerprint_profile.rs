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
    /// of the process. An on-path observer of **one** peer sees a
    /// single identity per peer — but if the same observer also
    /// sees the client's other peers (global DPI, ISP-level
    /// inspection, anti-bot CDN engine watching all fronted hosts)
    /// the per-host hash produces **different** browser identities
    /// for the same source IP, which is itself a strong signal.
    /// Use only when peers are fully decoupled across observers
    /// (different AS, different jurisdictions); otherwise prefer
    /// [`Self::ProcessStable`].
    PerHostStable,
    /// Same profile across **every** dial in this process. An
    /// observer sees the source IP consistently as one browser
    /// identity, matching how a real user actually behaves. The
    /// pick is seeded from `$HOSTNAME` / `%COMPUTERNAME%` when
    /// available, so identity stays the same across restarts on
    /// the same machine; in container / sandbox environments where
    /// no hostname is set, the seed falls back to a fresh random
    /// pick at process start (identity rotates on restart, but
    /// remains stable for the duration of the process). This is
    /// the recommended default whenever the operator has no
    /// specific reason to prefer a per-peer split.
    ProcessStable,
    /// Fresh random profile on every dial. Useful when probing or
    /// when a peer-stable identity is undesirable (testing).
    Random,
}

impl Strategy {
    /// Stable, lowercase, snake_case label for this variant. Used as a
    /// Prometheus label value and as a snapshot field — the dashboard
    /// alerts and config reload tests both key on this exact string,
    /// so renaming a variant here is a wire-format break.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::PerHostStable => "per_host_stable",
            Self::ProcessStable => "process_stable",
            Self::Random => "random",
        }
    }

    /// Every label value [`Self::as_str`] can return. Snapshot
    /// renderers iterate this so an info-style gauge can publish a
    /// 0 row for inactive strategies before flipping the active one
    /// to 1.
    pub const ALL: &'static [Strategy] = &[
        Strategy::None,
        Strategy::PerHostStable,
        Strategy::ProcessStable,
        Strategy::Random,
    ];
}

impl std::fmt::Display for Strategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Strategy {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "off" | "none" | "disabled" => Ok(Self::None),
            // `stable` is intentionally NOT an alias for `per_host_stable`
            // anymore — it now resolves to `process_stable`, the
            // recommended default. Operators upgrading from older configs
            // get the safer behaviour automatically; those who specifically
            // want the per-host split must spell `per_host_stable` /
            // `per-host` in full.
            "stable" | "process" | "process_stable" | "process-stable" => {
                Ok(Self::ProcessStable)
            },
            "per_host_stable" | "per-host-stable" | "per-host" | "per_host" => {
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
pub const PROFILES_REFRESHED_AT_UNIX: u64 = 1_778_284_800; // 2026-05-09 00:00 UTC

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
        name: "chrome-142-windows",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: Some("\"Chromium\";v=\"142\", \"Google Chrome\";v=\"142\", \"Not?A_Brand\";v=\"99\""),
        sec_ch_ua_mobile: Some("?0"),
        sec_ch_ua_platform: Some("\"Windows\""),
    },
    Profile {
        name: "chrome-142-macos",
        // Chrome on macOS still pins `10_15_7` (Catalina) in the UA
        // string — Google froze that in 2021 to stop User-Agent
        // leaking the real macOS version. Recent Chrome stable still
        // ships the same string in 2026, so we mirror it. The actual
        // OS version travels via `Sec-CH-UA-Platform-Version` when
        // negotiated; we don't advertise that header in this pool.
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: Some("\"Chromium\";v=\"142\", \"Google Chrome\";v=\"142\", \"Not?A_Brand\";v=\"99\""),
        sec_ch_ua_mobile: Some("?0"),
        sec_ch_ua_platform: Some("\"macOS\""),
    },
    Profile {
        name: "firefox-150-windows",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language: "en-US,en;q=0.5",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: None,
        sec_ch_ua_mobile: None,
        sec_ch_ua_platform: None,
    },
    Profile {
        name: "firefox-150-macos",
        // Firefox uses the actual macOS major in its UA (unlike
        // Chrome's frozen `10_15_7`). macOS 16 (Tahoe) is current
        // stable as of 2026-05; Firefox follows via
        // `Intel Mac OS X 16.4`. Apple-silicon machines still
        // surface as `Intel Mac OS X` here — Firefox has no separate
        // ARM string in the UA.
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 16.4; rv:150.0) Gecko/20100101 Firefox/150.0",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language: "en-US,en;q=0.5",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: None,
        sec_ch_ua_mobile: None,
        sec_ch_ua_platform: None,
    },
    Profile {
        // Safari major releases ride the macOS yearly cadence:
        // Safari 17 (Sonoma, 2023), Safari 18 (Sequoia, 2024),
        // Safari 19 (Tahoe, 2025). Patch 19.4 is the May-2026
        // stable; the UA still pins `10_15_7` like Chrome does.
        name: "safari-19-macos",
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.4 Safari/605.1.15",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language: "en-US,en;q=0.9",
        // Safari still does NOT advertise `zstd` as of 19.x — Apple
        // has not shipped the algorithm in WebKit. Keep the list
        // short so the profile reads as Safari rather than
        // Chrome-with-different-UA.
        accept_encoding: "gzip, deflate, br",
        sec_ch_ua: None,
        sec_ch_ua_mobile: None,
        sec_ch_ua_platform: None,
    },
    Profile {
        name: "edge-142-windows",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: Some("\"Chromium\";v=\"142\", \"Microsoft Edge\";v=\"142\", \"Not?A_Brand\";v=\"99\""),
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

/// Returns the process-wide strategy set by [`init_strategy`], or
/// the default ([`Strategy::None`]) when nothing was wired. Snapshot
/// builders read this to surface the active default on the
/// dashboard / Prometheus when the per-uplink override is absent.
///
/// Note: this is the **declared** default, not the strategy the next
/// dial will actually see — a task-local override pushed via
/// [`with_strategy_override`] supersedes this for the duration of the
/// scope. The snapshot path runs outside any such scope, so this is
/// the right value to show on the dashboard.
pub fn current_strategy() -> Strategy {
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
        Strategy::ProcessStable => Some(&PROFILES[process_index()]),
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

/// Process-wide profile index used by [`Strategy::ProcessStable`].
///
/// Seeded from the OS-level hostname when available — that keeps
/// identity stable across restarts on the same machine, which
/// matches how a real user with a single browser actually appears to
/// an on-path observer. When the hostname syscall fails or returns
/// empty (containers without a hostname set, minimal sandboxes), the
/// seed falls back to `rand::random` at process start: identity then
/// rotates on every restart but stays consistent for the duration of
/// the process — still strictly better than per-host split, just not
/// stable across restarts.
///
/// **Why not `$HOSTNAME` env-var?** On Linux / macOS `$HOSTNAME` is a
/// shell-internal variable (set by bash / zsh in interactive shells),
/// **not** part of the process environment. systemd, docker, cron,
/// launchd — none of them propagate it. Reading `std::env::var("HOSTNAME")`
/// in a daemon-like process therefore returns `None` almost always,
/// which would make ProcessStable fall through to the random fallback
/// in production deployments — exactly the opposite of "stable across
/// restarts". So we call `gethostname(2)` directly. Windows is
/// different: `%COMPUTERNAME%` IS set on every process by the OS,
/// so reading env there is correct.
fn process_index() -> usize {
    static IDX: OnceLock<usize> = OnceLock::new();
    *IDX.get_or_init(|| match read_hostname() {
        Some(name) => {
            let mut hasher = DefaultHasher::new();
            name.hash(&mut hasher);
            (hasher.finish() as usize) % PROFILES.len()
        },
        None => rand::random::<usize>() % PROFILES.len(),
    })
}

/// Returns the OS-reported hostname, trimmed and non-empty, or `None`
/// when the syscall fails or yields an empty string. On Unix uses
/// `gethostname(2)` directly because `$HOSTNAME` is a shell-internal
/// variable that daemons never see; on Windows reads
/// `%COMPUTERNAME%` (which Windows actually puts in the process env).
#[cfg(unix)]
fn read_hostname() -> Option<String> {
    // POSIX `_POSIX_HOST_NAME_MAX` is 255; +1 for NUL gives 256. Real
    // systems sometimes carry longer names (FQDNs in containers); we
    // keep the buffer at 256 because the seed only needs *something
    // stable*, not the full FQDN — truncated bytes still hash to a
    // stable value.
    let mut buf = [0u8; 256];
    // SAFETY: `gethostname` writes up to `buf.len()` bytes into the
    // pointer we hand it; we own the buffer for the duration of the
    // call. The function returns 0 on success and sets `errno` on
    // failure; we only treat 0 as "data available". The result may
    // not be NUL-terminated when the hostname is exactly buf.len()
    // bytes, so we scan for the first NUL ourselves and fall back to
    // the full buffer if there is none.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = std::str::from_utf8(&buf[..end]).ok()?.trim();
    if s.is_empty() { None } else { Some(s.to_string()) }
}

#[cfg(windows)]
fn read_hostname() -> Option<String> {
    std::env::var("COMPUTERNAME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(not(any(unix, windows)))]
fn read_hostname() -> Option<String> {
    // No hostname API on the current target — fall through to the
    // random seed. The caller treats `None` as "no stable seed
    // available, rotate on restart".
    None
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
