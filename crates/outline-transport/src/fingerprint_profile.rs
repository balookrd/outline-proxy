//! Per-host browser fingerprint profile pool used to diversify the
//! HTTP-layer surface of WS / XHTTP dials.
//!
//! Without a profile the dial path advertises no `User-Agent`, no
//! `Accept-Language`, no `Sec-Fetch-*` — a regex-DPI rule like
//! "WS upgrade missing User-Agent" trivially separates this client
//! from real browser traffic. A profile mixes in the headers its
//! browser sends for the request the carrier really makes (a `fetch()`
//! GET / POST for xhttp, a WebSocket for ws; laid out by
//! `crate::request_headers`), and a per-host-stable selector makes the choice deterministic per
//! `(host, port)` so a single observer sees a single identity per
//! peer instead of a per-dial reshuffle (which is itself a signal).
//!
//! Profiles are picked only from the sub-pool matching the OS the client
//! really runs on ([`host_os`], see [`pool_for`]): macOS = Chrome / Firefox /
//! Safari, Linux = Chrome / Firefox, Android = Chrome. The TLS family does not vary by OS: Chrome on Android
//! sends the desktop Chromium ClientHello (confirmed 2026-10-30: Chrome
//! Android 156.0.8078.73 on Android 17 matches desktop Chrome 156 byte for
//! byte, trust anchors included). 0-RTT is not aligned with the browsers yet.
//!
//! The pool is process-wide and opt-in: callers wire a `Strategy`
//! at startup via [`init_strategy`]. The default is [`Strategy::None`]
//! — no headers are added (TLS dials still send the Chromium ClientHello).
//! Cross-transport session-resumption headers
//! (`X-Outline-Resume*`) are inserted by the dial sites independently
//! of this module; they ride on top of whatever profile is active.
//!
//! What this module does NOT do:
//! * It does not shape the TLS ClientHello itself: that is done by
//!   `crate::tcp_tls_profile` (TCP carriers, the certificate check and
//!   the HTTPS probe) and `crate::quic::tls_profile` (H3), both through
//!   the vendored rustls client-hello shape. This module only picks the
//!   profile they follow.
//! * It does not shape HTTP/2 SETTINGS, windows or header order itself:
//!   `crate::h2_profile` does, per the profile's browser family, as far
//!   as `hyper`/`h2` allow (pseudo-header order, the priority flag,
//!   Firefox's first stream id, Safari's SETTINGS order and id 9 and the
//!   always-sent MAX_HEADER_LIST_SIZE stay hyper's). QUIC transport
//!   parameters are shaped by `crate::quic`.

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{OnceLock, RwLock};

use anyhow::{Result, bail};
use url::Url;

/// How the dial path picks a profile from [`PROFILES`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Strategy {
    /// No profile applied: no `User-Agent` / `Accept-Language` /
    /// `Sec-Fetch-*` headers are added. TLS dials (TCP and QUIC) still
    /// send the Chromium ClientHello. Default.
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
    pub const ALL: &'static [Strategy] =
        &[Strategy::None, Strategy::PerHostStable, Strategy::ProcessStable, Strategy::Random];
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
            "stable" | "process" | "process_stable" | "process-stable" => Ok(Self::ProcessStable),
            "per_host_stable" | "per-host-stable" | "per-host" | "per_host" => {
                Ok(Self::PerHostStable)
            },
            "random" => Ok(Self::Random),
            other => bail!("unknown fingerprint profile strategy: {other}"),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Strategy {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// TLS-layer browser family a [`Profile`] mimics. Selects the browser
/// whose ClientHello the dial sends ([`crate::tcp_tls_profile`] over TCP,
/// `crate::quic::tls_profile` over QUIC), so the JA4 surface lines up
/// with the HTTP-layer identity the same profile advertises — a Chrome
/// `User-Agent` paired with a stock rustls ClientHello is itself a
/// mismatch a fingerprinting DPI can key on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TlsFingerprint {
    /// Chromium family — Chrome, Edge, and other Blink/BoringSSL clients.
    Chromium,
    /// Gecko (Firefox, NSS).
    Firefox,
    /// WebKit (Safari) — Apple's URLSession / Network.framework.
    Safari,
}

/// Operating system a [`Profile`] claims to run on. The dial path only
/// picks profiles whose `os` matches the OS the client really runs on
/// ([`host_os`]): the TCP SYN (TTL, option layout) is visible to a DPI
/// right next to the ClientHello, so a Safari hello from a Linux stack
/// is an incompatible pair. There is no Windows client, so no Windows pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProfileOs {
    MacOs,
    Linux,
    Android,
}

/// OS the running binary targets, resolved at compile time. Every OS
/// without a dedicated pool (Windows, BSDs, ...) maps to [`ProfileOs::Linux`].
/// Android is checked first: `target_os = "android"` is distinct from
/// `"linux"` for rustc, but the explicit ordering keeps the intent clear.
pub const fn host_os() -> ProfileOs {
    if cfg!(target_os = "android") {
        ProfileOs::Android
    } else if cfg!(target_os = "macos") {
        ProfileOs::MacOs
    } else {
        ProfileOs::Linux
    }
}

/// A single browser identity. Values are `&'static` so the whole
/// pool is a single `const` table — selection is a hash-and-index,
/// no allocation, no string copies.
#[derive(Clone, Copy, Debug)]
pub struct Profile {
    pub name: &'static str,
    /// OS this identity claims; selection is restricted to [`host_os`].
    pub os: ProfileOs,
    pub user_agent: &'static str,
    pub accept_language: &'static str,
    pub accept_encoding: &'static str,
    /// Client Hints. `None` for browsers that do not emit them
    /// (Firefox, Safari) — leaving the header off is itself the
    /// signature.
    pub sec_ch_ua: Option<&'static str>,
    pub sec_ch_ua_mobile: Option<&'static str>,
    pub sec_ch_ua_platform: Option<&'static str>,
    /// TLS-layer family whose ClientHello cipher / kx ordering this
    /// profile's dials should mimic, kept consistent with the HTTP
    /// identity above (Chrome UA ⇒ Chromium TLS order, etc.).
    pub tls: TlsFingerprint,
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
pub const PROFILES_REFRESHED_AT_UNIX: u64 = 1_793_381_218; // 2026-10-30 UTC

/// Maximum tolerated age of [`PROFILES`] before the staleness test
/// fails. Six months is short enough to keep up with browser-major
/// drift (Chrome ships ~6 majors per year) and long enough that
/// regular contributors are not woken up by the nag.
pub const REFRESH_PERIOD_SECS: u64 = 180 * 24 * 60 * 60;

/// Catalog of representative browser identities, one per (browser, OS)
/// pair a real client of that OS can plausibly be: Chrome on all three
/// OSes, Firefox on macOS / Linux, Safari on macOS. Only the sub-pool of the host OS is ever selected (see
/// [`pool_for`]); the other entries stay for tests and snapshots.
pub const PROFILES: &[Profile] = &[
    Profile {
        name: "chrome-156-macos",
        os: ProfileOs::MacOs,
        tls: TlsFingerprint::Chromium,
        // Chrome on macOS still pins `10_15_7` (Catalina) in the UA
        // string — Google froze that in 2021 to stop User-Agent
        // leaking the real macOS version. Recent Chrome stable still
        // ships the same string in 2026 (macOS 27 does not change
        // it), so we mirror it. The actual OS version travels via
        // `Sec-CH-UA-Platform-Version` when negotiated; we don't
        // advertise that header in this pool.
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: Some(
            "\"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"156\", \"Google Chrome\";v=\"156\"",
        ),
        sec_ch_ua_mobile: Some("?0"),
        sec_ch_ua_platform: Some("\"macOS\""),
    },
    Profile {
        name: "chrome-156-linux",
        os: ProfileOs::Linux,
        tls: TlsFingerprint::Chromium,
        // Chrome on Linux reports `x86_64` even on aarch64 hosts (UA
        // Reduction), so one string covers every Linux client.
        user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: Some(
            "\"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"156\", \"Google Chrome\";v=\"156\"",
        ),
        sec_ch_ua_mobile: Some("?0"),
        sec_ch_ua_platform: Some("\"Linux\""),
    },
    Profile {
        name: "chrome-156-android",
        os: ProfileOs::Android,
        tls: TlsFingerprint::Chromium,
        // UA Reduction freezes Android Chrome at `Android 10; K` and a
        // `Mobile Safari` tail. The TLS family stays Chromium: measured
        // 2026-10-30, Chrome Android 156.0.8078.73 (Android 17) sends the
        // desktop Chrome 156 ClientHello byte for byte, trust anchors included.
        user_agent: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: Some(
            "\"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"156\", \"Google Chrome\";v=\"156\"",
        ),
        sec_ch_ua_mobile: Some("?1"),
        sec_ch_ua_platform: Some("\"Android\""),
    },
    Profile {
        name: "firefox-159-macos",
        os: ProfileOs::MacOs,
        tls: TlsFingerprint::Firefox,
        // Firefox caps the reported macOS version at `10.15` in its UA
        // (Bugzilla 1679929, shipped in Firefox 87) — exactly like
        // Chrome/Safari freeze `10_15_7`, just spelled with dots and
        // no patch component. So a real Firefox on macOS 27 still
        // sends `Intel Mac OS X 10.15`, NOT the true `27.x`; emitting
        // the actual major would itself be the fingerprint. Apple-
        // silicon machines still surface as `Intel Mac OS X` here —
        // Firefox has no separate ARM string in the UA.
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:159.0) Gecko/20100101 Firefox/159.0",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: None,
        sec_ch_ua_mobile: None,
        sec_ch_ua_platform: None,
    },
    Profile {
        name: "firefox-159-linux",
        os: ProfileOs::Linux,
        tls: TlsFingerprint::Firefox,
        // Header values measured on macOS Firefox 159 and extrapolated to
        // Linux (only the UA platform token differs).
        user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: None,
        sec_ch_ua_mobile: None,
        sec_ch_ua_platform: None,
    },
    Profile {
        // Apple switched to year-based version numbers at WWDC 2025:
        // the release after Safari 18 (Sequoia, 2024) is Safari 26,
        // then 27 with macOS 27. The UA still pins `10_15_7` for the
        // OS like Chrome does; only the `Version/` token tracks the
        // release (major.minor).
        name: "safari-27-macos",
        os: ProfileOs::MacOs,
        tls: TlsFingerprint::Safari,
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0.1 Safari/605.1.15",
        accept_language: "en-US,en;q=0.9",
        // Measured 2026-10-31 (Safari 27.0.1): over HTTPS Safari offers
        // `zstd` too (over plain http only `gzip, deflate`).
        accept_encoding: "gzip, deflate, br, zstd",
        sec_ch_ua: None,
        sec_ch_ua_mobile: None,
        sec_ch_ua_platform: None,
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

/// What the current dial pinned in its task-local scope.
#[derive(Clone, Copy, Debug)]
enum DialScope {
    /// The profile the dial picked (`None` = no profile under the active
    /// strategy). [`select`] returns it verbatim and the TLS family follows
    /// it, so the ClientHello, the HTTP/2 SETTINGS and the request headers of
    /// one dial all come from the same browser even under
    /// [`Strategy::Random`].
    Profile(Option<&'static Profile>),
    /// A bare TLS family with no profile pinned: [`select`] keeps its
    /// unscoped behaviour. Only tests push this, to drive the TLS / h2
    /// builders for one family directly.
    #[cfg(test)]
    Fingerprint(Option<TlsFingerprint>),
}

tokio::task_local! {
    /// The current dial's pinned profile, set by [`with_dial_profile`]. The
    /// dial path picks one [`Profile`] per connection and pins it here so
    /// every later [`select`] in the same dial returns it and the TLS-config
    /// builder ([`crate::tls::build_client_config`]) and the HTTP/2 shape
    /// ([`crate::h2_profile`]) mimic its family — without threading the
    /// value through every transport signature. Same propagation as
    /// [`STRATEGY_OVERRIDE`]: it follows awaited futures but not
    /// freshly-spawned tasks, which is exactly the dial → TLS-handshake →
    /// request-headers path (all awaited inline; post-handshake tasks reuse
    /// the profile and config captured by the dial).
    static DIAL_SCOPE: DialScope;
}

/// Pick the profile for `url` once and run `f` with it pinned: every
/// [`select`] inside `f` returns that same profile and
/// [`current_dial_fingerprint`] its TLS family. Wrap the whole dial future
/// (TCP + TLS + handshake + request headers). Outside any such scope
/// [`select`] picks afresh under the active strategy, as before. One scope
/// covers one dial to one `url`'s host; a nested scope keeps the outer pin.
pub(crate) async fn with_dial_profile<F>(url: &Url, f: F) -> F::Output
where
    F: std::future::Future,
{
    let profile = select(url);
    DIAL_SCOPE.scope(DialScope::Profile(profile), f).await
}

/// Run `f` as a dial that pinned `profile` (the dial path's own
/// [`with_dial_profile`] keeps an outer pin), so a test can drive a whole dial
/// with one chosen browser.
#[cfg(test)]
pub(crate) async fn with_pinned_profile<F>(profile: Option<&'static Profile>, f: F) -> F::Output
where
    F: std::future::Future,
{
    DIAL_SCOPE.scope(DialScope::Profile(profile), f).await
}

/// Run `f` with a bare dial-scoped TLS family (no profile pinned), as the
/// TLS / h2 builders read it. `None` sends the Chromium ClientHello.
#[cfg(test)]
pub(crate) async fn with_dial_fingerprint<F>(fp: Option<TlsFingerprint>, f: F) -> F::Output
where
    F: std::future::Future,
{
    DIAL_SCOPE.scope(DialScope::Fingerprint(fp), f).await
}

/// The dial-scoped TLS fingerprint (the pinned profile's family), or `None`
/// outside any dial scope (probes, tests) and for a dial without a profile.
pub(crate) fn current_dial_fingerprint() -> Option<TlsFingerprint> {
    match DIAL_SCOPE.try_with(|scope| *scope) {
        Ok(DialScope::Profile(profile)) => profile.map(|p| p.tls),
        #[cfg(test)]
        Ok(DialScope::Fingerprint(fp)) => fp,
        Err(_) => None,
    }
}

/// The dial-scoped TLS family with the no-profile case normalised to
/// Chromium, the ClientHello and transport parameters such a dial sends. Shared
/// connection caches key on this so a connection opened as one browser never
/// carries a dial pinned to another.
#[cfg(feature = "h3")]
pub(crate) fn dial_tls_family() -> TlsFingerprint {
    current_dial_fingerprint().unwrap_or(TlsFingerprint::Chromium)
}

/// The profile pinned by an enclosing [`with_dial_profile`] scope:
/// `Some(pinned)` inside a dial, `None` outside any (or under a bare
/// test-only fingerprint scope).
fn pinned_dial_profile() -> Option<Option<&'static Profile>> {
    match DIAL_SCOPE.try_with(|scope| *scope) {
        Ok(DialScope::Profile(profile)) => Some(profile),
        #[cfg(test)]
        Ok(DialScope::Fingerprint(_)) => None,
        Err(_) => None,
    }
}

/// Returns the profile selected for `url` under the active strategy,
/// or `None` when fingerprint diversification is disabled. Inside a
/// [`with_dial_profile`] scope it returns the profile that dial pinned, so a
/// [`Strategy::Random`] dial does not mix two browsers. Logs the
/// (host, port, profile.name) triple at `info` the first time each
/// distinct combination is observed in the current process — useful
/// for operators verifying that the strategy actually engaged and for
/// correlating dial failures with a specific profile choice.
pub fn select(url: &Url) -> Option<&'static Profile> {
    if let Some(pinned) = pinned_dial_profile() {
        return pinned;
    }
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

/// Profiles selectable on `os`, in [`PROFILES`] order. Profiles of
/// other OSes stay in the catalog (tests, snapshots) but are never
/// picked on this OS. Per-OS pools: macOS = Chrome, Firefox, Safari;
/// Linux = Chrome, Firefox; Android = Chrome.
pub(crate) fn pool_for(os: ProfileOs) -> impl Iterator<Item = &'static Profile> {
    PROFILES.iter().filter(move |p| p.os == os)
}

fn pick(os: ProfileOs, seed: usize) -> &'static Profile {
    // One pass over `PROFILES` into a stack buffer (no allocation on the
    // dial path), then index it.
    let mut pool = [&PROFILES[0]; PROFILES.len()];
    let mut len = 0;
    for profile in pool_for(os) {
        pool[len] = profile;
        len += 1;
    }
    assert!(len > 0, "every OS has a non-empty pool");
    pool[seed % len]
}

/// Variant of [`select`] that ignores the process-wide
/// [`init_strategy`] and uses `strategy` directly. Exposed so unit
/// tests can drive the selector without poisoning the global
/// `OnceLock`. Picks from the pool of the OS the binary runs on.
pub fn select_with_strategy(url: &Url, strategy: Strategy) -> Option<&'static Profile> {
    select_with_strategy_for_os(url, strategy, host_os())
}

/// [`select_with_strategy`] for an explicit OS, so tests can cover
/// every per-OS pool from a single host.
pub fn select_with_strategy_for_os(
    url: &Url,
    strategy: Strategy,
    os: ProfileOs,
) -> Option<&'static Profile> {
    match strategy {
        Strategy::None => None,
        Strategy::PerHostStable => Some(pick(os, host_index(url))),
        Strategy::ProcessStable => Some(pick(os, process_index())),
        Strategy::Random => Some(pick(os, rand::random_range(0..usize::MAX))),
    }
}

/// Stable hash of `(host, port)`; reduced modulo the sub-pool size by [`pick`].
fn host_index(url: &Url) -> usize {
    let host = url.host_str().unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or(0);
    let mut hasher = DefaultHasher::new();
    host.hash(&mut hasher);
    port.hash(&mut hasher);
    hasher.finish() as usize
}

/// Process-wide profile seed (reduced modulo the sub-pool size by [`pick`])
/// used by [`Strategy::ProcessStable`].
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
            hasher.finish() as usize
        },
        None => rand::random_range(0..usize::MAX),
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

#[cfg(test)]
#[path = "tests/fingerprint_profile.rs"]
mod tests;
