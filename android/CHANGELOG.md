# Changelog — Android app

The Android VPN client ([`android/`](.)) wraps the `outline-ws-rust` uplink
stack in a `VpnService`, driving the native `outline-tun` engine directly over
the tunnel fd. Releases are cut as `android-v*` tags; CI also publishes a
rolling `android-nightly` prerelease off `main`. This log records user-visible
changes, not every commit.

The format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- **Update check on the build label, with the download it offers.** Tapping the version footer asks GitHub what the build's own channel publishes — a release compares versions across `android-v*` tags, a nightly compares the commit baked into the rolling tag's asset name — and the footer reports the whole run in place (`checking… → downloading 42% → downloaded — tap to install`). The APK is fetched in-process into Downloads through MediaStore, so no storage permission is needed, and the app never installs it: `REQUEST_INSTALL_PACKAGES` is the permission Play Protect weighs heaviest next to a VPN service, so the final tap opens the system Downloads instead, which is a permitted install source.
- **Live status and traffic in the ongoing notification.** The banner refreshes every 2s: its title carries the same state the home screen shows (Connecting… / Connected / No link · profile) and its text the bytes moved this session.
- **An expired subscription is refreshed before connecting.** The periodic worker only keeps configs fresh "eventually" — WorkManager defers under doze — so a connect could dial servers from a stale config. The connect path now refetches a subscription past its refresh interval (capped at 4s) and falls back to the cached config on any failure.
- **Build-version footer**, labelled by what actually identifies the build: a tagged release shows its version and code (`v1.1.2 (57)`), while nightly and local builds show the channel and the commit they came from (`nightly · cdcaf46f`, `dev · 4f71e7ef`) — their version is a fixed placeholder that never moves. CI stamps `BuildConfig` via `BUILD_CHANNEL` / `BUILD_VERSION_NAME` / `BUILD_VERSION_CODE` / `BUILD_GIT_SHA`.

### Changed

- **Dropped the `USE_EXACT_ALARM` permission.** It is reserved for alarm clocks and calendars, and next to the VPN service, `QUERY_ALL_PACKAGES` and boot persistence it completed the permission profile Play Protect scores as stalkerware — which is what got sideloaded builds flagged as malware on install. The keep-alive checklist asks for `SCHEDULE_EXACT_ALARM` instead, and until that is granted the watchdog runs on an inexact alarm.

### Fixed

- The protocol readout names the carrier family of the wire actually in use. It was read off the parent uplink, so a chain that mixes families — the generated config pairs a VLESS primary with `ss://` fallbacks and reshuffles the chain on every connect — kept showing `vless` after the tunnel moved onto a Shadowsocks leg, which made the label look frozen.
- **"No link" no longer flashes while connecting.** The status is debounced over a 2s grace window, and the core reports a link as down only once an outage is *proven* (every uplink explicitly unhealthy) rather than merely unproven — a freshly started tunnel reads as connecting instead.

## [1.1.2] - 2026-08-20

### Added

- **Link-status states.** The card distinguishes Connecting… (up, no link yet, with animated dots), Connected (a live uplink) and No link (up, but no uplink is healthy) instead of a bare connected/disconnected pair.

### Fixed

- The Split Tunneling glyph uses the auto-mirrored `AltRoute` icon, so it flips correctly under RTL layouts.

## [1.1.1] - 2026-08-20

### Added

- **Split-tunnel picker over network-capable apps, with independent allow / deny lists.** The picker lists apps holding `INTERNET` (Android Auto included) rather than launcher entries only, and allow and deny are kept as separate sets.

## [1.1.0] - 2026-08-20

### Added

- **Live tunnel status card** on the home screen: connection duration, bytes moved this session (from Android `TrafficStats`), and the active carrier per transport (`tcp  vless/xhttp/h3`, `udp  ss/ws/h2`) in an elastic three-column layout so the widest carrier label never clips. The carrier is read from the running client over a new `tunnel_status()` FFI.
- **Signed release APK from CI**: a reusable workflow cross-compiles the native library (cargo-ndk) and the UniFFI bindings, assembles a release APK signed from repository secrets (unsigned when they are absent), and publishes it to a GitHub release — on `android-v*` tags (stable) and as a rolling `android-nightly` prerelease.
- **Native TUN data plane**: the app drives the native `outline-tun` engine over the `VpnService` fd — no SOCKS5 listener, no tun2proxy bridge.
- **Config sources**: subscribe to a client config over an HTTPS URL (auto-refreshed on a schedule), or configure a Shadowsocks uplink from an `ss://` share link.
- **Home screen to the brand mockup**: status card, a single connect/disconnect button with state toasts, quick links, an adaptive launcher icon from the emblem, a full-width banner header, and system light/dark theming.
- **Keep-alive**: the tunnel survives task swipe, process kill, reboot, and OEM cleanup, and names the active profile in the ongoing notification.
- **External control** over the `outline://` URI scheme (connect / disconnect / toggle), gated by a switch and an optional token.
- **Split tunneling** (per-app allow / deny).

### Changed

- Moved to the native TUN engine (dropped the SOCKS5 + tun2proxy bridge), uniffi 0.32, AGP 9 with R8, and Gradle 9.7.0.

### Fixed

- No phantom "Connected" after a connect that failed at startup (`is_running()` now reflects the client task's liveness), and a "Couldn't connect: …" message carrying the core's reason instead of a silent failure.
- Bind the tunnel to the best non-VPN network, following Wi-Fi ⇄ cellular handovers.
- System back returns to the list from sub-screens; app-branded status-bar notification icon.
- Build on Linux CI: pick the host cdylib extension by OS (`.so` vs `.dylib`) and resolve an empty `ANDROID_NDK_HOME`.

---

*Русская версия: [CHANGELOG.ru.md](CHANGELOG.ru.md)*
