# Changelog — Android app

The Android VPN client ([`android/`](.)) wraps the `outline-ws-rust` uplink
stack in a `VpnService`, driving the native `outline-tun` engine directly over
the tunnel fd. It has not had a stable release yet: CI publishes a rolling
`android-nightly` prerelease, and stable releases will ship under `android-v*`
tags. This log records user-visible changes, not every commit.

The format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- **Live tunnel status card** on the home screen: connection duration, bytes moved this session (from Android `TrafficStats`), and the active carrier per transport (`tcp  vless/xhttp/h3`, `udp  ss/ws/h2`) in an elastic three-column layout so the widest carrier label never clips. The carrier is read from the running client over a new `tunnel_status()` FFI.
- **Build-version footer** (`v0.1.0 (1) · <sha>`) whose name / code / commit CI stamps into `BuildConfig` via `BUILD_VERSION_NAME` / `BUILD_VERSION_CODE` / `BUILD_GIT_SHA`.
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
