# Outline Proxy — macOS Client

Native macOS menu-bar client (Apple Silicon & Intel) powered by the `outline-ws-rust` proxy engine (VLESS, Shadowsocks AEAD, WebSocket, HTTP/3, padding, failover).

## Features

- **Dual Proxy Modes with One-Click Switching:**
  - **SOCKS5 (System Proxy):** Runs without root or administrator credentials. Automatically manages macOS system proxy configuration via `networksetup`. Ideal for browsers and system-aware applications.
  - **TUN (Full L3 VPN):** Full system network interception through macOS native BSD kernel interface `utun` (`com.apple.net.utun_control`). Captures all traffic (CLI tools, games, background daemons, DNS).
- **Passwordless 1-Click TUN Launch:**
  - Preferences window includes a **"Configure in 1 click..."** button that prompts for admin credentials once and creates a secured, isolated `/etc/sudoers.d/outline-proxy` rule for `tun-runner.sh`.
  - Once configured, full L3 VPN connect and disconnect actions operate instantly in 1 click without any password dialogs. The rule can be removed at any time from the same settings card.
- **Menu Bar Status Item:** One-click connect/disconnect, live status indicator, instant mode and server switcher.
- **"TCP Only" Mode (Bypass HTTP/3):**
  - Instant toggle in Preferences and Menu Bar to force all tunnels to use HTTP/2 or HTTP/1.1 (TCP) carriers instead of HTTP/3 (QUIC/UDP 443).
  - Eliminates connection stalls, handshake timeouts, and repeated fallback cycles in networks where UDP 443 is blocked or throttled by DPI.
- **Profiles & Subscriptions:** Import `vless://`, `ss://`, and `outline://` share links (including clipboard import), plus auto-updating HTTPS config subscriptions.
- **Full macOS Main Menu & Standard Shortcuts:** Complete application menu bar (File, Edit, View, Window, Help) with standard shortcuts: `Cmd+Q` (clean quit with proxy and route teardown), `Cmd+W` (close active window), `Cmd+,` (preferences), `Cmd+O` (main window), `Cmd+L` (logs), `Cmd+Shift+C` (toggle connection), plus full clipboard and undo/redo support in text fields (`Cmd+Z`, `Cmd+C`, `Cmd+V`, `Cmd+A`).
- **Live Logs Window:** Real-time log inspector for connection diagnostics with copy-to-clipboard.
- **Clean Teardown:** Automatic reset of macOS system proxy and kernel routing tables on application exit or interruption.

## Prerequisites

- macOS 13.0 (Ventura) or later.
- Swift 5.9+ (Xcode Command Line Tools suffice; full Xcode is not required).
- Rust 1.75+ (Edition 2024).

## Building & Running

Build and package the complete application with the automated script:

```bash
./macos/scripts/package-app.sh
```

The script performs:
1. Release compilation of the Rust engine (`outline-ws-rust`).
2. Release compilation of the Swift application.
3. Bundle assembly at `macos/dist/OutlineProxy.app` with embedded binary, routing helper `tun-runner.sh`, and `Info.plist` (`LSUIElement = true`).
4. Ad-hoc codesigning for local execution.

### Launching:

```bash
open macos/dist/OutlineProxy.app
```

The shield icon will appear in your macOS menu bar.

## Switching Operational Modes

1. **Via Menu Bar Dropdown:**
   Click the shield icon -> under "Operational Mode" select:
   - `✓ SOCKS5 (System Proxy)`
   - `  TUN (Full VPN)`
2. **Via Preferences:**
   Open Preferences (`Cmd+,`) and select the desired mode from the top banner dropdown.
   If connected, Outline Proxy will seamlessly reconnect using the newly selected mode.

## Updates

The app updates itself from GitHub Releases, following its own build channel: a release build (`macos-v*` tag) moves to the newest `macos-v*` version, a nightly build follows the rolling `macos-nightly` tag and updates whenever the published DMG was built from a different commit.

- **Checking:** click the version line at the bottom of the main window, or choose **"Check for updates..."** in the menu-bar menu. A quiet check also runs at most once a day; a found build only shows up in the footer and the menu, nothing is downloaded until you ask.
- **Installing:** the dialog shows the release notes and offers **"Install and relaunch"**. The app downloads the DMG while bypassing the system proxy (so in SOCKS5 mode the download does not depend on the tunnel being fixed), verifies it against the release's `SHA256SUMS.txt`, unpacks it next to the installed bundle, checks the bundle signature and identifier, quits, swaps the bundles and relaunches. A tunnel that was up reconnects by itself (for TUN without a password only if the sudoers rule is configured). If the swap fails, the old bundle is restored. The swap log is at `~/Library/Logs/OutlineProxy/update.log`.
- **Manual fallback (as on Android):** when the bundle cannot be replaced in place (no write access to its folder, the app runs from an App Translocation copy, a development run outside an `.app`) or the in-place install fails, the verified DMG is saved to `~/Downloads` and opened in Finder; drag Outline Proxy into Applications, replacing the old copy.

Builds without this updater (nightly `4c7821c4` and older) have to be updated manually once.

## Packaging DMG Disk Images

To package the application into a compressed `.dmg` disk image with an `/Applications` drag-and-drop symlink:

```bash
# Build DMG for the host architecture (native):
./macos/scripts/package-app.sh --dmg
# or directly via the packager script:
./macos/scripts/package-dmg.sh

# Build a Universal DMG (Universal Binary: Apple Silicon + Intel):
./macos/scripts/package-dmg.sh --arch universal
```

The output DMG and checksum are saved to `macos/dist/OutlineProxy-v<version>-macOS.dmg` and `.sha256`.

## Continuous Integration (GitHub Actions CI)

macOS image builds are fully automated in the repository:

- **CI Merge Gate (`.github/workflows/ci.yml`):** Compiles a preview `.dmg` on every Pull Request and push to `main`, uploaded as an `OutlineProxy-macOS-preview` artifact (retained for 7 days).
- **Nightly Releases (`.github/workflows/macos-nightly-release.yml`):** Automatically builds a Universal DMG on client changes in `main` and updates the rolling `macos-nightly` release.
- **Tag Releases (`.github/workflows/macos-tag-release.yml`):** Pushing a `macos-v*` tag builds a release Universal DMG, calculates `SHA256SUMS.txt`, generates changelogs via `git-cliff`, and publishes to GitHub Releases.
- **Release Automation (`.github/workflows/macos-release.yml`):** Interactive `workflow_dispatch` runner to bump versions and generate `release: cut macos-v...` commits.
