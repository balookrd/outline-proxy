# Outline Proxy — macOS Client

Native macOS menu-bar client (Apple Silicon & Intel) powered by the `outline-ws-rust` proxy engine (VLESS, Shadowsocks AEAD, WebSocket, HTTP/3, padding, failover).

## Features

- **Dual Proxy Modes with One-Click Switching:**
  - **SOCKS5 (System Proxy):** Runs without root or administrator credentials. Automatically manages macOS system proxy configuration via `networksetup`. Ideal for browsers and system-aware applications.
  - **TUN (Full L3 VPN):** Full system network interception through macOS native BSD kernel interface `utun` (`com.apple.net.utun_control`). Captures all traffic (CLI tools, games, background daemons, DNS). Prompts for administrator credentials (Touch ID / password) upon connection to create the device and manage kernel routing tables (`0.0.0.0/1` and `128.0.0.0/1`).
- **Menu Bar Status Item:** One-click connect/disconnect, live status indicator, instant mode and server switcher.
- **Profiles & Subscriptions:** Import `vless://`, `ss://`, and `outline://` share links (including clipboard import), plus auto-updating HTTPS config subscriptions.
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
