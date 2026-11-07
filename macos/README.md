# Outline Proxy — macOS client

Russian version: [README.ru.md](README.ru.md).

Native macOS menu-bar client (Apple Silicon and Intel) for the `outline-ws-rust`
proxy engine (VLESS, Shadowsocks AEAD, WebSocket, HTTP/3, padding, failover).
The Swift app starts the engine as a child process and manages the system
proxy, the profiles and the subscriptions around it.

The interface is in Russian only; below, UI labels are quoted as they appear,
with an English gloss.

## Features

- Two operating modes:
  - SOCKS5 (system proxy). Runs without root. The engine listens on
    `127.0.0.1:1080`, and the app sets it as the SOCKS proxy of the active
    network services via `/usr/sbin/networksetup`. Only applications that honour
    the system proxy settings use it.
  - TUN (full L3 VPN). Traffic goes through a macOS `utun` interface
    (`com.apple.net.utun_control`). The helper `tun-runner.sh` runs the engine
    as root, adds host routes to the servers (so the tunnel does not route
    itself) and default sub-routes through the `utun` peer `10.0.85.1`.
    This captures traffic of every process, including CLI tools and DNS.
- Passwordless TUN start. The **Настроить в 1 клик...** ("Configure in 1
  click") button in Settings asks for the administrator password once, copies
  `tun-runner.sh` to `/Library/Application Support/OutlineProxy/tun-runner.sh`
  and writes a `NOPASSWD` rule for that path to `/etc/sudoers.d/outline-proxy`.
  After that, TUN connect and disconnect show no password dialog. The
  **Удалить правило** ("Remove rule") button in the same card removes it.
- Menu-bar item: connect/disconnect, status, mode and server selection.
- "TCP only" mode (no HTTP/3), a switch in Settings and in the menu-bar menu.
  It rewrites the config so that `xhttp_h3` / `ws_h3` carriers become `xhttp_h2`
  / `ws_h2` and `h3` is removed from `alpn=` in share links. Use it on networks
  where UDP 443 is blocked or throttled: without it the engine waits for the
  H3 handshake to time out before falling back to H2. Toggling it while
  connected reconnects the tunnel.
- Profiles and subscriptions: import of `vless://` and `ss://` share links
  (also wrapped in `outline://`), from the clipboard as well, and of
  subscription URLs (`https://`; the parser also accepts `http://`) that are
  re-fetched automatically.
- Main menu (Файл, Правка, Вид, Окно, Справка — File, Edit, View, Window,
  Help) with shortcuts: `Cmd+Q` (quit, removing the system proxy and routes),
  `Cmd+W` (close window), `Cmd+,` (settings), `Cmd+O` (main window), `Cmd+L`
  (logs), `Cmd+Shift+C` (connect/disconnect), `Cmd+M` (minimise), `Cmd+H`
  (hide), plus `Cmd+Z`/`Cmd+Shift+Z`, `Cmd+X`, `Cmd+C`, `Cmd+V`, `Cmd+A` in text
  fields.
- Log window with the engine output and a **Копировать всё** ("Copy all")
  button.
- Cleanup on exit. On quit and on SIGINT/SIGTERM the app removes the system
  proxy and, in TUN mode, the routes. After a crash, the stale
  `127.0.0.1:1080` proxy is switched off at the next launch, and
  `tun-runner.sh` removes leftover routes before it starts a new tunnel.

## Requirements

- macOS 13.0 (Ventura) or later (`LSMinimumSystemVersion`, `Package.swift`).
- Swift 5.9+ (`swift-tools-version: 5.9`). Xcode Command Line Tools are
  enough; full Xcode is not required.
- Rust stable 1.88+: the workspace uses edition 2024 and let-chains.
  [verify: minimum Rust version, `rust-version` is not set in `Cargo.toml`]

## Building and running

Build the app bundle:

```bash
./macos/scripts/package-app.sh
```

The script:

1. Builds `outline-ws-rust` in release mode (`cargo build -p outline-ws-rust --release`).
2. Builds the Swift app (`swift build -c release`).
3. Assembles `macos/dist/Outline Proxy.app`: the Swift binary in
   `Contents/MacOS/OutlineProxy`; the engine, `tun-runner.sh` and image assets in
   `Contents/Resources/`; `Info.plist` with the version, commit, channel and
   build date written in by `PlistBuddy`.
4. Signs the bundle ad-hoc (`codesign --force --deep --sign -`).

Launch:

```bash
open "macos/dist/Outline Proxy.app"
```

The shield icon appears in the menu bar.

## Switching modes

- From the menu-bar menu: click the shield icon and pick a mode under
  **Режим работы:** ("Operating mode"): **SOCKS5 (Системный прокси)** or
  **TUN (Полный VPN)**.
- From Settings (`Cmd+,`): pick the mode in the drop-down at the top.

If the tunnel is up, the app disconnects and reconnects in the new mode
about 0.6 s later.

## Installing from a DMG

Download `OutlineProxy-*-macOS-Universal.dmg` from GitHub Releases
(`macos-nightly` or a `macos-v*` tag), open it and drag Outline Proxy into
Applications.

On the first launch macOS will most likely refuse to open the app and offer to
move it to the Trash. The browser marks downloaded files with the
`com.apple.quarantine` attribute, the mark carries over to the app copied out of
the DMG, and Gatekeeper checks every marked app. The build is signed ad-hoc,
without an Apple Developer ID or notarization, so the check fails. Allow it in
one of two ways:

- Through System Settings: close the dialog with **Done**, open **System
  Settings → Privacy & Security**, find the message about Outline Proxy at the
  bottom and click **Open Anyway**, then confirm with your password. Recent
  macOS versions no longer offer the right-click → **Open** shortcut, so
  Settings is the only way through the UI.
- From Terminal: remove the mark from the installed app:

  ```bash
  xattr -dr com.apple.quarantine "/Applications/Outline Proxy.app"
  ```

This is needed only once, for an app installed from a browser-downloaded DMG.
Updates installed by the app itself (see below) download the DMG without a
browser, carry no quarantine mark and open without the dialog.

## Updates

The app updates itself from GitHub Releases, following its own build channel:
a release build (`macos-v*` tag) moves to the newest `macos-v*` version, a
nightly build follows the rolling `macos-nightly` tag and updates whenever the
published DMG was built from a different commit.

- Checking: click the version line at the bottom of the main window, or choose
  **Проверить обновления...** ("Check for updates") in the menu-bar menu. A
  background check also runs at most once every 24 hours; a found build only
  shows up in the footer and the menu, nothing is downloaded until you ask.
- Installing: the dialog shows the release notes and the **Установить и
  перезапустить** ("Install and relaunch") button. The app downloads the DMG
  bypassing the system proxy (so in SOCKS5 mode the download does not depend on
  the tunnel), verifies it against the release's `SHA256SUMS.txt`, unpacks it
  next to the installed bundle, checks the bundle signature and identifier,
  quits, swaps the bundles and relaunches. A tunnel that was up reconnects by
  itself (in TUN mode without a password prompt only if the sudoers rule is
  configured). If the swap fails, the old bundle is restored. The swap log is
  `~/Library/Logs/OutlineProxy/update.log`.
- Manual fallback (as on Android): when the bundle cannot be replaced in place
  (no write access to its folder, the app runs from an App Translocation copy, a
  development run outside an `.app`) or the in-place install fails, the
  verified DMG is saved to `~/Downloads` and opened in Finder; drag Outline
  Proxy into Applications, replacing the old copy.

Builds without this updater (nightly `4c7821c4` and older) have to be updated
manually once.

## Building a DMG

`package-dmg.sh` builds the app (unless told otherwise) and packs it into a
compressed (`UDZO`) DMG with an `/Applications` symlink for drag-and-drop
installation:

```bash
# Host architecture:
./macos/scripts/package-app.sh --dmg
# or directly:
./macos/scripts/package-dmg.sh

# Universal binary (arm64 + x86_64, joined with lipo):
./macos/scripts/package-dmg.sh --arch universal
```

`package-dmg.sh` options:

| Option | Default | What it does |
|---|---|---|
| `--arch <native\|universal\|aarch64\|x86_64>` | `native` | Target architecture of both binaries |
| `--version <version>` | `version` from `bins/outline-ws-rust/Cargo.toml` | Version in the DMG file name |
| `--output-dir <dir>` | `macos/dist` | Where the DMG is written; a relative path is taken from the repository root |
| `--dmg-name <name>` | see below | Exact DMG file name |
| `--app-path <path>` | — | Use an already built `.app`; implies `--skip-build` |
| `--skip-build` | — | Do not build; pack the existing `macos/dist/Outline Proxy.app` |

Default file names: `OutlineProxy-v<version>-macOS.dmg` for `native`,
`OutlineProxy-v<version>-macOS-Universal.dmg` for `universal`,
`OutlineProxy-v<version>-macOS-<arch>.dmg` otherwise. The checksum is written
next to it as `<dmg-name>.sha256`.

## CI and releases

| Workflow | Trigger | What it does |
|---|---|---|
| `.github/workflows/ci.yml`, job `macos` | Every pull request and push to `main` | `package-dmg.sh --arch native`; uploads the DMG as the `OutlineProxy-macOS-preview` artifact, kept for 7 days |
| `.github/workflows/macos-nightly-release.yml` | Push to `main` touching `macos/**`, `bins/outline-ws-rust/**`, `crates/**`, `vendor/**`, `Cargo.toml`, `Cargo.lock`, `.cargo/**`; manual dispatch | Builds `OutlineProxy-nightly-<sha8>-macOS-Universal.dmg` and updates the rolling `macos-nightly` release |
| `.github/workflows/macos-tag-release.yml` | Push of a `macos-v*` tag | Builds `OutlineProxy-v<version>-macOS-Universal.dmg`, writes `SHA256SUMS.txt`, generates release notes with `git-cliff` and publishes a GitHub release |
| `.github/workflows/macos-release.yml` | Manual (`workflow_dispatch`) | Bumps the version and commits `release: cut macos-v...` to `main` |
