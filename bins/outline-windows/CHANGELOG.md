# Changelog — outline-windows

Russian version: [CHANGELOG.ru.md](CHANGELOG.ru.md).

`outline-windows` is the native Outline Proxy desktop client for Windows (x86_64),
built with Tauri v2, Svelte 5, and Rust. It runs on top of the `outline-ws-rust`
network core, managing the Windows system proxy, Wintun TUN adapter, routing,
server profiles, and subscriptions.

Format follows [Keep a Changelog](https://keepachangelog.com/).

## [1.9.2] - 2026-11-21

### Added

- **Built-in update check and seamless installation system (In-app Updater)**:
  - **Interactive version footer**: shows current build channel, version, and
    commit hash (`nightly · v1.9.2 (971282b6)` for nightly builds or `v1.9.2` for releases).
    Clicking the footer triggers a manual update check with status transitions:
    `проверка обновлений…` ("checking for updates…") → `актуальная версия` ("up to date", 4s)
    or `доступно <label>` ("available <label>") opening the installation dialog.
  - **Silent background check**: queries GitHub releases 5 seconds after startup.
    When an update is found, footer text updates to `доступно <label> — нажмите`
    ("available <label> — click to view") without interrupting the user.
  - **Release channels**: supports `nightly` (tag `windows-nightly` on GitHub Releases
    with commit hash matching) and `release` (tags `windows-v*` selecting the highest SemVer).
  - **Installation dialog `UpdateModal`**: displays release version, release notes, and
    an interactive download progress bar with percentages.
  - **Streaming SHA-256 verification**: fetches `SHA256SUMS.txt`, computes SHA-256
    digest on the fly (`ring::digest::SHA256`) during download, and aborts with
    immediate file removal upon any checksum mismatch.
  - **Zip Slip protection**: safe extraction into temporary staging directory with
    path validation via `zip_file.enclosed_name()`.
  - **Seamless file replacement (`apply_update.cmd`)**: detached updater script
    `outline_update_<pid>.cmd` running in the background (`CREATE_NO_WINDOW | DETACHED_PROCESS`),
    waiting for the application PID to exit, replacing files (`xcopy /Y /Q /E`),
    launching updated `OutlineProxy.exe`, and cleaning up temporary assets.
  - **Automatic tunnel reconnect (`reconnect_after_update`)**: if the tunnel was connected
    before update, the client saves `reconnect_after_update = true` in settings.
    Upon restart, the new executable clears the flag and automatically reconnects to
    the active profile after a 1-second delay.

## [1.9.0] - 2026-08-24

### Added

- **Initial release of native Windows 10/11 client (x86_64)**:
  - GUI built with Svelte 5 (Runes) + Tailwind CSS and Tauri v2.
  - Two operational modes: SOCKS5 (system proxy via WinInet / Registry) and TUN (full L3 VPN via Wintun 0.14.1 driver and Windows IP Helper API).
  - Profile and subscription management: `vless://`, `ss://`, `outline://` import and HTTPS subscriptions.
  - System Tray integration with quick status and connection controls.
  - Real-time traffic and bandwidth monitoring via `outline-ws-rust` control API.
  - Packaging and cross-compilation script `scripts/package-windows.sh`.
