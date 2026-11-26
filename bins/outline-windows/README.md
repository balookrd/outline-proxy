# Outline Proxy — Windows client

Russian version: [README.ru.md](README.ru.md).

Native desktop client for Windows 10/11 (x86_64) built with Tauri v2 and Svelte 5.
Runs on top of the high-performance `outline-client` proxy engine (VLESS,
Shadowsocks AEAD, WebSocket, HTTP/3, padding, failover): the application launches
the engine as a managed child process and orchestrates system proxy settings,
profiles, subscriptions, and routing around it.

The user interface is in Russian; all labels and dialogs are tailored for a
native experience on Windows.

## Architecture

The application is structured as a modular system:

- **GUI Frontend**: Svelte 5 (Runes), TypeScript, Tailwind CSS, Vite.
  A compact window with adaptive light and dark themes, tunnel control cards,
  server profiles list, real-time log viewer, and settings dialogs.
- **Application Backend (Tauri v2 + Rust Edition 2024)**:
  - `process_controller.rs` — lifecycle management, child process monitoring, and
    graceful shutdown of `outline-client.exe`.
  - `profile_store.rs` — persistent storage for server profiles, settings, and
    subscriptions in `%APPDATA%\su.beerloga.outline.windows` (JSON manifest).
  - `traffic_monitor.rs` — polls the built-in control API of `outline-client`
    to display downlink/uplink speeds and total transferred data in real time.
  - `tray.rs` — Windows notification area (System Tray) integration: tray icon
    and context menu for quick connection, profile switching, mode selection, and exit.
  - `updater.rs` / `version.rs` — in-app update checker and installer with
    checksum verification.
- **Proxy Engine (`outline-client.exe`)**: the compiled client engine from the
  monorepo workspace.
- **Operating Modes**:
  - **SOCKS5 (System Proxy)**: engine listens on `127.0.0.1:1080`, and the app
    configures Windows system proxy via WinInet API and the Windows Registry
    (`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`:
    `ProxyEnable = 1`, `ProxyServer = 127.0.0.1:1080`). Runs without administrative
    privileges.
  - **TUN (Full L3 VPN)**: creates a virtual network interface using the official
    high-performance **Wintun** driver (`wintun.dll`). The app configures routes
    via the Windows IP Helper API (`windows-sys` Win32_NetworkManagement_IpHelper) —
    explicit host routes to proxy server endpoints via the physical default gateway
    (to prevent routing loops) and default route `0.0.0.0/0` via the Wintun adapter.
    Captures all system network traffic, including Windows system services, CLI tools,
    and DNS queries. Includes IPv6 leak protection. Requires administrator privileges.

## Update Mechanism and In-App Updater

The client includes a built-in update check and seamless installation flow without
requiring external installer wizards.

### Interactive Version Footer
The bottom of the main application window features an interactive version footer:
- **Nightly builds**: `nightly · v1.9.2 (971282b6)` (channel, version, and short commit SHA).
- **Release builds**: `v1.9.2`.

Clicking the footer triggers a manual update check:
1. The footer status switches to `проверка обновлений…` ("checking for updates…").
2. If already up to date, it displays `актуальная версия` ("up to date") for 4 seconds
   before reverting to the version label.
3. If an update is available, it shows `доступно <label>` ("update available <label>")
   and opens the `UpdateModal` dialog.

### Silent Background Check
Five seconds after application startup, a quiet background check queries GitHub for
new builds. If an update is detected, the footer text changes to
`доступно <label> — нажмите` ("update available <label> — click to view") without
interrupting user activity or displaying intrusive popup modals.

### Update Channels
The release channel is set at build time via the `OUTLINE_BUILD_CHANNEL` environment variable:
- **`nightly`** (default): queries the `windows-nightly` release tag via the
  GitHub API (`https://api.github.com/repos/balookrd/outline-proxy/releases/tags/windows-nightly`).
  Matches the commit SHA from the `OutlineProxy-x86_64-<commit>.zip` asset against
  the running binary commit (supporting prefix matching and ignoring the `-dirty` suffix).
- **`release`**: queries the `/releases/latest` endpoint via the GitHub API
  (`https://api.github.com/repos/balookrd/outline-proxy/releases/latest`), matching
  unified CalVer `v*` tags and downloading the `OutlineProxy-v<ver>-Windows-x86_64.zip` asset.

### Integrity Verification via `SHA256SUMS.txt`
To protect against corrupted downloads or file tampering, strict verification is
performed before installation:
1. The application fetches `SHA256SUMS.txt` from the release assets.
2. The update zip archive is streamed chunk-by-chunk (`reqwest`), computing the
   SHA-256 digest on the fly via `sha2` (`sha2::Sha256`) into a temporary
   file in `%TEMP%`.
3. The `UpdateModal` displays download progress with an accurate percentage bar.
4. Once download finishes, the calculated SHA-256 hash is compared against the entry
   in `SHA256SUMS.txt`. If there is any mismatch, the temporary file is deleted
   immediately and the update is aborted with an error.

### Safe Extraction without Zip Slip
The archive is extracted into a staging folder under `%TEMP%`.
Each file entry is validated using `zip_file.enclosed_name()` — any entry containing
directory traversal elements like `../` or absolute paths is rejected, neutralizing
the Zip Slip vulnerability.

### Seamless File Replacement (`apply_update.cmd`) and Auto-Reconnect
Because the running application executable is locked by Windows against overwrites,
replacement is delegated to a detached helper script:
1. **Auto-reconnect flag**: if the tunnel is currently active,
   `settings.reconnect_after_update = true` is saved in `profile_store`, and the
   proxy engine is cleanly stopped.
2. **Updater script**: a temporary batch file `outline_update_<pid>.cmd` is spawned
   as a detached process without a console window (`CREATE_NO_WINDOW | DETACHED_PROCESS`):
   - Loops using `tasklist` waiting for the application process PID to terminate.
   - Copies extracted files from staging into the application directory (`xcopy /Y /Q /E`).
   - Launches the new `OutlineProxy.exe`.
   - Cleans up the staging directory and self-deletes (`del "%~f0"`).
3. **Automatic reconnection**: upon launch, the updated `OutlineProxy.exe` detects
   `reconnect_after_update`, clears the flag to `false`, saves settings, and
   after a 1-second delay automatically connects back to the previously active
   server profile.

## Build and Packaging

Building and packaging the Windows client is automated with `scripts/package-windows.sh`.

### Prerequisites
- **Rust**: `nightly` or `stable` toolchain with the `x86_64-pc-windows-msvc` target.
- **Node.js**: Node 20+, `pnpm` package manager.
- **Cross-compilation tools** (when building from macOS / Linux):
  - `cargo-xwin` (`cargo install cargo-xwin`).
  - LLVM and LLD (`brew install llvm lld` on macOS).

### Build Commands

Check environment and prerequisites without compiling:
```bash
./scripts/package-windows.sh --check-only
```

Full release build:
```bash
./scripts/package-windows.sh
```

Build only the proxy engine (`outline-client.exe`) and Wintun driver (skip GUI):
```bash
./scripts/package-windows.sh --skip-ui
```

The packaging script:
1. Builds frontend assets via `pnpm build` (`bins/outline-windows/dist`).
2. Compiles `outline-client` for `x86_64-pc-windows-msvc`.
3. Compiles the `outline-windows` GUI wrapper for `x86_64-pc-windows-msvc`.
4. Downloads and validates the official Wintun `0.14.1` driver against its known SHA-256 hash.
5. Produces `OutlineProxy-x86_64.zip` and `SHA256SUMS.txt` in `dist/windows/`.
