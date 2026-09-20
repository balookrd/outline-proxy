# Changelog — Android app

The Android VPN client ([`android/`](.)) wraps the `outline-ws-rust` uplink
stack in a `VpnService`, driving the native `outline-tun` engine directly over
the tunnel fd. Releases are cut as `android-v*` tags; CI also publishes a
rolling `android-nightly` prerelease off `main`. This log records user-visible
changes, not every commit.

The format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- **Brand identity redesign: new logo and app icon.** Replaced the legacy wireframe shield with a sleek tunnel portal emblem featuring luminous data paths and glowing spheres. Refreshed the home screen header banner (`brand_logo`) with clean vector typography free of background seams, the connection status ring emblem (`brand_ring`) across dark and light themes, launcher icon sets with full-bleed gradient coverage and authentic safe-zone margins (`ic_launcher`, adaptive `ic_launcher_foreground` calibrated to 66–72dp safe zone without edge-clipping or black borders, natively adapting to Honor MagicOS squircles and Pixel circles), and the vector quick settings tile / status-bar emblem (`ic_stat_tunnel`).
- **Airplane Mode pause and auto-resume to save battery.** The Keeping Alive screen gains a toggle to automatically pause the VPN when Airplane Mode is turned on. When Airplane Mode is turned off and network connectivity returns, the VPN tunnel restores automatically if it was running before.
- **Trusted Wi-Fi network automation.** A new "Network Rules" screen (accessible from the quick links on the Home screen) lets users automate VPN connections based on the active Wi-Fi network:
  - **Pause VPN on selected networks**: automatically suspends VPN on trusted home or office Wi-Fi networks and reconnects when leaving for cellular data or unknown networks.
  - **Connect VPN on selected networks**: connects only when joining designated networks and disconnects elsewhere.
  - Seamless one-tap addition of the current network (with location permission prompt required by Android to read SSIDs) and manual SSID entry.
  - Reliable SSID detection on Android 12+ using `FLAG_INCLUDE_LOCATION_INFO`, fallback to `WifiManager.connectionInfo`, detection of disabled system location services, and service standby mode.
- **Split tunneling support for Gemini and launcher apps.** Apps without direct `INTERNET` permissions (such as Google Gemini, `com.google.android.apps.bard`) are now listed in the app picker. Selecting Gemini automatically selects the primary Google app (`com.google.android.googlequicksearchbox`) through which its network traffic is actually routed, accompanied by an explanatory banner and inline item hints.
- **Complete, high-contrast dotted world map on the home screen.** Redesigned the background dotted matrix world map in the connection status card: it now renders the entire globe and all landmasses (including North and South America, Eurasia, Africa, Australia, and New Zealand), spans across the full card width, and adapts its brightness based on the active theme (35% in dark mode, 22% in light mode).
- **A persistent notification you can keep even while the VPN is off.** A "Persistent notification" switch on the Keeping Alive screen keeps the ongoing banner in the status bar around the clock, not only while connected: disconnecting drops the service into a standby state that keeps the banner (with the tunnel torn down) instead of removing it, and opening the app raises it when idle. The banner carries a single status-aware action — **Disconnect** while the tunnel is up, **Connect** while it is down — so the tunnel toggles straight from the shade; Connect opens an invisible activity only long enough to obtain VPN consent the first time. Its second line names the traffic moved while connected and the server transport in standby, dropping the app-name filler. Opt-in and off by default, so the standard behaviour — a banner only while connected — is unchanged.
- **A Quick Settings tile that toggles the tunnel.** An "Outline" tile mirrors the notification's toggle — highlighted while connected, dim while off, the selected server as its subtitle — so the VPN flips from the Quick Settings panel without opening the app. The Keeping Alive screen offers an "Add tile" button that asks the system to place it in one tap on Android 13+ (and points at the Quick Settings editor below that).
- **Localization: the UI now follows the phone's language — Russian on a Russian device, English otherwise.** The system locale picks the string set automatically; there is no in-app language switch.
- **The Split Tunneling screen's app-search field has a clear (✕) button.** It appears once you start typing and clears the filter in one tap.
- **The Keeping Alive screen now covers the phone vendor's own restrictions, not just Android's.** Skins that keep a separate autostart list or per-app battery policy (Xiaomi, Huawei, Honor, Oppo, realme, vivo, OnePlus, Samsung, Asus, Meizu, Tecno/Infinix/itel) get their own cards naming the exact setting to change: "Autostart" on Xiaomi, the never-sleeping list on Samsung, the three-step "App launch" sequence on Huawei and Honor. Android's battery-optimisation exemption lifts none of these restrictions: a phone can report that permission as granted and still stop the tunnel, and MIUI — going by the AdGuard and Briar bug trackers — resets the Android grant on its own.
- **The Split Tunneling picker shows app icons.** They load as rows scroll into view, so the screen opens no slower than before.
- **The update dialog now shows what changed.** When a newer build is found, the dialog lists the release's changes — features, fixes and any breaking changes — above the download note, taken from the published release's notes and shown as a scrollable "What's new" section. A release without notes (or a build channel that publishes none) shows the dialog exactly as before.

### Changed

- **A server saved with a blank name now takes its name from the link's `#remark`, or its hostname if there is no remark.** Applies whichever link is in play — the subscription config URL, a `vless://` link, or an `ss://` link.
- **The keep-alive checklist is worded for people, not for the APIs behind it.** "Exact alarms" is now "Background wake-ups" and says what the app actually does with the permission — wake every few minutes, check the tunnel, bring it back — naming the system screen ("Alarms & reminders") so the button lands somewhere recognisable. References to the watchdog and to Doze are gone from the user-facing text.
- **Samsung's card opens the never-auto-sleeping list directly.** It uses the deeplink Samsung documents for it, so the button lands on the list itself instead of the Battery screen two taps above; all that is left is "+" to add the app. The manual path is still spelled out for builds without the deeplink. The earlier wording quoted a list name ("Never sleeping apps") that One UI renamed in 6.1, which is why it sent people hunting for a menu entry their phone does not have.

### Fixed

- **Xiaomi no longer shows a battery-optimisation card that turns red the moment you connect.** MIUI/HyperOS pulls Android's battery-optimisation exemption the instant the VPN foreground service starts, so the "Ignore battery optimisation" card flipped from green to red on every connect with nothing the user could do about it — the flip that started this whole thread. On Xiaomi that card is now hidden; the vendor battery card («No restrictions») and autostart are the controls that actually hold the tunnel there. Other skins, where the exemption is stable, keep the card.
- **The Keeping Alive checklist no longer shows stale statuses.** Grants are re-read every time the screen comes back into view rather than when a button is tapped, so a permission changed in a system or vendor screen — or straight from the notification shade — is reflected on return. Previously the check ran before the user had answered the system dialog, leaving the card showing the old answer.
- **Samsung devices no longer get an "Autostart" card: One UI has no autostart list.** The screens it pointed at are One UI's battery policy, and they now open from the battery card instead.
- **"Connected · slow" now reflects the path's round-trip, not what a dial cost.** The latency behind the status line was the time a dial took — DNS, the TLS and HTTP handshakes, and, when a carrier descended `h3 → h2`, the whole budget the failed attempt burned before the fallback succeeded. That is how a healthy link showed "7.1 s" over an `xhttp/h2` carrier that had done nothing wrong: 7 s of H3 stream budget plus a fast H2 handshake. Worse, the app sizes its own dial budget from this number, so a burnt timeout widened the budget, which widened the next attempt's timeout, which reported more seconds — a loop. The status now reads the path's own round-trip as the carrier's transport measures it (the kernel's `tcpi_rtt`, QUIC's `PathStats`), sampled continuously on the live carrier — including while it merely sits in the warm pool, where no dial happens. Two older faults go with it: the number is read off the wire actually carrying traffic (a descended uplink no longer pairs one wire's carrier label with another wire's cost), and a reading nothing has refreshed expires instead of labelling the tunnel slow forever. Where no path RTT can be had — an `xhttp/h1` carrier, a VLESS-UDP mux — the line shows nothing rather than a wrong number. The bar for the label was recalibrated to the new number too: "slow" now shows at 0.7 s of path round-trip, where it read 1 s against the old dial-cost figure and barely fired for the right reason (a healthy dial already cost most of a second). It is kept below the separate, higher bar that widens the dial budget, so a link that merely feels sluggish is not also handed a slow failover window.

## [1.2.0] - 2026-08-24

### Added

- **Update check on the build label, with the download it offers.** Tapping the version footer asks GitHub what the build's own channel publishes — a release compares versions across `android-v*` tags, a nightly compares the commit baked into the rolling tag's asset name — and the footer reports the whole run in place (`checking… → downloading 42% → downloaded — tap to install`). The APK is fetched in-process into Downloads through MediaStore, so no storage permission is needed, and the app never installs it: `REQUEST_INSTALL_PACKAGES` is the permission Play Protect weighs heaviest next to a VPN service, so the final tap opens the system Downloads instead, which is a permitted install source.
- **Live status and traffic in the ongoing notification.** The banner refreshes every 2s: its title carries the same state the home screen shows (Connecting… / Connected / No link · profile) and its text the bytes moved this session.
- **An expired subscription is refreshed before connecting.** The periodic worker only keeps configs fresh "eventually" — WorkManager defers under doze — so a connect could dial servers from a stale config. The connect path now refetches a subscription past its refresh interval (capped at 4s) and falls back to the cached config on any failure.
- **The home screen names the link the tunnel is riding.** "Connected · slow" said something was wrong without saying what; the status card now carries a line underneath it — `Wi-Fi · 20 ms`, or `LTE · 4.2 s` — pairing the radio technology (2G / 3G / LTE / 5G, named only when `READ_PHONE_STATE` is granted, which is offered on the Keeping Alive checklist and never requested on its own) with the round-trip the core measured on a real dial. Nothing derived is shown: the platform's bandwidth estimate is a number firmware invents — one device reported 14 kbit/s on a full-signal LTE cell carrying traffic fine — so it sizes the dial budget but never reaches the screen, and a round-trip that reaches the dial budget is dropped too, because that is a timeout rather than a measurement.
- **Build-version footer**, labelled by what actually identifies the build: a tagged release shows its version and code (`v1.1.2 (57)`), while nightly and local builds show the channel and the commit they came from (`nightly · cdcaf46f`, `dev · 4f71e7ef`) — their version is a fixed placeholder that never moves. CI stamps `BuildConfig` via `BUILD_CHANNEL` / `BUILD_VERSION_NAME` / `BUILD_VERSION_CODE` / `BUILD_GIT_SHA`.

### Changed

- **"Connected" now qualifies a live-but-useless link as "Connected · slow", and the dial budget follows the link.** "Connected" could not separate a fibre path from a 2G one, where the tunnel is honestly up and equally honestly useless — a handshake alone eats seconds and apps time out before they reach the server, while the UI sits on a flat green the user can see is wrong. The home screen and the ongoing notification now read "Connected · slow" once the worse of the two transports' measured latency crosses a second; an unmeasured link stays plain "Connected", because absence of a measurement is not evidence of a bad path. The carrier-dial budget is sized for the link too: a slow cell gets a wider budget so a handshake that runs close to a second can complete instead of expiring mid-way and scoring every attempt a failure, and because a walk from Wi-Fi into a 2G cell (or a data-SIM switch, which many devices deliver as a capability change on the same `Network`) would otherwise leave the fast-link budget frozen, the service re-derives it on every network change and re-checks it on its 2-second tick.
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
