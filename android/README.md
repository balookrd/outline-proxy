<picture>
    <source media="(prefers-color-scheme: dark)" srcset="../docs/logo-dark.png">
    <img src="../docs/logo-light.png" alt="outline-proxy logo" width="100%">
</picture>

# Outline Proxy — Android client

Russian version: [README.ru.md](README.ru.md).

Android VPN client built on the `outline-ws-rust` uplink stack (padding, VLESS,
SS, WS, TLS, failover). The Rust core is reused unchanged; Android adds a
Material Design 3 UI (Jetpack Compose) and the `VpnService` layer.

> Status: increments 1–6 are done (see "Development history"): Rust⇄Kotlin
> bridge, the native `outline-tun` engine attached to the `VpnService` fd,
> QUIC/HTTP-3 carriers, a persisted server list, Wi-Fi⇄cellular handover,
> per-app split tunneling, `outline://` external control, config-over-URL
> subscriptions, Material You dynamic colour on Android 12+, themed monochrome
> launcher icon on Android 13+, signed release builds, keeping the tunnel alive
> across kills / reboot / OEM cleanup, a profile-named foreground notification
> and system-back navigation. The Rust stack (including quinn + h3)
> cross-compiles under NDK r29; the Gradle build produces a debug APK and a
> minified release APK, and the JVM unit tests pass. What has and has not been
> run is listed in "Verification status".
> [verify: the verification status is older than the code — `DialTimeout.kt`
> describes a HONOR device carrying LTE traffic through the tunnel]

## Layout

```
android/
  build-rust.sh    # builds the .so and the UniFFI Kotlin bindings
  rust/            # outline-android: cdylib + UniFFI wrapper around ws-rust
    src/lib.rs       # start() / stop() / is_running()
    src/bin/         # uniffi-bindgen
  app/             # Android app (Gradle, Kotlin, Compose)
    src/main/java/com/outline/proxy/
      OutlineVpnService.kt   # VpnService: establish() TUN, drive the core
      MainActivity.kt / HomeScreen.kt          # screens, connect/disconnect
      ServerProfile.kt / ProfileStore.kt       # profile model + persistence
      SplitTunnel.kt         # per-app allow/deny modes
      ConfigFetcher.kt / SubscriptionWorker.kt / SubscriptionRefresh.kt  # config-over-URL
      ExternalControl.kt / ControlActivity.kt  # outline:// grammar + entry point
      DialTimeout.kt         # carrier-dial budget per link
      TcpOnlyConfig.kt       # "TCP only" config rewrite
      LinkProbe.kt / LinkInfo.kt / LinkQuality.kt  # link readout on the home screen
      KeepAlivePolicy.kt / KeepAliveState.kt / KeepAliveScreen.kt
      AutomationPolicy.kt / AutomationStore.kt / AutomationState.kt / WifiAutomationScreen.kt
      OutlineTileService.kt / QuickConnectActivity.kt  # quick-settings tile, shortcut
      UpdateChecker.kt / ReleaseNotes.kt       # in-app update check
      keepalive/             # BootReceiver, WatchdogAlarm/Worker/Receiver, vendor profiles
    src/test/java/com/outline/proxy/           # JVM unit tests
```

## Architecture

```
VpnService.establish() ──tun_fd──┐
                                 ▼
   outline-tun ── native engine, attached to the fd directly ─┐
                                                              ▼
   outline-ws-rust uplinks: padding/VLESS/SS/WS/TLS (SOCKS5 ingress compiled out)
                                                              │
   uplink sockets ── bypass the TUN (own package is ──────────┘
                     addDisallowedApplication'd) → real network
```

The Rust core attaches the native `outline-tun` engine directly to the
`VpnService` TUN fd via `RunOptions.tun_fd` and passes TCP/UDP flows straight
into the uplink stack, with no tun2proxy bridge and no SOCKS5 loopback hop in
between. Loop avoidance: the Kotlin side excludes this app's own package from
the VPN (`addDisallowedApplication(self)`), so every socket the uplinks open
bypasses the TUN without a per-socket `VpnService.protect()`.

The uplink sockets use whatever network the tunnel is bound to with
`setUnderlyingNetworks`. `OutlineVpnService` watches the best non-VPN network
with `INTERNET` and re-binds on Wi-Fi ⇄ cellular handovers:

- API 31+: `registerBestMatchingNetworkCallback`, which delivers the single best
  match.
- Below API 31: the app picks from all matching networks itself — validated
  first, then Ethernet > Wi-Fi > cellular (`LinkProbe.bestNonVpn`).

Two filters matter here. `NET_CAPABILITY_NOT_VPN`: a default-network callback
reports our own VPN network back to us, and the tunnel would become its own
underlying network. And tracking which network is actually in use: a network
coming up next to a better one does not take over the binding, and the loss of
a network we are not using is ignored. Watching networks needs
`ACCESS_NETWORK_STATE`; without it the callback throws and only handover
tracking is lost, not the tunnel.

The Rust core is built with `default-features = false` plus `h3` and `tun`
(`android/rust/Cargo.toml`): the native TUN engine, the WS/TLS uplink stack and
the QUIC/HTTP-3 carriers. Left out are the `socks5` ingress, `metrics`,
`control`, `env-filter`, `multi-thread` and the `jemalloc` allocator. On top of
the compiled-out `socks5` feature, `outline-ws-rust` also skips the SOCKS5
listener at runtime when a `tun_fd` is passed, regardless of the TOML.

## Requirements

Rust side:

```sh
rustup target add aarch64-linux-android      # + armv7/x86_64 for more ABIs
cargo install cargo-ndk
brew install --cask android-ndk              # NDK r29 -> /opt/homebrew/share/android-ndk
export ANDROID_NDK_HOME=/opt/homebrew/share/android-ndk
```

App side:

- JDK 17. Gradle fails under openjdk 25, and recent Android Studio releases
  bundle JBR 25 (`/Applications/Android Studio.app/Contents/jbr/Contents/Home`),
  so do not point `JAVA_HOME` at the bundled JBR. CI uses Temurin 17
  (`.github/workflows/_android-release-build.yml`); the build itself targets
  Java 17 (`compileOptions` in `app/build.gradle.kts`).
- Android SDK with platform 37 (`compileSdk = 37`). Android Studio installs it;
  for a CLI-only build set `sdk.dir` in `local.properties`.
- Gradle itself is not needed: the wrapper is checked in (`gradlew`,
  `gradle/wrapper/`, Gradle 9.7.0).

## Building the Rust artifacts

`build-rust.sh` regenerates both the native library
(`app/src/main/jniLibs/<abi>/liboutline_android.so`) and the UniFFI Kotlin
bindings (`app/src/main/java/uniffi/`):

```sh
export ANDROID_NDK_HOME=/opt/homebrew/share/android-ndk
./build-rust.sh                      # arm64-v8a, debug
./build-rust.sh arm64-v8a --release
```

Both outputs are gitignored. Rerun the script after any change under
`android/rust/` or in the monorepo crates it pulls in.

Notes:

- The app ships only `arm64-v8a` (`abiFilters` in `app/build.gradle.kts`).
- `h3` pulls quinn and the patched forks in `vendor/`. `android/rust` is a
  detached workspace, so its `Cargo.toml` repeats the root's
  `[patch.crates-io]` entries for `h3`, `hyper`, `quinn-proto` and `rustls`;
  without the `h3` patch the vendored `sockudo-ws` HTTP/3 carrier fails to
  compile against upstream `h3`.
- Bindings are generated from the host library (`.dylib` on macOS, `.so` on
  Linux): a cross-compiled Android `.so` cannot be loaded on the build host. The
  script builds the host library for this.
- cargo-ndk 4.x: the API level is `--platform N` (the script passes 24), not
  `-p N`, which is cargo's `--package`; cargo arguments go after `--`.
- uniffi 0.31+ detects a library source on its own, so the bindgen takes the
  library path as a positional argument; the old `--library <path>` flag is a
  no-op.

## Building and running the app

1. Run `./build-rust.sh` (once, and after Rust changes).
2. Open `android/` in Android Studio. On first sync it writes
   `local.properties` (SDK path) and downloads Gradle 9.7.0. Set
   **Settings → Build, Execution, Deployment → Build Tools → Gradle → Gradle
   JDK** to a JDK 17.
3. Run on a device or emulator, add a server, press **Connect**.

From the command line (JDK 17, Android SDK, `local.properties` with `sdk.dir`):

```sh
cd android
export JAVA_HOME=<jdk17_home>   # a JDK 17 installation, not Android Studio's JBR 25
./gradlew :app:assembleDebug        # debug APK
./gradlew :app:testDebugUnitTest    # JVM unit tests
./gradlew :app:lintDebug            # EN/RU string parity (MissingTranslation, ExtraTranslation)
```

The debug build has the application ID `com.outline.proxy.debug`, so it installs
next to a release build instead of replacing it.

### Release signing

`:app:assembleRelease` signs the APK when release credentials are available,
and produces an unsigned APK when they are not, so a fresh clone builds either
way. Credentials come from `android/keystore.properties` first, and from the
environment (`OUTLINE_KEYSTORE_FILE`, `OUTLINE_KEYSTORE_PASSWORD`,
`OUTLINE_KEY_ALIAS`, `OUTLINE_KEY_PASSWORD`) when that file is absent. A
partial set fails the build (`Incomplete release-signing config; missing: …`):
an unsigned APK cannot be installed over a signed one, and finding that out at
`adb install` time is worse than failing the build.

The properties file and any `*.jks`/`*.keystore`/`*.p12` in the tree are
gitignored; keep the keystore outside the work tree
(`~/.android/outline-proxy-release.jks`). To create one:

```sh
keytool -genkeypair -v -keystore ~/.android/outline-proxy-release.jks \
  -storetype PKCS12 -alias outline-proxy -keyalg RSA -keysize 4096 \
  -validity 10950 -dname "CN=Outline Proxy, O=Outline Proxy, C=RU"
```

Then point `keystore.properties` at it (`storeFile`, `storePassword`,
`keyAlias`, `keyPassword`). Only the v2/v3 signature schemes are enabled:
`minSdk` is 24, the release that introduced v2, so the legacy v1 JAR signature
adds nothing.

**Warning:** back up the keystore and its password. Without them the app can
only be reinstalled from scratch (losing its data), never upgraded in place.

Verify the signed APK:

```sh
$ANDROID_HOME/build-tools/<ver>/apksigner verify --print-certs -v \
  app/build/outputs/apk/release/app-release.apk
```

`<ver>` is an installed build-tools version.

### Gradle toolchain

AGP 9.4.0, Gradle 9.7.0, Compose compiler plugin 2.4.10 on AGP 9 defaults:
`gradle.properties` sets only `android.useAndroidX` and
`android.nonTransitiveRClass`, no compatibility flags. The two
`Expression is unused` warnings in the build output come from the generated
UniFFI bindings.

- AGP compiles Kotlin itself (built-in Kotlin). There is no
  `org.jetbrains.kotlin.android` plugin; only the Compose compiler plugin is
  applied, and AGP finds it by plugin id and wires it into its own compile
  tasks. That plugin was also the only caller of the legacy variant API
  (`testVariants`/`unitTestVariants`), removed in AGP 10.
- The JVM target is set once. Built-in Kotlin takes `jvmTarget` from
  `compileOptions.targetCompatibility` and fails the build if the two diverge,
  so `compileOptions` alone pins both compilers to 17. A `kotlin { }` block is
  redundant, and a conflicting one is a build error.
- R8 minification is on and depends on keep rules. JNA and the UniFFI bindings
  are wired by reflection and by symbol name (`Native.register`), so R8 cannot
  see their use; `proguard-rules.pro` pins those names and silences JNA's
  desktop AWT paths (`-dontwarn java.awt.**`), which android.jar has no classes
  for. Check a rule change by running the release build, not by building it:
  a wrong rule breaks at runtime, never at build time.

## Where the config comes from

The node generates a client config per user: `<user>.toml`, next to `.conf`
and `.json` (`ops/access-keys/generate_keys.py`; the report calls its link
`ws_url`). It carries the full carrier chain for every entry node, failover
between nodes and live-flow migration. The structured profile form cannot
express that: a single `vless://` / `ss://` link describes one carrier of one
node. Paste the file whole into the **Raw TOML override** field.

The generated `[tun] mtu` must match `ServerProfile.TUN_MTU`: 1500 on both sides
(`TUN_MTU` in `ops/access-keys/ws_toml.py`). Change one and you must change the
other, or the VPN comes up with an MTU the proxy core does not know about.

What lands in the config depends on the node: the h3 carrier mode, the set of
paths, padding, carrier migration and soft node switching are turned on only
when the node has the matching sections. The generator reports the ones that
are off as `warning:` lines; see
[`ops/access-keys/README.md`](../ops/access-keys/README.md).

The generated profile also carries `[outline.probe]`: a DNS probe plus TLS
handshakes through the tunnel, mirroring the fleet's `main` group. Without it
the client has no health signal independent of traffic: an uplink marked down
is cleared only by data flowing over it, so losing every uplink at once (a SIM
switch, a dead cell) read as "no link" until the tunnel was reconnected by hand.
The probe interval is 300 s (`PROBE_INTERVAL_SECS` in
`ops/access-keys/ws_toml.py`) instead of the fleet's 10 s: on a phone each probe
cycle costs battery and, on an edge-class cell, bandwidth the tunnel needs.

### Subscription URL

Instead of pasting the config, a profile can point at an HTTPS URL that serves
one (**Config URL (subscription)** field in the editor) — the same
`<user>.toml` the node generates. With a URL set, the transport fields are
hidden: the URL is the only source of the config.

- The body must be a whole client config, not an xray-style list of servers;
  one URL is one profile with all its uplinks inside.
- HTTPS only: the config carries UUIDs and passwords. The URL path is a secret
  token, so it is never logged in full, only masked (`host/…tail`).
- The fetched config is cached in the profile. `SubscriptionWorker`
  (WorkManager, every 12 h) refreshes it; a failed fetch keeps the last good
  cache and does not touch a running tunnel. The server list shows
  "updated N h ago" and a refresh button for an immediate fetch.
- A response replaces the cache only if it contains `[tun]` or
  `[[outline.uplinks]]`, so an HTML error page or a captcha cannot replace a
  working config.
- The fetch goes out directly, since the app is excluded from its own VPN. If
  the source is reachable only through the tunnel, background refresh fails
  and the cached config stays in use.

### Dial budget on slow links

The generated config has no `[dial]` section, so the core bounds every fresh
carrier dial at its default of 10 s (`DEFAULT_DIAL_TIMEOUT` in
`crates/outline-transport/src/dial_timeouts.rs`). On an edge-class cell that
budget is the cause of failure: a 2G round trip is close to a second and the
certificate chain alone takes seconds, so the budget expires mid-handshake,
every attempt is scored a failure, and the retries eat the bandwidth the
handshake needed. The tunnel reports itself up while carrying nothing.

The app therefore sets the budget itself (`DialTimeout.secondsFor`):

| Input | Condition | Budget |
|---|---|---|
| Path RTT measured by the core (any transport) | ≥ 3000 ms | 60 s |
| | ≥ 1000 ms | 30 s |
| | below 1000 ms | core default (10 s) |
| No RTT yet; platform bandwidth estimate (cellular only) | ≤ 200 kbit/s | 60 s |
| | ≤ 2000 kbit/s | 30 s |
| | faster | core default |

- A measured RTT always wins over the estimate: some firmware invents the
  estimate (one HONOR device reported 14 kbit/s on a full-signal LTE cell that
  carried traffic normally). The estimate covers the cold start, before a
  carrier exists to measure.
- Wi-Fi and Ethernet are never widened on the estimate: a slow Wi-Fi usually
  means a slow backhaul, where the handshake still completes in a couple of
  round trips, and a wider bound would only delay failover. A measured RTT
  widens any transport.
- An estimate of 0 or none (the link is not characterised yet) is ignored, not
  treated as 2G.
- A config that declares `[dial]` itself is never touched.

The budget follows the link. The service recomputes it in its network callbacks
(`onAvailable`, `onCapabilitiesChanged`, `onLost`); `onCapabilitiesChanged` is
how a cell handover, a generation change (2G ↔ 3G ↔ LTE ↔ 5G) and, on many
devices, a data-SIM switch arrive, because the `Network` object stays the same
while its properties change. Moving from Wi-Fi to a 2G cell widens the bound,
moving back restores the default. The engine picks the new value up on its next
dial (`setDialTimeoutSecs`); handshakes already in flight keep their deadline.
Nothing is torn down, and an unchanged value is not re-applied.

### TCP only mode (no HTTP/3)

On networks where UDP 443 or QUIC is blocked or throttled, uplinks configured
with `xhttp_h3` or `ws_h3` wait for the H3 handshake to time out before falling
back to H2, and later attempts to return to H3 stall again.

The **TCP only** switch on the **Keeping Alive** screen (for all profiles) and
in the server editor (per profile) rewrites the config before start
(`TcpOnlyConfig`): `xhttp_h3` → `xhttp_h2`, `ws_h3` → `ws_h2` in
`vless_mode`/`ss_mode`/`tcp_mode`/`udp_mode`, and `h3` → `h2` in `alpn=` of
share links. It applies to structured profiles, share links, subscriptions and
raw TOML overrides. UDP inside the tunnel (DNS, VoIP) is carried over the
HTTP/2 connection. A change takes effect on the next connect.

### What the home screen says about the link

Under the tunnel status the card shows the network the tunnel is using:
`Wi-Fi · 20 ms` or `LTE · 4.2 s`. Either part is omitted when unknown:

- The link type. Wi-Fi and Ethernet name themselves. A cellular link shows its
  radio technology (2G / 3G / LTE / 5G) when the app may read it
  (`dataNetworkType`), and `Cellular` otherwise. This is the radio carrying
  data, which often disagrees with the status-bar icon: that icon commonly
  tracks 5G coverage or a 5G-capable NSA anchor, so "5G" in the status bar and
  `LTE` here is expected.
- The path round-trip measured continuously on the live carrier (the kernel's
  `tcpi_rtt`, quinn's `PathStats`), not the elapsed time of a dial. A dial time
  includes the handshakes and, after an `h3 → h2` descent, the failed attempt,
  so it showed values such as "10.0 s" on a 10 s budget for healthy links. At
  700 ms and above the status reads as slow (`LinkQuality.SLOW_LATENCY_MS`).

The platform's bandwidth estimate is not shown: firmware invents it (see the
HONOR example above). It is still read to size the dial budget before anything
is measured.

Naming the radio technology needs `READ_PHONE_STATE`. The app does not request
it on its own: it is an optional item on the **Keeping Alive** checklist,
because no tunnel decision depends on it. Denying it removes the label and
nothing else.

## External control (`outline://`)

Automation apps (Tasker, launcher shortcuts, `adb`) can drive the tunnel over a
URI scheme:

```
outline://connect                     # bring up the profile selected in the UI
outline://connect?profile=<name|id>   # bring up a specific saved profile
outline://disconnect
outline://toggle[?profile=<name|id>]  # down if up, otherwise connect
```

Scheme, command and query keys are case-insensitive; values are
percent-decoded (`?profile=Home%20VPN`). A command never creates a server: the
profile must already exist, matched by id first, then by name (case-insensitive).
On success nothing is shown; the foreground-service notification shows the
state. A refusal shows a Toast and logs a warning with tag `OutlineControl`.

```sh
adb shell am start -a android.intent.action.VIEW -d 'outline://connect'
adb shell am start -a android.intent.action.VIEW -d 'outline://toggle?profile=Home&token=s3cret'
```

Access is controlled on the **External Control** screen: a switch (on by
default) and an optional token. Once a token is set, commands without a
matching `?token=` are ignored; the comparison is constant-time
(`MessageDigest.isEqual`). Any installed app, and any web page (the intent
filter carries `BROWSABLE`), can fire these URIs, so set a token if an
unexpected `disconnect` matters to you.

`ControlActivity` is a transparent activity that dispatches the command and
finishes. It cannot be a receiver or an exported service: the system VPN
consent dialog needs an activity to launch from, and Android 12+ forbids
starting a foreground service from the background. Callers must be allowed to
start activities: for a background app without that permission (e.g. Tasker
without "Display over other apps") the platform drops the URI silently.

## Keeping the tunnel alive

Every path that may have to bring the tunnel back — always-on VPN, boot, the
watchdog alarm, the WorkManager job, `onDestroy` — goes through
`OutlineVpnService.ensure()`. It reads the user's intent
(`KeepAliveState.shouldRun`, set on connect, cleared on an explicit disconnect)
and the core state (`isRunning()`), and `KeepAlivePolicy.decide(...)`, a pure
unit-tested function, returns one of: do nothing, stop, give up (and notify),
or connect. A failing connect is retried every 5 min for the first three
failures, every 15 min for the fourth and fifth, then every 30 min
(`KeepAlivePolicy.backoffFor`). While the tunnel is healthy, the exact alarm is cancelled so it does not
wake the device from Doze.

The tunnel comes back in four ways:

- Always-on VPN: the system starts and restarts the service itself, which is
  why `onStartCommand(null)` maps to `ensure()`. The user enables it in system
  settings.
- Boot / app update: `BootReceiver` (`BOOT_COMPLETED`, `MY_PACKAGE_REPLACED`),
  after unlock. Not direct-boot aware on purpose: profiles hold credentials and
  stay in credential-protected storage.
- Watchdog pair: an exact alarm (`WatchdogAlarm`; fires through Doze during
  reconnection backoff, cancelled while the tunnel is healthy) and a 15-minute
  WorkManager job (`WatchdogWorker`; its schedule survives reboot); each calls
  `ensure()`. The alarm is exact only once `SCHEDULE_EXACT_ALARM` is granted;
  otherwise the system batches it. `USE_EXACT_ALARM`, which would grant that
  without asking, is left out on purpose; the reason is in a comment in
  `AndroidManifest.xml`.
- Swipe / kill: `stopWithTask="false"` plus `onTaskRemoved`/`onDestroy`
  schedule a check right after the process goes away.

The **Keeping Alive** screen is a checklist of what only the user can grant:
always-on VPN, battery-optimisation exemption, exact alarms, notifications, and
the vendor autostart screen (probed per device with `resolveActivity`; on HONOR
it opens `com.hihonor.systemmanager`). Each row shows its status and a button to
the system screen. These grants also make starting a foreground service from
the background legal on Android 12+.

`specialUse` is not on Android 15's list of foreground-service types barred
from `BOOT_COMPLETED`, so the boot path is open. Test the restriction without
changing `targetSdk`:

```sh
adb shell am compat enable FGS_BOOT_COMPLETED_RESTRICTIONS com.outline.proxy
adb shell am broadcast -a android.intent.action.BOOT_COMPLETED com.outline.proxy
```

Verified: unit tests for the decision table; on a device, the checklist screen
and its system-screen intents (HONOR / MagicOS). The background revival paths
(force-stop → return, reboot) are implemented but not yet run end-to-end on
hardware. The vendor table for MIUI/EMUI/ColorOS/One UI is not verified.

## Development history

- Increment 1: Rust⇄Kotlin bridge, SOCKS5 + uplinks boot, `VpnService` +
  Compose scaffold.
- Increment 2: a tun2proxy bridge (TUN fd → SOCKS5) with loop avoidance via
  `addDisallowedApplication(self)`. Later replaced by the native `outline-tun`
  engine attached to the `VpnService` fd via `RunOptions.tun_fd` (see
  "Architecture"); SOCKS5 ingress is compiled out for Android (`socks5` feature
  off, plus the runtime check on `tun_fd`).
- Increment 3: QUIC/h3 (`h3` feature), logcat logging (`paranoid-android`),
  persisted server list, re-binding on network change (`setUnderlyingNetworks`).
- Increment 4: per-app split tunneling (`addAllowedApplication` /
  `addDisallowedApplication`) with an app picker. Modes OFF / ALLOWLIST /
  DENYLIST; the allow and deny lists are stored separately in
  SharedPreferences, and only the list of the active mode is applied (Android
  does not allow mixing them on one `VpnService.Builder`).
- Increment 5: external control over `outline://` (connect / disconnect /
  toggle, optional profile selector) behind a switch and an optional token;
  the parser and the access check have JVM unit tests.
- Increment 6: config-over-URL subscriptions (`ConfigFetcher` /
  `SubscriptionWorker`), keep-alive (`KeepAlivePolicy` + the `keepalive/`
  watchdog pair), system light/dark theme, launcher icon, signed release
  builds, a single connect/disconnect button, a profile-named foreground
  notification.

## Verification status

[verify: this list is older than the code — `DialTimeout.kt` describes a HONOR
device carrying LTE traffic through the tunnel]

- Build: the Rust core (`outline-android` cdylib) cross-compiles to a loadable
  `aarch64` Android `.so`, including the native TUN engine, the uplink stack and
  the QUIC/h3 carriers; SOCKS5 ingress and tun2proxy are not in it.
- Build (Kotlin): `:app:assembleDebug` produces a debug APK and
  `:app:testDebugUnitTest` passes.
- Emulator (Pixel_10, API 37, arm64), debug build, under the old tun2proxy
  bridge: the service established the TUN, the Rust core started (SOCKS5 on
  127.0.0.1:1080, uplink registry up), tun2proxy connected to it,
  `outline://connect` / `disconnect` worked, and underlying-network tracking
  followed a Wi-Fi ⇄ cellular handover both ways: in `dumpsys connectivity` the
  VPN agent's `underlying{[N]}` switched between the cellular and Wi-Fi
  networks and never pointed at the VPN network itself.
- Emulator, release build: with R8 minification on, the `.so` loads and
  `start()` reaches Rust, so the keep rules hold. Checked by running the signed
  release APK.
- Not verified: on real hardware only the keep-alive checklist screen and its
  vendor intents have been run (HONOR / MagicOS); no traffic has gone
  end-to-end through a live server (the emulator ran against a dead endpoint).
  Per-app split tunneling has not been run on a device. The native TUN engine
  has not been run on an emulator or a device.

## Notes for porting

The Rust core needs a few `cfg(android)` adaptations as features are added:

- `outline-net` `SO_MARK` is privileged on Android; use `VpnService.protect()`.
- The `freebind` / `/proc/net/if_inet6` IPv6-source logic does not apply; gate
  it off.
- `outline-tun` has two device paths: `/dev/net/tun` + `TUNSETIFF` (needs
  root) on desktop, and attaching to an already-open fd (`RunOptions.tun_fd`),
  the one `VpnService` hands over, without root.
