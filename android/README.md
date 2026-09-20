<picture>
    <source media="(prefers-color-scheme: dark)" srcset="../docs/logo-dark.png">
    <img src="../docs/logo-light.png" alt="outline-proxy logo" width="100%">
</picture>

# Outline Proxy — Android client

Android VPN client that connects to your servers using the full `outline-ws-rust`
uplink stack (padding + VLESS / SS / WS / TLS, failover). The Rust core is reused
unchanged; Android adds a modern Material Design 3 (Material You) UI + `VpnService` layer.

> Status: **feature-complete client, not yet run against a live server**.
> Increments 1–5 are done — Rust⇄Kotlin bridge, a native `outline-tun` engine
> attached to the `VpnService` fd, QUIC/HTTP-3 carriers, a persisted server-list
> UI, Wi-Fi⇄cellular handover, per-app split tunneling, and `outline://`
> external control — plus a run of later work: config-over-URL subscriptions,
> full Material Design 3 (Material You dynamic theming on Android 12+, themed monochrome launcher icons on Android 13+),
> new brand identity (shield & speed stream tunnel), signed release builds, a unified
> connect/disconnect action with connecting indicators, keep-the-tunnel-alive across kills / reboot / OEM
> cleanup, a profile-named foreground notification, and system-back navigation.
> The whole Rust stack (incl. quinn + h3) cross-compiles under NDK r29, and the
> Gradle/Kotlin app builds (debug APK, minified release APK, green JVM unit
> tests). It has run on an **emulator** (under the earlier tun2proxy bridge,
> since replaced by the native engine); on **real hardware** only the keep-alive
> checklist screen and its vendor intents have been exercised. No traffic has
> crossed a live server yet, and the native TUN engine has not been booted at
> runtime — see "What is verified vs. not".

## Layout

```
android/
  rust/            # outline-android: cdylib + UniFFI wrapper around ws-rust
    src/lib.rs       # start() / stop() / is_running()
  app/             # Android app (Gradle, Kotlin, Compose)
    src/main/java/com/outline/proxy/
      OutlineVpnService.kt   # VpnService: establish() TUN, drive the core
      MainActivity.kt        # config editor + connect/disconnect, screens
      ServerProfile.kt / ProfileStore.kt        # profile model + persistence
      SplitTunnel.kt         # per-app allow/deny modes
      ConfigFetcher.kt / SubscriptionWorker.kt  # config-over-URL subscription
      ExternalControl.kt / ControlActivity.kt   # outline:// grammar + entry point
      AppTheme.kt            # system light/dark theme
      KeepAlivePolicy.kt / KeepAliveState.kt / KeepAliveScreen.kt
      AutomationPolicy.kt / AutomationStore.kt / AutomationState.kt / WifiAutomationScreen.kt
      keepalive/             # BootReceiver, WatchdogAlarm/Worker/Receiver, helper
    src/test/java/com/outline/proxy/
      ExternalControlTest.kt, KeepAlivePolicyTest.kt, AutomationPolicyTest.kt,   # JVM unit tests
      SubscriptionProfileTest.kt, ConfigValidationTest.kt
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
`VpnService` TUN fd via `RunOptions.tun_fd` and drives TCP/UDP flows straight
into the uplink stack — no tun2proxy bridge, no SOCKS5 loopback hop in
between. Loop avoidance is unchanged: the Kotlin side excludes this app's own
package from the VPN (`addDisallowedApplication(self)`), so every socket the
uplinks open bypasses the TUN automatically — no per-socket
`VpnService.protect()`.

Those uplink sockets ride whatever network the tunnel is bound to with
`setUnderlyingNetworks`, so `OutlineVpnService` watches the best **non-VPN**
network offering `INTERNET` — `registerBestMatchingNetworkCallback` on API 31+,
a ranked pick (validated first, then Ethernet > Wi-Fi > cellular) over the
matching networks below that — and re-binds on Wi-Fi ⇄ cellular handovers. Two
filters carry their weight: `NET_CAPABILITY_NOT_VPN`, because a default-network
callback reports our own VPN network back to us and the tunnel would end up as
its own underlying network; and the bookkeeping of which network is actually in
use, so that a network coming up beside a better one cannot steal the binding
and the loss of a network we are not riding is ignored. Watching networks needs
`ACCESS_NETWORK_STATE`; without it the callback throws and only the handover
tracking is lost, not the tunnel.

The Rust core is built slim (`--no-default-features` + `h3, tun`): the native
TUN engine, the WS/TLS uplink stack, and the QUIC/HTTP-3 carriers — without
mimalloc, metrics, dashboard, or SOCKS5 ingress (the `socks5` feature stays
off, and `outline-ws-rust` also gates the listener at runtime: given a
`tun_fd`, it never starts, regardless of the TOML).

## Prerequisites

```sh
rustup target add aarch64-linux-android      # + armv7/x86_64 for more ABIs
cargo install cargo-ndk
brew install --cask android-ndk              # NDK r29 -> /opt/homebrew/share/android-ndk
export ANDROID_NDK_HOME=/opt/homebrew/share/android-ndk
```

For the **app** you also need Android Studio (it bundles a JDK 17 + the Android
SDK). No system-wide JDK/SDK/Gradle is required — the Gradle **wrapper** is
checked in (`gradlew`, `gradle/wrapper/`).

## Build the Rust artifacts

One script regenerates both the native `.so` (into `app/src/main/jniLibs/`) and
the UniFFI Kotlin bindings (into `app/src/main/java/uniffi/`):

```sh
export ANDROID_NDK_HOME=/opt/homebrew/share/android-ndk
./build-rust.sh                 # arm64-v8a, debug
./build-rust.sh arm64-v8a --release
```

Both outputs are gitignored — rerun this after any change under `android/rust/`
(or the monorepo crates it pulls in).

Notes:
- The crate enables the ws-rust `h3` and `tun` features — QUIC/HTTP-3 carriers
  and the native TUN engine, no SOCKS5 (`socks5` stays off). `h3` pulls quinn +
  the patched `h3` fork (`vendor/h3`); `android/rust` is a detached workspace,
  so it repeats the root's `[patch.crates-io] h3 = …` — without it the
  vendored `sockudo-ws` HTTP/3 carrier fails to compile against upstream `h3`.
- Bindings are generated from the **host** `.dylib` (a cross-compiled `.so`
  can't be loaded on the build host); the script handles this.
- cargo-ndk 4.x: API level is `--platform N` (not `-p N`, which is cargo's
  `--package`); cargo args go after `--`.
- uniffi 0.31+ auto-detects a library source, so the bindgen takes the `.dylib`
  as a positional argument; the old `--library <path>` flag is a no-op.

## Build & run the app

1. `./build-rust.sh` (once, and after Rust changes).
2. Open `android/` in Android Studio — it writes `local.properties` (SDK path)
   and downloads the Gradle 9.7.0 distribution on first sync. `compileSdk = 37`
   is pulled in automatically if the platform is missing.
3. Run on a device/emulator, add a server, Connect.

CLI alternative (needs a JDK 17+ and an Android SDK, `local.properties` with
`sdk.dir`): `./gradlew :app:assembleDebug`, `./gradlew :app:testDebugUnitTest`
for the JVM unit tests. Without a system JDK, Android Studio's bundled one
works: `export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"`.

### Release signing

`:app:assembleRelease` signs the APK when release credentials are available, and
falls back to an unsigned APK when they are not — a fresh clone builds either
way. Credentials come from `android/keystore.properties` first, and from the
environment (`OUTLINE_KEYSTORE_FILE`, `OUTLINE_KEYSTORE_PASSWORD`,
`OUTLINE_KEY_ALIAS`, `OUTLINE_KEY_PASSWORD`) when that file is absent. A
*partial* set is a hard error rather than a silent downgrade: an unsigned APK
cannot be installed over a signed one, and finding that out at `adb install`
time is worse than failing the build.

The properties file and any `*.jks`/`*.keystore`/`*.p12` in the tree are
gitignored; keep the keystore itself outside the work tree
(`~/.android/outline-proxy-release.jks`). To create one:

```sh
keytool -genkeypair -v -keystore ~/.android/outline-proxy-release.jks \
  -storetype PKCS12 -alias outline-proxy -keyalg RSA -keysize 4096 \
  -validity 10950 -dname "CN=Outline Proxy, O=Outline Proxy, C=RU"
```

Then point `keystore.properties` at it (`storeFile`, `storePassword`,
`keyAlias`, `keyPassword`). Only v2/v3 signature schemes are enabled: `minSdk`
is 24, the release that introduced v2, so the legacy v1 JAR signature is dead
weight. **Back the keystore and its password up** — losing them means the app
can only ever be reinstalled from scratch, never upgraded in place.

Verify what you shipped:

```sh
$ANDROID_HOME/build-tools/<ver>/apksigner verify --print-certs -v \
  app/build/outputs/apk/release/app-release.apk
```

### Gradle toolchain

AGP 9.3.1 / Gradle 9.7.0 / Kotlin 2.4.10 on stock AGP 9 defaults —
`gradle.properties` carries no `android.*` compatibility flags, and the build
draws no deprecation warnings from AGP or Gradle (the two `Expression is
unused` ones come from the generated UniFFI bindings). Three consequences
worth knowing:

- **AGP compiles Kotlin itself** (built-in Kotlin). There is no
  `org.jetbrains.kotlin.android` plugin — only the Compose compiler plugin is
  applied on top, which AGP finds by plugin id and wires into its own compile
  tasks. That plugin was also the sole caller of the legacy variant API
  (`testVariants`/`unitTestVariants`), removed in AGP 10.
- **The JVM target is set once.** Built-in Kotlin defaults `jvmTarget` to
  `compileOptions.targetCompatibility` and fails the build if the two diverge,
  so `compileOptions` alone pins both compilers to 17. A `kotlin { }` block
  would be redundant, and a conflicting one is a build error.
- **R8 minification is on, and it only survives because of keep rules.** JNA
  and the UniFFI bindings are wired by reflection and by symbol name
  (`Native.register`), so R8 cannot see how any of it is used;
  `proguard-rules.pro` pins those names and silences JNA's desktop AWT paths
  (`-dontwarn java.awt.**`), which android.jar has no classes for. Verify a
  rule change by *running* the release build, not by building it: renaming
  breaks at runtime, never at build time.

## Where the config comes from

The node generates a ready client config per user — `<user>.toml`, next to
`.conf` and `.json` (`ops/access-keys/generate_keys.py`; the report calls its
link `ws_url`). It carries the full carrier chain for every entry node, failover
between nodes, and live-flow migration — none of which the profile's structured
form can express, since a single `vless://` / `ss://` link describes one carrier
of one node. Paste it whole into the **Raw TOML override** field.

The generated `[tun] mtu` must match `ServerProfile.TUN_MTU` — 1500 on both
sides today. Change one and you must change the other, or the VPN comes up with
an MTU the proxy core does not know about.

What lands in the config depends on the node: the h3 carrier mode, the set of
paths, padding, carrier migration and soft node switching are only turned on
when the node ships the matching sections. The generator reports the ones that
are off as `warning:` lines — see
[`ops/access-keys/README.md`](../ops/access-keys/README.md).

The generated profile also carries `[outline.probe]` — a DNS probe plus TLS
handshakes through the tunnel, mirroring the fleet's own `main` group. Without
it the client has no health signal independent of traffic: an uplink marked down
can only be cleared by data flowing over it, so losing every uplink at once (a
SIM switch, a dead cell) used to read as "no link" until the tunnel was
reconnected by hand. The probe interval is 60 s rather than the fleet's 10 s —
on a phone the difference is battery, and on an edge-class cell it is the very
bandwidth the tunnel needs.

### Subscription URL

Instead of pasting the config, a profile can point at an HTTPS URL that serves
one (**Config URL** field in the editor) — the same `<user>.toml` the node
generates, fetched and kept current the way Happ tracks a subscription. With a
URL set, the transport fields are hidden: the URL is the single source of the
config.

- The body must be a whole client config (not an xray-style list of servers);
  one URL is one profile with all its uplinks inside.
- **HTTPS only** — the config carries UUIDs and passwords. The URL's path is a
  secret token, so it is never logged in full, only masked (`host/…tail`).
- The fetched config is cached in the profile. A background worker
  (`SubscriptionWorker`, WorkManager, every 12 h) refreshes it; a failed fetch
  keeps the last good cache and never disturbs a running tunnel. The list shows
  "updated N h ago" and a **Refresh** button for an immediate pull.
- A response only replaces the cache if it looks like a config (has `[tun]` or
  `[[outline.uplinks]]`), so an HTML error page or captcha cannot blank out a
  working subscription.
- The fetch goes out directly (this app is excluded from its own VPN). If the
  source is only reachable *through* the tunnel, background refresh will fail and
  the cache carries on — a known limitation.

### Dial budget on slow links

The generated config carries no `[dial]` section, so the core bounds every fresh
carrier dial at its 10 s default. That fits Wi-Fi and LTE and is the *cause* of
failure on an edge-class cell: a 2G round trip runs close to a second and the
certificate chain alone takes seconds to clock out, so the budget expires
mid-handshake, every attempt is scored a failure, and the retries eat the
bandwidth the handshake needed — the tunnel reports itself up while carrying
nothing.

So the app fills the section in from what the platform says about the link it is
about to ride (`DialTimeout`): a cellular link estimated at or below 200 kbit/s
gets 60 s, one below 2 Mbit/s gets 30 s, anything faster keeps the default. Wi-Fi
and Ethernet are never widened — a slow Wi-Fi is usually a slow backhaul, where
the handshake still completes in a couple of round trips, and widening the bound
would only delay failover. A link the platform has not characterised yet is left
alone rather than assumed slow.

A config that declares `[dial]` itself is never touched: an explicit value from
the operator outranks this guess.

The budget **follows the link**, it is not frozen at connect time. The service
watches the network it rides — including `onCapabilitiesChanged`, which is how a
cell handover, a generation change (2G ↔ 3G ↔ LTE ↔ 5G) and, on many devices, a
data-SIM switch actually arrive: the `Network` object stays the same while its
properties change underneath. Walking from Wi-Fi into a 2G cell widens the bound,
walking back restores the default (leaving 60 s on a fast link would only slow
failover down), and the engine picks the new value up on its next dial —
handshakes already in flight keep the deadline they started with. Nothing is torn
down, and a repeated estimate is not re-applied, so a signal-strength wobble
costs nothing.

Generations land where you would expect them: GPRS and EDGE are estimated at or
below 200 kbit/s and get 60 s, UMTS and a weak HSPA or LTE land under 2 Mbit/s
and get 30 s, and anything healthier keeps the default. Since not every firmware
re-reports the bandwidth estimate when only the radio technology changes, the
budget is also re-checked on the service's existing 2-second tick — a capability
read and a comparison, free when nothing moved.

### What the home screen says about the link

Under the tunnel status the card shows the network the tunnel is actually
riding: `Wi-Fi · 20 ms`, or `LTE · 4.2 s`. Two facts, both of them measured or
named by the platform, and either is dropped rather than faked when unknown:

- **What the link is.** Wi-Fi and Ethernet name themselves. A cellular link
  names its radio technology (2G / 3G / LTE / 5G) when the app is allowed to
  read it, and says "Cellular" otherwise. Note that this is the radio actually
  carrying data (`dataNetworkType`), which routinely disagrees with the
  status-bar icon: that icon commonly tracks 5G *coverage* or a 5G-capable NSA
  anchor, so "5G" up there and `LTE` here is normal, not a bug.
- **What the link costs the tunnel** — the last round-trip the core measured on
  a real dial.

Nothing derived is shown. An earlier version also printed the platform's
bandwidth estimate and a speed class computed from it, and both were removed:
firmware invents the estimate (one device reported 14 kbit/s on a full-signal
LTE cell that was carrying traffic perfectly well), and a label computed from a
wrong number is a wrong number with more confidence behind it. The estimate is
still read — it sizes the dial budget before anything has been measured — it is
just not put on screen.

A round-trip that reaches the dial budget is dropped too. That is a dial which
ran out of time, and the number it yields is the budget rather than the link:
the first probe after a connect produced exactly "10.0 s" on a 10-second budget.
Showing nothing beats showing a timeout dressed up as a measurement.

Naming the radio technology needs `READ_PHONE_STATE`. The app never asks for it
on its own: it sits on the **Keeping Alive** checklist with the other grants,
marked optional, because nothing the tunnel decides depends on it — the dial
budget is sized from the bandwidth estimate either way, and denying it costs a
label and nothing else.

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
percent-decoded (`?profile=Home%20VPN`). A command never creates a server — the
profile must already exist in the list, matched by id first, then by name. On
success nothing is shown; the foreground-service notification is the status
indicator. Refusals raise a Toast and a `OutlineControl` warning in logcat.

```sh
adb shell am start -a android.intent.action.VIEW -d 'outline://connect'
adb shell am start -a android.intent.action.VIEW -d 'outline://toggle?profile=Home&token=s3cret'
```

Access is gated in **External control…** on the main screen: a switch (on by
default) and an optional token. Once a token is set, commands without a
matching `?token=` are ignored — the comparison is content-independent
(`MessageDigest.isEqual`). Any installed app, and — because the intent filter
carries `BROWSABLE` — any web page, can fire these URIs, so set a token if a
silent `disconnect` would matter to you.

Implementation: `ControlActivity` is a transparent activity that dispatches the
command and finishes. It cannot be a receiver or an exported service — the
system VPN consent dialog needs an activity to launch from, and Android 12+
forbids starting a foreground service from the background. Callers must
themselves be allowed to start activities: a background app without that
privilege (Tasker without "Draw over other apps", say) will have the URI
silently dropped by the platform.

## Keeping the tunnel alive

Every path that might have to bring the tunnel back — always-on VPN, boot, the
watchdog alarm, the WorkManager job, `onDestroy` — routes through a single
`OutlineVpnService.ensure()`. It reads the user's *intent* (`KeepAliveState.shouldRun`,
set on connect, cleared on an explicit disconnect) and the live core state
(`isRunning()`), and `KeepAlivePolicy.decide(...)` — a pure, unit-tested function —
returns one of: do nothing, stop, give up (and notify), or connect. A failing
connect backs off 5 → 15 → 30 min; a healthy tunnel is re-checked every 5 min.

Four ways the tunnel comes back:

- **Always-on VPN** — the strongest, and the reason `onStartCommand(null)` maps
  to `ensure()`: the system starts and restarts the service itself. Enabled by
  the user in system settings.
- **Boot / app update** — `BootReceiver` (BOOT_COMPLETED, MY_PACKAGE_REPLACED),
  after unlock. Not direct-boot aware on purpose: profiles hold credentials and
  stay in credential-protected storage.
- **Watchdog pair** — an alarm (`WatchdogAlarm`, pierces Doze, re-arms itself)
  and a 15-minute WorkManager job (`WatchdogWorker`, its schedule survives
  reboot); each calls `ensure()`. The alarm is exact only once
  `SCHEDULE_EXACT_ALARM` is granted, otherwise the system batches it at its own
  discretion; `USE_EXACT_ALARM`, which would grant that without asking, is
  deliberately left out — the manifest comment says why.
- **Swipe / kill** — `stopWithTask="false"` plus `onTaskRemoved`/`onDestroy`
  schedule a check right behind the process going away.

The **Keeping alive…** screen is a checklist of what only the user can grant —
always-on VPN, battery-optimisation exemption, exact alarms, notifications, and
the vendor autostart screen (probed per-device with `resolveActivity`; on this
HONOR it opens `com.hihonor.systemmanager`). Each row shows its status and a
button to the right system screen. These grants are also what makes starting a
foreground service from the background legal on Android 12+.

`specialUse` is **not** on Android 15's list of FGS types barred from
`BOOT_COMPLETED`, so the boot path is open. Test the restriction without changing
`targetSdk`:

```sh
adb shell am compat enable FGS_BOOT_COMPLETED_RESTRICTIONS com.outline.proxy
adb shell am broadcast -a android.intent.action.BOOT_COMPLETED com.outline.proxy
```

Verified so far: unit tests for the decision table; on-device, the checklist
screen and its system-screen intents (HONOR / MagicOS). The background revival
paths (force-stop → return, reboot) are wired but not yet run end-to-end on
hardware. The vendor table for MIUI/EMUI/ColorOS/One UI is carried unverified.

## Roadmap

- **Increment 1 (done):** Rust⇄Kotlin bridge, SOCKS5 + uplinks boot, `VpnService`
  + Compose scaffold. `.so` verified to cross-compile under NDK r29.
- **Increment 2 (done, now superseded by native TUN):** shipped a tun2proxy
  bridge (TUN fd → SOCKS5) so the tunnel carried traffic, loop avoidance via
  `addDisallowedApplication(self)`. tun2proxy is gone — replaced by the native
  `outline-tun` engine attached directly to the `VpnService` fd via
  `RunOptions.tun_fd` (see Architecture). SOCKS5 ingress is compiled out for
  Android (`socks5` feature off, plus a runtime gate: fd present ⇒ no
  listener); loop avoidance is unchanged. `.so` (built with the `h3, tun`
  features) verified to cross-compile under NDK r29 and the debug APK builds
  against it; not yet exercised end-to-end on an emulator or device.
- **Increment 3 (done):** QUIC/h3 (`h3` feature; quinn + h3 verified to
  cross-compile under NDK), logcat logging (paranoid-android), persisted
  server-list UI, reconnect on network change (`setUnderlyingNetworks`). Rust
  verified; Kotlin authored but not yet built on a device.
- **Increment 4 (done):** per-app split tunneling (`addAllowedApplication` /
  `addDisallowedApplication`) with an app-picker UI — modes OFF / ALLOWLIST /
  DENYLIST, persisted in SharedPreferences, applied in `OutlineVpnService`.
  Kotlin authored, not yet built on a device.
- **Increment 5 (done):** external control over the `outline://` scheme
  (connect / disconnect / toggle, optional profile selector), gated by a switch
  and an optional token; parser and gate covered by JVM unit tests.
- **Increment 6 (done):** productisation — config-over-URL subscriptions
  (`ConfigFetcher` / `SubscriptionWorker`), keep-the-tunnel-alive infrastructure
  (`KeepAlivePolicy` + the `keepalive/` watchdog pair), a system light/dark
  theme, a launcher icon, signed release builds, a single connect/disconnect
  button, and a profile-named foreground notification. See the sections above
  for each.

## What is verified vs. not

- **Verified by build:** the Rust core (`outline-android` cdylib) cross-compiles
  to a loadable `aarch64` Android `.so`, including the native TUN engine, the
  uplink stack, and the QUIC/h3 carriers — SOCKS5 ingress and tun2proxy are
  compiled out (see Architecture).
- **Verified by build (Kotlin):** `:app:assembleDebug` produces a debug APK and
  `:app:testDebugUnitTest` passes — the latter covers the `outline://` parser,
  the access gate, and profile resolution on the JVM.
- **Verified on an emulator** (Pixel_10, API 37, arm64), debug build, under the
  original tun2proxy bridge (now superseded — see Architecture): the service
  established the TUN, the Rust core booted (SOCKS5 listening on
  127.0.0.1:1080, uplink registry up) and tun2proxy connected into it,
  `outline://connect` / `disconnect` dispatched, and the underlying-network
  tracking followed a Wi-Fi ⇄ cellular handover both ways — `dumpsys
  connectivity` showed the VPN agent's `underlying{[N]}` swapping between the
  cellular and Wi-Fi networks, never binding the VPN network itself. The
  native TUN engine that replaced tun2proxy has not had an equivalent run yet
  (see "Not verified" below).
- **Verified on an emulator**, release build: with R8 minification on, the
  `.so` loads and `start()` reaches Rust — the keep rules hold. Checked by
  running the signed release APK, since a bad keep rule fails at runtime only.
- **Not verified:** on real hardware only the keep-alive checklist screen and
  its vendor intents have been exercised (a HONOR / MagicOS device) — no data
  plane has, and no traffic has been carried end-to-end through a live server
  (the emulator runs pointed at a dead endpoint). Per-app split tunneling still
  needs a real run. The native TUN engine itself has not been exercised on an
  emulator or a device yet — cross-compile and the debug APK build are confirmed
  (see Roadmap, increment 2), but nobody has booted the tunnel and watched
  packets cross it.

## Notes for porting

The Rust core needs a few `cfg(android)` adaptations as features expand:
- `outline-net` `SO_MARK` is privileged on Android — use `VpnService.protect()`.
- `freebind` / `/proc/net/if_inet6` IPv6-source logic is not applicable; gate it off.
- `outline-tun` now runs on Android too: `/dev/net/tun` + `TUNSETIFF` (needs
  root) stays the desktop path, and a second one attaches the engine to an
  already-open fd (`RunOptions.tun_fd`) — the one the `VpnService` hands us, no
  root needed.
