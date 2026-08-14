# Outline Proxy — Android client

Android VPN client that connects to your servers using the full `outline-ws-rust`
uplink stack (padding + VLESS / SS / WS / TLS, failover). The Rust core is reused
unchanged; Android only adds a thin `VpnService` + UI layer on top.

> Status: **increment 4**. On top of increments 1–3 (Rust⇄Kotlin bridge, TUN
> traffic carried through the uplinks, QUIC/HTTP-3 carriers, logcat logging,
> persisted server-list UI, Wi-Fi⇄cellular handover), now with **per-app split
> tunneling**: an app-picker UI with three modes (all apps / only selected /
> all except selected). The whole Rust stack (incl. quinn + h3) is verified to
> cross-compile under NDK r29, and the Gradle/Kotlin app builds (debug APK,
> minified release APK, green JVM unit tests). Both builds were **run on an
> emulator** under the original tun2proxy bridge — TUN up, Rust core booted,
> handover followed; that bridge has since been replaced by a native
> `outline-tun` engine attached directly to the TUN fd (see Architecture),
> verified so far by build/cross-compile only. Nothing has run on **real
> hardware**, and no traffic has crossed a live server yet.

## Layout

```
android/
  rust/            # outline-android: cdylib + UniFFI wrapper around ws-rust
    src/lib.rs       # start() / stop() / is_running()
  app/             # Android app (Gradle, Kotlin, Compose)
    src/main/java/com/outline/proxy/
      OutlineVpnService.kt   # VpnService: establish() TUN, drive the core
      MainActivity.kt        # config editor + connect/disconnect
      ExternalControl.kt     # outline:// URI grammar, access gate, settings
      ControlActivity.kt     # invisible entry point for outline:// commands
    src/test/java/com/outline/proxy/
      ExternalControlTest.kt # JVM unit tests for the URI parser and the gate
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
   and downloads the Gradle 9.6.1 distribution on first sync. `compileSdk = 37`
   is pulled in automatically if the platform is missing.
3. Run on a device/emulator, add a server, Connect.

CLI alternative (needs a JDK 17+ and an Android SDK, `local.properties` with
`sdk.dir`): `./gradlew :app:assembleDebug`, `./gradlew :app:testDebugUnitTest`
for the JVM unit tests. Without a system JDK, Android Studio's bundled one
works: `export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"`.

### Gradle toolchain

AGP 9.3.1 / Gradle 9.6.1 / Kotlin 2.4.10 on stock AGP 9 defaults —
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
- **Not verified:** nothing has been run on real hardware, and no traffic has
  been carried end-to-end through a live server — the emulator runs pointed at
  a dead endpoint. Per-app split tunneling still needs a real run. The native
  TUN engine itself has not been exercised on an emulator or a device yet —
  cross-compile and the debug APK build are confirmed (see Roadmap, increment
  2), but nobody has booted the tunnel and watched packets cross it.

## Notes for porting

The Rust core needs a few `cfg(android)` adaptations as features expand:
- `outline-net` `SO_MARK` is privileged on Android — use `VpnService.protect()`.
- `freebind` / `/proc/net/if_inet6` IPv6-source logic is not applicable; gate it off.
- `outline-tun` now runs on Android too: `/dev/net/tun` + `TUNSETIFF` (needs
  root) stays the desktop path, and a second one attaches the engine to an
  already-open fd (`RunOptions.tun_fd`) — the one the `VpnService` hands us, no
  root needed.
