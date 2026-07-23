# Outline Proxy — Android client

Android VPN client that connects to your servers using the full `outline-ws-rust`
uplink stack (padding + VLESS / SS / WS / TLS, failover). The Rust core is reused
unchanged; Android only adds a thin `VpnService` + UI layer on top.

> Status: **increment 4**. On top of increments 1–3 (bridge + tun2proxy carry
> traffic, QUIC/HTTP-3 carriers, logcat logging, persisted server-list UI,
> Wi-Fi⇄cellular handover), now with **per-app split tunneling**: an app-picker
> UI with three modes (all apps / only selected / all except selected). The
> whole Rust stack (incl. quinn + h3) is verified to cross-compile under NDK
> r29. The Gradle/Kotlin app is authored but **not yet built or run on a
> device** (no Android SDK in this environment).

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
   tun2proxy ── reads TUN fd, forwards captured flows to ─┐
                                                          ▼
   outline-ws-rust SOCKS5 (127.0.0.1:1080) ── uplinks: padding/VLESS/SS/WS/TLS
                                                          │
   uplink sockets ── bypass the TUN (own package is ─────┘
                     addDisallowedApplication'd) → real network
```

The Rust core is built slim (`--no-default-features` + `h3`): SOCKS5 ingress,
the WS/TLS uplink stack, and the QUIC/HTTP-3 carriers — without mimalloc,
metrics, dashboard, or the desktop TUN engine.

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
- The crate enables the ws-rust `h3` feature, pulling quinn + the patched `h3`
  fork (`vendor/h3`). `android/rust` is a detached workspace, so it repeats the
  root's `[patch.crates-io] h3 = …` — without it the vendored `sockudo-ws`
  HTTP/3 carrier fails to compile against upstream `h3`.
- Bindings are generated from the **host** `.dylib` (a cross-compiled `.so`
  can't be loaded on the build host); the script handles this.
- cargo-ndk 4.x: API level is `--platform N` (not `-p N`, which is cargo's
  `--package`); cargo args go after `--`.

## Build & run the app

1. `./build-rust.sh` (once, and after Rust changes).
2. Open `android/` in Android Studio — it writes `local.properties` (SDK path)
   and downloads the Gradle 8.10.2 distribution on first sync.
3. Run on a device/emulator, add a server, Connect.

CLI alternative (needs a JDK 17+ and an Android SDK, `local.properties` with
`sdk.dir`): `./gradlew :app:assembleDebug`, `./gradlew :app:testDebugUnitTest`
for the JVM unit tests. Without a system JDK, Android Studio's bundled one
works: `export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"`.

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
- **Increment 2 (done):** tun2proxy bridge (TUN fd → SOCKS5) so the tunnel
  carries traffic; loop avoidance via `addDisallowedApplication(self)`. `.so`
  (incl. tun2proxy's stack) verified to cross-compile under NDK r29. Not yet
  exercised end-to-end on a device. DNS handling (tun2proxy virtual vs direct)
  is still at defaults — a likely tuning point for first real runs.
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
  to a loadable `aarch64` Android `.so`, including the SOCKS5 + uplink stack,
  tun2proxy, and the QUIC/h3 carriers.
- **Verified by build (Kotlin):** `:app:assembleDebug` produces a debug APK and
  `:app:testDebugUnitTest` passes — the latter covers the `outline://` parser,
  the access gate, and profile resolution on the JVM.
- **Not verified:** nothing has been run on a device or emulator. The UniFFI
  Kotlin bindings, Compose UI, VpnService lifecycle, `outline://` dispatch
  end-to-end, and traffic flow all need a first real run. DNS handling in
  tun2proxy is at defaults and is the likeliest first thing to tune.

## Notes for porting

The Rust core needs a few `cfg(android)` adaptations as features expand:
- `outline-net` `SO_MARK` is privileged on Android — use `VpnService.protect()`.
- `freebind` / `/proc/net/if_inet6` IPv6-source logic is not applicable; gate it off.
- The desktop `outline-tun` engine opens `/dev/net/tun` via `TUNSETIFF` (needs
  root) — not used here; tun2proxy consumes the VpnService fd instead.
