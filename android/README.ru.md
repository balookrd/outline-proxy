# Outline Proxy — клиент для Android

Android-клиент VPN, подключающийся к вашим серверам через полный uplink-стек
`outline-ws-rust` (padding + VLESS / SS / WS / TLS, failover). Rust-ядро
переиспользуется без изменений; Android добавляет лишь тонкий слой
`VpnService` + UI.

> Статус: **инкремент 4**. Поверх инкрементов 1–3 (мост + tun2proxy несут
> трафик, носители QUIC/HTTP-3, логирование в logcat, персистентный UI со
> списком серверов, переключение Wi-Fi⇄мобильная сеть) теперь добавлен
> **per-app split tunneling**: UI выбора приложений с тремя режимами (все
> приложения / только выбранные / все, кроме выбранных). Весь Rust-стек
> (включая quinn + h3) проверен на кросс-компиляцию под NDK r29.
> Gradle/Kotlin-приложение написано, но **ещё не собиралось и не запускалось на
> устройстве** (в этом окружении нет Android SDK).

## Структура

```
android/
  rust/            # outline-android: cdylib + UniFFI-обёртка над ws-rust
    src/lib.rs       # start() / stop() / is_running()
  app/             # Android-приложение (Gradle, Kotlin, Compose)
    src/main/java/com/outline/proxy/
      OutlineVpnService.kt   # VpnService: establish() TUN, управляет ядром
      MainActivity.kt        # список серверов + connect/disconnect
```

## Архитектура

```
VpnService.establish() ──tun_fd──┐
                                 ▼
   tun2proxy ── читает TUN fd, форвардит захваченные потоки в ─┐
                                                               ▼
   outline-ws-rust SOCKS5 (127.0.0.1:1080) ── uplinks: padding/VLESS/SS/WS/TLS
                                                               │
   аплинк-сокеты ── идут мимо TUN (свой пакет исключён ───────┘
                    через addDisallowedApplication) → реальная сеть
```

Rust-ядро собирается в slim-виде (`--no-default-features` + `h3`): SOCKS5-вход,
WS/TLS uplink-стек и носители QUIC/HTTP-3 — без mimalloc, метрик, дашборда и
десктопного TUN-движка.

## Требования

```sh
rustup target add aarch64-linux-android      # + armv7/x86_64 для других ABI
cargo install cargo-ndk
brew install --cask android-ndk              # NDK r29 -> /opt/homebrew/share/android-ndk
export ANDROID_NDK_HOME=/opt/homebrew/share/android-ndk
```

Для **приложения** дополнительно нужен Android Studio (он несёт встроенные
JDK 17 + Android SDK). Общесистемные JDK/SDK/Gradle не требуются — Gradle
**wrapper** закоммичен (`gradlew`, `gradle/wrapper/`).

## Сборка Rust-артефактов

Один скрипт пересобирает и нативную `.so` (в `app/src/main/jniLibs/`), и
UniFFI-биндинги Kotlin (в `app/src/main/java/uniffi/`):

```sh
export ANDROID_NDK_HOME=/opt/homebrew/share/android-ndk
./build-rust.sh                 # arm64-v8a, debug
./build-rust.sh arm64-v8a --release
```

Оба артефакта в gitignore — перезапускайте скрипт после любых правок в
`android/rust/` (или в крейтах монорепо, которые он подтягивает).

Замечания:
- Крейт включает фичу `h3` из ws-rust, что тянет quinn + патченый форк `h3`
  (`vendor/h3`). `android/rust` — отдельный (detached) workspace, поэтому он
  повторяет корневой `[patch.crates-io] h3 = …`; без него vendored-носитель
  HTTP/3 `sockudo-ws` не компилируется против апстримного `h3`.
- Биндинги генерируются из **host**-`.dylib` (кросс-скомпилированную `.so`
  нельзя загрузить на хосте сборки); скрипт это учитывает.
- cargo-ndk 4.x: уровень API задаётся `--platform N` (а не `-p N` — это cargo
  `--package`); cargo-аргументы идут после `--`.

## Сборка и запуск приложения

1. `./build-rust.sh` (один раз и после правок Rust).
2. Откройте `android/` в Android Studio — она запишет `local.properties` (путь
   к SDK) и при первой синхронизации скачает дистрибутив Gradle 8.10.2.
3. Запустите на устройстве/эмуляторе, добавьте сервер, нажмите Connect.

Альтернатива через CLI (нужны JDK 17 + Android SDK в `PATH`, `local.properties`
с `sdk.dir`): `./gradlew :app:assembleDebug`.

## Дорожная карта

- **Инкремент 1 (готово):** мост Rust⇄Kotlin, запуск SOCKS5 + uplinks, каркас
  `VpnService` + Compose. `.so` проверена на кросс-компиляцию под NDK r29.
- **Инкремент 2 (готово):** мост tun2proxy (TUN fd → SOCKS5) — туннель несёт
  трафик; защита от петли через `addDisallowedApplication(self)`. `.so`
  (вместе со стеком tun2proxy) проверена под NDK r29. End-to-end на устройстве
  ещё не прогонялось. Обработка DNS (tun2proxy virtual vs direct) на дефолтах —
  вероятная точка тюнинга при первых реальных запусках.
- **Инкремент 3 (готово):** QUIC/h3 (фича `h3`; quinn + h3 проверены на
  кросс-компиляцию под NDK), логирование в logcat (paranoid-android),
  персистентный UI со списком серверов, переподключение при смене сети
  (`setUnderlyingNetworks`). Rust проверен; Kotlin написан, но на устройстве ещё
  не собирался.
- **Инкремент 4 (готово):** per-app split tunneling (`addAllowedApplication` /
  `addDisallowedApplication`) с UI-выбором приложений — режимы OFF / ALLOWLIST /
  DENYLIST, хранятся в SharedPreferences, применяются в `OutlineVpnService`.
  Kotlin написан, на устройстве ещё не собирался.

## Что проверено, а что нет

- **Проверено сборкой:** Rust-ядро (cdylib `outline-android`) кросс-компилируется
  в загружаемую `aarch64` Android-`.so`, включая стек SOCKS5 + uplinks,
  tun2proxy и носители QUIC/h3.
- **Не проверено:** Gradle/Kotlin-приложение здесь ни разу не собиралось и не
  запускалось (нет Android SDK / Gradle). UniFFI-биндинги Kotlin, Compose-UI,
  жизненный цикл VpnService и сквозное прохождение трафика — всё это требует
  первой реальной сборки на устройстве. Обработка DNS в tun2proxy на дефолтах и
  является наиболее вероятным первым кандидатом на тюнинг.

## Заметки по портированию

Rust-ядру нужны несколько адаптаций под `cfg(android)` по мере роста фич:
- `SO_MARK` в `outline-net` привилегирован на Android — использовать
  `VpnService.protect()`.
- Логика IPv6-source `freebind` / `/proc/net/if_inet6` неприменима — отключать
  фича-флагом.
- Десктопный TUN-движок `outline-tun` открывает `/dev/net/tun` через `TUNSETIFF`
  (нужен root) — здесь не используется; вместо него tun2proxy потребляет
  дескриптор от VpnService.
