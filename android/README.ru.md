# Outline Proxy — клиент для Android

Android-клиент VPN, подключающийся к вашим серверам через полный uplink-стек
`outline-ws-rust` (padding + VLESS / SS / WS / TLS, failover). Rust-ядро
переиспользуется без изменений; Android добавляет лишь тонкий слой
`VpnService` + UI.

> Статус: **инкремент 4**. Поверх инкрементов 1–3 (мост Rust⇄Kotlin, TUN несёт
> трафик через аплинки, носители QUIC/HTTP-3, логирование в logcat,
> персистентный UI со списком серверов, переключение Wi-Fi⇄мобильная сеть)
> теперь добавлен **per-app split tunneling**: UI выбора приложений с тремя
> режимами (все приложения / только выбранные / все, кроме выбранных). Весь
> Rust-стек (включая quinn + h3) проверен на кросс-компиляцию под NDK r29, а
> Gradle/Kotlin-приложение собирается (debug-APK, минифицированный
> release-APK, зелёные JVM-юнит-тесты). Обе сборки **запускались на
> эмуляторе** ещё на исходном мосте tun2proxy — TUN поднят, Rust-ядро
> стартовало, хендовер отработан; этот мост с тех пор заменён нативным
> движком `outline-tun`, подключённым напрямую к TUN-дескриптору (см.
> «Архитектура»), и пока проверен только сборкой/кросс-компиляцией. На
> **реальном железе** ничего не запускалось, трафик через живой сервер не шёл.

## Структура

```
android/
  rust/            # outline-android: cdylib + UniFFI-обёртка над ws-rust
    src/lib.rs       # start() / stop() / is_running()
  app/             # Android-приложение (Gradle, Kotlin, Compose)
    src/main/java/com/outline/proxy/
      OutlineVpnService.kt   # VpnService: establish() TUN, управляет ядром
      MainActivity.kt        # список серверов + connect/disconnect
      ExternalControl.kt     # грамматика outline://, гейт доступа, настройки
      ControlActivity.kt     # невидимая точка входа для команд outline://
    src/test/java/com/outline/proxy/
      ExternalControlTest.kt # JVM-тесты парсера URI и гейта доступа
```

## Архитектура

```
VpnService.establish() ──tun_fd──┐
                                 ▼
   outline-tun ── нативный движок, подключён к дескриптору напрямую ─┐
                                                                     ▼
   outline-ws-rust uplinks: padding/VLESS/SS/WS/TLS (SOCKS5-вход исключён из сборки)
                                                                     │
   аплинк-сокеты ── идут мимо TUN (свой пакет исключён ──────────────┘
                    через addDisallowedApplication) → реальная сеть
```

Rust-ядро подключает нативный движок `outline-tun` напрямую к
TUN-дескриптору `VpnService` через `RunOptions.tun_fd` и гонит TCP/UDP-потоки
прямо в uplink-стек — без моста tun2proxy и без захода в SOCKS5 через loopback.
Защита от петли не изменилась: Kotlin-сторона исключает пакет самого
приложения из VPN (`addDisallowedApplication(self)`), поэтому каждый сокет,
который открывают аплинки, автоматически идёт мимо TUN — без посокетного
`VpnService.protect()`.

Аплинк-сокеты идут по той сети, к которой туннель привязан через
`setUnderlyingNetworks`, поэтому `OutlineVpnService` следит за лучшей **не-VPN**
сетью с `INTERNET` — `registerBestMatchingNetworkCallback` на API 31+, а ниже
собственный выбор по рангу (сначала validated, затем Ethernet > Wi-Fi >
сотовая) — и перепривязывается на хендовере Wi-Fi ⇄ сотовая. Два фильтра здесь
не декоративны: `NET_CAPABILITY_NOT_VPN`, потому что default-колбэк отдаёт нам
нашу же VPN-сеть и туннель становится несущей сетью самому себе; и учёт того,
какая сеть используется сейчас, — чтобы поднявшаяся рядом сеть не перехватывала
привязку, а потеря сети, по которой мы не идём, игнорировалась. Слежение за
сетями требует `ACCESS_NETWORK_STATE`; без него колбэк падает с
`SecurityException`, и теряется только отслеживание хендовера, а не туннель.

Rust-ядро собирается в slim-виде (`--no-default-features` + `h3, tun`):
нативный TUN-движок, WS/TLS uplink-стек и носители QUIC/HTTP-3 — без
mimalloc, метрик, дашборда и SOCKS5-входа (фича `socks5` выключена, и
`outline-ws-rust` дополнительно гейтит слушатель в рантайме: если передан
`tun_fd`, он не стартует вне зависимости от TOML).

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
- Крейт включает фичи `h3` и `tun` из ws-rust — носители QUIC/HTTP-3 и
  нативный TUN-движок, без SOCKS5 (`socks5` остаётся выключенной). `h3` тянет
  quinn + патченый форк `h3` (`vendor/h3`); `android/rust` — отдельный
  (detached) workspace, поэтому он повторяет корневой
  `[patch.crates-io] h3 = …`; без него vendored-носитель HTTP/3 `sockudo-ws`
  не компилируется против апстримного `h3`.
- Биндинги генерируются из **host**-`.dylib` (кросс-скомпилированную `.so`
  нельзя загрузить на хосте сборки); скрипт это учитывает.
- cargo-ndk 4.x: уровень API задаётся `--platform N` (а не `-p N` — это cargo
  `--package`); cargo-аргументы идут после `--`.
- uniffi 0.31+ сам распознаёт библиотеку как источник, поэтому bindgen получает
  `.dylib` позиционным аргументом; старый флаг `--library <path>` — no-op.

## Сборка и запуск приложения

1. `./build-rust.sh` (один раз и после правок Rust).
2. Откройте `android/` в Android Studio — она запишет `local.properties` (путь
   к SDK) и при первой синхронизации скачает дистрибутив Gradle 9.6.1.
   `compileSdk = 37` докачивается автоматически, если платформы нет.
3. Запустите на устройстве/эмуляторе, добавьте сервер, нажмите Connect.

Альтернатива через CLI (нужны JDK 17+ и Android SDK, `local.properties` с
`sdk.dir`): `./gradlew :app:assembleDebug`, а `./gradlew :app:testDebugUnitTest` —
JVM-юнит-тесты. Если системной JDK нет, подойдёт встроенная в Android Studio:
`export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"`.

### Gradle-тулчейн

AGP 9.3.1 / Gradle 9.6.1 / Kotlin 2.4.10 на штатных дефолтах AGP 9 — в
`gradle.properties` нет ни одного флага совместимости `android.*`, и ни AGP, ни
Gradle не выдают предупреждений об устаревании (два `Expression is unused` —
из сгенерированных UniFFI-биндингов). Три следствия, о которых стоит знать:

- **Kotlin компилирует сам AGP** (built-in Kotlin). Плагина
  `org.jetbrains.kotlin.android` нет — сверху применяется только Compose-плагин,
  который AGP находит по id и подключает к собственным задачам компиляции.
  Именно тот плагин был единственным потребителем legacy variant API
  (`testVariants`/`unitTestVariants`), удаляемого в AGP 10.
- **JVM-target задаётся в одном месте.** Built-in Kotlin берёт `jvmTarget` из
  `compileOptions.targetCompatibility` и валит сборку, если они разошлись, —
  поэтому один `compileOptions` фиксирует 17 для обоих компиляторов. Блок
  `kotlin { }` избыточен, а противоречащий — ошибка сборки.
- **Минификация R8 включена и держится исключительно на keep-правилах.** JNA и
  UniFFI-биндинги связаны рефлексией и именами символов (`Native.register`),
  поэтому R8 не видит, как они используются; `proguard-rules.pro` закрепляет
  эти имена и глушит десктопные AWT-ветки JNA (`-dontwarn java.awt.**`) —
  классов для них в android.jar нет. Правку правил проверяй *запуском*
  release-сборки, а не сборкой: переименование ломается в рантайме, а не при
  компиляции.

## Внешнее управление (`outline://`)

Приложения-автоматизации (Tasker, ярлыки лаунчера, `adb`) управляют туннелем
через URI-схему:

```
outline://connect                     # поднять профиль, выбранный в UI
outline://connect?profile=<имя|id>    # поднять конкретный сохранённый профиль
outline://disconnect
outline://toggle[?profile=<имя|id>]   # опустить, если поднят, иначе поднять
```

Схема, команда и ключи query нечувствительны к регистру; значения
percent-декодируются (`?profile=Home%20VPN`). Команда никогда не создаёт сервер —
профиль должен уже быть в списке; сопоставление сначала по id, затем по имени.
При успехе ничего не показывается: индикатор состояния — уведомление
foreground-сервиса. Отказы дают Toast и предупреждение `OutlineControl` в logcat.

```sh
adb shell am start -a android.intent.action.VIEW -d 'outline://connect'
adb shell am start -a android.intent.action.VIEW -d 'outline://toggle?profile=Home&token=s3cret'
```

Доступ ограничивается в разделе **External control…** на главном экране:
переключатель (по умолчанию включён) и опциональный токен. Если токен задан,
команды без совпадающего `?token=` игнорируются, а сравнение не зависит от
содержимого (`MessageDigest.isEqual`). Дёрнуть такой URI может любое
установленное приложение — и, поскольку intent-фильтр несёт `BROWSABLE`, любая
веб-страница; так что если тихий `disconnect` для вас критичен, задайте токен.

Реализация: `ControlActivity` — прозрачная Activity, которая отправляет команду
и завершается. Ни receiver, ни exported-сервис здесь не подходят: системному
диалогу VPN-согласия нужна Activity, а Android 12+ запрещает старт
foreground-сервиса из фона. Вызывающей стороне при этом нужно право запускать
Activity: у фонового приложения без него (например, Tasker без «Поверх других
приложений») платформа молча отбросит URI.

## Дорожная карта

- **Инкремент 1 (готово):** мост Rust⇄Kotlin, запуск SOCKS5 + uplinks, каркас
  `VpnService` + Compose. `.so` проверена на кросс-компиляцию под NDK r29.
- **Инкремент 2 (готово, теперь заменено нативным TUN):** был мост tun2proxy
  (TUN fd → SOCKS5) — туннель нёс трафик, защита от петли через
  `addDisallowedApplication(self)`. tun2proxy убран — заменён нативным
  движком `outline-tun`, подключённым напрямую к дескриптору `VpnService`
  через `RunOptions.tun_fd` (см. «Архитектура»). SOCKS5-вход на Android
  исключён из сборки (фича `socks5` выключена, плюс рантайм-гейт: если
  передан `tun_fd` — слушатель не стартует); защита от петли не изменилась.
  `.so` (собрана с фичами `h3, tun`) проверена на кросс-компиляцию под NDK
  r29, а debug-APK успешно собирается с ней; end-to-end на эмуляторе или
  устройстве ещё не прогонялось.
- **Инкремент 3 (готово):** QUIC/h3 (фича `h3`; quinn + h3 проверены на
  кросс-компиляцию под NDK), логирование в logcat (paranoid-android),
  персистентный UI со списком серверов, переподключение при смене сети
  (`setUnderlyingNetworks`). Rust проверен; Kotlin написан, но на устройстве ещё
  не собирался.
- **Инкремент 4 (готово):** per-app split tunneling (`addAllowedApplication` /
  `addDisallowedApplication`) с UI-выбором приложений — режимы OFF / ALLOWLIST /
  DENYLIST, хранятся в SharedPreferences, применяются в `OutlineVpnService`.
  Kotlin написан, на устройстве ещё не собирался.
- **Инкремент 5 (готово):** внешнее управление по схеме `outline://`
  (connect / disconnect / toggle, опциональный выбор профиля) под
  переключателем и опциональным токеном; парсер и гейт покрыты JVM-тестами.

## Что проверено, а что нет

- **Проверено сборкой:** Rust-ядро (cdylib `outline-android`) кросс-компилируется
  в загружаемую `aarch64` Android-`.so`, включая нативный TUN-движок,
  uplink-стек и носители QUIC/h3 — SOCKS5-вход и tun2proxy из сборки
  исключены (см. «Архитектура»).
- **Проверено сборкой (Kotlin):** `:app:assembleDebug` собирает debug-APK, а
  `:app:testDebugUnitTest` проходит — тесты покрывают парсер `outline://`, гейт
  доступа и резолвинг профиля на JVM.
- **Проверено на эмуляторе** (Pixel_10, API 37, arm64), debug-сборка, ещё на
  исходном мосте tun2proxy (сейчас заменён — см. «Архитектура»): служба
  поднимала TUN, Rust-ядро стартовало (SOCKS5 слушал 127.0.0.1:1080, реестр
  аплинков инициализирован), tun2proxy в него соединялся, отрабатывали
  `outline://connect` / `disconnect`, а слежение за несущей сетью проходило
  хендовер Wi-Fi ⇄ сотовая в обе стороны — в `dumpsys connectivity` у
  VPN-агента `underlying{[N]}` переключался между сотовой и Wi-Fi и никогда не
  привязывал саму VPN-сеть. Нативный TUN-движок, заменивший tun2proxy, такого
  прогона ещё не проходил (см. «Не проверено» ниже).
- **Проверено на эмуляторе**, release-сборка: с включённой минификацией R8
  `.so` грузится и `start()` доходит до Rust — keep-правил достаточно. Сверено
  запуском подписанного release-APK: неверное keep-правило падает только в
  рантайме.
- **Не проверено:** на реальном железе ничего не запускалось, сквозного трафика
  через живой сервер не было — эмулятор ходил в мёртвый endpoint. Per-app split
  tunneling ещё ждёт реального прогона. Сам нативный TUN-движок ещё не
  прогонялся ни на эмуляторе, ни на устройстве — подтверждены только
  кросс-компиляция и сборка debug-APK (см. «Дорожная карта», инкремент 2), но
  туннель ещё никто не поднимал и не смотрел, как через него идут пакеты.

## Заметки по портированию

Rust-ядру нужны несколько адаптаций под `cfg(android)` по мере роста фич:
- `SO_MARK` в `outline-net` привилегирован на Android — использовать
  `VpnService.protect()`.
- Логика IPv6-source `freebind` / `/proc/net/if_inet6` неприменима — отключать
  фича-флагом.
- `outline-tun` теперь работает и на Android: `/dev/net/tun` + `TUNSETIFF`
  (нужен root) остаётся десктопным путём, а второй подключает движок к уже
  открытому дескриптору (`RunOptions.tun_fd`) — тому, что отдаёт `VpnService`,
  без root.
