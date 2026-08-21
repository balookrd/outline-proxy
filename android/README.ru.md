# Outline Proxy — клиент для Android

Android-клиент VPN, подключающийся к вашим серверам через полный uplink-стек
`outline-ws-rust` (padding + VLESS / SS / WS / TLS, failover). Rust-ядро
переиспользуется без изменений; Android добавляет лишь тонкий слой
`VpnService` + UI.

> Статус: **клиент функционально готов, ещё не прогнан против живого сервера**.
> Инкременты 1–5 сделаны — мост Rust⇄Kotlin, нативный движок `outline-tun`,
> подключённый к дескриптору `VpnService`, носители QUIC/HTTP-3, персистентный
> UI со списком серверов, переключение Wi-Fi⇄мобильная сеть, per-app split
> tunneling и внешнее управление `outline://` — плюс более поздняя работа:
> подписка на конфиг по URL, следование системной светлой/тёмной теме, иконка
> лаунчера, подписанные release-сборки, единая кнопка connect/disconnect,
> удержание туннеля при убийстве / ребуте / OEM-чистке, foreground-уведомление
> с именем профиля и навигация системной кнопкой «назад». Весь Rust-стек
> (включая quinn + h3) кросс-компилируется под NDK r29, а Gradle/Kotlin-
> приложение собирается (debug-APK, минифицированный release-APK, зелёные
> JVM-юнит-тесты). Приложение запускалось на **эмуляторе** (на прежнем мосте
> tun2proxy, ныне заменённом нативным движком); на **реальном железе** прогнан
> только экран чеклиста keep-alive и его вендорские intent'ы. Трафик через
> живой сервер ещё не шёл, нативный TUN-движок в рантайме не поднимался — см.
> «Что проверено, а что нет».

## Структура

```
android/
  rust/            # outline-android: cdylib + UniFFI-обёртка над ws-rust
    src/lib.rs       # start() / stop() / is_running()
  app/             # Android-приложение (Gradle, Kotlin, Compose)
    src/main/java/com/outline/proxy/
      OutlineVpnService.kt   # VpnService: establish() TUN, управляет ядром
      MainActivity.kt        # редактор конфига + connect/disconnect, экраны
      ServerProfile.kt / ProfileStore.kt        # модель профиля + персистентность
      SplitTunnel.kt         # per-app режимы allow/deny
      ConfigFetcher.kt / SubscriptionWorker.kt  # подписка на конфиг по URL
      ExternalControl.kt / ControlActivity.kt   # грамматика outline:// + точка входа
      AppTheme.kt            # системная светлая/тёмная тема
      KeepAlivePolicy.kt / KeepAliveState.kt / KeepAliveScreen.kt
      keepalive/             # BootReceiver, WatchdogAlarm/Worker/Receiver, helper
    src/test/java/com/outline/proxy/
      ExternalControlTest.kt, KeepAlivePolicyTest.kt,   # JVM-юнит-тесты
      SubscriptionProfileTest.kt, ConfigValidationTest.kt
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
   к SDK) и при первой синхронизации скачает дистрибутив Gradle 9.7.0.
   `compileSdk = 37` докачивается автоматически, если платформы нет.
3. Запустите на устройстве/эмуляторе, добавьте сервер, нажмите Connect.

Альтернатива через CLI (нужны JDK 17+ и Android SDK, `local.properties` с
`sdk.dir`): `./gradlew :app:assembleDebug`, а `./gradlew :app:testDebugUnitTest` —
JVM-юнит-тесты. Если системной JDK нет, подойдёт встроенная в Android Studio:
`export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"`.

### Подпись release-сборки

`:app:assembleRelease` подписывает APK, если креды доступны, и молча отдаёт
неподписанный APK, если их нет, — свежий клон собирается в любом случае. Креды
берутся сначала из `android/keystore.properties`, а при отсутствии файла — из
окружения (`OUTLINE_KEYSTORE_FILE`, `OUTLINE_KEYSTORE_PASSWORD`,
`OUTLINE_KEY_ALIAS`, `OUTLINE_KEY_PASSWORD`). *Неполный* набор — жёсткая ошибка,
а не тихий откат к неподписанной сборке: неподписанный APK не встаёт поверх
подписанного, и узнавать об этом на `adb install` хуже, чем упасть на сборке.

Файл с паролями и любые `*.jks`/`*.keystore`/`*.p12` в дереве — в `.gitignore`;
сам keystore держите вне рабочего дерева
(`~/.android/outline-proxy-release.jks`). Создать новый:

```sh
keytool -genkeypair -v -keystore ~/.android/outline-proxy-release.jks \
  -storetype PKCS12 -alias outline-proxy -keyalg RSA -keysize 4096 \
  -validity 10950 -dname "CN=Outline Proxy, O=Outline Proxy, C=RU"
```

Дальше пропишите путь и пароли в `keystore.properties` (`storeFile`,
`storePassword`, `keyAlias`, `keyPassword`). Включены только схемы подписи
v2/v3: `minSdk` = 24, а это как раз релиз, в котором появилась v2, — legacy-v1
(JAR) не даёт ничего. **Сохраните бэкап keystore и пароля**: без них приложение
можно будет только переустановить с нуля, обновить поверх — уже никогда.

Проверить то, что собралось:

```sh
$ANDROID_HOME/build-tools/<ver>/apksigner verify --print-certs -v \
  app/build/outputs/apk/release/app-release.apk
```

### Gradle-тулчейн

AGP 9.3.1 / Gradle 9.7.0 / Kotlin 2.4.10 на штатных дефолтах AGP 9 — в
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

## Откуда брать конфиг

Узел сам генерирует готовый конфиг клиента на юзера — `<user>.toml`, рядом с
`.conf` и `.json` (`ops/access-keys/generate_keys.py`; в отчёте ссылка на него
называется `ws_url`). Он несёт полную цепочку носителей на каждый входной узел,
failover между узлами и миграцию живых флоу — то, чего структурированная форма
профиля выразить не может: одна `vless://` / `ss://`-ссылка описывает один
носитель одного узла. Поэтому содержимое вставляется целиком в поле **Raw TOML
override**.

`[tun] mtu` в сгенерированном конфиге обязан совпадать с
`ServerProfile.TUN_MTU` — сейчас 1500 с обеих сторон. Меняете одну величину —
меняйте и вторую, иначе VPN поднимется с MTU, о котором ядро прокси не знает.

Что именно попадёт в конфиг, зависит от узла: h3-режим носителей, набор путей,
padding, миграция носителей и мягкая смена узла включаются только если узел
несёт соответствующие секции. Генератор о выключенных докладывает строками
`warning:` — подробности в [`ops/access-keys/README.md`](../ops/access-keys/README.md).

### Подписка по URL

Вместо вставки конфига профиль может указывать на HTTPS-URL, который его отдаёт
(поле **Config URL** в редакторе) — тот же `<user>.toml`, что генерит узел,
скачивается и держится свежим, как Happ ведёт подписку. Если URL задан, поля
транспорта скрываются: URL — единственный источник конфига.

- Тело — цельный клиентский конфиг (не xray-список серверов); один URL = один
  профиль со всеми uplink'ами внутри.
- **Только HTTPS** — конфиг несёт UUID и пароли. Путь URL — секретный токен,
  поэтому целиком не логируется, только маскированно (`host/…хвост`).
- Скачанный конфиг кэшируется в профиле. Фоновый воркер (`SubscriptionWorker`,
  WorkManager, раз в 12 ч) его обновляет; неудачное скачивание оставляет
  последний рабочий кэш и не трогает активный туннель. В списке видно «updated
  N h ago» и кнопка **Refresh** для немедленного обновления.
- Ответ заменяет кэш, только если похож на конфиг (есть `[tun]` или
  `[[outline.uplinks]]`), — HTML-страница ошибки или капча не затрут рабочую
  подписку.
- Запрос идёт напрямую (приложение исключено из собственного VPN). Если источник
  доступен только *через* туннель, фоновое обновление не пройдёт, а кэш
  продолжит работать — известное ограничение.

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

## Защита туннеля от закрытия

Каждый путь, которому может понадобиться поднять туннель заново — always-on VPN,
загрузка, будильник-watchdog, задача WorkManager, `onDestroy`, — проходит через
единственный `OutlineVpnService.ensure()`. Он читает *намерение* пользователя
(`KeepAliveState.shouldRun`, ставится при подключении, снимается при явном
отключении) и живое состояние ядра (`isRunning()`), а
`KeepAlivePolicy.decide(...)` — чистая, покрытая тестами функция — возвращает
одно из: ничего не делать, остановиться, сдаться (и уведомить), подключиться.
Неудачное подключение отступает 5 → 15 → 30 мин; живой туннель перепроверяется
раз в 5 мин.

Четыре способа возврата:

- **Always-on VPN** — сильнейший, и причина, по которой `onStartCommand(null)`
  ведёт в `ensure()`: система сама запускает и перезапускает сервис. Включается
  пользователем в системных настройках.
- **Загрузка / обновление** — `BootReceiver` (BOOT_COMPLETED, MY_PACKAGE_REPLACED),
  после разблокировки. Сознательно не direct-boot: профили несут креды и остаются
  в credential-protected storage.
- **Пара watchdog'ов** — будильник (`WatchdogAlarm`, пробивает Doze,
  переармливает себя) и 15-минутная задача WorkManager (`WatchdogWorker`, её
  расписание переживает ребут); каждый зовёт `ensure()`. Будильник точен только
  с выданным `SCHEDULE_EXACT_ALARM`, иначе система батчит его по своему
  усмотрению; `USE_EXACT_ALARM`, которое дало бы это право без спроса, мы
  сознательно не объявляем — обоснование в комментарии манифеста.
- **Свайп / убийство** — `stopWithTask="false"` плюс `onTaskRemoved`/`onDestroy`
  ставят проверку сразу вслед уходящему процессу.

Экран **Keeping alive…** — чеклист того, что может дать только пользователь:
always-on VPN, исключение из оптимизации батареи, точные будильники,
уведомления и вендорский экран автозапуска (проверяется на устройстве через
`resolveActivity`; на этом HONOR открывает `com.hihonor.systemmanager`). Каждый
пункт показывает статус и кнопку в нужный системный экран. Эти разрешения заодно
делают легальным старт foreground-сервиса из фона на Android 12+.

`specialUse` **не** входит в список типов FGS, запрещённых к старту из
`BOOT_COMPLETED` на Android 15, — значит boot-путь открыт. Проверить ограничение
без смены `targetSdk`:

```sh
adb shell am compat enable FGS_BOOT_COMPLETED_RESTRICTIONS com.outline.proxy
adb shell am broadcast -a android.intent.action.BOOT_COMPLETED com.outline.proxy
```

Что проверено: unit-тесты таблицы решений; на устройстве — экран чеклиста и его
переходы в системные экраны (HONOR / MagicOS). Фоновые пути возврата (force-stop
→ возврат, ребут) реализованы, но end-to-end на железе ещё не прогнаны. Таблица
вендорских экранов для MIUI/EMUI/ColorOS/One UI перенесена без проверки.

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
- **Инкремент 6 (готово):** продуктизация — подписка на конфиг по URL
  (`ConfigFetcher` / `SubscriptionWorker`), инфраструктура удержания туннеля
  (`KeepAlivePolicy` + watchdog-пара в `keepalive/`), системная светлая/тёмная
  тема, иконка лаунчера, подписанные release-сборки, единая кнопка
  connect/disconnect и foreground-уведомление с именем профиля. См. разделы
  выше по каждой.

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
- **Не проверено:** на реальном железе прогнан только экран чеклиста keep-alive
  и его вендорские intent'ы (устройство HONOR / MagicOS) — data plane не
  прогонялся, сквозного трафика через живой сервер не было (эмулятор ходил в
  мёртвый endpoint). Per-app split tunneling ещё ждёт реального прогона. Сам
  нативный TUN-движок ещё не прогонялся ни на эмуляторе, ни на устройстве —
  подтверждены только кросс-компиляция и сборка debug-APK (см. «Дорожная карта»,
  инкремент 2), но туннель ещё никто не поднимал и не смотрел, как через него
  идут пакеты.

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
