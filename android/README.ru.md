<picture>
    <source media="(prefers-color-scheme: dark)" srcset="../docs/logo-dark.png">
    <img src="../docs/logo-light.png" alt="outline-proxy logo" width="100%">
</picture>

# Outline Proxy — клиент для Android

English version: [README.md](README.md).

VPN-клиент для Android поверх uplink-стека `outline-ws-rust` (padding, VLESS,
SS, WS, TLS, failover). Rust-ядро переиспользуется без изменений; Android
добавляет интерфейс на Material Design 3 (Jetpack Compose) и слой `VpnService`.

> Статус: инкременты 1–6 сделаны (см. «История разработки»): мост Rust⇄Kotlin,
> нативный движок `outline-tun`, подключённый к дескриптору `VpnService`,
> носители QUIC/HTTP-3, сохраняемый список серверов, переключение
> Wi-Fi⇄мобильная сеть, per-app split tunneling, внешнее управление
> `outline://`, подписка на конфиг по URL, динамические цвета Material You на
> Android 12+, тематическая монохромная иконка на Android 13+, подписанные
> release-сборки, удержание туннеля при убийстве процесса / ребуте / OEM-чистке,
> foreground-уведомление с именем профиля и навигация системной кнопкой «назад».
> Rust-стек (включая quinn + h3) кросс-компилируется под NDK r29; Gradle собирает
> debug-APK и минифицированный release-APK, JVM-юнит-тесты проходят. Что
> запускалось, а что нет, — в разделе «Что проверено».
> [проверить: раздел «Что проверено» старше кода — `DialTimeout.kt` описывает
> устройство HONOR, через туннель которого шёл LTE-трафик]

## Структура

```
android/
  build-rust.sh    # собирает .so и UniFFI-биндинги Kotlin
  rust/            # outline-android: cdylib + UniFFI-обёртка над ws-rust
    src/lib.rs       # start() / stop() / is_running()
    src/bin/         # uniffi-bindgen
  app/             # Android-приложение (Gradle, Kotlin, Compose)
    src/main/java/com/outline/proxy/
      OutlineVpnService.kt   # VpnService: establish() TUN, управляет ядром
      MainActivity.kt / HomeScreen.kt          # экраны, connect/disconnect
      ServerProfile.kt / ProfileStore.kt       # модель профиля + хранение
      SplitTunnel.kt         # per-app режимы allow/deny
      ConfigFetcher.kt / SubscriptionWorker.kt / SubscriptionRefresh.kt  # конфиг по URL
      ExternalControl.kt / ControlActivity.kt  # грамматика outline:// + точка входа
      DialTimeout.kt         # бюджет дозвона носителя под канал
      TcpOnlyConfig.kt       # переписывание конфига для «Только TCP»
      LinkProbe.kt / LinkInfo.kt / LinkQuality.kt  # сведения о канале на главном экране
      KeepAlivePolicy.kt / KeepAliveState.kt / KeepAliveScreen.kt
      AutomationPolicy.kt / AutomationStore.kt / AutomationState.kt / WifiAutomationScreen.kt
      OutlineTileService.kt / QuickConnectActivity.kt  # плитка быстрых настроек, ярлык
      UpdateChecker.kt / ReleaseNotes.kt       # проверка обновлений в приложении
      keepalive/             # BootReceiver, WatchdogAlarm/Worker/Receiver, профили вендоров
    src/test/java/com/outline/proxy/           # JVM-юнит-тесты
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

Rust-ядро подключает нативный движок `outline-tun` напрямую к TUN-дескриптору
`VpnService` через `RunOptions.tun_fd` и передаёт TCP/UDP-потоки прямо в
uplink-стек — без моста tun2proxy и без захода в SOCKS5 через loopback. Защита
от петли: Kotlin-сторона исключает пакет самого приложения из VPN
(`addDisallowedApplication(self)`), поэтому каждый сокет, который открывают
аплинки, идёт мимо TUN без посокетного `VpnService.protect()`.

Аплинк-сокеты идут по той сети, к которой туннель привязан через
`setUnderlyingNetworks`. `OutlineVpnService` следит за лучшей не-VPN сетью с
`INTERNET` и перепривязывается при переключении Wi-Fi ⇄ сотовая:

- API 31+: `registerBestMatchingNetworkCallback`, который отдаёт одну лучшую
  подходящую сеть.
- Ниже API 31: приложение само выбирает из всех подходящих сетей — сначала
  validated, затем Ethernet > Wi-Fi > сотовая (`LinkProbe.bestNonVpn`).

Здесь важны два фильтра. `NET_CAPABILITY_NOT_VPN`: default-колбэк отдаёт нам
нашу же VPN-сеть, и туннель стал бы нижележащей сетью самому себе. И учёт того,
какая сеть используется сейчас: поднявшаяся рядом сеть не перехватывает
привязку, а потеря сети, которой мы не пользуемся, игнорируется. Слежение за
сетями требует `ACCESS_NETWORK_STATE`; без него колбэк падает с
`SecurityException`, и теряется только отслеживание переключений, а не туннель.

Rust-ядро собирается с `default-features = false` плюс `h3` и `tun`
(`android/rust/Cargo.toml`): нативный TUN-движок, WS/TLS uplink-стек и носители
QUIC/HTTP-3. Не входят вход `socks5`, `metrics`, `control`, `env-filter`,
`multi-thread` и аллокатор `jemalloc`. Помимо выключенной фичи `socks5`,
`outline-ws-rust` ещё и в рантайме не запускает SOCKS5-слушатель, если передан
`tun_fd`, независимо от TOML.

## Требования

Rust-часть:

```sh
rustup target add aarch64-linux-android      # + armv7/x86_64 для других ABI
cargo install cargo-ndk
brew install --cask android-ndk              # NDK r29 -> /opt/homebrew/share/android-ndk
export ANDROID_NDK_HOME=/opt/homebrew/share/android-ndk
```

Приложение:

- JDK 17. Под openjdk 25 Gradle падает, а свежие версии Android Studio несут
  JBR 25 (`/Applications/Android Studio.app/Contents/jbr/Contents/Home`), поэтому
  не указывайте встроенный JBR в `JAVA_HOME`. CI использует Temurin 17
  (`.github/workflows/_android-release-build.yml`); сама сборка нацелена на
  Java 17 (`compileOptions` в `app/build.gradle.kts`).
- Android SDK с платформой 37 (`compileSdk = 37`). Android Studio ставит её
  сама; для сборки только из CLI пропишите `sdk.dir` в `local.properties`.
- Gradle ставить не нужно: wrapper закоммичен (`gradlew`, `gradle/wrapper/`,
  Gradle 9.7.0).

## Сборка Rust-артефактов

`build-rust.sh` пересобирает и нативную библиотеку
(`app/src/main/jniLibs/<abi>/liboutline_android.so`), и UniFFI-биндинги Kotlin
(`app/src/main/java/uniffi/`):

```sh
export ANDROID_NDK_HOME=/opt/homebrew/share/android-ndk
./build-rust.sh                      # arm64-v8a, debug
./build-rust.sh arm64-v8a --release
```

Оба артефакта в gitignore. Перезапускайте скрипт после любых правок в
`android/rust/` или в крейтах монорепо, которые он подтягивает.

Замечания:

- Приложение поставляет только `arm64-v8a` (`abiFilters` в
  `app/build.gradle.kts`).
- `h3` тянет quinn и пропатченные форки из `vendor/`. `android/rust` — отдельный
  (detached) workspace, поэтому его `Cargo.toml` повторяет корневые записи
  `[patch.crates-io]` для `h3`, `hyper`, `quinn-proto` и `rustls`; без патча `h3`
  vendored-носитель HTTP/3 `sockudo-ws` не компилируется против апстримного `h3`.
- Биндинги генерируются из библиотеки под хост (`.dylib` на macOS, `.so` на
  Linux): кросс-скомпилированную Android-`.so` на хосте сборки загрузить нельзя.
  Скрипт для этого собирает библиотеку под хост.
- cargo-ndk 4.x: уровень API задаётся `--platform N` (скрипт передаёт 24), а не
  `-p N` — это cargo `--package`; аргументы cargo идут после `--`.
- uniffi 0.31+ сам распознаёт библиотеку как источник, поэтому bindgen получает
  путь к библиотеке позиционным аргументом; старый флаг `--library <path>` ничего
  не делает.

## Сборка и запуск приложения

1. Запустите `./build-rust.sh` (один раз и после правок Rust).
2. Откройте `android/` в Android Studio. При первой синхронизации она запишет
   `local.properties` (путь к SDK) и скачает Gradle 9.7.0. В **Settings →
   Build, Execution, Deployment → Build Tools → Gradle → Gradle JDK** выберите
   JDK 17.
3. Запустите на устройстве или эмуляторе, добавьте сервер, нажмите
   **Подключить**.

Из командной строки (JDK 17, Android SDK, `local.properties` с `sdk.dir`):

```sh
cd android
export JAVA_HOME=<jdk17_home>   # установленный JDK 17, не JBR 25 из Android Studio
./gradlew :app:assembleDebug        # debug-APK
./gradlew :app:testDebugUnitTest    # JVM-юнит-тесты
./gradlew :app:lintDebug            # паритет строк EN/RU (MissingTranslation, ExtraTranslation)
```

У debug-сборки application ID `com.outline.proxy.debug`, поэтому она ставится
рядом с release-сборкой, а не поверх неё.

### Подпись release-сборки

`:app:assembleRelease` подписывает APK, если креды доступны, и собирает
неподписанный APK, если их нет, — свежий клон собирается в любом случае. Креды
берутся сначала из `android/keystore.properties`, а при отсутствии файла — из
окружения (`OUTLINE_KEYSTORE_FILE`, `OUTLINE_KEYSTORE_PASSWORD`,
`OUTLINE_KEY_ALIAS`, `OUTLINE_KEY_PASSWORD`). Неполный набор валит сборку
(`Incomplete release-signing config; missing: …`): неподписанный APK не встаёт
поверх подписанного, и узнавать об этом на `adb install` хуже, чем упасть на
сборке.

Файл с паролями и любые `*.jks`/`*.keystore`/`*.p12` в дереве — в `.gitignore`;
сам keystore держите вне рабочего дерева
(`~/.android/outline-proxy-release.jks`). Создать новый:

```sh
keytool -genkeypair -v -keystore ~/.android/outline-proxy-release.jks \
  -storetype PKCS12 -alias outline-proxy -keyalg RSA -keysize 4096 \
  -validity 10950 -dname "CN=Outline Proxy, O=Outline Proxy, C=RU"
```

Затем пропишите путь и пароли в `keystore.properties` (`storeFile`,
`storePassword`, `keyAlias`, `keyPassword`). Включены только схемы подписи
v2/v3: `minSdk` = 24, а это релиз, в котором появилась v2, поэтому legacy-v1
(JAR) ничего не добавляет.

**Внимание:** сохраните бэкап keystore и пароля. Без них приложение можно будет
только переустановить с нуля (с потерей данных), обновить поверх — никогда.

Проверьте подпись собранного APK:

```sh
$ANDROID_HOME/build-tools/<ver>/apksigner verify --print-certs -v \
  app/build/outputs/apk/release/app-release.apk
```

`<ver>` — установленная версия build-tools.

### Gradle-тулчейн

AGP 9.4.0, Gradle 9.7.0, Compose compiler plugin 2.4.10 на штатных настройках
AGP 9: `gradle.properties` задаёт только `android.useAndroidX` и
`android.nonTransitiveRClass`, флагов совместимости нет. Два предупреждения
`Expression is unused` в выводе сборки — из сгенерированных UniFFI-биндингов.

- Kotlin компилирует сам AGP (built-in Kotlin). Плагина
  `org.jetbrains.kotlin.android` нет; применяется только Compose-плагин, который
  AGP находит по id и подключает к собственным задачам компиляции. Именно тот
  плагин был единственным потребителем legacy variant API
  (`testVariants`/`unitTestVariants`), удалённого в AGP 10.
- JVM-target задаётся в одном месте. Built-in Kotlin берёт `jvmTarget` из
  `compileOptions.targetCompatibility` и валит сборку, если они разошлись,
  поэтому один `compileOptions` фиксирует 17 для обоих компиляторов. Блок
  `kotlin { }` избыточен, а противоречащий ему — ошибка сборки.
- Минификация R8 включена и зависит от keep-правил. JNA и UniFFI-биндинги
  связаны рефлексией и именами символов (`Native.register`), поэтому R8 не видит,
  как они используются; `proguard-rules.pro` закрепляет эти имена и глушит
  десктопные AWT-ветки JNA (`-dontwarn java.awt.**`), классов для которых в
  android.jar нет. Правку правил проверяйте запуском release-сборки, а не только
  сборкой: неверное правило ломается в рантайме, а не при компиляции.

## Откуда брать конфиг

Узел генерирует конфиг клиента на каждого пользователя: `<user>.toml`, рядом с
`.conf` и `.json` (`ops/access-keys/generate_keys.py`; в отчёте ссылка на него
называется `ws_url`). Он несёт полную цепочку носителей на каждый входной узел,
failover между узлами и миграцию живых флоу. Структурированная форма профиля
этого выразить не может: одна `vless://` / `ss://`-ссылка описывает один
носитель одного узла. Вставьте файл целиком в поле **Ручной TOML**.

`[tun] mtu` в сгенерированном конфиге обязан совпадать с
`ServerProfile.TUN_MTU`: 1500 с обеих сторон (`TUN_MTU` в
`ops/access-keys/ws_toml.py`). Меняете одну величину — меняйте и вторую, иначе
VPN поднимется с MTU, о котором ядро прокси не знает.

Что попадёт в конфиг, зависит от узла: h3-режим носителей, набор путей,
padding, миграция носителей и мягкая смена узла включаются, только если на узле
есть соответствующие секции. Выключенные генератор перечисляет строками
`warning:`; подробности — в [`ops/access-keys/README.md`](../ops/access-keys/README.md).

Сгенерированный профиль несёт ещё и `[outline.probe]`: DNS-пробу и
TLS-рукопожатия через туннель, как в группе `main` самого парка. Без них у
клиента нет сигнала здоровья, независимого от трафика: помеченный мёртвым
аплинк оживает только от данных, прошедших по нему, поэтому потеря разом всех
аплинков (смена SIM, мёртвая сота) читалась как «no link» до ручного
переподключения. Интервал проб — 300 с (`PROBE_INTERVAL_SECS` в
`ops/access-keys/ws_toml.py`) против 10 с на парке: на телефоне каждый цикл проб
стоит батареи, а на соте edge-класса — полосы, которой не хватает туннелю.

### Подписка по URL

Вместо вставки конфига профиль может указывать на HTTPS-URL, который его отдаёт
(поле **URL конфигурации (подписка)** в редакторе), — тот же `<user>.toml`,
что генерирует узел. Если URL задан, поля транспорта скрываются: URL —
единственный источник конфига.

- Тело — цельный клиентский конфиг, а не xray-список серверов; один URL — один
  профиль со всеми аплинками внутри.
- Только HTTPS: конфиг несёт UUID и пароли. Путь URL — секретный токен, поэтому
  целиком он не логируется, только маскированно (`host/…хвост`).
- Скачанный конфиг кэшируется в профиле. `SubscriptionWorker` (WorkManager, раз
  в 12 ч) его обновляет; неудачное скачивание оставляет последний рабочий кэш и
  не трогает активный туннель. В списке серверов видно «обновлено N ч назад» и
  кнопка обновления для немедленного скачивания.
- Ответ заменяет кэш, только если в нём есть `[tun]` или `[[outline.uplinks]]`,
  поэтому HTML-страница ошибки или капча не заменят рабочий конфиг.
- Запрос идёт напрямую, потому что приложение исключено из собственного VPN.
  Если источник доступен только через туннель, фоновое обновление не пройдёт и
  в работе останется закэшированный конфиг.

### Бюджет дозвона на медленных каналах

В сгенерированном конфиге секции `[dial]` нет, поэтому ядро ограничивает каждый
свежий дозвон носителя своим значением по умолчанию — 10 с
(`DEFAULT_DIAL_TIMEOUT` в `crates/outline-transport/src/dial_timeouts.rs`). На
соте edge-класса этот бюджет и есть причина отказа: round trip на 2G доходит до
секунды, одна цепочка сертификатов передаётся несколько секунд, бюджет истекает
посреди рукопожатия, каждая попытка засчитывается отказом, а повторы съедают ту
полосу, которой рукопожатию не хватило. Туннель числится поднятым и не несёт
ничего.

Поэтому приложение задаёт бюджет само (`DialTimeout.secondsFor`):

| Вход | Условие | Бюджет |
|---|---|---|
| RTT пути, измеренный ядром (любой транспорт) | ≥ 3000 мс | 60 с |
| | ≥ 1000 мс | 30 с |
| | меньше 1000 мс | по умолчанию ядра (10 с) |
| RTT ещё нет; оценка полосы от платформы (только сотовая) | ≤ 200 кбит/с | 60 с |
| | ≤ 2000 кбит/с | 30 с |
| | быстрее | по умолчанию ядра |

- Измеренный RTT всегда важнее оценки: некоторые прошивки оценку выдумывают
  (одно устройство HONOR сообщало 14 кбит/с на LTE-соте с полным сигналом,
  которая нормально несла трафик). Оценка нужна на холодном старте, пока нет
  носителя, на котором можно измерить RTT.
- Wi-Fi и Ethernet по оценке не расширяются никогда: медленный Wi-Fi обычно
  означает медленный backhaul, где рукопожатие всё равно укладывается в пару
  round trip'ов, а расширение границы только задержит failover. Измеренный RTT
  расширяет бюджет на любом транспорте.
- Оценка 0 или её отсутствие (платформа ещё не охарактеризовала канал)
  игнорируется, а не принимается за 2G.
- Конфиг, в котором `[dial]` объявлен явно, не изменяется.

Бюджет следует за каналом. Сервис пересчитывает его в сетевых колбэках
(`onAvailable`, `onCapabilitiesChanged`, `onLost`); через
`onCapabilitiesChanged` приходят переход между сотами, смена поколения
(2G ↔ 3G ↔ LTE ↔ 5G) и на многих устройствах переключение SIM для данных: объект
`Network` остаётся прежним, а его свойства меняются. Переход с Wi-Fi на 2G-соту
расширяет границу, обратный переход возвращает значение по умолчанию. Движок
подхватывает новое значение на следующем дозвоне (`setDialTimeoutSecs`);
начатые рукопожатия доживают со своим прежним дедлайном. Ничего не разрывается,
а неизменившееся значение повторно не применяется.

### Режим «Только TCP» (без HTTP/3)

В сетях, где UDP 443 или QUIC заблокирован или троттлится, аплинки с
`xhttp_h3` или `ws_h3` ждут тайм-аута рукопожатия H3, прежде чем откатиться на
H2, а последующие попытки вернуться на H3 снова подвисают.

Переключатель **Только TCP** на экране **Поддержание связи** (для всех
профилей) и в редакторе сервера (для одного профиля) переписывает конфиг перед
запуском (`TcpOnlyConfig`): `xhttp_h3` → `xhttp_h2`, `ws_h3` → `ws_h2` в
`vless_mode`/`ss_mode`/`tcp_mode`/`udp_mode` и `h3` → `h2` в `alpn=`
share-ссылок. Это касается структурированных профилей, share-ссылок, подписок и
ручного TOML. UDP внутри туннеля (DNS, звонки) идёт поверх соединения HTTP/2.
Изменение применяется при следующем подключении.

### Что главный экран говорит о канале

Под статусом туннеля карточка показывает сеть, по которой идёт туннель:
`Wi-Fi · 20 ms` или `LTE · 4.2 s`. Неизвестная часть не показывается:

- Тип канала. Wi-Fi и Ethernet называют себя сами. Сотовый канал показывает
  радиотехнологию (2G / 3G / LTE / 5G), если приложению разрешено её читать
  (`dataNetworkType`), и `Cellular` в противном случае. Это радиосеть, которая
  реально несёт данные, и она часто расходится с иконкой в строке состояния:
  иконка обычно отражает покрытие 5G или NSA-якорь с поддержкой 5G, так что «5G»
  в строке состояния и `LTE` здесь — ожидаемая картина.
- RTT пути, который носитель измеряет постоянно (`tcpi_rtt` ядра, `PathStats`
  у quinn), а не время дозвона. Время дозвона включает рукопожатия, а после
  отката `h3 → h2` — ещё и неудачную попытку, поэтому на здоровых каналах оно
  давало значения вроде «10.0 s» при бюджете 10 с. Начиная с 700 мс статус
  помечается как медленный (`LinkQuality.SLOW_LATENCY_MS`).

Оценка полосы от платформы не показывается: прошивки её выдумывают (см. пример
HONOR выше). Она по-прежнему читается, чтобы выбрать бюджет дозвона, пока ничего
не измерено.

Для названия радиотехнологии нужен `READ_PHONE_STATE`. Само приложение его не
запрашивает: это необязательный пункт в чеклисте **Поддержание связи**, потому
что ни одно решение туннеля от него не зависит. Отказ убирает подпись и больше
ничего.

## Внешнее управление (`outline://`)

Приложения автоматизации (Tasker, ярлыки лаунчера, `adb`) управляют туннелем
через URI-схему:

```
outline://connect                     # поднять профиль, выбранный в UI
outline://connect?profile=<имя|id>    # поднять конкретный сохранённый профиль
outline://disconnect
outline://toggle[?profile=<имя|id>]   # опустить, если поднят, иначе поднять
```

Схема, команда и ключи query нечувствительны к регистру; значения
percent-декодируются (`?profile=Home%20VPN`). Команда никогда не создаёт
сервер: профиль должен уже быть в списке; сопоставление сначала по id, затем по
имени (без учёта регистра). При успехе ничего не показывается, состояние видно
по уведомлению foreground-сервиса. Отказ показывает Toast и пишет
предупреждение с тегом `OutlineControl` в logcat.

```sh
adb shell am start -a android.intent.action.VIEW -d 'outline://connect'
adb shell am start -a android.intent.action.VIEW -d 'outline://toggle?profile=Home&token=s3cret'
```

Доступ настраивается на экране **Внешнее управление**: переключатель (по
умолчанию включён) и необязательный токен. Если токен задан, команды без
совпадающего `?token=` игнорируются; сравнение идёт за постоянное время
(`MessageDigest.isEqual`). Вызвать такой URI может любое установленное
приложение и любая веб-страница (intent-фильтр несёт `BROWSABLE`), поэтому
задайте токен, если неожиданный `disconnect` для вас важен.

`ControlActivity` — прозрачная Activity, которая выполняет команду и
завершается. Ни receiver, ни exported-сервис не подходят: системному диалогу
согласия на VPN нужна Activity, а Android 12+ запрещает запускать
foreground-сервис из фона. Вызывающему приложению нужно право запускать
Activity: у фонового приложения без него (например, Tasker без разрешения
«Поверх других приложений») платформа молча отбрасывает URI.

## Удержание туннеля

Каждый путь, которому может понадобиться поднять туннель заново, — always-on
VPN, загрузка, будильник-watchdog, задача WorkManager, `onDestroy` — проходит
через `OutlineVpnService.ensure()`. Он читает намерение пользователя
(`KeepAliveState.shouldRun`, ставится при подключении, снимается при явном
отключении) и состояние ядра (`isRunning()`), а `KeepAlivePolicy.decide(...)`,
чистая функция с юнит-тестами, возвращает одно из: ничего не делать,
остановиться, сдаться (и уведомить), подключиться. Неудачное подключение
повторяется раз в 5 мин для первых трёх отказов, раз в 15 мин для четвёртого и
пятого, дальше раз в 30 мин (`KeepAlivePolicy.backoffFor`). Пока туннель
работает, точный будильник отменён и не будит устройство из Doze.

Туннель возвращается четырьмя путями:

- Always-on VPN: система сама запускает и перезапускает сервис, поэтому
  `onStartCommand(null)` ведёт в `ensure()`. Включается пользователем в
  системных настройках.
- Загрузка / обновление приложения: `BootReceiver` (`BOOT_COMPLETED`,
  `MY_PACKAGE_REPLACED`), после разблокировки. Намеренно не direct-boot aware:
  профили содержат креды и лежат в credential-protected storage.
- Пара watchdog'ов: точный будильник (`WatchdogAlarm`; срабатывает сквозь Doze
  во время бэкоффа переподключения, отменяется, пока туннель работает) и
  15-минутная задача WorkManager (`WatchdogWorker`; её расписание переживает
  ребут); каждый вызывает `ensure()`. Будильник точный, только если выдано
  `SCHEDULE_EXACT_ALARM`; иначе система группирует его по своему усмотрению.
  `USE_EXACT_ALARM`, которое дало бы это право без запроса, намеренно не
  объявлено; причина — в комментарии в `AndroidManifest.xml`.
- Свайп / убийство процесса: `stopWithTask="false"` плюс
  `onTaskRemoved`/`onDestroy` ставят проверку сразу после ухода процесса.

Экран **Поддержание связи** — чеклист того, что может выдать только
пользователь: always-on VPN, исключение из оптимизации батареи, точные
будильники, уведомления и вендорский экран автозапуска (проверяется на
устройстве через `resolveActivity`; на HONOR открывает
`com.hihonor.systemmanager`). Каждый пункт показывает статус и кнопку перехода в
системный экран. Эти разрешения заодно делают легальным запуск
foreground-сервиса из фона на Android 12+.

`specialUse` не входит в список типов foreground-сервисов, которым Android 15
запрещает старт из `BOOT_COMPLETED`, поэтому путь через загрузку открыт.
Проверить ограничение без смены `targetSdk`:

```sh
adb shell am compat enable FGS_BOOT_COMPLETED_RESTRICTIONS com.outline.proxy
adb shell am broadcast -a android.intent.action.BOOT_COMPLETED com.outline.proxy
```

Проверено: юнит-тесты таблицы решений; на устройстве — экран чеклиста и его
переходы в системные экраны (HONOR / MagicOS). Фоновые пути возврата
(force-stop → возврат, ребут) реализованы, но end-to-end на железе не прогнаны.
Таблица вендорских экранов для MIUI/EMUI/ColorOS/One UI не проверена.

## История разработки

- Инкремент 1: мост Rust⇄Kotlin, запуск SOCKS5 + аплинков, каркас
  `VpnService` + Compose.
- Инкремент 2: мост tun2proxy (TUN fd → SOCKS5) с защитой от петли через
  `addDisallowedApplication(self)`. Позже заменён нативным движком
  `outline-tun`, подключённым к дескриптору `VpnService` через
  `RunOptions.tun_fd` (см. «Архитектура»); SOCKS5-вход на Android исключён из
  сборки (фича `socks5` выключена, плюс проверка `tun_fd` в рантайме).
- Инкремент 3: QUIC/h3 (фича `h3`), логирование в logcat (`paranoid-android`),
  сохраняемый список серверов, перепривязка при смене сети
  (`setUnderlyingNetworks`).
- Инкремент 4: per-app split tunneling (`addAllowedApplication` /
  `addDisallowedApplication`) с выбором приложений. Режимы OFF / ALLOWLIST /
  DENYLIST; списки allow и deny хранятся раздельно в SharedPreferences, а
  применяется только список активного режима (Android запрещает смешивать
  их в одном `VpnService.Builder`).
- Инкремент 5: внешнее управление по схеме `outline://` (connect / disconnect /
  toggle, необязательный выбор профиля) под переключателем и необязательным
  токеном; парсер и проверка доступа покрыты JVM-тестами.
- Инкремент 6: подписка на конфиг по URL (`ConfigFetcher` /
  `SubscriptionWorker`), удержание туннеля (`KeepAlivePolicy` + пара
  watchdog'ов в `keepalive/`), системная светлая/тёмная тема, иконка лаунчера,
  подписанные release-сборки, единая кнопка connect/disconnect,
  foreground-уведомление с именем профиля.

## Что проверено

[проверить: список старше кода — `DialTimeout.kt` описывает устройство HONOR,
через туннель которого шёл LTE-трафик]

- Сборка: Rust-ядро (cdylib `outline-android`) кросс-компилируется в
  загружаемую `aarch64` Android-`.so`, включая нативный TUN-движок, uplink-стек
  и носители QUIC/h3; SOCKS5-входа и tun2proxy в ней нет.
- Сборка (Kotlin): `:app:assembleDebug` собирает debug-APK, `:app:testDebugUnitTest`
  проходит.
- Эмулятор (Pixel_10, API 37, arm64), debug-сборка, ещё на мосте tun2proxy:
  служба поднимала TUN, Rust-ядро стартовало (SOCKS5 на 127.0.0.1:1080, реестр
  аплинков инициализирован), tun2proxy к нему подключался,
  `outline://connect` / `disconnect` работали, а слежение за нижележащей сетью
  отрабатывало переключение Wi-Fi ⇄ сотовая в обе стороны: в
  `dumpsys connectivity` у VPN-агента `underlying{[N]}` переключался между
  сотовой и Wi-Fi и ни разу не указывал на саму VPN-сеть.
- Эмулятор, release-сборка: с включённой минификацией R8 `.so` грузится и
  `start()` доходит до Rust, то есть keep-правил достаточно. Проверено запуском
  подписанного release-APK.
- Не проверено: на реальном железе запускались только экран чеклиста
  keep-alive и его вендорские intent'ы (HONOR / MagicOS); сквозного трафика
  через живой сервер не было (эмулятор ходил в мёртвый endpoint). Per-app split
  tunneling на устройстве не запускался. Нативный TUN-движок не запускался ни на
  эмуляторе, ни на устройстве.

## Заметки по портированию

Rust-ядру нужны несколько адаптаций под `cfg(android)` по мере добавления фич:

- `SO_MARK` в `outline-net` на Android привилегирован; используйте
  `VpnService.protect()`.
- Логика IPv6-источника `freebind` / `/proc/net/if_inet6` неприменима;
  отключайте её.
- У `outline-tun` два пути к устройству: `/dev/net/tun` + `TUNSETIFF` (нужен
  root) на десктопе и подключение к уже открытому дескриптору
  (`RunOptions.tun_fd`), который отдаёт `VpnService`, без root.
