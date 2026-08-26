# Локализация Android-клиента по системной локали (EN/RU) — дизайн

Дата: 2026-08-26
Статус: согласовано в чате

## Контекст

Android-приложение (`android/app`, чистый Jetpack Compose, `minSdk 24` /
`targetSdk 36`, без `androidx.appcompat`) полностью на английском: **все видимые
строки захардкожены** прямо в Kotlin/Compose-коде как строковые литералы.

- `res/values/` содержит только `ic_launcher_background.xml` — **нет
  `strings.xml`**.
- В `.kt`-исходниках: 0 обращений `stringResource`, 0 `R.string.…`, 0 кириллицы.
- Видимые строки живут на многих поверхностях:
  - Compose-экраны:
    [HomeScreen.kt](../../../android/app/src/main/java/com/outline/proxy/HomeScreen.kt)
    (`Disconnected`, `Connecting`, `No link`, `No server`, `Add a server to begin`,
    `Subscription`, `Active`, `Add Server`, `Connect`, `Disconnect`,
    `Split Tunneling`, `External Control`, `Keeping Alive`, `DURATION`, `TRAFFIC`,
    `PROTOCOL`, `just now`/`Nm ago`, contentDescription-строки),
    [MainActivity.kt](../../../android/app/src/main/java/com/outline/proxy/MainActivity.kt)
    (крупнейшая поверхность: диалоги добавления/редактирования/удаления сервера,
    подписки, меню, парсинг ссылок),
    [KeepAliveScreen.kt](../../../android/app/src/main/java/com/outline/proxy/KeepAliveScreen.kt),
    экраны Split Tunnel / External Control, `ControlActivity`, общие компоненты
    `UiKit`.
  - Не-Compose (есть `Context` → `getString`):
    [OutlineVpnService.kt](../../../android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt)
    — имена каналов (`VPN status`, `VPN alerts`), статусы, лейблы действий
    Connect/Disconnect, разовые `alert(...)`-уведомления;
    [OutlineTileService.kt](../../../android/app/src/main/java/com/outline/proxy/OutlineTileService.kt)
    — `Connected`/`Disconnected` (бренд `Outline` не трогаем);
    [UpdateChecker.kt](../../../android/app/src/main/java/com/outline/proxy/UpdateChecker.kt),
    ~10 `Toast` по коду, `QuickConnectActivity`, воркеры подписки/keepalive.

Статусы туннеля (`Connecting… / Connected / No link / Disconnected`) формируются
и на главном экране, и в нотификации
([OutlineVpnService.kt:825](../../../android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt)),
и в tile — из одних и тех же понятий.

Два presentation-объекта намеренно свободны от Android API ради юнит-тестов
(есть `LinkQualityTest`, `LinkInfoTest`):
[LinkQuality.kt](../../../android/app/src/main/java/com/outline/proxy/LinkQuality.kt)
(`connectedLabel` → `Connected` / `Connected · slow`) и
[LinkInfo.kt](../../../android/app/src/main/java/com/outline/proxy/LinkInfo.kt)
(`summary` → `Wi-Fi/Ethernet/Cellular/Network/2G/3G/LTE/5G · 180 ms`).

## Цель

Язык приложения **следует за настройками телефона**: системная локаль русская →
русский UI; любая другая локаль мира → английский. Достигается стандартной
Android-локализацией ресурсов, без рантайм-кода и без выбора языка внутри
приложения. Охват — **всё приложение** (все экраны, диалоги, нотификации,
Quick Settings tile, toasts, апдейтер), чтобы на русском телефоне не было смеси
EN/RU.

## Не-цели (YAGNI)

- **Ручной переключатель языка внутри приложения** и per-app язык
  (`LocaleManager` / `android:localeConfig`, Android 13+). Просили «по настройкам
  телефона» — это и делаем.
- **Языки кроме RU и EN.** `values/` (английский) остаётся fallback для всех
  прочих локалей.
- **Смена архитектуры/навигации, правка Rust-ядра** (`android/rust`, монорепо).
  Только вынос строк и точечный рефактор presentation-логики.

## Подход

Канонический Android resource i18n:

- `res/values/strings.xml` — английский, дефолт и fallback.
- `res/values-ru/strings.xml` — русский, **полный паритет ключей** (иначе lint
  `MissingTranslation`).
- Compose: литералы → `stringResource(R.string.key)` /
  `stringResource(R.string.key, arg)` / `pluralStringResource(...)`.
- Не-Compose (Service/Tile/Activity/Worker): `context.getString(R.string.key)` /
  `resources.getQuantityString(...)`. Все такие места уже имеют `Context`.

Отвергнутые альтернативы: Kotlin-объект строк с `when(Locale…)` (ломает
Compose-preview и accessibility, дублирует фреймворк); per-app язык (это ручной
выбор, а не «по телефону»).

## Раскладка и именование ключей

Ключи по доменам-префиксам: `home_*`, `status_*`, `server_*`, `keepalive_*`,
`split_*`, `control_*`, `notif_*`, `tile_*`, `update_*`, `a11y_*`
(contentDescription).

**Единый набор статусов** переиспользуется главным экраном, нотификацией и tile:
`status_connected`, `status_connected_slow`, `status_connecting`,
`status_no_link`, `status_disconnected`.

## Особые случаи

- **Format-аргументы:** позиционные плейсхолдеры, напр.
  `"Updated %1$s · Every %2$dh"` → «Обновлено %1$s · каждые %2$d ч».
- **Склонения:** компактные метки возраста — сокращёнными единицами без plurals:
  `just now`→«только что», `never`→«никогда», `5m/3h/2d ago`→«5 мин / 3 ч /
  2 дн назад» (единицы не склоняются, читается естественно, остаётся компактным).
  Полноценные счётные фразы, если найдутся (напр. «N серверов»), — через
  `<plurals>` с формами `one/few/many/other` для RU.
- **Числа/единицы — не переводим и не локализуем разделитель:** форматирование
  байт/латентности остаётся на `String.format(Locale.ROOT, …)`.
- **НЕ переводим вовсе:** протоколы/carrier из ядра
  (`ss/vless/ws/xhttp/h3/h2/tcp/udp`), RAN (`2G/3G/LTE/5G`), `Wi-Fi`/`Ethernet`,
  единицы (`B/KB/MB/GB`, `ms`, `s`, формат `hh:mm:ss`), бренд (`Outline`,
  `outline-proxy`), имена серверов (данные пользователя), версия/commit.

## Рефактор presentation-логики (сохранить юнит-тестируемость)

Чтобы не тащить `Context` в pure-объекты:

- **`LinkQuality`:** потребители (HomeScreen, OutlineVpnService) переходят на уже
  существующий `isSlow(latencyMs): Boolean` и сами выбирают ключ
  `status_connected` / `status_connected_slow`; строкогенерирующий
  `connectedLabel` убирается. `LinkQualityTest` — на `isSlow` (уже покрыт).
- **`LinkInfo`:** непереводимые токены (`Wi-Fi/Ethernet`, RAN, число+единица
  latency) остаются в pure-логике; переводимые головы `Cellular`/`Network` и
  склейка `" · "` уезжают в UI-слой (`stringResource`). `LinkInfoTest` тестирует
  непереводимые части и структуру, а не готовую фразу.

## Тестирование и верификация

- **Unit:** обновлённые `LinkQualityTest`/`LinkInfoTest` зелёные; прочие
  (`NotificationPolicyTest`, `SubscriptionProfileTest`, …) не затронуты.
- **Lint:** нет `MissingTranslation` — паритет ключей EN/RU
  (`./gradlew :app:lintDebug`).
- **Сборка/тесты:** `./gradlew :app:assembleDebug :app:testDebugUnitTest`.
- **Гейт `android/rust`** из корневого `AGENTS.md` прогнать (Rust не меняем):
  `(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)`.
- **Ручная проверка в эмуляторе** (JDK 17 liberica): системная локаль RU и EN →
  главный экран, под-экраны, нотификация, QS-tile переключают язык.

## Качество русского

Тексты — по правилам `ru-text` (типографика, короткие UX-формулировки,
терминология: `carrier`→«носитель», не «карьер»; `gate`→«гейт»). Проверка
переводов скиллом `ru-text:ru-check` перед финалом.

## Документация

Двуязычно (правило репо): запись в
[android/CHANGELOG.md](../../../android/CHANGELOG.md) и
[android/CHANGELOG.ru.md](../../../android/CHANGELOG.ru.md) — локализация EN/RU
по системной локали.
