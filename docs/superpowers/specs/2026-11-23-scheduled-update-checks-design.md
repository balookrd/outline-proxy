# Проверка обновлений при старте и раз в неделю (Android, macOS, Windows)

**Дата:** 2026-11-23  
**Статус:** Согласовано и принято к реализации

---

## 1. Цель

Обеспечить единое предсказуемое поведение автоматической проверки обновлений во всех трёх клиентских приложениях (`android`, `macos`, `windows`):
- при каждом холодном запуске приложения;
- регулярно по расписанию **раз в 7 дней** (604 800 с).

Сейчас поведение между платформами расходилось:
- **Android** — только ручная проверка по тапу на версию в футере;
- **macOS** — проверка при старте и по таймеру, но только если прошло ≥ 24 часов с прошлой проверки (то есть не при каждом запуске и с дневным, а не недельным интервалом);
- **Windows** — одноразовая проверка через 5 с после запуска WebView без периодического планировщика и без интеграции с системным треем.

---

## 2. Единый контракт поведения

1. **Холодный старт:**
   - При каждом холодном запуске приложения выполняется одна тихая фоновая проверка через короткую задержку после старта (5 с на Android и Windows, 10 с на macOS), независимо от времени предыдущей проверки.
   - На Android пересоздание `Activity` (смена ориентации, темы и т.д.) **не** должно запускать стартовую проверку повторно — защита на уровне процесса.
2. **Еженедельное расписание (раз в 7 дней):**
   - Периодический планировщик срабатывает, когда с момента последней *успешной* проверки (`Available` или `UpToDate`, включая ручную и стартовую) прошло **≥ 7 дней** (`604 800` с), сейчас не идёт другая проверка/установка и обновление ещё не найдено.
   - Ошибка сети или GitHub API в фоновом режиме игнорируется тихо: UI не показывает ошибку, а метка `lastUpdateCheck` **не** обновляется — следующий тик планировщика повторит попытку.
   - Откат системных часов назад (`now < lastCheck`) трактуется как основание выполнить проверку, чтобы расписание не зависало.
3. **Отображение результата (неинтрузивное):**
   - Если новая сборка найдена (`Available`), она **не** скачивается автоматически и не открывает принудительно модальные диалоги.
   - Во всех клиентах статус появляется в футере (`доступно <label> — нажмите` / локализованный эквивалент на Android) и в меню трея/статус-бара (macOS, Windows). Повторный клик сразу открывает диалог обновления с заметками к релизу без повторного запроса к GitHub.
   - При фоновой проверке на Android (`WorkManager`) дополнительно показывается одноразовое системное уведомление (с дедупликацией по `label` версии), тап по которому открывает главное окно и сразу диалог обновления.

---

## 3. Архитектура по платформам

### 3.1. Android (`android/app/`)

- **`UpdateSchedule.kt`** — чистые функции расчёта периодической проверки (`WEEKLY_INTERVAL_MS = 7d`, `WORKER_PERIOD_HOURS = 24h`, `STARTUP_DELAY_MS = 5s`), проверки необходимости показа уведомления (`shouldNotify`) и валидации кэша по `buildId` (`channel:versionName:gitSha`).
- **`UpdateStore.kt`** — персистентное хранилище на базе `SharedPreferences("outline_updates")`:
  - хранит `last_check_ms`, `cached_build_id`, поля найденного `Result.Available` (`avail_label`, `avail_asset_name`, `avail_url`, `avail_notes`) и `last_notified_label`;
  - при несовпадении `cached_build_id` с текущей сборкой (пользователь установил новую версию) автоматически очищает кэш и снимает устаревшее уведомление.
- **`UpdateNotification.kt`** — системное уведомление о доступном обновлении:
  - отдельный канал `outline_updates` (`IMPORTANCE_DEFAULT`, создаётся на API ≥ 26);
  - `NOTIFICATION_ID = 3` (1 и 2 заняты `OutlineVpnService`);
  - совместимость с `minSdk = 24` через `NotificationCompat.Builder`;
  - проверка разрешения `POST_NOTIFICATIONS` на Android 13+ (API ≥ 33) — при отказе уведомление тихо пропускается, но статус сохраняется в футере;
  - `PendingIntent` запускает `MainActivity` с `EXTRA_OPEN_UPDATE = true` (`FLAG_ACTIVITY_SINGLE_TOP | FLAG_ACTIVITY_CLEAR_TOP`).
- **`UpdateCoordinator.kt`** — процессный singleton (`StateFlow<UiState>`):
  - хранит состояние проверки, загрузки, прогресса, скачанного APK и кэшированного `Available`;
  - `hydrate(context)` восстанавливает найденное в фоне обновление из `UpdateStore` при запуске `MainActivity`;
  - `scheduleStartupCheck(context)` использует `AtomicBoolean` для однократной отложенной проверки через 5 с на один процесс;
  - `checkManually(...)` и `startDownload(...)` синхронизируют ручные действия пользователя с `UpdateStore` и снимают уведомление.
- **`UpdateWorker.kt`** — `CoroutineWorker` на базе `WorkManager`:
  - уникальная периодическая задача `outline-update-check` с периодом 24 часа, ограничением `NetworkType.CONNECTED`, `initialDelay = 24h` и политикой `ExistingPeriodicWorkPolicy.KEEP`;
  - внутри проверяет `UpdateSchedule.isPeriodicCheckDue(...)`: пока не прошла неделя с последней успешной проверки, сетевых запросов не делает; при временном сбое сети повторит на следующий цикл через 24 часа, а не через ещё 7 дней;
  - планируется из `MainActivity.onCreate()` и из `BootReceiver.onReceive()` (до проверки `KeepAliveState.shouldRun`, чтобы обновления проверялись даже при выключенном Keep-Alive; при `ACTION_MY_PACKAGE_REPLACED` очищает кэш обновлений и снимает старое уведомление).
- **`MainActivity.kt`** — обрабатывает `EXTRA_OPEN_UPDATE` в `onCreate` и `onNewIntent`, подписывается на `UpdateCoordinator.state` и отображает диалог обновления.

### 3.2. macOS (`macos/Sources/OutlineProxy/`)

- **`UpdateSchedule.swift`** — вынесенная чистая логика расписания:
  - `weeklyInterval = 7 * 24 * 60 * 60` (7 дней), `startupDelay = 10` с, `pollInterval = 60 * 60` с;
  - `isDue(lastCheck:now:interval:force:)`.
- **`UpdateController.swift`**:
  - при старте через 10 с вызывает `checkInBackground(force: true)` — безусловную тихую проверку на холодном запуске;
  - часовой `Timer` вызывает `checkInBackground(force: false)`, проверяя 7-дневный интервал через `UpdateSchedule.isDue`;
  - результат по-прежнему отображается в футере `MainWindowController` и в пункте меню `StatusMenuController`.

### 3.3. Windows (`bins/outline-windows/`)

- **Персистентность (`profile_store.rs`)**:
  - в `ProfileStoreData` добавляется опциональное поле `#[serde(default)] pub last_update_check: Option<u64>` (в секундах Unix epoch) и методы `last_update_check()` / `set_last_update_check(u64)`.
  - поле размещено именно в `ProfileStoreData`, а не в `AppSettings`, чтобы сохранение настроек из `SettingsModal` не затирало метку времени проверки.
- **Менеджер и планировщик (`updater.rs`)**:
  - чистые функции `is_periodic_check_due` (порог 7 дней = `604 800` с) и `current_unix_secs()`;
  - `UpdateState` (`checking`, `installing`, `available`, `status`) и `UpdateManager` в `AppState`, защищающий от параллельных проверок/установок и единый для GUI и трея;
  - `UpdateManager::spawn_scheduler` запускает через `tauri::async_runtime::spawn`:
    1. тихую проверку через 5 с после старта приложения (работает даже при `start_minimized = true`, когда WebView скрыт или не взаимодействует с пользователем);
    2. часовой `tokio::time::interval`, который инициирует тихую проверку, когда прошло ≥ 7 дней с `last_update_check`.
- **Трей и IPC (`tray.rs`, `commands.rs`, `lib.rs`)**:
  - в меню трея перед выходом добавлен пункт проверки/установки обновления (`Check for Updates...` / `Checking for updates...` / `Install Update <label>...`);
  - клик при наличии найденного обновления сразу показывает окно и открывает `UpdateModal`, при отсутствии — запускает интерактивную проверку;
  - добавлена команда `get_update_state` и событие `"update-state-changed"`.
- **Фронтенд (`App.svelte`, `lib/api.ts`, `lib/types.ts`)**:
  - одноразовый `setTimeout(..., 5000)` удалён;
  - при монтировании окно запрашивает `getUpdateState()`, слушает `"update-state-changed"` и `"navigate"` (`'update'`).

---

## 4. Краевые случаи

- **Одинаковая версия при повторных тиках:** на Windows и macOS кэш `available` в памяти предотвращает лишние запросы; на Android `UpdateStore` хранит кэш и `lastNotifiedLabel`, не тревожа пользователя повторным уведомлением об одной и той же сборке.
- **Неудачная проверка (оффлайн / GitHub rate limit):** при тихой проверке ошибка логируется на уровне `WARN` (или тихо игнорируется), `lastUpdateCheck` не обновляется, UI не замусоривается.
- **Смена версии приложения (ручное обновление):** при первом старте новой сборки на Android `UpdateStore.clearIfBuildChanged` сбрасывает устаревшее уведомление и кэш.
- **Изоляция прокси-петли:** существующие транспорты проверок (`UpdateChecker.kt` через собственный процесс вне TUN, `UpdateChecker.swift` с отключённым системным прокси в `URLSessionConfiguration.ephemeral`, `reqwest` на Windows) сохраняются без изменений.

---

## 5. План верификации

- **Android:**
  - unit-тесты `UpdateScheduleTest` и `UpdateCheckerTest` (`./gradlew :app:testDebugUnitTest`);
  - строгий i18n-lint на паритет EN/RU (`./gradlew :app:lintDebug`);
  - компиляция Kotlin (`./gradlew :app:compileDebugKotlin`).
- **macOS:**
  - сборка пакета (`swift build`);
  - unit-проверки `UpdateSchedule` (`verify-update-schedule.swift`).
- **Windows:**
  - сборка фронтенда (`pnpm build`);
  - `cargo fmt --check -p outline-windows`, `cargo clippy -p outline-windows --all-targets --no-deps -- -D warnings`, `cargo test -p outline-windows` (тесты `is_periodic_check_due`, `UpdateManager`, `ProfileStore::last_update_check`).
- **Документация:** синхронное обновление `README.md` и `README.ru.md` для `android/`, `macos/`, `windows/`.
