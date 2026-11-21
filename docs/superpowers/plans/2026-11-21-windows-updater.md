# План реализации проверки и установки обновлений Windows-клиента (Tauri v2)

> **Для агентов-исполнителей:** ОБЯЗАТЕЛЬНЫЙ НАВЫК: использовать `superpowers:subagent-driven-development` (рекомендуется) или `superpowers:executing-plans` для пошаговой реализации задач этого плана. Шаги оформлены в виде чекбоксов (`- [ ]`).

**Цель:** Реализовать в Windows-клиенте (`bins/outline-windows`) полный цикл проверки обновлений, отображения статуса в футере и диалоге, скачивания verified ZIP-архива с проверкой контрольной суммы по `SHA256SUMS.txt`, безопасного применения обновления с перезапуском и восстановлением туннеля (паритет с macOS Menu Bar клиентом).

**Архитектура:**
- Backend на Rust: в `build.rs` фиксируются коммит (`OUTLINE_BUILD_COMMIT`) и канал (`OUTLINE_BUILD_CHANNEL`). Модуль `updater.rs` выполняет асинхронные HTTP-запросы к GitHub API (`balookrd/outline-proxy`), парсит релизы и `SHA256SUMS.txt`, проверяет коммиты, скачивает и верифицирует SHA256 архива, распаковывает в staging-каталог с защитой от zip-slip (`enclosed_name`), генерирует detached batch-скрипт замены файлов `apply_update.cmd` и завершает процесс приложения.
- Frontend на Svelte 5: динамический футер с версией и live-статусом (`проверка обновлений…`, `доступно nightly · <sha>`, `актуальная версия`, `загрузка N%`), модальное окно `UpdateModal.svelte` с описанием изменений, прогресс-баром и подтверждением установки.

**Стек технологий:** Rust 2024, Tauri v2, `reqwest`, `zip` (pure-rust deflate с miniz_oxide), Svelte 5, TypeScript, Tailwind CSS v4.

## Глобальные ограничения
- Следовать инвариантам монорепо: rustls только на aws-lc-rs, единый аллокатор, отсутствие сторонних C-зависимостей.
- Безопасность: никогда не применять бинарники без сверки хэша с `SHA256SUMS.txt`; строгая валидация путей в архиве от zip-slip атак.
- Сохранение состояния: при установке обновления во время активного подключения сохранять `reconnect_after_update: true` и восстанавливать туннель после старта новой версии.
- Все диалоги, рассуждения и планы — строго на русском языке. Коммиты — на английском языке (Conventional Commits).

---

### Task 1: Встраивание метаданных сборки и модуль версии приложения

**Файлы:**
- Модификация: `bins/outline-windows/build.rs`
- Модификация: `bins/outline-windows/Cargo.toml`
- Создание: `bins/outline-windows/src/version.rs`
- Модификация: `bins/outline-windows/src/lib.rs`

**Интерфейсы:**
- `AppVersionInfo`: `{ version: String, commit: String, channel: String, display_string: String }`
- Функция: `AppVersion::current() -> AppVersionInfo`
- Функция: `AppVersion::same_commit(published: &str, current: &str) -> bool`

- [x] **Шаг 1: Написать failing unit-тесты для метаданных версии и сопоставления коммитов**
  Создать тесты в `bins/outline-windows/src/version.rs`:
  - `test_display_string_nightly()`
  - `test_same_commit_exact_and_prefix()`
  - `test_same_commit_dirty_handling()`

- [x] **Шаг 2: Запустить тесты и убедиться в ошибке компиляции (отсутствие модуля)**
  Команда: `cargo test -p outline-windows version`

- [x] **Шаг 3: Реализовать `build.rs` и `src/version.rs`**
  - В `build.rs` определять `OUTLINE_BUILD_COMMIT` через `git rev-parse --short HEAD` (с фолбэком на env `OUTLINE_BUILD_COMMIT` или `"dev"`), `OUTLINE_BUILD_CHANNEL` (фолбэк `"nightly"`).
  - В `version.rs` реализовать структуры и функции нормализации коммита (удаление `-dirty`, сравнение префиксов длиной не менее 7 символов).
  - Подключить `pub mod version;` в `src/lib.rs`.

- [x] **Шаг 4: Запустить тесты и убедиться в успешном прохождении**
  Команда: `cargo test -p outline-windows version`

- [x] **Шаг 5: Закоммитить изменения**
  Команда: `git add bins/outline-windows/build.rs bins/outline-windows/Cargo.toml bins/outline-windows/src/version.rs bins/outline-windows/src/lib.rs && git commit -m "feat(windows): add build metadata and AppVersion resolver"`

---

### Task 2: Модуль обновления `updater.rs` (проверка, верификация SHA256, распаковка и инсталлятор)

**Файлы:**
- Модификация: `bins/outline-windows/Cargo.toml` (подключение `zip` с `default-features = false, features = ["deflate"]`)
- Создание: `bins/outline-windows/src/updater.rs`
- Модификация: `bins/outline-windows/src/lib.rs`

**Интерфейсы:**
- `UpdateInfo`: `{ label: String, asset_name: String, download_url: String, checksums_url: Option<String>, notes: String, commit: String }`
- `UpdateCheckResult`: `UpToDate`, `Available(UpdateInfo)`
- Функция: `UpdateChecker::check(channel: &str, current_commit: &str, current_version: &str) -> Result<UpdateCheckResult, String>`
- Функция: `UpdateInstaller::download_and_verify(update: &UpdateInfo, on_progress: F) -> Result<PathBuf, String>`
- Функция: `UpdateInstaller::stage_update(zip_path: &Path, staging_dir: &Path) -> Result<(), String>`
- Функция: `UpdateInstaller::launch_updater(staging_dir: &Path, target_exe: &Path, current_pid: u32) -> Result<(), String>`

- [x] **Шаг 1: Написать failing unit-тесты для парсинга `SHA256SUMS.txt`, имени ассета и защиты от zip-slip**
  В `bins/outline-windows/src/updater.rs`:
  - `test_parse_checksums_txt_with_asterisk_and_space()`
  - `test_evaluate_nightly_release_asset_name()`
  - `test_zip_slip_protection()`

- [x] **Шаг 2: Запустить тесты и зафиксировать failure**
  Команда: `cargo test -p outline-windows updater`

- [x] **Шаг 3: Реализовать `updater.rs`**
  - Реализовать GitHub API парсер для тега `windows-nightly` и релизов `windows-v*`.
  - Реализовать парсер `SHA256SUMS.txt`.
  - Реализовать скачивание с расчётом SHA256 через потоковый хэшер `sha2::Sha256` (или `ring::digest::SHA256`).
  - Реализовать безопасную распаковку zip-архива с проверкой `enclosed_name()` (блокировка `../`).
  - Реализовать генерацию detached скрипта `apply_update.cmd`: ожидание завершения PID, копирование `OutlineProxy.exe`, `outline-ws-rust.exe`, `wintun.dll`, запуск нового приложения, удаление staging каталога.
  - Подключить `pub mod updater;` в `src/lib.rs`.

- [x] **Шаг 4: Запустить unit-тесты**
  Команда: `cargo test -p outline-windows updater`

- [x] **Шаг 5: Закоммитить изменения**
  Команда: `git add bins/outline-windows/Cargo.toml bins/outline-windows/src/updater.rs bins/outline-windows/src/lib.rs && git commit -m "feat(windows): implement update checker, checksum verifier and installer"`

---

### Task 3: Tauri команды и интеграция с управлением туннелем

**Файлы:**
- Модификация: `bins/outline-windows/src/commands.rs`
- Модификация: `bins/outline-windows/src/lib.rs`
- Модификация: `bins/outline-windows/src/profile_store.rs` (добавление поля `reconnect_after_update: bool` в `AppSettings`)

**Интерфейсы:**
- Tauri команды:
  - `get_app_version() -> Result<AppVersionInfo, String>`
  - `check_for_updates() -> Result<UpdateCheckResponse, String>`
  - `install_update(update: UpdateInfo) -> Result<(), String>`

- [x] **Шаг 1: Написать failing тест на сериализацию команд и обработку `reconnect_after_update`**
  В `bins/outline-windows/src/profile_store.rs` проверить сохранение флага `reconnect_after_update`.

- [x] **Шаг 2: Реализовать команды в `commands.rs` и зарегистрировать их в `src/lib.rs`**
  - `get_app_version`: возвращает `AppVersion::current()`.
  - `check_for_updates`: вызывает `UpdateChecker::check()`.
  - `install_update`:
    1. Если туннель запущен (`process_controller.is_running()`), установить `settings.reconnect_after_update = true` и вызвать `disconnect()`.
    2. Скачать, верифицировать и распаковать обновление.
    3. Запустить `apply_update.cmd` и завершить работу приложения через `app_handle.exit(0)`.
  - При старте `setup` в `lib.rs`: если `reconnect_after_update == true`, сбросить флаг и запланировать автоподключение активного профиля через 1 секунду.

- [x] **Шаг 3: Проверить компиляцию и unit-тесты**
  Команда: `cargo test -p outline-windows`

- [x] **Шаг 4: Закоммитить изменения**
  Команда: `git add bins/outline-windows/src/commands.rs bins/outline-windows/src/lib.rs bins/outline-windows/src/profile_store.rs && git commit -m "feat(windows): wire update commands into Tauri and auto-reconnect tunnel"`

---

### Task 4: Frontend UI (Svelte 5) — модальное окно `UpdateModal` и интерактивный футер

**Файлы:**
- Модификация: `bins/outline-windows/frontend/src/lib/types.ts`
- Модификация: `bins/outline-windows/frontend/src/lib/api.ts`
- Создание: `bins/outline-windows/frontend/src/components/UpdateModal.svelte`
- Модификация: `bins/outline-windows/frontend/src/App.svelte`

**Интерфейсы:**
- `types.ts`: `AppVersionInfo`, `UpdateInfo`, `UpdateCheckResponse`
- `api.ts`: `getAppVersion()`, `checkForUpdates()`, `installUpdate(update)`
- `UpdateModal.svelte`: props `{ isOpen, theme, update, isInstalling, progressPercent, error, onInstall, onClose }`

- [x] **Шаг 1: Добавить типы и методы API в `types.ts` и `api.ts`**
- [x] **Шаг 2: Создать компонент `UpdateModal.svelte`**
  - Поддержка темной и светлой тем (акцентный синий `#1E5EE8` / `#60A5FA`).
  - Информация о сборке, текст release notes / body в аккуратном скроллируемом блоке.
  - Отображение состояния загрузки: полоса прогресса, проценты.
  - Кнопки «Обновить» (или «Перезапустить»), «Отмена», при ошибке — сообщение и «Повторить».
- [x] **Шаг 3: Интегрировать логику обновления в `App.svelte`**
  - При монтировании (`onMount`): загрузка текущей версии через `getAppVersion()`, тихий запуск `checkForUpdates()` через 5 секунд.
  - Футер: отображает текущую версию (`nightly · v1.9.2 (971282b6)`) или активный статус (`проверка обновлений…`, `доступно nightly · <sha>`, `актуальная версия`, `ошибка...`).
  - Обработчик клика по футеру `handleFooterClick`:
    - Если обновление уже найдено — сразу открывает `UpdateModal`.
    - Если нет — запускает проверку, обновляет статус в футере; при обнаружении обновления автоматически открывает `UpdateModal`.
- [x] **Шаг 4: Собрать фронтенд и проверить отсутствие ошибок TypeScript / Svelte**
  Команда: `pnpm --prefix bins/outline-windows/frontend build`

- [x] **Шаг 5: Закоммитить изменения фронтенда**
  Команда: `git add bins/outline-windows/frontend/src/ && git commit -m "feat(windows): add UpdateModal and interactive update check in footer"`

---

### Task 5: Скрипт сборки и CI интеграция метаданных

**Файлы:**
- Модификация: `scripts/package-windows.sh`
- Модификация: `.github/workflows/_windows-release-build.yml`

- [x] **Шаг 1: Экспортировать `OUTLINE_BUILD_COMMIT` и `OUTLINE_BUILD_CHANNEL` в `scripts/package-windows.sh` и CI**
  - В `package-windows.sh` брать короткий хэш git коммита и передавать в сборку.
  - В `_windows-release-build.yml` передавать `OUTLINE_BUILD_COMMIT="${{ github.sha }}"` и `OUTLINE_BUILD_CHANNEL="nightly"`.
- [x] **Шаг 2: Проверить локальный сухой прогон сборки (`--check-only`)**
  Команда: `./scripts/package-windows.sh --check-only`
- [x] **Шаг 3: Закоммитить изменения**
  Команда: `git add scripts/package-windows.sh .github/workflows/_windows-release-build.yml && git commit -m "ci(windows): propagate build commit and channel into Windows app compilation"`

---

### Task 6: Документация (EN/RU) и валидация монорепо

**Файлы:**
- Модификация: `bins/outline-windows/README.md`
- Модификация: `bins/outline-windows/README.ru.md`
- Модификация: `CHANGELOG.md`
- Модификация: `CHANGELOG.ru.md`

- [ ] **Шаг 1: Обновить документацию на обоих языках**
  - Описать механизм проверки обновлений по клику на футер и автоматического обновления.
  - Описать формат артефактов и сверку SHA256 по `SHA256SUMS.txt`.
- [ ] **Шаг 2: Запустить локальный гейт проверок монорепо**
  - `cargo fmt --check -p outline-windows`
  - `cargo clippy -p outline-windows --no-deps -- -D warnings`
  - `cargo test -p outline-windows`
- [ ] **Шаг 3: Закоммитить изменения**
  Команда: `git add bins/outline-windows/ CHANGELOG.md CHANGELOG.ru.md && git commit -m "docs(windows): document in-app updater and footer interaction"`
