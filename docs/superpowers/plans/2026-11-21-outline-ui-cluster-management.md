# План реализации: Кластерное управление, полная настройка `outline-server` и генерация подписок в `outline-ui`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Расширить `outline-ui`, control API `outline-server` и `ops/access-keys` для полного редактирования всех настроек сервера (включая `[[endpoint]]` и сброс опциональных полей), конфиг-управляемого управления кластерами с контролем дрейфа и синхронным CRUD пользователей, безопасной перегенерации/очистки подписок (`--prune`) через `generate_keys.py`, отображения ссылок/QR в UI и вывода версии `outline-ui` в подвале левого сайдбара.

**Architecture:** Работы разделены на 5 последовательных этапов:
1. Расширение Python-генератора `ops/access-keys/` (`[access_keys].nodes`, `--prune`, `--json-report`, `--user --links-json`).
2. Расширение Control API `bins/outline-server/` (трёхсостоянный `FieldPatch<T>`, полное покрытие `FileConfig`, `[[endpoint]]` CRUD, `restart_pending`, BLAKE3-отпечатки секретов, безопасный запуск генератора через `tokio::process::Command`).
3. Расширение бэкенда `bins/outline-ui/` (`GET /api/meta` с версией, `[[ss.clusters]]` и автообнаружение кластеров, модуль `ss/cluster.rs` для fan-out операций, drift-отчётов, pre-flight/отката при создании пользователей и маршрутов подписок).
4. Расширение фронтенда `bins/outline-ui/frontend/` (версия в подвале `Sidebar.svelte`, единый селектор кластера/узла, кластерные `Users`/`Cluster`/`ServerSettings`, локальный SVG QR в `AccessKeysModal.svelte`, `RegenerateBanner.svelte`).
5. Финальная верификация (полный CI-гейт, Docker Linux-проверка прав/компиляции), синхронная EN/RU документация и поэтапный регламент выкатки (строго по команде владельца).

**Tech Stack:** Rust (Edition 2024, Axum 0.8, Tokio, `toml_edit`, `blake3`), Python 3 (stdlib, `unittest`), Svelte 5 + TypeScript + Vite + Tailwind + Vitest (`uqr` для матрицы QR-кода).

## Global Constraints

- **Спецификация:** `docs/superpowers/specs/2026-11-21-outline-ui-cluster-management-design.md`.
- **Анонимизация и секретный путь ключей:** в коммитируемых файлах не использовать реальные домены, имена узлов, IP и путь `[access_keys] write_dir` (проверяется `.github/scripts/check-served-key-path.sh`). Python запускать только с `PYTHONDONTWRITEBYTECODE=1 python3 -B`.
- **Терминология и язык:** диалоги, спеки и планы — на русском (`carrier` → «носитель»/`carrier`, `gate` → «гейт»/`gate`); код, логи и коммиты — на английском; user-facing документация обновляется в EN и RU параллельно.
- **Монорепо-инварианты:** `rustls` только с `aws-lc-rs`; `--exclude sockudo-ws --exclude outline-windows` в workspace-командах; сборка `outline-server --no-default-features` обязана компилироваться без ошибок и warning'ов; при добавлении зависимостей (если потребуются общие) использовать корневой `[workspace.dependencies]`.
- **Правила работы с артефактами и деплоем:** после проверок чистить `target/debug/`; после финального `git push` запускать `cargo clean`; на боевые узлы и в k3s ничего не выкатывать без явной команды владельца.

---

### Этап 1: Расширение генератора `ops/access-keys/`

**Files:**
- Modify: `ops/access-keys/config_model.py`
- Modify: `ops/access-keys/artifacts.py`
- Modify: `ops/access-keys/generate_keys.py`
- Modify: `ops/access-keys/test_config_model.py`
- Modify: `ops/access-keys/test_generate_keys.py`

- [ ] **Step 1: Добавить `[access_keys].nodes` в `config_model.py` и тесты в `test_config_model.py`**

  - В `AccessKeys` добавить `nodes: tuple[str, ...] | None = None`.
  - В `load()` читать `ak_section.get("nodes")`: проверять, что это список непустых строк (если задан и не список/пустая строка — бросать `SystemExit`), обрезать пробелы и сохранять `tuple(...)` (при пустом списке — `None`).
  - Написать unit-тесты в `test_config_model.py`: чтение `nodes`, валидация некорректного типа, отсутствие `nodes` даёт `None`.

- [ ] **Step 2: Реализовать `--prune`, граничный случай 0 юзеров, `--json-report` и `--user <id> --links-json` в `artifacts.py` и `generate_keys.py`**

  - В `artifacts.py` добавить helper `txt_url(user, server)` (при наличии `ak.url_base` и непустых `user_urls`, возвращает `uri.join_url(ak.url_base, f"{user.filename}.txt")`).
  - В `generate_keys.py`:
    - Выбор узлов: `tuple(args.nodes)` → иначе `server.access_keys.nodes` → иначе `xray_json.DEFAULT_NODES`.
    - При `--prune`:
      - Разрешать `not server.users` (не падать с `no enabled users`, а переходить к очистке `out_dir` и выводить пустой отчёт).
      - Собирать `expected_filenames` (имена файлов без директории).
      - Добавлять функцию `prune_stale_files(out_dir, expected_filenames, managed_extensions, dry_run)` — сканирует только `out_dir.iterdir()`, игнорирует dotfiles (`name.startswith(".")`), симлинки (`is_symlink()`) и не-файлы (`not is_file()`), удаляет файлы с расширениями из `{ak.file_extension, ".conf", ".yaml", ".json", ".toml", ".txt"}`, которых нет в `expected_filenames`.
    - Добавить флаг `--json-report`: печатать JSON `{ nodes, users, pruned, group_warnings }` в stdout (имена файлов в `written` / `pruned`, только URL без сырых секретов).
    - Добавить пару флагов `--user <id>` и `--links-json`:
      - Ничего не писать на диск и не чистить (`out_dir` не обязателен);
      - Искать пользователя по точному `id` среди включённых (или сообщать отдельно, если найден среди отключённых, чтобы control API мог вернуть `409`);
      - Отдавать JSON `{ user, enabled, outline_url, happ_url, ws_url, txt_url, share_links, artifacts, warnings }` (где `share_links` — `user_urls` без первой `ssconf://`, а `artifacts` — словарь непустых текстов `conf`/`json`/`toml`/`txt`).

- [ ] **Step 3: Написать и прогнать Python-тесты**

  - В `test_generate_keys.py` добавить тесты:
    - удаление артефактов удалённого и отключённого юзера при `--prune`, сохранение посторонних файлов (например, `index.html`, подкаталогов, dotfiles и симлинков);
    - работа `--prune` при 0 активных юзерах и в `--dry-run --prune`;
    - приоритет `--node` > `[access_keys].nodes` > `DEFAULT_NODES`;
    - формат `--json-report` (валидный JSON, отсутствие секретов);
    - `--user <id> --links-json` (успех, отсутствие записи на диск, ошибка для несуществующего/отключённого пользователя);
    - сохранение 100% прохождения `GoldenCorpusTest`.
  - Команда проверки:
    ```bash
    PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s ops/access-keys -v
    ```

---

### Этап 2: Полное покрытие настроек и генератор подписок в `bins/outline-server`

**Files:**
- Modify: `Cargo.toml` (если не хватает workspace-фич — `tokio` уже есть), `bins/outline-server/Cargo.toml`
- Modify: `bins/outline-server/src/config/file.rs`
- Modify: `bins/outline-server/src/config/control.rs`
- Modify: `bins/outline-server/src/config/tests/control.rs`
- Modify: `bins/outline-server/src/config/tests/file.rs`
- Modify: `bins/outline-server/src/server/control/mod.rs`
- Modify: `bins/outline-server/src/server/control/server.rs`
- Modify: `bins/outline-server/src/server/control/manager.rs`
- Modify: `bins/outline-server/src/server/control/handlers.rs`
- Modify: `bins/outline-server/src/server/control/persist.rs`
- Create: `bins/outline-server/src/server/control/access_keys.rs`
- Modify: `bins/outline-server/src/server/control/tests/{handlers,manager,persist,server}.rs`
- Create: `bins/outline-server/src/server/control/tests/access_keys.rs`

- [ ] **Step 1: Расширить `[access_keys]` и `[control]` в конфигурации сервера**

  - В `bins/outline-server/Cargo.toml` добавить `"process"` в фичи `tokio`.
  - В `bins/outline-server/src/config/file.rs`:
    - В `AccessKeysSection` добавить `pub nodes: Option<Vec<String>>`.
    - В `ControlFileConfig` добавить `pub access_keys_generator: Option<PathBuf>`, `pub access_keys_python: Option<PathBuf>`, `pub access_keys_timeout_secs: Option<u64>`.
  - В `bins/outline-server/src/config/control.rs`:
    - Расширить `ControlConfig` полями `access_keys_generator: Option<PathBuf>`, `access_keys_python: PathBuf` (дефолт `"python3"`), `access_keys_timeout_secs: u64` (дефолт `15`, проверка `1..=120` и непустоты путей в `resolve_control_config`).
    - Проверить `Debug` на `ControlConfig` (токен остаётся `<redacted>`).
  - Обновить `bins/outline-server/src/config/tests/control.rs` и `tests/file.rs`.

- [ ] **Step 2: Добавить BLAKE3-отпечатки секретов и перенести `FieldPatch<T>` для `persist.rs`**

  - В `bins/outline-server/src/server/control/manager.rs`:
    - Сделать `FieldPatch<T>` видимым на уровне `pub(super)`.
    - Добавить в `UserView`: `#[serde(skip_serializing_if = "Option::is_none")] pub password_fp: Option<String>` и `vless_id_fp: Option<String>` (12 hex-символов `blake3::Hasher` с доменным разделителем + `user.id` + `\0` + секрет).
  - В `bins/outline-server/src/server/control/handlers.rs`:
    - Вычислять `psk_fingerprint: Option<String>` в `ClusterConfigView` (`blake3` от декодированного/сырого PSK с доменом `"outline-cluster-psk-fp\0"`, первые 12 hex-символов).
    - Проверить, что сам секрет в `ClusterConfigView` по-прежнему маскируется (`"********"`).

- [ ] **Step 3: Полное покрытие `GET /control/config`, `PATCH /control/config`, `[[endpoint]]` CRUD и `restart_pending`**

  - Расширить `ServerConfigResponse` и `ServerConfigPatch` в `handlers.rs` и `persist.rs`:
    - Перевести опциональные поля патчей на `FieldPatch<T>` (включая `FieldPatch` для опциональных секций целиком: `http_fallback`, `sni_fallback`, `h3`, `access_keys`, `tuning`).
    - В `EndpointConfigView` добавить `pub kind: EndpointKind`, сохранив `protocol`, `transport`, `padded`. В `EndpointPatch` поддержать полный список `{ path, kind, padded }`: в `patch_toml_config` перестраивать `[[endpoint]]` (проверять непустоту и уникальность `path`, валидность `kind`).
    - Добавить `ServerTlsCertView` / `ServerTlsCertPatch` (`cert_path`, `key_path`, `sni`), `max_connections_per_ip`, `h3_certs`, `h3_alpn`, `h3_udp_datagrams`, `shadowsocks.method`, `http_root.{auth, realm}`, `access_keys.{public_host, public_scheme, url_base, file_extension, write_dir, nodes}` (без логирования `write_dir`), `tuning` (все 23 поля `TuningOverrides`), read-only `metrics` и `control` views.
    - В `persist.rs::ensure_table`: при вставке новой таблицы позиционировать её **до** `[[users]]`.
    - Всегда прогонять `crate::config::parse_and_validate(&new_contents)` до `atomic_write`.
    - Добавить вычисление `restart_pending` в `GET /control/config` (сравнение runtime-полей `disk_file` с `state.config`) и честный `requires_restart` в `PATCH /control/config` (`false`, если менялся только `access_keys`).
  - Написать подробные тесты в `tests/persist.rs`, `tests/handlers.rs`, `tests/manager.rs`.

- [ ] **Step 4: Реализовать `control/access_keys.rs` и маршруты `/control/access-keys/regenerate`, `/control/users/{id}/access-keys`**

  - В `bins/outline-server/src/server/control/access_keys.rs` (под модулем `control`, который компилируется только с `feature = "control"`):
    - Валидаторы `validate_node_host` (не пустой, <= 253, без пробелов/управляющих/`/`, не начинается с `-`, допустимые символы hostname/IPv6/port) и `validate_user_id`.
    - Резолв узлов: `req.nodes` → `disk.access_keys.nodes` → `[disk.access_keys.public_host]`.
    - Вызов `tokio::process::Command::new(&python)` без shell, `kill_on_drop(true)`, таймаут `access_keys_timeout_secs`, ограниченный сбор stdout/stderr (4 MiB).
    - Захват `state.manager.config_file_lock().lock().await` на время `regenerate`.
    - Регистрация маршрутов в `bins/outline-server/src/server/control/server.rs`:
      - `.route("/control/access-keys/regenerate", post(access_keys::regenerate))`
      - `.route("/control/users/{id}/access-keys", get(access_keys::get_user_access_keys))`
  - Написать тесты в `tests/access_keys.rs` и `tests/server.rs`: с мок-скриптом Python на `tempfile`, проверкой отказа при невалидных `nodes` / `id`, проверкой таймаута, `501` без настроенного генератора, и auth-гейта.
  - Проверить сборку и тесты `outline-server` (включая `--no-default-features`):
    ```bash
    cargo check -p outline-server --no-default-features
    cargo test -p outline-server
    ```

---

### Этап 3: Бэкенд `bins/outline-ui` (метаданные, кластеры, fan-out, drift, подписки)

**Files:**
- Modify: `bins/outline-ui/src/config.rs`
- Modify: `bins/outline-ui/src/main.rs`
- Modify: `bins/outline-ui/src/ss/mod.rs`
- Modify: `bins/outline-ui/src/ss/api.rs`
- Create: `bins/outline-ui/src/ss/cluster.rs`
- Modify: `bins/outline-ui/src/tests/{config.rs,routing.rs}`
- Modify: `bins/outline-ui/src/ss/tests/{mod.rs,api.rs}`
- Create: `bins/outline-ui/src/ss/tests/cluster.rs`

- [ ] **Step 1: Эндпоинт `GET /api/meta` и версия в `outline-ui`**

  - В `bins/outline-ui/src/main.rs`:
    - Добавить маршрут `.route("/api/meta", get(api_meta))` до `.fallback(...)`, возвращающий `{ "name": "outline-ui", "version": env!("CARGO_PKG_VERSION") }`.
    - В `security_headers`: обновить условие `is_api` → `path == "/api/meta" || path.starts_with("/api/") || path.starts_with("/ss/dashboard/api/") || path.starts_with("/ws/dashboard/api/")`, чтобы отдавать `Cache-Control: no-store`.
    - В стартовом `info!` добавить `version = env!("CARGO_PKG_VERSION")`.
  - В `bins/outline-ui/src/tests/routing.rs`:
    - Проверить, что `GET /api/meta` без токена отдаёт `401`, с невалидным `Host` — `403`, с валидным токеном — `200`, `Cache-Control: no-store` и точную `CARGO_PKG_VERSION`.

- [ ] **Step 2: Модель `[[ss.clusters]]` и метаданных узлов в `config.rs`**

  - В `InstanceConfig` (или `SsInstanceConfig` / общие поля с `Option`): добавить `public_host: Option<String>`, `mesh_addr: Option<String>`.
  - В `UiConfig` добавить `pub ss_clusters: Vec<ClusterConfig>` (`name: String`, `members: Vec<String>`, `subscription_nodes: Vec<String>`).
  - Валидация: непустые имена кластеров без дублей, непустой `members` из уникальных имён, присутствующих в `ss.instances`, один узел не состоит в двух явных кластерах.
  - Передать `clusters: Arc<[ClusterConfig]>` в `SsState`.
  - Обновить `src/tests/config.rs`, `src/tests/routing.rs`, `src/ss/tests/mod.rs`.

- [ ] **Step 3: Одиночные эндпоинты подписок и расширение `/ss/dashboard/api/instances`**

  - В `bins/outline-ui/src/ss/api.rs`:
    - `list_instances`: отдавать `instances` (включая `public_host`, `mesh_addr`, `cluster`) и `clusters` (и опциональный флаг `discovered` при автоопределении).
    - Добавить одиночные прокси-хендлеры:
      - `POST /ss/dashboard/api/access-keys/regenerate?instance=...` → `POST /control/access-keys/regenerate`
      - `GET /ss/dashboard/api/users/{id}/access-keys?instance=...` → `GET /control/users/{id}/access-keys`

- [ ] **Step 4: Кластерный модуль `bins/outline-ui/src/ss/cluster.rs` и маршруты в `ss/mod.rs`**

  - Подключить маршруты в `bins/outline-ui/src/ss/mod.rs`:
    - `GET /dashboard/api/clusters` (возвращает явные + автодетектированные по `psk_fingerprint` кластеры);
    - `GET /dashboard/api/clusters/{cluster}/config` + `PATCH /dashboard/api/clusters/{cluster}/config`;
    - `GET /dashboard/api/clusters/{cluster}/users` + `POST /dashboard/api/clusters/{cluster}/users`;
    - `PATCH /dashboard/api/clusters/{cluster}/users/{id}` + `DELETE /dashboard/api/clusters/{cluster}/users/{id}`;
    - `POST /dashboard/api/clusters/{cluster}/users/{id}/block` + `POST .../unblock`;
    - `POST /dashboard/api/clusters/{cluster}/access-keys/regenerate`;
    - `GET /dashboard/api/clusters/{cluster}/users/{id}/access-keys`.
  - Реализовать в `cluster.rs`:
    - Параллельный fan-out через `futures_util::future::join_all` (или `tokio::task::JoinSet` — `futures-util` уже есть в `workspace.dependencies`, либо `tokio::JoinSet` без новых зависимостей!). `tokio::task::JoinSet` не требует добавлять крейт в `outline-ui/Cargo.toml`.
    - Drift-анализ по общим секциям конфигурации и mesh-инвариантам (`psk_match`, `shards_unique`, `peers_symmetric`, `restart_pending_nodes`).
    - Pre-flight + rollback при `POST /users` (если одна из нод упала после создания на другой — откатить `DELETE` на успевших нодах).
    - Идемпотентный `DELETE` (принимать `404` как `already_absent`).
    - Передача `cluster.subscription_nodes` при `access-keys/regenerate` (если не пуст).
  - Написать интеграционные тесты в `bins/outline-ui/src/ss/tests/cluster.rs` с локальными mock HTTP control-серверами на `127.0.0.1:0` (проверка drift, fan-out, rollback при сбое, идемпотентный delete, подписки).
  - Команда проверки:
    ```bash
    cargo test -p outline-ui
    ```

---

### Этап 4: Фронтенд `bins/outline-ui/frontend/`

**Files:**
- Modify: `bins/outline-ui/frontend/package.json`, `pnpm-lock.yaml` (добавить `uqr` — лёгкая zero-dep библиотека генерации матрицы QR)
- Modify: `bins/outline-ui/frontend/vite.config.ts`
- Modify: `bins/outline-ui/frontend/src/lib/types.ts`
- Modify: `bins/outline-ui/frontend/src/lib/api.ts`
- Modify: `bins/outline-ui/frontend/src/lib/api.test.ts`
- Modify: `bins/outline-ui/frontend/src/lib/userForm.ts`
- Modify: `bins/outline-ui/frontend/src/lib/userForm.test.ts`
- Create: `bins/outline-ui/frontend/src/lib/meta.svelte.ts`
- Create: `bins/outline-ui/frontend/src/lib/ssTarget.svelte.ts`
- Create: `bins/outline-ui/frontend/src/lib/serverConfigForm.ts` (+ `serverConfigForm.test.ts`)
- Create: `bins/outline-ui/frontend/src/lib/qr.ts` (+ `qr.test.ts`)
- Modify: `bins/outline-ui/frontend/src/components/layout/Sidebar.svelte`
- Modify: `bins/outline-ui/frontend/src/components/layout/Topbar.svelte`
- Modify: `bins/outline-ui/frontend/src/components/layout/InstanceSelector.svelte` (или новый `SsTargetSelector.svelte`)
- Create: `bins/outline-ui/frontend/src/components/ui/ConfirmDialog.svelte`
- Create: `bins/outline-ui/frontend/src/components/ui/QrCode.svelte`
- Modify: `bins/outline-ui/frontend/src/features/ss/Users.svelte`
- Modify: `bins/outline-ui/frontend/src/features/ss/UsersTable.svelte`
- Modify: `bins/outline-ui/frontend/src/features/ss/UserDrawer.svelte`
- Modify: `bins/outline-ui/frontend/src/features/ss/Cluster.svelte`
- Modify: `bins/outline-ui/frontend/src/features/ss/ServerSettings.svelte`
- Create: `bins/outline-ui/frontend/src/features/ss/ClusterStatusStrip.svelte`
- Create: `bins/outline-ui/frontend/src/features/ss/DriftBadge.svelte`
- Create: `bins/outline-ui/frontend/src/features/ss/PerNodeResultPanel.svelte`
- Create: `bins/outline-ui/frontend/src/features/ss/AccessKeysModal.svelte`
- Create: `bins/outline-ui/frontend/src/features/ss/RegenerateBanner.svelte`
- Modify: `bins/outline-ui/frontend/src/app.css`

- [ ] **Step 1: Версия в подвале левого сайдбара, мобильная версия в `Topbar.svelte` и дизайн-токены `app.css`**

  - В `bins/outline-ui/frontend/vite.config.ts`: добавить `'/api': 'http://127.0.0.1:9500'` в `server.proxy`.
  - В `bins/outline-ui/frontend/src/lib/types.ts` и `api.ts`: тип `MetaResponse` и `getMeta()`, покрыть тестом в `api.test.ts`.
  - Создать `lib/meta.svelte.ts`: единый reactive-загрузчик `/api/meta` (1 запрос за сессию без polling, безопасный fallback при ошибке).
  - В `Sidebar.svelte`: оформить `<div class="foot">` с `border-top: 1px solid var(--border-soft)` и выводом `outline-ui` слева + `<span class="ver mono">v{version}</span>` справа цветом `var(--fg-muted)` (WCAG AA 4.5:1 в обеих темах).
  - В `Topbar.svelte`: добавить `<span class="ver-mobile mono">v{version}</span>` рядом с `.brand small`, отображаемый только в `@media (max-width: 900px)`, когда `.sidebar .foot` скрывается.
  - В `app.css`:
    - добавить стили для нативных `<dialog>` (`dialog:modal { overscroll-behavior: contain; }`, `dialog::backdrop { overflow: hidden; overscroll-behavior: contain; }`, `dialog[open]`), горизонтальных вкладок `[role="tablist"]` (`border-block-end: 3px solid var(--accent)` на `[aria-selected="true"]::after`), `.table-wrapper`, sticky save-bar, `ClusterStatusStrip`, `DriftBadge`, `PerNodeResultPanel`, а также `@media (pointer: coarse)` для увеличения touch-зоны `.iconbtn` и инпутов (с зазором `>= 8px`);
    - очистить inline-ссылки на несуществующие переменные (`--bg-surface-2`, `--border-subtle`) и нестилизованные классы (`btn sm danger` → описанные в `app.css` классы на реальных токенах `--surface-2`, `--border-soft`, `--chip-*`, `--danger`).

- [ ] **Step 2: Селектор цели (`/ss`), общие UI-примитивы и чистая логика форм / QR**

  - Создать `ssTarget.svelte.ts` (хранит выбранную цель `{ kind: 'cluster' | 'instance', name }`, синхронизирует список инстансов и кластеров, сохраняет выбор при переключении `/ss` ↔ `/ss/cluster` ↔ `/ss/settings`).
  - Обновить селектор в шапке `/ss`-страниц (`<optgroup label="Clusters">`, `<optgroup label="Nodes">`), добавить подсказку «Switch to cluster `<name>`» при выборе члена кластера и защиту переключения цели при несохранённых правках.
  - В `userForm.ts`: поддержать кнопки генерации `password` / `vlessId` не только в `cloning`, но и при **Add** и **Edit** (ротация секрета) + инлайн-валидацию; покрыть тестами в `userForm.test.ts`.
  - Создать `serverConfigForm.ts`: сборка diff-патча через `null` для сброса очищенных полей (`FieldPatch::Set(None)`), проверка равенства/дрейфа между нодами, подсчёт изменённых секций, автосборка симметричных `peers` из таблицы участников кластера. Покрыть unit-тестами в `serverConfigForm.test.ts`.
  - Установить `uqr` и создать `qr.ts` (+ `qr.test.ts`) и `QrCode.svelte`: генерация inline `<svg>` без `{@html}` и `data:` URI (строгий CSP `default-src 'self'`), фиксированная белая подложка `#ffffff` с тёмными модулями `#0f172a` и `quiet zone >= 4` модуля в обеих темах, `role="img"` + осмысленный `aria-label`.
  - Создать `ConfirmDialog.svelte` (нативный `<dialog>` + `showModal()`, `closedby="closerequest"`, `autofocus` строго на `Cancel`, `aria-labelledby`, сброс `returnValue = ''` в `close`, `.btn.danger` визуально отделена от `Cancel`) и `PerNodeResultPanel.svelte` (`role="status"` / `role="alert"` + кнопка **Retry failed nodes**).

- [ ] **Step 3: Страницы `Users`, `UsersTable`, `UserDrawer`, `AccessKeysModal`**

  - `UsersTable.svelte`: обернуть таблицу в `.table-wrapper` (`overflow-x: auto`, `tabindex="0"`, `role="region"`, `aria-label`); убрать пустую колонку `Created`; заменить `Access` на компактную колонку **Keys** (`SS` / `VLESS`); добавить колонку `Sync` в режиме кластера (`Synced`, `Partial`, `Drift` с раскрытием расхождений по клику); добавить кнопку **Links / QR** на каждой строке; заменить все текстовые псевдоиконки на 15px SVG (`stroke-width="2"`).
  - `UserDrawer.svelte`: отображение и перегенерация секретов во всех режимах, чекбокс «Обновить подписки после сохранения» (вкл. по умолчанию), инлайн-валидация полей на `blur` (`aria-invalid` + `aria-describedby`) с фокусом на первое невалидное поле при submit, loading-состояние кнопки сохранения, предупреждение в режиме одиночной ноды кластера.
  - `Users.svelte`: подключить `ClusterStatusStrip.svelte`, работу с кластерным/одиночным API, подтверждение удаления через `ConfirmDialog.svelte` (вместо `confirm()`), `PerNodeResultPanel.svelte` для частичных сбоев, автовызов перегенерации с `prune = true` после мутаций и кнопку **Regenerate subscriptions** в тулбаре, переход в **Show links** после создания.
  - `AccessKeysModal.svelte`: нативный `<dialog>` + `showModal()` + `closedby="any"` (с fallback `pointerdown`/`pointerup` + `getBoundingClientRect()` для Safari), 4 горизонтальные вкладки в одну строку (`Outline`, `Happ / Xray`, `App Config`, `Share Links`) с `aria-selected` и `role="tabpanel"`, понятный empty-state для недоступной подписки, `QrCode.svelte`, кнопки Copy (`Copied` на 1.5с + `aria-live="polite"`) / Download, отображение `warnings`.

- [ ] **Step 4: Страницы `Cluster.svelte`, `ServerSettings.svelte` и `RegenerateBanner.svelte`**

  - `Cluster.svelte`: выровнять иерархию заголовков (`h1` → `h2` → `h3`), добавить `ClusterStatusStrip.svelte`, кластерную карточку (`PSK match`, `shards`, `peers`, `restart_pending`), таблицу участников с автосборкой `peers`, кнопку **Rotate PSK on all nodes** (через `ConfirmDialog.svelte`), `PerNodeResultPanel.svelte`, а также режим одиночной ноды.
  - `ServerSettings.svelte`:
    - разбить все настройки на 5 горизонтальных суб-вкладок (`Carriers & Endpoints`, `Network & TLS`, `Resumption & Camouflage`, `Subscriptions`, `Tuning & System`) с сохранением `role="tablist"`/`role="tabpanel"` и без переноса строк;
    - поддержать все секции `outline-server` (включая `[[endpoint]]` CRUD, `[shadowsocks]`, `[http_root]`, `[access_keys]` с маскировкой `write_dir` как `type="password"` + show/hide, `[session_resumption]`, `[outbound]`, 11 полей `[padding]`, `[http_fallback]`, `[sni_fallback]`, `tuning_profile` + нативный `<details>` для `[tuning]` без заголовков внутри `<summary>`, read-only `[metrics]`/`[control]`);
    - в режиме кластера разделять общие поля (с интерактивным `DriftBadge.svelte` по клику и кнопкой выравнивания) и Per-node вкладки;
    - реализовать sticky save-bar (счётчик изменённых секций, `Discard`, primary `Save changes` / `Save to cluster` с loading-спиннером) и инлайн-валидацию на `blur`;
    - подключить `PerNodeResultPanel.svelte` и `RegenerateBanner.svelte` (info-режим vs warning `.applybar` при `restart_pending`, со списком нод и кнопкой **Regenerate subscriptions**).

- [ ] **Step 5: Сборка и проверка фронтенда + встроенных ассетов**

  ```bash
  pnpm -C bins/outline-ui/frontend install
  pnpm -C bins/outline-ui/frontend check
  pnpm -C bins/outline-ui/frontend exec vitest run
  pnpm -C bins/outline-ui/frontend build
  cargo build -p outline-ui --features embed-assets
  ```

---

### Этап 5: Финальная верификация, документация (EN/RU) и безопасная выкатка

**Files:**
- Modify: `bins/outline-ui/README.md`, `bins/outline-ui/README.ru.md`
- Modify: `bins/outline-server/README.md`, `bins/outline-server/README.ru.md`
- Modify: `ops/access-keys/README.md`
- Create: `ops/access-keys/README.ru.md`
- Modify: `CHANGELOG.md`, `CHANGELOG.ru.md`

- [ ] **Step 1: Обновить документацию синхронно (EN + RU)**

  - Описать новые возможности без реальных имён/доменов/путей парка (только `fleet.example`, `relay-a`/`relay-b`, `exit-a`/`exit-b`, `198.51.100.x`, `<keys-dir>`):
    - `bins/outline-ui/README.md` + `README.ru.md`: секция `[[ss.clusters]]`, кластерный режим, `GET /api/meta`, генерация ссылок и QR.
    - `bins/outline-server/README.md` + `README.ru.md`: `[[endpoint]]` CRUD в Control API, `FieldPatch` очистка полей, отпечатки секретов, `restart_pending`, настройки `[control].access_keys_*` и новые эндпоинты `/control/access-keys/regenerate`, `/control/users/{id}/access-keys`, `[access_keys].nodes`.
    - `ops/access-keys/README.md` + `README.ru.md`: `--prune` (в т.ч. 0 активных юзеров), `[access_keys].nodes`, `--json-report`, `--user --links-json`.
    - `CHANGELOG.md` + `CHANGELOG.ru.md`.

- [ ] **Step 2: Прогнать полный CI-гейт и Linux-проверку в Docker**

  - Полный локальный CI-гейт из `AGENTS.md`:
    ```bash
    cargo fmt --check -p outline-server -p outline-client -p outline-ui \
      -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
      -p outline-tun -p outline-uplink -p outline-wire \
      -p shadowsocks-crypto -p socks5-proto
    cargo clippy --workspace --exclude sockudo-ws --exclude outline-windows --all-targets --no-deps -- -D warnings
    cargo test --workspace --exclude sockudo-ws --exclude outline-windows
    cargo check -p outline-server --no-default-features
    (cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)
    PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s ops/access-keys -v
    .github/scripts/check-served-key-path.sh
    ```
  - В Linux Docker-контейнере прогнать:
    - компиляцию и тесты `outline-server` (включая `control/access_keys.rs` с реальным `python3` и проверкой прав `0640`/`www-data` в `generate_keys.py`) и `outline-ui` (`--features embed-assets`).
  - Очистить промежуточные debug-артефакты (`rm -rf target/debug`).

- [ ] **Step 3: Регламент выкатки на парк (СТРОГО после явной команды владельца)**

  - **Не выполнять автоматически до отдельного разрешения владельца!**
  - После согласования:
    1. Обновить `ops/access-keys/` на узлах (и убедиться, что в `/etc/outline-server/config.toml` прописаны `[access_keys]` `file_extension = ".conf"`, `nodes = [...]` на облачной паре и свой хост на exit-узлах, а в `[control]` — `access_keys_generator = "/opt/outline/access-keys/generate_keys.py"`).
    2. Поузлово, строго по одному узлу через `ops/deploy/deploy-binary.sh`, раскатать новый `outline-server`.
    3. Собрать `outline-ui` с `--features embed-assets` и Docker-образ с `--provenance=false --sbom=false`, обновить ConfigMap (добавить `[[ss.clusters]]`) и манифест в соседнем репозитории `<infra-repo>/ops/` и выполнить `kubectl rollout`.
    4. После финального `git push` (по команде владельца) выполнить `cargo clean`.
