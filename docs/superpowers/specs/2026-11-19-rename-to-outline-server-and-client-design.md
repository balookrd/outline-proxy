# Спецификация: Переименование `outline-ss-rust` в `outline-server` и `outline-ws-rust` в `outline-client`

## 1. Цели и область действия

Целью данной работы является унификация наименований серверного и клиентского компонентов монорепозитория `outline-proxy`:
- `outline-ss-rust` (серверный бинарь и крейт data plane) переименовывается в **`outline-server`**.
- `outline-ws-rust` (клиентский бинарь и крейт SOCKS5/TUN ingress) переименовывается в **`outline-client`**.

С момента исходного наброска спецификации (2026-11-19) в `main` произошли существенные архитектурные изменения, которые полностью учтены в данном документе:
- стабильные релизы объединены под общим CalVer-тегом `vYY.M.PATCH` (выпущен `v26.11.0`, общий `[workspace.package].version` в корневом `Cargo.toml`);
- добавлен полноценный десктопный клиент для Windows (`bins/outline-windows/`, Tauri v2 + Wintun + автоапдейтер);
- обновлён macOS-клиент (привилегированный helper `PrivilegedHelperManager.swift` и `tun-runner.sh`);
- инфраструктура K3s, `vmalert`, Alertmanager, VictoriaMetrics и скрипты деплоя дашбордов Grafana вынесены в соседний репозиторий `~/IdeaProjects/ambar`.

Область действия изменений охватывает:
1. **Дерево монорепозитория:** директории `bins/`, корневой `Cargo.toml`, алиасы `.cargo/config.toml`, манифесты и внутренний код крейтов, интеграционные и e2e-тесты, клиентские платформы (`android/`, `macos/`, `bins/outline-windows/` + `windows/`), веб-дашборд `bins/outline-ui/`.
2. **CI/CD и релизы:** гейт `.github/workflows/ci.yml`, единые релизные воркфлоу (`release.yml`, `tag-release.yml`), переименованные rolling nightly- и reusable-воркфлоу (`server-nightly-release.yml`, `client-nightly-release.yml`, `_server-release-build.yml`, `_client-release-build.yml`), скрипты `.github/scripts/`.
3. **Эксплуатационные скрипты:** `install-server.sh`, `install-client.sh`, `ops/deploy/deploy-binary.sh`, `ops/watchdog/`, `ops/access-keys/`, `ops/provision-node/`, `ops/memory-tuning/`, `ops/nanopi104-backup/`, `ops/heartbeat/`, `scripts/package-windows.sh`, `scripts/quic-initial-sink.py`.
4. **Боевой парк серверов:** автоматизированный скрипт чистой миграции `ops/deploy/migrate-node-rename.sh` и поузловой регламент выкатки на все узлы (`exit-a`, `exit-b`, `relay-a`, `relay-b`, `198.51.100.104`, `198.51.100.102`; маппинг реальных имён см. в локальном `FLEET.local.md`).
5. **Смежная инфраструктура и документация:** синхронизация репозитория `~/IdeaProjects/ambar` (деплой дашбордов Grafana, тексты алертов и k3s-скелеты) и двуязычное обновление документации (`AGENTS.md`, `CLAUDE.md`, `README*`, `PATCHES*`, `CHANGELOG*`, `docs/*`).

---

## 2. Архитектурные решения и инварианты

### 2.1. Метрики Prometheus и мониторинг
- **Префиксы метрик сохраняются:** все имена метрик Prometheus (`outline_ss_*` для сервера и `outline_ws_*` для клиента) **не меняются**. Это сохраняет непрерывность исторических временных рядов в VictoriaMetrics и работоспособность правил оповещения `vmalert` (`TargetDown`, `AllUplinksDown`, `UplinkCarrierLossHigh`). Меняются только человекочитаемые строки `HELP`/`description` (например, в `bins/outline-server/src/metrics/process_memory.rs` и `crates/outline-metrics/src/registration/core.rs`).
- **Scrape-джобы и порты сохраняются:** имена `rust-ss-exporter` (`:9090`) и `rust-ws-exporter` (`:9091`) в VictoriaMetrics и location-блоках `nginx` на узлах парка, а также порты control API (`:9190` / `:9191`) и cluster mesh (`9443/udp`) остаются неизменными.
- **Стабильные UID дашбордов Grafana:** файлы JSON-дашбордов переименовываются (`outline-server-dashboard.json`, `outline-client-dashboard.json`, `outline-client-hang-diagnostics.json`), обновляются их `title`/`description`, но поле `"uid"` (`outline-ss-rust`, `outline-ws-rust`, `outline-ws-rust-hang-diag`) сохраняется прежним, чтобы в Grafana не потерялись закладки и ссылки. Внешний скрипт деплоя дашбордов в `~/IdeaProjects/ambar/ops/grafana/dashboards/deploy.sh` обновляется синхронно до рестарта Grafana, так как провайдер на NAS работает с `disableDeletion: false`.

### 2.2. Протокольные и системные инварианты (не трогать)
- **`SYNC_SEED_CONTEXT` остаётся неизменным:** константа `const SYNC_SEED_CONTEXT: &str = "outline-ws-rust reselect-sync seed v1";` в `crates/outline-uplink/src/manager/sync_order.rs` не переименовывается. Изменение строки доменного разделения BLAKE3 заставит обновлённые и необновлённые узлы вычислять разный порядок `reselect_sync` во время поузловой раскатки.
- **Переменные окружения runtime-конфигурации и тестовых хуков сохраняются:** CLI-переменные `OUTLINE_SS_*` (в `cli.rs`), `OUTLINE_SS_TEST_WS_KEEPALIVE_SECS` и `OUTLINE_WS_TEST_TLS_CA_DER` не переименовываются, чтобы не ломать существующие drop-in переопределения и окружение. Для Windows-контроллера процесса поддерживается только новое имя `OUTLINE_CLIENT_BIN` (или fallback на переименованную функцию `find_outline_client_binary`).
- **Единый провайдер `rustls`:** только `aws-lc-rs` без `ring`-провайдера в `rustls`, гейты vendored API остаются за модулями `crates/outline-transport/src/{h3/vendored,quic/vendored,tls_vendored,hyper_vendored}.rs` и `bins/outline-server/src/server/h3/vendored.rs`.
- **Аллокатор:** весь парк работает строго на `jemalloc`, на aarch64 Linux закреплена страница 4 КиБ (`*_JEMALLOC_SYS_WITH_LG_PAGE = "12"`), в `MALLOC_CONF` остаётся `calloc_madvise_threshold:0`.
- **Конфигурационные модели:** на сервере сохраняется строгая модель `[[endpoint]]` без `[dashboard]`; на клиенте — либо одиночный `username`/`password`, либо `[[socks5.users]]`.

### 2.3. Стратегия чистой миграции на хостах боевого парка (без симлинков)
- Принята стратегия **чистой замены без создания постоянных симлинков и systemd `Alias=`**:
  - бинари: `/usr/local/bin/outline-server` и `/usr/local/bin/outline-client`;
  - каталоги конфигурации: `/etc/outline-server/` и `/etc/outline-client/` (права `0750` на директорию, `0640` на файлы);
  - каталоги состояния и логов: `/var/lib/outline-server/`, `/var/lib/outline-client/`, `/var/log/outline-client/`;
  - systemd-юниты: `outline-server.service`, `outline-client.service`, `outline-client@.service`, а также drop-in каталоги `outline-server.service.d/`, `outline-client.service.d/` и активные инстансы `outline-client@*.service`;
  - watchdog-таймеры: `outline-watchdog@outline-server.timer`, `outline-watchdog@outline-client.timer`;
  - системные пользователи и группы ОС: `outline-server:outline-server` (с обязательным сохранением членства в дополнительной группе `certs` для чтения TLS-сертификатов) и `outline-client:outline-client` (переименование из `outline-ws` через `groupmod`/`usermod`).
- **Переписывание сопутствующих артефактов на хостах:** чистый перенос без симлинков требует, чтобы при миграции узла также обновлялись:
  1. Абсолютные пути внутри `/etc/outline-client/config.toml` (например, `domains-main.list`, `domains-russia.list` с `/etc/outline-ws-rust/` на `/etc/outline-client/`) и в `STATE_PATH`/drop-in-файлах `*.service.d/*.conf`.
  2. Ссылка `Before=outline-ws-rust.service` / `Before=outline-ss-rust.service` внутри `/etc/systemd/system/post-up.service`.
  3. Скрипты генерации ключей на узлах (`/opt/outline/outline-ss-rust/save-keys.sh` и установленный рядом `generate_keys.py` или переход на пути `/etc/outline-server/config.toml` и группу `outline-server`), скрипты прав на сертификаты (`/opt/ddns/*/permission-certs.sh`, если ссылаются на старого юзера) и `/etc/default/nanopi104-backup` на `.104`.
  4. Старые юниты, старые watchdog-таймеры и старые бинари в `/usr/local/bin/` удаляются только после успешного запуска новых служб и прохождения проверки `/metrics` HTTP 200.

### 2.4. Схема релизов CalVer `vYY.M.PATCH` и алиасы Cargo
- **Стабильные релизы сохраняются едиными CalVer (`vYY.M.PATCH`):** `.github/workflows/release.yml` и `.github/workflows/tag-release.yml` не возвращаются к схеме `server-v*`/`client-v*`. После переименования единый релиз `vYY.M.PATCH` публикует архивы `outline-server-<ver>-<target>.tar.gz` и `outline-client-<ver>-<target>.tar.gz` вместе с `outline-ui-*.tar.gz`, APK, macOS DMG и Windows ZIP.
- **Rolling nightly-релизы и теги:** `ss-nightly-release.yml` → `server-nightly-release.yml` (rolling-тег `server-nightly`), `ws-nightly-release.yml` → `client-nightly-release.yml` (rolling-тег `client-nightly`). Старые rolling-теги и пререлизы `ss-nightly`/`ws-nightly` удаляются вручную после первого зелёного прогона новых воркфлоу.
- **Инсталляторы `install-server.sh` и `install-client.sh`:** по умолчанию тянут `/releases/latest` (CalVer `v*`), а для `CHANNEL=nightly` используют `NIGHTLY_TAG="server-nightly"` / `"client-nightly"` (без возврата `TAG_PREFIX="ss-"`/`"ws-"`). Поддержка исторических CalVer-тегов `v*` и проверка байтовой идентичности общих helper-функций через `.github/scripts/check-install-scripts.sh` сохраняются.
- **Алиасы сборки в `.cargo/config.toml`:** полная замена `ss-build-musl-*` / `ss-release-musl-*` → `server-build-musl-*` / `server-release-musl-*`, `ws-release-musl-*` → `client-release-musl-*` без сохранения старых алиасов.

---

## 3. Детализация изменений по компонентам

### 3.1. Структура Cargo Workspace, крейты и Rust-код
- Переименование директорий: `bins/outline-ss-rust/` → `bins/outline-server/`, `bins/outline-ws-rust/` → `bins/outline-client/`.
- Корневой `Cargo.toml`: обновление `members`, сохранение `--exclude sockudo-ws --exclude outline-windows` в CI/командах.
- `.cargo/config.toml`: новые алиасы `server-{build,release}-musl-{x86_64,aarch64,arm,armv7}` и `client-release-musl-{x86_64,aarch64}`.
- Пакеты: `bins/outline-server/Cargo.toml` (`name = "outline-server"`), `bins/outline-client/Cargo.toml` (`name = "outline-client"`), обновление `Cargo.lock`.
- Код бинарей и крейтов:
  - `bins/outline-server/src/`: `main.rs` (`outline_server::run()`), `lib.rs` (`EnvFilter` `outline_server=info,tower_http=info`), `config/cli.rs` (`name = "outline-server"`), `config/loader.rs` (`parse_from(["outline-server"])`), `config/tests/control.rs`, `metrics/process_memory.rs` (текст HELP), `server/control/tests/persist.rs`, `server/tests/{mod,sni_fallback}.rs` и комментарии в `server/tests/cross_repo_*.rs` / `resumption/*`.
  - `bins/outline-client/src/`: `main.rs` (`use outline_client::...`, `EnvFilter` `"info,outline_client=debug"`), `lib.rs` (doc-комментарий), `proxy/tcp/session.rs` (`target: "outline_client::session_death"`).
  - `crates/`: `outline-metrics/src/registration/core.rs` (`"Build info for outline-client."`), `outline-transport/src/{frame_io_ws,tcp_transport/reader/transport,tcp_transport/writer/mod}.rs` (`target: "outline_client::..."`), `outline-tun/src/tcp/engine/tests/mod.rs` (имена временных файлов), doc-комментарии по всем крейтам (`crates/outline-uplink/src/manager/sync_order.rs` — строку `SYNC_SEED_CONTEXT` не менять!).
  - Тесты e2e клиента: `bins/outline-client/tests/support/server_process.rs` (`CARGO_BIN_EXE_outline-client`, `outline-server`, `cargo build -p outline-server --features test-hooks`, `RUST_LOG="info,outline_server=debug"`), `proxy_test_utils.rs` (`CARGO_BIN_EXE_outline-client`), `standby_validation.rs`, `e2e_*.rs`.

### 3.2. Клиентские платформы и Web-UI
- **Android (`android/`):**
  - `android/rust/Cargo.toml`: зависимость `outline-client = { path = "../../bins/outline-client", default-features = false, features = ["h3", "tun"] }`, перегенерация `android/rust/Cargo.lock`.
  - `android/rust/src/lib.rs`: `use outline_client::...`, `Args::try_parse_from(["outline-client", ...])`, обновление логов.
  - `android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt`: лог запуска `outline-client`.
- **macOS (`macos/`):**
  - `PrivilegedHelperManager.swift` и `tun-runner.sh`: замена `systemBinaryPath`/`SYSTEM_BIN` на `/Library/Application Support/OutlineProxy/outline-client`, а при `installSudoersRule()` и `removeSudoersRule()` удаление возможного остаточного файла `/Library/Application Support/OutlineProxy/outline-ws-rust` от предыдущих версий приложения.
  - `ProcessController.swift`, `ConfigGenerator.swift`, `UpdateChecker.swift`: поиск, запуск и логирование `outline-client`.
  - `macos/scripts/package-app.sh` и `package-dmg.sh`: сборка `-p outline-client` и упаковка `Contents/Resources/outline-client`.
- **Windows (`bins/outline-windows/`, `windows/`, `scripts/package-windows.sh`):**
  - `bins/outline-windows/src/process_controller.rs` и `src/tests/process_controller.rs`: `find_outline_client_binary()`, переменная `OUTLINE_CLIENT_BIN`, бинарник `outline-client.exe` / `outline-client`.
  - `bins/outline-windows/src/updater.rs`: в сгенерированном batch-скрипте обновления после копирования новых файлов очищать устаревший `%TARGET_DIR%\outline-ws-rust.exe` (`del /F /Q "%TARGET_DIR%\outline-ws-rust.exe" >NUL 2>&1`), чтобы апдейт с `v26.11.0` не оставлял мусора.
  - `bins/outline-windows/src/config_generator.rs`, `frontend/src/App.svelte`, `scripts/package-windows.sh` (сборка `-p outline-client`, упаковка `outline-client.exe`), `windows/README*.md`, `bins/outline-windows/{README,CHANGELOG}*.md`.
- **Web-UI (`bins/outline-ui/`):**
  - `Dockerfile`, `frontend/src/features/{ss/ServerSettings,ws/WsSettings,ws/RouteDrawer,ws/UplinkDrawer}.svelte`, `frontend/src/lib/{groupForm,types,uplinkForm,uplinkForm.test,userForm,wsTopology,wsTopology.test}.ts`, `src/ws/tests/mod.rs`, `README*.md`.

### 3.3. Инсталляторы и эксплуатационные скрипты (`ops/`, `scripts/`)
- **`install-server.sh`:** `BINARY_NAME="outline-server"`, `NIGHTLY_TAG="server-nightly"`, `SERVICE_NAME="outline-server.service"`, `CONFIG_DIR="/etc/outline-server"`, `STATE_DIR="/var/lib/outline-server"`, `SERVICE_USER="outline-server"`, `SERVICE_GROUP="outline-server"`, `BIN_SUBDIR="bins/outline-server"`.
- **`install-client.sh`:** `BINARY_NAME="outline-client"`, `NIGHTLY_TAG="client-nightly"`, `SERVICE_NAME="outline-client.service"`, `TEMPLATE_NAME="outline-client@.service"`, `CONFIG_DIR="/etc/outline-client"`, `STATE_DIR="/var/lib/outline-client"`, `SERVICE_USER="outline-client"`, `SERVICE_GROUP="outline-client"`, `BIN_SUBDIR="bins/outline-client"`. При правке общих helper-функций соблюдается байтовая идентичность для `.github/scripts/check-install-scripts.sh`.
- **`ops/deploy/deploy-binary.sh`:** допустимые `<unit>` — `outline-server` (`PORT=9090`) и `outline-client` (`PORT=9091`).
- **`ops/watchdog/outline-watchdog` и `install.sh`:** маршрутизация `outline-client*` → `:9091/metrics`, `outline-server*` → `:9090/metrics`; цикл установки по `outline-client outline-server`.
- **`ops/access-keys/`:** `DEFAULT_CONFIG = "/etc/outline-server/config.toml"` в `generate_keys.py`, заголовки `# outline-client client config for the Android app.` в `ws_toml.py`, обновление `golden/` и комментариев в `config_model.py`, `xray_json.py`, `nginx-subscription-headers.conf`, `README.md`.
- **`ops/provision-node/`:** обновление `collect-from-reference.sh`, `install.sh` (пользователи `outline-server`, `outline-client`, каталоги `/etc/outline-{server,client}`, `/var/lib/outline-{server,client}`, `/var/log/outline-client`, drop-in `20-memory.conf`, `Before=`), `register-uplink-user.sh`, профилей `profiles/cloud1.conf` и `profiles/nuxt.conf`.
- **Прочие скрипты:** `ops/memory-tuning/apply.sh` (строки `apply_unit` на `outline-client` и `outline-server`), `ops/nanopi104-backup/{backup-p9.sh,nanopi104-backup.default}`, `ops/heartbeat/{heartbeat-watch,install.sh,nginx-heartbeat.conf}`, `scripts/quic-initial-sink.py`.

### 3.4. CI/CD (GitHub Actions)
- `.github/workflows/ci.yml`: пакеты `rustfmt`, `cargo test -p outline-client --features test-tls --test 'e2e_*'`, `cargo check -p outline-server` / `outline-client`, пути `^bins/outline-server/src/server/h3/vendored\.rs:` в обоих vendored-гейтах.
- `.github/workflows/release.yml`: список `workspace_packages` (`"outline-server"`, `"outline-client"` вместо старых) и `required_android_pkgs = {"outline-android", "outline-client"}`.
- `.github/workflows/tag-release.yml`: вызов `_server-release-build.yml` и `_client-release-build.yml`, проверка ассетов `dist/outline-server-*.tar.gz` и `dist/outline-client-*.tar.gz`.
- Переименование воркфлоу (`git mv`):
  - `_ss-release-build.yml` → `_server-release-build.yml` (алиасы `server-release-musl-*`, артефакт `outline-server-...`, компонент `server`);
  - `_ws-release-build.yml` → `_client-release-build.yml` (передача `flavor: client`, вызов `gen-release-notes.sh client`);
  - `ss-nightly-release.yml` → `server-nightly-release.yml` (пути `bins/outline-server/**`, тег `server-nightly`);
  - `ws-nightly-release.yml` → `client-nightly-release.yml` (пути `bins/outline-client/**`, тег `client-nightly`).
- Обновление триггеров путей (`bins/outline-client/**`) в `android-nightly-release.yml`, `macos-nightly-release.yml`, `windows-nightly-release.yml`, комментариев в `_windows-release-build.yml`.
- `.github/scripts/build-release-asset.sh` (`binary_name="outline-client"`, `flavor=client`, `-p outline-client`) и `.github/scripts/gen-release-notes.sh` (компоненты `server|client`, исторические префиксы в якоре первого CalVer-релиза сохраняются только как git-тег-маска, пути `bins/outline-server`, `bins/outline-client`).

### 3.5. Синхронизация соседнего репозитория `~/IdeaProjects/ambar`
- `~/IdeaProjects/ambar/ops/grafana/dashboards/deploy.sh`: заменить `$bins_dir/outline-ss-rust/grafana/*.json` и `outline-ws-rust/grafana/*.json` на `outline-server/grafana/*.json` и `outline-client/grafana/*.json`.
- `~/IdeaProjects/ambar/ops/alerting/vmalert/rules.yaml`, `tests/uplink.yaml`, `ops/grafana/dashboards/outline-alerting.json`: обновить тексты `summary`/`description` (`outline-client restarted...`), оставив PromQL-выражения и `job`-лейблы (`outline_ws_*`, `rust-ws-exporter`, `rust-ss-exporter`) без изменений.
- `~/IdeaProjects/ambar/ops/nanopi-r5c-k3s/apps/outline/`: переименовать скелеты манифестов и их `README.md` на `outline-server.daemonset.yaml` и `outline-client.deployment.yaml`.

### 3.6. Двуязычная документация
- Обновляются пары `*.md` / `*.ru.md` в одном изменении: корневые `README*`, `CHANGELOG*`, `PATCHES*`, `AGENTS.md`, `CLAUDE.md`, документация обоих бинарей (`bins/outline-server/`, `bins/outline-client/`), `docs/{CLUSTER,CLUSTER-DEPLOY,CODE-INDEX,OUTBOUND-IPV6,PADDING}*.md`, `android/README*.md`, `macos/README*.md`, `windows/README*.md`, `bins/outline-{ui,windows}/{README,CHANGELOG}*.md`, `scripts/fingerprint-drift/README*.md`, `ops/**/README*.md`.

---

## 4. Скрипт миграции узла парка (`ops/deploy/migrate-node-rename.sh`)

Для безопасной чистой миграции узлов создаётся и документируется в `ops/deploy/README.md` скрипт `ops/deploy/migrate-node-rename.sh <host> <role> [--audit | --dry-run]`, где `<role>` — `server`, `client` или `all`:

1. **SSH и аудит (`--audit`, `--dry-run`):**
   - Используется единое SSH-соединение через `ControlMaster=auto` + `ControlPersist=60`, чтобы не спровоцировать `sshguard` серией подключений.
   - В режиме `--audit` скрипт в read-only режиме выводит наличие старых/новых юнитов, инстансов `@*.service`, drop-in `*.service.d/`, пользователей/групп (включая доп. группы, такие как `certs`), содержимое `post-up.service`, ссылки внутри `/etc/outline-*/config.toml`, пути `/opt/outline/.../save-keys.sh` и `/etc/default/nanopi104-backup`.
   - В режиме `--dry-run` проверяется совместимость архитектуры и наличие локальных бинарей, а на удалённом хосте печатается план действий без изменений.
2. **Локальная подготовка и перенос файлов:**
   - Проверка `file -b` против `uname -m` на узле, подсчёт SHA-256 бинарей `outline-server` / `outline-client`, передача новых бинарей, systemd-юнитов и `ops/watchdog/outline-watchdog` во временную staging-директорию `/tmp/outline-rename-stage.$$` через `scp` с проверкой контрольной суммы.
3. **Снимок отката (Rollback State):**
   - Копирование текущих бинарей `/usr/local/bin/outline-{ss,ws}-rust`, каталогов `/etc/outline-{ss,ws}-rust`, `/etc/systemd/system/outline-{ss,ws}-rust*`, `post-up.service` и списка пользователей/групп во временный снимок `/var/tmp/outline-rename-rollback.<ts>` (сохранённый с правами `0700` на случай сбоя или аварийного восстановления).
4. **Остановка старых служб:**
   - Остановка и disable `outline-watchdog@outline-{ss,ws}-rust.timer`, `outline-ss-rust.service`, `outline-ws-rust.service` и всех инстансов `outline-ws-rust@*.service`.
5. **Миграция пользователей и групп ОС:**
   - Сервер: переименование группы `outline-ss-rust` → `outline-server`, затем `usermod -l outline-server -d /var/lib/outline-server outline-ss-rust` (с сохранением доп. группы `certs`, при необходимости `usermod -aG certs outline-server`).
   - Клиент: переименование группы `outline-ws` → `outline-client`, затем `usermod -l outline-client -d /var/lib/outline-client outline-ws`.
6. **Перемещение каталогов, drop-in'ов и прав:**
   - `/etc/outline-ss-rust` → `/etc/outline-server`, `/var/lib/outline-ss-rust` → `/var/lib/outline-server`.
   - `/etc/outline-ws-rust` → `/etc/outline-client`, `/var/lib/outline-ws-rust` → `/var/lib/outline-client`, `/var/log/outline-ws-rust` → `/var/log/outline-client` (при наличии).
   - Drop-in каталоги `/etc/systemd/system/outline-ss-rust.service.d` → `outline-server.service.d`, `outline-ws-rust.service.d` → `outline-client.service.d`, обновление ссылок внутри drop-in (если встречаются `outline-ws-rust`/`outline-ss-rust`).
   - Обновление путей внутри `/etc/outline-client/config.toml` (`/etc/outline-ws-rust/` → `/etc/outline-client/`) и `/etc/outline-server/config.toml` (`/etc/outline-ss-rust/` → `/etc/outline-server/`), строго сохраняя права `0750` на директории и `0640` на конфиги с владельцами `outline-server:outline-server` и `outline-client:outline-client`.
   - Обновление сопутствующих хостовых файлов (если присутствуют): `Before=` в `/etc/systemd/system/post-up.service`, конфиг-путь/владелец в `/opt/outline/outline-ss-rust/save-keys.sh` и локальном `generate_keys.py` (если скопирован на узел), упоминания юзера в `/opt/ddns/*/permission-certs.sh`, `SERVICE=` в `/etc/default/nanopi104-backup`.
7. **Установка новых бинарников и юнитов, удаление старых:**
   - Установка `/usr/local/bin/outline-server`, `/usr/local/bin/outline-client`, `/usr/local/sbin/outline-watchdog`, юнитов `outline-server.service`, `outline-client.service`, `outline-client@.service`.
   - Удаление старых юнитов `/etc/systemd/system/outline-{ss,ws}-rust*.service` и старых бинарей `/usr/local/bin/outline-{ss,ws}-rust` (+ ротация/очистка по явному флагу или сохранение снимка отката отдельно).
   - `systemctl daemon-reload`.
8. **Запуск, верификация и автооткат:**
   - `systemctl enable --now` для новых служб и watchdog-таймеров `outline-watchdog@outline-{server,client}.timer`.
   - Опрос `http://127.0.0.1:9090/metrics` и `http://127.0.0.1:9091/metrics` до 15 попыток (HTTP 200 OK) + проверка `systemctl is-active`.
   - При любом отказе — полный автоматический откат из `/var/tmp/outline-rename-rollback.<ts>` с восстановлением старых пользователей, каталогов, бинарников, юнитов и перезапуском прежних служб.

---

## 5. Порядок раскатки на боевом парке

Раскатка выполняется строго по одному узлу за раз и только после явного разрешения владельца на каждый узел:

```text
[Фаза 1: Локальная сборка musl-бинарников]
  ├── cargo server-release-musl-x86_64   && cargo server-release-musl-aarch64
  └── cargo client-release-musl-x86_64   && cargo client-release-musl-aarch64

[Фаза 2: Синхронизация ~/IdeaProjects/ambar (до рестартов/деплоя дашбордов)]
  └── Обновление ops/grafana/dashboards/deploy.sh, алертов и k3s-скелетов

[Фаза 3: Exit-узлы (только outline-server)]
  ├── 1. exit-a (x86_64)  -> migrate-node-rename.sh <host> server --audit -> apply
  └── 2. exit-b (x86_64)  -> migrate-node-rename.sh <host> server --audit -> apply

[Фаза 4: Промежуточные узлы (relay/mesh, оба сервиса)]
  ├── 3. relay-a (x86_64) -> migrate-node-rename.sh <host> all --audit -> apply
  │      └── Проверка mesh cluster 9443/udp и reselect_sync
  └── 4. relay-b (x86_64) -> migrate-node-rename.sh <host> all --audit -> apply
         └── Проверка парного кластера и скриптов save-keys.sh / heartbeat-watch

[Фаза 5: Домашние входные узлы (Ingress, оба сервиса)]
  ├── 5. 198.51.100.104 (aarch64) -> migrate-node-rename.sh <host> all --audit -> apply
  │      └── Проверка TUN/VRF, 4 KiB jemalloc page и nanopi104-backup
  └── 6. 198.51.100.102 (x86_64)  -> migrate-node-rename.sh <host> all --audit -> apply
         └── Проверка SOCKS5/TUN и VRF

[Фаза 6: Пост-миграционные действия]
  ├── Проверка VictoriaMetrics, Grafana (деплой обновлённых JSON) и vmalert (OK)
  ├── Обновление некоммитируемых FLEET.local.md и MEMORY.md
  ├── После первого зелёного прогона server-nightly/client-nightly — удаление старых ss-nightly/ws-nightly на GitHub
  └── Очистка артефактов сборки (`cargo clean`) после финального push
```

---

## 6. Критерии приёмки (Verification Criteria)

1. **Rust lint-гейт и тесты workspace:**
   - `cargo fmt --check -p outline-server -p outline-client -p outline-ui -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto`
   - `cargo clippy --workspace --exclude sockudo-ws --exclude outline-windows --all-targets --no-deps -- -D warnings`
   - `(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)`
   - `cargo test --workspace --exclude sockudo-ws --exclude outline-windows`
   - `RUN_E2E_FAILOVER=1 cargo test -p outline-client --features test-tls --test 'e2e_*' -- --test-threads=1`
2. **Матрица фич, инварианты монорепо и Linux Docker:**
   - `cargo check -p outline-server --no-default-features`, `cargo check -p outline-server --features test-hooks`, `cargo check -p outline-client --no-default-features`.
   - Проверка всех инвариантов из `.github/workflows/ci.yml` (`aws-lc-rs`, vendored-гейты `sockudo_ws`/`quinn-proto`/`rustls`/`hyper`, `.github/scripts/check-install-scripts.sh`, `.github/scripts/check-served-key-path.sh`).
   - Проверка сборки и тестов Linux-специфики (`#[cfg(target_os = "linux")]`, jemalloc page check, `malloc_conf_reaches_jemalloc`) в Docker-контейнере до коммита/пуша.
3. **Клиентские платформы, Web-UI и скрипты:**
   - `pnpm -C bins/outline-ui/frontend` (`svelte-check`, `vitest run`, `build`) и `cargo build -p outline-ui --features embed-assets`.
   - `./macos/scripts/package-app.sh` (наличие `Contents/Resources/outline-client` в бандле).
   - `pnpm -C bins/outline-windows` (`svelte-check`/сборка) и проверка Windows-таргета (в CI job `windows` / локально).
   - `PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s ops/access-keys` и `shellcheck` на всех изменённых shell-скриптах.
4. **Боевой парк:**
   - Все узлы работают под юнитами `outline-server` и `outline-client` без остаточных юнитов/бинарников `outline-ss-rust`/`outline-ws-rust`.
   - Метрики `rust-ss-exporter` и `rust-ws-exporter` поступают в VictoriaMetrics без разрывов, дашборды Grafana открываются по старым UID, `vmalert` без новых инцидентов.
