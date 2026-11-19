# Спецификация: Переименование outline-ss-rust в outline-server и outline-ws-rust в outline-client

## 1. Цели и область действия

Целью данной работы является унификация наименований серверного и клиентского компонентов монорепозитория `outline-proxy`:
- `outline-ss-rust` (серверный бинарник и крейт data plane) переименовывается в **`outline-server`**.
- `outline-ws-rust` (клиентский бинарник и крейт SOCKS5/TUN ingress) переименовывается в **`outline-client`**.

Область действия изменений охватывает:
1. Дерево монорепозитория: директории `bins/`, манифесты `Cargo.toml`, имена пакетов, алиасы кросс-компиляции, тесты, клиентские платформы (`macos/`, `android/`), сервис дашборда `bins/outline-ui/`.
2. CI/CD автоматизацию: рабочие процессы GitHub Actions, скрипты сборки релизов, схему тегов релизов (`server-v*` и `client-v*`).
3. Эксплуатационные скрипты: `ops/deploy/deploy-binary.sh`, `ops/watchdog/`, `ops/access-keys/`, `ops/provision-node/`, `install-server.sh`, `install-client.sh`.
4. Боевой парк серверов: поузловой регламент и автоматизированный скрипт чистой миграции (без симлинков) системных пользователей, групп, каталогов `/etc` и `/var/lib`, бинарников в `/usr/local/bin` и systemd-юнитов на всех узлах (`nuxt`, `nuxt2`, `cloud1`, `cloud2`, `.102`, `.104`).
5. Документацию: синхронное обновление всех руководств и спецификаций на английском и русском языках (`AGENTS.md`, `README*`, `CHANGELOG*`, `docs/*`).

---

## 2. Архитектурные решения и инварианты

### 2.1. Метрики Prometheus и мониторинг
- **Префиксы метрик:** Сохраняются в неизменном виде (`outline_ss_*` для сервера и `outline_ws_*` для клиента). Это гарантирует непрерывность исторических временных рядов в VictoriaMetrics, сохраняет работоспособность правил оповещения в `ops/alerting/vmalert/rules.yaml` (например, `TargetDown`, `AllUplinksDown`, `UplinkCarrierLossHigh`) и не требует массовой модификации дашбордов Grafana.
- **Scrape-джобы:** Имена `rust-ss-exporter` (порт 9090) и `rust-ws-exporter` (порт 9091) в `ops/nas-monitoring/victoria-metrics/scrape.yaml` и конфигурациях nginx на узлах сохраняются без изменений.

### 2.2. Стратегия миграции на хостах боевого парка (Чистая замена)
- Принята стратегия **чистой замены без создания постоянных симлинков**:
  - Каталоги конфигурации: `/etc/outline-server/` и `/etc/outline-client/`.
  - Каталоги рабочего состояния: `/var/lib/outline-server/` и `/var/lib/outline-client/`.
  - Бинарники: `/usr/local/bin/outline-server` и `/usr/local/bin/outline-client`.
  - Юниты systemd: `outline-server.service`, `outline-client.service`, `outline-client@.service`.
  - Watchdog-таймеры: `outline-watchdog@outline-server.timer`, `outline-watchdog@outline-client.timer`.
  - Пользователи и группы ОС: `outline-server:outline-server` (для сервера) и `outline-client:outline-client` (для клиента).
  - Старые юниты останавливаются и удаляются; старые бинарники и каталоги перемещаются/удаляются после подтверждения успешного старта новых служб.

### 2.3. Релизные теги и алиасы Cargo
- Старые теги `ss-*` и `ws-*` заменяются на `server-*` (например, `server-v1.9.3`) и `client-*` (например, `client-v1.9.3`).
- Алиасы в `.cargo/config.toml` полностью переводятся на новые имена (`server-release-musl-*`, `client-release-musl-*` и соответствующие `*-build-*`) без сохранения устаревших алиасов `ss-*` / `ws-*`.

---

## 3. Детализация изменений в компонентах

### 3.1. Структура крейтов и Cargo Workspace
- Перемещение каталогов:
  - `bins/outline-ss-rust/` $\to$ `bins/outline-server/`
  - `bins/outline-ws-rust/` $\to$ `bins/outline-client/`
- Корневой `Cargo.toml`:
  - `members`: замена `"bins/outline-ss-rust"` $\to$ `"bins/outline-server"`, `"bins/outline-ws-rust"` $\to$ `"bins/outline-client"`.
- Манифесты пакетов:
  - `bins/outline-server/Cargo.toml`: `name = "outline-server"`.
  - `bins/outline-client/Cargo.toml`: `name = "outline-client"`.
- Зависимости между компонентами:
  - `android/rust/Cargo.toml`: замена зависимости `outline-ws-rust = { path = "../../bins/outline-client", ... }`.
  - Тестовые утилиты: `bins/outline-client/tests/support/server_process.rs` (сборка и запуск `-p outline-server`), `bins/outline-client/tests/support/proxy_test_utils.rs` (`CARGO_BIN_EXE_outline-client`).

### 3.2. Клиентские платформы и UI
- **macOS (`macos/`):**
  - Обновление Swift-сервисов (`ProcessController.swift`, `ConfigGenerator.swift`), скрипта `tun-runner.sh`.
  - Обновление сборочных скриптов `package-app.sh` и `package-dmg.sh` для компиляции `outline-client` и упаковки бинарника в бандл `Contents/Resources/outline-client`.
- **Android (`android/`):**
  - Манифест `android/rust/Cargo.toml`, обертка `android/rust/src/lib.rs` (`outline_client::config::Args...`).
  - Класс службы Kotlin `OutlineVpnService.kt` (логирование и запуск `outline-client`).
- **Web-UI (`bins/outline-ui/`):**
  - `Dockerfile`: комментарии и команды сборки.
  - Svelte-компоненты: всплывающие уведомления при сохранении настроек ("Restart outline-server...", "Restart outline-client...").
  - Документация сервиса (`README.md`, `README.ru.md`).

### 3.3. Эксплуатационные скрипты (`ops/` и корень)
- **`ops/deploy/deploy-binary.sh`:**
  - Поддержка параметров `UNIT`: `outline-server` (порт метрик 9090) и `outline-client` (порт метрик 9091).
- **`ops/watchdog/outline-watchdog` и `ops/watchdog/install.sh`:**
  - Маршрутизация проверок метрик по имени юнита: `outline-server*` $\to$ `9090`, `outline-client*` $\to$ `9091`.
  - Таймеры: `outline-watchdog@outline-server.timer`, `outline-watchdog@outline-client.timer`.
- **`install-server.sh`:**
  - `BINARY_NAME="outline-server"`, `TAG_PREFIX="server-"`, `SERVICE_NAME="outline-server.service"`.
  - `CONFIG_DIR="/etc/outline-server"`, `STATE_DIR="/var/lib/outline-server"`.
  - `SERVICE_USER="outline-server"`, `SERVICE_GROUP="outline-server"`.
- **`install-client.sh`:**
  - `BINARY_NAME="outline-client"`, `TAG_PREFIX="client-"`, `SERVICE_NAME="outline-client.service"`.
  - `CONFIG_DIR="/etc/outline-client"`, `STATE_DIR="/var/lib/outline-client"`.
  - `SERVICE_USER="outline-client"`, `SERVICE_GROUP="outline-client"`.
- **`ops/access-keys/`:**
  - `generate_keys.py`: `DEFAULT_CONFIG = "/etc/outline-server/config.toml"`.
  - `ws_toml.py`: генерация заголовков и комментариев для `outline-client`.
  - `config_model.py`, `README.md`, golden-файлы.
- **`ops/provision-node/`:**
  - Профили `profiles/cloud1.conf` и `profiles/nuxt.conf`: пути бинарников, юниты, директории конфигурации, переменные `NET_BRINGUP_BEFORE`.
  - Скрипты `collect-from-reference.sh`, `install.sh`, `register-uplink-user.sh`.
- **`ops/nanopi-r5c-k3s/apps/outline/`:**
  - Переименование скелетов манифестов в `outline-server.daemonset.yaml` и `outline-client.deployment.yaml`, обновление содержимого.

### 3.4. CI/CD (GitHub Actions)
- Переименование рабочих процессов:
  - `.github/workflows/ss-release.yml` $\to$ `.github/workflows/server-release.yml`
  - `.github/workflows/ss-nightly-release.yml` $\to$ `.github/workflows/server-nightly-release.yml`
  - `.github/workflows/_ss-release-build.yml` $\to$ `.github/workflows/_server-release-build.yml`
  - `.github/workflows/ws-release.yml` $\to$ `.github/workflows/client-release.yml`
  - `.github/workflows/ws-nightly-release.yml` $\to$ `.github/workflows/client-nightly-release.yml`
- Обновление триггеров путей (`bins/outline-server/**`, `bins/outline-client/**`), имен релизных артефактов и тегов.
- Обновление основного гейта `.github/workflows/ci.yml`:
  - Шаги форматирования и clippy с новыми именами пакетов.
  - e2e тесты: `cargo test -p outline-client --features test-tls --test 'e2e_*'`.
  - Проверки фич `--no-default-features` для `outline-server` и `outline-client`.

---

## 4. Скрипт миграции узла парка (`ops/deploy/migrate-node-rename.sh`)

Для автоматизации чистой миграции узлов создается скрипт `ops/deploy/migrate-node-rename.sh <host> <role>`, где `<role>` принимает значения `server`, `client` или `all` (`server+client`):

1. **Предварительные проверки:**
   - Доступность узла по SSH.
   - Определение архитектуры хоста (`x86_64` или `aarch64`).
   - Наличие локально собранных бинарников нужной архитектуры в `target/<arch>/release/outline-server` и `outline-client`.
   - Проверка контрольных сумм SHA-256 передаваемых бинарников и unit-файлов.
2. **Создание снимка отката (Rollback State):**
   - Сохранение текущих бинарников, unit-файлов и конфигов во временную директорию отката `/tmp/rename-backup-<timestamp>`.
3. **Остановка сервисов:**
   - Остановка watchdog-таймеров (`outline-watchdog@outline-ss-rust.timer`, `outline-watchdog@outline-ws-rust.timer`).
   - Остановка служб `outline-ss-rust.service`, `outline-ws-rust.service` (или `outline-ws-rust@*.service`).
4. **Миграция системных пользователей и групп:**
   - Если существует пользователь `outline-ss-rust`:
     `groupmod -n outline-server outline-ss-rust || true`
     `usermod -l outline-server -g outline-server -d /var/lib/outline-server outline-ss-rust`
   - Если существует пользователь `outline-ws`:
     `groupmod -n outline-client outline-ws || true`
     `usermod -l outline-client -g outline-client -d /var/lib/outline-client outline-ws`
5. **Миграция файловых каталогов и прав:**
   - Перемещение каталогов конфигурации (`mv /etc/outline-ss-rust /etc/outline-server`, `mv /etc/outline-ws-rust /etc/outline-client`).
   - Перемещение каталогов данных (`mv /var/lib/outline-ss-rust /var/lib/outline-server`, `mv /var/lib/outline-ws-rust /var/lib/outline-client`).
   - Корректировка владельцев: `chown -R outline-server:outline-server /etc/outline-server /var/lib/outline-server` (и аналогично для `outline-client`).
6. **Установка новых бинарников и служб:**
   - Установка бинарников в `/usr/local/bin/outline-server` (0755 root:root) и `/usr/local/bin/outline-client`.
   - Установка новых unit-файлов в `/etc/systemd/system/`:
     - `outline-server.service`
     - `outline-client.service` (и шаблона `outline-client@.service` при необходимости).
   - Установка обновленного `outline-watchdog` в `/usr/local/sbin/outline-watchdog`.
   - Удаление старых unit-файлов (`outline-ss-rust.service`, `outline-ws-rust.service`, старых watchdog-таймеров).
   - Удаление старых бинарников `/usr/local/bin/outline-ss-rust`, `/usr/local/bin/outline-ws-rust`.
   - `systemctl daemon-reload`.
7. **Запуск и валидация:**
   - Включение и запуск новых служб: `systemctl enable --now outline-server` (и/или `outline-client`).
   - Включение новых watchdog-таймеров: `systemctl enable --now outline-watchdog@outline-server.timer` (и/или `@outline-client.timer`).
   - Проверка работоспособности: опрос `curl -s -m 5 http://127.0.0.1:9090/metrics` и `http://127.0.0.1:9091/metrics` с подтверждением HTTP 200 OK.
8. **Откат при сбое:**
   - Если опрос метрик завершился неудачей, скрипт восстанавливает старые бинарники, каталоги и unit-файлы из снимка отката, перезапускает старые службы и возвращает код ошибки 1.

---

## 5. Порядок раскатки на боевом парке (Fleet Rollout Plan)

Раскатка проводится строго по одному узлу за раз с ручным запуском и подтверждением владельца после каждого шага:

```
[Фаза 1: Сборка]
  ├── Сборка release-бинарей под x86_64-unknown-linux-musl
  └── Сборка release-бинарей под aarch64-unknown-linux-musl

[Фаза 2: Exit-узлы (только server)]
  ├── 1. nuxt (x86_64)   -> migrate-node-rename.sh nuxt server
  └── 2. nuxt2 (x86_64)  -> migrate-node-rename.sh nuxt2 server

[Фаза 3: Cloud-узлы (relay + mesh)]
  ├── 3. cloud1 (x86_64) -> migrate-node-rename.sh cloud1 all
  │      └── Проверка mesh cluster 9443/udp и reselect_sync
  └── 4. cloud2 (x86_64) -> migrate-node-rename.sh cloud2 all
         └── Проверка парного кластера cloud1 <-> cloud2

[Фаза 4: Ingress-узлы (домашние)]
  ├── 5. .104 / NanoPi R5C (aarch64) -> migrate-node-rename.sh .104 all
  │      └── Проверка TUN/шлюза домашней сети
  └── 6. .102 / Beelink (x86_64)      -> migrate-node-rename.sh .102 all
         └── Проверка SOCKS5/TUN и VRF
```

---

## 6. Критерии приемки (Verification Criteria)

1. **Кодовая база и линтеры:**
   - `cargo fmt --check` проходит чисто по всем пакетам.
   - `cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings` завершается без предупреждений.
   - `(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)` проходит успешно.
2. **Тесты:**
   - `cargo test --workspace --exclude sockudo-ws` проходит успешно.
   - `RUN_E2E_FAILOVER=1 cargo test -p outline-client --features test-tls --test 'e2e_*' -- --test-threads=1` проходит полностью.
3. **Сборка клиентских платформ:**
   - Сборка macOS: `./macos/scripts/package-app.sh` успешно собирает `.app` с вложенным `outline-client`.
   - Android workspace компилируется без ошибок.
4. **Скрипты:**
   - Тесты генератора access-key (`python3 -m unittest discover ops/access-keys`) проходят.
   - Скрипт `ops/deploy/deploy-binary.sh` корректно принимает юниты `outline-server` и `outline-client`.
5. **Боевой парк:**
   - Все узлы переведены на службы `outline-server` и `outline-client`.
   - Метрики собираются VictoriaMetrics без пропусков рядов.
   - Алерты в `vmalert` находятся в состоянии OK.
