# План реализации: Устранение уязвимостей и дефектов в vendored-патчах, скриптах, CI/CD и инфраструктуре (Домен 4)

**Дата:** 2026-11-19  
**Область:** `vendor/sockudo-ws`, `vendor/rustls`, `vendor/quinn-proto`, `.github/workflows/`, `install-server.sh`, `install-client.sh`, `ops/`, `Cargo.toml`.  
**Цель:** Устранение подтверждённых уязвимостей и дефектов безопасности [H-25]–[H-30], [M-24], [M-25] согласно аудиту безопасности.

---

## 1. Затронутые файлы и архитектурные решения

### 1.1. Vendored-патчи и vendored-крейты
- **`vendor/sockudo-ws/src/stream/transport_stream.rs`** и **`sockudo-ws-1.7.5.patch`** ([H-25]):
  - Запрет `poll_write` после вызова/инициации `poll_shutdown` (`shutdown_started = true`) с возвратом `io::ErrorKind::BrokenPipe`.
  - Защита от cancellation-бага при смене размера буфера: при завершении дренажа ранее поставленного в очередь фрагмента возвращать не более текущего `buf.len()` (`queued.min(buf.len())`), предотвращая panic `index out of bounds` в `AsyncWriteExt::write_all`.
  - Реализация дренажа очереди в `poll_flush`: вызов `stream.poll_drain(cx)` при `write_queued.is_some()`.
- **`vendor/rustls/src/server/tls13.rs`** и **`rustls-0.23.46.patch`** ([H-26]):
  - Обеспечение уникальности `ticket_nonce`: пустой nonce (`Vec::new()`, 0 байт) сохраняется только для случая ровно 1 тикета (эмуляция Go `crypto/tls` / Caddy). При `send_tickets > 1` для каждого тикета генерируется уникальный 8-байтный nonce через CSPRNG, выполняя требование RFC 8446 §4.6.1.
- **`vendor/rustls/src/msgs/fragmenter.rs`** и **`rustls-0.23.46.patch`** ([M-24]):
  - Ограничение динамического размера записи `TCP_MSS_PAYLOAD.min(self.limit)` в `Chunker::next()` и `Chunker::len()`, предотвращающее превышение `max_fragment_size` при установленном ограничении.
- **`vendor/quinn-proto/src/connection/assembler.rs`** и **`quinn-proto-0.11.19.patch`** ([M-24]):
  - Использование `COMPACT_FACTOR.saturating_mul(max_chunks)` для защиты от переполнения целочисленного типа на 32-битных платформах.
  - Введение жесткого потолка `HARD_CEILING_CHUNKS = 16384` в `chunk_limit(window)` для защиты от DoS по памяти при аномально больших окнах приема.

### 1.2. GitHub Actions Release Workflows ([H-27])
- **`.github/workflows/_ss-release-build.yml`**
- **`.github/workflows/_ws-release-build.yml`**
- **`.github/workflows/_ui-release-build.yml`**
- **`.github/workflows/_android-release-build.yml`**
- **`.github/workflows/_macos-release-build.yml`**
  - Вынос прямого использования `${{ inputs.* }}` из тела bash-скриптов (`run: |`) в секции `env:` шага `Resolve workflow variables`. Это исключает возможность Script Injection через специально сформированные Git-теги.

### 1.3. Скрипты установки ([H-28], [H-29])
- **`install-client.sh`**:
  - Переход от фиксированного `/tmp/${BINARY_NAME}-install` к безопасному `mktemp -d -t outline-ws-rust-install.XXXXXX` с регистрацией `trap` на удаление при выходе, как в `install-server.sh`.
- **`install-server.sh`** и **`install-client.sh`**:
  - Исправление `asset_pattern`: замена обязательного `-v` (`/${BINARY_NAME}-v[^/]*-...`) на опциональный `v?` (`/${BINARY_NAME}-v?[^/]*-...`), что обеспечивает успешный поиск релизных архивов, собранных CI без префикса `v`.
  - Исправление `strip_v()`: корректное снятие префиксов тегов `${TAG_PREFIX:-}` (`ss-` или `ws-`), а затем `v`, с сохранением байтовой идентичности функции между обоими инсталлерами (проверяется `.github/scripts/check-install-scripts.sh`).

### 1.4. Скрипты эксплуатации `ops/` ([H-30])
- **`ops/grafana/alerting/deploy.sh`**:
  - Исключение передачи секретов в `argv` для `sed`. Использование Python3 с передачей токенов через переменные окружения.
  - Безопасное копирование на удаленный хост в выделенный `mktemp -d` с правами `0700` вместо world-writable `/tmp/`.
- **`ops/alerting/deploy.sh`**:
  - Замена интерполяции токенов в `sed` на Python3 с передачей через переменные окружения.
- **`ops/heartbeat/install.sh`**:
  - Замена `sed` на Python3 с передачей токена через переменную окружения.
  - Установка прав `0640` и владельца `root:www-data` на `/etc/nginx/snippets/heartbeat.conf`.

### 1.5. Гигиена `Cargo.toml` ([M-25])
- **`Cargo.toml` (root)**:
  - Добавление `quinn-proto = { version = "0.11", default-features = false }` в `[workspace.dependencies]`.
- **`crates/outline-transport/Cargo.toml`** и **`bins/outline-ss-rust/Cargo.toml`**:
  - Перевод зависимости `quinn-proto` на `workspace = true`.

---

## 2. План верификации

1. Проверка синтаксиса и инвариантов инсталлеров:
   - `bash .github/scripts/check-install-scripts.sh`
2. Проверка сборки и форматирования Rust workspace:
   - `cargo check -p outline-ss-rust -p outline-transport`
   - `cargo fmt --check -p outline-ss-rust -p outline-transport`
   - `cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings`
3. Проверка тестов:
   - `cargo test -p outline-ss-rust -p outline-transport`
   - Проверка аудита vendored: `bash scripts/audit-vendored.sh`
4. Проверка целостности и соответствия патчей:
   - Проверка `git diff` для `vendor/` и соответствия `*.patch` файлам.

---

## 3. Безопасность и порядок выкатки
- Все изменения локальные (клиент, сервер, vendored-слой, CI, ops-скрипты).
- Никакого автоматического деплоя на боевые серверы.
- Строгое соблюдение инварианта отсутствия коммита локальных файлов `ops/nas-monitoring/` и `docs/superpowers/plans/2026-11-19-nas-node-exporter.md`.
