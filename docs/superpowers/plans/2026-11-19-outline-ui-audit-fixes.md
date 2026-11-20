# План реализации: устранение уязвимостей и аудит-дефектов безопасности в outline-ui

**Цель:** Устранить дефекты безопасности, выявленные в ходе аудита `bins/outline-ui` (дефект [M-21] и сопутствующие Low):
1. Отсутствие HTTP Security Headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Cache-Control: no-store для API).
2. Dot-Segment Path Traversal в `encode_path_segment` (`src/ss/api.rs`).
3. Запрет пустого токена API панели (`src/config.rs`).
4. Ограничение DoS и размера тела ответа бэкенда (`backend.rs`, `ws/api.rs`, `origin.rs`, `auth.rs`).

---

## 1. Затрагиваемые файлы и архитектурные решения

1. `Cargo.toml` (корневой):
   - Добавить `subtle = "2.6"` в `[workspace.dependencies]`.
2. `bins/outline-ss-rust/Cargo.toml`:
   - Заменить `subtle = "2.6"` на `subtle = { workspace = true }`.
3. `bins/outline-ui/Cargo.toml`:
   - Добавить зависимости `subtle = { workspace = true }` и `ring = { workspace = true }`.
4. `bins/outline-ui/src/main.rs`:
   - Добавить middleware безопасности `security_headers` для установки:
     - `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'`
     - `X-Frame-Options: DENY`
     - `X-Content-Type-Options: nosniff`
     - `Referrer-Policy: no-referrer`
     - `Cache-Control: no-store` для путей, начинающихся с `/ss/dashboard/api/` и `/ws/dashboard/api/`.
   - Обновить тесты роутинга в `bins/outline-ui/src/tests/routing.rs` для проверки наличия этих заголовков.
5. `bins/outline-ui/src/ss/api.rs` и `bins/outline-ui/src/ss/tests/api.rs`:
   - В `encode_path_segment`: исключить `b'.'` из набора неэкранируемых символов (кодировать как `%2E`).
   - В эндпоинтах `update_user`, `delete_user`, `block_user`, `unblock_user`: валидировать `id` — отклонять `.` и `..`, пустые строки, а также разделители путей (`/`, `\`) кодом `400 Bad Request`.
   - Добавить модульные тесты для проверки защиты от обхода пути (path traversal).
6. `bins/outline-ui/src/config.rs` и `bins/outline-ui/src/tests/config.rs`:
   - В `resolve_secret`: проверять, что после `trim()` секрет не пустой; при пустом значении или пустом файле возвращать ошибку валидации конфигурации (`bail!`).
   - Добавить модульные тесты для пустого литерала `token = ""` и пустого файла токена.
7. `bins/outline-ui/src/backend.rs` и `bins/outline-ui/src/tests/backend.rs`:
   - Ограничить размер тела ответа control API до 16 MiB с использованием `http_body_util::Limited`.
   - Добавить тест на отсечение слишком большого ответа.
8. `bins/outline-ui/src/ws/api.rs` и `bins/outline-ui/src/ws/tests/api.rs`:
   - Ограничить максимальное количество `targets` в запросе `activate` (константа `MAX_ACTIVATE_TARGETS = 64`).
   - Добавить проверку и тест на возврат `400 Bad Request` при превышении лимита.
9. `bins/outline-ui/src/origin.rs` и `bins/outline-ui/src/tests/origin.rs`:
   - Запретить userinfo (`@`) в `Origin` и `Host` заголовках.
   - Добавить тесты на отклонение запросов с `@` в Origin/Host.
10. `bins/outline-ui/src/auth.rs` и `bins/outline-ui/src/tests/auth.rs`:
    - Использовать хеширование токена (SHA-256) фиксированной длины (32 байта) и сравнение через `subtle::ConstantTimeEq`, устраняя утечку информации о длине токена по времени ответа (ранний выход).
    - Обновить тесты аутентификации.

---

## 2. Порядок реализации по шагам

### Шаг 1. Зависимости (Cargo.toml)
- Зарегистрировать `subtle = "2.6"` в корневом `Cargo.toml`.
- Подключить `subtle` и `ring` в `bins/outline-ui/Cargo.toml`.
- Перевести `bins/outline-ss-rust/Cargo.toml` на `subtle = { workspace = true }`.
- Проверить сборку `cargo check -p outline-ui`.

### Шаг 2. Запрет пустого токена API панели (`config.rs`)
- Реализовать строгую проверку непустоты секрета в `resolve_secret`.
- Добавить тесты в `src/tests/config.rs`.
- Запустить `cargo test -p outline-ui --test config` / `cargo test -p outline-ui`.

### Шаг 3. Защита от Dot-Segment Path Traversal (`ss/api.rs`)
- Изменить `encode_path_segment` для кодирования точки `.` в `%2E`.
- Добавить валидацию `id` в обработчиках пользователей (`update_user`, `delete_user`, `block_user`, `unblock_user`).
- Добавить тесты в `src/ss/tests/api.rs`.
- Запустить тесты `cargo test -p outline-ui`.

### Шаг 4. Устранение тайминг-атаки по длине токена (`auth.rs`)
- Перевести `AuthState` на хранение SHA-256 хеша токена и проверку через `subtle::ConstantTimeEq`.
- Обновить тесты в `src/tests/auth.rs`.
- Запустить тесты `cargo test -p outline-ui`.

### Шаг 5. Строгий парсинг Origin и запрет userinfo (`origin.rs`)
- Добавить отклонение `Origin` и `Host`, содержащих символ `@`.
- Добавить тесты в `src/tests/origin.rs`.
- Запустить тесты `cargo test -p outline-ui`.

### Шаг 6. Ограничения DoS в Backend и WS API (`backend.rs`, `ws/api.rs`)
- Применить `http_body_util::Limited` на 16 MiB в `backend.rs`.
- Добавить лимит `MAX_ACTIVATE_TARGETS = 64` в `activate` (`ws/api.rs`).
- Добавить тесты на лимиты.
- Запустить тесты `cargo test -p outline-ui`.

### Шаг 7. HTTP Security Headers (`main.rs`)
- Реализовать middleware безопасности с CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy и Cache-Control: no-store для API.
- Подключить middleware в `build_app`.
- Добавить тесты заголовков в `src/tests/routing.rs`.
- Запустить тесты `cargo test -p outline-ui`.

---

## 3. План верификации и CI-гейт

1. Проверка компиляции:
   ```bash
   cargo check -p outline-ui
   cargo check -p outline-ss-rust
   ```
2. Запуск тестов:
   ```bash
   cargo test -p outline-ui
   ```
3. Проверка линтером Clippy:
   ```bash
   cargo clippy -p outline-ui --all-targets --no-deps -- -D warnings
   ```
4. Проверка форматирования:
   ```bash
   cargo fmt --check -p outline-ui -p outline-ss-rust
   ```
5. Полный локальный CI-гейт для затронутых пакетов.
