# План реализации: Исправление подтвержденных ошибок и уязвимостей в `outline-ss-rust`

> **Дата**: 2026-11-19  
> **Компонент**: `bins/outline-ss-rust/` (серверный бинарник)  
> **Цель**: Комплексное устранение 17 подтвержденных дефектов и уязвимостей безопасности категорий High, Medium и Low, выявленных в ходе аудита кодовой базы `outline-proxy`.

---

## 1. Обзор задач и архитектурные решения

Все изменения производятся строго в рамках `bins/outline-ss-rust/` (и, при необходимости, `crates/outline-wire/`) без попутных рефакторингов и без нарушения обратной совместимости боевого парка серверов (включая домашние узлы `.102`/`.104` и облачные кластеры `cloud1`/`cloud2`/`nuxt`/`nuxt2`).

### 1.1. Матрица исправлений по этапам

| Этап | ID | Описание | Затронутые файлы |
|---|---|---|---|
| **Этап 1** | **M-4** | Запрет пустого токена `control.token = ""` | `src/config/control.rs` |
| | **M-7** | Устранение Path-Probing Oracle на XHTTP axum | `src/server/transport/xhttp/handlers.rs` |
| | **L-7** | Устранение unaligned pointer в `outbound.rs:620` | `src/outbound.rs` |
| | **L-3** | Асинхронное чтение файла в `GET /control/config` | `src/server/control/handlers.rs` |
| | **L-4** | Декодирование `combined_base_path` при percent-encoded token | `src/server/transport/mod.rs` |
| | **L-1** | IPv6 /64 маскирование в `RootAuthRateLimiter` + `Secure` cookie | `src/server/auth.rs` |
| | **L-2** | Корректный `stream.finish().await` для bodyless H3-ответов | `src/server/h3/http.rs` |
| | **L-5** | Владение запаркованной сессией по `user.id()` вместо IP-alias | `src/server/transport/tcp.rs` |
| **Этап 2** | **H-3** | Вынос `splice_to_backend` из `preauth_deadline` в `sni_fallback` | `src/server/bootstrap/axum.rs`, `src/server/transport/sni_fallback.rs` |
| | **H-4** | Устранение injection/smuggling через H3 request trailers | `src/server/transport/fallback/h3_stream.rs` |
| | **H-8** & **M-8** | Фрагментация в смешанном пуле и лимит буфера хендшейка | `src/crypto/stream.rs`, `src/server/transport/tcp.rs` |
| **Этап 3** | **H-7** | Сброс и изоляция `SessionKeyCache` при мутации пользователей | `src/crypto/session_cache.rs`, `src/server/endpoint_routes.rs`, `src/server/control/manager.rs`, `src/server/state.rs`, `src/server/transport/udp.rs` |
| | **M-1** | Per-user квоты и изоляция в `SaltReplayStore` | `src/server/salt_replay.rs`, `src/server/transport/tcp.rs` |
| **Этап 4** | **M-5** | Дефекты XHTTP (reorder buffer, `remove_if_same`, wakeups, timeouts) | `src/server/transport/xhttp/mod.rs`, `src/server/transport/xhttp/h3.rs` |
| | **M-9** | Гонки `ReplayStore`, `NatTable` (OnceCell) и `OrphanRegistry` | `src/server/replay.rs`, `src/server/nat/table.rs`, `src/server/resumption/registry.rs` |
| | **H-5** | Устранение дедлоков/зависаний teardown и harvest парковки | `src/server/relay.rs`, `src/server/transport/tcp.rs`, `src/server/transport/vless/tcp.rs`, `src/server/transport/vless_mux/state.rs` |
| **Этап 5** | **H-2** | Pre-auth HoL blocking на Cluster Mesh Listener | `src/server/cluster/mesh/endpoint.rs`, `src/server/transport/mesh_relay/home.rs` |
| | **H-6** | Pre-auth hardening: H2 keep-alive и H3 IP tracking/timeouts | `src/server/bootstrap/axum.rs`, `src/server/h3/mod.rs` |
| | **M-3** | Гонка записи `config.toml`, post-patch валидация и UserManager | `src/server/control/handlers.rs`, `src/server/control/manager.rs`, `src/server/control/persist.rs` |
| | **H-1** | Outbound SSRF фильтрация с configurable allowlist | `src/config/`, `src/server/connect.rs`, `src/server/nat/table.rs`, `src/server/transport/vless_udp.rs`, `src/server/transport/vless_mux/udp_sub.rs` |
| **Этап 6** | **CI** | Полная верификация, тесты, clippy, fmt | Тестовые модули, CI-гейт |

---

## 2. Поэтапный план реализации

### Этап 1: Изолированные точечные исправления (M-4, M-7, L-1..L-5, L-7)

1. **[M-4] `src/config/control.rs`**:
   - Запретить пустую строку в `control.token`: если `token.trim().is_empty()`, возвращать ошибку валидации `bail!("control.token cannot be empty")`.
   - Добавить юнит-тест в `src/config/tests.rs` (или существующий тестовый файл конфига).
2. **[M-7] `src/server/transport/xhttp/handlers.rs`**:
   - В `xhttp_handler_with_path_seq` изменить сигнатуру экстрактора `Path`: принимать `Path((session_id, seq_str)): Path<(String, String)>`.
   - Если `seq_str.parse::<u64>()` падает — считать запрос malformed и возвращать `unmatched_xhttp_response(&state, request).await`.
   - Добавить тест проверки ответа cover-сайта при нечисловом сегменте.
3. **[L-7] `src/outbound.rs:620`**:
   - Заменить `let sa6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };` на безопасное чтение невыровненного указателя: `let sa6: libc::sockaddr_in6 = unsafe { std::ptr::read_unaligned(ifa.ifa_addr as *const libc::sockaddr_in6) };`.
4. **[L-3] `src/server/control/handlers.rs:335`**:
   - Заменить синхронный `std::fs::read_to_string` на `tokio::fs::read_to_string(path).await`.
5. **[L-4] `src/server/transport/mod.rs:520`**:
   - Переписать `combined_base_path`: разделять по последнему слэшу (`full.rsplit_once('/')`), сверять с декодированным токеном, не допуская сбоя при percent-encoding.
6. **[L-1] `src/server/auth.rs`**:
   - В `RootAuthRateLimiter`: для IPv6 маскировать адрес до `/64` (`ip_network` или срез первых 8 байт `octets[..8]`), чтобы злоумышленник не мог обходить лимит генерацией новых IPv6 адресов внутри своей подсети.
   - В ответах авторизации (`Set-Cookie`) добавить атрибут `Secure` (для HTTPS/TLS запросов).
7. **[L-2] `src/server/h3/http.rs`**:
   - В ветках возврата коротких/ошибочных bodyless ответов (например, 404/400) вызывать `stream.finish().await`, чтобы корректно закрыть поток со стороны сервера.
8. **[L-5] `src/server/transport/tcp.rs`**:
   - Для ключа владения запаркованной сессией в `OrphanRegistry` использовать неизменный `user.id_arc()` вместо `user.effective_label(...)`, чтобы переключение клиента между Wi-Fi и сотовой сетью (смена IP) не приводило к `OwnerMismatch` при resume.

---

### Этап 2: Криптография и потоковые ошибки (H-3, H-4, H-8, M-8)

1. **[H-3] `src/server/bootstrap/axum.rs` и `src/server/transport/sni_fallback.rs`**:
   - Разделить логику `dispatch_sni`: под `preauth_deadline` выполнять исключительно `peek_sni` и `lookup`.
   - `splice_to_backend` возвращать как вариант `SniDispatchOutcome::Backend(idx, buffered)` и выполнять в `axum.rs` **вне** `preauth_deadline`.
   - Внутри `splice_to_backend` таймаутом ограничивать только установку TCP-соединения к бэкенду и запись буфера ClientHello.
   - Добавить интеграционный тест, проверяющий, что сессия через `sni_fallback` живет дольше 10 секунд.
2. **[H-4] `src/server/transport/fallback/h3_stream.rs`**:
   - Исключить перенос клиентских `request_trailers` в `upstream_parts.headers`. Заголовки трейлеров не должны попадать в основные заголовки запроса бэкенда, исключая Request Smuggling и спуфинг заголовков.
3. **[H-8] & [M-8] `src/crypto/stream.rs` и `src/server/transport/tcp.rs`**:
   - В `AeadStreamDecryptor::ensure_session_key`:
     - Если `self.users.is_empty()`, возвращать `Err(CryptoError::UnknownUser)`.
     - Отслеживать `any_too_short: bool`.
     - Возвращать `Err(CryptoError::UnknownUser)` только когда `any_candidate && !any_too_short`. Если хотя бы один пользователь вернул `TooShort`, возвращать `Ok(())` и ждать следующих данных.
     - Ограничить максимальный размер буфера рукопожатия до аутентификации константой `MAX_HANDSHAKE_BUFFER_LEN` (128 байт). Если буфер превышает лимит, а `active.is_none()`, немедленно завершать с `CryptoError::UnknownUser`.
   - Добавить тесты на смешанный пул (AES-128 + AES-256/SS-2022) с побайтовой подачей фрагментов.

---

### Этап 3: Управление состоянием пользователей и сессиями (H-7, M-1)

1. **[H-7] `SessionKeyCache`**:
   - Добавить метод `clear(&self)` в `SessionKeyCache`.
   - Включить `SessionKeyCache` в структуру `TransportRoute` (аналогично `peer_user_cache`), чтобы при каждом `UserManager::commit` создавался чистый кэш сессионных ключей.
   - В `CacheKey` включить идентификатор пользователя (`user_index` + `cipher` или привязку к пользователю), исключая коллизии.
   - Покрыть тестами сценарий отзыва пользователя / смены пароля: старые пакеты не должны расшифровываться от имени нового пользователя.
2. **[M-1] `SaltReplayStore`**:
   - Добавить per-user квоту `max_salts_per_user` и/или LRU вытеснение старых солей при заполнении кэша.
   - Передавать `user_id` в `check_and_mark`, чтобы переполнение кэша одним пользователем не отключало защиту от повторов для других пользователей (устранение cross-tenant DoS / fail-open).

---

### Этап 4: Асинхронные гонки, жизненный цикл и надежность (M-5, M-9, H-5)

1. **[M-5] `src/server/transport/xhttp/mod.rs` и `h3.rs`**:
   - В `ingest_uplink`: при получении дубликата `seq` корректно пересчитывать `state.reorder_bytes`: вычитать длину старого буфера и прибавлять длину нового с предварительной проверкой квоты.
   - В `XhttpRegistry`: заменить безусловный `remove(session_id)` на `remove_session_if_same(&self, session_id: &str, expected: &Arc<XhttpSession>)`, использующий `remove_if` у `DashMap`.
   - В `close_uplink`: уведомлять `uplink_drain_notify` и `uplink_room_notify`.
   - В `xhttp/h3.rs`:
     - Добавить таймаут чтения тела в `xhttp_h3_post` (`POST_BODY_READ_TIMEOUT`).
     - В `xhttp_h3_stream_one`: вызывать `uplink_task.abort()` при выходе из `drive_downlink_send_only`.
2. **[M-9] Гонки в `ReplayStore`, `NatTable` и `OrphanRegistry`**:
   - `ReplayStore`: обновлять `entry.last_seen_secs` только при успешном прохождении проверки на свежесть пакета (`Fresh`). Ключевать записи с учетом `user_id`.
   - `NatTable`: в `evict_idle` не удалять только что созданную `OnceCell` (проверять время создания или удалять только по явному отказу инициализации).
   - `OrphanRegistry`: в `try_take_committed` удалять запись из таблицы только если владелец совпал (через `remove_if`), избегая гонки `remove -> insert` при `OwnerMismatch`. В `probe_park` проверять актуальность `entry.deadline`.
3. **[H-5] Teardown и backpressure парковки**:
   - В `relay.rs`: обернуть `sink.send_ciphertext` в `tokio::select!` с уведомлением об отмене.
   - В `tcp.rs`, `vless/tcp.rs`, `vless_mux/state.rs`: сборку и harvest reader/writer задач при парковке и завершении ограничивать таймаутом `PARK_HARVEST_WAIT` с вызовом `.abort()`, аналогично `vless/udp.rs:62`.

---

### Этап 5: Сетки, лимиты подключений и SSRF (H-2, H-6, M-3, H-1)

1. **[H-2] `Cluster Mesh Listener`**:
   - В `MeshEndpoint::accept` не блокировать accept-цикл вызовом `incoming.await`. Вызывать `incoming` асинхронно в отдельной задаче с таймаутом рукопожатия `MESH_HANDSHAKE_TIMEOUT` (5 секунд).
   - В `accept_relay` читать `read_open_header` с таймаутом (5 секунд), сбрасывая зависшие стримы.
2. **[H-6] HTTP/2 и HTTP/3 Pre-auth Hardening**:
   - В `build_http_server_builder` (`axum.rs`): настроить `keep_alive_interval(Duration::from_secs(45))` и `keep_alive_timeout(Duration::from_secs(20))` для H2; включить `SO_KEEPALIVE` на TCP сокетах.
   - В `h3/mod.rs`: подключить `IpConnectionTracker` для ограничения подключений с одного IP; добавить таймаут на `incoming.await` (10 секунд); закрывать неактивные QUIC-соединения без HTTP-запросов.
3. **[M-3] Гонки и валидация конфига**:
   - В `ControlState`: защитить запись `config.toml` мьютексом, общим между `PATCH /control/config` и `UserManager::commit`.
   - В `persist_config_patch`: после применения патча к TOML десериализовать и валидировать результат через `Config::validate(&parsed)` перед записью на диск.
   - В `UserManager::rebuild_snapshots`: проверять уникальность `vless_id` (UUID), проверять `MAX_USER_LEN` для кластера и валидировать ip-aliases.
4. **[H-1] Outbound SSRF фильтрация**:
   - В конфигурацию `[outbound]` добавить опции:
     - `block_private_ips = true` (дефолт `false` или безопасный настраиваемый с поддержкой явных allowlist, чтобы не сломать `.102`/`.104`).
     - `allowed_subnets = [...]` (список разрешенных локальных подсетей/IP).
   - Создать модуль проверки IP-адресов (`is_blocked_outbound_ip`):
     - `ip.to_canonical()`
     - проверка на loopback, private, link-local, unspecified, multicast, cloud metadata (`169.254.169.254`, `fd00:ec2::254`).
     - проверка по `allowed_subnets`.
   - Встроить проверку в:
     - `connect_tcp_target` (после DNS-резолва и для literal IP).
     - `resolve_udp_target` в `connect.rs` и `nat/table.rs`.
     - `vless_udp.rs` и `vless_mux/udp_sub.rs`.

---

### Этап 6: Комплексное тестирование и верификация

1. Прогон юнит- и интеграционных тестов `bins/outline-ss-rust/`.
2. Проверка форматирования: `cargo fmt --check -p outline-ss-rust`.
3. Проверка линтера: `cargo clippy -p outline-ss-rust --all-targets --no-deps -- -D warnings`.
4. Проверка сборки: `cargo check -p outline-ss-rust`.
5. Обновление документации (README.md, README.ru.md) при добавлении новых конфигурационных параметров `[outbound]`.
6. Финальный отчет с результатами аудита и тестов.
