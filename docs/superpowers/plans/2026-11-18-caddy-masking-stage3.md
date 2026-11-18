# Серверный HTTP/3 и TCP: эмуляция Caddy (quic-go) — Этап 3

План финализации стека сетевой маскировки сервера `outline-ss-rust` под Caddy (quic-go / Go 1.26).
Цель — устранить оставшиеся расхождения в HTTP/3 SETTINGS, GREASE Transport Parameters и добавить настраиваемый per-IP connection cap на TLS-листенере, согласно бэклогу аудита (`audit-2026-11-10-masking-backlog.md`).

---

## 1. Контекст и архитектурные решения

На Этапах 1 и 2 были реализованы:
- QUIC transport parameters и длина CID (4 байта) по эталону quic-go.
- HTTP-заголовки `Server: Caddy`, `Alt-Svc`, ответ на открытый HTTP-запрос `400 Bad Request`, пустой fallback `200 OK`, HTTP/2 настройки hyper.
- TLS 1.3 ServerHello extension order (`[0x002b, 0x0033]`), 1 тикет 604800s с пустым nonce, Dynamic Record Sizing в `vendor/rustls`.

### Что осталось до полного совпадения с Caddy (Этап 3):

1. **H3 SETTINGS (`vendor/h3` и `outline-ss-rust`)**:
   - В Caddy (quic-go):
     1. `0x06 MAX_FIELD_SECTION_SIZE = 16384` (16 KiB)
     2. `[0x33 H3_DATAGRAM = 1]` — передаётся **только** если включены датаграммы (`udp_datagrams = true`)
     3. `[0x08 ENABLE_CONNECT_PROTOCOL = 1]` — передаётся **только** если включен Extended CONNECT (`enable_extended_connect = true`)
   - В upstream `h3`:
     - Всегда добавляется GREASE setting (если `send_grease = true`).
     - `max_field_section_size` по умолчанию равен $2^{62}-1$.
     - Параметры WebTransport (`0x2b ENABLE_WEBTRANSPORT = 0` и `0x2c WEBTRANSPORT_MAX_SESSIONS = 0`) передаются всегда.
     - `0x33 H3_DATAGRAM = 0` передаётся даже если датаграммы выключены.
   - **Решение**: В `vendor/h3/src/config.rs` скорректировать кодирование фрейма SETTINGS:
     - Опускать WebTransport параметры, если WebTransport выключен.
     - Опускать `H3_DATAGRAM`, если датаграммы выключены (`enable_datagram == false`).
     - Опускать `ENABLE_CONNECT_PROTOCOL`, если `enable_extended_connect == false`.
     - Обеспечить канонический порядок параметров: `0x06` -> `0x33` (при наличии) -> `0x08` (при наличии).
     - В `bins/outline-ss-rust/src/server/h3/vendored.rs` в `h3_server_builder` задавать `.send_grease(false)` и `.max_field_section_size(16384)`.

2. **GREASE Transport Parameter ID (`vendor/quinn-proto`)**:
   - В quic-go (Caddy): `N` выбирается как случайный байт (`0..=255`), поэтому ID GREASE TP (`31 * N + 27`) лежит в диапазоне `27..=7932` и занимает 1 или 2 байта varint.
   - В upstream `quinn-proto`: `N` выбирается из `0..(1<<62)-27`, занимая 8 байт varint.
   - **Решение**: В `vendor/quinn-proto/src/transport_parameters.rs` изменить генерацию `generate_reserved_id`, чтобы `N` выбирался из `0..=255`, в точности повторяя quic-go.

3. **Per-IP лимит соединений на TLS-листенере (`outline-ss-rust`)**:
   - В аудите 2026-11-10 отмечено: лимит соединений на IP на TLS-листенере сервера должен быть настраиваемым и по умолчанию выключенным (за CDN сервер видит адрес CDN).
   - **Решение**: В `[server]` добавить опцию `max_connections_per_ip: Option<usize>` (по умолчанию `None` / 0 — выключено). При значении > 0 отслеживать активные TCP соединения через потокобезопасный трекер `IpConnectionTracker` с RAII guard `IpConnectionGuard`. При превышении лимита новое соединение немедленно закрывается с предупреждением в лог.

---

## 2. Пошаговый план работ

### Фаза 3.1: H3 SETTINGS под Caddy (`vendor/h3` + `outline-ss-rust`)
1. Править `vendor/h3/src/config.rs`:
   - В `TryFrom<Config> for frame::Settings`:
     - Если `send_grease == true`, добавлять GREASE.
     - Добавлять `MAX_HEADER_LIST_SIZE (0x06)` со значением `max_field_section_size`.
     - Если `enable_datagram == true`, добавлять `H3_DATAGRAM (0x33)` со значением 1.
     - Если `enable_extended_connect == true`, добавлять `ENABLE_CONNECT_PROTOCOL (0x08)` со значением 1.
     - Если `enable_webtransport == true`, добавлять `ENABLE_WEBTRANSPORT (0x2b)` и `WEBTRANSPORT_MAX_SESSIONS (0x2c)`.
2. В `bins/outline-ss-rust/src/server/h3/vendored.rs`:
   - В `h3_server_builder`: выставлять `.send_grease(false)` и `.max_field_section_size(16384)`.
3. Регенерировать `h3-0.0.8.patch`.

### Фаза 3.2: GREASE TP ID под Caddy (`vendor/quinn-proto`)
1. В `vendor/quinn-proto/src/transport_parameters.rs`:
   - В `ReservedTransportParameter::generate_reserved_id` ограничить `N` диапазоном `0..=255`.
2. Регенерировать `quinn-proto-0.11.19.patch`.

### Фаза 3.3: Настраиваемый Per-IP connection cap (`outline-ss-rust`)
1. Конфигурация:
   - В `bins/outline-ss-rust/src/config/file.rs` в `ServerSection` добавить `pub max_connections_per_ip: Option<usize>`.
   - В `bins/outline-ss-rust/src/config/resolved.rs` пробросить поле в `ServerConfig`.
2. Механизм трекинга:
   - Создать `IpConnectionTracker` в `bins/outline-ss-rust/src/server/bootstrap/axum.rs` (или вспомогательном модуле).
   - В цикле accept TLS-листенера проверять `tracker.try_acquire(peer_addr.ip())`.
   - Если лимит превышен — сбрасывать/закрывать сокет.
   - Если в рамках лимита — передавать Guard в асинхронную задачу соединения.

### Фаза 3.4: Тесты и верификация
1. Тесты H3 SETTINGS: проверить сырой фрейм SETTINGS сервера (порядок 0x06 -> 0x33 -> 0x08, отсутствие GREASE и нулей WebTransport).
2. Тесты GREASE TP ID: убедиться, что сгенерированный ID лежит в `27..=7932` и занимает <= 2 байт.
3. Тесты Per-IP connection limit: проверить отсечение соединений с одного IP при превышении порога и беспрепятственный пропуск при выключенном лимите.
4. Прогон полного CI-гейта.

---

## 3. План верификации

1. `cargo check --workspace --exclude sockudo-ws`
2. `cargo test --workspace --exclude sockudo-ws`
3. CI-гейт команды:
   - `cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto`
   - `cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings`
   - `cargo test --workspace --exclude sockudo-ws`
   - `RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls --test 'e2e_*' -- --test-threads=1`
   - `(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)`
   - `scripts/audit-vendored.sh`
   - Invariant checks
