# Дедупликация примитивов протокола и кадрирования в `outline-wire` (M3 — Подпроект 1)

**Дата:** 2026-11-26
**Статус:** На ревью
**Затронутые пакеты:** `outline-wire`, `outline-transport`, `outline-server`

---

## 1. Контекст и дорожная карта M3

После объединения `outline-server` и `outline-client` в единый workspace базовый словарь wire-протокола (`CipherKind`/KDF, `TargetAddr`, заголовки SS2022, фреймы VLESS и `vless_mux`, константы `resume` и `xhttp`, `padding`, `padding_frames`, `early_shape`, `udp_records`, `h3_datagram`) уже живёт в листовом крейте `crates/outline-wire`.

Оставшееся дублирование между сервером и клиентом делится на три независимых уровня, которые прорабатываются и выкатываются последовательно от листа графа вверх:

1. **Подпроект 1 (Уровень A — предмет этой спецификации):** чистые без-IO примитивы, кольцевой буфер байтового реплея, расчёты H2/padding-кадрирования и `http::HeaderMap`-кодеки переговоров `X-Outline-*` / `X-Padding` в `outline-wire`.
2. **Подпроект 2 (Уровень B — отдельно):** единая без-IO машина состояний потокового чанкового кодека Shadowsocks AEAD (`[enc_len + tag][payload + tag]`, счётчик nonce, лимит `0x3fff`) поверх абстракции блочного AEAD.
3. **Подпроект 3 (Уровень C — отдельно):** унификация сессионного кадрирования поверх транспорта (WS writer с батчингом/cover-трафиком, упорядочивание `seq` в XHTTP `packet-up` и общие части диспетчера `vless_mux`).

Асимметричный сетевой код (клиентские TLS/H2/QUIC-профили, `dial_plan`, кэши режимов, `outline-uplink`; серверные accept-loop, SNI/HTTP fallback, anti-replay кэши солей, `OrphanRegistry`, кластерный mesh) намеренно остаётся раздельным.

---

## 2. Цели и ограничения Подпроекта 1

### Цели
1. Устранить дублирование `SessionId` между `bins/outline-server/src/server/resumption/session_id.rs` и `crates/outline-transport/src/resumption.rs`.
2. Объединить серверный `DownlinkRing` (`bins/outline-server/src/server/resumption/downlink_ring.rs`) и клиентский `ClientUpstreamRingBuffer` (`crates/outline-transport/src/uplink_replay.rs`) в единый `ReplayRing` в `outline-wire`, перенеся серверное zero-alloc переиспользование вытесненных буферов (`reusable`) и на клиентскую сторону.
3. Заменить три раздельные реализации сборки/разбора заголовков `X-Outline-*` (серверный `resume_headers.rs`, клиентский `resumption.rs` и копипаст в клиентском `xhttp/mod.rs`) единым типизированным кодеком на базе `http::HeaderMap`, устранив расхождение в `.trim() == "1"` при проверке булевых флагов.
4. Перенести генерацию `X-Padding` и статические наборы заголовков ответов XHTTP из `bins/outline-server/src/server/transport/xhttp/padding.rs` в `outline_wire::xhttp`.
5. Вынести дублирующуюся математику расчёта `H2_DATA_PAYLOAD_MAX`-бюджета, нарезки `Bytes` на куски под одну TLS-запись и datagram-padding из обоих `carrier_padding.rs` в `outline_wire::padding_frames`.

### Ограничения и инварианты
- **Ноль новых крейтов в workspace:** всё размещается в существующем `crates/outline-wire` (списки пакетов в `.github/workflows/ci.yml`, `AGENTS.md` и `android/rust/Cargo.toml` не меняются).
- **Чистота графа зависимостей `outline-wire`:** добавляется только безусловная зависимость `http = { workspace = true }` (чистые типы заголовков без runtime/hyper, уже присутствующие в графе `outline-server`, `outline-client` и `outline-android`). Зависимости от `tokio`, `rustls` или AEAD-бэкендов в дефолтный набор `outline-wire` не добавляются.
- **Неизменность wire-формата:** байтовые представления фреймов, имена и значения HTTP-заголовков на проводе остаются полностью совместимыми с развёрнутым парком.

---

## 3. Архитектура и публичный API в `outline-wire`

### 3.1. `SessionId` в `outline_wire::resume`

В `crates/outline-wire/src/resume.rs` переносится единый тип идентификатора сессии:

```rust
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);

impl SessionId {
    pub const HEX_LEN: usize = 32;

    pub const fn from_bytes(bytes: [u8; 16]) -> Self;
    pub const fn as_bytes(&self) -> &[u8; 16];

    /// Draws a fresh random identifier from `rng` (e.g. `rand::rng()`, ChaCha12 CSPRNG).
    pub fn random<R: rand::Rng + ?Sized>(rng: &mut R) -> Self;

    /// Draws an identifier carrying the obfuscated cluster `shard` under `key`.
    pub fn random_with_shard<R: rand::Rng + ?Sized>(
        rng: &mut R,
        key: &crate::cluster::ObfuscationKey,
        shard: crate::cluster::ShardId,
    ) -> Self;

    /// Decodes the cluster shard embedded in this identifier under `key`.
    pub fn shard(&self, key: &crate::cluster::ObfuscationKey) -> crate::cluster::ShardId;

    /// Lowercase 32-char hex representation for HTTP headers.
    pub fn to_hex(self) -> String;

    /// Case-insensitive 32-char hex parser; returns `None` on wrong length or non-hex bytes.
    pub fn parse_hex(s: &str) -> Option<Self>;
}
```

- `fmt::Display` форматирует полный 32-символьный hex (`to_hex()`).
- `fmt::Debug` форматирует усечённый вид `SessionId(abcd1234…)`, чтобы bearer-токен не попадал целиком в логи.
- Изменения у потребителей:
  - `bins/outline-server/src/server/resumption/session_id.rs` и его тестовый файл удаляются (тесты переезжают в `outline-wire`); `resumption/mod.rs` реэкспортирует `pub(crate) use outline_wire::resume::SessionId;`. Поле `rng: ring::rand::SystemRandom` удаляется из `OrphanRegistry` в пользу `rand::rng()`.
  - `crates/outline-transport/src/resumption.rs` заменяет локальное определение на `pub use outline_wire::resume::SessionId;`.

---

### 3.2. `ReplayRing` в `outline_wire::replay_ring`

Новый модуль `crates/outline-wire/src/replay_ring.rs` объединяет оба кольцевых буфера реплея по абсолютным байтовым смещениям:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushError {
    OversizedSingleChunk { chunk_len: usize, capacity_bytes: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    OffsetEvicted { requested: u64, oldest_available: u64 },
    OffsetAhead { requested: u64, total_sent: u64 },
}

pub struct ReplayRing {
    capacity_bytes: usize,
    entries: VecDeque<Entry>,
    current_bytes: usize,
    total_sent: u64,
}

impl ReplayRing {
    pub fn new(capacity_bytes: usize) -> Self;
    pub fn capacity_bytes(&self) -> usize;
    pub fn total_sent(&self) -> u64;
    pub fn oldest_offset(&self) -> u64;
    pub fn buffered_bytes(&self) -> usize;

    /// Strict FIFO push (client uplink): rejects `chunk.len() > capacity_bytes`
    /// without mutating state; recycles evicted `Vec<u8>` buffers when
    /// `evicted.capacity() <= chunk.len() * 2`. Empty chunks are a no-op.
    pub fn push_strict(&mut self, chunk: &[u8]) -> Result<(), PushError>;

    /// Infallible FIFO push (server downlink): when `capacity_bytes == 0`, only
    /// advances `total_sent`; when `chunk.len() >= capacity_bytes`, drops existing
    /// entries and retains the trailing `capacity_bytes` suffix while advancing
    /// `total_sent` by `chunk.len()`. Empty chunks are a no-op.
    pub fn push_truncating(&mut self, chunk: &[u8]);

    /// Returns the contiguous slice `[offset, total_sent())` as a single `Vec<u8>`.
    /// `offset == total_sent()` returns `Ok(Vec::new())`.
    pub fn replay_from(&self, offset: u64) -> Result<Vec<u8>, ReplayError>;
}
```

- Изменения у потребителей:
  - `bins/outline-server/src/server/resumption/downlink_ring.rs` удаляется: `DownlinkRing` заменяется на `outline_wire::replay_ring::ReplayRing` с вызовами `push_truncating`, а матчинг `ReplayOutcome` заменяется на `Result<Vec<u8>, ReplayError>` (`Ok(bytes)` / `Err(ReplayError::OffsetEvicted { .. })` / `Err(ReplayError::OffsetAhead { .. })`).
  - `crates/outline-transport/src/uplink_replay.rs` заменяется тонкой обёрткой (или реэкспортом `PushError`, `ReplayError` и методом `push` поверх `ReplayRing::push_strict`), сохраняя внешний контракт для `outline-client` и `outline-tun`.

---

### 3.3. Кодек заголовков переговоров `X-Outline-*` в `outline_wire::resume`

В `crates/outline-wire/src/resume.rs` добавляются структуры чтения/записи заголовков поверх `http::HeaderMap`:

```rust
/// Client → server negotiation headers for session resumption and UDP framing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResumeRequestHeaders {
    pub resume_capable: bool,
    pub resume_request: Option<SessionId>,
    /// Emitted only when `resume_request` is `None`.
    pub home_affinity: Option<SessionId>,
    pub ack_prefix: bool,
    pub symmetric_replay: bool,
    /// Emitted on the wire only when `symmetric_replay && down_acked > 0`.
    pub down_acked: u64,
    pub udp_datagram: bool,
    pub udp_records: bool,
}

/// Raw parsed request headers before server-side registry/cluster policy gating.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RawResumeRequest {
    pub resume_capable: bool,
    pub resume_request: Option<SessionId>,
    pub home_affinity: Option<SessionId>,
    pub ack_prefix: bool,
    pub symmetric_replay: bool,
    pub down_acked: u64,
    /// `true` when `x-outline-resume-down-acked` was present and non-empty,
    /// but failed `u64` parsing (`down_acked` is set to `0` per spec).
    pub malformed_down_acked: bool,
    pub udp_datagram: bool,
    pub udp_records: bool,
}

impl ResumeRequestHeaders {
    pub fn write_to(&self, headers: &mut http::HeaderMap);
    pub fn parse_raw(headers: &http::HeaderMap) -> RawResumeRequest;
}

/// Server → client echo headers confirming session id and negotiated capabilities.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResumeResponseHeaders {
    pub session_id: Option<SessionId>,
    pub ack_prefix: bool,
    pub symmetric_replay: bool,
    pub udp_datagram: bool,
    pub udp_records: bool,
}

impl ResumeResponseHeaders {
    pub fn write_to(&self, headers: &mut http::HeaderMap);

    /// Parses server response headers gated against what the client `requested`:
    /// ignores unrequested echoes and enforces the `symmetric_replay => ack_prefix`
    /// invariant. Boolean flags accept `"1"` after ASCII whitespace trimming.
    pub fn parse_echo(headers: &http::HeaderMap, requested: &ResumeRequestHeaders) -> Self;
}
```

- Единый хелпер `header_is_one(headers, name)` проверяет `.to_str().ok().is_some_and(|v| v.trim() == "1")` как на сервере, так и на клиенте.
- Изменения у потребителей:
  - Клиентские `resumption::apply_resume_request_headers`, `apply_udp_datagram_request_header`, `parse_resume_response_echo` и ручная вставка `X-Outline-*` в `crates/outline-transport/src/xhttp/mod.rs` делегируют в `ResumeRequestHeaders::write_to` и `ResumeResponseHeaders::parse_echo`.
  - Серверные `ResumeContext::from_request_headers`, `edge_route` и `ResumeResponseEcho::apply` в `bins/outline-server/src/server/transport/resume_headers.rs` делегируют разбор в `ResumeRequestHeaders::parse_raw` (сохраняя `debug!`-лог при `malformed_down_acked` и всю логику `OrphanRegistry` / `RouteDecision`), а запись — в `ResumeResponseHeaders::write_to`.

---

### 3.4. Заголовки XHTTP и `X-Padding` в `outline_wire::xhttp`

В `crates/outline-wire/src/xhttp.rs` переносятся из серверного `xhttp/padding.rs`:

```rust
pub const PADDING_MIN_LEN: usize = 100;
pub const PADDING_MAX_LEN: usize = 1024;

/// Generates `(HeaderName::from_static(PADDING_HEADER), value)` with length
/// uniformly chosen in `PADDING_MIN_LEN..=PADDING_MAX_LEN` over `SESSION_ID_ALPHABET`.
pub fn generate_padding_header<R: rand::Rng + ?Sized>(
    rng: &mut R,
) -> (http::HeaderName, http::HeaderValue);

/// Browser-streamed SSE masquerade headers for XHTTP GET responses.
pub fn masquerade_response_headers() -> [(http::HeaderName, http::HeaderValue); 4];

/// Headers for XHTTP 200 POST upload responses.
pub fn post_response_headers() -> [(http::HeaderName, http::HeaderValue); 2];

/// Checks whether `name` (e.g. `UDP_RECORDS_HEADER` or `UDP_DATAGRAM_HEADER`) is `"1"`.
pub fn header_flag_enabled(headers: &http::HeaderMap, name: &str) -> bool;
```

- Серверный файл `bins/outline-server/src/server/transport/xhttp/padding.rs` удаляется; вызовы `if let Some((name, value)) = generate_padding_header()` в `xhttp/handlers.rs` и `xhttp/h3.rs` упрощаются до прямого `let (name, value) = generate_padding_header(&mut rand::rng());`.

---

### 3.5. H2 record cap и datagram padding в `outline_wire::padding_frames`

В `crates/outline-wire/src/padding_frames.rs` выносятся общие функции кадрирования из серверного и клиентского `carrier_padding.rs`:

```rust
/// Server→client WebSocket binary frame header for 126..=65535 B (no mask).
pub const H2_WS_SERVER_HEADER_LEN: usize = 4;

/// Client→server WebSocket binary frame header for 126..=65535 B (2 + 2 ext len + 4 mask).
pub const H2_WS_CLIENT_HEADER_LEN: usize = 8;

/// Maximum data bytes per message on an HTTP/2 carrier so that WS header +
/// max padding + `inner_overhead` + data fit in a single `H2_DATA_PAYLOAD_MAX`
/// TLS record. Returns `None` if the remaining budget is `< MIN_H2_PLAINTEXT_CAP`.
pub fn h2_record_payload_cap(
    ws_header_len: usize,
    scheme: PaddingScheme,
    inner_overhead: usize,
) -> Option<usize>;

/// Cuts `frame` into evenly-sized messages of at most `cap` bytes (when `cap` is
/// `Some(c)` and `frame.len() > c`), framing each piece under `scheme` when enabled
/// or returning zero-copy `Bytes` slices when disabled.
pub fn h2_capped_messages<R: Rng + ?Sized>(
    scheme: PaddingScheme,
    cap: Option<usize>,
    frame: Bytes,
    rng: &mut R,
) -> Vec<Bytes>;

/// Frames a single datagram payload to fit within `room` bytes (including the
/// 4-byte padding header when `scheme.is_enabled()`). Returns `None` if the
/// unpadded payload (or header + payload) exceeds `room`.
pub fn try_frame_datagram<R: Rng + ?Sized>(
    scheme: PaddingScheme,
    record: &Bytes,
    room: usize,
    rng: &mut R,
) -> Option<Bytes>;
```

- В серверном и клиентском `carrier_padding.rs` удаляется дублирующаяся арифметика/нарезка; там остаются только платформенные механизмы выбора конфигурации (глобальный per-path `OnceLock<PaddingConfig>` на сервере и `tokio::task_local!` override на клиенте).

---

## 4. Обработка ошибок и граничные случаи

1. **Битый `X-Outline-Resume-Down-Acked`:** `ResumeRequestHeaders::parse_raw` выставляет `down_acked = 0` и `malformed_down_acked = true` (включая значения `> u64::MAX` или нечисловой мусор), сохраняя требование спеки «трактовать как `0` и не рвать сессию», а сервер продолжает писать `debug!`-сообщение. Пустая строка или отсутствие заголовка дают `down_acked = 0, malformed_down_acked = false`.
2. **Непрошеное эхо возможностей от сервера:** `ResumeResponseHeaders::parse_echo` обнуляет любой флаг (`ack_prefix`, `symmetric_replay`, `udp_datagram`, `udp_records`), который клиент не запрашивал в `requested`, а также обнуляет `symmetric_replay`, если `ack_prefix == false`.
3. **Переполнение `ReplayRing` одиночным чанком:** `push_strict` возвращает `Err(PushError::OversizedSingleChunk)` без изменения `entries`/`total_sent`; `push_truncating` детерминированно сохраняет последние `capacity_bytes` байт чанка.
4. **H2 cap при огромном `max_pad`:** если `ws_header_len + 4 + max_pad + inner_overhead > H2_DATA_PAYLOAD_MAX - MIN_H2_PLAINTEXT_CAP`, `h2_record_payload_cap` возвращает `None` через `checked_sub` без арифметического underflow.

---

## 5. План тестирования и верификации

1. **Unit- и property-тесты в `crates/outline-wire/src/tests/`:**
   - `resume.rs`: round-trip `SessionId` (`to_hex`/`parse_hex`, регистронезависимость, усечённый `Debug`, `random_with_shard`/`shard`), round-trip `ResumeRequestHeaders` / `ResumeResponseHeaders` (включая пробелы вокруг `"1"`, правило взаимного исключения `resume_request` и `home_affinity`, подавление непрошеного эха, `v2 => v1`, битый `down-acked`).
   - `replay_ring.rs`: перенос всех тестов из серверного `tests/downlink_ring.rs` и клиентского `tests/uplink_replay.rs`, плюс явный тест переиспользования буферов (`reusable`) в `push_strict` и `proptest`-сверка инвариантов смещений при произвольной последовательности `push_*` и `replay_from`.
   - `xhttp.rs`: проверка длины (`100..=1024`) и алфавита `generate_padding_header` на фиксированном сиде RNG.
   - `padding_frames.rs`: проверка `h2_record_payload_cap`, `h2_capped_messages` (включённый и выключенный `PaddingScheme`, граничные размеры) и `try_frame_datagram`.
2. **Полный локальный CI-гейт монорепо:**
   - `cargo fmt --check` по всем пакетам workspace;
   - `cargo clippy --workspace --exclude sockudo-ws --exclude outline-windows --all-targets --no-deps -- -D warnings`;
   - `cargo test --workspace --exclude sockudo-ws --exclude outline-windows`;
   - `RUN_E2E_FAILOVER=1 cargo test -p outline-client --features test-tls --test 'e2e_*' -- --test-threads=1` (живая проверка совместимости клиента и сервера на всех носителях и сценариях миграции/resume);
   - `(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)`.
