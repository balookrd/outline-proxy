# План реализации Подпроекта 3 (Уровень C): дедупликация сессионного кадрирования и runtime-утилит

> **Для исполнителя:** Выполняйте строго по шагам; каждый Task завершается проверками и отдельным коммитом. Весь код и комментарии в коде — на английском, отчёты — на русском. После проверок подчищайте `target/debug/` только в финальной задаче или при нехватке места (чтобы инкрементальная сборка не сбрасывалась на каждом шаге).

**Спецификация:** [`docs/superpowers/specs/2026-11-26-session-framing-dedup-design.md`](../specs/2026-11-26-session-framing-dedup-design.md)

---

### Task 1: Примитивы кадрирования и XHTTP/UDP заголовки в `outline-wire`

**Затронутые файлы:**
- Изменить: `crates/outline-wire/src/padding_frames.rs`
- Изменить: `crates/outline-wire/src/udp_records.rs`
- Изменить: `crates/outline-wire/src/xhttp.rs`
- Изменить: `crates/outline-wire/src/resume.rs`
- Тесты: `crates/outline-wire/src/tests/padding_frames.rs`, `crates/outline-wire/src/tests/udp_records.rs`, `crates/outline-wire/src/tests/xhttp.rs`

**Что сделать:**
1. В `crates/outline-wire/src/padding_frames.rs`:
   - Добавить `pub fn frame_message<R: Rng + ?Sized>(scheme: PaddingScheme, bytes: Bytes, rng: &mut R) -> Bytes`: при `scheme.is_enabled()` выделяет `Vec` и вызывает `frame_payload_into`, иначе возвращает `bytes` без копирования.
   - Добавить `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct CoverParams { pub scheme: PaddingScheme, pub jitter_min_ms: u64, pub jitter_max_ms: u64 }` с методами:
     - `pub const fn new(scheme: PaddingScheme, cover: bool, jitter_min_ms: u64, jitter_max_ms: u64) -> Option<Self>`
     - `pub fn next_gap<R: Rng + ?Sized>(&self, rng: &mut R) -> Duration`
     - `pub fn frame<R: Rng + ?Sized>(&self, rng: &mut R) -> Bytes`
   - Добавить `pub enum OutboundFrames { Single(Bytes), Multi(Vec<Bytes>) }` с `IntoIterator<Item = Bytes>` (и методом `pub fn len(&self) -> usize` / `is_empty(&self) -> bool` при необходимости, или без лишних методов если достаточно `IntoIterator`).
   - Добавить `pub struct OutboundFramer` (`scheme: PaddingScheme`, `shaper: Option<EarlyShaper>`, `h2_cap: Option<usize>`) с `new`, `set_h2_cap`, `scheme`, `frame(&mut self, payload: Bytes, rng: &mut R) -> OutboundFrames`. При `!shaper.is_active()` автоматически выставлять `self.shaper = None`.
   - Задействовать `frame_message` внутри `h2_capped_messages`, чтобы не дублировать логику одиночного фрейма.
2. В `crates/outline-wire/src/udp_records.rs`:
   - Добавить `pub fn encode_record(payload: &[u8]) -> Result<Bytes, UdpRecordError>` поверх `encode_record_into`.
   - Добавить `pub struct UdpRecordStream { decoder: Option<UdpRecordDecoder>, pending: VecDeque<Bytes> }`:
     - `pub fn new(enabled: bool) -> Self`
     - `pub fn is_enabled(&self) -> bool`
     - `pub fn push_chunk(&mut self, chunk: Bytes)` — с декодером `push` + цикл `next_record` в `pending`; без декодера — `pending.push_back(chunk)`
     - `pub fn pop_datagram(&mut self) -> Option<Bytes>`
3. В `crates/outline-wire/src/xhttp.rs`:
   - Добавить `pub fn offers_udp_datagrams(headers: &http::HeaderMap) -> bool`
   - Добавить `pub fn apply_udp_datagram_header(headers: &mut http::HeaderMap)`
   - В `crates/outline-wire/src/resume.rs` перевести `UDP_DATAGRAM_HEADER` в `ResumeRequestHeaders` / `ResumeResponseHeaders` на использование `offers_udp_datagrams` / `apply_udp_datagram_header`.
4. Добавить unit-тесты в `crates/outline-wire/src/tests/`:
   - `OutboundFramer`: passthrough без паддинга/шейпера, разовая активация и авто-сброс `EarlyShaper`, нарезка по `h2_cap`, `frame_message` zero-copy.
   - `CoverParams`: `new` возвращает `None` без padding или без cover, `frame` декодируется `PaddingDecoder` в 0 полезных байт.
   - `UdpRecordStream`: `enabled = false` (passthrough), `enabled = true` (склейка сплита и разрезка склеенного чанка), `encode_record` на переполнении `u16`.
   - `xhttp`: `offers_udp_datagrams` и `apply_udp_datagram_header`.

**Проверка:**
- `cargo test -p outline-wire`
- `cargo clippy -p outline-wire --all-targets --no-deps -- -D warnings`

**Коммит:** `refactor(wire): add OutboundFramer, CoverParams, UdpRecordStream, and UDP datagram header helpers`

---

### Task 2: Общие `tokio`-примитивы `AbortOnDrop` и `JitteredTicker` / `CoverTimer` в `outline-net`

**Затронутые файлы:**
- Изменить: `crates/outline-net/Cargo.toml`
- Изменить: `crates/outline-net/src/lib.rs`
- Создать: `crates/outline-net/src/task.rs`
- Создать: `crates/outline-net/src/time.rs`
- Изменить (миграция сервера и клиента):
  - Удалить: `bins/outline-server/src/server/abort.rs`
  - Удалить: `bins/outline-server/src/server/transport/jittered_ticker.rs`
  - Удалить: `bins/outline-server/src/server/transport/tests/jittered_ticker.rs`
  - Обновить импорты `AbortOnDrop` на сервере (`bins/outline-server/src/server/mod.rs` и `transport/*`)
  - Обновить `bins/outline-server/src/server/transport/mod.rs`, `tcp.rs`, `vless/mod.rs` (перевод `JitteredTicker` на `outline_net::time::JitteredTicker`)
  - Обновить `crates/outline-transport/src/guards.rs` (реэкспорт `pub use outline_net::task::AbortOnDrop;` вместо локальной структуры; для тестового `XhttpStream::for_loss_probe_test` в `xhttp/stream.rs` использовать `AbortOnDrop::new(tokio::spawn(async {}))`)
  - Обновить `crates/outline-transport/src/lib.rs` (`jittered` делегирует в `outline_net::time::jittered_period`)

**Что сделать:**
1. В `crates/outline-net/Cargo.toml`:
   - В `[dependencies]` добавить `bytes = { workspace = true }` и `outline-wire = { path = "../outline-wire" }` (без фич).
   - В `[dependencies]` у `tokio` проверить наличие `rt` и `time` (уже есть; для тестов в `[dev-dependencies]` убедиться, что `macros`, `rt`, `time` доступны — уже есть).
2. В `crates/outline-net/src/task.rs`:
   - Перенести `AbortOnDrop<T = ()>` (generic с дефолтом `T = ()`), методы `new(handle: JoinHandle<T>) -> Self`, `into_inner(mut self) -> JoinHandle<T>`, `Drop`.
   - Написать unit-тест: дроп `AbortOnDrop` прерывает задачу, а `into_inner()` позволяет дождаться её завершения.
3. В `crates/outline-net/src/time.rs`:
   - `pub fn jittered_period(period: Duration) -> Duration`
   - `pub struct JitteredTicker` (`new`, `tick`) — перенести тесты из `bins/outline-server/src/server/transport/tests/jittered_ticker.rs`.
   - `pub struct CoverTimer` поверх `Option<CoverTimerInner>` (`params: CoverParams`, `sleep: Pin<Box<Sleep>>`):
     - `pub fn new(params: Option<CoverParams>) -> Self`
     - `pub const fn is_enabled(&self) -> bool`
     - `pub async fn wait(&mut self)` (при `None` — `std::future::pending::<()>().await`, без создания `Sleep`)
     - `pub fn rearm(&mut self)`
     - `pub fn frame(&self) -> Option<Bytes>`
   - Написать unit-тесты на `CoverTimer` (`is_enabled() == false` при `None`, `frame()` возвращает валидный cover-кадр и `rearm()` сдвигает дедлайн при `Some`).
4. Перевести `outline-server` и `outline-transport` на `outline_net::{task::AbortOnDrop, time::{JitteredTicker, jittered_period}}`, удалить `abort.rs`, `jittered_ticker.rs` и его серверный тест.

**Проверка:**
- `cargo test -p outline-net`
- `cargo test -p outline-server --no-run` и `cargo test -p outline-transport --no-run`
- `cargo clippy -p outline-net -p outline-server -p outline-transport -p outline-tun --all-targets --no-deps -- -D warnings`

**Коммит:** `refactor(net): share AbortOnDrop, JitteredTicker, and CoverTimer across server and client`

---

### Task 3: Перевод сервера и XHTTP на `OutboundFramer`, `CoverParams`, `CoverTimer`, `UdpRecordStream` и заголовки H3 datagram

**Затронутые файлы:**
- Изменить: `bins/outline-server/src/server/transport/carrier_padding.rs`
- Изменить: `bins/outline-server/src/server/transport/ws_writer.rs`
- Изменить: `bins/outline-server/src/server/transport/tcp.rs`
- Изменить: `bins/outline-server/src/server/transport/vless/tcp.rs`
- Изменить: `bins/outline-server/src/server/transport/held_header.rs`
- Изменить: `bins/outline-server/src/server/transport/ws_socket.rs`
- Изменить: `bins/outline-server/src/server/transport/vless_udp.rs`
- Изменить: `bins/outline-server/src/server/transport/h3_datagram.rs`
- Изменить: `bins/outline-server/src/server/transport/xhttp/duplex.rs`
- Изменить: `crates/outline-transport/src/carrier_padding.rs`
- Изменить: `crates/outline-transport/src/resumption.rs`
- Изменить: `crates/outline-transport/src/xhttp/mod.rs`
- Изменить: `crates/outline-transport/src/xhttp/stream.rs`
- При необходимости обновить импорты в тестах `bins/outline-server/src/server/transport/tests/*`.

**Что сделать:**
1. В `bins/outline-server/src/server/transport/carrier_padding.rs`:
   - Заменить локальную `CoverParams` на `pub(in crate::server) use outline_wire::padding_frames::{CoverParams, frame_message};`.
   - Обновить `cover_for_path` на `CoverParams::new(p.scheme(), p.cover_enabled() && p.applies_to(path), p.cover_jitter_min_ms, p.cover_jitter_max_ms)`.
   - Удалить `frame_downlink_message` (все вызовы на сервере перевести на `carrier_padding::frame_message(scheme, bytes, &mut rand::rng())` — или оставить тонкий однострочник только если он реально нужен; лучше сразу `frame_message`, чтобы не плодить синонимы) и `shaped_messages`, если `OutboundFramer` полностью закрывает `tcp.rs` и `vless/tcp.rs` (проверить `tests/carrier_padding.rs`).
2. В `bins/outline-server/src/server/transport/ws_writer.rs`:
   - Заменить `COVER_DISABLED_PARK`, `cover_sleep` и `arm_cover` на `outline_net::time::CoverTimer`.
   - Упростить `send_cover` (брать `cover_timer.frame()`).
3. В `bins/outline-server/src/server/transport/tcp.rs` (`ChannelSink`) и `vless/tcp.rs`:
   - Заменить связку `padding: PaddingScheme` + `shaper: Option<EarlyShaper>` + ручное ветвление `if let Some(shaper) ... else if padding.is_enabled()` на `framer: OutboundFramer::new(padding, shaper, None)`.
4. В `bins/outline-server/src/server/transport/xhttp/duplex.rs` и `crates/outline-transport/src/xhttp/stream.rs`:
   - Заменить поля `records: Option<UdpRecordDecoder>` + `pending: VecDeque<Bytes>` и функции `take_records` / `frame_datagram` на `UdpRecordStream` и `outline_wire::udp_records::encode_record`.
5. Заголовки H3 datagram:
   - В `bins/outline-server/src/server/transport/h3_datagram.rs` (`offers_udp_datagrams`, `apply_udp_datagram_echo`), `crates/outline-transport/src/resumption.rs` (`apply_udp_datagram_request_header`) и `crates/outline-transport/src/xhttp/mod.rs` (`parse_udp_datagram_echo`) использовать `outline_wire::xhttp::{offers_udp_datagrams, apply_udp_datagram_header}`.

**Проверка:**
- `cargo test -p outline-server`
- `cargo test -p outline-transport`
- `cargo clippy -p outline-server -p outline-transport --all-targets --no-deps -- -D warnings`

**Коммит:** `refactor(transport): adopt OutboundFramer, CoverTimer, UdpRecordStream, and shared H3 datagram headers`

---

### Task 4: Единое клиентское ядро WS writer в `outline-transport`

**Затронутые файлы:**
- Создать: `crates/outline-transport/src/ws_writer.rs`
- Изменить: `crates/outline-transport/src/lib.rs`
- Изменить: `crates/outline-transport/src/carrier_padding.rs`
- Изменить: `crates/outline-transport/src/frame_io_ws.rs`
- Изменить: `crates/outline-transport/src/tcp_transport/writer/transport.rs`

**Что сделать:**
1. В `crates/outline-transport/src/carrier_padding.rs`:
   - Добавить `pub(crate) fn cover_params(&self) -> Option<outline_wire::padding_frames::CoverParams>` (использует `CoverParams::new`).
   - Удалить `cover_gap` и `cover_frame` (после перевода обоих writer'ов на `CoverTimer` они больше не нужны), а также `shaped_messages`/`h2_capped_messages` реэкспорты, если `frame_io_ws.rs` и `transport.rs` используют `OutboundFramer` напрямую.
2. Создать `crates/outline-transport/src/ws_writer.rs`:
   - `WsWriterOptions { pub cover: Option<CoverParams>, pub hold_header: Option<Duration>, pub diag_writer: &'static str, pub stop_on_data_close_frame: bool }`
   - `WsWriterHandles { pub task: AbortOnDrop, pub data_tx: BudgetedSender<Message>, pub ctrl_tx: mpsc::Sender<Message>, pub held_tx: Option<mpsc::Sender<Vec<u8>>>, pub exit_rx: watch::Receiver<bool> }`
   - `pub(crate) fn spawn_ws_writer<S>(sink: S, options: WsWriterOptions) -> WsWriterHandles where S: Sink<Message, Error = WsError> + Unpin + Send + 'static`
   - Внутри:
     - `CoverTimer::new(options.cover)`
     - Опциональный канал `held_rx` (создаётся и слушается только при `options.hold_header.is_some()`), опциональный `Pin<Box<Sleep>>` для `hold_sleep` без 24-часового парка когда `held` пуст или `hold_header` выключен
     - `WriterExit` drop-guard для `exit_tx`
     - Сохранение всех инвариантов `take_pending_held`, склейки с первым `Message::Binary`, `drop(permit)` после `send_or_report`, закрытия `ws_sink.close()` при закрытии `data_rx` или получении `Message::Close` (при `stop_on_data_close_frame == true`).
3. В `crates/outline-transport/src/frame_io_ws.rs`:
   - Удалить локальный `spawn_ws_writer`, `arm_cover`, `send_cover`, `COVER_DISABLED_PARK`, `WriterExit`, и перевести `from_ws_frames` / `from_ws_datagrams` на `crate::ws_writer::spawn_ws_writer`.
   - Перевести `spawn_keepalive` на `outline_net::time::JitteredTicker`.
   - В `WsFrameSink` заменить поля `padding`, `shaper`, `h2_cap` и 45 строк `send_frame` на `framer: OutboundFramer`.
4. В `crates/outline-transport/src/tcp_transport/writer/transport.rs`:
   - Удалить `COVER_DISABLED_PARK`, `arm_cover`, `take_pending_held`, `flush_held`, `send_cover` и ручной `tokio::spawn` внутри `WsWriteTransport::spawn` — вызвать `crate::ws_writer::spawn_ws_writer`.
   - В `WsWriteTransport` заменить `padding`, `shaper`, `h2_cap` на `framer: OutboundFramer` (+ `framer.set_h2_cap(...)` в `set_h2_uplink_cap`), упростив `write_frame` и `write_frame_held` (`frame_message` для `held`).
5. Добавить unit-тесты для `ws_writer.rs` (проверка склейки `held_tx` с первым `data_tx`, тайм-аута удержания, и корректного `exit_rx` при закрытии).

**Проверка:**
- `cargo test -p outline-transport`
- `cargo clippy -p outline-transport --all-targets --no-deps -- -D warnings`

**Коммит:** `refactor(transport): unify client WS writer loop and OutboundFramer`

---

### Task 5: Синхронизация документации и полный локальный CI-гейт

**Затронутые файлы:**
- Изменить: `AGENTS.md` (обновить описание модулей `outline-wire` и `outline-net` с учётом `OutboundFramer`, `CoverParams`, `UdpRecordStream`, `outline_net::task::AbortOnDrop` и `outline_net::time::{JitteredTicker, CoverTimer}`)
- Проверить двуязычную документацию (если какие-то `docs/*.md` / `docs/*.ru.md` упоминают удалённые `abort.rs` или `jittered_ticker.rs`, обновить синхронно обе версии).

**Что сделать:**
1. Проверить через `git grep` отсутствие устаревших ссылок на `server::abort`, `jittered_ticker` или `frame_downlink_message` в документации.
2. Обновить `AGENTS.md`.
3. Прогнать **полный** локальный CI-гейт:
   - `cargo fmt --check -p outline-server -p outline-client -p outline-ui -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto`
   - `cargo clippy --workspace --exclude sockudo-ws --exclude outline-windows --all-targets --no-deps -- -D warnings`
   - `cargo test --workspace --exclude sockudo-ws --exclude outline-windows`
   - `RUN_E2E_FAILOVER=1 cargo test -p outline-client --features test-tls --test 'e2e_*' -- --test-threads=1`
   - `(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)`
   - `cargo check -p outline-server --no-default-features` и `cargo check -p outline-client --no-default-features`
   - `cargo tree -i 'ring' -e features` (пусто / пакет не найден).
4. Удалить `target/debug` после прогона тестов (до `git push` пользователя).

**Коммит:** `docs: update AGENTS.md for shared level-C framing and runtime primitives`
