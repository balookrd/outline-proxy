# Подпроект 3 (Уровень C): дедупликация сессионного кадрирования и общих runtime-механизмов

**Дата:** 2026-11-26
**Статус:** Утверждена к планированию
**Контекст:** Третий (завершающий) этап стратегического рефакторинга **M3** по устранению дублирования между `outline-server` и `outline-client` (`outline-transport`, `outline-tun`) поверх результатов Подпроекта 1 (`outline-wire`, Уровень A) и Подпроекта 2 (`shadowsocks-crypto`, Уровень B).

---

## 1. Цели и границы

### Входит в Подпроект 3
1. **Единый пайплайн кадрирования исходящих сообщений и cover-параметров в `outline-wire`:**
   - `frame_message`, `CoverParams`, `OutboundFramer`, `OutboundFrames` в `outline_wire::padding_frames`.
   - Устранение 4 копий логики `EarlyShaper -> h2_cap -> PaddingScheme` (`frame_io_ws.rs`, `tcp_transport/writer/transport.rs`, `server/transport/tcp.rs`, `server/transport/vless/tcp.rs`) и 2 копий `CoverParams` (`carrier_padding.rs` на сервере и клиенте).
2. **Потоковый дефреймер UDP-записей XHTTP и заголовки H3 datagram в `outline-wire`:**
   - `encode_record` и `UdpRecordStream` в `outline_wire::udp_records`.
   - `offers_udp_datagrams` и `apply_udp_datagram_header` в `outline_wire::xhttp`.
   - Устранение дублей в `server/transport/xhttp/duplex.rs`, `outline-transport/src/xhttp/stream.rs`, `server/transport/h3_datagram.rs`, `outline-transport/src/resumption.rs`, `outline-transport/src/xhttp/mod.rs` и `outline_wire::resume`.
3. **Общие `tokio`-утилиты жизненного цикла и таймеров в `outline-net`:**
   - `outline_net::task::AbortOnDrop<T = ()>` (единый тип с `into_inner` вместо серверного `server/abort.rs` и клиентского `outline-transport/src/guards.rs::AbortOnDrop`).
   - `outline_net::time::{jittered_period, JitteredTicker, CoverTimer}` (заменяет серверный `server/transport/jittered_ticker.rs`, клиентский `outline_transport::jittered`, а также три копии `COVER_DISABLED_PARK` + `arm_cover` в `ws_writer.rs`, `frame_io_ws.rs` и `tcp_transport/writer/transport.rs`).
4. **Единое ядро клиентского WS writer в `outline-transport`:**
   - Новый внутренний модуль `crates/outline-transport/src/ws_writer.rs`, объединяющий `spawn_ws_writer` (`frame_io_ws.rs`) и цикл задачи в `WsWriteTransport::spawn` (`tcp_transport/writer/transport.rs`).

### Осознанно НЕ входит (YAGNI / принципиальная асимметрия)
- **`vless_mux`:** клиент `outline-client` не реализует клиентский `vless_mux` — протокол поддерживается только сервером для сторонних клиентов (`xray` / `sing-box`).
- **XHTTP `packet-up` драйверы:** клиент (`UplinkWindow`, `BusyRetry` по 503, `FinOnDrop`) и сервер (`DashMap`-реестр, `BTreeMap` reorder-буфер) решают строго асимметричные задачи.
- **Серверный `run_ws_writer` (`bins/outline-server/src/server/transport/ws_writer.rs`):** завязан на `ThroughputMonitor` (`ThrottleSwitchUplink`), `DatagramActivity`, flush без Ping на H3 и серверные метрики; сливать его с клиентским `BudgetedSink`/`HeldHeader` нецелесообразно (он только переходит на общие `CoverTimer` и `CoverParams`).

---

## 2. Архитектурные решения

### 2.1. `outline-wire::padding_frames`
Добавляются:
- `pub fn frame_message<R: Rng>(scheme: PaddingScheme, bytes: Bytes, rng: &mut R) -> Bytes` — при `scheme.is_enabled()` возвращает один padded-кадр, иначе отдаёт `bytes` без копирования.
- `#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct CoverParams { pub scheme: PaddingScheme, pub jitter_min_ms: u64, pub jitter_max_ms: u64 }`:
  - `pub const fn new(scheme: PaddingScheme, cover: bool, jitter_min_ms: u64, jitter_max_ms: u64) -> Option<Self>` (возвращает `Some`, только если `scheme.is_enabled() && cover`);
  - `pub fn next_gap<R: Rng + ?Sized>(&self, rng: &mut R) -> Duration`;
  - `pub fn frame<R: Rng + ?Sized>(&self, rng: &mut R) -> Bytes` (pad-only кадр с `real_len = 0`).
- `pub enum OutboundFrames { Single(Bytes), Multi(Vec<Bytes>) }` с реализацией `IntoIterator<Item = Bytes>` (без аллокации `Vec` на горячем пути после завершения early shaping).
- `pub struct OutboundFramer`:
  - поля: `scheme: PaddingScheme`, `shaper: Option<EarlyShaper>`, `h2_cap: Option<usize>`;
  - `pub fn new(scheme: PaddingScheme, shaper: Option<EarlyShaper>, h2_cap: Option<usize>) -> Self`;
  - `pub fn set_h2_cap(&mut self, h2_cap: Option<usize>)`;
  - `pub fn scheme(&self) -> PaddingScheme`;
  - `pub fn frame<R: Rng>(&mut self, payload: Bytes, rng: &mut R) -> OutboundFrames`:
    1. если `shaper` ещё активен — режет через `shaped_messages(scheme, shaper, &payload, h2_cap, rng)`, и сбрасывает `self.shaper = None`, когда `!shaper.is_active()`;
    2. иначе если `h2_cap` задан и `payload.len() > cap` — режет через `h2_capped_messages(scheme, Some(cap), payload, rng)`;
    3. иначе возвращает `OutboundFrames::Single(frame_message(scheme, payload, rng))`.

В `bins/outline-server/src/server/transport/carrier_padding.rs`:
- `CoverParams` становится реэкспортом `outline_wire::padding_frames::CoverParams`.
- `frame_downlink_message` удаляется (или заменяется прямыми вызовами `outline_wire::padding_frames::frame_message`).
- `ChannelSink` (`tcp.rs`) и цикл в `vless/tcp.rs` используют `OutboundFramer` (`h2_cap` = `None` в местах, где plaintext cap уже применён до шифрования/чтения, чтобы не менять текущую семантику нарезки).

В `crates/outline-transport/src/carrier_padding.rs`:
- `CarrierPadding` делегирует `cover_params(&self) -> Option<CoverParams>`.

### 2.2. `outline-wire::udp_records` и `outline-wire::xhttp`
- В `outline_wire::udp_records`:
  - `pub fn encode_record(payload: &[u8]) -> Result<Bytes, UdpRecordError>` — собирает запись `len:u16 || payload` в `Bytes`.
  - `pub struct UdpRecordStream` (`enabled: bool`, `decoder: Option<UdpRecordDecoder>`, `pending: VecDeque<Bytes>`):
    - `pub fn new(enabled: bool) -> Self`;
    - `pub fn is_enabled(&self) -> bool`;
    - `pub fn push_chunk(&mut self, chunk: Bytes)` — если `decoder` есть, декодирует все полные записи в `pending`; если `enabled == false`, кладёт `chunk` напрямую в `pending` (passthrough);
    - `pub fn pop_datagram(&mut self) -> Option<Bytes>` — отдаёт очередную готовую датаграмму/чанк.
- В `outline_wire::xhttp`:
  - `pub fn offers_udp_datagrams(headers: &http::HeaderMap) -> bool` (`headers.get(UDP_DATAGRAM_HEADER).and_then(|v| v.to_str().ok()) == Some("1")`).
  - `pub fn apply_udp_datagram_header(headers: &mut http::HeaderMap)` (`headers.insert(UDP_DATAGRAM_HEADER, HeaderValue::from_static("1"))`).

### 2.3. `outline-net::task` и `outline-net::time`
В `crates/outline-net/Cargo.toml` добавляются безусловные зависимости `bytes = { workspace = true }` и `outline-wire = { path = "../outline-wire" }` (без дополнительных фич, так что `outline-wire` остаётся без безусловного `tokio`).

- **`outline_net::task::AbortOnDrop<T = ()>`:**
  - `pub struct AbortOnDrop<T = ()>(Option<JoinHandle<T>>);`
  - `pub fn new(handle: JoinHandle<T>) -> Self`
  - `pub fn into_inner(mut self) -> JoinHandle<T>`
  - `#[cfg(feature = "test-helpers")]` или `pub fn noop() -> AbortOnDrop<()>` (проверить, нужно ли `noop()` только под `#[cfg(test)]` — достаточно `pub fn noop() -> Self` под `#[cfg(all(test, target_os = "linux"))]` оставить в `outline-transport` либо сделать `AbortOnDrop<()>::noop()` в `outline-net` или прямо `AbortOnDrop::new(tokio::spawn(async {}))` в тестовом методе `for_loss_probe_test`).
  - В `Drop`: `if let Some(h) = self.0.take() { h.abort(); }`.
  - `bins/outline-server/src/server/abort.rs` удаляется; `crates/outline-transport/src/guards.rs` реэкспортирует `pub use outline_net::task::AbortOnDrop;`.

- **`outline_net::time`:**
  - `pub fn jittered_period(period: Duration) -> Duration` — обёртка над `outline_wire::jitter::jitter_down(period, rand::random())`.
  - `pub struct JitteredTicker { period: Duration, sleep: Pin<Box<Sleep>> }` с `new(period: Duration) -> Self` и cancel-safe `pub async fn tick(&mut self)`. Серверный `server/transport/jittered_ticker.rs` удаляется (его unit-тесты переезжают в `outline-net`); клиентский `outline_transport::jittered` делегирует в `outline_net::time::jittered_period`, а `spawn_keepalive` использует `JitteredTicker`.
  - `pub struct CoverTimer`:
    - внутри хранит `Option<CoverTimerInner>` (`params: CoverParams`, `sleep: Pin<Box<Sleep>>`). Когда `params: Option<CoverParams>` равен `None`, **таймер в timer wheel Tokio не создаётся**;
    - `pub fn new(params: Option<CoverParams>) -> Self` — при `Some(p)` сразу взводит `Sleep` на `Instant::now() + p.next_gap(&mut rand::rng())`;
    - `pub fn is_enabled(&self) -> bool`;
    - `pub async fn wait(&mut self)` — если `Some`, ждёт `sleep.as_mut().await`, иначе `std::future::pending::<()>().await`;
    - `pub fn rearm(&mut self)` — если `Some`, переставляет `sleep` на `Instant::now() + p.next_gap(&mut rand::rng())`;
    - `pub fn frame(&self) -> Option<Bytes>` — строит cover-кадр через `p.frame(&mut rand::rng())`.

### 2.4. Клиентское ядро WS writer (`crates/outline-transport/src/ws_writer.rs`)
Единая функция `spawn_ws_writer<S>(sink: S, options: WsWriterOptions) -> WsWriterHandles`:
- Параметры `WsWriterOptions`:
  - `cover: Option<CoverParams>`
  - `hold_header: Option<Duration>` (при `None` канал удержания не используется и таймер удержания не создаётся; при `Some(SS2022_HEADER_HOLD)` включается режим удержания первого заголовка)
  - `diag_writer: &'static str` (`WRITER_FRAME` или `WRITER_SS`)
  - `stop_on_data_close_frame: bool` (`true` для `frame_io_ws`, `false` для `WsWriteTransport`)
- Возвращает `WsWriterHandles`: `task: AbortOnDrop`, `data_tx: BudgetedSender<Message>`, `ctrl_tx: mpsc::Sender<Message>`, `held_tx: Option<mpsc::Sender<Vec<u8>>>`, `exit_rx: watch::Receiver<bool>`.
- Сохраняет все инварианты:
  - `biased;` `select!` с приоритетом `held_rx` → `ctrl_rx` → `data_rx` → `hold_sleep` → `cover_sleep`;
  - `take_pending_held` перед отправкой `ctrl`, `data` и при закрытии `data_rx`;
  - склейка удержанного заголовка с первым `Message::Binary(p)` в один WS-кадр;
  - освобождение `BudgetedSender` permit только после успешного завершения `send_or_report`;
  - `WriterExit` drop-guard для `watch::Sender<bool>`, гарантирующий уведомление `await_writer_exit` в `WsFrameSink::close`.

---

## 3. Верификация и безопасность изменений

- Побайтовая совместимость wire-протокола: никаких изменений формата заголовков, фреймов и конфигов.
- Полный локальный CI-гейт после завершения всех задач:
  - `cargo fmt --check` по всем пакетам workspace;
  - `cargo clippy --workspace --exclude sockudo-ws --exclude outline-windows --all-targets --no-deps -- -D warnings`;
  - `cargo test --workspace --exclude sockudo-ws --exclude outline-windows`;
  - `RUN_E2E_FAILOVER=1 cargo test -p outline-client --features test-tls --test 'e2e_*' -- --test-threads=1`;
  - `(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)`;
  - проверка отсутствия `ring` в `cargo tree` и `cargo check -p <bin> --no-default-features` для `outline-server` и `outline-client`.
