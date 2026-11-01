# UDP по HTTP/3 DATAGRAM — план реализации

> **Для агентов-исполнителей:** обязательный под-скилл — superpowers:subagent-driven-development. Шаги отмечаются чекбоксами (`- [ ]`).

**Цель.** На носителях `ws_h3` и `xhttp_h3` возить клиентский UDP (SS/SS2022 и VLESS) фреймами HTTP/3 DATAGRAM (RFC 9297), а не внутри надёжного потока. Пакет, который не влезает в датаграмму, идёт по потоку, как сейчас.

**Архитектура.**
- Поток-якорь остаётся прежним: WebSocket-CONNECT или GET сессии xhttp. На нём заголовки, авторизация, NAT и resume.
- Датаграмма — `varint(stream_id/4) || payload`. `payload` — те же байты, что сейчас идут одним WS Binary-кадром или одной записью xhttp.
- На каждое QUIC-соединение один демультиплексор раскладывает датаграммы по якорям.
- Согласование: заголовок `x-outline-udp-datagram: 1` в запросе и такое же эхо в ответе, плюс у QUIC `max_datagram_size()` равен `Some`.

**Стек.** Rust; quinn 0.11 (`send_datagram` / `read_datagram` / `max_datagram_size`); вендоренный h3 0.0.8 (билдеры `enable_datagram` / `enable_extended_connect`, `RequestStream::id()`, `StreamId::index()`).

**Спек:** [`docs/superpowers/specs/2026-10-31-udp-over-h3-datagram-design.md`](../specs/2026-10-31-udp-over-h3-datagram-design.md). Замеры — в памяти `h3-datagram-udp-sizing-measurements`.

## Глобальные ограничения

- Заголовок: `x-outline-udp-datagram`, значение `1`, в запросе и в ответе. Константа `UDP_DATAGRAM_HEADER` в `crates/outline-wire/src/xhttp.rs`, рядом с `UDP_RECORDS_HEADER`.
- Формат датаграммы: QUIC varint (RFC 9000 §16) от `quarter_stream_id = stream_id >> 2`, затем `payload`. Context ID не пишется.
- Клиент предлагает датаграммы, только если одновременно:
  - `[quic] udp_datagrams` (по умолчанию `true`);
  - профиль даёт `max_datagram_frame_size` (Chromium, Firefox, без профиля);
  - носитель `ws_h3` или `xhttp_h3`;
  - план UDP.

  На Safari-профиле не предлагает никогда.
- Сервер подтверждает, только если одновременно:
  - `[server.h3] udp_datagrams` (по умолчанию `true`);
  - клиент прислал заголовок;
  - `connection.max_datagram_size().is_some()`.

  SETTINGS пира прочитать нельзя: `ConnectionState::settings()` закрыт фичей h3, которую мы не включаем. Поэтому достаточное условие — эхо плюс `max_datagram_size()`.
- SETTINGS: обе стороны шлют `H3_DATAGRAM=1` (`builder().enable_datagram(true)`). Сервер дополнительно `enable_extended_connect(true)` (RFC 9220).
- Отправка: если `varint_len + payload.len() <= connection.max_datagram_size()` — датаграмма, иначе поток. Решение на каждый пакет.
- Сервер: `H3_MAX_UDP_PAYLOAD_SIZE` 1350 → 1452. Буфер датаграмм на отправку и приём — `H3_DATAGRAM_BUFFER_BYTES = 1 << 20` на обеих сторонах.
- Неизвестный `quarter_stream_id`, битый varint или переполнение буфера → датаграмма отбрасывается, счётчик растёт, соединение не рвётся.
- Без согласования провод байт в байт как сейчас. Старые клиенты и серверы совместимы.
- Тесты — в `tests/` рядом с модулем (правило репозитория).
- Перед коммитом:
  - `cargo fmt --check` по списку пакетов из CI;
  - `cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings`;
  - android `cargo clippy --no-deps -- -D warnings`;
  - **все шаги job `features-and-invariants` из `.github/workflows/ci.yml`** (включая `cargo check --no-default-features` и grep-инварианты);
  - Linux docker.
- Патченый API вендоренных крейтов упоминается только в gate-модулях. Это касается и комментариев: инвариант CI их тоже ловит.
- Документация EN/RU обновляется парой. В русском тексте «carrier» — «носитель», «gate» — «гейт».
- Исполнители не коммитят. Одобренная работа индексируется.

---

## Файлы

- **Создать:**
  - `crates/outline-wire/src/h3_datagram.rs` — кодек и демультиплексор;
  - `crates/outline-wire/src/tests/h3_datagram.rs`;
  - `crates/outline-transport/src/h3/datagram.rs` — клиентский `H3DatagramChannel`.
- **Изменить (клиент):**
  - `crates/outline-transport/src/h3/shared.rs`, `h3/mod.rs`;
  - `crates/outline-transport/src/xhttp/h3.rs`, `xhttp/h3_pool.rs`, `xhttp/mod.rs`, `xhttp/stream.rs`;
  - `crates/outline-transport/src/ws_stream.rs`, `udp_transport.rs`, `vless/udp.rs`, `dial_plan.rs`, `resumption.rs`;
  - `crates/outline-transport/src/quic/tls_config.rs`, `quic/mod.rs`, `lib.rs`;
  - `crates/outline-metrics/src/*`.
- **Изменить (конфиг клиента):**
  - `bins/outline-ws-rust/src/config/schema.rs`, `config/types.rs`, `config/load/quic.rs`;
  - `src/http/control/config_crud.rs`, `src/lib.rs`.
- **Изменить (сервер):**
  - `bins/outline-ss-rust/src/server/constants.rs`, `server/h3/mod.rs`, `server/h3/http.rs`;
  - `server/transport/udp.rs`, `server/transport/ws_socket.rs`, `server/nat/entry.rs`;
  - `server/transport/xhttp/{h3.rs,handlers.rs,duplex.rs,mod.rs}`;
  - `server/transport/vless/mod.rs`, `server/transport/vless_udp.rs`;
  - `bins/outline-ss-rust/src/config/{file.rs,resolved.rs,loader.rs}`;
  - `bins/outline-ss-rust/src/metrics/{registry.rs,mod.rs}`.
- **Документация:**
  - `bins/outline-ws-rust/{CHANGELOG,README,docs/UPLINK-CONFIGURATIONS}{.md,.ru.md}`;
  - `bins/outline-ss-rust/{CHANGELOG,README}{.md,.ru.md}`;
  - Grafana-дашборды обоих бинарей.

---

### Task 1: кодек и демультиплексор в `outline-wire`

**Файлы:**
- создать `crates/outline-wire/src/h3_datagram.rs` и `crates/outline-wire/src/tests/h3_datagram.rs`;
- изменить `crates/outline-wire/src/lib.rs`, `crates/outline-wire/Cargo.toml`, `crates/outline-wire/src/xhttp.rs`.

**Интерфейсы.**
- Отдаёт (без фич):
  - `pub fn encode_datagram(quarter_stream_id: u64, payload: &[u8]) -> Bytes`;
  - `pub fn decode_datagram(datagram: Bytes) -> Option<(u64, Bytes)>`;
  - `pub fn datagram_overhead(quarter_stream_id: u64) -> usize`;
  - `pub const UDP_DATAGRAM_HEADER: &str = "x-outline-udp-datagram";`.
- Отдаёт (фича `h3-datagram` = `["dep:quinn", "dep:tokio"]`):
  - `pub struct DatagramDemux`;
  - `pub fn DatagramDemux::spawn(connection: quinn::Connection, on_drop: fn(DropReason)) -> Arc<DatagramDemux>`;
  - `pub fn register(&self, quarter_stream_id: u64) -> DatagramRegistration`.

  `DatagramRegistration { rx: mpsc::Receiver<Bytes> }` снимает регистрацию в `Drop`.
- Отдаёт ещё `pub enum DropReason { UnknownStream, Malformed }` и `pub const DATAGRAM_QUEUE: usize = 256`.

- [ ] **Шаг 1. Тесты кодека (падают).** Файл `crates/outline-wire/src/tests/h3_datagram.rs`:

```rust
use bytes::Bytes;

use super::*;

#[test]
fn round_trips_across_varint_widths() {
    for id in [0u64, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1] {
        let d = encode_datagram(id, b"payload");
        assert_eq!(d.len(), datagram_overhead(id) + 7, "id {id}");
        let (got, payload) = decode_datagram(d).expect("decodes");
        assert_eq!(got, id);
        assert_eq!(&payload[..], b"payload");
    }
}

#[test]
fn overhead_matches_rfc9000_varint() {
    assert_eq!(datagram_overhead(0), 1);
    assert_eq!(datagram_overhead(63), 1);
    assert_eq!(datagram_overhead(64), 2);
    assert_eq!(datagram_overhead(16_383), 2);
    assert_eq!(datagram_overhead(16_384), 4);
    assert_eq!(datagram_overhead(1 << 30), 8);
}

#[test]
fn rejects_truncated_or_empty() {
    assert!(decode_datagram(Bytes::new()).is_none());
    // 2-byte varint prefix (0b01) with only one byte present.
    assert!(decode_datagram(Bytes::from_static(&[0x40])).is_none());
}

#[test]
fn empty_payload_is_valid() {
    let (id, p) = decode_datagram(encode_datagram(5, b"")).unwrap();
    assert_eq!((id, p.len()), (5, 0));
}
```

Подключить из `h3_datagram.rs` так: `#[cfg(test)] #[path = "tests/h3_datagram.rs"] mod tests;`.

- [ ] **Шаг 2.** `cargo test -p outline-wire h3_datagram` → FAIL (нет модуля).

- [ ] **Шаг 3. Кодек.** `crates/outline-wire/src/h3_datagram.rs` (без фич):

```rust
//! HTTP/3 datagrams (RFC 9297) bound to a request stream: a QUIC DATAGRAM
//! payload is `varint(quarter_stream_id) || payload`, `quarter_stream_id =
//! stream_id >> 2`. The carriers put in `payload` exactly the bytes they would
//! otherwise send as one WebSocket Binary frame or one xhttp UDP record.

use bytes::{BufMut, Bytes, BytesMut};

/// Bytes the quarter-stream-id prefix takes (RFC 9000 §16 varint).
pub fn datagram_overhead(quarter_stream_id: u64) -> usize {
    match quarter_stream_id {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

pub fn encode_datagram(quarter_stream_id: u64, payload: &[u8]) -> Bytes {
    debug_assert!(quarter_stream_id < 1 << 62, "varint range");
    let len = datagram_overhead(quarter_stream_id);
    let mut out = BytesMut::with_capacity(len + payload.len());
    match len {
        1 => out.put_u8(quarter_stream_id as u8),
        2 => out.put_u16(0x4000 | quarter_stream_id as u16),
        4 => out.put_u32(0x8000_0000 | quarter_stream_id as u32),
        _ => out.put_u64(0xc000_0000_0000_0000 | quarter_stream_id),
    }
    out.put_slice(payload);
    out.freeze()
}

/// `None` on an empty or truncated prefix.
pub fn decode_datagram(mut datagram: Bytes) -> Option<(u64, Bytes)> {
    let first = *datagram.first()?;
    let len = 1usize << (first >> 6);
    if datagram.len() < len {
        return None;
    }
    let mut id = u64::from(first & 0x3f);
    for b in &datagram[1..len] {
        id = (id << 8) | u64::from(*b);
    }
    let payload = datagram.split_off(len);
    Some((id, payload))
}
```

В `crates/outline-wire/src/lib.rs` добавить `pub mod h3_datagram;`, а в `xhttp.rs` — константу `UDP_DATAGRAM_HEADER` с doc-комментарием в стиле `UDP_RECORDS_HEADER`.

- [ ] **Шаг 4.** `cargo test -p outline-wire h3_datagram` → PASS.

- [ ] **Шаг 5. Тест демультиплексора (падает)**, под `#[cfg(feature = "h3-datagram")]`, в том же файле тестов. Две реальные quinn-конечные точки на loopback с самоподписанным сертификатом. Сертификат — уже имеющийся в репозитории хелпер, если он доступен из `outline-wire`; иначе `rcgen` как dev-зависимость (проверить, что он уже есть в lock-файле). Сервер шлёт:
  - `encode_datagram(1, b"a")`;
  - `encode_datagram(2, b"b")`;
  - `encode_datagram(9, b"x")` — незарегистрированный id;
  - сырые `[0x40]` — битый varint.

  Клиент держит `register(1)` и `register(2)`. Ожидание:
  - `rx1` получает `a`, `rx2` получает `b`;
  - `on_drop` вызван с `UnknownStream` и `Malformed` (счёт через `AtomicUsize` в static);
  - после `drop(reg1)` датаграмма на id 1 считается `UnknownStream`.

- [ ] **Шаг 6. Демультиплексор**, в том же модуле под `#[cfg(feature = "h3-datagram")]`:

```rust
#[cfg(feature = "h3-datagram")]
mod demux {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use tokio::sync::mpsc;

    use super::decode_datagram;

    pub const DATAGRAM_QUEUE: usize = 256;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum DropReason {
        UnknownStream,
        Malformed,
    }

    /// One reader of `read_datagram` per QUIC connection, routing each HTTP/3
    /// datagram to the request stream it is bound to.
    pub struct DatagramDemux {
        routes: Mutex<HashMap<u64, mpsc::Sender<Bytes>>>,
    }

    pub struct DatagramRegistration {
        pub rx: mpsc::Receiver<Bytes>,
        id: u64,
        demux: Arc<DatagramDemux>,
    }

    impl Drop for DatagramRegistration {
        fn drop(&mut self) {
            self.demux.routes.lock().expect("demux lock").remove(&self.id);
        }
    }

    impl DatagramDemux {
        pub fn spawn(connection: quinn::Connection, on_drop: fn(DropReason)) -> Arc<Self> {
            let demux = Arc::new(Self { routes: Mutex::new(HashMap::new()) });
            let weak = Arc::downgrade(&demux);
            tokio::spawn(async move {
                while let Ok(datagram) = connection.read_datagram().await {
                    let Some(demux) = weak.upgrade() else { return };
                    let Some((id, payload)) = decode_datagram(datagram) else {
                        on_drop(DropReason::Malformed);
                        continue;
                    };
                    let tx = demux.routes.lock().expect("demux lock").get(&id).cloned();
                    match tx {
                        // A full queue drops like a lost UDP packet.
                        Some(tx) => {
                            let _ = tx.try_send(payload);
                        },
                        None => on_drop(DropReason::UnknownStream),
                    }
                }
            });
            demux
        }

        pub fn register(self: &Arc<Self>, quarter_stream_id: u64) -> DatagramRegistration {
            let (tx, rx) = mpsc::channel(DATAGRAM_QUEUE);
            self.routes.lock().expect("demux lock").insert(quarter_stream_id, tx);
            DatagramRegistration { rx, id: quarter_stream_id, demux: Arc::clone(self) }
        }
    }
}
#[cfg(feature = "h3-datagram")]
pub use demux::{DATAGRAM_QUEUE, DatagramDemux, DatagramRegistration, DropReason};
```

В `crates/outline-wire/Cargo.toml`:
- `[features] h3-datagram = ["dep:quinn", "dep:tokio"]`;
- `quinn` и `tokio` (`rt`, `sync`) — optional, той же версии и с теми же `default-features`/features, что в `outline-transport`.

Переполненная очередь (`try_send` → Full) отбрасывает пакет, как потерю UDP, и отдельной метрики не получает.

**Отличия от спека:**
- причина `send_buffer` в `dropped_total` убрана: старые датаграммы из буфера отправки quinn выбрасывает молча и не сообщает об этом, считать нечего;
- проверка «`H3_DATAGRAM=1` у пира» заменена на эхо плюс `max_datagram_size()`. SETTINGS пира закрыты фичей h3 (см. глобальные ограничения).

- [ ] **Шаг 7.** `cargo test -p outline-wire --features h3-datagram` → PASS. Затем `cargo check -p outline-wire` (без фичи) и clippy.

---

### Task 2: SETTINGS, размеры и выключатели на обеих сторонах

**Файлы:**
- клиент: `crates/outline-transport/src/h3/shared.rs:700`, `crates/outline-transport/src/xhttp/h3_pool.rs:324`, `crates/outline-transport/src/quic/tls_config.rs`, `quic/mod.rs`, `lib.rs`; `bins/outline-ws-rust/src/config/{schema.rs,types.rs,load/quic.rs}`, `src/http/control/config_crud.rs`, `src/lib.rs`;
- сервер: `bins/outline-ss-rust/src/server/constants.rs`, `server/h3/mod.rs`, `server/h3/http.rs:43`; `src/config/{file.rs,resolved.rs,loader.rs}`, `src/server/tests/mod.rs` (литерал `sample_config_with_users`).

**Интерфейсы.**
- Клиент:
  - `pub fn init_quic_udp_datagrams(enabled: bool)` и `pub(crate) fn quic_udp_datagrams_enabled() -> bool` в `quic/tls_config.rs` (OnceLock, по умолчанию `true`; паттерн `init_quic_idle_timeout`), реэкспорт из `quic/mod.rs` и `lib.rs`;
  - `pub(crate) fn h3_client_builder() -> h3::client::Builder` в `h3/vendored.rs`: `enable_datagram(true)`.
- Сервер:
  - `Config.h3_udp_datagrams: bool` (resolved);
  - `pub(super) fn h3_server_builder() -> h3::server::Builder` в `server/h3/vendored.rs`: `enable_datagram(true).enable_extended_connect(true)`.

- [ ] **Шаг 1. Тесты (падают):**
  - клиентский конфиг: `[quic] udp_datagrams = false` парсится, по умолчанию `true`; неизвестный ключ по-прежнему ошибка (`deny_unknown_fields`);
  - серверный конфиг: `[server.h3] udp_datagrams` парсится, по умолчанию `true`;
  - серверный H3-тест в `server/tests/h3.rs`. Клиент со своим билдером (`enable_datagram(true)`) подключается к тестовому серверу. Сервер отвечает на CONNECT, а `quinn::Connection::max_datagram_size()` на клиенте равен `Some(n)` с `n > 1200`;
  - тест констант: `H3_MAX_UDP_PAYLOAD_SIZE == 1452`.
- [ ] **Шаг 2.** Убедиться, что тесты падают.
- [ ] **Шаг 3. Реализация:**
  - клиент: `h3::client::new(h3_quinn::Connection::new(c))` → `vendored::h3_client_builder().build(h3_quinn::Connection::new(c))` в обоих местах. Builder доступен как `h3::client::builder()`; обращение — в gate `h3/vendored.rs`, `xhttp/h3_pool.rs` идёт через него;
  - сервер: `H3Connection::new(..)` → `vendored::h3_server_builder().build(..)` в `server/h3/http.rs:43`;
  - сервер: `H3_MAX_UDP_PAYLOAD_SIZE = 1_452`; добавить `H3_DATAGRAM_BUFFER_BYTES: usize = 1 << 20`. В `build_h3_transport_config` вместо `h3_connection_window_bytes`: `datagram_receive_buffer_size(Some(H3_DATAGRAM_BUFFER_BYTES))` и `datagram_send_buffer_size(H3_DATAGRAM_BUFFER_BYTES)`;
  - клиент: в `quic/vendored.rs::apply_browser_tp_options`, ветка `Some(size)` — `datagram_send_buffer_size(H3_DATAGRAM_BUFFER_BYTES)`; константа в `quic/tls_config.rs`. Initial от этого не меняется: буфер отправки не является transport parameter;
  - конфиги и view по паттерну соседних полей: клиент `QuicSection` → `QuicConfig` → `load_quic_config` → `QuicConfigView` → `init_quic_udp_datagrams` в `src/lib.rs:84-99`; сервер `ServerH3Section` → `Config` → loader.
- [ ] **Шаг 4.**
  - `cargo test -p outline-transport --all-features`;
  - `cargo test -p outline-ss-rust`;
  - `cargo test -p outline-ws-rust`;
  - `cargo check -p outline-ss-rust --no-default-features` и `cargo check -p outline-ws-rust --no-default-features` без предупреждений.

---

### Task 3: клиент — SS-UDP по ws_h3 через датаграммы

**Файлы:**
- создать `crates/outline-transport/src/h3/datagram.rs` и `crates/outline-transport/src/h3/tests/datagram.rs`;
- изменить `h3/shared.rs`, `h3/mod.rs`, `ws_stream.rs`, `dial_plan.rs`, `resumption.rs`, `udp_transport.rs`, `crates/outline-metrics/src/*`.

**Интерфейсы.**
- Потребляет:
  - Task 1 — `encode_datagram`, `datagram_overhead`, `DatagramDemux`, `DatagramRegistration`, `UDP_DATAGRAM_HEADER`;
  - Task 2 — `quic_udp_datagrams_enabled()`.
- Отдаёт:
  - `pub(crate) struct H3DatagramBinding { connection: quinn::Connection, quarter_stream_id: u64, registration: DatagramRegistration }`;
  - `pub(crate) struct H3DatagramChannel` (`impl DatagramChannel`):
    - `H3DatagramChannel::new(binding: H3DatagramBinding, fallback: Arc<dyn DatagramChannel>, transport: &'static str /* "ws_h3" | "xhttp_h3" */, proto: &'static str /* "ss" | "vless" */) -> Self`;
  - поле `datagram: Option<H3DatagramBinding>` в `TransportStream::H3` (`ws_stream.rs:187`) и метод `TransportStream::take_h3_datagram(&mut self) -> Option<H3DatagramBinding>`;
  - флаг `DialResumeOptions.udp_datagram_requested: bool` (`dial_plan.rs:35`, derive уже `Copy`) и поле `NegotiatedResume.udp_datagram_accepted: bool` (`resumption.rs:155`).
- Метрики (`crates/outline-metrics`, по всем местам: поле `Metrics`, `registration/core.rs`, `registration/mod.rs`, функция в `transport.rs` + реэкспорт, `stub.rs`, `process.rs` reset и предзаполнение, тесты рендера):
  - `outline_ws_udp_h3_datagrams_total{direction,transport,proto}`;
  - `outline_ws_udp_h3_datagram_fallback_total{direction,transport,proto}`;
  - `outline_ws_udp_h3_datagram_dropped_total{reason}` (`unknown_stream` | `malformed`);
  - `outline_ws_udp_h3_datagram_sessions_total{transport,state}` (`negotiated` | `declined`).

- [ ] **Шаг 1. Юнит-тесты `H3DatagramChannel` (падают).** Пара quinn на loopback, как в Task 1. Сервер-эхо читает `read_datagram` и отправляет то же обратно; fallback — `MockChannel` из `crates/outline-transport/src/tests/udp_transport.rs:39`, его нужно сделать `pub(crate)`.
  - пакет 100 байт уходит датаграммой, а не в `MockChannel`, и возвращается через `recv_datagram`;
  - пакет больше `max_datagram_size()` уходит в `MockChannel.sent`;
  - `recv_datagram` отдаёт пакет и из `MockChannel`, и из очереди демультиплексора;
  - `close()` закрывает fallback и снимает регистрацию.
- [ ] **Шаг 2. Тест согласования (падает).** `udp_datagram_requested` ставит `x-outline-udp-datagram: 1` в CONNECT. `parse_resume_response_echo` поднимает `udp_datagram_accepted` только при эхе `1` в ответе.
- [ ] **Шаг 3. Реализация:**
  - `SharedH3Connection` (`h3/shared.rs:223`): поле `datagrams: Option<Arc<DatagramDemux>>`. Создаётся в `connect_h3_connection` рядом с `connection_handle`, только если `quic_udp_datagrams_enabled()` и `connection.max_datagram_size().is_some()`. Колбэк `on_drop` пишет `outline_ws_udp_h3_datagram_dropped_total`;
  - `open_websocket_inner` (`h3/shared.rs:339`):
    - если `resume.udp_datagram_requested && self.datagrams.is_some()` — вставить заголовок перед `send_request`;
    - после `send_request` (`:372`) взять `stream.id().index()`;
    - после `parse_resume_response_echo` (`:407`), если `negotiated.udp_datagram_accepted`, собрать `H3DatagramBinding { connection: self.connection.clone(), quarter_stream_id, registration: demux.register(quarter_stream_id) }`. Регистрироваться **до** `client_ws_stream`, чтобы не потерять первую датаграмму сервера;
    - записать `sessions_total{state}`;
  - `H3Dialer::open_on` (`:623`): передать binding в `TransportStream::H3 { .., datagram }`;
  - `connect_ws_h3_with_fallback` (`dial_plan.rs:262`) прокидывает `options.resume` как есть. Флаг ставит `UdpWsTransport::connect` / `connect_with_resume` (`udp_transport.rs:~270/~315`): `udp_datagram_requested: true` при `mode == WsH3`;
  - `UdpWsTransport::from_websocket` (`udp_transport.rs:132`): `ws_stream.take_h3_datagram()` берётся до `from_ws_datagrams`. При `Some(binding)`:
    - `channel = Arc::new(H3DatagramChannel::new(binding, Arc::new(from_ws_datagrams(ws_stream, ..)), "ws_h3", "ss"))`;
    - padding прежний: `effective_carrier_padding()`; в датаграмму кладётся тот же кадр с паддингом, что и в Binary;
  - `H3DatagramChannel::send_datagram`:

```rust
let room = self.binding.connection.max_datagram_size().unwrap_or(0);
if datagram_overhead(self.binding.quarter_stream_id) + data.len() <= room {
    match self.binding.connection.send_datagram(encode_datagram(self.binding.quarter_stream_id, &data)) {
        Ok(()) => {
            metrics::record_udp_h3_datagram("up", self.transport, self.proto);
            return Ok(());
        },
        // TooLarge after an MTU drop, or the peer stopped accepting: use the stream.
        Err(_) => {},
    }
}
metrics::record_udp_h3_datagram_fallback("up", self.transport, self.proto);
self.fallback.send_datagram(data).await
```

  - `recv_datagram`: `tokio::select!` по `registration.rx.recv()` и `fallback.recv_datagram()`. EOF fallback — это EOF канала; закрытая очередь демультиплексора — ещё не EOF, ждём fallback.
- [ ] **Шаг 4.** `cargo test -p outline-transport --all-features` → PASS. Метрики: тест рендера в `crates/outline-metrics`.

---

### Task 4: сервер — SS-UDP по ws_h3 через датаграммы, сквозной тест

**Файлы:**
- `bins/outline-ss-rust/src/server/h3/{mod.rs,http.rs,vendored.rs}`;
- `server/transport/{udp.rs,ws_socket.rs}`, `server/nat/entry.rs`;
- `src/metrics/{registry.rs,mod.rs}`;
- тесты `bins/outline-ss-rust/src/server/tests/cross_repo_ss_h3_datagram.rs` (новый) и `src/metrics/tests/mod.rs`;
- `bins/outline-ss-rust/Cargo.toml`: `outline-wire` с фичей `h3-datagram`.

**Интерфейсы.**
- Потребляет Task 1 и Task 2.
- Отдаёт:
  - `pub(in crate::server) struct H3DatagramRoute { connection: quinn::Connection, quarter_stream_id: u64, registration: DatagramRegistration }`;
  - параметр `datagram: Option<H3DatagramRoute>` у `handle_udp_h3_connection` и `run_udp_relay`. Для axum и xhttp передаётся `None`; xhttp — до Task 5;
  - `struct DatagramResponseSender { route_conn: quinn::Connection, quarter_stream_id: u64, stream: UdpResponseSender, padding: PaddingScheme, monitor: Option<Arc<ThroughputMonitor>> }`, `impl ResponseSender`, `protocol()` = `Protocol::Http3`.
- Метрики сервера (`describe_counter!` в `registry.rs` и метод в `metrics/mod.rs`, паттерн `record_udp_relay_drop`):
  - `outline_ss_udp_h3_datagrams_total{direction,proto}`;
  - `outline_ss_udp_h3_datagram_fallback_total{direction,proto}`;
  - `outline_ss_udp_h3_datagram_dropped_total{reason}`;
  - `outline_ss_udp_h3_datagram_sessions_total{state}`.

- [ ] **Шаг 1. Сквозной тест (падает)**, `cross_repo_ss_h3_datagram.rs` (по образцу `cross_repo_ss_xhttp.rs:201` и ws-h3 сервера из `cross_repo_vless.rs:~290`):
  - `UdpWsTransport::connect(.., TransportMode::WsH3, ..)` → `send_packet(ss_first_chunk(upstream, b"ping"))` → `read_packet()` == `pong` от UDP-эхо;
  - метрика сервера `outline_ss_udp_h3_datagrams_total{direction="up"}` ≥ 1;
  - клиентская `outline_ws_udp_h3_datagrams_total{direction="down",transport="ws_h3"}` ≥ 1;
  - пакет 1400 байт (больше места) доходит и считается в `fallback_total{direction="up"}`;
  - сервер с `h3_udp_datagrams = false` → `sessions_total{state="declined"}`, обмен идёт по потоку;
  - resume: обрыв якоря и повторный `connect_with_resume` с тем же `SessionId` → датаграммы снова идут, NAT тот же (ответ от того же upstream-сокета).
- [ ] **Шаг 2.** Убедиться, что тест падает.
- [ ] **Шаг 3. Реализация:**
  - `handle_h3_connection` (`server/h3/http.rs:37`): `let dgram_conn = connection.clone();` до `h3_server_builder().build(..)`. `demux = (ctx.h3_udp_datagrams && dgram_conn.max_datagram_size().is_some()).then(|| DatagramDemux::spawn(dgram_conn.clone(), on_drop))`. Передать `Option<(quinn::Connection, Arc<DatagramDemux>)>` в `handle_h3_request` (`:95`) новым параметром;
  - в `handle_h3_request`, ветка UDP (`path_is_udp`):
    - если в запросе `x-outline-udp-datagram: 1` и есть demux — `quarter = stream.id().index()`, `registration = demux.register(quarter)` до `send_response`;
    - в ответ (`:295`) добавить эхо-заголовок;
    - собрать `H3DatagramRoute` и передать в `handle_udp_h3_connection` (`:~360`);
    - TCP- и VLESS-пути не трогать (VLESS — Task 6);
  - `run_udp_relay` (`udp.rs:1086`):
    - при `Some(route)` — `select!`-ветка в главном цикле по `route.registration.rx.recv()`. Каждая датаграмма идёт тем же путём, что `WsFrame::Binary(data)` (`:~1178`): снятие padding, `record_websocket_binary_frame`, mesh или локальный `handle_udp_datagram_common`;
    - выделить тело Binary-ветки в функцию `ingest_udp_binary(..)`, чтобы обе ветки звали одно и то же, без копии кода;
    - отправитель ответов: при `Some(route)` — `UdpResponseSender::new(Arc::new(DatagramResponseSender { stream: <нынешний sender>, .. }))`, иначе нынешний;
  - `DatagramResponseSender::send_bytes(data)`:
    - `framed = carrier_padding::frame_downlink_message(padding, data)` — тот же кадр, что у `Http3ResponseSender`;
    - если `datagram_overhead + framed.len() <= max_datagram_size()` и `send_datagram(encode_datagram(..))` ок → метрика, `true`;
    - иначе `stream.send_bytes(data)`. Padding внутри него свой, двойного паддинга нет: в поток уходит исходный `data`;
  - `reattach_parked_nat_keys` / `release_ss_udp_stream_on_drop` не меняются: отправитель NAT-записи — это `UdpResponseSender` нового якоря, а он уже указывает на датаграммы нового якоря;
  - cover-трафик padding остаётся в WS-писателе, в датаграммы не идёт.
- [ ] **Шаг 4.** `cargo test -p outline-ss-rust` → PASS, включая новый сквозной тест.

---

### Task 5: xhttp_h3 — SS-UDP через датаграммы (клиент и сервер)

**Файлы:**
- клиент: `crates/outline-transport/src/xhttp/{h3.rs,h3_pool.rs,mod.rs,stream.rs}`;
- сервер: `bins/outline-ss-rust/src/server/transport/xhttp/{h3.rs,handlers.rs,duplex.rs,mod.rs}`, `server/h3/http.rs`;
- тест: дописать `cross_repo_ss_h3_datagram.rs` случаем `TransportMode::XhttpH3` (packet-up и stream-one).

**Интерфейсы.**
- Потребляет Task 1–4.
- Отдаёт:
  - `PooledCarrier.connection: quinn::Connection` и `PooledCarrier.datagrams: Option<Arc<DatagramDemux>>` (`xhttp/h3_pool.rs:242`, наполняется в `session_on` `:251`; demux создаётся в `dial` `:295` по тем же условиям, что в Task 3);
  - у `XhttpStream` — `take_h3_datagram(&mut self) -> Option<H3DatagramBinding>`;
  - на сервере — `XhttpH3Ctx.datagram: Option<(quinn::Connection, Arc<DatagramDemux>)>`.

- [ ] **Шаг 1. Сквозной тест (падает).** Тот же набор, что в Task 4, для `XhttpH3` в режимах packet-up и stream-one.
- [ ] **Шаг 2. Клиент:**
  - `build_session_request_headers` (`xhttp/mod.rs:387`): параметр `udp_datagram: bool` → заголовок рядом с `UDP_RECORDS_HEADER`;
  - `parse_udp_datagram_echo(requested, headers) -> bool` — рядом с `parse_udp_records_echo` (`:491`);
  - `open_h3_get` (`h3.rs:275`) и `open_h3_stream_one` (`:485`): `stream.id().index()` после `send_request` (`:312`). Регистрация в demux — до `recv_response`, эхо — после (`:338`, `:547`). Binding передаётся в `XhttpStream::from_channels` новым аргументом;
  - флаг ставит `UdpWsTransport::connect*` при `mode == XhttpH3`, через `TransportDialOptions` → `connect_xhttp(.., datagram_records, udp_datagram)`;
  - `from_websocket` берёт binding так же, как в Task 3, с `transport = "xhttp_h3"`. Fallback-канал — нынешний `from_ws_datagrams(xhttp_stream)` с записями `len||payload`; в датаграмму кладётся **сам пакет без записи** (граница датаграммы — граница пакета).
- [ ] **Шаг 3. Сервер:**
  - `handle_h3_request` передаёт `(connection, demux)` в `XhttpH3Ctx` (`http.rs:100-140`);
  - `xhttp_h3_get` (`xhttp/h3.rs:120`) и `xhttp_h3_stream_one` (`:414`):
    - если `XhttpRoute::SsUdp` + заголовок + demux — `register(stream.id().index())` и эхо рядом с `apply_udp_records_echo` (`:212`);
    - регистрация хранится в сессии: `XhttpSession::attach_datagram(route: H3DatagramRoute)`, `xhttp/mod.rs:389`. Сессия переживает отдельные POST'ы, а GET — её якорь;
  - `spawn_relay` (`handlers.rs:997`), SS-UDP-ветка (`:~1150`): передать `session.take_datagram()` в `run_udp_relay(.., datagram)`. Дальше работает код Task 4. `DatagramResponseSender.stream` = нынешний `XhttpUdpResponseSender`;
  - повторный GET той же сессии (resume) заменяет регистрацию.
- [ ] **Шаг 4.** `cargo test -p outline-transport --all-features`, `cargo test -p outline-ss-rust` → PASS.

---

### Task 6: VLESS-UDP по ws_h3 и xhttp_h3 через датаграммы

**Файлы:**
- клиент: `crates/outline-transport/src/vless/udp.rs`;
- сервер: `bins/outline-ss-rust/src/server/transport/vless/mod.rs`, `server/transport/vless_udp.rs`, `server/transport/vless/ctx.rs`, `server/h3/http.rs`;
- тест: `bins/outline-ss-rust/src/server/tests/cross_repo_vless.rs` — UDP-случаи по ws_h3 и xhttp_h3.

**Интерфейсы.**
- Потребляет Task 1–5.
- Решение по формату:
  - датаграммы включаются только для простой VLESS-команды UDP (не mux / XUDP);
  - первый пакет, где лежит VLESS request header, **всегда идёт по потоку**;
  - датаграммы разрешены только после ответа сервера на заголовок, то есть после первого downlink-сообщения;
  - каждая датаграмма — ровно одна запись `len(2 BE) || payload`, тот же формат, что у потоковых записей.

- [ ] **Шаг 1. Сквозной тест (падает):**
  - VLESS UDP по ws_h3 и по xhttp_h3: `VlessUdpTransport::connect` → эхо работает, метрики `proto="vless"` в датаграммах ≥ 1 с обеих сторон;
  - mux-сессия VLESS датаграммы не согласует: `sessions_total{state="declined"}`.
- [ ] **Шаг 2. Клиент.** `VlessUdpTransport::from_websocket` (`vless/udp.rs:82`): binding берётся так же; канал `H3DatagramChannel::new(.., proto = "vless")`. `send_datagram` ещё до ответа сервера идёт в fallback — флаг `AtomicBool header_acked`, его ставит первый `recv_datagram`.
- [ ] **Шаг 3. Сервер.**
  - `handle_h3_request`, ветка `path_is_vless`: регистрация и эхо по тем же правилам. Route передаётся в `handle_vless_h3_connection` (`vless/mod.rs:776`) → `run_vless_relay`;
  - после `establish_vless_udp_upstream` (`vless/mod.rs:539`), только для не-mux UDP:
    - вход: очередь датаграмм → `forward_vless_udp_client_frames` (`vless_udp.rs:305`), запись целая;
    - выход: `relay_vless_udp_upstream_to_client` (`vless_udp.rs:608`) получает альтернативный выход: датаграмма, если влезает `framed`, иначе нынешний `tx`;
    - выход абстрагировать через `VlessWsOutbound` (`vless/ctx.rs:239`), добавив `datagram: Option<DatagramOut>`;
  - для mux / XUDP регистрацию снять (`drop`) и записать `declined`.
- [ ] **Шаг 4.** `cargo test -p outline-ss-rust`, `cargo test -p outline-transport --all-features` → PASS.

---

### Task 7: документация, дашборды, e2e на реальных бинарях, проверки CI

**Файлы:**
- `bins/outline-ws-rust/{CHANGELOG,README,docs/UPLINK-CONFIGURATIONS}{.md,.ru.md}`;
- `bins/outline-ss-rust/{CHANGELOG,README}{.md,.ru.md}`;
- Grafana-дашборды обоих бинарей;
- `bins/outline-ws-rust/tests/e2e_tls_carriers.rs`;
- `bins/outline-ui` — только если в UI есть экраны `[quic]` или `[server.h3]` (проверить grep'ом `idle_timeout_secs` в `bins/outline-ui/frontend/src`, поле `udp_datagrams` добавить рядом).

- [ ] **Шаг 1. E2e на реальных бинарях** (`e2e_tls_carriers.rs`, по образцу `tls_ws_h3_ss_dial_works` `:121` + `socks5_udp_echo` из `tests/support/traffic.rs:77`):
  - SOCKS5 UDP через `ws_h3` и `xhttp_h3` с профилем Chromium: эхо работает, `outline_ws_udp_h3_datagrams_total` > 0 по `metrics_scrape`;
  - профиль Safari: датаграмм 0, эхо работает.
- [ ] **Шаг 2. Документация EN/RU:**
  - CHANGELOG обоих бинарей (Unreleased);
  - ключи `[quic] udp_datagrams` и `[server.h3] udp_datagrams`;
  - заголовок `x-outline-udp-datagram`;
  - размеры: предел 1452, стартовый MTU 1400, «большие — в поток», Safari без датаграмм;
  - описание метрик;
  - в README сервера: порядок раскатки «сервер раньше клиента».
- [ ] **Шаг 3. Дашборды:** панели датаграмм, fallback и drops на клиенте и сервере.
- [ ] **Шаг 4. Проверки, как в CI:**
  - fmt по списку пакетов;
  - clippy workspace и android;
  - все шаги `features-and-invariants` (извлечь из `ci.yml` по одному в файл и выполнить);
  - `cargo test --workspace`;
  - e2e (`RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls --test e2e_tls_carriers -- --test-threads=1`);
  - Linux docker: workspace на фичах по умолчанию и `outline-transport --all-features`. `--all-features` на весь workspace нельзя: конфликт jemalloc и mimalloc.

---

## Порядок выкатки

1. Серверы — по одному узлу, с проверкой `outline_ss_udp_h3_datagram_sessions_total`.
2. Клиенты .102, .104, cloud1/2 — по одному. После каждого:
   - `cap102b.sh` на .102;
   - метрики `datagrams` / `fallback`.
3. Откат — `udp_datagrams = false` на той стороне, где проблема, без пересборки.
4. Проверить, не закреплён ли на серверах `[server.h3] initial_mtu` 1200: замер показал около 10 % пакетов по 1200.
