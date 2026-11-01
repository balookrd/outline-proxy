# UDP по H3 DATAGRAM: паддинг под размер датаграммы и маршрут после переключения — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Цель:** чтобы на эндпоинтах с паддингом UDP-пакет, который сам по себе влезает в датаграмму, уходил датаграммой, а не потоком; и чтобы после переключения аплинка downlink не уходил в маршрут брошенного носителя.

**Архитектура:** отправитель (клиент на uplink, сервер на downlink) узнаёт свободное место в датаграмме (`max_datagram_size − datagram_overhead`) ДО кадрирования и урезает случайный паддинг до этого остатка. Если запись не влезает даже без паддинга, кадрирование прежнее (полный диапазон), и пакет идёт потоком, как сейчас. Декодер на обеих сторонах читает только длины из заголовка кадра и границы схемы не проверяет. Поэтому урезанный паддинг (в том числе ниже `min_bytes`) принимают уже раскатанные пиры: изменение только на стороне отправителя, клиент и сервер выкатываются независимо. Вторая часть: сервер сбрасывает цель downlink-датаграмм, как только маршрут перестал доставлять, и есть воспроизведение мягкого переключения VLESS-UDP с датаграммами.

**Стек:** Rust, quinn 0.11, h3 (vendored), tokio; крейты `outline-wire`, `outline-transport`, бинари `outline-ss-rust`, `outline-ws-rust`.

## Global Constraints

- Комментарии в коде и сообщения коммитов — по-английски; документация EN и RU обновляется вместе (`CHANGELOG.md` и `CHANGELOG.ru.md` обоих бинарей).
- Тесты — в `tests/` рядом с модулем (`#[cfg(test)] #[path = "tests/<name>.rs"] mod tests;`), не inline.
- Формат кадра паддинга не меняется: `real_len:u16 | pad_len:u16 | real | pad`, `PADDING_FRAME_HEADER_LEN = 4`.
- Формат датаграммы не меняется: `varint(quarter_stream_id) || payload`, накладные расходы — `outline_wire::h3_datagram::datagram_overhead(quarter_stream_id)`.
- Поток (stream fallback) кадрируется как сейчас — полный диапазон `[min_bytes, max_bytes]`; урезание действует ТОЛЬКО на то, что уходит датаграммой.
- Cover-кадры по-прежнему никогда не идут датаграммой.
- Без новых метрик и ключей конфига; Grafana не трогаем.
- Перед коммитом — CI-эквивалент локально: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo clippy -p outline-ws-rust --no-default-features --all-targets -- -D warnings`, тесты; linux-прогон в docker (workspace на default-фичах + `outline-transport --all-features`, e2e `e2e_tls_carriers`).
- Коммит и пуш — только по явной команде владельца; раскатка — по одному узлу.

## Почему так (замер 2026-11-01)

- Все клиенты парка ходят на пути `/p*` (`padded = true`), `[padding] max_bytes = 256`.
- Сервер вызывает `carrier_padding::frame_downlink_message` до проверки размера, клиент вызывает `carrier_padding::frame_payload_into` до `send_datagram`.
- Сегмент googlevideo весит 1350 байт: запись VLESS 1352 байта + 4 байта заголовка + U(0..256) паддинга. В остаток ~1396 байт она влезает только при паддинге меньше ~40 байт.
- Результат на nuxt2: downlink VLESS — 133 270 пакетов потоком против 23 374 датаграммами (85 % потоком).
- PMTU тут ни при чём: на nuxt2 QUIC встал на внешние 1426 байт.
- Отдельно, около 09:01, мягкое переключение `.102` с nuxt2 на nuxt:
  - TCP-сессии возобновились (`orphan_resume_hit_total{kind="tcp"}` = 48), UDP — ни одной.
  - nuxt2 ещё ~2 минуты отправлял downlink в старый носитель (2873 датаграммы и 15 957 пакетов потоком за 09:02), а клиент получил 249 и 1018.
  - У клиента набралось `dropped_total{reason="unknown_stream"}` 60. Видео остановилось.

## Файлы

- `crates/outline-wire/src/padding.rs` — `PaddingScheme::pad_len_capped`, `datagram_pad_budget`.
- `crates/outline-wire/src/tests/padding.rs` — тесты.
- `crates/outline-transport/src/frame_io.rs` — `DatagramChannel::datagram_room` (по умолчанию `None`).
- `crates/outline-transport/src/h3/datagram.rs` — реализация `datagram_room` у `H3DatagramChannel`.
- `crates/outline-transport/src/carrier_padding.rs` — `frame_datagram_into`.
- `crates/outline-transport/src/vless/udp.rs`, `crates/outline-transport/src/udp_transport.rs` — uplink через `frame_datagram_into`.
- `crates/outline-transport/src/h3/tests/datagram.rs`, `crates/outline-transport/src/tests/carrier_padding.rs` — тесты клиента.
- `bins/outline-ss-rust/src/server/transport/carrier_padding.rs` — `frame_datagram_message`.
- `bins/outline-ss-rust/src/server/transport/h3_datagram.rs` — `DatagramDownlink::send_record`, сброс цели при `Ok(None)`.
- `bins/outline-ss-rust/src/server/transport/vless_udp.rs` — `send_downlink` получает некадрированную запись.
- `bins/outline-ss-rust/src/server/transport/tests/{h3_datagram.rs,vless_udp.rs,carrier_padding.rs}` — тесты сервера.
- `bins/outline-ss-rust/src/server/tests/cross_repo_vless_h3_datagram.rs` — воспроизведение переключения (задача 4).
- `bins/outline-ss-rust/CHANGELOG{,.ru}.md`, `bins/outline-ws-rust/CHANGELOG{,.ru}.md`.

---

### Задача 1: бюджет паддинга в `outline-wire`

**Files:**
- Modify: `crates/outline-wire/src/padding.rs` (рядом с `PaddingScheme::pad_len`, ~стр. 137)
- Test: `crates/outline-wire/src/tests/padding.rs`

**Interfaces:**
- Produces: `PaddingScheme::pad_len_capped(self, rand: u16, cap: usize) -> u16`; `pub fn datagram_pad_budget(room: usize, real_len: usize) -> Option<usize>`.

- [ ] **Шаг 1: падающие тесты** — дописать в `crates/outline-wire/src/tests/padding.rs`:

```rust
#[test]
fn pad_len_capped_never_exceeds_the_cap() {
    let scheme = PaddingScheme::new(0, 256);
    for rand in [0u16, 1, 40, 255, 256, 1000, u16::MAX] {
        assert!(scheme.pad_len_capped(rand, 10) <= 10);
        assert_eq!(scheme.pad_len_capped(rand, 10_000), scheme.pad_len(rand));
    }
}

#[test]
fn pad_len_capped_may_go_below_min_and_still_decodes() {
    let scheme = PaddingScheme::new(32, 64);
    assert_eq!(scheme.pad_len_capped(0, 0), 0);
    let mut wire = Vec::new();
    encode_frame_into(&mut wire, b"payload", &[]).unwrap();
    let mut out = Vec::new();
    PaddingDecoder::new().push(&wire, &mut out);
    assert_eq!(out, b"payload");
}

#[test]
fn datagram_pad_budget_is_the_room_left_after_header_and_payload() {
    assert_eq!(datagram_pad_budget(1396, 1352), Some(1396 - 4 - 1352));
    assert_eq!(datagram_pad_budget(1356, 1352), Some(0));
    assert_eq!(datagram_pad_budget(1355, 1352), None);
    assert_eq!(datagram_pad_budget(0, 0), None);
}
```

- [ ] **Шаг 2:** `cargo test -p outline-wire padding` → FAIL (`pad_len_capped`/`datagram_pad_budget` не найдены).

- [ ] **Шаг 3: реализация** — в `impl PaddingScheme` после `pad_len`:

```rust
    /// [`Self::pad_len`], capped at `cap` bytes. Used where the frame must fit
    /// a size limit (one HTTP/3 datagram): the cap wins over `min_pad`, which
    /// the decoder never checks, so a capped frame stays valid on every peer.
    pub fn pad_len_capped(self, rand: u16, cap: usize) -> u16 {
        self.pad_len(rand).min(u16::try_from(cap).unwrap_or(u16::MAX))
    }
```

и свободную функцию рядом с `PADDING_FRAME_HEADER_LEN`:

```rust
/// Pad bytes one frame can carry when the whole frame (header, `real_len`
/// payload bytes and pad) must fit in `room` bytes; `None` when even the
/// unpadded frame does not fit.
pub fn datagram_pad_budget(room: usize, real_len: usize) -> Option<usize> {
    room.checked_sub(PADDING_FRAME_HEADER_LEN + real_len)
}
```

- [ ] **Шаг 4:** `cargo test -p outline-wire padding` → PASS.

---

### Задача 2: клиент урезает паддинг uplink-датаграмм

**Files:**
- Modify: `crates/outline-transport/src/frame_io.rs` (трейт `DatagramChannel`, ~стр. 93)
- Modify: `crates/outline-transport/src/h3/datagram.rs` (`impl DatagramChannel for H3DatagramChannel`)
- Modify: `crates/outline-transport/src/carrier_padding.rs` (рядом с `frame_payload_into`, ~стр. 197)
- Modify: `crates/outline-transport/src/vless/udp.rs` (~стр. 305), `crates/outline-transport/src/udp_transport.rs` (~стр. 419)
- Test: `crates/outline-transport/src/h3/tests/datagram.rs`, `crates/outline-transport/src/tests/carrier_padding.rs`

**Interfaces:**
- Consumes: `PaddingScheme::pad_len_capped`, `outline_wire::padding::datagram_pad_budget` (задача 1).
- Produces: `fn datagram_room(&self) -> Option<usize>` в `DatagramChannel` (sync, по умолчанию `None`); `pub(crate) fn frame_datagram_into<R: RngCore>(scheme: PaddingScheme, data: &[u8], room: Option<usize>, rng: &mut R, out: &mut Vec<u8>)`.

- [ ] **Шаг 1: падающие тесты.**

В `crates/outline-transport/src/tests/carrier_padding.rs`:

```rust
#[test]
fn datagram_frame_fits_the_room_whatever_pad_is_drawn() {
    let scheme = PaddingScheme::new(0, 256);
    let data = vec![0x11; 1352];
    let room = 1396;
    let mut rng = rand::rng();
    for _ in 0..500 {
        let mut out = Vec::new();
        frame_datagram_into(scheme, &data, Some(room), &mut rng, &mut out);
        assert!(out.len() <= room, "frame {} over room {room}", out.len());
        let mut decoded = Vec::new();
        PaddingDecoder::new().push(&out, &mut decoded);
        assert_eq!(decoded, data);
    }
}

#[test]
fn datagram_frame_without_room_is_the_stream_frame() {
    let scheme = PaddingScheme::new(200, 256);
    let data = vec![0x22; 1352];
    let mut rng = rand::rng();
    for room in [None, Some(1355)] {
        let mut out = Vec::new();
        frame_datagram_into(scheme, &data, room, &mut rng, &mut out);
        let pad = u16::from_be_bytes([out[2], out[3]]) as usize;
        assert!((200..=256).contains(&pad), "full-range pad when it cannot fit, got {pad}");
    }
}
```

В `crates/outline-transport/src/h3/tests/datagram.rs`:

```rust
#[tokio::test]
async fn datagram_room_is_the_payload_room_and_none_while_gated() {
    let f = fixture().await;
    let max = f.channel.connection.max_datagram_size().expect("datagrams enabled");
    assert_eq!(
        f.channel.datagram_room(),
        Some(max - outline_wire::h3_datagram::datagram_overhead(ID))
    );

    let gate = Arc::new(DatagramGate::default());
    let gated = fixture_with(Some(Arc::clone(&gate))).await;
    assert_eq!(gated.channel.datagram_room(), None, "closed gate: everything rides the stream");
    gate.open();
    assert!(gated.channel.datagram_room().is_some());
}
```

(Если у `DatagramGate` нет `Default`, взять конструктор, которым gate создаётся в соседних тестах этого файла.)

- [ ] **Шаг 2:** `cargo test -p outline-transport --features h3 datagram carrier_padding` → FAIL (нет `frame_datagram_into` / `datagram_room`).

- [ ] **Шаг 3: реализация.**

`frame_io.rs`, в трейт `DatagramChannel`:

```rust
    /// Bytes a payload may take to go out as one datagram right now, when this
    /// channel sends datagrams at all; `None` means every packet rides the
    /// stream. A hint for framing (padding is cut to fit it): `send_datagram`
    /// still checks, since the room can shrink before the send.
    fn datagram_room(&self) -> Option<usize> {
        None
    }
```

`h3/datagram.rs`, в `impl DatagramChannel for H3DatagramChannel`:

```rust
    fn datagram_room(&self) -> Option<usize> {
        if *self.closed.borrow() || !self.gate.as_deref().is_none_or(DatagramGate::is_open) {
            return None;
        }
        self.connection
            .max_datagram_size()?
            .checked_sub(datagram_overhead(self.quarter_stream_id))
    }
```

`carrier_padding.rs` (клиент), после `frame_payload_into`:

```rust
/// Frames one datagram-bound payload. When it fits `room` (the channel's
/// [`crate::frame_io::DatagramChannel::datagram_room`]) unpadded, the pad is
/// cut to what is left, so padding never pushes a packet onto the stream;
/// otherwise the frame is the stream's own (full-range pad) — it will ride the
/// stream anyway.
pub(crate) fn frame_datagram_into<R: RngCore>(
    scheme: PaddingScheme,
    data: &[u8],
    room: Option<usize>,
    rng: &mut R,
    out: &mut Vec<u8>,
) {
    let Some(budget) = room.and_then(|room| datagram_pad_budget(room, data.len())) else {
        frame_payload_into(scheme, data, rng, out);
        return;
    };
    let mut pad = vec![0u8; scheme.pad_len_capped(rng.random::<u16>(), budget) as usize];
    rng.fill_bytes(&mut pad);
    // `data` fits one datagram, far below the u16 segment ceiling.
    encode_frame_into(out, data, &pad).expect("datagram-sized segments cannot overflow u16");
}
```

(импорт: `use outline_wire::padding::datagram_pad_budget;`)

`vless/udp.rs` — заменить вызов `frame_payload_into(self.padding.scheme, &frame, &mut rand::rng(), &mut out)` на:

```rust
            carrier_padding::frame_datagram_into(
                self.padding.scheme,
                &frame,
                self.chan.datagram_room(),
                &mut rand::rng(),
                &mut out,
            );
```

`udp_transport.rs` — в ветке `UdpTransport::Channel(chan)` аналогично: `carrier_padding::frame_datagram_into(self.padding.scheme, &packet, chan.datagram_room(), &mut rand::rng(), &mut out)`.

- [ ] **Шаг 4:** `cargo test -p outline-transport --all-features` → PASS; `cargo clippy -p outline-transport --all-features --all-targets -- -D warnings` чисто.

---

### Задача 3: сервер урезает паддинг downlink-датаграмм

**Files:**
- Modify: `bins/outline-ss-rust/src/server/transport/carrier_padding.rs` (после `frame_downlink_message`, ~стр. 161)
- Modify: `bins/outline-ss-rust/src/server/transport/h3_datagram.rs` (`impl DatagramDownlink` ~стр. 247–310, `impl ResponseSender for DatagramResponseSender` ~стр. 327)
- Modify: `bins/outline-ss-rust/src/server/transport/vless_udp.rs` (цикл насоса ~стр. 693–700, `send_downlink` ~стр. 712)
- Test: `bins/outline-ss-rust/src/server/transport/tests/h3_datagram.rs`, `.../tests/vless_udp.rs`, `.../tests/carrier_padding.rs`

**Interfaces:**
- Consumes: `PaddingScheme::pad_len_capped`, `datagram_pad_budget` (задача 1).
- Produces: `carrier_padding::frame_datagram_message(scheme: PaddingScheme, record: &[u8], room: usize) -> Option<Bytes>`; `DatagramDownlink::send_record(&self, scheme: PaddingScheme, record: &Bytes, upstream_len: Option<usize>) -> DownlinkSend` (заменяет `send`); `send_downlink(tx, make_binary, datagram, padding: PaddingScheme, record: Bytes)`.

- [ ] **Шаг 1: падающие тесты.**

`tests/carrier_padding.rs` (сервер):

```rust
#[test]
fn datagram_message_fits_or_declines() {
    let scheme = PaddingScheme::new(0, 256);
    let record = vec![0x33; 1352];
    for _ in 0..500 {
        let framed = frame_datagram_message(scheme, &record, 1396).expect("fits unpadded");
        assert!(framed.len() <= 1396);
    }
    assert!(frame_datagram_message(scheme, &record, 1355).is_none());
    // Unpadded path: the record itself, when it fits.
    assert_eq!(
        frame_datagram_message(PaddingScheme::disabled(), &record, 1352).as_deref(),
        Some(&record[..])
    );
    assert!(frame_datagram_message(PaddingScheme::disabled(), &record, 1351).is_none());
}
```

`tests/h3_datagram.rs` — новый тест рядом с `padded_downlink_datagram_carries_the_stream_frame`, на схеме `[0, 256]` и пакете, который влезает только с урезанным паддингом:

```rust
#[tokio::test]
async fn near_full_packet_goes_as_a_datagram_with_a_cut_pad() -> Result<()> {
    let pair = quic_datagram_pair().await?;
    let stream = Arc::new(RecordingSender::default());
    let activity = Arc::new(DatagramActivity::default());
    let mut sender = padded_sender(&pair, &stream, &activity);
    sender.padding = PaddingScheme::new(0, 256);

    let room = pair.server.max_datagram_size().context("datagrams negotiated")?
        - datagram_overhead(QUARTER_ID);
    let data = Bytes::from(vec![0x5b; room - PADDING_FRAME_HEADER_LEN - 8]);
    for _ in 0..50 {
        assert!(sender.send_bytes(data.clone()).await);
        let datagram = timeout(Duration::from_secs(5), pair.client.read_datagram()).await??;
        let (_, body) = decode_datagram(datagram).context("datagram prefix")?;
        let pad_len = u16::from_be_bytes([body[2], body[3]]) as usize;
        assert!(pad_len <= 8, "pad {pad_len} must be cut to the room");
        let mut decoded = Vec::new();
        PaddingDecoder::new().push(&body, &mut decoded);
        assert_eq!(decoded, data);
    }
    assert!(stream.0.lock().expect("recording lock").is_empty(), "nothing rode the stream");
    Ok(())
}
```

Существующий `oversized_downlink_falls_back_with_the_unpadded_original` должен пройти без изменений (пакет размером `max` не влезает даже без паддинга).

`tests/vless_udp.rs` — тест на `send_downlink`, по образцу соседних тестов файла. Проверить два случая: запись 1352 байта при схеме `[0, 256]` и room ≥ 1356 всегда уходит датаграммой с `real_len = 1352`, в mpsc ничего; запись, которая не влезает, уходит в mpsc одним Binary-сообщением, которое `PaddingDecoder` раскодирует в исходную запись, а `pad_len` лежит в `[min, max]` схемы.

- [ ] **Шаг 2:** `cargo test -p outline-ss-rust h3_datagram vless_udp carrier_padding` → FAIL.

- [ ] **Шаг 3: реализация.**

`carrier_padding.rs` (сервер):

```rust
/// The frame `record` takes as one HTTP/3 datagram of `room` payload bytes:
/// the record itself on an unpadded path, else one padding frame whose pad is
/// cut to what is left. `None` when even the bare record does not fit — the
/// caller sends it on the stream, framed as usual.
pub(in crate::server) fn frame_datagram_message(
    scheme: PaddingScheme,
    record: &[u8],
    room: usize,
) -> Option<Bytes> {
    if !scheme.is_enabled() {
        return (record.len() <= room).then(|| Bytes::copy_from_slice(record));
    }
    let budget = datagram_pad_budget(room, record.len())?;
    let mut rng = rand::rng();
    let mut pad = vec![0u8; scheme.pad_len_capped(rng.random::<u16>(), budget) as usize];
    rng.fill_bytes(&mut pad);
    let mut out = Vec::with_capacity(PADDING_FRAME_HEADER_LEN + record.len() + pad.len());
    encode_frame_into(&mut out, record, &pad).expect("datagram-sized segments cannot overflow u16");
    Some(out.into())
}
```

Копирования на неподпаддированном пути не будет, если принимать `&Bytes` и возвращать `record.clone()`. Для `Bytes` это дешёвая операция; выбрать этот вариант, если сигнатура позволяет.

`h3_datagram.rs` — `send` заменить на `send_record`:

```rust
    /// Sends `record` (the unpadded frame the stream would write) as one
    /// datagram when it fits the route, padding it within the room left.
    pub(in crate::server) fn send_record(
        &self,
        scheme: PaddingScheme,
        record: &Bytes,
        upstream_len: Option<usize>,
    ) -> DownlinkSend {
        let target = self.target.load();
        let Some(peer) = target.as_deref() else {
            return DownlinkSend::NoTarget;
        };
        let framed = peer
            .connection
            .max_datagram_size()
            .and_then(|max| max.checked_sub(datagram_overhead(peer.quarter_stream_id)))
            .and_then(|room| carrier_padding::frame_datagram_message(scheme, record, room));
        if framed.is_some_and(|framed| self.try_send(peer, &framed, upstream_len)) {
            self.metrics.record_udp_h3_datagram("down", self.proto);
            DownlinkSend::Sent
        } else {
            self.metrics.record_udp_h3_datagram_fallback("down", self.proto);
            DownlinkSend::Fallback
        }
    }
```

`try_send` сохраняет свою проверку `fits` как защиту от сжатия MTU между расчётом и отправкой.

`DatagramResponseSender::send_bytes`:

```rust
        match self.downlink.send_record(self.padding, &data, Some(data.len())) {
            DownlinkSend::Sent => Box::pin(async { true }),
            // The original packet: the stream sender pads it itself.
            DownlinkSend::NoTarget | DownlinkSend::Fallback => {
                Box::pin(self.stream.send_bytes(data))
            },
        }
```

(строку `let framed = carrier_padding::frame_downlink_message(...)` удалить).

`vless_udp.rs` — в насосе больше не кадрировать заранее:

```rust
                let mut record = BytesMut::with_capacity(2 + read);
                record.put_u16(read as u16);
                record.extend_from_slice(&buffer[..read]);
                send_downlink(&tx, make_binary, datagram.as_deref(), padding, record.freeze())
                    .await
                    .map_err(|error| anyhow!("failed to queue vless udp websocket frame: {error}"))?;
```

и `send_downlink`:

```rust
async fn send_downlink<Msg>(
    tx: &mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    datagram: Option<&DatagramDownlink>,
    padding: PaddingScheme,
    record: Bytes,
) -> Result<(), mpsc::error::SendError<Msg>> {
    // The pump already fed the throttle monitor the upstream bytes.
    if datagram.is_some_and(|datagram| datagram.send_record(padding, &record, None) == DownlinkSend::Sent) {
        return Ok(());
    }
    tx.send(make_binary(carrier_padding::frame_downlink_message(padding, record))).await
}
```

Найти ВСЕ вызовы `send_downlink` и `DatagramDownlink::send` (`grep -rn 'send_downlink\|\.send(&' bins/outline-ss-rust/src/server`) и перевести на новые сигнатуры. Поведение потокового пути не меняется ни на байт: `frame_downlink_message` от той же записи.

- [ ] **Шаг 4:** `cargo test -p outline-ss-rust` → PASS; `cargo clippy -p outline-ss-rust --all-targets -- -D warnings` чисто.

---

### Задача 4: downlink после смены маршрута и мягкое переключение VLESS-UDP

**Files:**
- Modify: `bins/outline-ss-rust/src/server/transport/h3_datagram.rs` (`DatagramLink::next_datagram`, ветка `Ok(None)`, ~стр. 480)
- Test: `bins/outline-ss-rust/src/server/transport/tests/h3_datagram.rs`
- Test: `bins/outline-ss-rust/src/server/tests/cross_repo_vless_h3_datagram.rs`

**Interfaces:**
- Consumes: `DatagramLink`, `DatagramAnchor`, `DatagramTarget`, хелпер `quic_datagram_pair()` и `route_on(...)` из `tests/h3_datagram.rs`.
- Produces: инвариант — пока у link нет живой регистрации, `target` пуст.

- [ ] **Шаг 1: падающий unit-тест.** Маршрут перестал доставлять — регистрацию того же id перехватили, или соединение закрылось. После этого downlink должен идти потоком, а не в мёртвый маршрут:

```rust
#[tokio::test]
async fn link_empties_the_target_when_its_route_stops_delivering() -> Result<()> {
    let pair = quic_datagram_pair().await?;
    let demux = DatagramDemux::spawn(pair.server.clone(), Arc::new(|_| {}));
    let anchor = DatagramAnchor::with_route(route_on(&pair, &demux, QUARTER_ID));
    let target = Arc::new(DatagramTarget::empty());
    let mut link = DatagramLink::new(
        Arc::clone(&anchor),
        Arc::clone(&target),
        LinkPolicy::Immediate,
        Metrics::new(&sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))),
    );
    assert!(target.load().is_some());

    // Re-registering the id ends the link's registration.
    let _stolen = demux.register(QUARTER_ID);
    let _ = timeout(Duration::from_millis(300), link.next_datagram()).await;
    assert!(target.load().is_none(), "a route that stopped delivering must not take downlink");
    Ok(())
}
```

(Подогнать под фактическую сигнатуру `route_on` в этом файле.)

- [ ] **Шаг 2:** `cargo test -p outline-ss-rust link_empties_the_target` → FAIL (сейчас ветка `Ok(None)` только обнуляет `registration`).

- [ ] **Шаг 3: реализация** — ветка `Ok(None)` в `next_datagram`:

```rust
                // The route stopped delivering (connection closed, or the id was
                // registered again). Not the end of the session: the stream
                // still carries it, and the next anchor may bring a new route —
                // until then downlink rides the stream too, never the dead route.
                Ok(None) => {
                    self.registration = None;
                    self.unarmed = None;
                    self.target.store(None);
                },
```

- [ ] **Шаг 4:** тест → PASS.

- [ ] **Шаг 5: воспроизведение мягкого переключения.** В `cross_repo_vless_h3_datagram.rs` по образцу существующего теста:
  1. Клиент открывает VLESS-UDP через `ws_h3` с датаграммами.
  2. Echo-upstream заставляет downlink пойти датаграммами.
  3. Сессия паркуется и возобновляется на НОВОМ носителе с тем же resume-токеном, как при `activate` с `soft: true`: дропнуть первый транспорт и открыть второй с `DialResumeOptions`.

  Ожидания:
  - (а) `orphan_resume_hit_total{kind="vless_udp_single"}` вырос;
  - (б) после резюма каждый downlink-пакет приходит клиенту (датаграммой или потоком), ни одного `unknown_stream`;
  - (в) старый носитель после резюма downlink не получает.

  Повторить для SS-UDP (`kind="ss_udp_stream"`).

- [ ] **Шаг 6:** если шаг 5 падает, записать в отчёт задачи, на каком из (а)/(б)/(в), и чинить по месту падения. Кандидаты по коду:
  - resume-ключ UDP-сессии теряется, когда клиент запрашивает датаграммы (`apply_udp_datagram_request_header` / `udp_datagram_requested` в `crates/outline-transport/src/resumption.rs` и `dial_plan.rs`);
  - насос VLESS-UDP не получает `cancel` при перехвате сессии, когда у ctx есть `DatagramDownlink` (`vless_udp.rs`, ветка `cancelled`);
  - новый ctx после резюма не получает `DatagramDownlink` нового носителя (`vless/mod.rs` ~стр. 98).

  Тест из шага 5 остаётся регрессионным. Если на старой ветке без датаграмм (`[quic] udp_datagrams = false`) (а) тоже не выполняется, это уже существующий дефект resume, а не датаграмм: отметить в отчёте и согласовать с владельцем, чинить ли в этой серии.

---

### Задача 5: документация

**Files:**
- Modify: `bins/outline-ss-rust/CHANGELOG.md`, `bins/outline-ss-rust/CHANGELOG.ru.md`, `bins/outline-ws-rust/CHANGELOG.md`, `bins/outline-ws-rust/CHANGELOG.ru.md` (раздел Unreleased).

- [ ] **Шаг 1:** в обоих бинарях записать, на обоих языках:
  - на путях с паддингом датаграмма несёт урезанный паддинг, и пакет, который влезает без паддинга, больше не уходит в поток из-за него;
  - декодеры принимают такие кадры, поэтому совместимость с раскатанными пирами сохраняется;
  - (сервер) когда маршрут датаграмм перестал доставлять, downlink идёт потоком;
  - итог задачи 4 по resume — по факту.

- [ ] **Шаг 2:** проверить, что `docs/UPLINK-CONFIGURATIONS{,.ru}.md` обоих бинарей не утверждают обратного про паддинг в датаграммах; при необходимости поправить обе версии.

---

### Задача 6: проверка и раскатка

- [ ] **Шаг 1:** локально `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo clippy -p outline-ws-rust --no-default-features --all-targets -- -D warnings`, `cargo test --workspace`.
- [ ] **Шаг 2:** linux docker: workspace на default-фичах + `outline-transport --all-features` + `e2e_tls_carriers`. Всё зелёное.
- [ ] **Шаг 3:** коммит — по команде владельца; пуш — по отдельной команде; после пуша `gh run list --commit <полный sha>` → все задания зелёные; `cargo clean` в корне и `android/rust`.
- [ ] **Шаг 4: раскатка (по одному узлу, `ops/deploy/deploy-binary.sh`).**
  1. Сервер nuxt2 (там замерены откаты). Увод трафика: `activate main→nuxt` на всех четырёх клиентах. Признак успеха после возврата трафика: доля `outline_ss_udp_h3_datagram_fallback_total{direction="down",proto="vless"}` падает с ~85 % до долей процента.
  2. Затем nuxt, .102, .104, cloud1, cloud2.
  3. Клиенты: cloud1, cloud2, .104, .102.
- [ ] **Шаг 5:** контрольное мягкое переключение одного клиента (сначала `.104`), когда владелец смотрит видео. Ожидания:
  - `orphan_resume_hit_total{kind="vless_udp_single"}` растёт;
  - `outline_ws_udp_h3_datagram_dropped_total{reason="unknown_stream"}` не растёт;
  - видео не встаёт.
- [ ] **Шаг 6:** откат при регрессии: на клиенте `[quic] udp_datagrams = false` и рестарт (ключ уже знаком бинарю) или предыдущий бэкап бинаря. Бинарь подменять через `cp` во временный файл и `mv`: `cp` поверх запущенного файла даёт «Text file busy».
