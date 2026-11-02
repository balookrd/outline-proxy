# Форма начала сессии (метки + нарезка) — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Цель:** убрать постоянные метки начала сессии (записи 26/1041 на h2, отдельный ответ VLESS 21 B, отдельный
заголовок SS2022) и на padded-путях нарезать первые сообщения TCP-сессий h1/h2 по браузерным размерам — по спеке
`docs/superpowers/specs/2026-11-02-early-session-shape-design.md`.

**Архитектура:** чистый планировщик нарезки `early_shape` в `outline-wire` (без RNG — случай передаёт вызывающий);
адаптер `CoalescingWrite` в `outline-net`, склеивающий векторную запись в один вызов TLS; правки отправителей на
клиенте (`WsWriteTransport`, `WsFrameSink`) и сервере (`ChannelSink`, downlink VLESS). Провод не меняется.

**Tech Stack:** Rust, tokio, tokio-rustls, hyper/h2, tungstenite, крейты `outline-wire`, `outline-net`,
`outline-transport`, `outline-ss-rust`, `outline-ws-rust`.

## Global Constraints

- Провод не меняется: нарезка = больше сообщений `Binary`; cover = существующий кадр `real_len = 0`.
- Часть 1 (метки) — всегда, на всех путях. Часть 2 (нарезка) — только TCP-сессии на h1/h2 (не h3, не UDP) и только
  когда паддинг пути включён; новых ключей конфига нет.
- Окно нарезки на сессию и направление: `N` случайно в 6..=10 сообщений, `B` случайно в 16384..=24576 байт.
- Клиент → сервер: резать сообщения > 900 B на куски 300..=850 (остаток < 300 приклеивается к предыдущему куску).
- Сервер → клиент: резать сообщения > 1500 B на куски 600..=2800 (остаток < 600 приклеивается к предыдущему).
- Cover перед первым крупным (> 900 B) сообщением клиента: с вероятностью 1/2, 1..=2 кадра, добивка 40..=100 B.
- Заголовок SS2022 держится до первых данных не дольше `SS2022_HEADER_HOLD = 50 ms`.
- `outline-wire` не зависит от `rand`: случай приходит параметром.
- Комментарии в коде — по-английски; документация — парами EN/RU; тесты — в `tests/` рядом с модулем через
  `#[cfg(test)] #[path = "tests/<name>.rs"] mod tests;`, без inline-модулей.
- `cargo fmt` только `-p` по пакетам CI (не `--all`: трогает `vendor/sockudo-ws`); `vendor/` и `macos/` не трогать.
- Коммиты — только по команде владельца, `git commit -- <пути>`; параллельно в main работает другой агент — не
  стейджить чужое, не делать stash/checkout/reset.
- Гейт как в CI: fmt по списку пакетов, `cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings`,
  `--no-default-features` для обоих бинарей, `cargo test --workspace --exclude sockudo-ws`,
  `cargo test -p outline-transport --all-features`, e2e `RUN_E2E_FAILOVER=1 … --test-threads=1`, инварианты CI,
  Linux в docker (без `RUN_E2E_FAILOVER` в общем прогоне).

## Отклонения от спеки (решено при планировании)

- **VLESS-UDP: ответ `[VER,0]` не переносится** (спека предлагала). Для UDP ответ открывает клиенту датаграммы, а
  первая запись может уйти датаграммой мимо потока; склейка требует менять гейт клиента. UDP вне рамок нарезки; метка
  21 B у UDP-сессий остаётся. Также не меняются редкие пути resume/mesh/mux VLESS-TCP (там за заголовком идут
  ack-prefix/replay отдельными сообщениями).
- **Отдельный сброс на кусок** делать не нужно: и клиент, и сервер уже отправляют каждое сообщение через
  `SinkExt::send` (feed + flush), склейки сообщений нет.
- **Заголовок SS2022 держит задача-писатель `WsWriteTransport`**, а не relay-циклы: через неё идут SOCKS, TUN, пробы и
  миграция, поэтому вызывающий код не меняется.
- Найдено при планировании и **чинится здесь отдельной задачей (Task 4)**: весь downlink VLESS-mux на сервере идёт
  мимо паддинга — заголовок ответа (`vless/mod.rs` ~754 resume, ~811 fresh), данные подсоединений
  (`vless_mux/tcp_sub.rs` ~204/~213, `vless_mux/udp_sub.rs` ~202/~211) и кадры завершения (`vless_mux/frames.rs::send_end`).
  Uplink сервер при этом декодирует как padded. На padded-пути это сломало бы декодер клиента; наш клиент mux не
  инициирует, поэтому пока не проявлялось.

## Файлы

- Create: `crates/outline-wire/src/early_shape.rs`, `crates/outline-wire/src/tests/early_shape.rs` — планировщик.
- Modify: `crates/outline-wire/src/lib.rs` — `pub mod early_shape;`.
- Create: `crates/outline-net/src/coalescing_write.rs`, `crates/outline-net/src/tests/coalescing_write.rs` — адаптер.
- Modify: `crates/outline-net/src/lib.rs`, `crates/outline-net/Cargo.toml` (если нужен `pin-project-lite`).
- Modify: `crates/outline-transport/src/h2/shared.rs` (~596), `crates/outline-transport/src/xhttp/h2.rs` (~485, ~489).
- Modify: `bins/outline-ss-rust/src/server/bootstrap/axum.rs` (~694).
- Modify: `bins/outline-ss-rust/src/server/transport/vless/tcp.rs` (~519-531 и `relay_vless_upstream_to_client` ~850-974).
- Modify: `bins/outline-ss-rust/src/server/transport/vless/mod.rs` (~754, ~811), `bins/outline-ss-rust/src/server/transport/vless_mux/{mod.rs,state.rs,frames.rs,tcp_sub.rs,udp_sub.rs}` — паддинг downlink mux.
- Modify: `crates/outline-transport/src/tcp_transport/writer/{transport.rs,mod.rs}` — удержание заголовка и нарезка SS.
- Modify: `crates/outline-transport/src/frame_io_ws.rs` (`WsFrameSink`, `from_ws_frames`) — нарезка VLESS.
- Modify: `crates/outline-transport/src/carrier_padding.rs` — обёртка случая для планировщика.
- Modify: call-sites `TcpShadowsocksWriter::connect`: `bins/outline-ws-rust/src/proxy/tcp/failover.rs` (~722),
  `crates/outline-tun/src/tcp/engine/connect.rs` (~449), `crates/outline-uplink/src/probe/transport.rs` (~111), тесты.
- Modify: `bins/outline-ss-rust/src/server/transport/tcp.rs` (`ChannelSink` ~264-323, конструкции ~815, ~1229, ~1360),
  `bins/outline-ss-rust/src/server/transport/carrier_padding.rs` — нарезка на сервере.
- Modify: `ops/access-keys/{xray_json.py,artifacts.py,README.md,golden/config.toml}`, `golden/expected/*` — Xray-подписка без padded-путей.
- Tests: см. задачи; e2e — `bins/outline-ws-rust/tests/e2e_padding.rs`.
- Docs: `docs/PADDING.md` / `docs/PADDING.ru.md`, `bins/outline-ss-rust/CHANGELOG{,.ru}.md`,
  `bins/outline-ws-rust/CHANGELOG{,.ru}.md`.

---

### Task 1: Планировщик нарезки `early_shape` (outline-wire)

**Files:**
- Create: `crates/outline-wire/src/early_shape.rs`
- Create: `crates/outline-wire/src/tests/early_shape.rs`
- Modify: `crates/outline-wire/src/lib.rs` (список модулей ~15-25)

**Interfaces:**
- Produces:
  - `pub enum ShapeDirection { ClientToServer, ServerToClient }`
  - `pub struct EarlyShaper` с `pub fn new(direction: ShapeDirection, draw: &mut dyn FnMut(usize, usize) -> usize) -> Self`
  - `pub fn plan(&mut self, len: usize, draw: &mut dyn FnMut(usize, usize) -> usize) -> ShapePlan`
  - `pub fn is_active(&self) -> bool`
  - `pub struct ShapePlan { pub covers: Vec<usize>, pub pieces: Vec<usize> }` — `covers`: размеры добивки
    cover-кадров перед сообщением; `pieces`: длины кусков, сумма = `len`.
  - `draw(lo, hi)` — случайное целое в `lo..=hi` (вызывающий реализует через `rand`).

- [ ] **Step 1: Тесты**

`crates/outline-wire/src/tests/early_shape.rs`:

```rust
use super::{EarlyShaper, ShapeDirection, ShapePlan};

/// Deterministic `draw`: a small LCG mapped into `lo..=hi`.
fn lcg(seed: u64) -> impl FnMut(usize, usize) -> usize {
    let mut s = seed;
    move |lo, hi| {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        lo + (s >> 33) as usize % (hi - lo + 1)
    }
}

fn sum(plan: &ShapePlan) -> usize {
    plan.pieces.iter().sum()
}

#[test]
fn client_pieces_stay_in_browser_range_and_sum_to_message() {
    for seed in 0..200 {
        let mut d = lcg(seed);
        let mut s = EarlyShaper::new(ShapeDirection::ClientToServer, &mut d);
        let plan = s.plan(1964, &mut d);
        assert_eq!(sum(&plan), 1964, "seed {seed}");
        let (last, head) = plan.pieces.split_last().unwrap();
        assert!(plan.pieces.len() >= 2, "seed {seed}: {plan:?}");
        for p in head {
            assert!((300..=850).contains(p), "seed {seed}: {plan:?}");
        }
        assert!((300..=850 + 299).contains(last), "seed {seed}: {plan:?}");
    }
}

#[test]
fn server_pieces_stay_in_range_and_sum_to_message() {
    for seed in 0..200 {
        let mut d = lcg(seed);
        let mut s = EarlyShaper::new(ShapeDirection::ServerToClient, &mut d);
        let plan = s.plan(4499, &mut d);
        assert_eq!(sum(&plan), 4499);
        assert!(plan.pieces.len() >= 2, "seed {seed}: {plan:?}");
        let (last, head) = plan.pieces.split_last().unwrap();
        for p in head {
            assert!((600..=2800).contains(p), "seed {seed}: {plan:?}");
        }
        assert!((600..=2800 + 599).contains(last), "seed {seed}: {plan:?}");
        assert!(plan.covers.is_empty(), "server never sends lead-in covers");
    }
}

#[test]
fn small_messages_are_not_split() {
    let mut d = lcg(7);
    let mut c = EarlyShaper::new(ShapeDirection::ClientToServer, &mut d);
    assert_eq!(c.plan(900, &mut d).pieces, vec![900]);
    let mut s = EarlyShaper::new(ShapeDirection::ServerToClient, &mut d);
    assert_eq!(s.plan(1500, &mut d).pieces, vec![1500]);
}

#[test]
fn window_closes_after_message_count() {
    let mut d = lcg(3);
    let mut s = EarlyShaper::new(ShapeDirection::ClientToServer, &mut d);
    let mut split = 0;
    for _ in 0..20 {
        if s.plan(1200, &mut d).pieces.len() > 1 {
            split += 1;
        }
    }
    assert!((6..=10).contains(&split), "split {split} messages");
    assert!(!s.is_active());
    assert_eq!(s.plan(5000, &mut d).pieces, vec![5000]);
}

#[test]
fn window_closes_after_byte_budget_and_only_the_head_is_split() {
    let mut d = lcg(11);
    let mut s = EarlyShaper::new(ShapeDirection::ServerToClient, &mut d);
    let plan = s.plan(100_000, &mut d);
    assert_eq!(sum(&plan), 100_000);
    let shaped: usize = plan.pieces[..plan.pieces.len() - 1].iter().sum();
    assert!(shaped <= 24_576 + 2800, "shaped {shaped}");
    assert!(*plan.pieces.last().unwrap() >= 100_000 - 24_576 - 2800);
    assert!(!s.is_active());
}

#[test]
fn client_covers_come_once_before_the_first_big_message() {
    let mut with_covers = 0;
    for seed in 0..400 {
        let mut d = lcg(seed);
        let mut s = EarlyShaper::new(ShapeDirection::ClientToServer, &mut d);
        assert!(s.plan(200, &mut d).covers.is_empty(), "small message gets no cover");
        let first = s.plan(1964, &mut d);
        assert!(first.covers.len() <= 2);
        for c in &first.covers {
            assert!((40..=100).contains(c));
        }
        if !first.covers.is_empty() {
            with_covers += 1;
        }
        assert!(s.plan(1964, &mut d).covers.is_empty(), "covers come once");
    }
    assert!((120..=280).contains(&with_covers), "about half: {with_covers}/400");
}
```

- [ ] **Step 2: Убедиться, что не собирается**

Run: `cargo test -p outline-wire early_shape`
Expected: ошибка компиляции — модуля `early_shape` нет.

- [ ] **Step 3: Реализация**

`crates/outline-wire/src/early_shape.rs`:

```rust
//! Early-session shaping: plans how the first messages of a padded TCP session
//! are cut into browser-sized pieces, so an observer does not see one record the
//! size of the tunnelled TLS ClientHello followed, one RTT later, by one record
//! the size of the server's certificate flight (the TLS-in-TLS signature).
//!
//! Pure planning, like [`crate::padding`]: no RNG and no clock here. The caller
//! passes `draw(lo, hi)`, a uniform integer in `lo..=hi`. Sizes are real payload
//! bytes; each piece still gets the ordinary per-frame padding when sent.

/// Messages the window covers, drawn per session.
const WINDOW_MSGS: (usize, usize) = (6, 10);
/// Payload bytes the window covers, drawn per session.
const WINDOW_BYTES: (usize, usize) = (16 * 1024, 24 * 1024);

/// Client→server: messages longer than this are cut into HEADERS-sized pieces.
const C2S_SPLIT_ABOVE: usize = 900;
const C2S_PIECE: (usize, usize) = (300, 850);
/// Server→client: messages longer than this are cut into response-sized pieces.
const S2C_SPLIT_ABOVE: usize = 1500;
const S2C_PIECE: (usize, usize) = (600, 2800);

/// Lead-in covers before the client's first big message: Chrome sends a few
/// short records after its handshake before HEADERS.
const COVER_COUNT: (usize, usize) = (1, 2);
const COVER_PAD: (usize, usize) = (40, 100);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeDirection {
    ClientToServer,
    ServerToClient,
}

/// What to send for one message: `covers` pad-only frames first (their pad
/// sizes), then `pieces` (lengths, summing to the message length) as separate
/// messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShapePlan {
    pub covers: Vec<usize>,
    pub pieces: Vec<usize>,
}

#[derive(Debug)]
pub struct EarlyShaper {
    direction: ShapeDirection,
    msgs_left: usize,
    bytes_left: usize,
    covers_pending: bool,
}

impl EarlyShaper {
    pub fn new(direction: ShapeDirection, draw: &mut dyn FnMut(usize, usize) -> usize) -> Self {
        let msgs_left = draw(WINDOW_MSGS.0, WINDOW_MSGS.1);
        let bytes_left = draw(WINDOW_BYTES.0, WINDOW_BYTES.1);
        let covers_pending = direction == ShapeDirection::ClientToServer && draw(0, 1) == 1;
        Self { direction, msgs_left, bytes_left, covers_pending }
    }

    /// Whether the window is still open.
    pub fn is_active(&self) -> bool {
        self.msgs_left > 0 && self.bytes_left > 0
    }

    pub fn plan(&mut self, len: usize, draw: &mut dyn FnMut(usize, usize) -> usize) -> ShapePlan {
        if !self.is_active() {
            return ShapePlan { covers: Vec::new(), pieces: vec![len] };
        }
        self.msgs_left -= 1;
        let (split_above, piece) = match self.direction {
            ShapeDirection::ClientToServer => (C2S_SPLIT_ABOVE, C2S_PIECE),
            ShapeDirection::ServerToClient => (S2C_SPLIT_ABOVE, S2C_PIECE),
        };
        let shaped = len.min(self.bytes_left);
        self.bytes_left -= shaped;
        if len <= split_above {
            return ShapePlan { covers: Vec::new(), pieces: vec![len] };
        }
        let mut covers = Vec::new();
        if self.covers_pending {
            self.covers_pending = false;
            for _ in 0..draw(COVER_COUNT.0, COVER_COUNT.1) {
                covers.push(draw(COVER_PAD.0, COVER_PAD.1));
            }
        }
        let mut pieces = Vec::new();
        let mut left = shaped;
        while left > piece.1 {
            let p = draw(piece.0, piece.1);
            pieces.push(p);
            left -= p;
        }
        if left > 0 {
            match pieces.last_mut() {
                Some(last) if left < piece.0 => *last += left,
                _ => pieces.push(left),
            }
        }
        if len > shaped {
            pieces.push(len - shaped);
        }
        ShapePlan { covers, pieces }
    }
}

#[cfg(test)]
#[path = "tests/early_shape.rs"]
mod tests;
```

В `crates/outline-wire/src/lib.rs` добавить `pub mod early_shape;` в алфавитном порядке среди `pub mod …`.

Замечание к алгоритму: при `shaped ≤ piece.1` (например, сообщение 1000 B на c→s) цикл не выполняется и получается
один кусок; тест `client_pieces…` проверяет 1964 B (≥ 2 кусков всегда, т. к. 1964 > 850). Если ревью потребует резать
и 901..=850+… — это в рамках диапазона «последний ≤ 850+299», менять не нужно.

- [ ] **Step 4: Тесты проходят**

Run: `cargo test -p outline-wire early_shape`
Expected: 6 passed.

- [ ] **Step 5: fmt/clippy пакета**

Run: `cargo fmt -p outline-wire && cargo clippy -p outline-wire --all-targets --all-features --no-deps -- -D warnings`
Expected: чисто. Коммит — нет (только по команде владельца).

---

### Task 2: `CoalescingWrite` для h2 (клиент и сервер)

**Files:**
- Create: `crates/outline-net/src/coalescing_write.rs`, `crates/outline-net/src/tests/coalescing_write.rs`
- Modify: `crates/outline-net/src/lib.rs` (`pub mod coalescing_write; pub use coalescing_write::CoalescingWrite;`)
- Modify: `crates/outline-transport/src/h2/shared.rs:596` — `TokioIo::new(CoalescingWrite::new(io))`
- Modify: `crates/outline-transport/src/xhttp/h2.rs:485,489` — `spawn_h2(TokioIo::new(CoalescingWrite::new(BoxedIo::…)))`
  (тип параметра `spawn_h2<T>` generic — меняется только выражение)
- Modify: `bins/outline-ss-rust/src/server/bootstrap/axum.rs:694` — `let io = TokioIo::new(CoalescingWrite::new(tls_stream));`

**Interfaces:**
- Produces: `pub struct outline_net::CoalescingWrite<T>`; `CoalescingWrite::new(inner: T) -> Self`;
  `AsyncRead`/`AsyncWrite` при `T: AsyncRead/AsyncWrite + Unpin`; `is_write_vectored() == true`.

- [ ] **Step 1: Тест**

`crates/outline-net/src/tests/coalescing_write.rs`:

```rust
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::CoalescingWrite;

/// Records every `poll_write` call the inner stream sees.
#[derive(Default)]
struct Recorder {
    writes: Vec<Vec<u8>>,
    accept_at_most: Option<usize>,
}

impl AsyncWrite for Recorder {
    fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let n = self.accept_at_most.map_or(buf.len(), |m| m.min(buf.len()));
        self.writes.push(buf[..n].to_vec());
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn vectored_write_reaches_the_inner_stream_as_one_write() {
    let mut w = CoalescingWrite::new(Recorder::default());
    assert!(w.is_write_vectored());
    let header = [0u8; 9];
    let payload = vec![7u8; 1572];
    let n = w.write_vectored(&[IoSlice::new(&header), IoSlice::new(&payload)]).await.unwrap();
    assert_eq!(n, 9 + 1572);
    let inner = w.into_inner();
    assert_eq!(inner.writes.len(), 1, "an h2 frame header and its payload must be one TLS write");
    assert_eq!(inner.writes[0].len(), 9 + 1572);
}

#[tokio::test]
async fn partial_inner_write_reports_what_was_taken() {
    let mut w = CoalescingWrite::new(Recorder { writes: Vec::new(), accept_at_most: Some(100) });
    let a = [1u8; 60];
    let b = [2u8; 60];
    let n = w.write_vectored(&[IoSlice::new(&a), IoSlice::new(&b)]).await.unwrap();
    assert_eq!(n, 100);
    let inner = w.into_inner();
    assert_eq!(inner.writes, vec![[&a[..], &b[..40]].concat()]);
}
```

- [ ] **Step 2: Не собирается**

Run: `cargo test -p outline-net coalescing_write` — Expected: ошибка компиляции.

- [ ] **Step 3: Реализация**

`crates/outline-net/src/coalescing_write.rs`:

```rust
//! Hands vectored writes to the inner stream as one write.
//!
//! The `h2` crate writes a frame's 9-byte header and its payload separately when
//! the IO is not vectored, and cuts large payloads at 1024 bytes; rustls makes a
//! TLS record of every write, so an observer saw a 26-byte record (header plus
//! TLS overhead) and a constant 1041-byte one. Advertising vectored writes and
//! gathering the slices into a single inner write keeps a frame in one record,
//! as browsers do.

use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Largest gather: one TLS record's worth; the rest of the slices are taken by
/// the caller's next write, as with any partial vectored write.
const MAX_GATHER: usize = 16 * 1024;

pub struct CoalescingWrite<T> {
    inner: T,
    gather: Vec<u8>,
}

impl<T> CoalescingWrite<T> {
    pub fn new(inner: T) -> Self {
        Self { inner, gather: Vec::new() }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CoalescingWrite<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CoalescingWrite<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.gather.clear();
        for b in bufs {
            let room = MAX_GATHER.saturating_sub(this.gather.len());
            if room == 0 {
                break;
            }
            this.gather.extend_from_slice(&b[..b.len().min(room)]);
        }
        // The gathered bytes are rebuilt from `bufs` on every poll, so a Pending
        // inner write loses nothing: the caller retries with the same slices.
        Pin::new(&mut this.inner).poll_write(cx, &this.gather)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "tests/coalescing_write.rs"]
mod tests;
```

Проверить `crates/outline-net/Cargo.toml`: нужен `tokio` с фичей `io-util` в `[dependencies]` для `AsyncWriteExt` в тестах
(dev-dependencies уже содержат `io-util`); сам адаптер использует только трейты `tokio::io` (без фич). Типы на
call-sites: `H2Io`, `BoxedIo`, `tokio_rustls::server::TlsStream<PrependStream<TcpStream>>` — все `Unpin`.

- [ ] **Step 4: Подключить на трёх call-sites** (выражения выше).

- [ ] **Step 5: Тесты**

Run: `cargo test -p outline-net coalescing_write && cargo test -p outline-transport --all-features h2 && cargo test -p outline-ss-rust --lib server::tests`
Expected: всё зелёное (адаптер прозрачен для h1 на сервере). Проверить TLS-e2e:
`RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls --test e2e_tls_carriers -- --test-threads=1`.

---

### Task 3: Ответ VLESS вместе с первыми данными (сервер, свежий TCP-путь)

**Files:**
- Modify: `bins/outline-ss-rust/src/server/transport/vless/tcp.rs` — ~519-531 (не отправлять заголовок отдельно) и
  `relay_vless_upstream_to_client` ~850-974 (новый параметр `response_header: Option<Bytes>`)
- Test: `bins/outline-ss-rust/src/server/transport/vless/tests/tcp.rs` (если файла нет — тесты VLESS-TCP лежат в
  `src/server/transport/tests/vless*.rs`; положить рядом с существующими тестами `relay_vless_upstream_to_client`)

**Interfaces:**
- Consumes: `carrier_padding::frame_downlink_message(scheme, Bytes) -> Bytes`.
- Produces: `relay_vless_upstream_to_client(…, response_header: Option<Bytes>, …)` — новый параметр сразу после
  `monitor` (последним); все вызовы resume/mesh передают `None` (поведение не меняется).

- [ ] **Step 1: Тест** — upstream-мок присылает `b"hello"`: первое сообщение в `tx` после `frame_downlink_message`-декода
  равно `[VERSION, 0x00] ++ b"hello"`, отдельного сообщения `[VERSION,0]` нет. Второй тест: upstream закрывается без
  данных — в `tx` приходит `[VERSION,0]` одним сообщением, затем close. Писать через существующие хелперы тестов relay
  (найти `relay_vless_upstream_to_client` в `src/server/transport/tests/`; при отсутствии — `tokio::io::duplex` как
  upstream и `mpsc::channel` как `tx`, `make_binary = |b| b`, padding `PaddingScheme::disabled()`).
- [ ] **Step 2: Тест падает** (`cargo test -p outline-ss-rust --lib vless`).
- [ ] **Step 3: Реализация.**
  - В свежем пути (~519-531) убрать `outbound.data_tx.send(... [VERSION, 0x00] ...)` и передать в relay
    `Some(Bytes::from_static(&[vless::VERSION, 0x00]))`.
  - В relay: `let mut header = response_header;` перед циклом; при отправке
    ```rust
    let payload = downlink_buf.split_to(total).freeze();
    let payload = match header.take() {
        Some(h) => {
            let mut joined = BytesMut::with_capacity(h.len() + payload.len());
            joined.extend_from_slice(&h);
            joined.extend_from_slice(&payload);
            joined.freeze()
        },
        None => payload,
    };
    let frame = carrier_padding::frame_downlink_message(padding, payload);
    ```
  - На EOF перед `make_close()`: `if let Some(h) = header.take() { let _ = tx.send(make_binary(carrier_padding::frame_downlink_message(padding, h))).await; }`.
  - На ветке cancel (park для resume) заголовок отбрасывается: resume-путь отправляет свой заголовок сам.
  - Остальные вызовы `relay_vless_upstream_to_client` (resume ~418, mesh) — `None`.
- [ ] **Step 4: Тесты** `cargo test -p outline-ss-rust --lib vless` и e2e VLESS:
  `RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --test e2e_padding --test e2e_smoke -- --test-threads=1`.

---

### Task 4: Паддинг всего downlink VLESS-mux (сервер)

**Files:**
- Modify: `bins/outline-ss-rust/src/server/transport/vless_mux/state.rs` — `MuxState` (~97-106): поле `padding: PaddingScheme`; `MuxState::new(...)` получает `padding`
- Modify: `bins/outline-ss-rust/src/server/transport/vless_mux/mod.rs` — `attach_parked` (~38): параметр `padding`
- Modify: `bins/outline-ss-rust/src/server/transport/vless_mux/frames.rs` — `send_end` (~196), вызовы в `handle_new`/`dispatch_frame`
- Modify: `bins/outline-ss-rust/src/server/transport/vless_mux/tcp_sub.rs` (`open_tcp_sub` ~31, `run_tcp_reader` ~112, отправки ~204/~213), `udp_sub.rs` (`open_udp_sub` ~30, `run_udp_reader` ~124, отправки ~202/~211)
- Modify: `bins/outline-ss-rust/src/server/transport/vless/mod.rs` — заголовок ответа mux ~754 (resume) и ~811 (fresh)
- Test: `bins/outline-ss-rust/src/server/tests/vless.rs` (рядом с `vless_websocket_mux_tcp_relay_smoke`, ~304)

**Interfaces:**
- Consumes: `carrier_padding::frame_downlink_message(scheme: PaddingScheme, bytes: Bytes) -> Bytes`; `route.padding`.
- Produces:
  - `MuxState::new(user, user_counters, accounting, padding: PaddingScheme)`; поле `pub(super) padding: PaddingScheme`.
  - `vless_mux::attach_parked(parked, tx, make_binary, metrics, protocol, accounting, padding: PaddingScheme)` (новый последний параметр).
  - `send_end(tx, make_binary, padding: PaddingScheme, session_id, error)`; `open_tcp_sub`/`run_tcp_reader`/`open_udp_sub`/`run_udp_reader` получают `padding: PaddingScheme` и передают дальше.

- [ ] **Step 1: Падающий тест** — копия `vless_websocket_mux_tcp_relay_smoke` (`server/tests/vless.rs:304`) с путём, где
  `padded = true` (как в существующих padded-тестах сервера: `[padding]` + endpoint `padded = true`; кадры клиента
  оборачивать `outline_wire::padding::encode_frame_into(&mut out, &bytes, &[])`). Все сообщения, полученные клиентом,
  прогонять через `PaddingDecoder::push` в один `BytesMut`; проверить: первые 2 байта — `[VERSION, 0]`, затем
  разбираемый mux-кадр с эхом полезной нагрузки (тем же `parse_frame`, что в исходном тесте). Сейчас тест падает: часть
  сообщений не обёрнута, декодер видит мусор.

Run: `cargo test -p outline-ss-rust --lib server::tests::vless::vless_websocket_mux_tcp_relay_padded`
Expected: FAIL (рассинхрон декодера / неверный заголовок).

- [ ] **Step 2: Реализация** — каждая отправка downlink в mux идёт через `frame_downlink_message`:
  - `vless/mod.rs` ~811 и ~754:
    ```rust
    .send((outbound.make_binary)(carrier_padding::frame_downlink_message(
        route.padding,
        Bytes::from_static(&[vless::VERSION, 0x00]),
    )))
    ```
  - `MuxState::new(..., route.padding)` в свежем пути (~818); `attach_parked(..., route.padding)` в resume (~761);
    `attach_parked` сохраняет `padding` в восстановленный `MuxState`.
  - `send_end`: `tx.send(make_binary(carrier_padding::frame_downlink_message(padding, frame.freeze())))`.
  - `run_tcp_reader` / `run_udp_reader`: `tx.send(make_binary(carrier_padding::frame_downlink_message(padding, frame)))`
    (~204, ~202) и финальные отправки (~213, ~211) так же.
  - `handle_new` берёт `state.padding` и передаёт в `open_tcp_sub` / `open_udp_sub`; прочие вызовы `send_end` —
    `state.padding` или параметр `padding` в задачах подсоединений.
  - На не-padded пути `frame_downlink_message` возвращает байты без изменений — поведение прежнее.
- [ ] **Step 3: Тесты**

Run: `cargo test -p outline-ss-rust --lib server::tests::vless server::tests::resumption`
Expected: PASS, включая новый padded-тест и `vless_mux_resume_hit_preserves_all_sub_conns` (resume-путь с `padding`).

- [ ] **Step 4: fmt/clippy пакета** — `cargo fmt -p outline-ss-rust && cargo clippy -p outline-ss-rust --all-targets --no-deps -- -D warnings`.
- [ ] **Step 5: CHANGELOG сервера** (EN/RU, `Unreleased` → `Fixed`): «VLESS-mux на padded-пути: весь downlink (ответ,
  данные подсоединений, кадры завершения) теперь обёрнут паддингом; раньше уходил без обёртки и ломал бы декодер
  клиента, который включил паддинг».

---

### Task 5: Xray-подписка не берёт padded-эндпоинты (ops/access-keys)

Найдено при планировании: `ops/access-keys/xray_json.py::_vless_path` берёт **первый** VLESS-эндпоинт типа, не
глядя на `padded`, а Xray паддинг не умеет. На .104 padded-эндпоинты стоят первыми — подписка для Happ с такого
конфига указала бы на путь, где Xray не работает. Outline-артефакт padded-пути уже пропускает (`artifacts.py::_outline_legs`).

**Files:**
- Modify: `ops/access-keys/xray_json.py` (`_vless_path` ~133-141)
- Modify: `ops/access-keys/artifacts.py` (`has_subscription` ~42-44)
- Modify: `ops/access-keys/golden/config.toml` (после padded VLESS-эндпоинтов ~38-46 добавить обычные)
- Regenerate: `ops/access-keys/golden/expected/*` (через генератор)
- Test: `ops/access-keys/test_xray_json.py`, `ops/access-keys/test_artifacts.py`
- Docs: `ops/access-keys/README.md` (рядом с правилом паддинга ~268-275; файл только русский)

**Interfaces:**
- Produces: `_vless_path(server, kind)` возвращает путь первого **непадед** эндпоинта типа или `None`;
  `has_subscription(user, server)` = есть `vless_id` и хотя бы один **непадед** `ws_vless`/`xhttp_vless`.

- [ ] **Step 1: Падающие тесты**

В `ops/access-keys/test_xray_json.py` (класс `BuildConfigTest` или новый `PaddedEndpointTest`):

```python
def test_padded_endpoints_are_skipped_even_when_listed_first(self):
    server = ServerConfig(
        access_keys=AK,
        users=(),
        alpn_has_h3=True,
        endpoints=(
            Endpoint("/PAD/vless", "ws_vless", True),
            Endpoint("/PAD/xhttp", "xhttp_vless", True),
            Endpoint("/PLAIN/vless", "ws_vless", False),
            Endpoint("/PLAIN/xhttp", "xhttp_vless", False),
        ),
    )
    doc = json.dumps(gen.build_config(make_user(), NODES, server))
    self.assertIn("/PLAIN/vless", doc)
    self.assertIn("/PLAIN/xhttp", doc)
    self.assertNotIn("/PAD/", doc)
```

В `ops/access-keys/test_artifacts.py`:

```python
def test_no_subscription_when_every_vless_endpoint_is_padded(self):
    server = ServerConfig(
        access_keys=AK,  # константа AccessKeys этого файла
        users=(),
        alpn_has_h3=True,
        endpoints=(Endpoint("/PAD/vless", "ws_vless", True),),
    )
    self.assertFalse(artifacts.has_subscription(make_user(), server))
```

(использовать фабрики пользователя и `AccessKeys`, которые уже есть в `test_artifacts.py`; если имена другие — взять их).

Run: `python3 -m unittest discover -s ops/access-keys -p "test_*.py"` — Expected: оба новых теста FAIL.

- [ ] **Step 2: Реализация**

`xray_json.py`:

```python
def _vless_path(server: ServerConfig, kind: str) -> str | None:
    """The first plain VLESS endpoint path of a kind, or None if the server has none.

    Xray cannot speak the carrier padding, so padded endpoints are skipped even
    when listed first. ...(остальной текст докстринга сохранить)...
    """
    endpoints = [e for e in endpoints_of_kind(server, kind) if not e.padded]
    return endpoints[0].path if endpoints else None
```

`artifacts.py`:

```python
def has_subscription(user: User, server: ServerConfig) -> bool:
    """Whether this user gets a <user>.json — a VLESS id plus a plain VLESS endpoint
    (Xray cannot speak the carrier padding)."""
    return bool(user.vless_id) and any(
        not e.padded for e in endpoints_of_kind(server, "ws_vless", "xhttp_vless")
    )
```

- [ ] **Step 3: Эталонный конфиг как на .104** — в `ops/access-keys/golden/config.toml` сразу после блока
  `/GLOBAL/xhttp` (padded) добавить:

```toml
[[endpoint]]
path = "/GLOBAL/vless-plain"
kind = "ws_vless"

[[endpoint]]
path = "/GLOBAL/xhttp-plain"
kind = "xhttp_vless"
```

- [ ] **Step 4: Перестроить эталоны** — сгенерировать во временный каталог и сравнить:

```bash
T=$(mktemp -d) && python3 ops/access-keys/generate_keys.py --config ops/access-keys/golden/config.toml --out-dir "$T" --file-extension .conf && diff -ru ops/access-keys/golden/expected "$T"
```

Ожидаемый diff: в `*.json` пути `/GLOBAL/vless` → `/GLOBAL/vless-plain` и `/GLOBAL/xhttp` → `/GLOBAL/xhttp-plain`;
в `*.txt` добавились ссылки на обычные пути; `*.toml` **не меняются** (правило «только padded, если они есть»);
`*.conf` не меняются. Если diff другой — разобраться до копирования. Затем `cp "$T"/* ops/access-keys/golden/expected/`
(генератор может писать файлы с правами 0640 — проверить, что в репозитории права обычные, `git diff --summary`).

- [ ] **Step 5: Тесты** — `python3 -m unittest discover -s ops/access-keys -p "test_*.py"` — Expected: всё зелёное.

- [ ] **Step 6: README** (`ops/access-keys/README.md`, после абзаца о правиле паддинга ~275): «Xray-подписка
  (`<user>.json`) строится только по **непадед** VLESS-эндпоинтам: Xray паддинг не умеет. Если у сервера все
  VLESS-эндпоинты padded, `.json` не создаётся.»

- [ ] **Step 7: Раскатка генератора** — отдельно, с согласия владельца: по процедуре `ops/access-keys/README.md`
  (rsync на узлы) и перегенерация ключей на .104; проверить, что `.json` пользователей .104 теперь указывает на
  обычный путь (`curl` кода ответа ссылки — см. память про 0640/403).

---

### Task 6: Заголовок SS2022 уходит вместе с первыми данными (клиент)

**Files:**
- Modify: `crates/outline-transport/src/tcp_transport/writer/transport.rs` — трейт `WriteTransport` (~27-31),
  `WsWriteTransport` (поле `held_tx`, задача-писатель ~68-149, `impl WriteTransport` ~166-192)
- Modify: `crates/outline-transport/src/tcp_transport/writer/mod.rs:122-139` — заголовок через `write_frame_held`
- Test: `crates/outline-transport/src/tcp_transport/writer/tests/transport.rs` (или существующий файл тестов писателя)

**Interfaces:**
- Produces:
  - `trait WriteTransport { …; async fn write_frame_held(&mut self, frame: Vec<u8>) -> Result<()> { self.write_frame(frame).await } }`
    (метод по умолчанию: сокетный транспорт пишет сразу).
  - `pub(crate) const SS2022_HEADER_HOLD: Duration = Duration::from_millis(50);` в `transport.rs`.

- [ ] **Step 1: Тесты** (на `WsWriteTransport` с тестовым sink, который пишет полученные `Message` в `Vec`; время —
  `tokio::time::pause()`):
  1. `write_frame_held(h)` затем `write_frame(d)` в пределах 50 мс → sink получил **одно** `Binary`, равное
     `encode(h) ++ encode(d)` (при выключенном паддинге — `h ++ d`).
  2. `write_frame_held(h)` и тишина → после `advance(50ms)` sink получил одно `Binary` = `h`.
  3. `write_frame_held(h)` затем закрытие писателя → `h` отправлен до закрытия.
- [ ] **Step 2: Тесты падают.**
- [ ] **Step 3: Реализация.**
  - `WsWriteTransport` получает `held_tx: Option<mpsc::Sender<Vec<u8>>>` (ёмкость 1). `write_frame_held` применяет
    паддинг так же, как `write_frame` (тот же `frame_payload_into`), и кладёт результат в `held_tx`.
  - Задача-писатель: `let mut held: Option<Vec<u8>> = None;` и таймер `hold_sleep` (запаркован, как `cover_sleep`).
    В `select!` (biased) ветка `h = held_rx.recv()` идёт **перед** `data_rx`: сохранить в `held`, взвести
    `hold_sleep` на `SS2022_HEADER_HOLD`. В ветке данных: если `held.is_some()` и сообщение `Message::Binary(p)` —
    отправить `Message::Binary([held, p].concat())`, `held = None`. Ветка `hold_sleep` (guard `held.is_some()`) —
    отправить `held` одним `Binary`. Ветки ctrl и закрытие data-канала — сначала отправить `held`, если он есть.
  - В `TcpShadowsocksWriter::send_chunk` (ветка заголовка SS2022, ~139) заменить `self.write_frame(frame)` на
    `self.transport.write_frame_held(frame)`.
- [ ] **Step 4: Тесты писателя и e2e** `RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --test e2e_padding --test e2e_smoke -- --test-threads=1`.

---

### Task 7: Нарезка на клиенте (SS и VLESS)

**Files:**
- Modify: `crates/outline-transport/src/carrier_padding.rs` — хелпер случая и отправка плана
- Modify: `crates/outline-transport/src/tcp_transport/writer/{mod.rs,transport.rs}` — параметр `shape: bool` в
  `TcpShadowsocksWriter::connect` → `WsWriteTransport::spawn`
- Modify: `crates/outline-transport/src/frame_io_ws.rs` — `WsFrameSink` (~279-309), `from_ws_frames` (~456-492)
- Modify: call-sites `connect`: `bins/outline-ws-rust/src/proxy/tcp/failover.rs:~722`,
  `crates/outline-tun/src/tcp/engine/connect.rs:~449`, `crates/outline-uplink/src/probe/transport.rs:~111`, тесты
- Test: `crates/outline-transport/src/tests/carrier_padding.rs`

**Interfaces:**
- Consumes: `outline_wire::early_shape::{EarlyShaper, ShapeDirection, ShapePlan}` (Task 1).
- Produces:
  - `pub(crate) fn draw_in(rng: &mut impl rand::Rng) -> impl FnMut(usize, usize) -> usize + '_` в `carrier_padding.rs`
    (`move |lo, hi| rng.random_range(lo..=hi)`).
  - `pub(crate) fn shaped_messages(scheme: PaddingScheme, shaper: &mut EarlyShaper, frame: &[u8], rng: &mut impl rand::Rng) -> Vec<Vec<u8>>`
    — список готовых (с паддингом) полезных нагрузок сообщений: сначала cover-кадры
    (`encode_frame_into(out, &[], &pad)` с `pad.len()` из плана), затем куски через `frame_payload_into`.
  - `TcpShadowsocksWriter::connect(sink, cipher, master_key, lifetime, shape: bool)`;
    `WsWriteTransport::spawn(sink, shape: bool)`; `from_ws_frames(ws_stream, idle_timeout, keepalive)` вычисляет
    `shape = padding.is_enabled() && !ws_stream.is_h3()` сам.

- [ ] **Step 1: Тест** `shaped_messages`: для кадра 1964 B при включённой схеме — ≥ 2 сообщения после cover'ов;
  декодирование всех сообщений по порядку через `PaddingDecoder` даёт ровно исходные 1964 B; после закрытия окна —
  одно сообщение.
- [ ] **Step 2: Падает.**
- [ ] **Step 3: Реализация.**
  - `WsWriteTransport` хранит `shaper: Option<EarlyShaper>` (`Some` только если `shape && padding.scheme.is_enabled()`,
    создаётся `EarlyShaper::new(ShapeDirection::ClientToServer, &mut draw_in(&mut rand::rng()))`).
    `write_frame`: если `shaper` есть и активен — отправить каждое сообщение из `shaped_messages` отдельным
    `tx.send(Message::Binary(..), bytes)`; иначе — как сейчас.
  - `WsFrameSink::send_frame` — то же для VLESS.
  - Call-sites: вычислить `shape = !ws_stream.is_h3()` **до** `ws_stream.split()` и передать в `connect`;
    в `probe/transport.rs` флаг `is_h3` уже вычислен (~105). Паддинг отключён → `shaper = None` независимо от флага.
- [ ] **Step 4: Тесты** `cargo test -p outline-transport --all-features carrier_padding writer frame_io` и e2e
  `RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls --test e2e_padding -- --test-threads=1`.

---

### Task 8: Нарезка на сервере (SS и VLESS)

**Files:**
- Modify: `bins/outline-ss-rust/src/server/transport/carrier_padding.rs` — `draw_in`, `shaped_messages`
  (те же сигнатуры, что в Task 7, для серверного крейта)
- Modify: `bins/outline-ss-rust/src/server/transport/tcp.rs` — `ChannelSink` (+ поле `shaper: Option<EarlyShaper>`),
  конструкции ~815 / ~1229 / ~1360
- Modify: `bins/outline-ss-rust/src/server/transport/vless/tcp.rs` — `relay_vless_upstream_to_client` (отправка ~964)
- Test: `bins/outline-ss-rust/src/server/transport/tests/carrier_padding.rs`

**Interfaces:**
- Consumes: Task 1, `route.protocol: Protocol` (`metrics/labels.rs:61-80`).
- Produces: `pub(in crate::server) fn shape_eligible(protocol: Protocol, scheme: PaddingScheme) -> bool` =
  `scheme.is_enabled() && matches!(protocol, Protocol::Http1 | Protocol::Http2 | Protocol::XhttpH1 | Protocol::XhttpH2)`.

- [ ] **Step 1: Тесты** `shape_eligible` (h3/socket — false; без паддинга — false) и `shaped_messages` для 4499 B
  в направлении `ServerToClient` (≥ 2 куска, cover'ов нет, декод = исходные байты).
- [ ] **Step 2: Падают.**
- [ ] **Step 3: Реализация.**
  - `ChannelSink::send_ciphertext`: если `shaper` активен — отправить каждое сообщение из `shaped_messages`
    отдельным `self.tx.send((self.make_binary)(Bytes::from(m))).await`; иначе как сейчас. Создавать `shaper` в трёх
    конструкциях: `shape_eligible(route.protocol, route.padding).then(|| EarlyShaper::new(ShapeDirection::ServerToClient, &mut draw_in(&mut rand::rng())))`.
  - VLESS relay: локальный `shaper` по `shape_eligible(protocol, padding)`; отправку ~964 (после склейки с заголовком
    из Task 3) заменить на цикл по `shaped_messages`, если `shaper` активен.
- [ ] **Step 4: Тесты** `cargo test -p outline-ss-rust --lib carrier_padding vless tcp` и e2e как в Task 7.

---

### Task 9: e2e, документация, гейт

**Files:**
- Modify: `bins/outline-ws-rust/tests/e2e_padding.rs` — новые тесты
- Modify: `docs/PADDING.md`, `docs/PADDING.ru.md`; `bins/outline-ss-rust/CHANGELOG{,.ru}.md`;
  `bins/outline-ws-rust/CHANGELOG{,.ru}.md`

- [ ] **Step 1: e2e** — по образцу `padding_ss_ws_h1_roundtrip_with_cover` (`e2e_padding.rs:23-88`):
  `padding_ss_ws_h1_large_first_write_roundtrip` и `padding_vless_ws_h1_large_first_write_roundtrip` с
  `socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), &ramp(6000))`, где `ramp(n)` — `(0..n).map(|i| (i * 31 % 251) as u8).collect::<Vec<_>>()`
  (порядок байт проверяется сравнением эха); и `#[cfg(feature = "test-tls")] padding_ss_ws_h2_large_first_write_roundtrip`
  по образцу `padding_ss_ws_h3_roundtrip_with_cover` (`:612-679`), но `mode: "ws_h2"` и TCP-адрес TLS-сервера.
- [ ] **Step 2: Документация** — в `docs/PADDING.md`/`.ru.md` раздел «Early-session shaping / Форма начала сессии»:
  что режется (h1/h2 TCP на padded-путях, окно 6–10 сообщений / 16–24 КиБ, c→s 300–850, s→c 600–2800, cover 1–2 по
  40–100 с вероятностью 1/2), что всегда (h2 одна запись на кадр, ответ VLESS с данными, заголовок SS2022 с первыми
  данными до 50 мс), что вне рамок (h3, UDP, тайминги). CHANGELOG обоих бинарей, `Unreleased` → `Changed`, EN/RU.
- [ ] **Step 3: Гейт** — все команды из Global Constraints; Linux в docker.
- [ ] **Step 4: Сдать владельцу** `git diff --stat` и итоги гейта; коммит — только по команде.

---

### Task 10 (после коммита и с согласия владельца): повтор замера и раскатка

- [ ] Пересобрать стенд `early-shape` (scratchpad, скрипты `run_in.sh`, `matrix*.sh`, `extract.sh`, `analyze.py`) из
  снимка `git archive <новый коммит>`; прогнать `iso_*` и Chromium-прогоны для `ws_h1`, `ws_h2`, `xhttp_h2`, SS и VLESS,
  паддинг off/on.
- [ ] Критерии успеха (из спеки): h2 без записей 26 и 1041; VLESS-TCP без отдельной s→c 21 B; SS без отдельной
  записи 130–141 B; padded h1/h2 — в окне нет c→s записей > 1,5 КБ, внутренний flight приходит ≥ 2 записями,
  размеры укладываются в c→s 300–850 (+короткие) и s→c 600–2800.
- [ ] Раскатка по одному узлу (серверы, затем клиенты), проверка рестартов и скорости больших загрузок.
