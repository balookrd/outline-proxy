# Дедупликация примитивов и кадрирования в `outline-wire` (M3 — Подпроект 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Вынести дублирующиеся между `outline-server` и `outline-transport` примитивы (`SessionId`, кольцевой буфер байтового реплея `ReplayRing`, кодек заголовков `X-Outline-*`, генератор `X-Padding` и расчёты H2/datagram padding) в общий крейт `outline-wire` без изменения wire-формата.

**Architecture:** Расширяем существующий листовой крейт `crates/outline-wire` безусловной зависимостью `http = { workspace = true }` (чистые типы заголовков без runtime), добавляем модуль `replay_ring` и дополняем модули `resume`, `xhttp` и `padding_frames`. Потребители в `outline-server` и `outline-transport` переводятся на реэкспорты и тонкие доменные фасады (`DownlinkRing` / `ClientUpstreamRingBuffer`), сохраняя внешние сигнатуры для `outline-client` и `outline-tun`.

**Tech Stack:** Rust (Edition 2024), `outline-wire`, `http` 1.x, `bytes`, `rand` 0.10, `proptest`.

## Global Constraints

- Новые крейты в workspace не создаются; все общие компоненты размещаются в `crates/outline-wire`.
- В `crates/outline-wire/Cargo.toml` добавляется только `http = { workspace = true }`; зависимости на `tokio`, `rustls` или AEAD-бэкенды вне существующей фичи `h3-datagram` запрещены.
- Формат кадров и имена/значения HTTP-заголовков на проводе остаются неизменными (совместимость со старыми узлами парка обязательна).
- После проверок и тестов на каждом шаге промежуточные артефакты `target/debug` сразу очищаются (`rm -rf target/debug`), чтобы не забивать диск.
- Все комментарии и docstring'и внутри Rust-кода пишутся на английском языке.

---

## Карта файлов

- **Создаваемые файлы:**
  - `crates/outline-wire/src/replay_ring.rs` — единый кольцевой буфер байтового реплея (`ReplayRing`, `PushError`, `ReplayError`) с переиспользованием вытесненных буферов и режимами `push_strict` / `push_truncating`.
  - `crates/outline-wire/src/tests/replay_ring.rs` — объединённый набор unit- и `proptest`-тестов для обоих режимов `ReplayRing`.
- **Модифицируемые файлы в `outline-wire`:**
  - `crates/outline-wire/Cargo.toml` — добавление `http = { workspace = true }`.
  - `crates/outline-wire/src/lib.rs` — объявление `pub mod replay_ring;` и реэкспорт `SessionId`.
  - `crates/outline-wire/src/resume.rs` и `crates/outline-wire/src/tests/resume.rs` — перенос `SessionId` и добавление `ResumeRequestHeaders`, `RawResumeRequest`, `ResumeResponseHeaders`.
  - `crates/outline-wire/src/xhttp.rs` и `crates/outline-wire/src/tests/xhttp.rs` — добавление `PADDING_MIN_LEN`, `PADDING_MAX_LEN`, `generate_padding_header`, `masquerade_response_headers`, `post_response_headers`, `header_flag_enabled`.
  - `crates/outline-wire/src/padding_frames.rs` и `crates/outline-wire/src/tests/padding_frames.rs` — добавление `H2_WS_SERVER_HEADER_LEN`, `H2_WS_CLIENT_HEADER_LEN`, `h2_record_payload_cap`, `h2_capped_messages`, `try_frame_datagram_into`, `try_frame_datagram`.
- **Модифицируемые / удаляемые файлы в `outline-server` и `outline-transport`:**
  - Удаляются: `bins/outline-server/src/server/resumption/session_id.rs`, `bins/outline-server/src/server/resumption/tests/session_id.rs`, `bins/outline-server/src/server/transport/xhttp/padding.rs`.
  - Обновляются под реэкспорты и фасады:
    - `bins/outline-server/src/server/resumption/mod.rs`, `bins/outline-server/src/server/resumption/registry.rs`, `bins/outline-server/src/server/resumption/downlink_ring.rs`, `bins/outline-server/src/server/resumption/tests/downlink_ring.rs`;
    - `bins/outline-server/src/server/transport/resume_headers.rs`, `bins/outline-server/src/server/transport/xhttp/mod.rs`, `bins/outline-server/src/server/transport/xhttp/handlers.rs`, `bins/outline-server/src/server/transport/xhttp/h3.rs`, `bins/outline-server/src/server/transport/carrier_padding.rs` (+ тестовые вызовы `SessionId::random*` в тестах сервера);
    - `crates/outline-transport/src/resumption.rs`, `crates/outline-transport/src/xhttp/mod.rs`, `crates/outline-transport/src/uplink_replay.rs`, `crates/outline-transport/src/carrier_padding.rs`.

---

### Task 1: Единый `SessionId` в `outline-wire` и подключение `http`

**Files:**
- Modify: `crates/outline-wire/Cargo.toml`
- Modify: `crates/outline-wire/src/lib.rs`
- Modify: `crates/outline-wire/src/resume.rs`
- Modify: `crates/outline-wire/src/tests/resume.rs`
- Delete: `bins/outline-server/src/server/resumption/session_id.rs`
- Delete: `bins/outline-server/src/server/resumption/tests/session_id.rs`
- Modify: `bins/outline-server/src/server/resumption/mod.rs`
- Modify: `bins/outline-server/src/server/resumption/registry.rs`
- Modify: `bins/outline-server/src/server/transport/resume_headers.rs`
- Modify: `bins/outline-server/src/server/cluster/tests/routing.rs`
- Modify: `bins/outline-server/src/server/tests/resumption/cluster.rs`
- Modify: `bins/outline-server/src/server/transport/tests/resume_headers.rs`
- Modify: `bins/outline-server/src/server/transport/tests/tcp.rs`
- Modify: `bins/outline-server/src/server/transport/tests/udp.rs`
- Modify: `crates/outline-transport/src/resumption.rs`

**Interfaces:**
- Produces:
  - `outline_wire::resume::SessionId` (и реэкспорт `outline_wire::SessionId`):
    - `pub const HEX_LEN: usize = 32`
    - `pub const fn from_bytes(bytes: [u8; 16]) -> Self`
    - `pub const fn as_bytes(&self) -> &[u8; 16]`
    - `pub fn random<R: rand::Rng + ?Sized>(rng: &mut R) -> Self`
    - `pub fn random_with_shard<R: rand::Rng + ?Sized>(rng: &mut R, key: &ObfuscationKey, shard: ShardId) -> Self`
    - `pub fn shard(&self, key: &ObfuscationKey) -> ShardId`
    - `pub fn to_hex(self) -> String`
    - `pub fn parse_hex(s: &str) -> Option<Self>`

- [ ] **Step 1: Добавить зависимость `http` в `outline-wire/Cargo.toml` и тесты `SessionId` в `crates/outline-wire/src/tests/resume.rs`**

В `crates/outline-wire/Cargo.toml` в `[dependencies]` добавить `http = { workspace = true }`:

```toml
base64 = { workspace = true, features = ["std"] }
blake3 = { workspace = true }
bytes = { workspace = true }
clap = { workspace = true, optional = true, features = ["derive", "std"] }
http = { workspace = true }
md5 = { workspace = true }
```

В конец `crates/outline-wire/src/tests/resume.rs` добавить тесты `SessionId`:

```rust
#[test]
fn session_id_round_trip_hex_and_case_folding() {
    let mut rng = rand::rng();
    let id = SessionId::random(&mut rng);
    let hex = id.to_hex();
    assert_eq!(hex.len(), SessionId::HEX_LEN);
    assert_eq!(SessionId::parse_hex(&hex), Some(id));
    assert_eq!(SessionId::parse_hex(&hex.to_ascii_uppercase()), Some(id));
}

#[test]
fn session_id_parse_hex_rejects_bad_length_and_non_hex() {
    assert!(SessionId::parse_hex("").is_none());
    assert!(SessionId::parse_hex(&"a".repeat(31)).is_none());
    assert!(SessionId::parse_hex(&"a".repeat(33)).is_none());
    assert!(SessionId::parse_hex(&"g".repeat(32)).is_none());
}

#[test]
fn session_id_debug_truncates_secret() {
    let id = SessionId::from_bytes([0xAB; 16]);
    let debug = format!("{id:?}");
    assert_eq!(debug, "SessionId(abababab…)");
    assert_eq!(format!("{id}"), "abababababababababababababababab");
}

#[test]
fn session_id_shard_round_trips_all_shards() {
    use crate::cluster::{MAX_SHARDS, ObfuscationKey, ShardId};

    let mut rng = rand::rng();
    let key = ObfuscationKey::derive_from_psk(b"session-id-shard-psk");
    for s in 0..MAX_SHARDS {
        let shard = ShardId::new(s).unwrap();
        let id = SessionId::random_with_shard(&mut rng, &key, shard);
        assert_eq!(id.shard(&key), shard);
        let parsed = SessionId::parse_hex(&id.to_hex()).unwrap();
        assert_eq!(parsed.shard(&key), shard);
    }
}
```

- [ ] **Step 2: Запустить тест и убедиться, что он ещё не компилируется**

Run: `cargo test -p outline-wire session_id_`
Expected: FAIL (`cannot find type SessionId in this scope`).

- [ ] **Step 3: Реализовать `SessionId` в `crates/outline-wire/src/resume.rs` и реэкспортировать в `lib.rs`**

В `crates/outline-wire/src/resume.rs` добавить тип `SessionId`:

```rust
use std::fmt;

use rand::{Rng, RngExt};

use crate::cluster::{ObfuscationKey, ShardId, decode_shard, encode_session_id};

/// Server-minted opaque 16-byte token identifying a resumable session.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);

impl SessionId {
    /// Length, in characters, of [`Self::to_hex`] output.
    pub const HEX_LEN: usize = 32;

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Draws a fresh random identifier from `rng`.
    pub fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Draws a fresh identifier carrying the obfuscated cluster `shard` under `key`.
    pub fn random_with_shard<R: Rng + ?Sized>(
        rng: &mut R,
        key: &ObfuscationKey,
        shard: ShardId,
    ) -> Self {
        let mut entropy = [0u8; 16];
        rng.fill_bytes(&mut entropy);
        Self(encode_session_id(key, shard, &entropy))
    }

    /// Decodes the cluster shard embedded in this id under `key`.
    pub fn shard(&self, key: &ObfuscationKey) -> ShardId {
        decode_shard(key, &self.0)
    }

    /// Lowercase 32-hex-char representation suitable for HTTP headers.
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(Self::HEX_LEN);
        for byte in &self.0 {
            out.push(hex_nibble(byte >> 4));
            out.push(hex_nibble(byte & 0x0f));
        }
        out
    }

    /// Parses a 32-character hex value (case-insensitive).
    pub fn parse_hex(s: &str) -> Option<Self> {
        if s.len() != Self::HEX_LEN {
            return None;
        }
        let bytes = s.as_bytes();
        let mut out = [0u8; 16];
        for i in 0..16 {
            let hi = hex_value(bytes[2 * i])?;
            let lo = hex_value(bytes[2 * i + 1])?;
            out[i] = (hi << 4) | lo;
        }
        Some(Self(out))
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Truncate so logs stay readable; the full ID is a bearer token.
        let hex = self.to_hex();
        write!(f, "SessionId({}…)", &hex[..8])
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

const fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => '?',
    }
}

const fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
```

В `crates/outline-wire/src/lib.rs` добавить `pub use resume::SessionId;`.

- [ ] **Step 4: Перевести `outline-transport` и `outline-server` на `outline_wire::resume::SessionId`**

1. В `crates/outline-transport/src/resumption.rs` удалить локальное объявление `struct SessionId`, `impl SessionId`, `fmt::Debug`, `fmt::Display`, `hex_nibble`, `hex_value` и заменить реэкспортом:
   ```rust
   pub use outline_wire::resume::{
       ACK_PREFIX_HEADER, DOWN_ACKED_HEADER, HOME_AFFINITY_HEADER, RESUME_CAPABLE_HEADER,
       RESUME_REQUEST_HEADER, SESSION_RESPONSE_HEADER, SYMMETRIC_REPLAY_HEADER, SessionId,
   };
   ```
2. Удалить файлы `bins/outline-server/src/server/resumption/session_id.rs` и `bins/outline-server/src/server/resumption/tests/session_id.rs`.
3. В `bins/outline-server/src/server/resumption/mod.rs` убрать `mod session_id;` и заменить `pub(super) use session_id::SessionId;` на `pub(crate) use outline_wire::resume::SessionId;`.
4. В `bins/outline-server/src/server/resumption/registry.rs`:
   - убрать импорт `ring::rand::SystemRandom` и поле `rng: SystemRandom` из `OrphanRegistry`;
   - упростить `mint_session_id` и `mint_session_id_for_shard`:
     ```rust
     pub(crate) fn mint_session_id(&self) -> Option<SessionId> {
         if !self.enabled() {
             return None;
         }
         let mut rng = rand::rng();
         Some(match &self.cluster {
             Some(identity) => {
                 SessionId::random_with_shard(&mut rng, &identity.key, identity.shard)
             },
             None => SessionId::random(&mut rng),
         })
     }

     #[allow(dead_code)]
     pub(crate) fn mint_session_id_for_shard(
         &self,
         shard: outline_wire::cluster::ShardId,
     ) -> Option<SessionId> {
         if !self.enabled() {
             return None;
         }
         let id = self.cluster.as_ref()?;
         Some(SessionId::random_with_shard(&mut rand::rng(), &id.key, shard))
     }
     ```
5. В `bins/outline-server/src/server/transport/resume_headers.rs:246` и в тестах сервера (`cluster/tests/routing.rs`, `tests/resumption/cluster.rs`, `transport/tests/resume_headers.rs`, `transport/tests/tcp.rs`, `transport/tests/udp.rs`) заменить `SessionId::random_with_shard(&SystemRandom::new(), &key, shard).unwrap()` на `SessionId::random_with_shard(&mut rand::rng(), &key, shard)`.

- [ ] **Step 5: Прогнать тесты, линтер, очистить `target/debug` и закоммитить**

Run:
```bash
cargo fmt --check -p outline-wire -p outline-transport -p outline-server && \
cargo clippy -p outline-wire -p outline-transport -p outline-server --all-targets --no-deps -- -D warnings && \
cargo test -p outline-wire -p outline-transport -p outline-server && \
rm -rf target/debug
```
Expected: PASS (exit code 0).

Commit:
```bash
git add -A crates/outline-wire crates/outline-transport bins/outline-server Cargo.lock
git commit -m "refactor(wire): unify SessionId in outline-wire::resume"
```

---

### Task 2: Единый кольцевой буфер `ReplayRing` в `outline-wire`

**Files:**
- Create: `crates/outline-wire/src/replay_ring.rs`
- Create: `crates/outline-wire/src/tests/replay_ring.rs`
- Modify: `crates/outline-wire/src/lib.rs`
- Modify: `crates/outline-transport/src/uplink_replay.rs`
- Modify: `bins/outline-server/src/server/resumption/downlink_ring.rs`

**Interfaces:**
- Produces:
  - `outline_wire::replay_ring::{ReplayRing, PushError, ReplayError}`
  - Методы `ReplayRing::new`, `capacity_bytes`, `total_sent`, `oldest_offset`, `buffered_bytes`, `push_strict`, `push_truncating`, `replay_from`.
  - Сохраняет публичные фасады `outline_transport::uplink_replay::{ClientUpstreamRingBuffer, PushError, ReplayError}` и `outline_server` `DownlinkRing` / `ReplayOutcome`.

- [ ] **Step 1: Создать `crates/outline-wire/src/tests/replay_ring.rs` с тестами обоих режимов и проверкой переиспользования буфера**

Создать `crates/outline-wire/src/tests/replay_ring.rs`:

```rust
use proptest::prelude::*;

use super::{PushError, ReplayError, ReplayRing};

#[test]
fn push_strict_rejects_oversized_without_mutating_state() {
    let mut ring = ReplayRing::new(8);
    ring.push_strict(b"abcd").unwrap();
    assert_eq!(
        ring.push_strict(b"012345678"),
        Err(PushError::OversizedSingleChunk { chunk_len: 9, capacity_bytes: 8 }),
    );
    assert_eq!(ring.total_sent(), 4);
    assert_eq!(ring.buffered_bytes(), 4);
    assert_eq!(ring.replay_from(0), Ok(b"abcd".to_vec()));
}

#[test]
fn push_strict_evicts_fifo_and_replays_partial_chunk_suffix() {
    let mut ring = ReplayRing::new(6);
    ring.push_strict(b"aaa").unwrap();
    ring.push_strict(b"bbb").unwrap();
    ring.push_strict(b"cc").unwrap();
    assert_eq!(ring.oldest_offset(), 3);
    assert_eq!(
        ring.replay_from(2),
        Err(ReplayError::OffsetEvicted { requested: 2, oldest_available: 3 }),
    );
    assert_eq!(ring.replay_from(4), Ok(b"bbcc".to_vec()));
    assert_eq!(ring.replay_from(8), Ok(Vec::new()));
    assert_eq!(
        ring.replay_from(9),
        Err(ReplayError::OffsetAhead { requested: 9, total_sent: 8 }),
    );
}

#[test]
fn push_strict_reuses_evicted_buffer_without_oversized_pinning() {
    let mut ring = ReplayRing::new(16);
    ring.push_strict(&[b'x'; 16]).unwrap();
    let first_ptr = ring.entries.front().unwrap().payload.as_ptr();

    // Evicts the 16-byte entry; 16 <= 10 * 2, so the buffer is recycled in place.
    ring.push_strict(&[b'y'; 10]).unwrap();
    assert_eq!(ring.entries.back().unwrap().payload.as_ptr(), first_ptr);

    // A tiny 2-byte push that evicts the 16-cap buffer must NOT pin it (16 > 2 * 2).
    ring.push_strict(&[b'z'; 6]).unwrap();
    ring.push_strict(&[b'w'; 2]).unwrap();
    assert!(ring.entries.back().unwrap().payload.capacity() <= 4);
}

#[test]
fn push_truncating_retains_tail_of_oversized_chunk_and_handles_zero_cap() {
    let mut zero = ReplayRing::new(0);
    zero.push_truncating(b"hello");
    assert_eq!(zero.total_sent(), 5);
    assert_eq!(zero.buffered_bytes(), 0);
    assert_eq!(
        zero.replay_from(0),
        Err(ReplayError::OffsetEvicted { requested: 0, oldest_available: 5 }),
    );
    assert_eq!(zero.replay_from(5), Ok(Vec::new()));

    let mut ring = ReplayRing::new(4);
    ring.push_truncating(b"ab");
    ring.push_truncating(b"012345");
    assert_eq!(ring.total_sent(), 8);
    assert_eq!(ring.oldest_offset(), 4);
    assert_eq!(ring.buffered_bytes(), 4);
    assert_eq!(ring.replay_from(4), Ok(b"2345".to_vec()));
    assert_eq!(ring.replay_from(6), Ok(b"45".to_vec()));
}

proptest! {
    #[test]
    fn replay_ring_truncating_matches_reference_stream(
        cap in 0usize..64,
        chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..48), 0..20),
    ) {
        let mut ring = ReplayRing::new(cap);
        let mut reference = Vec::new();
        for chunk in &chunks {
            ring.push_truncating(chunk);
            reference.extend_from_slice(chunk);
        }
        prop_assert_eq!(ring.total_sent(), reference.len() as u64);
        prop_assert!(ring.buffered_bytes() <= cap);
        let oldest = ring.oldest_offset() as usize;
        for offset in 0..=reference.len() {
            let res = ring.replay_from(offset as u64);
            if offset < oldest {
                prop_assert!(matches!(res, Err(ReplayError::OffsetEvicted { .. })));
            } else {
                prop_assert_eq!(res, Ok(reference[offset..].to_vec()));
            }
        }
    }
}
```

- [ ] **Step 2: Подключить `pub mod replay_ring;` в `lib.rs` и убедиться, что тест падает до реализации**

В `crates/outline-wire/src/lib.rs` добавить `pub mod replay_ring;`.
Run: `cargo test -p outline-wire replay_ring`
Expected: FAIL (файл `replay_ring.rs` ещё не создан).

- [ ] **Step 3: Реализовать `crates/outline-wire/src/replay_ring.rs` и перевести фасады `DownlinkRing` / `ClientUpstreamRingBuffer`**

Создать `crates/outline-wire/src/replay_ring.rs`:

```rust
//! Bounded byte-offset-addressed FIFO replay ring shared by the client uplink
//! and server downlink session-resumption buffers.

use std::collections::VecDeque;

/// Failure modes for [`ReplayRing::push_strict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushError {
    OversizedSingleChunk { chunk_len: usize, capacity_bytes: usize },
}

/// Failure modes for [`ReplayRing::replay_from`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    OffsetEvicted { requested: u64, oldest_available: u64 },
    OffsetAhead { requested: u64, total_sent: u64 },
}

#[derive(Debug)]
struct Entry {
    offset: u64,
    payload: Vec<u8>,
}

fn reusable(buffer: Vec<u8>, chunk_len: usize) -> Option<Vec<u8>> {
    (buffer.capacity() <= chunk_len.saturating_mul(2)).then_some(buffer)
}

fn store(recycled: Option<Vec<u8>>, chunk: &[u8]) -> Vec<u8> {
    match recycled {
        Some(mut buffer) => {
            buffer.clear();
            buffer.extend_from_slice(chunk);
            buffer
        },
        None => chunk.to_vec(),
    }
}

/// Bounded FIFO ring of byte chunks indexed by absolute stream offset.
#[derive(Debug)]
pub struct ReplayRing {
    capacity_bytes: usize,
    entries: VecDeque<Entry>,
    current_bytes: usize,
    total_sent: u64,
}

impl ReplayRing {
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            capacity_bytes,
            entries: VecDeque::new(),
            current_bytes: 0,
            total_sent: 0,
        }
    }

    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }

    pub fn total_sent(&self) -> u64 {
        self.total_sent
    }

    pub fn oldest_offset(&self) -> u64 {
        match self.entries.front() {
            Some(entry) => entry.offset,
            None => self.total_sent,
        }
    }

    pub fn buffered_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Strict FIFO push (client uplink): rejects a single chunk larger than
    /// `capacity_bytes` without mutating state.
    pub fn push_strict(&mut self, chunk: &[u8]) -> Result<(), PushError> {
        if chunk.is_empty() {
            return Ok(());
        }
        if chunk.len() > self.capacity_bytes {
            return Err(PushError::OversizedSingleChunk {
                chunk_len: chunk.len(),
                capacity_bytes: self.capacity_bytes,
            });
        }
        self.push_fitting(chunk);
        Ok(())
    }

    /// Infallible FIFO push (server downlink): retains at most the trailing
    /// `capacity_bytes` of an oversized chunk while advancing `total_sent` by
    /// the full `chunk.len()`.
    pub fn push_truncating(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        if self.capacity_bytes == 0 {
            self.total_sent = self.total_sent.saturating_add(chunk.len() as u64);
            return;
        }
        if chunk.len() >= self.capacity_bytes {
            self.entries.clear();
            self.current_bytes = 0;
            let drop_prefix = chunk.len() - self.capacity_bytes;
            let kept_offset = self.total_sent.saturating_add(drop_prefix as u64);
            let kept_payload = chunk[drop_prefix..].to_vec();
            let kept_len = kept_payload.len();
            self.entries.push_back(Entry {
                offset: kept_offset,
                payload: kept_payload,
            });
            self.current_bytes = kept_len;
            self.total_sent = self.total_sent.saturating_add(chunk.len() as u64);
            return;
        }
        self.push_fitting(chunk);
    }

    fn push_fitting(&mut self, chunk: &[u8]) {
        let mut recycled: Option<Vec<u8>> = None;
        while self.current_bytes + chunk.len() > self.capacity_bytes {
            let evicted = self
                .entries
                .pop_front()
                .expect("loop condition implies entries is non-empty");
            self.current_bytes = self.current_bytes.saturating_sub(evicted.payload.len());
            if let Some(buffer) = reusable(evicted.payload, chunk.len()) {
                recycled = Some(buffer);
            }
        }
        let offset = self.total_sent;
        self.entries
            .push_back(Entry { offset, payload: store(recycled, chunk) });
        self.current_bytes += chunk.len();
        self.total_sent = self.total_sent.saturating_add(chunk.len() as u64);
    }

    /// Returns the contiguous suffix `[offset, total_sent())` as a fresh `Vec<u8>`.
    pub fn replay_from(&self, offset: u64) -> Result<Vec<u8>, ReplayError> {
        if offset > self.total_sent {
            return Err(ReplayError::OffsetAhead {
                requested: offset,
                total_sent: self.total_sent,
            });
        }
        if offset == self.total_sent {
            return Ok(Vec::new());
        }
        let oldest = self.oldest_offset();
        if offset < oldest {
            return Err(ReplayError::OffsetEvicted {
                requested: offset,
                oldest_available: oldest,
            });
        }
        let bytes_to_replay = (self.total_sent - offset) as usize;
        let mut out = Vec::with_capacity(bytes_to_replay);
        for entry in &self.entries {
            let entry_end = entry.offset + entry.payload.len() as u64;
            if entry_end <= offset {
                continue;
            }
            if entry.offset >= offset {
                out.extend_from_slice(&entry.payload);
            } else {
                let split = (offset - entry.offset) as usize;
                out.extend_from_slice(&entry.payload[split..]);
            }
        }
        debug_assert_eq!(out.len(), bytes_to_replay);
        Ok(out)
    }
}

#[cfg(test)]
#[path = "tests/replay_ring.rs"]
mod tests;
```

Обновить `crates/outline-transport/src/uplink_replay.rs` до тонкого фасада над `ReplayRing`:

```rust
//! Client uplink replay buffer backed by [`outline_wire::replay_ring::ReplayRing`].

pub use outline_wire::replay_ring::{PushError, ReplayError};
use outline_wire::replay_ring::ReplayRing;

pub struct ClientUpstreamRingBuffer(ReplayRing);

impl ClientUpstreamRingBuffer {
    pub fn new(capacity_bytes: usize) -> Self {
        Self(ReplayRing::new(capacity_bytes))
    }

    pub fn capacity_bytes(&self) -> usize {
        self.0.capacity_bytes()
    }

    pub fn total_sent(&self) -> u64 {
        self.0.total_sent()
    }

    pub fn oldest_offset(&self) -> u64 {
        self.0.oldest_offset()
    }

    pub fn buffered_bytes(&self) -> usize {
        self.0.buffered_bytes()
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<(), PushError> {
        self.0.push_strict(chunk)
    }

    pub fn replay_from(&self, offset: u64) -> Result<Vec<u8>, ReplayError> {
        self.0.replay_from(offset)
    }
}

#[cfg(test)]
#[path = "tests/uplink_replay.rs"]
mod tests;
```

Обновить `bins/outline-server/src/server/resumption/downlink_ring.rs` до тонкого фасада над `ReplayRing`:

```rust
//! Server downlink replay buffer backed by [`outline_wire::replay_ring::ReplayRing`].

use outline_wire::replay_ring::{ReplayError, ReplayRing};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplayOutcome {
    Available(Vec<u8>),
    Truncated,
    OffsetAhead,
}

pub(crate) struct DownlinkRing(ReplayRing);

impl DownlinkRing {
    pub(crate) fn new(capacity_bytes: usize) -> Self {
        Self(ReplayRing::new(capacity_bytes))
    }

    #[allow(dead_code)]
    pub(crate) fn capacity_bytes(&self) -> usize {
        self.0.capacity_bytes()
    }

    pub(crate) fn total_sent(&self) -> u64 {
        self.0.total_sent()
    }

    pub(crate) fn oldest_offset(&self) -> u64 {
        self.0.oldest_offset()
    }

    pub(crate) fn buffered_bytes(&self) -> usize {
        self.0.buffered_bytes()
    }

    pub(crate) fn push(&mut self, chunk: &[u8]) {
        self.0.push_truncating(chunk);
    }

    pub(crate) fn replay_from(&self, offset: u64) -> ReplayOutcome {
        match self.0.replay_from(offset) {
            Ok(bytes) => ReplayOutcome::Available(bytes),
            Err(ReplayError::OffsetEvicted { .. }) => ReplayOutcome::Truncated,
            Err(ReplayError::OffsetAhead { .. }) => ReplayOutcome::OffsetAhead,
        }
    }
}

#[cfg(test)]
#[path = "tests/downlink_ring.rs"]
mod tests;
```

- [ ] **Step 4: Запустить тесты `outline-wire`, `outline-transport`, `outline-server` и очистить `target/debug`**

Run:
```bash
cargo fmt --check -p outline-wire -p outline-transport -p outline-server && \
cargo clippy -p outline-wire -p outline-transport -p outline-server --all-targets --no-deps -- -D warnings && \
cargo test -p outline-wire -p outline-transport -p outline-server && \
rm -rf target/debug
```
Expected: PASS (все старые тесты в `tests/uplink_replay.rs` и `tests/downlink_ring.rs` плюс новые тесты в `outline-wire` проходят зелёными).

- [ ] **Step 5: Закоммитить**

```bash
git add crates/outline-wire/src/lib.rs crates/outline-wire/src/replay_ring.rs crates/outline-wire/src/tests/replay_ring.rs crates/outline-transport/src/uplink_replay.rs bins/outline-server/src/server/resumption/downlink_ring.rs
git commit -m "refactor(wire): extract shared ReplayRing for uplink and downlink replay"
```

---

### Task 3: Кодек заголовков `X-Outline-*` (`ResumeRequestHeaders` / `ResumeResponseHeaders`)

**Files:**
- Modify: `crates/outline-wire/src/resume.rs`
- Modify: `crates/outline-wire/src/tests/resume.rs`
- Modify: `crates/outline-transport/src/resumption.rs`
- Modify: `crates/outline-transport/src/xhttp/mod.rs`
- Modify: `bins/outline-server/src/server/transport/resume_headers.rs`

**Interfaces:**
- Consumes: `outline_wire::resume::SessionId`, `http::HeaderMap`
- Produces:
  - `outline_wire::resume::{ResumeRequestHeaders, RawResumeRequest, ResumeResponseHeaders, header_is_one}`

- [ ] **Step 1: Добавить тесты `ResumeRequestHeaders` и `ResumeResponseHeaders` в `crates/outline-wire/src/tests/resume.rs`**

```rust
#[test]
fn resume_request_headers_round_trip_and_mutual_exclusion() {
    let resume_id = SessionId::from_bytes([0x11; 16]);
    let affinity_id = SessionId::from_bytes([0x22; 16]);
    let req = ResumeRequestHeaders {
        resume_capable: true,
        resume_request: Some(resume_id),
        home_affinity: Some(affinity_id),
        ack_prefix: true,
        symmetric_replay: true,
        down_acked: 4096,
        udp_datagram: true,
        udp_records: true,
    };
    let mut map = http::HeaderMap::new();
    req.write_to(&mut map);

    let parsed = ResumeRequestHeaders::parse_raw(&map);
    assert!(parsed.resume_capable);
    assert_eq!(parsed.resume_request, Some(resume_id));
    // home_affinity is suppressed when resume_request is present.
    assert_eq!(parsed.home_affinity, None);
    assert!(parsed.ack_prefix);
    assert!(parsed.symmetric_replay);
    assert_eq!(parsed.down_acked, 4096);
    assert!(!parsed.malformed_down_acked);
    assert!(parsed.udp_datagram);
    assert!(parsed.udp_records);
}

#[test]
fn resume_request_parse_raw_handles_malformed_down_acked_and_trimmed_flags() {
    let mut map = http::HeaderMap::new();
    map.insert(ACK_PREFIX_HEADER, http::HeaderValue::from_static(" 1 "));
    map.insert(DOWN_ACKED_HEADER, http::HeaderValue::from_static("not-a-u64"));
    let parsed = ResumeRequestHeaders::parse_raw(&map);
    assert!(parsed.ack_prefix);
    assert_eq!(parsed.down_acked, 0);
    assert!(parsed.malformed_down_acked);
}

#[test]
fn resume_response_echo_masks_unrequested_and_enforces_v2_on_v1() {
    let id = SessionId::from_bytes([0x55; 16]);
    let mut resp_map = http::HeaderMap::new();
    resp_map.insert(SESSION_RESPONSE_HEADER, id.to_hex().parse().unwrap());
    resp_map.insert(SYMMETRIC_REPLAY_HEADER, http::HeaderValue::from_static(" 1 "));
    resp_map.insert(crate::xhttp::UDP_DATAGRAM_HEADER, http::HeaderValue::from_static("1"));

    // Request asked for v1 + v2, but server echoed ONLY v2 (missing v1) and unrequested datagram.
    let requested = ResumeRequestHeaders {
        ack_prefix: true,
        symmetric_replay: true,
        udp_datagram: false,
        ..Default::default()
    };
    let echo = ResumeResponseHeaders::parse_echo(&resp_map, &requested);
    assert_eq!(echo.session_id, Some(id));
    assert!(!echo.ack_prefix);
    assert!(!echo.symmetric_replay, "v2 without v1 echo must be rejected");
    assert!(!echo.udp_datagram, "unrequested datagram echo must be ignored");
}
```

- [ ] **Step 2: Запустить тесты `outline-wire` и убедиться, что новые тесты ещё не компилируются**

Run: `cargo test -p outline-wire resume_`
Expected: FAIL (`cannot find struct ResumeRequestHeaders`).

- [ ] **Step 3: Реализовать `ResumeRequestHeaders`, `RawResumeRequest`, `ResumeResponseHeaders` в `crates/outline-wire/src/resume.rs`**

В `crates/outline-wire/src/resume.rs` добавить:

```rust
use http::{HeaderMap, HeaderName, HeaderValue};

use crate::xhttp::{UDP_DATAGRAM_HEADER, UDP_RECORDS_ENABLED, UDP_RECORDS_HEADER};

/// Whether `name` in `headers` equals `"1"` after ASCII whitespace trimming.
pub fn header_is_one(headers: &HeaderMap, name: &str) -> bool {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == "1")
}

/// Client → server negotiation headers for session resumption and UDP framing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResumeRequestHeaders {
    pub resume_capable: bool,
    pub resume_request: Option<SessionId>,
    /// Emitted only when `resume_request` is `None`.
    pub home_affinity: Option<SessionId>,
    pub ack_prefix: bool,
    pub symmetric_replay: bool,
    /// Emitted only when `symmetric_replay && down_acked > 0`.
    pub down_acked: u64,
    pub udp_datagram: bool,
    pub udp_records: bool,
}

/// Raw parsed request headers before server-side registry / cluster policy gating.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RawResumeRequest {
    pub resume_capable: bool,
    pub resume_request: Option<SessionId>,
    pub home_affinity: Option<SessionId>,
    pub ack_prefix: bool,
    pub symmetric_replay: bool,
    pub down_acked: u64,
    pub malformed_down_acked: bool,
    pub udp_datagram: bool,
    pub udp_records: bool,
}

impl ResumeRequestHeaders {
    pub fn write_to(&self, headers: &mut HeaderMap) {
        if self.resume_capable {
            headers.insert(RESUME_CAPABLE_HEADER, HeaderValue::from_static("1"));
        }
        if let Some(id) = self.resume_request {
            headers.insert(
                RESUME_REQUEST_HEADER,
                HeaderValue::try_from(id.to_hex()).expect("hex Session ID is a valid header value"),
            );
        } else if let Some(affinity_id) = self.home_affinity {
            headers.insert(
                HOME_AFFINITY_HEADER,
                HeaderValue::try_from(affinity_id.to_hex())
                    .expect("hex Session ID is a valid header value"),
            );
        }
        if self.ack_prefix {
            headers.insert(ACK_PREFIX_HEADER, HeaderValue::from_static("1"));
        }
        if self.symmetric_replay {
            headers.insert(SYMMETRIC_REPLAY_HEADER, HeaderValue::from_static("1"));
        }
        if self.symmetric_replay && self.down_acked > 0 {
            headers.insert(DOWN_ACKED_HEADER, HeaderValue::from(self.down_acked));
        }
        if self.udp_records {
            headers.insert(
                HeaderName::from_static(UDP_RECORDS_HEADER),
                HeaderValue::from_static(UDP_RECORDS_ENABLED),
            );
        }
        if self.udp_datagram {
            headers.insert(
                HeaderName::from_static(UDP_DATAGRAM_HEADER),
                HeaderValue::from_static("1"),
            );
        }
    }

    pub fn parse_raw(headers: &HeaderMap) -> RawResumeRequest {
        let resume_request = headers
            .get(RESUME_REQUEST_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(SessionId::parse_hex);
        let home_affinity = headers
            .get(HOME_AFFINITY_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(SessionId::parse_hex);
        let (down_acked, malformed_down_acked) = match headers
            .get(DOWN_ACKED_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
        {
            Some(value) if !value.is_empty() => match value.parse::<u64>() {
                Ok(n) => (n, false),
                Err(_) => (0, true),
            },
            _ => (0, false),
        };
        RawResumeRequest {
            resume_capable: header_is_one(headers, RESUME_CAPABLE_HEADER),
            resume_request,
            home_affinity,
            ack_prefix: header_is_one(headers, ACK_PREFIX_HEADER),
            symmetric_replay: header_is_one(headers, SYMMETRIC_REPLAY_HEADER),
            down_acked,
            malformed_down_acked,
            udp_datagram: header_is_one(headers, UDP_DATAGRAM_HEADER),
            udp_records: header_is_one(headers, UDP_RECORDS_HEADER),
        }
    }
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
    pub fn write_to(&self, headers: &mut HeaderMap) {
        if let Some(id) = self.session_id {
            headers.insert(
                SESSION_RESPONSE_HEADER,
                HeaderValue::try_from(id.to_hex()).expect("hex Session ID is a valid header value"),
            );
        }
        if self.ack_prefix {
            headers.insert(ACK_PREFIX_HEADER, HeaderValue::from_static("1"));
        }
        if self.symmetric_replay {
            headers.insert(SYMMETRIC_REPLAY_HEADER, HeaderValue::from_static("1"));
        }
        if self.udp_records {
            headers.insert(
                HeaderName::from_static(UDP_RECORDS_HEADER),
                HeaderValue::from_static(UDP_RECORDS_ENABLED),
            );
        }
        if self.udp_datagram {
            headers.insert(
                HeaderName::from_static(UDP_DATAGRAM_HEADER),
                HeaderValue::from_static("1"),
            );
        }
    }

    pub fn parse_echo(headers: &HeaderMap, requested: &ResumeRequestHeaders) -> Self {
        let session_id = headers
            .get(SESSION_RESPONSE_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(SessionId::parse_hex);
        let ack_prefix = requested.ack_prefix && header_is_one(headers, ACK_PREFIX_HEADER);
        let symmetric_replay = requested.symmetric_replay
            && ack_prefix
            && header_is_one(headers, SYMMETRIC_REPLAY_HEADER);
        let udp_datagram = requested.udp_datagram && header_is_one(headers, UDP_DATAGRAM_HEADER);
        let udp_records = requested.udp_records && header_is_one(headers, UDP_RECORDS_HEADER);
        Self {
            session_id,
            ack_prefix,
            symmetric_replay,
            udp_datagram,
            udp_records,
        }
    }
}
```

- [ ] **Step 4: Перевести `outline-transport` (`resumption.rs` и `xhttp/mod.rs`) и `outline-server` (`resume_headers.rs`) на общий кодек**

1. В `crates/outline-transport/src/resumption.rs`:
   - `apply_resume_request_headers(resume, headers)` строит `ResumeRequestHeaders` (`resume_capable: true`, `udp_datagram: false`, `udp_records: false`) и вызывает `.write_to(headers)`.
   - `parse_resume_response_echo(resume, headers)` строит `ResumeRequestHeaders` из `resume` (с `udp_datagram: resume.udp_datagram_requested`) и маппит `ResumeResponseHeaders::parse_echo(headers, &req)` в `NegotiatedResume`.
2. В `crates/outline-transport/src/xhttp/mod.rs:471-507` заменить ручную вставку всех 8 заголовков одним вызовом:
   ```rust
   outline_wire::resume::ResumeRequestHeaders {
       resume_capable: true,
       resume_request: open.resume_request,
       home_affinity: open.home_affinity,
       ack_prefix: open.ack_prefix_requested,
       symmetric_replay: open.symmetric_replay_requested,
       down_acked: open.client_acked_offset,
       udp_datagram,
       udp_records: open.datagram_records,
   }
   .write_to(&mut headers);
   ```
3. В `bins/outline-server/src/server/transport/resume_headers.rs`:
   - В `ResumeContext::from_request_headers` вызвать `let raw = ResumeRequestHeaders::parse_raw(headers);`, сохранить `RouteDecision` и `OrphanRegistry`-гейтинг, а при `symmetric_replay_requested && requested_resume.is_some() && raw.malformed_down_acked` оставить `debug!("malformed X-Outline-Resume-Down-Acked; treating as 0 per spec")`.
   - В `edge_route` использовать `let raw = ResumeRequestHeaders::parse_raw(headers);` вместо ручного чтения 5 заголовков и удалить дубликат `fn header_is_one`.
   - В `ResumeResponseEcho::apply` вызывать `ResumeResponseHeaders { session_id: self.session_id, ack_prefix: self.ack_prefix, symmetric_replay: self.symmetric_replay, ..Default::default() }.write_to(headers)`.

- [ ] **Step 5: Прогнать тесты, линтер, очистить `target/debug` и закоммитить**

Run:
```bash
cargo fmt --check -p outline-wire -p outline-transport -p outline-server && \
cargo clippy -p outline-wire -p outline-transport -p outline-server --all-targets --no-deps -- -D warnings && \
cargo test -p outline-wire -p outline-transport -p outline-server && \
rm -rf target/debug
```
Expected: PASS (exit code 0).

Commit:
```bash
git add crates/outline-wire/src/resume.rs crates/outline-wire/src/tests/resume.rs crates/outline-transport/src/resumption.rs crates/outline-transport/src/xhttp/mod.rs bins/outline-server/src/server/transport/resume_headers.rs
git commit -m "refactor(wire): deduplicate X-Outline-* resume header negotiation"
```

---

### Task 4: XHTTP `X-Padding` и маскировочные заголовки ответов в `outline-wire::xhttp`

**Files:**
- Modify: `crates/outline-wire/src/xhttp.rs`
- Modify: `crates/outline-wire/src/tests/xhttp.rs`
- Delete: `bins/outline-server/src/server/transport/xhttp/padding.rs`
- Modify: `bins/outline-server/src/server/transport/xhttp/mod.rs`
- Modify: `bins/outline-server/src/server/transport/xhttp/handlers.rs`
- Modify: `bins/outline-server/src/server/transport/xhttp/h3.rs`

**Interfaces:**
- Produces:
  - `outline_wire::xhttp::{PADDING_MIN_LEN, PADDING_MAX_LEN, generate_padding_header, masquerade_response_headers, post_response_headers, header_flag_enabled}`

- [ ] **Step 1: Добавить тесты в `crates/outline-wire/src/tests/xhttp.rs`**

```rust
#[test]
fn generate_padding_header_respects_bounds_and_alphabet() {
    let mut rng = rand::rng();
    for _ in 0..64 {
        let (name, value) = generate_padding_header(&mut rng);
        assert_eq!(name.as_str(), PADDING_HEADER);
        let s = value.to_str().unwrap();
        assert!(
            (PADDING_MIN_LEN..=PADDING_MAX_LEN).contains(&s.len()),
            "unexpected X-Padding length {}",
            s.len()
        );
        assert!(s.bytes().all(|b| SESSION_ID_ALPHABET.contains(&b)));
    }
}

#[test]
fn response_header_sets_and_flag_helper() {
    assert_eq!(masquerade_response_headers().len(), 4);
    assert_eq!(post_response_headers().len(), 2);
    let mut map = http::HeaderMap::new();
    assert!(!header_flag_enabled(&map, UDP_RECORDS_HEADER));
    map.insert(UDP_RECORDS_HEADER, http::HeaderValue::from_static(" 1 "));
    assert!(header_flag_enabled(&map, UDP_RECORDS_HEADER));
}
```

- [ ] **Step 2: Запустить тест и убедиться, что он падает до реализации**

Run: `cargo test -p outline-wire generate_padding_header`
Expected: FAIL (`cannot find function generate_padding_header`).

- [ ] **Step 3: Реализовать функции в `crates/outline-wire/src/xhttp.rs` и удалить серверный `xhttp/padding.rs`**

В `crates/outline-wire/src/xhttp.rs` добавить:

```rust
use http::{HeaderMap, HeaderName, HeaderValue};
use rand::{Rng, RngExt};

pub const PADDING_MIN_LEN: usize = 100;
pub const PADDING_MAX_LEN: usize = 1024;

/// Builds an `x-padding` header with a random alphanumeric value in
/// [`PADDING_MIN_LEN..=PADDING_MAX_LEN`].
pub fn generate_padding_header<R: Rng + ?Sized>(rng: &mut R) -> (HeaderName, HeaderValue) {
    let len = rng.random_range(PADDING_MIN_LEN..=PADDING_MAX_LEN);
    let mut raw = vec![0u8; len];
    rng.fill_bytes(&mut raw);
    for byte in &mut raw {
        *byte = SESSION_ID_ALPHABET[(*byte as usize) % SESSION_ID_ALPHABET.len()];
    }
    let value = HeaderValue::from_bytes(&raw)
        .expect("SESSION_ID_ALPHABET contains only visible ASCII header bytes");
    (HeaderName::from_static(PADDING_HEADER), value)
}

/// Static browser-streamed SSE masquerade headers for XHTTP GET responses.
pub fn masquerade_response_headers() -> [(HeaderName, HeaderValue); 4] {
    [
        (
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/event-stream"),
        ),
        (
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("no-store, no-cache, must-revalidate"),
        ),
        (HeaderName::from_static("pragma"), HeaderValue::from_static("no-cache")),
        (HeaderName::from_static("x-accel-buffering"), HeaderValue::from_static("no")),
    ]
}

/// Static headers for a 200 POST upload response.
pub fn post_response_headers() -> [(HeaderName, HeaderValue); 2] {
    [
        (
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/octet-stream"),
        ),
        (HeaderName::from_static("cache-control"), HeaderValue::from_static("no-store")),
    ]
}

/// Checks whether `name` in `headers` equals `"1"` (after ASCII whitespace trimming).
pub fn header_flag_enabled(headers: &HeaderMap, name: &str) -> bool {
    crate::resume::header_is_one(headers, name)
}
```

Удалить `bins/outline-server/src/server/transport/xhttp/padding.rs`.
В `bins/outline-server/src/server/transport/xhttp/mod.rs` удалить `mod padding;` и реэкспортировать `masquerade_response_headers` / `post_response_headers` из `outline_wire::xhttp`, а также добавить однострочный хелпер `pub(in crate::server) fn generate_padding_header() -> (axum::http::HeaderName, axum::http::HeaderValue) { outline_wire::xhttp::generate_padding_header(&mut rand::rng()) }`.
В `bins/outline-server/src/server/transport/xhttp/handlers.rs` (3 вызова) и `bins/outline-server/src/server/transport/xhttp/h3.rs` (3 вызова) упростить `if let Some((name, value)) = generate_padding_header() { headers.insert(name, value); }` до:
```rust
let (name, value) = generate_padding_header();
headers.insert(name, value);
```

- [ ] **Step 4: Прогнать тесты, линтер, очистить `target/debug` и закоммитить**

Run:
```bash
cargo fmt --check -p outline-wire -p outline-server && \
cargo clippy -p outline-wire -p outline-server --all-targets --no-deps -- -D warnings && \
cargo test -p outline-wire -p outline-server && \
rm -rf target/debug
```
Expected: PASS (exit code 0).

Commit:
```bash
git add -A crates/outline-wire bins/outline-server
git commit -m "refactor(wire): move XHTTP padding and response header helpers to outline-wire"
```

---

### Task 5: H2 record cap и datagram padding в `outline_wire::padding_frames` + финальный CI-гейт

**Files:**
- Modify: `crates/outline-wire/src/padding_frames.rs`
- Modify: `crates/outline-wire/src/tests/padding_frames.rs`
- Modify: `crates/outline-transport/src/carrier_padding.rs`
- Modify: `bins/outline-server/src/server/transport/carrier_padding.rs`

**Interfaces:**
- Produces:
  - `outline_wire::padding_frames::{H2_WS_SERVER_HEADER_LEN, H2_WS_CLIENT_HEADER_LEN, h2_record_payload_cap, h2_capped_messages, try_frame_datagram_into, try_frame_datagram}`

- [ ] **Step 1: Добавить тесты в `crates/outline-wire/src/tests/padding_frames.rs`**

```rust
#[test]
fn h2_record_payload_cap_accounts_for_ws_header_padding_and_overhead() {
    assert_eq!(
        h2_record_payload_cap(H2_WS_CLIENT_HEADER_LEN, PaddingScheme::disabled(), 0),
        Some(16375 - 8),
    );
    assert_eq!(
        h2_record_payload_cap(H2_WS_SERVER_HEADER_LEN, PaddingScheme::new(0, 256), 34),
        Some(16375 - 4 - 4 - 256 - 34),
    );
    assert_eq!(
        h2_record_payload_cap(H2_WS_CLIENT_HEADER_LEN, PaddingScheme::new(0, 16_000), 0),
        None,
    );
}

#[test]
fn h2_capped_messages_cuts_evenly_and_round_trips() {
    use crate::padding::PaddingDecoder;

    let scheme = PaddingScheme::new(0, 128);
    let cap = h2_record_payload_cap(H2_WS_CLIENT_HEADER_LEN, scheme, 0).unwrap();
    let payload = bytes::Bytes::from(vec![0x5A; cap * 2 + 17]);
    let msgs = h2_capped_messages(scheme, Some(cap), payload.clone(), &mut rand::rng());
    assert_eq!(msgs.len(), 3);
    let mut decoder = PaddingDecoder::new();
    let mut out = Vec::new();
    for m in msgs {
        assert!(m.len() + H2_WS_CLIENT_HEADER_LEN <= H2_DATA_PAYLOAD_MAX);
        decoder.feed(&m, &mut out).unwrap();
    }
    assert_eq!(out, payload.as_ref());
}

#[test]
fn try_frame_datagram_respects_room_budget() {
    let scheme = PaddingScheme::new(16, 64);
    let record = bytes::Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(try_frame_datagram(scheme, &record, 11, &mut rand::rng()).is_none());
    let framed = try_frame_datagram(scheme, &record, 24, &mut rand::rng()).unwrap();
    assert!(framed.len() <= 24);
}
```

- [ ] **Step 2: Запустить тест и убедиться, что он падает до реализации**

Run: `cargo test -p outline-wire h2_record_payload_cap`
Expected: FAIL (`cannot find function h2_record_payload_cap`).

- [ ] **Step 3: Реализовать хелперы в `crates/outline-wire/src/padding_frames.rs` и упростить оба `carrier_padding.rs`**

В `crates/outline-wire/src/padding_frames.rs` добавить:

```rust
use bytes::Bytes;

use crate::padding::{PADDING_FRAME_HEADER_LEN, datagram_pad_budget};

/// WebSocket header in front of a server→client binary message of 126..=65535 B (no mask).
pub const H2_WS_SERVER_HEADER_LEN: usize = 4;

/// WebSocket header in front of a client→server binary message of 126..=65535 B (with 4 B mask).
pub const H2_WS_CLIENT_HEADER_LEN: usize = 8;

/// Maximum data bytes per message on an HTTP/2 carrier so WS header + largest
/// padding + `inner_overhead` + data fit in a single `H2_DATA_PAYLOAD_MAX` TLS record.
pub fn h2_record_payload_cap(
    ws_header_len: usize,
    scheme: PaddingScheme,
    inner_overhead: usize,
) -> Option<usize> {
    let padding = if scheme.is_enabled() {
        PADDING_FRAME_HEADER_LEN + usize::from(scheme.max_pad())
    } else {
        0
    };
    H2_DATA_PAYLOAD_MAX
        .checked_sub(ws_header_len + padding + inner_overhead)
        .filter(|cap| *cap >= MIN_H2_PLAINTEXT_CAP)
}

/// Cuts `frame` into even pieces of at most `cap` bytes (when `cap` is `Some`
/// and `frame.len() > cap`), framing each piece under `scheme` when enabled or
/// returning zero-copy `Bytes` slices when disabled.
pub fn h2_capped_messages<R: Rng + ?Sized>(
    scheme: PaddingScheme,
    cap: Option<usize>,
    mut frame: Bytes,
    rng: &mut R,
) -> Vec<Bytes> {
    let frame_one = |piece: Bytes, rng: &mut R| -> Bytes {
        if scheme.is_enabled() {
            let mut out = Vec::with_capacity(piece.len() + 8);
            frame_payload_into(scheme, &piece, rng, &mut out);
            Bytes::from(out)
        } else {
            piece
        }
    };
    match cap {
        Some(c) if frame.len() > c => even_piece_lens(frame.len(), c)
            .map(|len| frame_one(frame.split_to(len), rng))
            .collect(),
        _ => vec![frame_one(frame, rng)],
    }
}

/// Appends one padded datagram frame into `out` when `data` fits `room`
/// (capping pad to the remaining room). Returns `false` without modifying `out`
/// when `data` cannot fit as a padded datagram.
pub fn try_frame_datagram_into<R: Rng + ?Sized>(
    scheme: PaddingScheme,
    data: &[u8],
    room: usize,
    rng: &mut R,
    out: &mut Vec<u8>,
) -> bool {
    let Some(budget) = datagram_pad_budget(room, data.len()) else {
        return false;
    };
    let mut pad = vec![0u8; scheme.pad_len_capped(rng.random::<u16>(), budget) as usize];
    rng.fill_bytes(&mut pad);
    encode_frame_into(out, data, &pad).expect("datagram-sized segments cannot overflow u16");
    true
}

/// Frames one datagram payload to fit within `room` bytes, returning zero-copy
/// `record.clone()` when `scheme` is disabled and `record.len() <= room`.
pub fn try_frame_datagram<R: Rng + ?Sized>(
    scheme: PaddingScheme,
    record: &Bytes,
    room: usize,
    rng: &mut R,
) -> Option<Bytes> {
    if !scheme.is_enabled() {
        return (record.len() <= room).then(|| record.clone());
    }
    let budget = datagram_pad_budget(room, record.len())?;
    let mut out = Vec::with_capacity(PADDING_FRAME_HEADER_LEN + record.len() + usize::from(budget));
    try_frame_datagram_into(scheme, record, room, rng, &mut out).then(|| Bytes::from(out))
}
```

Обновить потребителей:
1. В `bins/outline-server/src/server/transport/carrier_padding.rs`:
   - `pub(in crate::server) use outline_wire::padding_frames::H2_WS_SERVER_HEADER_LEN as H2_WS_HEADER_LEN;`
   - `frame_datagram_message(scheme, record, room)` -> `outline_wire::padding_frames::try_frame_datagram(scheme, record, room, &mut rand::rng())`
   - `h2_plaintext_cap(protocol, scheme, inner_overhead)` -> `matches!(protocol, Protocol::Http2 | Protocol::XhttpH2).then(|| outline_wire::padding_frames::h2_record_payload_cap(H2_WS_HEADER_LEN, scheme, inner_overhead)).flatten()`
   - `capped_downlink_messages(protocol, scheme, bytes)` -> `outline_wire::padding_frames::h2_capped_messages(scheme, h2_plaintext_cap(protocol, scheme, 0), bytes, &mut rand::rng())`
2. В `crates/outline-transport/src/carrier_padding.rs`:
   - `pub(crate) use outline_wire::padding_frames::H2_WS_CLIENT_HEADER_LEN;`
   - `frame_datagram_into(scheme, data, room, rng, out)`:
     ```rust
     pub(crate) fn frame_datagram_into<R: Rng>(
         scheme: PaddingScheme,
         data: &[u8],
         room: Option<usize>,
         rng: &mut R,
         out: &mut Vec<u8>,
     ) {
         if let Some(room) = room
             && outline_wire::padding_frames::try_frame_datagram_into(scheme, data, room, rng, out)
         {
             return;
         }
         frame_payload_into(scheme, data, rng, out);
     }
     ```
   - `h2_uplink_cap(scheme)` -> `outline_wire::padding_frames::h2_record_payload_cap(H2_WS_CLIENT_HEADER_LEN, scheme, 0)`
   - `h2_capped_messages(scheme, cap, frame, rng)` -> `outline_wire::padding_frames::h2_capped_messages(scheme, Some(cap), frame, rng)`

- [ ] **Step 4: Прогнать полный локальный CI-гейт монорепо (включая `e2e_*` и `android/rust`) и очистить `target/debug`**

Run:
```bash
cargo fmt --check -p outline-server -p outline-client -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto && \
cargo clippy --workspace --exclude sockudo-ws --exclude outline-windows --all-targets --no-deps -- -D warnings && \
cargo test --workspace --exclude sockudo-ws --exclude outline-windows && \
RUN_E2E_FAILOVER=1 cargo test -p outline-client --features test-tls --test 'e2e_*' -- --test-threads=1 && \
(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings) && \
rm -rf target/debug
```
Expected: PASS (все шаги возвращают exit code 0).

- [ ] **Step 5: Закоммитить**

```bash
git add crates/outline-wire/src/padding_frames.rs crates/outline-wire/src/tests/padding_frames.rs crates/outline-transport/src/carrier_padding.rs bins/outline-server/src/server/transport/carrier_padding.rs
git commit -m "refactor(wire): share H2 record cap and datagram padding framing"
```
