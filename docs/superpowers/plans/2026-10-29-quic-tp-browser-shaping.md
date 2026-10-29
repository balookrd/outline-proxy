# Подгонка QUIC transport parameters под браузер — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** QUIC Initial H3-носителя клиента (`ws_h3`, `xhttp_h3`) несёт transport parameters того браузера, под который маскируется dial-профиль (Chromium или Safari), а не узнаваемый набор quinn.

**Architecture:** Новый модуль `crates/outline-transport/src/quic/tp_profile.rs` держит per-family таблицу (`QuicTpProfile`) с замеренными значениями и применяет её в двух местах: к `quinn::TransportConfig` (окна, idle, лимиты потоков) в `h3_quic_client_config()` и к `quinn::EndpointConfig` (нулевая длина SCID, `grease_quic_bit`) в `client_endpoint()`. Оба места уже вызываются внутри fingerprint-scope dial'а и читают `current_dial_fingerprint()`. Фаза A обходится публичным API quinn 0.11; фаза B (опциональная, требует решения владельца) вендорит `quinn-proto` ради параметров, которые quinn выставить не даёт.

**Tech Stack:** Rust 2024, quinn 0.11.9 / quinn-proto 0.11.15, rustls 0.23 (aws-lc-rs), tshark 4.6 для проверки на проводе.

## Global Constraints

- Комментарии в коде, commit-сообщения и PR — на английском; план, чат и рассуждения — на русском.
- Никогда не добавлять трейлер `Co-Authored-By: Claude` и футер «Generated with Claude Code».
- Коммит — только по явной команде владельца; **никогда не `git push`** без отдельной команды. Работать в `main`, веток не создавать.
- Тесты — в `tests/` рядом с модулем: `quic/tp_profile.rs` → `quic/tests/tp_profile.rs`, подключение `#[cfg(test)] #[path = "tests/tp_profile.rs"] mod tests;`. Inline `mod tests {}` запрещены.
- Гейт каждой задачи (из `AGENTS.md`, ровно эти команды):
  ```bash
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
    -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
    -p outline-tun -p outline-uplink -p outline-wire \
    -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  cargo test --workspace --exclude sockudo-ws
  (cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)
  ```
- rustls — только `aws-lc-rs`; новые зависимости с rustls обязаны быть `default-features = false` + `aws_lc_rs`. Проверка: `cargo tree -i 'rustls@0.23' -e features | grep 'rustls feature "ring"'` — пусто.
- Меняется только **клиент**. Серверный `outline-ss-rust` не трогаем: его transport parameters уходят в EncryptedExtensions, их пассивный наблюдатель не видит.
- Сохранить `h3→h2→h1` и `xhttp_h3→h2→h1` fallback и cross-transport resume — задача их не касается.
- EN/RU документация обновляется парой в одном изменении (`CHANGELOG.md` / `CHANGELOG.ru.md`).
- Выкатка на хосты — только по команде владельца, строго по одному узлу (`ops/deploy/deploy-binary.sh`).

---

## Исходные данные (замер 2026-10-29)

Метод: UDP-приёмник на `127.0.0.1:4433` пишет датаграммы в pcap с синтетическими IPv4/UDP-заголовками, tshark расшифровывает Initial (ключи выводятся из DCID). Initial уходит до проверки сертификата, сервер не нужен. Chrome — `--headless=new --origin-to-force-quic-on=127.0.0.1:4433`, 4 прогона; Apple — `URLSession` с `assumesHTTP3Capable` (macOS 27, стек Safari); наш — `outline-ws-rust` с uplink `tcp_mode = "h3"`.

| TP (id) | Chrome 156 | Apple (Safari-стек) | Наш quinn сейчас |
|---|---|---|---|
| `max_idle_timeout` (0x01) | 30000 | **не шлёт** | 28000–35000 (джиттер) |
| `max_udp_payload_size` (0x03) | 1472 | не шлёт | 1472 |
| `initial_max_data` (0x04) | 15728640 | 16777216 | 67108864 |
| `initial_max_stream_data_*` (0x05–0x07) | 6291456 | 2097152 | 8388608 |
| `initial_max_streams_bidi` (0x08) | 100 | не шлёт (0) | 100 |
| `initial_max_streams_uni` (0x09) | 103 | 8 | 100 |
| `active_connection_id_limit` (0x0e) | не шлёт | 64 | 5 |
| `initial_source_connection_id` (0x0f) | длина 0 | длина 0 | длина 8 |
| `version_information` (0x11) | `1; [1, GREASE]`, порядок others случайный | не шлёт | не шлёт |
| `max_datagram_frame_size` (0x20) | 65536 | не шлёт | не шлёт |
| `google_connection_options` (0x3128) | `ORIG` (`4f524947`) | не шлёт | не шлёт |
| `grease_quic_bit` (0x2ab2) | не шлёт | не шлёт | шлёт |
| `min_ack_delay` (0xff04de1b) | не шлёт | не шлёт | шлёт (1000) |
| GREASE-параметр (27+31·N) | шлёт | **не шлёт** | шлёт |
| `0xff080808` (Apple private) | — | `09` | — |
| Порядок параметров | случайный каждый раз | — | случайный каждый раз (quinn) |

Что quinn 0.11 позволяет выставить публичным API (`quinn-proto/src/transport_parameters.rs::TransportParameters::new`):

- **можно:** 0x01, 0x04–0x09 (`TransportConfig`), `grease_quic_bit` (`EndpointConfig::grease_quic_bit`), длина SCID 0 через собственный `ConnectionIdGenerator` (при `cid_len() == 0` quinn не шлёт 0x0e);
- **нельзя без патча:** `min_ack_delay` шлётся всегда; 0x20 обрезается до `u16::MAX` = 65535 (у Chrome 65536); 0x11, 0x3128, `0xff080808` не поддерживаются; GREASE-параметр шлётся всегда; idle нельзя развести «объявленный» vs «локальный».

## Ограничение, о котором надо помнить

TLS-расширения того же ClientHello тоже выдают rustls. Chrome: `GREASE, 10, ALPS(17613), 43, 16, 13, 57, ECH(65037), 45, 27, 51` в случайном порядке; наш: `16, 5, 13, 57, 43, 45, 51, 11, 23, 10, 35` — без GREASE, ECH-GREASE, ALPS и `compress_certificate`, но с `ec_point_formats(11)`, `extended_master_secret(23)`, `session_ticket(35)`. План снимает отличия на уровне QUIC TP, но JA4-подобный отпечаток TLS-части останется отличимым. Подгонка TLS ClientHello — отдельная задача (rustls GREASE/ECH-GREASE/ALPS не умеет), в этот план не входит.

## Принятые решения

1. **Нулевая длина SCID у клиента** (как у Chrome и Apple). Безопасно: каждый H3-dial поднимает свой `quinn::Endpoint` на своём сокете (`client_endpoint`, см. комментарий «per-dial source port»), так что демультиплексировать соединения по CID клиенту не нужно. Сервер по-прежнему выдаёт свои 8-байтные CID, поэтому смена адреса клиента (NAT rebinding) продолжает работать — проверяется тестом в Задаче 3.
2. **Окна берутся из профиля, `[quic]` их переопределяет.** Сейчас `load_quic_config` подставляет 8 MiB / 64 MiB по умолчанию, и отличить «не задано» от «задано» нельзя. Делаем поля `Option<u32>`: не задано — значения браузера; задано — значение оператора (это ломает маскировку, о чём пишем в CHANGELOG). Цена для Chromium: окно соединения 64 → 15 MiB, потока 8 → 6 MiB; при RTT 300 мс это потолок ~50 МБ/с на носитель и ~20 МБ/с на поток, что выше реальных каналов парка.
3. **Idle:** Chromium — ровно 30 с без джиттера (джиттер 28–35 с сам по себе отличает нас от Chrome). Keep-alive PING (8–12 с) остаётся с джиттером: это поведение, а не transport parameter. Safari в фазе A тоже шлёт 30 с: если не слать idle совсем, quinn возьмёт серверные 120 с, и мёртвый путь будет обнаруживаться вчетверо дольше. Отличие от Apple остаётся до фазы B.
4. **Firefox-профиль** (`firefox-152-*`) до замера получает Chromium-таблицу. Firefox на маке не установлен; замер — Задача 5.
5. **`max_datagram_frame_size` в фазе A не включаем:** quinn может послать только 65535, а это само по себе неверное значение. Включение 65536 — в фазе B.
6. **Сгенерированные конфиги переопределяют idle — решает владелец.** `ops/access-keys/ws_toml.py:375-377` и `android/app/src/main/java/com/outline/proxy/ServerProfile.kt:79-81` пишут `[quic] keepalive_secs = 25` и `idle_timeout_secs = 60`. С таким конфигом клиент шлёт `max_idle_timeout = 60000`, а не хромовские 30000, и подгонка idle на этих клиентах не работает. Рекомендация (Task 4b): убрать строку `idle_timeout_secs`, `keepalive_secs = 25` оставить — PING раз в 25 с укладывается в 30 с idle (quinn требует только idle > keep-alive, каждый PING ack-eliciting и сбрасывает таймер с обеих сторон), а частота PING, выбранная ради батареи, не меняется. Риск: запас 5 с — при потере PING его повтор по PTO должен успеть за это время; на мобильной сети с RTT ~300 мс это так. Альтернатива — оставить 60 с и принять отличие.

## File Structure

| Файл | Что меняется |
|---|---|
| `crates/outline-transport/src/quic/tp_profile.rs` | **Новый.** `QuicTpProfile`, константы `CHROMIUM` / `SAFARI`, `for_fingerprint()`, `apply_to_transport()`, `endpoint_config()`, `ZeroLengthCid` |
| `crates/outline-transport/src/quic/tests/tp_profile.rs` | **Новый.** Тесты выбора профиля и NAT-rebinding с нулевым SCID |
| `crates/outline-transport/src/quic/mod.rs` | `mod tp_profile;`, реэкспорт `h3_endpoint_config` |
| `crates/outline-transport/src/quic/tls_config.rs` | `apply_quic_jitter` → `apply_quic_keepalive` (только PING); окна — `Option`-override поверх профиля; `h3_endpoint_config()`; исправлен ошибочный комментарий про 0x20 |
| `crates/outline-transport/src/quic/tests/tls_config.rs` | Парсер TP со значениями; `capture_clienthello` принимает `EndpointConfig`; тесты значений Chromium/Safari |
| `crates/outline-transport/src/h3/shared.rs` | `client_endpoint` берёт `crate::quic::h3_endpoint_config()` вместо `EndpointConfig::default()` |
| `crates/outline-transport/Cargo.toml` | dev-dependency `rcgen` (aws_lc_rs) для rebind-теста |
| `bins/outline-ws-rust/src/config/types.rs`, `config/load/quic.rs`, `src/lib.rs` | `QuicConfig` окна → `Option<u32>`, без дефолтов в загрузчике |
| `bins/outline-ws-rust/CHANGELOG.md`, `CHANGELOG.ru.md` | Запись в `[Unreleased]` |
| `scripts/quic-initial-sink.py` | **Новый.** Приёмник Initial → pcap для повторяемой проверки (Задача 4) |

---

## Фаза A — без вендоринга

### Task 1: Тестовый парсер TP со значениями и ловушка для Chromium

**Files:**
- Modify: `crates/outline-transport/src/quic/tests/tls_config.rs` (хелперы около строки 263, `capture_clienthello` около 302, новый тест в конце)

**Interfaces:**
- Produces (тестовые хелперы, используются в Task 2 и 3):
  - `fn transport_params_from_clienthello(ch: &[u8]) -> Vec<(u64, Vec<u8>)>`
  - `fn varint_value(bytes: &[u8]) -> u64`
  - `fn is_grease_tp(id: u64) -> bool`
  - `fn tp_value(tp: &[(u64, Vec<u8>)], id: u64) -> Option<&[u8]>`
  - `fn capture_clienthello(config: quinn::ClientConfig, endpoint_config: quinn::EndpointConfig) -> Vec<u8>`
- Consumes (появится в Task 2): `super::h3_endpoint_config() -> quinn::EndpointConfig`

- [ ] **Step 1: Добавить хелперы рядом с `transport_param_ids_from_clienthello`**

```rust
/// `(id, raw value)` pairs from the `quic_transport_parameters` extension
/// (0x0039), in wire order.
fn transport_params_from_clienthello(ch: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let data = clienthello_extension(ch, 0x0039)
        .expect("no quic_transport_parameters (0x0039) extension in ClientHello");
    let mut pr = Reader::new(data);
    let mut params = Vec::new();
    while pr.remaining() > 0 {
        let id = pr.varint();
        let len = pr.varint() as usize;
        params.push((id, pr.take(len).to_vec()));
    }
    params
}

/// Decodes a QUIC varint that fills the whole slice (a TP integer value).
fn varint_value(bytes: &[u8]) -> u64 {
    let mut r = Reader::new(bytes);
    let v = r.varint();
    assert_eq!(r.remaining(), 0, "trailing bytes after TP varint");
    v
}

/// RFC 9000 §18.1 reserved ids `31 * N + 27`.
fn is_grease_tp(id: u64) -> bool {
    id >= 27 && (id - 27) % 31 == 0
}

fn tp_value(tp: &[(u64, Vec<u8>)], id: u64) -> Option<&[u8]> {
    tp.iter().find(|(i, _)| *i == id).map(|(_, v)| v.as_slice())
}
```

`Reader::take(&mut self, n) -> &'a [u8]`, `Reader::varint()` и `Reader::remaining()` уже есть в этом файле (строки 27–60).

- [ ] **Step 2: Протянуть `EndpointConfig` в `capture_clienthello`**

```rust
fn capture_clienthello(
    config: quinn::ClientConfig,
    endpoint_config: quinn::EndpointConfig,
) -> Vec<u8> {
    let mut endpoint =
        quinn_proto::Endpoint::new(Arc::new(endpoint_config), None, false, Some([0x11; 32]));
    // ... rest unchanged
```

Существующие вызовы обновить на `capture_clienthello(cfg, quinn::EndpointConfig::default())` — кроме теста в Step 3. `quinn::EndpointConfig` — реэкспорт `quinn_proto::EndpointConfig`, а в `Cargo.lock` одна версия quinn-proto (0.11.15), так что тип совпадает.

- [ ] **Step 3: Написать падающий тест значений Chromium**

```rust
/// Chromium-profile H3 Initial carries Chrome 156's transport parameters
/// (measured 2026-10-29), minus what quinn cannot emit without a patch
/// (0x11, 0x20, 0x3128) and plus `min_ack_delay`, which quinn always sends.
#[tokio::test]
async fn h3_chromium_transport_params_match_chrome() {
    use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};
    use std::collections::BTreeSet;

    let ch = with_dial_fingerprint(Some(TlsFingerprint::Chromium), async {
        capture_clienthello(super::h3_quic_client_config(), super::h3_endpoint_config())
    })
    .await;
    let tp = transport_params_from_clienthello(&ch);

    let ids: BTreeSet<u64> = tp.iter().map(|(id, _)| *id).filter(|id| !is_grease_tp(*id)).collect();
    assert_eq!(
        ids,
        BTreeSet::from([0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0f, 0xff04de1b]),
        "unexpected transport-parameter set"
    );
    assert!(tp.iter().any(|(id, _)| is_grease_tp(*id)), "Chrome sends a GREASE parameter");

    let int = |id| varint_value(tp_value(&tp, id).expect("parameter missing"));
    assert_eq!(int(0x01), 30_000, "max_idle_timeout");
    assert_eq!(int(0x03), 1472, "max_udp_payload_size");
    assert_eq!(int(0x04), 15_728_640, "initial_max_data");
    for id in [0x05, 0x06, 0x07] {
        assert_eq!(int(id), 6_291_456, "initial_max_stream_data {id:#x}");
    }
    assert_eq!(int(0x08), 100, "initial_max_streams_bidi");
    assert_eq!(int(0x09), 103, "initial_max_streams_uni");
    assert_eq!(tp_value(&tp, 0x0f), Some(&[][..]), "zero-length initial_source_connection_id");
}
```

- [ ] **Step 4: Убедиться, что тест не компилируется / падает**

Run: `cargo test -p outline-transport --features h3 h3_chromium_transport_params_match_chrome`
Expected: ошибка компиляции `cannot find function h3_endpoint_config in module super` (функция появится в Task 2).

Commit — вместе с Task 2 (тест без реализации не собирается).

### Task 2: `tp_profile.rs` и подключение к H3-конфигам

**Files:**
- Create: `crates/outline-transport/src/quic/tp_profile.rs`
- Create: `crates/outline-transport/src/quic/tests/tp_profile.rs`
- Modify: `crates/outline-transport/src/quic/mod.rs`
- Modify: `crates/outline-transport/src/quic/tls_config.rs:18-118,120-153`
- Modify: `crates/outline-transport/src/h3/shared.rs:464-478`

**Interfaces:**
- Produces:
  - `pub(crate) struct QuicTpProfile { name, idle_timeout: Duration, receive_window: u32, stream_receive_window: u32, max_bidi_streams: u32, max_uni_streams: u32, zero_length_cid: bool, grease_quic_bit: bool }`
  - `pub(crate) const CHROMIUM: QuicTpProfile`, `pub(crate) const SAFARI: QuicTpProfile`
  - `pub(crate) fn for_fingerprint(fp: Option<TlsFingerprint>) -> &'static QuicTpProfile`
  - `impl QuicTpProfile { pub(crate) fn endpoint_config(&self) -> quinn::EndpointConfig }`
  - `pub(crate) fn h3_endpoint_config() -> quinn::EndpointConfig` (в `tls_config.rs`, реэкспорт из `quic`)
- Consumes: `crate::fingerprint_profile::{TlsFingerprint, current_dial_fingerprint}`

- [ ] **Step 1: Создать `quic/tp_profile.rs`**

```rust
//! Browser-shaped QUIC transport parameters for the H3 carrier.
//!
//! The client's transport parameters ride the Initial packet, whose keys any
//! passive observer derives from the destination connection id, so quinn's
//! defaults (8 MiB / 64 MiB windows, an 8-byte source CID, `grease_quic_bit`,
//! `min_ack_delay`) identify this client regardless of the TLS fingerprint.
//! Each family below mirrors values captured from the real browser
//! (Chrome 156 and Apple's Network.framework on macOS 27, 2026-10-29). Only
//! what quinn's public API can express is set here.

use std::time::Duration;

use crate::fingerprint_profile::TlsFingerprint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuicTpProfile {
    pub(crate) name: &'static str,
    /// `max_idle_timeout` (0x01). quinn uses the same value locally, so it
    /// also bounds how long a silently dead path survives.
    pub(crate) idle_timeout: Duration,
    /// `initial_max_data` (0x04).
    pub(crate) receive_window: u32,
    /// `initial_max_stream_data_{bidi_local,bidi_remote,uni}` (0x05-0x07).
    pub(crate) stream_receive_window: u32,
    /// `initial_max_streams_bidi` (0x08); 0 leaves it unsent.
    pub(crate) max_bidi_streams: u32,
    /// `initial_max_streams_uni` (0x09).
    pub(crate) max_uni_streams: u32,
    /// Zero-length source CID: both browsers send an empty
    /// `initial_source_connection_id` and, as a consequence, no
    /// `active_connection_id_limit`. Safe here because every H3 dial owns its
    /// endpoint and socket, so there is nothing to demultiplex by CID.
    pub(crate) zero_length_cid: bool,
    /// `grease_quic_bit` (0x2ab2) — neither browser sends it.
    pub(crate) grease_quic_bit: bool,
}

/// Chrome 156 (Edge and other Blink clients share the stack).
pub(crate) const CHROMIUM: QuicTpProfile = QuicTpProfile {
    name: "chromium",
    idle_timeout: Duration::from_secs(30),
    receive_window: 15_728_640,
    stream_receive_window: 6_291_456,
    max_bidi_streams: 100,
    max_uni_streams: 103,
    zero_length_cid: true,
    grease_quic_bit: false,
};

/// Apple Network.framework (Safari). Apple omits `max_idle_timeout`; quinn
/// would then fall back to the server's 120 s for dead-path detection, so the
/// 30 s budget stays on the wire until the parameter can be split from the
/// local timer.
pub(crate) const SAFARI: QuicTpProfile = QuicTpProfile {
    name: "safari",
    idle_timeout: Duration::from_secs(30),
    receive_window: 16_777_216,
    stream_receive_window: 2_097_152,
    max_bidi_streams: 0,
    max_uni_streams: 8,
    zero_length_cid: true,
    grease_quic_bit: false,
};

/// Firefox has not been measured yet and shares the Chromium table; with no
/// dial fingerprint the client still looks like the most common browser.
pub(crate) fn for_fingerprint(fp: Option<TlsFingerprint>) -> &'static QuicTpProfile {
    match fp {
        Some(TlsFingerprint::Safari) => &SAFARI,
        Some(TlsFingerprint::Chromium | TlsFingerprint::Firefox) | None => &CHROMIUM,
    }
}

impl QuicTpProfile {
    pub(crate) fn endpoint_config(&self) -> quinn::EndpointConfig {
        let mut config = quinn::EndpointConfig::default();
        config.grease_quic_bit(self.grease_quic_bit);
        if self.zero_length_cid {
            config.cid_generator(|| Box::new(ZeroLengthCid));
        }
        config
    }
}

/// Issues empty connection ids, which quinn treats as "route by remote
/// address" and which keeps `active_connection_id_limit` off the wire.
struct ZeroLengthCid;

impl quinn::ConnectionIdGenerator for ZeroLengthCid {
    fn generate_cid(&mut self) -> quinn::ConnectionId {
        quinn::ConnectionId::new(&[])
    }

    fn cid_len(&self) -> usize {
        0
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

#[cfg(test)]
#[path = "tests/tp_profile.rs"]
mod tests;
```

- [ ] **Step 2: Тест выбора профиля `quic/tests/tp_profile.rs`**

```rust
use super::*;

#[test]
fn safari_fingerprint_gets_safari_table() {
    assert_eq!(for_fingerprint(Some(TlsFingerprint::Safari)), &SAFARI);
}

#[test]
fn chromium_firefox_and_none_share_chromium_table() {
    for fp in [Some(TlsFingerprint::Chromium), Some(TlsFingerprint::Firefox), None] {
        assert_eq!(for_fingerprint(fp), &CHROMIUM, "{fp:?}");
    }
}

#[test]
fn idle_timeout_outlives_keepalive() {
    // Keep-alive PING is jittered over 8..=12 s; idle must stay > 2x that.
    for p in [&CHROMIUM, &SAFARI] {
        assert!(p.idle_timeout > Duration::from_secs(24), "{}", p.name);
    }
}
```

- [ ] **Step 3: Подключить модуль в `quic/mod.rs`**

```rust
mod tp_profile;
pub(crate) use tls_config::h3_endpoint_config;
```

(рядом с существующими `mod tls_config;` и `pub use tls_config::{init_quic_keepalive, init_quic_window_sizes};`)

- [ ] **Step 4: Переписать применение конфига в `tls_config.rs`**

Заменить `apply_quic_jitter` на две функции и подключить профиль:

```rust
/// Keep-alive PING cadence: per-process jitter (8..=12 s) unless configured.
/// PING timing is behaviour, not a transport parameter, so it keeps its
/// jitter even though `max_idle_timeout` now follows the browser profile.
pub(crate) fn apply_quic_keepalive(transport: &mut quinn::TransportConfig) {
    let keepalive = QUIC_CUSTOM_KEEPALIVE
        .get()
        .copied()
        .unwrap_or_else(|| Duration::from_secs(8 + (quic_param_seed() as u64 % 5)));
    transport.keep_alive_interval(Some(keepalive));
}

/// Transport parameters the Initial advertises, taken from the browser
/// profile; `[quic]` overrides (windows, idle) win when the operator set them.
fn apply_tp_profile(transport: &mut quinn::TransportConfig, tp: &super::tp_profile::QuicTpProfile) {
    let idle = QUIC_CUSTOM_IDLE_TIMEOUT.get().copied().unwrap_or(tp.idle_timeout);
    transport.max_idle_timeout(Some(idle.try_into().expect("valid client idle timeout")));
    transport.stream_receive_window(quinn::VarInt::from_u32(
        QUIC_STREAM_RECEIVE_WINDOW.get().copied().unwrap_or(tp.stream_receive_window),
    ));
    transport.receive_window(quinn::VarInt::from_u32(
        QUIC_RECEIVE_WINDOW.get().copied().unwrap_or(tp.receive_window),
    ));
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(tp.max_bidi_streams));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(tp.max_uni_streams));
}
```

`apply_quic_carrier_tuning` оставляет только BBR (окна переехали в `apply_tp_profile`). Удалить `DEFAULT_QUIC_*` константы и функции `quic_stream_receive_window()` / `quic_receive_window()`. В `init_quic_keepalive` оставить запись обоих `OnceLock` как есть. Блок-комментарий «Per-process QUIC transport parameter jitter» переписать: idle теперь из профиля, джиттер только у PING.

В `h3_quic_client_config()`:

```rust
    let tp = super::tp_profile::for_fingerprint(fp);
    let mut transport = quinn::TransportConfig::default();
    apply_quic_keepalive(&mut transport);
    apply_tp_profile(&mut transport, tp);
    apply_quic_carrier_tuning(&mut transport);
    // quinn can only advertise `max_datagram_frame_size` up to 65535 while
    // Chrome sends 65536, so the parameter stays off until it can be sent
    // exactly. (Chrome does send it; Apple does not.)
    transport.datagram_receive_buffer_size(None);
```

Исправить doc-комментарий функции (строки 120–126): убрать утверждение, что браузер не шлёт `max_datagram_frame_size`.

Добавить:

```rust
/// Endpoint config for one H3 dial, matched to the active dial fingerprint
/// like [`h3_quic_client_config`]: zero-length source CID and no
/// `grease_quic_bit`, as browsers send.
pub(crate) fn h3_endpoint_config() -> quinn::EndpointConfig {
    let fp = crate::fingerprint_profile::current_dial_fingerprint();
    super::tp_profile::for_fingerprint(fp).endpoint_config()
}
```

- [ ] **Step 5: Использовать в `h3/shared.rs::client_endpoint`**

```rust
    let endpoint = quinn::Endpoint::new(
        crate::quic::h3_endpoint_config(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
```

Проверить, что оба вызова (`h3/shared.rs:650` и `xhttp/h3_pool.rs:277`) идут внутри того же fingerprint-scope, что и соседний `h3_quic_client_config()`: в обоих местах конфиг клиента берётся в той же функции строкой выше/ниже, значит scope общий.

- [ ] **Step 6: Обновить старый тест `h3_config_carries_fingerprint_without_datagram_param`**

Doc-комментарий: причина отсутствия 0x20 — quinn шлёт максимум 65535 при 65536 у Chrome. Вызов — `capture_clienthello(super::h3_quic_client_config(), super::h3_endpoint_config())`. Ассерты не менять.

- [ ] **Step 7: Тест Safari в `quic/tests/tls_config.rs`**

```rust
/// Safari-profile H3 Initial follows Apple's Network.framework values where
/// quinn allows it (no bidi streams, 8 uni, 16 MiB / 2 MiB windows, empty
/// source CID). Idle and the GREASE parameter still differ until phase B.
#[tokio::test]
async fn h3_safari_transport_params_match_apple() {
    use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};

    let ch = with_dial_fingerprint(Some(TlsFingerprint::Safari), async {
        capture_clienthello(super::h3_quic_client_config(), super::h3_endpoint_config())
    })
    .await;
    let tp = transport_params_from_clienthello(&ch);
    let int = |id| tp_value(&tp, id).map(varint_value);
    assert_eq!(int(0x04), Some(16_777_216), "initial_max_data");
    for id in [0x05, 0x06, 0x07] {
        assert_eq!(int(id), Some(2_097_152), "initial_max_stream_data {id:#x}");
    }
    assert_eq!(int(0x08), None, "initial_max_streams_bidi must be unsent");
    assert_eq!(int(0x09), Some(8), "initial_max_streams_uni");
    assert_eq!(tp_value(&tp, 0x0f), Some(&[][..]), "zero-length initial_source_connection_id");
    assert!(tp_value(&tp, 0x2ab2).is_none(), "no grease_quic_bit");
}
```

- [ ] **Step 8: Прогнать тесты**

Run: `cargo test -p outline-transport --features h3 quic::`
Expected: все тесты `quic::tests::*` и `quic::tp_profile::tests::*` PASS, включая `h3_chromium_transport_params_match_chrome` и `h3_safari_transport_params_match_apple`.

- [ ] **Step 9: Полный гейт** (команды из Global Constraints). Expected: всё зелёное.

- [ ] **Step 10: Commit** (по команде владельца)

```bash
git add crates/outline-transport/src/quic crates/outline-transport/src/h3/shared.rs
git commit -m "feat(transport): shape H3 QUIC transport parameters like the dial's browser"
```

### Task 3: Нулевой SCID переживает смену адреса и работает с нашим сервером

**Files:**
- Modify: `crates/outline-transport/Cargo.toml` (`[dev-dependencies]`)
- Modify: `crates/outline-transport/src/quic/tests/tp_profile.rs`

**Interfaces:**
- Consumes: `CHROMIUM.endpoint_config()`, `crate::quic::h3_quic_client_config` не нужен — тест строит свой rustls-клиент с доверием к самоподписанному сертификату.

- [ ] **Step 1: Добавить dev-dependency**

```toml
# Self-signed cert for the zero-length-CID rebinding test (`quic/tests/tp_profile.rs`).
rcgen = { version = "0.14", default-features = false, features = ["aws_lc_rs"] }
```

Проверить инвариант: `cargo tree -i 'rustls@0.23' -e features | grep 'rustls feature "ring"'` — пусто.

- [ ] **Step 2: Написать тест rebinding**

```rust
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn loopback() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}

/// A client endpoint with zero-length CIDs keeps its connection when its
/// local address changes mid-connection (NAT rebinding): the server still
/// routes by its own 8-byte CID and validates the new path.
#[tokio::test]
async fn zero_length_cid_connection_survives_client_rebind() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
    ));
    let server = quinn::Endpoint::server(server_config, loopback()).unwrap();
    let server_addr = server.local_addr().unwrap();

    let echo = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let msg = recv.read_to_end(64).await.unwrap();
            send.write_all(&msg).await.unwrap();
            send.finish().unwrap();
        }
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_tls =
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
    ));

    let socket = UdpSocket::bind(loopback()).unwrap();
    let client = quinn::Endpoint::new(
        CHROMIUM.endpoint_config(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    let conn = client.connect_with(client_config, server_addr, "localhost").unwrap().await.unwrap();

    async fn roundtrip(conn: &quinn::Connection, msg: &[u8]) -> Vec<u8> {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(msg).await.unwrap();
        send.finish().unwrap();
        recv.read_to_end(64).await.unwrap()
    }

    assert_eq!(roundtrip(&conn, b"before").await, b"before");
    client.rebind(UdpSocket::bind(loopback()).unwrap()).unwrap();
    assert_eq!(roundtrip(&conn, b"after").await, b"after");

    conn.close(0u32.into(), b"done");
    echo.abort();
}
```

- [ ] **Step 3: Прогнать**

Run: `cargo test -p outline-transport --features h3 zero_length_cid_connection_survives_client_rebind`
Expected: PASS. Если FAIL на втором `roundtrip` — значит quinn не мигрирует путь при пустом клиентском CID: остановиться и вернуть решение 1 владельцу (вариант — оставить 8-байтный CID и принять отличие в 0x0e/0x0f).

- [ ] **Step 4: E2E против нашего сервера**

Run: `RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls --test e2e_tls_carriers tls_ws_h3_ss_dial_works -- --nocapture --test-threads=1` (без `--features test-tls` и `RUN_E2E_FAILOVER=1` тест не запускается — 0 tests)
Run: `cargo test -p outline-transport --features h3 xhttp::`
Expected: PASS (клиент с нулевым SCID договаривается с `outline-ss-rust` по `ws_h3`; XHTTP-over-H3 тесты зелёные).

- [ ] **Step 5: Полный гейт**, затем commit (по команде владельца)

```bash
git add crates/outline-transport/Cargo.toml crates/outline-transport/src/quic/tests/tp_profile.rs Cargo.lock
git commit -m "test(transport): zero-length client CID survives rebinding"
```

### Task 4: `[quic]` override, документация, проверка на проводе

**Files:**
- Modify: `bins/outline-ws-rust/src/config/types.rs:141-151`
- Modify: `bins/outline-ws-rust/src/config/load/quic.rs`
- Modify: `bins/outline-ws-rust/src/lib.rs:85-101`
- Modify: `crates/outline-transport/src/quic/tls_config.rs` (`init_quic_window_sizes`)
- Modify: `bins/outline-ws-rust/CHANGELOG.md`, `bins/outline-ws-rust/CHANGELOG.ru.md`
- Create: `scripts/quic-initial-sink.py`

**Interfaces:**
- Produces: `pub fn init_quic_window_sizes(stream: Option<u32>, connection: Option<u32>)`; `QuicConfig { stream_receive_window: Option<u32>, receive_window: Option<u32>, .. }`

- [ ] **Step 1: Окна в `QuicConfig` — `Option<u32>`**

`types.rs`:

```rust
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// Per-stream QUIC receive window in bytes. `None` follows the dial's
    /// browser profile (Chrome 6 MiB, Safari 2 MiB); setting it makes the
    /// Initial differ from that browser.
    pub stream_receive_window: Option<u32>,
    /// Per-connection QUIC receive window in bytes. `None` follows the
    /// browser profile (Chrome 15 MiB, Safari 16 MiB).
    pub receive_window: Option<u32>,
    /// Outbound QUIC PING keepalive interval in seconds (default: jittered 8..=12s).
    pub keepalive_secs: Option<u64>,
    /// QUIC idle timeout in seconds (default: 30 s from the browser profile).
    pub idle_timeout_secs: Option<u64>,
}
```

`load/quic.rs`:

```rust
pub(super) fn load_quic_config(quic: Option<&QuicSection>) -> QuicConfig {
    // Windows and idle default to the dial's browser profile
    // (`outline_transport` quic/tp_profile.rs); explicit values override it.
    QuicConfig {
        stream_receive_window: quic.and_then(|q| q.stream_receive_window),
        receive_window: quic.and_then(|q| q.receive_window),
        keepalive_secs: quic.and_then(|q| q.keepalive_secs),
        idle_timeout_secs: quic.and_then(|q| q.idle_timeout_secs),
    }
}
```

`tls_config.rs`:

```rust
/// Override the browser-profile QUIC receive windows from config. Must be
/// called before the first QUIC/H3 dial; `None` keeps the profile value.
/// First-writer-wins, mirroring [`crate::init_h2_window_sizes`].
pub fn init_quic_window_sizes(stream: Option<u32>, connection: Option<u32>) {
    if let Some(v) = stream {
        QUIC_STREAM_RECEIVE_WINDOW.get_or_init(|| v);
    }
    if let Some(v) = connection {
        QUIC_RECEIVE_WINDOW.get_or_init(|| v);
    }
}
```

`lib.rs` — вызов не меняется по форме, типы теперь `Option<u32>`.

- [ ] **Step 2: Найти и починить остальных потребителей**

Run: `cargo check --workspace --exclude sockudo-ws --all-targets` и `(cd android/rust && cargo check)`
Expected: ошибки только там, где читали `QuicConfig.*_window` как `u32` (тесты конфига); поправить их ожидания на `None`/`Some(..)`.

- [ ] **Step 3: Тест загрузчика** — `config/load/quic.rs` приватен внутри `load`, поэтому проверяем через полный `load_config`. В `bins/outline-ws-rust/src/config/tests/mod.rs` в существующий тест, который грузит golden `ops/access-keys/golden/expected-ws/both.toml` (около строки 1940, рядом с `assert_eq!(config.quic.keepalive_secs, Some(25));`), добавить:

```rust
    // The generated config sets no QUIC windows, so the dial's browser
    // profile supplies them.
    assert_eq!(config.quic.stream_receive_window, None);
    assert_eq!(config.quic.receive_window, None);
```

Run: `cargo test -p outline-ws-rust config::tests`
Expected: PASS.

- [ ] **Step 4: CHANGELOG EN/RU** — в `[Unreleased]`, раздел `### Changed`:

EN:
```markdown
- HTTP/3 carriers (`ws_h3`, `xhttp_h3`) now send the QUIC transport parameters of the browser the dial fingerprint mimics (Chrome 156 for Chromium/Firefox profiles, Apple Network.framework for Safari): browser receive windows, a fixed 30 s `max_idle_timeout`, browser stream limits, a zero-length source connection id and no `grease_quic_bit`. Previously quinn's defaults (8 MiB / 64 MiB windows, jittered 28–35 s idle, 8-byte CID) made the Initial recognisable. Explicit `[quic] stream_receive_window` / `receive_window` / `idle_timeout_secs` still override the profile, at the cost of that mimicry. `min_ack_delay` and the Chrome-only `version_information` / `google_connection_options` / `max_datagram_frame_size` are not yet aligned.
```

RU:
```markdown
- HTTP/3-носители (`ws_h3`, `xhttp_h3`) шлют transport parameters того браузера, под который маскируется dial-профиль (Chrome 156 для Chromium- и Firefox-профилей, Apple Network.framework для Safari): браузерные окна приёма, фиксированный `max_idle_timeout` 30 с, браузерные лимиты потоков, source connection id нулевой длины и без `grease_quic_bit`. Раньше дефолты quinn (окна 8 MiB / 64 MiB, idle 28–35 с с джиттером, CID 8 байт) делали Initial узнаваемым. Явные `[quic] stream_receive_window` / `receive_window` / `idle_timeout_secs` по-прежнему переопределяют профиль ценой маскировки. `min_ack_delay` и чисто хромовские `version_information` / `google_connection_options` / `max_datagram_frame_size` пока не выровнены.
```

- [ ] **Step 5: Положить скрипт замера** `scripts/quic-initial-sink.py` — содержимое `udp_sink_pcap.py` из замера (приёмник `127.0.0.1:<port>` → pcap `LINKTYPE_RAW` с синтетическими IPv4/UDP-заголовками), плюс docstring с командами:

```text
python3 -I scripts/quic-initial-sink.py 4433 out.pcap 15 &
# Chrome:  "Google Chrome" --headless=new --no-proxy-server --user-data-dir=<tmp> \
#          --origin-to-force-quic-on=127.0.0.1:4433 --dump-dom https://127.0.0.1:4433/
# ours:    outline-ws-rust --config <cfg with tcp_ws_url=wss://127.0.0.1:4433/x, tcp_mode=h3>
tshark -r out.pcap -d udp.port==4433,quic -V | grep 'Parameter: '
```

- [ ] **Step 6: Проверка на проводе**

Собрать `cargo build --release -p outline-ws-rust`, снять Initial скриптом (fingerprint `stable` и несколько перезапусков, чтобы попасть и в Chromium-, и в Safari-профиль; профиль виден в логе `info` при первом dial), сравнить с таблицей «Исходные данные».
Expected для Chromium: набор и значения совпадают с колонкой Chrome, кроме 0x11/0x20/0x3128 (нет) и `min_ack_delay` (есть).

- [ ] **Step 7: Полный гейт**, commit (по команде владельца)

```bash
git add bins/outline-ws-rust crates/outline-transport/src/quic/tls_config.rs scripts/quic-initial-sink.py
git commit -m "feat(ws): let QUIC windows follow the browser profile unless configured"
```

### Task 4b: Убрать `idle_timeout_secs` из генерируемых конфигов (если владелец выбрал рекомендацию из решения 6)

**Files:**
- Modify: `ops/access-keys/ws_toml.py:375-377`
- Modify: `ops/access-keys/golden/expected-ws/*.toml`, `ops/access-keys/golden/expected/*.toml` (везде, где есть `idle_timeout_secs = 60`)
- Modify: `ops/access-keys/test_ws_toml.py` (если проверяет эту строку)
- Modify: `android/app/src/main/java/com/outline/proxy/ServerProfile.kt:79-81`
- Modify: `bins/outline-ws-rust/src/config/tests/mod.rs:1941`

- [ ] **Step 1:** В `ws_toml.py` удалить строку `"idle_timeout_secs = 60",`, оставив `[quic]` с `keepalive_secs = 25`.
- [ ] **Step 2:** В `ServerProfile.kt` удалить `sb.append("idle_timeout_secs = 60\n\n")` и заменить предыдущую строку на `sb.append("keepalive_secs = 25\n\n")`, чтобы сохранить пустую строку перед `[[outline.uplinks]]`.
- [ ] **Step 3:** Перегенерировать golden-файлы тем способом, который описан в `ops/access-keys` (README или docstring `test_ws_toml.py`); проверить `grep -rn idle_timeout_secs ops/access-keys/golden` — пусто.
- [ ] **Step 4:** В Rust-тесте около строки 1941 заменить `assert_eq!(config.quic.idle_timeout_secs, Some(60));` на `assert_eq!(config.quic.idle_timeout_secs, None);`. Учесть `bins/outline-ws-rust/src/lib.rs:91-101`: при заданном только `keepalive_secs` lib.rs сам подставляет `idle = max(keepalive * 2, 60)` = 60 с, то есть override вернётся. Поменять ветку так, чтобы idle задавался только явным `idle_timeout_secs`:

```rust
        if let Some(keepalive) = config.quic.keepalive_secs {
            outline_transport::init_quic_keepalive_interval(Duration::from_secs(keepalive));
        }
        if let Some(idle) = config.quic.idle_timeout_secs {
            outline_transport::init_quic_idle_timeout(Duration::from_secs(idle));
        }
```

а `init_quic_keepalive(keepalive, idle)` в `crates/outline-transport/src/quic/tls_config.rs` разделить на `pub fn init_quic_keepalive_interval(Duration)` и `pub fn init_quic_idle_timeout(Duration)` (каждая пишет свой `OnceLock`), обновив реэкспорты в `quic/mod.rs` и `lib.rs:274`. Профиль гарантирует idle > keep-alive только для дефолтного джиттера; если оператор задал `keepalive_secs ≥ idle`, `init_quic_keepalive_interval` должна логировать `warn!` при первом dial (проверка в `apply_quic_keepalive`: `keepalive >= idle` → `warn!(?keepalive, ?idle, "QUIC keepalive is not shorter than idle timeout")`).
- [ ] **Step 5:** Гейт (включая `python3 -m pytest ops/access-keys` или тот запуск, что описан в `ops/access-keys`), CHANGELOG EN/RU одной строкой: генерируемые клиентские конфиги больше не задают `idle_timeout_secs`. Commit по команде владельца: `fix(access-keys): leave QUIC idle timeout to the browser profile`.

Существующие клиенты с уже выданными конфигами продолжат слать 60000, пока конфиг не перевыпущен или не обновлено Android-приложение.

### Task 5: Замер Firefox

Нужен установленный Firefox — скачивание с mozilla.org требует согласия владельца (имя файла, источник, размер).

- [ ] **Step 1:** Получить согласие и установить Firefox.
- [ ] **Step 2:** Снять Initial: `about:config` → `network.http.http3.enable = true`, затем запуск с `MOZ_LOG`-профилем не нужен — достаточно скрипта из Task 4. Firefox идёт на H3 только после `Alt-Svc`, поэтому вместо `--origin-to-force-quic-on` использовать pref `network.http.http3.alt-svc-mapping-for-testing = 127.0.0.1;h3=:4433` и открыть `https://127.0.0.1:4433/`.
- [ ] **Step 3:** Если значения отличаются от Chromium — добавить `const FIREFOX: QuicTpProfile`, ветку в `for_fingerprint`, тест `h3_firefox_transport_params_match_firefox` по образцу Chromium, строку в CHANGELOG EN/RU. Гейт, commit `feat(transport): add measured Firefox QUIC transport parameters`.

---

## Фаза B — патч quinn-proto (только по решению владельца)

Нужна, чтобы закрыть оставшиеся отличия: `min_ack_delay` (шлётся всегда), `max_datagram_frame_size = 65536` для Chromium, `version_information` и `google_connection_options` для Chromium, `active_connection_id_limit = 64` при нулевом CID, `0xff080808` и отсутствие GREASE-параметра для Safari, отсутствие `max_idle_timeout` в Initial при локальном idle 30 с для Safari.

Цена: третий vendored-крейт (`vendor/quinn-proto`, upstream 0.11.15), его патч-артефакт, разделы в `PATCHES.md` / `PATCHES.ru.md`, модуль-врата и обновление CI-проверки врат. `AGENTS.md` прямо требует причину для новых vendored-копий — решение за владельцем.

### Task 6: Вендоринг quinn-proto с минимальным патчем

**Files:**
- Create: `vendor/quinn-proto/` (копия crates.io 0.11.15), `quinn-proto-0.11.15.patch`
- Modify: корневой `Cargo.toml` (`[patch.crates-io] quinn-proto = { path = "vendor/quinn-proto" }`), `PATCHES.md`, `PATCHES.ru.md`, `AGENTS.md` (раздел «Единый `vendor/`»)
- Create: `crates/outline-transport/src/quic/vendored.rs` (модуль-врата)

Патч (только `src/config/transport.rs` и `src/transport_parameters.rs`), новые поля `TransportConfig` с upstream-дефолтами, сохраняющими поведение:

```rust
    // TransportConfig
    pub(crate) send_min_ack_delay: bool,                       // default true
    pub(crate) send_grease_transport_parameter: bool,          // default true
    pub(crate) advertised_max_datagram_frame_size: Option<VarInt>, // default None = derived from buffer
    pub(crate) advertised_idle_timeout: Option<Option<VarInt>>,     // default None = same as local
    pub(crate) active_connection_id_limit_override: Option<VarInt>, // default None
    pub(crate) extra_transport_parameters: Vec<(VarInt, Bytes)>,    // default empty
```

с сеттерами того же стиля, что у соседей (`pub fn send_min_ack_delay(&mut self, value: bool) -> &mut Self`). `TransportParameters::new` читает их; `write` пишет `extra_transport_parameters` через дополнительный слот в `write_order` (перемешивается вместе с остальными — у Chrome порядок тоже случайный).

- [ ] Шаги: скопировать upstream; убедиться `diff -r` против `~/.cargo/registry/src/*/quinn-proto-0.11.15` пуст; внести патч; тест в `vendor/quinn-proto` на «дефолты не меняют wire» (сериализация `TransportParameters::new` с дефолтным конфигом побайтово равна upstream при фиксированном rng); сгенерировать `.patch`; описать в `PATCHES*.md`; гейт; commit `build(vendor): patch quinn-proto for configurable client transport parameters`.

### Task 7: Использовать патч в профилях

**Files:** `crates/outline-transport/src/quic/tp_profile.rs`, `quic/vendored.rs`, `quic/tests/tls_config.rs`, CHANGELOG EN/RU.

- Chromium: `send_min_ack_delay(false)`; `advertised_max_datagram_frame_size(65536)`; extra `0x11` = `00000001` ‖ перестановка `{00000001, GREASE-версия 0x?a?a?a?a}`; extra `0x3128` = `4f524947`.
- Safari: `send_min_ack_delay(false)`; `send_grease_transport_parameter(false)`; `advertised_idle_timeout(None)` при локальных 30 с; `active_connection_id_limit_override(64)`; extra `0xff080808` = `09`.
- Тесты Chromium/Safari из Task 1–2 ужесточить до точного совпадения набора с колонками замера; тест на случайность GREASE-версии в 0x11 (два захвата — разные значения).
- Гейт, commit `feat(transport): align remaining H3 transport parameters with browsers`.

Включение `max_datagram_frame_size` у Chromium делает `datagram_receive_buffer_size` ненулевым: quinn начнёт принимать DATAGRAM-фреймы. Сервер их сейчас не шлёт, поэтому поведение не меняется; это задел под UDP по H3 DATAGRAM.

---

## Порядок выкатки

Меняется только клиент; серверам ничего делать не нужно (сервер на quinn принимает пустой клиентский CID — подтверждает Task 3 Step 4).

1. После Task 4 — релизная сборка `outline-ws-rust`, выкатка **по команде владельца** через `ops/deploy/deploy-binary.sh` сначала на один клиентский узел (`.102`), затем по одному: `.104`, `cloud1`, `cloud2`.
2. На каждом узле до перехода к следующему: метрики H3-носителя (ошибки dial/handshake, `conn_life`, доля даунгрейдов `ws_h3 → ws_h2`) не хуже, чем до выкатки, на интервале не меньше часа. WARN-всплеск сразу после рестарта — норма.
3. Android и macOS получают изменение со следующим релизом приложений (общий крейт `outline-transport`).
4. Откат — `deploy-binary.sh` восстанавливает предыдущий бинарь из ротируемого бэкапа.

## Self-review

- Покрытие: каждое отличие таблицы либо закрыто задачей (0x01, 0x04–0x09, 0x0f/0x0e, 0x2ab2 — фаза A; 0x11, 0x20, 0x3128, `min_ack_delay`, GREASE, `0xff080808`, idle Safari — фаза B), либо явно вынесено (TLS-расширения — «Ограничение»; Firefox — Task 5).
- Сигнатуры: `capture_clienthello(ClientConfig, EndpointConfig)`, `h3_endpoint_config()`, `for_fingerprint(Option<TlsFingerprint>)`, `init_quic_window_sizes(Option<u32>, Option<u32>)` согласованы между задачами.
- Риск, требующий остановки: Task 3 Step 3 (rebinding с нулевым CID) — при провале решение 1 возвращается владельцу.
- Решение 6 (idle в генерируемых конфигах) блокирует Task 4b; без него подгонка idle на Android-клиентах и клиентах с конфигом из `ops/access-keys` не действует, остальное — действует.
