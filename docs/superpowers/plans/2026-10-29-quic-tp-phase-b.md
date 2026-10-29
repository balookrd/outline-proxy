# Фаза B: оставшиеся transport parameters браузера — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Набор и значения QUIC transport parameters в Initial H3-клиента совпадают с замером Chrome 156 (Chromium-профиль) и Apple Network.framework (Safari-профиль) во всём, что можно сделать без изменения поведения протокола; единственный сознательный остаток — `active_connection_id_limit = 64` у Safari.

**Architecture:** Расширяем уже существующий патч `vendor/quinn-proto` (0.11.15) пятью опциями `TransportConfig` с upstream-дефолтами (сервер не меняется): отключение `min_ack_delay`, GREASE-параметра, объявления `max_idle_timeout` и `max_udp_payload_size`; точное объявленное `max_datagram_frame_size`; `version_information` с GREASE-версией; список дополнительных статических параметров. Дополнительные параметры пишутся в случайные позиции общего перемешанного порядка, как у Chrome. Клиент выставляет опции через модуль-врата `crates/outline-transport/src/quic/vendored.rs` по таблице профиля `QuicTpProfile`.

**Tech Stack:** Rust 2024, quinn 0.11.9, vendored quinn-proto 0.11.15, tshark 4.6 для проверки на проводе.

**Предыстория:** фаза A — `a3854e5f` (браузерные TP на публичном API quinn); окна — `d5bed81c` (vendor) и `c35b4d1a` (патч `initial_stream_receive_window`). Замер браузеров — таблица в `docs/superpowers/plans/2026-10-29-quic-tp-browser-shaping.md`, раздел «Исходные данные».

## Global Constraints

- Комментарии в коде, commit-сообщения и PR — на английском; план и чат — на русском.
- Никогда не добавлять трейлер `Co-Authored-By: Claude` и футер «Generated with Claude Code».
- Коммит — только по явной команде владельца; **никогда не `git push`** без отдельной команды. Работать в `main`, веток не создавать.
- Тесты наших крейтов — в `tests/` рядом с модулем; inline `mod tests {}` запрещены. `vendor/quinn-proto` — upstream-стиль, не форматировать и не линтовать.
- Гейт (из `AGENTS.md`, ровно эти команды):
  ```bash
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
    -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
    -p outline-tun -p outline-uplink -p outline-wire \
    -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  cargo test --workspace --exclude sockudo-ws
  (cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)
  ```
- **Никогда `cargo fmt --all`**; format-only diff в `vendor/` откатывать.
- Каждая новая опция патча обязана иметь дефолт, сохраняющий поведение upstream: серверный `outline-ss-rust` собирается с этим же vendored крейтом.
- Production-код обращается к патч-API quinn-proto только через `crates/outline-transport/src/quic/vendored.rs` (CI-инвариант расширяется на новые имена).
- `PATCHES.md` / `PATCHES.ru.md` и `CHANGELOG.md` / `CHANGELOG.ru.md` обновляются парой; патч-артефакт `quinn-proto-0.11.15.patch` перегенерируется тем же способом, что в прошлый раз, и проверяется round-trip'ом (`patch -p1` к чистому crates.io 0.11.15 → `diff -r` пусто).
- Выкатка — только по команде владельца, по одному узлу (`ops/deploy/deploy-binary.sh`).

## Целевое состояние Initial

| TP (id) | Chrome 156 | Chromium-профиль после плана | Apple | Safari-профиль после плана |
|---|---|---|---|---|
| `max_idle_timeout` (0x01) | 30000 | 30000 | не шлёт | **не шлёт**, локально 30 с |
| `max_udp_payload_size` (0x03) | 1472 | 1472 | не шлёт | **не шлёт** |
| 0x04–0x09 | как в фазе A | без изменений | как в фазе A | без изменений |
| `active_connection_id_limit` (0x0e) | не шлёт | не шлёт | 64 | **не шлёт — остаток** |
| SCID (0x0f) | длина 0 | длина 0 | длина 0 | длина 0 |
| `version_information` (0x11) | `1; перестановка {1, GREASE}` | **так же**, GREASE-версия случайная на соединение | не шлёт | не шлёт |
| `max_datagram_frame_size` (0x20) | 65536 | **65536** | не шлёт | не шлёт |
| `google_connection_options` (0x3128) | `ORIG` | **`ORIG`** | не шлёт | не шлёт |
| `min_ack_delay` (0xff04de1b) | не шлёт | **не шлёт** | не шлёт | **не шлёт** |
| GREASE-параметр | шлёт | шлёт | не шлёт | **не шлёт** |
| `0xff080808` | — | — | `09` | **`09`** |
| Порядок | случайный | случайный, включая доп. параметры | — | случайный |

## Решения

1. **`active_connection_id_limit = 64` у Safari не делаем.** Клиентская очередь remote CID в quinn — `CidQueue::LEN = 5`, а наш сервер выдаёт `min(лимит клиента, LOC_CID_COUNT = 8)` CID. Объявив 64, клиент получит 8 CID и упадёт с `CONNECTION_ID_LIMIT_ERROR` (`connection/mod.rs` ~2914–2922). Расширить очередь нельзя без изменения поведения сервера: тот же `CidQueue::LEN` определяет и его собственный объявляемый лимит. Остаток документируем.
2. **Отключение `min_ack_delay` безопасно.** Параметр объявляет поддержку ACK_FREQUENCY от пира. Наш сервер ACK_FREQUENCY не шлёт; реальные браузеры его не объявляют.
3. **`max_datagram_frame_size = 65536` у Chromium** требует включить приём датаграмм (`datagram_receive_buffer_size(Some(65536))`). H3-слой клиента не объявляет `SETTINGS_H3_DATAGRAM`, поэтому сервер датаграммы не шлёт — поведение не меняется; буфер выделяется только под реально пришедшие датаграммы.
4. **Не объявлять `max_udp_payload_size` у Safari** — значит разрешить пиру слать UDP-датаграммы до 65527 байт. Наш сервер ограничен своим MTU discovery (верхняя граница 1452 или `[server.h3].initial_mtu`), поэтому крупнее не пришлёт. Локальный размер приёма клиента не меняется. Альтернатива через `EndpointConfig::max_udp_payload_size(65527)` отвергнута: она раздувает приёмные буферы каждого per-dial endpoint (память на Android, см. память `xhttp-h3-carrier-pool`).
5. **`version_information` генерируется патчем, а не задаётся статикой:** GREASE-версия (вида `0x?a?a?a?a`, RFC 9368 §7) и порядок `other_versions` у Chrome меняются на каждое соединение (три захвата — три разных значения).
6. **Firefox** не входит: замер требует установки Firefox (Task 5 фазы A, отдельное согласие владельца).

## File Structure

| Файл | Что меняется |
|---|---|
| `vendor/quinn-proto/src/config/transport.rs` | 7 новых опций `TransportConfig` (поля, `Default`, `Debug`, сеттеры) |
| `vendor/quinn-proto/src/transport_parameters.rs` | `new()` учитывает опции; `extras` + позиции; `write()` вплетает доп. параметры; генерация `version_information` |
| `quinn-proto-0.11.15.patch` | перегенерирован |
| `PATCHES.md`, `PATCHES.ru.md` | п. 2 «browser-shaped transport parameters» в разделе quinn-proto |
| `crates/outline-transport/src/quic/vendored.rs` | функции-врата для новых опций |
| `crates/outline-transport/src/quic/tp_profile.rs` | новые поля `QuicTpProfile`, значения CHROMIUM / SAFARI |
| `crates/outline-transport/src/quic/tls_config.rs` | `build_h3_transport` применяет новые поля через врата |
| `crates/outline-transport/src/quic/tests/tls_config.rs` | точные wire-тесты наборов, значений, случайности; тест локального idle Safari |
| `crates/outline-transport/src/quic/tests/tp_profile.rs` | тест таблиц профилей |
| `.github/workflows/ci.yml` | инвариант охватывает новые имена API |
| `bins/outline-ws-rust/CHANGELOG.md`, `CHANGELOG.ru.md` | запись в `[Unreleased]` |

---

### Task 1: Расширение патча quinn-proto

**Files:**
- Modify: `vendor/quinn-proto/src/config/transport.rs`, `vendor/quinn-proto/src/transport_parameters.rs`
- Modify: `quinn-proto-0.11.15.patch`, `PATCHES.md`, `PATCHES.ru.md`

**Interfaces (Produces, все на `quinn::TransportConfig`, каждая возвращает `&mut Self`):**
- `advertise_min_ack_delay(bool)` — default `true`
- `send_grease_transport_parameter(bool)` — default `true`
- `advertise_max_idle_timeout(bool)` — default `true`
- `advertise_max_udp_payload_size(bool)` — default `true`
- `advertised_max_datagram_frame_size(Option<VarInt>)` — default `None`
- `send_version_information(bool)` — default `false`
- `extra_transport_parameters(Vec<(VarInt, Vec<u8>)>)` — default пустой

- [ ] **Step 1: Поля в `TransportConfig`** (рядом с `initial_stream_receive_window`, в том же стиле):

```rust
    pub(crate) advertise_min_ack_delay: bool,
    pub(crate) send_grease_transport_parameter: bool,
    pub(crate) advertise_max_idle_timeout: bool,
    pub(crate) advertise_max_udp_payload_size: bool,
    pub(crate) advertised_max_datagram_frame_size: Option<VarInt>,
    pub(crate) send_version_information: bool,
    pub(crate) extra_transport_parameters: Vec<(VarInt, Vec<u8>)>,
```

`Default`: `true, true, true, true, None, false, Vec::new()`. `Debug`: добавить все семь в деструктуризацию `let Self { .. } = self;` и `.field(..)`. `TransportConfig` не `Copy` (у него нет `#[derive]` с `Copy`), так что `Vec` в нём допустим.

- [ ] **Step 2: Сеттеры** (после `initial_stream_receive_window`):

```rust
    /// Whether to advertise `min_ack_delay` (draft-ietf-quic-ack-frequency). Advertising
    /// it invites the peer to send ACK_FREQUENCY frames. Defaults to `true`.
    pub fn advertise_min_ack_delay(&mut self, value: bool) -> &mut Self {
        self.advertise_min_ack_delay = value;
        self
    }

    /// Whether to include a randomly generated reserved (GREASE) transport parameter.
    /// Defaults to `true`.
    pub fn send_grease_transport_parameter(&mut self, value: bool) -> &mut Self {
        self.send_grease_transport_parameter = value;
        self
    }

    /// Whether to advertise `max_idle_timeout`. When `false` the parameter is omitted (the
    /// peer sees no limit) while `max_idle_timeout` still bounds the connection locally.
    /// Defaults to `true`.
    pub fn advertise_max_idle_timeout(&mut self, value: bool) -> &mut Self {
        self.advertise_max_idle_timeout = value;
        self
    }

    /// Whether to advertise the endpoint's `max_udp_payload_size`. When `false` the
    /// parameter is omitted (protocol default 65527). Defaults to `true`.
    pub fn advertise_max_udp_payload_size(&mut self, value: bool) -> &mut Self {
        self.advertise_max_udp_payload_size = value;
        self
    }

    /// Exact `max_datagram_frame_size` to advertise. Takes effect only while datagrams are
    /// enabled (`datagram_receive_buffer_size` is `Some`); `None` (the default) advertises the
    /// receive buffer size capped at 65535, as upstream does.
    pub fn advertised_max_datagram_frame_size(&mut self, value: Option<VarInt>) -> &mut Self {
        self.advertised_max_datagram_frame_size = value;
        self
    }

    /// Whether to send `version_information` (RFC 9368) with QUIC v1 as the chosen version
    /// and `other_versions` = a random permutation of {v1, a GREASE version}, regenerated per
    /// connection. Defaults to `false`.
    pub fn send_version_information(&mut self, value: bool) -> &mut Self {
        self.send_version_information = value;
        self
    }

    /// Additional transport parameters written verbatim at random positions among the others.
    /// Ids must not collide with parameters quinn writes itself. Defaults to none.
    pub fn extra_transport_parameters(&mut self, value: Vec<(VarInt, Vec<u8>)>) -> &mut Self {
        self.extra_transport_parameters = value;
        self
    }
```

- [ ] **Step 3: `TransportParameters` — новые поля** внутри макроса `make_struct` рядом с `grease_transport_parameter` (документированы так же, как соседи).

`TransportParameters` объявлен `#[derive(Debug, Copy, Clone, Eq, PartialEq)]` (`transport_parameters.rs:70`), и крейт полагается на `Copy`. Поэтому `Vec` в нём не используем — дополнительные параметры хранятся в массиве фиксированного размера, по образцу `ReservedTransportParameter` (фиксированный буфер + длина):

```rust
/// One extra transport parameter written verbatim (outgoing only, never decoded).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct ExtraTransportParameter {
    id: VarInt,
    len: u8,
    value: [u8; ExtraTransportParameter::MAX_LEN],
    /// Index in `write_order` before which it is written (`SUPPORTED.len()` = after all).
    slot: u8,
}

impl ExtraTransportParameter {
    /// Longest value the client needs: `version_information` with two other versions.
    pub(crate) const MAX_LEN: usize = 16;
    /// `version_information` plus up to two static parameters.
    pub(crate) const MAX_COUNT: usize = 3;
}
```

Поле в `TransportParameters`:

```rust
            /// Extra parameters written as-is at random positions; outgoing only.
            pub(crate) extras: [Option<ExtraTransportParameter>; ExtraTransportParameter::MAX_COUNT],
```

В `TransportParameters::default()` — `extras: [None; ExtraTransportParameter::MAX_COUNT],`.

В `TransportConfig` (не `Copy`) список остаётся `Vec<(VarInt, Vec<u8>)>`; сеттер `extra_transport_parameters` проверяет ограничения и паникует с понятным сообщением, если их нарушить (это ошибка конфигурации на стороне вызывающего кода, а не входные данные):

```rust
        assert!(
            value.len() < ExtraTransportParameter::MAX_COUNT,
            "at most {} extra transport parameters (one slot is reserved for version_information)",
            ExtraTransportParameter::MAX_COUNT - 1
        );
        assert!(
            value.iter().all(|(_, v)| v.len() <= ExtraTransportParameter::MAX_LEN),
            "extra transport parameter value longer than {} bytes",
            ExtraTransportParameter::MAX_LEN
        );
```

(`ExtraTransportParameter` сделать видимым из `config/transport.rs` через `crate::transport_parameters::ExtraTransportParameter`.)

- [ ] **Step 4: `TransportParameters::new` учитывает опции**

```rust
            max_udp_payload_size: if config.advertise_max_udp_payload_size {
                endpoint_config.max_udp_payload_size
            } else {
                // The protocol default is never written, so the parameter is omitted.
                VarInt::from_u32(65527)
            },
            max_idle_timeout: if config.advertise_max_idle_timeout {
                config.max_idle_timeout.unwrap_or(VarInt(0))
            } else {
                VarInt(0)
            },
            max_datagram_frame_size: config.datagram_receive_buffer_size.map(|x| {
                config
                    .advertised_max_datagram_frame_size
                    .unwrap_or_else(|| (x.min(u16::MAX.into()) as u16).into())
            }),
            min_ack_delay: config.advertise_min_ack_delay.then(|| {
                VarInt::from_u64(u64::try_from(TIMER_GRANULARITY.as_micros()).unwrap()).unwrap()
            }),
            grease_transport_parameter: config
                .send_grease_transport_parameter
                .then(|| ReservedTransportParameter::random(rng)),
```

(`65527` — значение по умолчанию `max_udp_payload_size` из макроса `apply_params!`, `transport_parameters.rs:40`.)

Переписать `new` так, чтобы `Self { .. }` собирался в `let mut params`, затем заполнить `extras` и вернуть `params`:

```rust
        let mut next = 0;
        let mut push = |params: &mut Self, id: VarInt, value: &[u8], rng: &mut _| {
            let mut buf = [0u8; ExtraTransportParameter::MAX_LEN];
            buf[..value.len()].copy_from_slice(value);
            params.extras[next] = Some(ExtraTransportParameter {
                id,
                len: value.len() as u8,
                value: buf,
                slot: rng.random_range(0..=TransportParameterId::SUPPORTED.len() as u8),
            });
            next += 1;
        };
        for (id, value) in &config.extra_transport_parameters {
            push(&mut params, *id, value, rng);
        }
        if config.send_version_information {
            push(&mut params, VarInt::from_u32(0x11), &version_information(rng), rng);
        }
        params
```

(Если замыкание с `rng: &mut _` не выводится компилятором — вынести в приватную функцию `fn push_extra(params: &mut Self, next: &mut usize, id: VarInt, value: &[u8], rng: &mut impl RngCore)`.) `write_order` по-прежнему перемешивается тем же `shuffle(rng)`.

Функция рядом с `ReservedTransportParameter`:

```rust
/// `version_information` (RFC 9368 §3) offering QUIC v1 plus one reserved GREASE version
/// (RFC 9368 §7: `0x?a?a?a?a`), in random order.
fn version_information(rng: &mut impl RngCore) -> Vec<u8> {
    const V1: u32 = 0x0000_0001;
    let grease = (rng.next_u32() & 0xf0f0_f0f0) | 0x0a0a_0a0a;
    let others = if rng.random::<bool>() { [V1, grease] } else { [grease, V1] };
    let mut value = Vec::with_capacity(12);
    value.extend_from_slice(&V1.to_be_bytes());
    for v in others {
        value.extend_from_slice(&v.to_be_bytes());
    }
    value
}
```

(`use rand::{Rng as _, RngCore, ..}` уже есть в `transport_parameters.rs:15`.)

- [ ] **Step 5: `write()` вплетает доп. параметры** — в начале цикла по `write_order` (позиция `pos`, 0-based) перед записью штатного параметра записать все `extras[i]` с `extra_slots[i] == pos`; после цикла — все с `extra_slots[i] == SUPPORTED.len()`:

```rust
    fn write_extras_at<W: BufMut>(&self, w: &mut W, pos: u8) {
        for extra in self.extras.iter().flatten() {
            if extra.slot == pos {
                w.write_var(extra.id.0);
                w.write_var(u64::from(extra.len));
                w.put_slice(&extra.value[..usize::from(extra.len)]);
            }
        }
    }
```

Цикл `for idx in ...` превратить в `for (pos, idx) in ....iter().enumerate()` с вызовом `self.write_extras_at(w, pos as u8);` первой строкой тела и `self.write_extras_at(w, TransportParameterId::SUPPORTED.len() as u8);` после цикла. При пустых `extras` поведение побайтово прежнее.

- [ ] **Step 6: Проверить, что локальные значения не читаются из собственных TP**

Run: `grep -n "max_udp_payload_size\|max_idle_timeout\|min_ack_delay\|max_datagram_frame_size" vendor/quinn-proto/src/connection/*.rs vendor/quinn-proto/src/connection/**/*.rs vendor/quinn-proto/src/endpoint.rs`
Expected: локальная логика берёт `self.config.*` / `endpoint_config.*`, а из `TransportParameters` читаются только параметры **пира** (`peer_params`, `params` в `set_peer_params`). Если где-то читаются собственные исходящие TP — описать в отчёте и остановиться (BLOCKED).

- [ ] **Step 7: Нейтральность и сборка**

Run: `cargo check --workspace --exclude sockudo-ws`, `(cd android/rust && cargo check)`, `cargo test -p outline-ss-rust`, `cargo test -p outline-transport --features h3 quic::`
Expected: всё зелёное; wire-тесты фазы A не меняются (новые опции ещё не вызываются).

- [ ] **Step 8: Патч-артефакт и документация**
  - Перегенерировать `quinn-proto-0.11.15.patch` (тот же формат заголовков, что сейчас), round-trip в scratchpad-каталоге сессии: `patch -p1` к чистой копии crates.io 0.11.15 → `diff -r src` и `Cargo.toml` пусто.
  - `PATCHES.md` / `PATCHES.ru.md`, раздел quinn-proto, новый пункт (RU; EN — тот же смысл):

```markdown
2. **browser-shaped-transport-parameters** (`src/config/transport.rs`,
   `src/transport_parameters.rs`) — опции `TransportConfig`, нужные H3-клиенту,
   чтобы transport parameters в Initial совпадали с браузером:
   `advertise_min_ack_delay`, `send_grease_transport_parameter`,
   `advertise_max_idle_timeout` (локальный idle продолжает действовать),
   `advertise_max_udp_payload_size`, `advertised_max_datagram_frame_size`,
   `send_version_information` (RFC 9368: v1 + GREASE-версия, перестановка на
   соединение) и `extra_transport_parameters` (сырые `(id, value)`, вплетаются в
   случайные позиции общего перемешанного порядка). Дефолты повторяют upstream;
   сервер их не трогает.
```

  Нумерацию следующего пункта (vendoring-trim) сдвинуть.

- [ ] **Step 9: Полный гейт.** Commit (по команде владельца): `build(vendor): add browser-shaping transport parameter options to quinn-proto`.

### Task 2: Профили и врата

**Files:**
- Modify: `crates/outline-transport/src/quic/vendored.rs`, `quic/tp_profile.rs`, `quic/tls_config.rs`
- Modify: `crates/outline-transport/src/quic/tests/tls_config.rs`, `quic/tests/tp_profile.rs`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: опции из Task 1.
- Produces:
  - врата: `pub(crate) fn apply_browser_tp_options(transport: &mut quinn::TransportConfig, opts: &BrowserTpOptions)`
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub(crate) struct BrowserTpOptions { pub(crate) advertise_min_ack_delay: bool, pub(crate) grease_parameter: bool, pub(crate) advertise_idle_timeout: bool, pub(crate) advertise_max_udp_payload_size: bool, pub(crate) datagram_frame_size: Option<u32>, pub(crate) version_information: bool, pub(crate) extra_parameters: &'static [(u64, &'static [u8])] }` (в `vendored.rs`)
  - `QuicTpProfile` получает поле `pub(crate) options: BrowserTpOptions`

- [ ] **Step 1: Врата** (`quic/vendored.rs`, дописать к существующей функции):

```rust
/// Transport-parameter knobs from the patched quinn-proto that shape the Initial like a
/// browser. See `tp_profile` for the measured values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BrowserTpOptions {
    pub(crate) advertise_min_ack_delay: bool,
    pub(crate) grease_parameter: bool,
    pub(crate) advertise_idle_timeout: bool,
    pub(crate) advertise_max_udp_payload_size: bool,
    /// Exact `max_datagram_frame_size`; `Some` also enables datagram receive.
    pub(crate) datagram_frame_size: Option<u32>,
    pub(crate) version_information: bool,
    pub(crate) extra_parameters: &'static [(u64, &'static [u8])],
}

pub(crate) fn apply_browser_tp_options(
    transport: &mut quinn::TransportConfig,
    opts: &BrowserTpOptions,
) {
    transport
        .advertise_min_ack_delay(opts.advertise_min_ack_delay)
        .send_grease_transport_parameter(opts.grease_parameter)
        .advertise_max_idle_timeout(opts.advertise_idle_timeout)
        .advertise_max_udp_payload_size(opts.advertise_max_udp_payload_size)
        .send_version_information(opts.version_information)
        .extra_transport_parameters(
            opts.extra_parameters
                .iter()
                .map(|(id, value)| (quinn::VarInt::from_u64(*id).expect("TP id fits a varint"), value.to_vec()))
                .collect(),
        );
    match opts.datagram_frame_size {
        Some(size) => {
            transport
                .datagram_receive_buffer_size(Some(size as usize))
                .advertised_max_datagram_frame_size(Some(quinn::VarInt::from_u32(size)));
        },
        None => {
            transport.datagram_receive_buffer_size(None);
        },
    }
}
```

- [ ] **Step 2: Таблицы профилей** (`tp_profile.rs`): поле `options: BrowserTpOptions` с doc-комментарием; значения:

```rust
// CHROMIUM
    options: BrowserTpOptions {
        advertise_min_ack_delay: false,
        grease_parameter: true,
        advertise_idle_timeout: true,
        advertise_max_udp_payload_size: true,
        datagram_frame_size: Some(65_536),
        version_information: true,
        // google_connection_options = "ORIG"
        extra_parameters: &[(0x3128, b"ORIG")],
    },
// SAFARI
    options: BrowserTpOptions {
        advertise_min_ack_delay: false,
        grease_parameter: false,
        // Apple omits it; the 30 s `idle_timeout` above still applies locally.
        advertise_idle_timeout: false,
        advertise_max_udp_payload_size: false,
        datagram_frame_size: None,
        version_information: false,
        // Apple's private parameter, value 0x09 as captured on macOS 27.
        extra_parameters: &[(0xff08_0808, &[0x09])],
    },
```

Обновить doc-комментарии констант: что теперь совпадает и что остаётся (`active_connection_id_limit = 64` у Safari — с причиной из «Решения 1»).

- [ ] **Step 3: Применить в `build_h3_transport`** (`tls_config.rs`): после выставления окон и лимитов потоков вызвать `super::vendored::apply_browser_tp_options(&mut transport, &tp.options);` и **удалить** прежнюю строку `transport.datagram_receive_buffer_size(None);` с комментарием про 65535 — теперь датаграммы решает профиль.

- [ ] **Step 4: Wire-тесты точных наборов** (`tests/tls_config.rs`): ужесточить `h3_chromium_transport_params_match_chrome` и `h3_safari_transport_params_match_apple`:

```rust
// Chromium: exact Chrome 156 set (GREASE ids filtered out separately)
assert_eq!(
    ids,
    BTreeSet::from([0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0f, 0x11, 0x20, 0x3128]),
);
assert!(tp.iter().any(|(id, _)| is_grease_tp(*id)), "Chrome sends a GREASE parameter");
assert_eq!(int(0x20), 65_536, "max_datagram_frame_size");
assert_eq!(tp_value(&tp, 0x3128), Some(&b"ORIG"[..]), "google_connection_options");
let vi = tp_value(&tp, 0x11).expect("version_information");
assert_eq!(vi.len(), 12);
assert_eq!(&vi[..4], &[0, 0, 0, 1], "chosen version v1");
let others = [u32::from_be_bytes(vi[4..8].try_into().unwrap()), u32::from_be_bytes(vi[8..12].try_into().unwrap())];
assert!(others.contains(&1), "v1 among other_versions");
assert!(others.iter().any(|v| *v & 0x0f0f_0f0f == 0x0a0a_0a0a), "GREASE version among other_versions");

// Safari: exact Apple set minus 0x0e (documented residual)
assert_eq!(ids, BTreeSet::from([0x04, 0x05, 0x06, 0x07, 0x09, 0x0f, 0xff08_0808]));
assert!(!tp.iter().any(|(id, _)| is_grease_tp(*id)), "Apple sends no GREASE parameter");
assert_eq!(tp_value(&tp, 0xff08_0808), Some(&[0x09][..]));
```

Существующий тест `h3_config_carries_fingerprint_without_datagram_param` противоречит новой цели (0x20 теперь есть у Chromium): переименовать в `h3_safari_config_has_no_datagram_param`, перевести на Safari-профиль, обновить doc-комментарий.

- [ ] **Step 5: Тест случайности** — 16 захватов Chromium-ClientHello; проверить, что (а) позиция `0x3128` в списке id не одна и та же во всех захватах, (б) GREASE-версия в `0x11` различается хотя бы между двумя захватами:

```rust
#[tokio::test]
async fn chromium_extras_and_grease_version_vary_per_connection() {
    use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};
    use std::collections::BTreeSet;

    let mut positions = BTreeSet::new();
    let mut grease_versions = BTreeSet::new();
    for _ in 0..16 {
        let ch = with_dial_fingerprint(Some(TlsFingerprint::Chromium), async {
            capture_clienthello(super::h3_quic_client_config(), super::h3_endpoint_config())
        })
        .await;
        let tp = transport_params_from_clienthello(&ch);
        positions.insert(tp.iter().position(|(id, _)| *id == 0x3128).unwrap());
        let vi = tp_value(&tp, 0x11).unwrap();
        for chunk in vi[4..].chunks(4) {
            let v = u32::from_be_bytes(chunk.try_into().unwrap());
            if v != 1 {
                grease_versions.insert(v);
            }
        }
    }
    assert!(positions.len() > 1, "extra parameter always at the same position");
    assert!(grease_versions.len() > 1, "GREASE version never changes");
}
```

(`capture_clienthello` использует фиксированный rng-seed эндпоинта; если из-за этого все 16 захватов одинаковы — передавать в `capture_clienthello` разный seed на итерацию, расширив хелпер параметром `seed: [u8; 32]`, и обновить существующие вызовы на прежний `[0x11; 32]`.)

- [ ] **Step 6: Тест локального idle без объявления** (`tests/tls_config.rs`, на `loopback::Loopback`): клиентский транспорт `max_idle_timeout(500 ms)`, `advertise_max_idle_timeout(false)` через `apply_browser_tp_options(&mut t, &SAFARI.options)`, без keep-alive; сервер без keep-alive. После `connect` ничего не слать; `tokio::time::timeout(5 s, conn.closed())` → `ConnectionError::TimedOut`, и закрылось не раньше 400 мс. Контроль не нужен: проверяется ровно «локальный idle работает, хотя не объявлен».

- [ ] **Step 7: CI-инвариант** — в шаге quinn-proto расширить шаблон grep на новые имена: `'initial_stream_receive_window\|advertise_min_ack_delay\|send_grease_transport_parameter\|advertise_max_idle_timeout\|advertise_max_udp_payload_size\|advertised_max_datagram_frame_size\|send_version_information\|extra_transport_parameters'`; локально — пусто.

- [ ] **Step 8: Прогон**: `cargo test -p outline-transport --features h3 quic::` (все PASS; новые тесты 5× подряд с `--test-threads=1`), e2e `RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls --test e2e_tls_carriers tls_ws_h3_ss_dial_works -- --nocapture --test-threads=1` (клиент с 0x11/0x20/0x3128 договаривается с нашим сервером), полный гейт. Commit (по команде владельца): `feat(transport): align remaining H3 transport parameters with Chrome and Safari`.

### Task 3: CHANGELOG и проверка на проводе

**Files:** `bins/outline-ws-rust/CHANGELOG.md`, `bins/outline-ws-rust/CHANGELOG.ru.md`

- [ ] **Step 1: CHANGELOG EN/RU** — в `[Unreleased]`, в записи про browser-shaped transport parameters, заменить список «not yet aligned» на фактический остаток (EN; RU — тот же смысл):

```markdown
Chromium-profile dials now also send Chrome's `version_information` (v1 plus a per-connection GREASE version), `max_datagram_frame_size = 65536` and `google_connection_options`, and no `min_ack_delay`; Safari-profile dials omit `max_idle_timeout` (the 30 s timer still applies locally), `max_udp_payload_size`, the GREASE parameter and `min_ack_delay`, and send Apple's private `0xff080808`. The only remaining transport-parameter difference is Apple's `active_connection_id_limit = 64`, which quinn's 5-entry connection-id queue cannot accept from our 8-CID server. The TLS ClientHello inside the same Initial still identifies rustls.
```

- [ ] **Step 2: Проверка на проводе** — `cargo build --release -p outline-ws-rust`, `scripts/quic-initial-sink.py`, конфиг как в прошлых планах (`tcp_ws_url = "wss://127.0.0.1:4433/x/tcp"`, `tcp_mode = "h3"`, `fingerprint_profile = "random"`), прогоны до Chromium- и Safari-захвата; `tshark ... -V | grep 'Parameter: ' | sort -u` для каждого. Expected: наборы — ровно колонки «после плана» таблицы «Целевое состояние Initial». Сохранить списки в отчёт; дополнительно снять ещё один свежий захват Chrome тем же способом, что в фазе A (headless Chrome, `--origin-to-force-quic-on=127.0.0.1:4433`), и сравнить побайтово типы и длины параметров.

- [ ] **Step 3: Полный гейт.** Commit (по команде владельца): `docs(ws): document aligned H3 transport parameters`.

---

## Порядок выкатки

Меняется только клиент; новые опции патча на сервере не вызываются. Выкатка по команде владельца через `ops/deploy/deploy-binary.sh`, по одному клиентскому узлу. На каждом проверить: H3-носители поднимаются без роста ошибок handshake (в логах нет `CONNECTION_ID_LIMIT_ERROR`, `TRANSPORT_PARAMETER_ERROR`), доля даунгрейдов `ws_h3 → ws_h2` не выросла. Android и macOS — со следующим релизом.

## Self-review

- Покрытие таблицы «Целевое состояние»: 0x01/0x03/GREASE/min_ack_delay/0x11/0x20/0x3128/0xff080808 — Task 1 (механизм) + Task 2 (значения и тесты); 0x0e — сознательный остаток (Решение 1) в CHANGELOG и doc-комментариях; Firefox — вне плана (Решение 6).
- Сигнатуры: семь опций Task 1 ↔ вызовы во `apply_browser_tp_options` Task 2; `BrowserTpOptions` ↔ поле `QuicTpProfile::options`; тесты используют `SAFARI.options`, `capture_clienthello`, `tp_value`, `varint_value`, `is_grease_tp`, `loopback::Loopback` из прошлых задач.
- Точки остановки: Task 1 Step 6 (собственные TP читаются локально) и Task 2 Step 5 (фиксированный seed) имеют явные указания.
- `TransportParameters` остаётся `Copy`: доп. параметры — фиксированный массив `[Option<ExtraTransportParameter>; 3]` с буфером 16 байт; Chromium использует 2 слота (`0x3128` + `version_information`), Safari — 1 (`0xff080808`).
