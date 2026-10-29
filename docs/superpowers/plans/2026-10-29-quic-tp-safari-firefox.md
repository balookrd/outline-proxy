# Порядок Safari и замеренный Firefox — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** QUIC Initial Safari-профиля совпадает с Apple ещё и по порядку параметров и по `active_connection_id_limit = 64`, а Firefox-профиль — с замером Firefox 159 вместо нынешней заглушки «Chromium без 0x3128».

**Architecture:** Ещё один логический патч к `vendor/quinn-proto` (0.11.15) с дефолтами, при которых всё работает как в upstream: режимы порядка transport parameters (перемешанный / фиксированный / циклический сдвиг), объявляемые окна потоков по направлениям, объявляемый `active_connection_id_limit` при любой длине CID и очередь remote CID на 8 записей, форма `version_information`, общий для объявления и ACK-таймера `max_ack_delay`. Профили `SAFARI` и `FIREFOX` в `crates/outline-transport/src/quic/tp_profile.rs` выставляют их через гейт-модуль `quic/vendored.rs`; Firefox получает CID клиента длиной 3 байта.

**Tech Stack:** Rust 2024, quinn 0.11.9, vendored quinn-proto 0.11.15, tshark 4.6, Firefox 159.0 (скачан в scratchpad с согласия владельца).

**Предыстория:** `a3854e5f` (фаза A), `d5bed81c` + `c35b4d1a` (раздельные окна), `55af7072` (фаза B). Замеры — память проекта `quic-transport-params-vs-browsers`.

## Global Constraints

- Комментарии в коде, commit-сообщения и PR — на английском; план и чат — на русском.
- Никогда не добавлять трейлер `Co-Authored-By: Claude` и футер «Generated with Claude Code».
- Коммит — только по явной команде владельца; **никогда не `git push`** без отдельной команды. Работать в `main`, веток не создавать. Исполнители задач НЕ коммитят: результат остаётся в рабочем дереве, ревью идёт по незастейдженному diff.
- Тесты наших крейтов — в `tests/` рядом с модулем; inline `mod tests {}` запрещены. `vendor/quinn-proto` — upstream-стиль, не форматировать и не линтовать; его собственные inline-тесты только чинить до компиляции, если сигнатура поменялась.
- Гейт (ровно эти команды):
  ```bash
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
    -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
    -p outline-tun -p outline-uplink -p outline-wire \
    -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  cargo test --workspace --exclude sockudo-ws
  (cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)
  ```
  Известный посторонний флейк: `outline-tun health_recovery::tun_downlink_traffic_restores_uplink_health_without_probe` — при единственном падении перезапустить и указать оба прогона.
- **Никогда `cargo fmt --all`**; format-only diff в `vendor/` откатывать.
- Каждая новая опция патча — с дефолтом, при котором кодирование TP и поведение на проводе **побайтово как у upstream**, включая порядок расхода rng: серверный `outline-ss-rust` собирается с этим же крейтом и опций не трогает.
- Патч-API в production-коде — только через `crates/outline-transport/src/quic/vendored.rs`; CI-инвариант в `.github/workflows/ci.yml` расширяется на новые имена методов (шаблон `\.name(`). Тестовые модули (`/tests/`) от инварианта освобождены.
- `PATCHES.md` / `PATCHES.ru.md`, `CHANGELOG.md` / `CHANGELOG.ru.md` — парой; `quinn-proto-0.11.15.patch` перегенерировать тем же форматом, round-trip (`patch -p1` к чистому crates.io 0.11.15 → `diff -r` пусто) в новом уникальном каталоге scratchpad. Никаких `rm -rf` с переменными.
- rustls — только aws-lc-rs: любая новая зависимость на quinn/quinn-proto идёт с `default-features = false` и `rustls-aws-lc-rs`.
- Выкатка — только по команде владельца, по одному узлу.

## Замеры

**Apple (macOS 27, URLSession, 4 захвата):** набор `04,05,06,07,09,0e,0f,ff080808`. Порядок — фиксированная последовательность `04,05,06,07,09,0e,0f`, циклически сдвинутая на каждое соединение (наблюдались начала с 04, 04, 09, 0e); `0xff080808` всегда последний. Значения: `active_connection_id_limit = 64` (varint 2 байта `4040`), остальное — как уже в `SAFARI`.

**Firefox 159.0 (3 захвата, `open -n -a Firefox.app --args -headless -no-remote -profile <dir> --origin-to-force-quic-on 127.0.0.1:4433 https://127.0.0.1:4433/`):** порядок **фиксированный** во всех захватах:

| # | id | значение |
|---|---|---|
| 1 | 0x01 `max_idle_timeout` | 30000 (4 байта `80007530`) |
| 2 | 0x04 `initial_max_data` | 25_165_824 |
| 3 | 0x05 `initial_max_stream_data_bidi_local` | 12_582_912 |
| 4 | 0x06 `initial_max_stream_data_bidi_remote` | 1_048_576 |
| 5 | 0x07 `initial_max_stream_data_uni` | 1_048_576 |
| 6 | 0x08 `initial_max_streams_bidi` | 100 |
| 7 | 0x09 `initial_max_streams_uni` | 100 |
| 8 | 0x0b `max_ack_delay` | 20 |
| 9 | 0x0e `active_connection_id_limit` | 8 |
| 10 | 0x0f `initial_source_connection_id` | 3 случайных байта |
| 11 | 0x11 `version_information` | 16 байт: v1, затем `[GREASE, 0x6b3343cf (QUIC v2), 0x00000001]` — меняется только GREASE |
| 12 | 0x1d | пустое значение |
| 13 | 0xff02de1a | `43e8` (varint 1000) — `min_ack_delay` старого драфта, постоянный; tshark ошибочно зовёт его GREASE |
| 14 | 0x20 `max_datagram_frame_size` | 65535 |

Нет: `max_udp_payload_size` (0x03), настоящего GREASE-параметра, `grease_quic_bit`, `min_ack_delay` 0xff04de1b.

## Решения

1. **Порядок — одна опция с тремя режимами** `TransportParameterOrder::{Shuffled, Fixed(ids), Rotated(ids)}`. `Shuffled` — нынешнее поведение и дефолт. В `Fixed`/`Rotated` список задаёт относительный порядок всех id, включая дополнительные; параметры из списка, которых в Initial нет (например, `max_ack_delay` при значении по умолчанию), просто пропускаются. Штатные параметры не из списка пишутся после списка в порядке upstream (`SUPPORTED`), дополнительные не из списка — в самом конце. В `Rotated` сдвигаются только id штатных параметров, дополнительные из списка идут сразу после них (у Safari `0xff080808` всегда последний).
2. **Очередь remote CID — 8 записей, лимит отдельно.** Сейчас `CidQueue::LEN = 5` — это и ёмкость кольцевого буфера, и проверка лимита, и (через `TransportParameters::new`) объявляемое значение. Разводим: буфер `CidQueue::CAPACITY = 8` (= `LOC_CID_COUNT`: больше наш сервер одновременно не выдаёт), проверка — по полю `limit` = объявленное значение, но не больше ёмкости; дефолт — прежние 5 (`CidQueue::LEN` остаётся и означает дефолтный лимит). Сервер по-прежнему объявляет 5 и проверяет по 5 — поведение то же, цена — 3 лишних `Option<CidData>` на соединение. Клиент, объявивший 64 (Safari) или 8 (Firefox), получает от нашего сервера ровно 8 CID (`issue_cids_limit = min(64, 8)`) и все их принимает. Сторонний сервер, выдавший больше 8 CID при объявленных 64, получит `CONNECTION_ID_LIMIT_ERROR` — документируем как ограничение: наш единственный пир — наш сервер.
3. **Окна по направлениям** — `initial_stream_receive_windows(Option<StreamReceiveWindows { bidi_local, bidi_remote, uni }>)`. Начальный кредит потока берётся по его классу: свой bidi → `bidi_local`, чужой bidi → `bidi_remote`, uni (всегда чужой для приёма) → `uni`. Пул освобождённых `Recv` (`free_recv`) делится на три пула по тем же классам: сейчас `Recv` при освобождении переинициализируется кредитом и потом достаётся любому новому потоку, а с разными окнами uni-поток получил бы кредит bidi. Существующий `initial_stream_receive_window` остаётся (Chromium/Safari) и означает «все три одинаковы»; при заданном `initial_stream_receive_windows` побеждает последний. Рабочее окно (`stream_receive_window`) — одно; `RuntimeWindows` берёт `max(рабочее, наибольшее из объявленных)`.
4. **`version_information` — форма, а не флаг.** `send_version_information(bool)` заменяется на `version_information(Option<VersionInformation>)`; `VersionInformation { other_versions: Vec<VersionSlot>, shuffle: bool }`, `VersionSlot::{Version(u32), Grease}`, не больше 3 слотов (16 байт = `ExtraTransportParameter::MAX_LEN`). Chromium: `[Version(1), Grease]`, `shuffle = true` (как сейчас). Firefox: `[Grease, Version(0x6b33_43cf), Version(1)]`, `shuffle = false`. Chosen version всегда v1 — клиент работает только на v1. Наш quinn-сервер `version_information` не разбирает, так что объявленная v2 ни на что не влияет; сервер с совместимым согласованием версий (RFC 9368) мог бы попытаться перейти на v2 — это ограничение Firefox-профиля, документируем в комментарии.
5. **`max_ack_delay`** — опция `max_ack_delay_ms(u32)`: значение и объявляется (0x0b), и задаёт локальный ACK-таймер (`AckFrequencyState::max_ack_delay`); дефолт 25 (= upstream: параметр не пишется, таймер прежний). Объявлять 20, а подтверждать по 25 нельзя: пир считает PTO по нашему значению.
6. **Ограничение на id дополнительных параметров** — запрещаются только id, которые quinn пишет сам (`TransportParameterId::SUPPORTED`, включая 0xff04de1b), и 0x11. Запрет формы `31N+27` снимается: Firefox шлёт 0xff02de1a, а это как раз такая форма. Цена — теоретическая коллизия со случайным GREASE-параметром, если профиль включит и то и другое; Firefox GREASE не шлёт.
7. **CID клиента у Firefox — 3 случайных байта.** Upstream уже умеет: `quinn_proto::RandomConnectionIdGenerator::new(3)`. Им же заменяется наш `ZeroLengthCid` (`RandomConnectionIdGenerator::new(0)` выдаёт пустые CID и не задаёт срок жизни — то же поведение). Профиль получает поле `source_cid_len: usize` вместо `zero_length_cid: bool`. Каждый dial — свой endpoint, так что демультиплексирование не страдает; RFC 9000 допускает CID длины 3.
8. **Зависимость.** Новые публичные типы патча (`TransportParameterOrder`, `StreamReceiveWindows`, `VersionInformation`, `VersionSlot`) и `RandomConnectionIdGenerator` quinn не реэкспортирует, поэтому `outline-transport` получает `quinn-proto` обычной опциональной зависимостью под фичей `quic` (`default-features = false`, `features = ["rustls-aws-lc-rs"]`). Запись в `[dev-dependencies]` остаётся как есть.

## File Structure

| Файл | Что меняется | Задача |
|---|---|---|
| `vendor/quinn-proto/src/config/transport.rs` | типы и опции `transport_parameter_order`, `advertised_active_connection_id_limit`, `version_information` (вместо `send_version_information`), `max_ack_delay_ms`; ослабление assert'а extras | 1 |
| `vendor/quinn-proto/src/config/transport.rs` | `initial_stream_receive_windows`, `advertised_stream_receive_windows()` | 2 |
| `vendor/quinn-proto/src/lib.rs` | реэкспорт новых типов | 1 |
| `vendor/quinn-proto/src/transport_parameters.rs` | порядок по режиму; `active_connection_id_limit`; форма `version_information`; `max_ack_delay` | 1 |
| `vendor/quinn-proto/src/transport_parameters.rs` | окна по направлениям | 2 |
| `vendor/quinn-proto/src/cid_queue.rs` | `CAPACITY = 8`, поле `limit` | 1 |
| `vendor/quinn-proto/src/connection/mod.rs` | лимит очереди CID из конфига; локальный `max_ack_delay` | 1 |
| `vendor/quinn-proto/src/connection/mod.rs`, `connection/streams/{state,mod,recv}.rs` | кредит по классу потока, пулы `free_recv` по классам | 2 |
| `crates/outline-transport/Cargo.toml` | `quinn-proto` под фичей `quic` | 1 |
| `crates/outline-transport/src/quic/vendored.rs` | `TpOrder`, `VersionInfo`, новые поля `BrowserTpOptions`; `set_advertised_stream_receive_windows` | 1, 2 |
| `crates/outline-transport/src/quic/tp_profile.rs` | новые поля с нейтральными значениями (1); `StreamWindows`, `source_cid_len`, `SAFARI`, `FIREFOX` (3) | 1, 3 |
| `crates/outline-transport/src/quic/tls_config.rs` | окна по направлениям в `build_h3_transport`, `RuntimeWindows::current` | 3 |
| `crates/outline-transport/src/quic/tests/{tls_config,tp_profile}.rs` | wire- и loopback-тесты | 1, 2, 3 |
| `.github/workflows/ci.yml` | новые имена в инварианте | 1 |
| `quinn-proto-0.11.15.patch`, `PATCHES.md`, `PATCHES.ru.md`, `AGENTS.md` | пункт 3 «browser-order-and-firefox» | 4 |
| `bins/outline-ws-rust/CHANGELOG.md`, `CHANGELOG.ru.md` | запись в `[Unreleased]` | 4 |

---

### Task 1: Патч quinn-proto — порядок, лимит CID, `version_information`, `max_ack_delay`

**Files:**
- Modify: `vendor/quinn-proto/src/config/transport.rs`, `vendor/quinn-proto/src/lib.rs`, `vendor/quinn-proto/src/transport_parameters.rs`, `vendor/quinn-proto/src/cid_queue.rs`, `vendor/quinn-proto/src/connection/mod.rs`
- Modify: `crates/outline-transport/Cargo.toml`, `crates/outline-transport/src/quic/vendored.rs`, `crates/outline-transport/src/quic/tp_profile.rs` (только новые поля с нейтральными значениями)
- Modify: `.github/workflows/ci.yml`
- Test: `crates/outline-transport/src/quic/tests/tls_config.rs`

**Interfaces:**
- Produces (на `quinn::TransportConfig`, каждая `-> &mut Self`):
  - `transport_parameter_order(TransportParameterOrder)` — default `Shuffled`
  - `advertised_active_connection_id_limit(Option<VarInt>)` — default `None` (прежнее правило: 5 при `cid_len > 0`, не слать при 0)
  - `version_information(Option<VersionInformation>)` — default `None`; **заменяет** `send_version_information(bool)`
  - `max_ack_delay_ms(u32)` — default 25
- Produces (типы, `pub` в `quinn_proto`):
  ```rust
  pub enum TransportParameterOrder { Shuffled, Fixed(Vec<VarInt>), Rotated(Vec<VarInt>) }
  pub enum VersionSlot { Version(u32), Grease }
  pub struct VersionInformation { pub other_versions: Vec<VersionSlot>, pub shuffle: bool }
  ```
- Produces (гейт `quic/vendored.rs`):
  ```rust
  pub(crate) use quinn_proto::VersionSlot;
  pub(crate) enum TpOrder { Shuffled, Fixed(&'static [u64]), Rotated(&'static [u64]) }
  pub(crate) struct VersionInfo { pub(crate) other_versions: &'static [VersionSlot], pub(crate) shuffle: bool }
  // BrowserTpOptions: `version_information: bool` -> `Option<VersionInfo>`, плюс
  //   order: TpOrder, active_connection_id_limit: Option<u32>, max_ack_delay_ms: u32
  ```

- [ ] **Step 1: Failing-тесты.** В `crates/outline-transport/src/quic/tests/tls_config.rs` добавить:

  ```rust
  /// Without any patch option the client Initial keeps upstream's shape: shuffled order,
  /// `active_connection_id_limit = 5` for 8-byte CIDs, no `max_ack_delay`, no
  /// `version_information`.
  #[tokio::test]
  async fn default_transport_keeps_upstream_parameter_shape() {
      let mut orders = std::collections::BTreeSet::new();
      for seed in 1..=8u8 {
          let mut config = super::h3_quic_client_config();
          config.transport_config(Arc::new(quinn::TransportConfig::default()));
          let ch = capture_clienthello(config, quinn::EndpointConfig::default(), [seed; 32]);
          let tp = transport_params_from_clienthello(&ch);
          assert_eq!(tp_value(&tp, 0x0e).map(varint_value), Some(5), "active_connection_id_limit");
          assert!(tp_value(&tp, 0x0b).is_none(), "default max_ack_delay is not written");
          assert!(tp_value(&tp, 0x11).is_none(), "no version_information by default");
          orders.insert(tp.iter().map(|(id, _)| *id).collect::<Vec<_>>());
      }
      assert!(orders.len() > 1, "default order must stay shuffled");
  }

  /// `Fixed` writes the listed ids in order, extras included; `Rotated` rotates only the
  /// ids quinn writes itself and keeps listed extras after them.
  #[tokio::test]
  async fn listed_orders_shape_the_initial() {
      use super::super::vendored::{BrowserTpOptions, TpOrder, apply_browser_tp_options};

      let base = super::super::tp_profile::SAFARI.options;
      let capture = |order: TpOrder, seed: u8| {
          let mut transport = quinn::TransportConfig::default();
          apply_browser_tp_options(&mut transport, &BrowserTpOptions { order, ..base });
          transport.max_concurrent_bidi_streams(0u32.into());
          let mut config = super::h3_quic_client_config();
          config.transport_config(Arc::new(transport));
          let ch = capture_clienthello(
              config,
              super::super::tp_profile::SAFARI.endpoint_config(),
              [seed; 32],
          );
          transport_params_from_clienthello(&ch).iter().map(|(id, _)| *id).collect::<Vec<_>>()
      };

      // 0x0f is listed first, the extra in the middle, 0x04 after it; 0x05..0x07, 0x09
      // are unlisted and follow in upstream order.
      let fixed = capture(TpOrder::Fixed(&[0x0f, 0xff08_0808, 0x04]), 1);
      assert_eq!(fixed, [0x0f, 0xff08_0808, 0x04, 0x05, 0x06, 0x07, 0x09]);

      const SEQ: [u64; 6] = [0x04, 0x05, 0x06, 0x07, 0x09, 0x0f];
      let mut starts = std::collections::BTreeSet::new();
      for seed in 0..16u8 {
          let ids = capture(
              TpOrder::Rotated(&[0x04, 0x05, 0x06, 0x07, 0x09, 0x0f, 0xff08_0808]),
              seed,
          );
          assert_eq!(ids.last(), Some(&0xff08_0808), "listed extra stays after the rotation");
          let start = SEQ.iter().position(|id| *id == ids[0]).expect("starts with a listed id");
          let mut rotated = SEQ;
          rotated.rotate_left(start);
          assert_eq!(ids[..SEQ.len()], rotated, "seed {seed}");
          starts.insert(start);
      }
      assert!(starts.len() > 1, "rotation never moved: {starts:?}");
  }

  /// `version_information` follows the configured slots; `max_ack_delay` is advertised.
  #[tokio::test]
  async fn version_information_form_and_max_ack_delay_are_written() {
      use super::super::vendored::{BrowserTpOptions, VersionInfo, VersionSlot, apply_browser_tp_options};

      let mut transport = quinn::TransportConfig::default();
      apply_browser_tp_options(
          &mut transport,
          &BrowserTpOptions {
              version_information: Some(VersionInfo {
                  other_versions: &[VersionSlot::Grease, VersionSlot::Version(0x6b33_43cf), VersionSlot::Version(1)],
                  shuffle: false,
              }),
              max_ack_delay_ms: 20,
              ..super::super::tp_profile::CHROMIUM.options
          },
      );
      let mut config = super::h3_quic_client_config();
      config.transport_config(Arc::new(transport));
      let ch = capture_clienthello(config, quinn::EndpointConfig::default(), [7; 32]);
      let tp = transport_params_from_clienthello(&ch);
      assert_eq!(tp_value(&tp, 0x0b).map(varint_value), Some(20), "max_ack_delay");
      let vi = tp_value(&tp, 0x11).expect("version_information");
      assert_eq!(vi.len(), 16);
      assert_eq!(&vi[..4], &[0, 0, 0, 1], "chosen version v1");
      let grease = u32::from_be_bytes(vi[4..8].try_into().unwrap());
      assert_eq!(grease & 0x0f0f_0f0f, 0x0a0a_0a0a, "GREASE version first");
      assert_eq!(&vi[8..], &[0x6b, 0x33, 0x43, 0xcf, 0, 0, 0, 1], "v2 then v1");
  }

  /// A client that advertises more CIDs than quinn's old 5-entry queue (64, like Apple)
  /// accepts the 8 our server issues instead of failing with CONNECTION_ID_LIMIT_ERROR.
  #[tokio::test]
  async fn advertised_cid_limit_above_queue_capacity_accepts_server_cids() {
      use super::super::vendored::{BrowserTpOptions, apply_browser_tp_options};

      let lb = loopback::Loopback::new();
      let server = lb.server.clone();
      let echo = tokio::spawn(async move {
          let conn = server.accept().await.unwrap().await.unwrap();
          let (mut send, mut recv) = conn.accept_bi().await.unwrap();
          let msg = recv.read_to_end(64).await.unwrap();
          send.write_all(&msg).await.unwrap();
          send.finish().unwrap();
          conn.closed().await
      });

      let mut transport = quinn::TransportConfig::default();
      apply_browser_tp_options(
          &mut transport,
          &BrowserTpOptions {
              active_connection_id_limit: Some(64),
              ..super::super::tp_profile::CHROMIUM.options
          },
      );
      let (_ep, conn) = lb.connect(quinn::EndpointConfig::default(), transport).await;
      // Give the server time to issue its NEW_CONNECTION_ID frames.
      tokio::time::sleep(std::time::Duration::from_millis(300)).await;
      let (mut send, mut recv) = conn.open_bi().await.unwrap();
      send.write_all(b"ping").await.unwrap();
      send.finish().unwrap();
      assert_eq!(recv.read_to_end(64).await.unwrap(), b"ping");
      assert!(conn.close_reason().is_none(), "{:?}", conn.close_reason());
      assert!(
          conn.stats().frame_rx.new_connection_id >= 7,
          "server issued {} CIDs",
          conn.stats().frame_rx.new_connection_id
      );
      conn.close(0u32.into(), b"done");
      echo.abort();
  }
  ```

  Если `Loopback` не импортирован в этом файле — он уже используется (`loopback::Loopback::new()` в соседних тестах), использовать так же.

- [ ] **Step 2: Убедиться, что тесты не собираются** (`TpOrder`, `VersionInfo`, новых полей ещё нет):
  `cargo test -p outline-transport --features h3 quic::tests::tls_config 2>&1 | tail -5` → ошибки компиляции `cannot find type TpOrder` и т. п.

- [ ] **Step 3: Типы и опции в `vendor/quinn-proto/src/config/transport.rs`.** Поля `TransportConfig` (рядом с полями фазы B): `transport_parameter_order: TransportParameterOrder`, `advertised_active_connection_id_limit: Option<VarInt>`, `version_information: Option<VersionInformation>` (вместо `send_version_information: bool`), `max_ack_delay: VarInt`. Дефолты в `impl Default`: `TransportParameterOrder::Shuffled`, `None`, `None`, `VarInt(25)`. Если у `TransportConfig` ручной `Debug` — дописать новые поля туда же. Типы:

  ```rust
  /// Order in which the client writes its transport parameters.
  #[derive(Debug, Clone, PartialEq, Eq, Default)]
  pub enum TransportParameterOrder {
      /// A random permutation per connection (upstream behaviour).
      #[default]
      Shuffled,
      /// Listed ids in this order; parameters quinn writes that are not listed follow in
      /// upstream order, unlisted extra parameters come last.
      Fixed(Vec<VarInt>),
      /// As `Fixed`, but the listed ids quinn writes itself are rotated to a random start
      /// per connection; listed extra parameters follow them in list order.
      Rotated(Vec<VarInt>),
  }

  /// One entry of `version_information`'s `other_versions`.
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum VersionSlot {
      /// A fixed version.
      Version(u32),
      /// A reserved version (RFC 9368 §7: `0x?a?a?a?a`), drawn per connection.
      Grease,
  }

  /// Shape of the `version_information` transport parameter (RFC 9368).
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub struct VersionInformation {
      /// `other_versions`, 1 to 3 entries.
      pub other_versions: Vec<VersionSlot>,
      /// Permute `other_versions` per connection.
      pub shuffle: bool,
  }
  ```

  Сеттеры (документация в стиле соседних опций; `send_version_information` удалить):

  ```rust
  /// Order of the client's transport parameters. Defaults to
  /// [`TransportParameterOrder::Shuffled`].
  ///
  /// # Panics
  ///
  /// If a `Fixed`/`Rotated` list repeats an id.
  pub fn transport_parameter_order(&mut self, value: TransportParameterOrder) -> &mut Self {
      if let TransportParameterOrder::Fixed(ids) | TransportParameterOrder::Rotated(ids) = &value {
          for (i, id) in ids.iter().enumerate() {
              assert!(!ids[..i].contains(id), "transport parameter id {id} listed twice");
          }
      }
      self.transport_parameter_order = value;
      self
  }

  /// `active_connection_id_limit` to advertise, also sent with zero-length local CIDs.
  /// The remote CID queue holds at most 8 entries whatever is advertised, so a peer that
  /// issues more than 8 active CIDs gets `CONNECTION_ID_LIMIT_ERROR`. `None` (the default)
  /// advertises 5, or nothing with zero-length local CIDs, as upstream does.
  ///
  /// # Panics
  ///
  /// If the value is below 2 (RFC 9000 §18.2).
  pub fn advertised_active_connection_id_limit(&mut self, value: Option<VarInt>) -> &mut Self {
      if let Some(limit) = value {
          assert!(limit.into_inner() >= 2, "active_connection_id_limit must be at least 2");
      }
      self.advertised_active_connection_id_limit = value;
      self
  }

  /// `version_information` (RFC 9368) with QUIC v1 as the chosen version and
  /// `other_versions` shaped by `value`. Defaults to `None` (not sent).
  ///
  /// Client-only: the chosen version is always QUIC v1 (the only version the client uses).
  ///
  /// # Panics
  ///
  /// If `other_versions` is empty or has more than 3 entries.
  pub fn version_information(&mut self, value: Option<VersionInformation>) -> &mut Self {
      if let Some(vi) = &value {
          assert!(
              (1..=3).contains(&vi.other_versions.len()),
              "version_information takes 1 to 3 other versions"
          );
      }
      self.version_information = value;
      self
  }

  /// `max_ack_delay` in milliseconds: advertised to the peer (when not 25, the protocol
  /// default) and used as the local delayed-ACK timer, so the peer's PTO matches how long
  /// we really hold ACKs. Defaults to 25.
  ///
  /// # Panics
  ///
  /// If the value is 2^14 or more (RFC 9000 §18.2).
  pub fn max_ack_delay_ms(&mut self, value: u32) -> &mut Self {
      assert!(value < 1 << 14, "max_ack_delay must be below 2^14 ms");
      self.max_ack_delay = VarInt::from_u32(value);
      self
  }

  pub(crate) fn remote_cid_queue_limit(&self) -> usize {
      self.advertised_active_connection_id_limit.map_or(CidQueue::LEN, |limit| {
          usize::try_from(limit.into_inner()).unwrap_or(usize::MAX).min(CidQueue::CAPACITY)
      })
  }
  ```

  В `extra_transport_parameters` убрать assert формы `31 * N + 27` и упоминание о ней из `# Panics`; ссылки на `send_version_information` в документации заменить на `version_information`.

- [ ] **Step 4: Реэкспорт.** В `vendor/quinn-proto/src/lib.rs` добавить `TransportParameterOrder`, `VersionInformation`, `VersionSlot` в тот же `pub use crate::config::{...}`, где экспортируется `TransportConfig`.

- [ ] **Step 5: `TransportParameters::new` в `vendor/quinn-proto/src/transport_parameters.rs`.**

  ```rust
  active_connection_id_limit: match config.advertised_active_connection_id_limit {
      Some(limit) => limit,
      None if cid_gen.cid_len() == 0 => VarInt::from_u32(2), // i.e. default, i.e. unsent
      None => VarInt::from_u32(CidQueue::LEN as u32),
  },
  max_ack_delay: config.max_ack_delay,
  write_order: Some({
      let mut order = std::array::from_fn(|i| i as u8);
      // Listed orders are laid out below; only the default draws from the rng here.
      if config.transport_parameter_order == TransportParameterOrder::Shuffled {
          order.shuffle(rng);
      }
      order
  }),
  ```

  Хвост функции:

  ```rust
  let mut next = 0;
  for (id, value) in &config.extra_transport_parameters {
      Self::push_extra(&mut params, &mut next, *id, value, rng);
  }
  if let Some(form) = &config.version_information {
      let value = version_information(form, rng);
      Self::push_extra(&mut params, &mut next, VarInt::from_u32(0x11), &value, rng);
  }
  match &config.transport_parameter_order {
      TransportParameterOrder::Shuffled => {}
      TransportParameterOrder::Fixed(ids) => params.apply_listed_order(ids, 0),
      TransportParameterOrder::Rotated(ids) => {
          let known = ids.iter().filter(|id| supported_index(**id).is_some()).count();
          let shift = if known == 0 { 0 } else { rng.random_range(0..known) };
          params.apply_listed_order(ids, shift);
      }
  }
  params
  ```

  Новые функции рядом с `push_extra`:

  ```rust
  /// Lays out `write_order` and the extras' slots so the parameters follow `ids`. The
  /// listed ids quinn writes itself are rotated left by `shift`; in a rotation the listed
  /// extras follow them, otherwise they keep their listed place. Unlisted parameters quinn
  /// writes follow in upstream order; unlisted extras keep the last slot.
  fn apply_listed_order(&mut self, ids: &[VarInt], shift: usize) {
      #[derive(Clone, Copy, PartialEq, Eq)]
      enum Entry {
          Known(u8),
          Extra(VarInt),
      }
      let listed: Vec<Entry> = ids
          .iter()
          .map(|id| match supported_index(*id) {
              Some(i) => Entry::Known(i as u8),
              None => Entry::Extra(*id),
          })
          .collect();
      let mut sequence: Vec<Entry> = if shift == 0 {
          listed
      } else {
          let mut known: Vec<Entry> =
              listed.iter().copied().filter(|e| matches!(e, Entry::Known(_))).collect();
          known.rotate_left(shift);
          known.extend(listed.iter().copied().filter(|e| matches!(e, Entry::Extra(_))));
          known
      };
      for i in 0..TransportParameterId::SUPPORTED.len() as u8 {
          if !sequence.contains(&Entry::Known(i)) {
              sequence.push(Entry::Known(i));
          }
      }

      let mut order = [0u8; TransportParameterId::SUPPORTED.len()];
      let mut written = 0;
      for entry in &sequence {
          match entry {
              Entry::Known(i) => {
                  order[written] = *i;
                  written += 1;
              }
              Entry::Extra(id) => {
                  for extra in self.extras.iter_mut().flatten().filter(|e| e.id == *id) {
                      extra.slot = written as u8;
                  }
              }
          }
      }
      for extra in self.extras.iter_mut().flatten() {
          if !sequence.contains(&Entry::Extra(extra.id)) {
              extra.slot = TransportParameterId::SUPPORTED.len() as u8;
          }
      }
      // Extras sharing a slot are written in array order; sort them by listed position.
      let rank = |id: VarInt| {
          sequence.iter().position(|e| *e == Entry::Extra(id)).unwrap_or(usize::MAX)
      };
      self.extras.sort_by_key(|extra| extra.map_or(usize::MAX, |e| rank(e.id)));
      self.write_order = Some(order);
  }
  ```

  ```rust
  fn supported_index(id: VarInt) -> Option<usize> {
      TransportParameterId::SUPPORTED.iter().position(|known| *known as u64 == id.into_inner())
  }
  ```

  `version_information` — заменить целиком:

  ```rust
  /// `version_information` (RFC 9368 §3): QUIC v1 as the chosen version, then
  /// `other_versions` as configured, GREASE slots drawn per connection
  /// (RFC 9368 §7: `0x?a?a?a?a`).
  fn version_information(form: &VersionInformation, rng: &mut impl RngCore) -> Vec<u8> {
      const V1: u32 = 0x0000_0001;
      let mut others: Vec<u32> = form
          .other_versions
          .iter()
          .map(|slot| match slot {
              VersionSlot::Version(v) => *v,
              VersionSlot::Grease => (rng.next_u32() & 0xf0f0_f0f0) | 0x0a0a_0a0a,
          })
          .collect();
      if form.shuffle {
          others.shuffle(rng);
      }
      let mut value = Vec::with_capacity(4 + 4 * others.len());
      value.extend_from_slice(&V1.to_be_bytes());
      for v in others {
          value.extend_from_slice(&v.to_be_bytes());
      }
      value
  }
  ```

  Комментарий к `ExtraTransportParameter::MAX_LEN` поправить: «`version_information` with three other versions».

- [ ] **Step 6: `vendor/quinn-proto/src/cid_queue.rs`.** Буфер — `[Option<CidData>; Self::CAPACITY]`, новое поле `limit: u64` с комментарием «Most CIDs the peer may have active at once: our advertised limit, capped by `CAPACITY`». `new(cid: ConnectionId, limit: usize)` с `debug_assert!((2..=Self::CAPACITY).contains(&limit))`. В `insert` проверка `index >= self.limit + retired_count`; все `% Self::LEN` и `.min(Self::LEN ...)`, относящиеся к кольцевому буферу, — на `Self::CAPACITY`; диапазон из комментария «CIDs that we haven't yet received» (`orig_offset + Self::LEN`) — на `orig_offset + self.limit`. Константы:

  ```rust
  /// Default `active_connection_id_limit` (upstream's queue length).
  pub(crate) const LEN: usize = 5;
  /// Ring-buffer capacity: the most CIDs our own server ever issues (`LOC_CID_COUNT`).
  pub(crate) const CAPACITY: usize = 8;
  ```

  Upstream inline-тесты файла: `CidQueue::new(cid)` → `CidQueue::new(cid, CidQueue::LEN)`. `MAX_PENDING_RETIRED_CIDS` в `connection/mod.rs` не трогать (остаётся `LEN * 10`).

- [ ] **Step 7: `vendor/quinn-proto/src/connection/mod.rs`.** Перед литералом `Self { ... }` в конструкторе соединения (где `config` ещё не перемещён): `let rem_cid_limit = config.remote_cid_queue_limit();`, затем `rem_cids: CidQueue::new(rem_cid, rem_cid_limit)`. ACK-таймер:

  ```rust
  ack_frequency: {
      let mut state =
          AckFrequencyState::new(get_max_ack_delay(&TransportParameters::default()));
      // Hold ACKs no longer than the max_ack_delay we advertise.
      state.max_ack_delay = Duration::from_millis(config.max_ack_delay.into_inner());
      state
  },
  ```

  При дефолте 25 таймер прежний. `peer_max_ack_delay` не трогать — его выставляют параметры пира.

- [ ] **Step 8: Зависимость.** `crates/outline-transport/Cargo.toml`, `[dependencies]`:

  ```toml
  # Patched-API types (transport-parameter order, version_information) and
  # RandomConnectionIdGenerator, which quinn does not re-export. Same
  # aws-lc-rs-only features as quinn.
  quinn-proto = { version = "0.11", default-features = false, features = ["rustls-aws-lc-rs"], optional = true }
  ```

  и `quic = ["dep:quinn", "dep:quinn-proto", "dep:once_cell", "dep:ring"]`. Запись в `[dev-dependencies]` не трогать. Проверить, что `android/rust/Cargo.lock` обновился сборкой Android-гейта и других версий `quinn-proto` не появилось: `cargo tree -i quinn-proto` в корне и в `android/rust` — одна версия, `0.11.15 (…/vendor/quinn-proto)`.

- [ ] **Step 9: Гейт `crates/outline-transport/src/quic/vendored.rs`.**

  ```rust
  pub(crate) use quinn_proto::VersionSlot;

  /// Order of the client's transport parameters (see `TransportConfig::transport_parameter_order`).
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub(crate) enum TpOrder {
      Shuffled,
      Fixed(&'static [u64]),
      Rotated(&'static [u64]),
  }

  /// `version_information` shape; the chosen version is always QUIC v1.
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub(crate) struct VersionInfo {
      pub(crate) other_versions: &'static [VersionSlot],
      pub(crate) shuffle: bool,
  }
  ```

  В `BrowserTpOptions`: `version_information: Option<VersionInfo>` (вместо `bool`), новые поля

  ```rust
  pub(crate) order: TpOrder,
  /// `active_connection_id_limit`; `None` keeps quinn's rule (5, or unsent with
  /// zero-length CIDs). At most 8 remote CIDs are held whatever is advertised.
  pub(crate) active_connection_id_limit: Option<u32>,
  /// Advertised `max_ack_delay` and the local delayed-ACK timer; 25 is the protocol
  /// default and is not written.
  pub(crate) max_ack_delay_ms: u32,
  ```

  В `apply_browser_tp_options` вместо `.send_version_information(...)`:

  ```rust
  let varints = |ids: &[u64]| -> Vec<quinn::VarInt> {
      ids.iter().map(|id| quinn::VarInt::from_u64(*id).expect("TP id fits a varint")).collect()
  };
  transport
      .transport_parameter_order(match opts.order {
          TpOrder::Shuffled => quinn_proto::TransportParameterOrder::Shuffled,
          TpOrder::Fixed(ids) => quinn_proto::TransportParameterOrder::Fixed(varints(ids)),
          TpOrder::Rotated(ids) => quinn_proto::TransportParameterOrder::Rotated(varints(ids)),
      })
      .version_information(opts.version_information.map(|vi| {
          quinn_proto::VersionInformation {
              other_versions: vi.other_versions.to_vec(),
              shuffle: vi.shuffle,
          }
      }))
      .advertised_active_connection_id_limit(
          opts.active_connection_id_limit.map(quinn::VarInt::from_u32),
      )
      .max_ack_delay_ms(opts.max_ack_delay_ms);
  ```

- [ ] **Step 10: Нейтральные значения в профилях `tp_profile.rs`** (поведение профилей в этой задаче не меняется):
  - `CHROMIUM.options`: `version_information: Some(VersionInfo { other_versions: &[VersionSlot::Version(1), VersionSlot::Grease], shuffle: true })`, `order: TpOrder::Shuffled`, `active_connection_id_limit: None`, `max_ack_delay_ms: 25`.
  - `SAFARI.options`: `version_information: None`, `order: TpOrder::Shuffled`, `active_connection_id_limit: None`, `max_ack_delay_ms: 25`.
  - `FIREFOX` по-прежнему `..CHROMIUM.options` без `0x3128`.

- [ ] **Step 11: CI-инвариант.** В `.github/workflows/ci.yml` в шаблоне `leaked=$(grep -rn '…'` заменить `\.send_version_information(` на `\.version_information(` и добавить `\|\.transport_parameter_order(\|\.advertised_active_connection_id_limit(\|\.max_ack_delay_ms(`. Комментарий над шагом не трогать. Локальная проверка — тот же grep из шага CI:

  ```bash
  grep -rn 'initial_stream_receive_window\|\.advertise_min_ack_delay(\|\.send_grease_transport_parameter(\|\.advertise_max_idle_timeout(\|\.advertise_max_udp_payload_size(\|\.advertised_max_datagram_frame_size(\|\.version_information(\|\.extra_transport_parameters(\|\.transport_parameter_order(\|\.advertised_active_connection_id_limit(\|\.max_ack_delay_ms(' bins/*/src crates/*/src --include='*.rs' | grep -v '/tests/' | grep -v '^crates/outline-transport/src/quic/vendored\.rs:'
  ```
  Expected: пусто.

- [ ] **Step 12: Тесты.** `cargo test -p outline-transport --features h3 quic::` → новые четыре теста и все прежние (`h3_chromium_transport_params_match_chrome`, `chromium_extras_and_grease_version_vary_per_connection`, `h3_safari_transport_params_match_apple`, loopback-тесты окон) — PASS. Если `cargo test` по фильтру не находит модуль из-за имени фичи — посмотреть фичи `outline-transport` в `Cargo.toml` и взять ту, под которой собирается `quic::tests` (как в прошлых задачах).

- [ ] **Step 13: Полный гейт** из Global Constraints → всё зелёное. Не коммитить.

---

### Task 2: Патч quinn-proto — окна потоков по направлениям

**Files:**
- Modify: `vendor/quinn-proto/src/config/transport.rs`, `vendor/quinn-proto/src/lib.rs`, `vendor/quinn-proto/src/transport_parameters.rs`, `vendor/quinn-proto/src/connection/mod.rs`, `vendor/quinn-proto/src/connection/streams/state.rs`, `vendor/quinn-proto/src/connection/streams/mod.rs`, `vendor/quinn-proto/src/connection/streams/recv.rs`
- Modify: `crates/outline-transport/src/quic/vendored.rs`
- Test: `crates/outline-transport/src/quic/tests/tls_config.rs`

**Interfaces:**
- Consumes: Task 1 (гейт, `quinn-proto` в зависимостях).
- Produces:
  - `quinn::TransportConfig::initial_stream_receive_windows(Option<StreamReceiveWindows>) -> &mut Self`, default `None`
  - `pub struct StreamReceiveWindows { pub bidi_local: VarInt, pub bidi_remote: VarInt, pub uni: VarInt }` (`#[derive(Debug, Clone, Copy, PartialEq, Eq)]`, реэкспорт из `quinn_proto`)
  - гейт: `pub(crate) fn set_advertised_stream_receive_windows(transport: &mut quinn::TransportConfig, bidi_local: u32, bidi_remote: u32, uni: u32)`

- [ ] **Step 1: Failing-тесты** в `crates/outline-transport/src/quic/tests/tls_config.rs`:

  ```rust
  #[derive(Debug, Clone, Copy)]
  enum Opened {
      ClientBidi,
      ServerBidi,
      ServerUni,
  }

  /// Bytes the server writes on one stream that the client never reads, within 1 s.
  async fn server_writes_unread(
      lb: &loopback::Loopback,
      transport: quinn::TransportConfig,
      opened: Opened,
  ) -> u64 {
      use std::sync::atomic::{AtomicU64, Ordering};

      let written = Arc::new(AtomicU64::new(0));
      let server_written = Arc::clone(&written);
      let server = lb.server.clone();
      let task = tokio::spawn(async move {
          let conn = server.accept().await.unwrap().await.unwrap();
          let mut send = match opened {
              Opened::ClientBidi => {
                  let (send, mut recv) = conn.accept_bi().await.unwrap();
                  let mut hello = [0u8; 1];
                  recv.read_exact(&mut hello).await.unwrap();
                  send
              },
              Opened::ServerBidi => conn.open_bi().await.unwrap().0,
              Opened::ServerUni => conn.open_uni().await.unwrap(),
          };
          let chunk = vec![0u8; 64 * 1024];
          while send.write_all(&chunk).await.is_ok() {
              server_written.fetch_add(chunk.len() as u64, Ordering::Relaxed);
          }
      });

      let (_ep, conn) = lb.connect(quinn::EndpointConfig::default(), transport).await;
      // Kept alive: dropping a RecvStream sends STOP_SENDING.
      let _client_stream = match opened {
          Opened::ClientBidi => {
              let (mut send, recv) = conn.open_bi().await.unwrap();
              send.write_all(b"h").await.unwrap();
              Some((send, recv))
          },
          Opened::ServerBidi | Opened::ServerUni => None,
      };
      tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
      let total = written.load(Ordering::Relaxed);
      conn.close(0u32.into(), b"done");
      task.abort();
      total
  }

  /// Each new receive stream starts with the credit of its own class.
  #[tokio::test]
  async fn stream_credit_follows_stream_direction() {
      const LOCAL: u32 = 256 << 10;
      const REMOTE: u32 = 1 << 20;
      const UNI: u32 = 2 << 20;
      const SLACK: u64 = 64 << 10;

      let lb = loopback::Loopback::new();
      let transport = || {
          let mut t = quinn::TransportConfig::default();
          t.stream_receive_window(quinn::VarInt::from_u32(UNI));
          t.receive_window(quinn::VarInt::from_u32(64 << 20));
          super::super::vendored::set_advertised_stream_receive_windows(&mut t, LOCAL, REMOTE, UNI);
          t
      };
      for (opened, window) in
          [(Opened::ClientBidi, LOCAL), (Opened::ServerBidi, REMOTE), (Opened::ServerUni, UNI)]
      {
          let written = server_writes_unread(&lb, transport(), opened).await;
          eprintln!("{opened:?}: {written} bytes");
          let window = u64::from(window);
          assert!(
              written + SLACK >= window && written <= window + SLACK,
              "{opened:?} wrote {written}, expected about {window}"
          );
      }
  }

  /// Per-direction windows reach the Initial as three different parameters.
  #[tokio::test]
  async fn per_direction_windows_are_advertised() {
      let mut transport = quinn::TransportConfig::default();
      super::super::vendored::set_advertised_stream_receive_windows(
          &mut transport,
          12_582_912,
          1_048_576,
          524_288,
      );
      let mut config = super::h3_quic_client_config();
      config.transport_config(Arc::new(transport));
      let ch = capture_clienthello(config, quinn::EndpointConfig::default(), [3; 32]);
      let tp = transport_params_from_clienthello(&ch);
      let int = |id| tp_value(&tp, id).map(varint_value);
      assert_eq!(int(0x05), Some(12_582_912), "bidi_local");
      assert_eq!(int(0x06), Some(1_048_576), "bidi_remote");
      assert_eq!(int(0x07), Some(524_288), "uni");
  }
  ```

- [ ] **Step 2: Убедиться, что не собирается** (`set_advertised_stream_receive_windows` нет): `cargo test -p outline-transport --features h3 quic::tests::tls_config 2>&1 | tail -5`.

- [ ] **Step 3: Конфиг `vendor/quinn-proto/src/config/transport.rs`.** Тип рядом с `VersionInformation`:

  ```rust
  /// Per-direction `initial_max_stream_data_*` (RFC 9000 §18.2).
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub struct StreamReceiveWindows {
      /// Receive credit on bidirectional streams we open (0x05).
      pub bidi_local: VarInt,
      /// Receive credit on bidirectional streams the peer opens (0x06).
      pub bidi_remote: VarInt,
      /// Receive credit on unidirectional streams the peer opens (0x07).
      pub uni: VarInt,
  }
  ```

  Поле `initial_stream_receive_windows: Option<StreamReceiveWindows>`, default `None` (и в ручной `Debug`, если он есть). Сеттер и хелпер:

  ```rust
  /// Per-direction stream receive windows advertised in the transport parameters; each new
  /// receive stream starts with the credit of its class until the application first polls
  /// it (then it is widened to `stream_receive_window`, as with
  /// `initial_stream_receive_window`). Takes precedence over
  /// `initial_stream_receive_window`. Defaults to `None`.
  pub fn initial_stream_receive_windows(&mut self, value: Option<StreamReceiveWindows>) -> &mut Self {
      self.initial_stream_receive_windows = value;
      self
  }

  pub(crate) fn advertised_stream_receive_windows(&self) -> StreamReceiveWindows {
      self.initial_stream_receive_windows.unwrap_or_else(|| {
          let window = self.advertised_stream_receive_window();
          StreamReceiveWindows { bidi_local: window, bidi_remote: window, uni: window }
      })
  }
  ```

  Реэкспорт `StreamReceiveWindows` в `lib.rs` рядом с типами Task 1.

- [ ] **Step 4: Transport parameters.** В `TransportParameters::new`:

  ```rust
  let windows = config.advertised_stream_receive_windows();
  // ...
  initial_max_stream_data_bidi_local: windows.bidi_local,
  initial_max_stream_data_bidi_remote: windows.bidi_remote,
  initial_max_stream_data_uni: windows.uni,
  ```

- [ ] **Step 5: Потоки, `vendor/quinn-proto/src/connection/streams/state.rs`.** Поле `initial_stream_receive_window: u64` → `initial_stream_receive_windows: [u64; 3]` (индекс — класс потока); `free_recv: Vec<StreamRecv>` → `free_recv: [Vec<StreamRecv>; 3]` с комментарием, что `Recv` переинициализируется кредитом своего класса и поэтому переиспользуется только внутри класса. `StreamsState::new` принимает `initial_stream_receive_windows: StreamReceiveWindows` вместо `VarInt` и раскладывает `[bidi_local, bidi_remote, uni]` в `u64`; `free_recv: Default::default()`. Новые методы:

  ```rust
  /// 0: bidi opened by us, 1: bidi opened by the peer, 2: uni (always the peer's here).
  fn recv_class(&self, id: StreamId) -> usize {
      match id.dir() {
          Dir::Uni => 2,
          Dir::Bi if id.initiator() == self.side => 0,
          Dir::Bi => 1,
      }
  }

  /// Credit a new receive stream starts with, by its direction.
  pub(super) fn initial_recv_window(&self, id: StreamId) -> u64 {
      self.initial_stream_receive_windows[self.recv_class(id)]
  }
  ```

  Использования:
  - `insert`: `let recv = self.free_recv[self.recv_class(id)].pop();`
  - `stream_recv_freed`:
    ```rust
    let class = self.recv_class(id);
    self.free_recv[class].push(recv.free(self.initial_stream_receive_windows[class]));
    ```
  - обработчики STREAM и RESET_STREAM (два `get_or_insert_recv(self.initial_stream_receive_window)`): до `self.recv.get_mut(&id)` вычислить `let window = self.initial_recv_window(id);` и передать `get_or_insert_recv(window)`.
  - `connection/streams/mod.rs` (`stop`): `let window = self.state.initial_recv_window(self.id);` до `self.state.recv.entry(...)`, затем `get_or_insert_recv(window)`.
  - `connection/streams/recv.rs` (`Chunks::new` или где сейчас `get_or_insert_recv(streams.initial_stream_receive_window)`): `let window = streams.initial_recv_window(id);` до `streams.recv.entry(id)`.
  - `connection/mod.rs`: в `StreamsState::new(...)` вместо `config.advertised_stream_receive_window()` передать `config.advertised_stream_receive_windows()`.

  После правок `grep -n "initial_stream_receive_window\b\|free_recv" vendor/quinn-proto/src/connection -r` не должен находить старых обращений. Upstream inline-тесты и fuzz-код, вызывающие `StreamsState::new`, — передать `StreamReceiveWindows` из одного окна (`StreamReceiveWindows { bidi_local: w, bidi_remote: w, uni: w }`), чтобы компилировались.

- [ ] **Step 6: Гейт** — в `crates/outline-transport/src/quic/vendored.rs`:

  ```rust
  /// Advertise per-direction stream credit (`initial_max_stream_data_bidi_local`,
  /// `_bidi_remote`, `_uni`); `TransportConfig::stream_receive_window` stays the window
  /// granted when the application first polls a receive stream.
  pub(crate) fn set_advertised_stream_receive_windows(
      transport: &mut quinn::TransportConfig,
      bidi_local: u32,
      bidi_remote: u32,
      uni: u32,
  ) {
      transport.initial_stream_receive_windows(Some(quinn_proto::StreamReceiveWindows {
          bidi_local: quinn::VarInt::from_u32(bidi_local),
          bidi_remote: quinn::VarInt::from_u32(bidi_remote),
          uni: quinn::VarInt::from_u32(uni),
      }));
  }
  ```

  `set_advertised_stream_receive_window` остаётся (его вызывает `build_h3_transport` до Task 3 и тест `stream_window_grows_past_advertised_after_first_read`). CI-инвариант новое имя уже ловит: шаблон `initial_stream_receive_window` — префикс `initial_stream_receive_windows`.

- [ ] **Step 7: Тесты.** `cargo test -p outline-transport --features h3 quic::` → `stream_credit_follows_stream_direction`, `per_direction_windows_are_advertised` и все прежние — PASS. Числа из `eprintln!` привести в отчёте.

- [ ] **Step 8: Полный гейт** → зелёный. Не коммитить.

---

### Task 3: Профили Safari и Firefox

**Files:**
- Modify: `crates/outline-transport/src/quic/tp_profile.rs`, `crates/outline-transport/src/quic/tls_config.rs`
- Test: `crates/outline-transport/src/quic/tests/tls_config.rs`, `crates/outline-transport/src/quic/tests/tp_profile.rs`

**Interfaces:**
- Consumes: Task 1 (`TpOrder`, `VersionInfo`, `VersionSlot`, поля `BrowserTpOptions`), Task 2 (`set_advertised_stream_receive_windows`).
- Produces (`tp_profile.rs`):
  ```rust
  pub(crate) struct StreamWindows { pub(crate) bidi_local: u32, pub(crate) bidi_remote: u32, pub(crate) uni: u32 }
  impl StreamWindows {
      pub(crate) const fn uniform(window: u32) -> Self;
      pub(crate) fn largest(&self) -> u32;
  }
  // QuicTpProfile: `stream_receive_window: u32` -> `stream_receive_windows: StreamWindows`,
  //                `zero_length_cid: bool`      -> `source_cid_len: usize`
  ```

- [ ] **Step 1: Failing-тесты.** В `crates/outline-transport/src/quic/tests/tls_config.rs`:
  - Заменить `h3_firefox_initial_has_no_google_connection_options` на:

    ```rust
    /// Firefox-profile H3 Initial carries Firefox 159's transport parameters in its fixed
    /// order (measured 2026-10-29); only the source CID and the GREASE version vary.
    #[tokio::test]
    async fn h3_firefox_transport_params_match_firefox_159() {
        use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};

        for seed in [[0x11; 32], [0x22; 32]] {
            let ch = with_dial_fingerprint(Some(TlsFingerprint::Firefox), async {
                capture_clienthello(super::h3_quic_client_config(), super::h3_endpoint_config(), seed)
            })
            .await;
            let tp = transport_params_from_clienthello(&ch);
            let ids: Vec<u64> = tp.iter().map(|(id, _)| *id).collect();
            assert_eq!(
                ids,
                [0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0b, 0x0e, 0x0f, 0x11, 0x1d, 0xff02_de1a, 0x20],
                "Firefox order"
            );
            let int = |id| varint_value(tp_value(&tp, id).expect("parameter missing"));
            assert_eq!(int(0x01), 30_000, "max_idle_timeout");
            assert_eq!(int(0x04), 25_165_824, "initial_max_data");
            assert_eq!(int(0x05), 12_582_912, "initial_max_stream_data_bidi_local");
            assert_eq!(int(0x06), 1_048_576, "initial_max_stream_data_bidi_remote");
            assert_eq!(int(0x07), 1_048_576, "initial_max_stream_data_uni");
            assert_eq!(int(0x08), 100, "initial_max_streams_bidi");
            assert_eq!(int(0x09), 100, "initial_max_streams_uni");
            assert_eq!(int(0x0b), 20, "max_ack_delay");
            assert_eq!(int(0x0e), 8, "active_connection_id_limit");
            assert_eq!(int(0x20), 65_535, "max_datagram_frame_size");
            assert_eq!(tp_value(&tp, 0x0f).map(<[u8]>::len), Some(3), "3-byte source CID");
            assert_eq!(tp_value(&tp, 0x1d), Some(&[][..]), "empty 0x1d");
            assert_eq!(tp_value(&tp, 0xff02_de1a), Some(&[0x43, 0xe8][..]), "draft min_ack_delay");
            let vi = tp_value(&tp, 0x11).expect("version_information");
            assert_eq!(vi.len(), 16);
            assert_eq!(&vi[..4], &[0, 0, 0, 1], "chosen version v1");
            let grease = u32::from_be_bytes(vi[4..8].try_into().unwrap());
            assert_eq!(grease & 0x0f0f_0f0f, 0x0a0a_0a0a, "GREASE version first");
            assert_eq!(&vi[8..], &[0x6b, 0x33, 0x43, 0xcf, 0, 0, 0, 1], "v2 then v1");
        }
    }
    ```

  - В `h3_safari_transport_params_match_apple`: ожидаемый набор `BTreeSet::from([0x04, 0x05, 0x06, 0x07, 0x09, 0x0e, 0x0f, 0xff08_0808])`, `tp.len() == 8`, добавить `assert_eq!(int(0x0e), Some(64), "active_connection_id_limit");`, из doc-комментария убрать фразу про недостающий 0x0e.
  - Новый тест порядка Safari:

    ```rust
    /// Apple writes a fixed sequence rotated per connection, `0xff080808` always last.
    #[tokio::test]
    async fn h3_safari_order_is_rotated_apple_sequence() {
        use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};

        const APPLE: [u64; 7] = [0x04, 0x05, 0x06, 0x07, 0x09, 0x0e, 0x0f];
        let mut starts = std::collections::BTreeSet::new();
        for seed in 0..16u8 {
            let ch = with_dial_fingerprint(Some(TlsFingerprint::Safari), async move {
                capture_clienthello(super::h3_quic_client_config(), super::h3_endpoint_config(), [seed; 32])
            })
            .await;
            let ids: Vec<u64> =
                transport_params_from_clienthello(&ch).iter().map(|(id, _)| *id).collect();
            assert_eq!(ids.last(), Some(&0xff08_0808), "Apple's private parameter is last");
            let start = APPLE.iter().position(|id| *id == ids[0]).expect("starts with an Apple id");
            let mut rotated = APPLE;
            rotated.rotate_left(start);
            assert_eq!(ids[..APPLE.len()], rotated, "seed {seed}");
            starts.insert(start);
        }
        assert!(starts.len() > 1, "rotation never moved: {starts:?}");
    }
    ```

  - Новый тест рабочих окон:

    ```rust
    /// The runtime stream window never falls below the largest advertised one.
    #[test]
    fn runtime_stream_window_covers_largest_advertised() {
        let fx = super::RuntimeWindows::current(&super::super::tp_profile::FIREFOX);
        assert!(fx.stream >= 12_582_912, "{fx:?}");
    }
    ```

  В `crates/outline-transport/src/quic/tests/tp_profile.rs`: удалить `firefox_differs_from_chromium_only_by_google_extra`, добавить

  ```rust
  #[test]
  fn stream_windows_largest_and_uniform() {
      assert_eq!(StreamWindows::uniform(7).largest(), 7);
      assert_eq!(FIREFOX.stream_receive_windows.largest(), 12_582_912);
  }
  ```

  Тест `zero_length_cid_connection_survives_client_rebind` оставить: он должен проходить и с новым генератором CID (если он создаёт `ZeroLengthCid` напрямую — брать `SAFARI.endpoint_config()`).

- [ ] **Step 2: Убедиться, что падают/не собираются** (`StreamWindows`, `source_cid_len` ещё нет): `cargo test -p outline-transport --features h3 quic:: 2>&1 | tail -5`.

- [ ] **Step 3: `tp_profile.rs`.**

  ```rust
  /// `initial_max_stream_data_{bidi_local,bidi_remote,uni}` (0x05-0x07).
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub(crate) struct StreamWindows {
      pub(crate) bidi_local: u32,
      pub(crate) bidi_remote: u32,
      pub(crate) uni: u32,
  }

  impl StreamWindows {
      pub(crate) const fn uniform(window: u32) -> Self {
          Self { bidi_local: window, bidi_remote: window, uni: window }
      }

      pub(crate) fn largest(&self) -> u32 {
          self.bidi_local.max(self.bidi_remote).max(self.uni)
      }
  }
  ```

  В `QuicTpProfile`: `stream_receive_windows: StreamWindows` вместо `stream_receive_window`; `source_cid_len: usize` вместо `zero_length_cid` с комментарием: «Length of the client's source CIDs. 0 (Chrome, Apple) sends an empty `initial_source_connection_id` and, unless `options.active_connection_id_limit` says otherwise, no `active_connection_id_limit`. Safe here because every H3 dial owns its endpoint and socket, so there is nothing to demultiplex by CID.»

  `endpoint_config`:

  ```rust
  pub(crate) fn endpoint_config(&self) -> quinn::EndpointConfig {
      let mut config = quinn::EndpointConfig::default();
      config.grease_quic_bit(self.grease_quic_bit);
      let len = self.source_cid_len;
      config.cid_generator(move || Box::new(quinn_proto::RandomConnectionIdGenerator::new(len)));
      config
  }
  ```

  `ZeroLengthCid` удалить.

  `CHROMIUM`: `stream_receive_windows: StreamWindows::uniform(6_291_456)`, `source_cid_len: 0`, опции — как после Task 1.

  `SAFARI`:

  ```rust
  /// Apple Network.framework (Safari). Apple omits `max_idle_timeout` and
  /// `max_udp_payload_size`; the 30 s `idle_timeout` still applies locally. Parameters
  /// follow Apple's fixed sequence rotated to a different start per connection, with
  /// `0xff080808` always last. `active_connection_id_limit = 64` is advertised while
  /// quinn holds at most 8 remote CIDs - exactly what our server issues.
  pub(crate) const SAFARI: QuicTpProfile = QuicTpProfile {
      name: "safari",
      idle_timeout: Duration::from_secs(30),
      receive_window: 16_777_216,
      stream_receive_windows: StreamWindows::uniform(2_097_152),
      max_bidi_streams: 0,
      max_uni_streams: 8,
      source_cid_len: 0,
      grease_quic_bit: false,
      options: BrowserTpOptions {
          advertise_min_ack_delay: false,
          grease_parameter: false,
          // Apple omits it; the 30 s `idle_timeout` above still applies locally.
          advertise_idle_timeout: false,
          advertise_max_udp_payload_size: false,
          datagram_frame_size: None,
          version_information: None,
          // Apple's private parameter, value 0x09 as captured on macOS 27.
          extra_parameters: &[(0xff08_0808, &[0x09])],
          order: TpOrder::Rotated(&[0x04, 0x05, 0x06, 0x07, 0x09, 0x0e, 0x0f, 0xff08_0808]),
          active_connection_id_limit: Some(64),
          max_ack_delay_ms: 25,
      },
  };
  ```

  `FIREFOX`:

  ```rust
  /// Firefox 159 (neqo), measured 2026-10-29: fixed parameter order, per-direction stream
  /// windows, a 3-byte source CID, `max_ack_delay = 20` (also our local ACK timer),
  /// `version_information` offering a GREASE version, QUIC v2 and v1, an empty 0x1d and
  /// neqo's draft `min_ack_delay` 0xff02de1a = 1000 us. The client only speaks v1; our
  /// quinn server ignores `version_information`, a server doing compatible version
  /// negotiation (RFC 9368) might pick the advertised v2.
  pub(crate) const FIREFOX: QuicTpProfile = QuicTpProfile {
      name: "firefox",
      idle_timeout: Duration::from_secs(30),
      receive_window: 25_165_824,
      stream_receive_windows: StreamWindows {
          bidi_local: 12_582_912,
          bidi_remote: 1_048_576,
          uni: 1_048_576,
      },
      max_bidi_streams: 100,
      max_uni_streams: 100,
      source_cid_len: 3,
      grease_quic_bit: false,
      options: BrowserTpOptions {
          advertise_min_ack_delay: false,
          grease_parameter: false,
          advertise_idle_timeout: true,
          advertise_max_udp_payload_size: false,
          datagram_frame_size: Some(65_535),
          version_information: Some(VersionInfo {
              other_versions: &[
                  VersionSlot::Grease,
                  VersionSlot::Version(0x6b33_43cf),
                  VersionSlot::Version(1),
              ],
              shuffle: false,
          }),
          extra_parameters: &[(0x1d, &[]), (0xff02_de1a, &[0x43, 0xe8])],
          order: TpOrder::Fixed(&[
              0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0b, 0x0e, 0x0f, 0x11, 0x1d,
              0xff02_de1a, 0x20,
          ]),
          active_connection_id_limit: Some(8),
          max_ack_delay_ms: 20,
      },
  };
  ```

  Doc-комментарий модуля: вместо «Everything except two Safari residuals is matched…» — «Each family mirrors a capture of the real browser (Chrome 156, Apple's Network.framework on macOS 27 and Firefox 159, 2026-10-29), parameter order included.»

- [ ] **Step 4: `tls_config.rs`.** В `build_h3_transport` вместо `set_advertised_stream_receive_window(&mut transport, tp.stream_receive_window)`:

  ```rust
  let w = tp.stream_receive_windows;
  super::vendored::set_advertised_stream_receive_windows(&mut transport, w.bidi_local, w.bidi_remote, w.uni);
  ```

  В `RuntimeWindows::current`: `.max(tp.stream_receive_windows.largest())`. Остальные обращения к `stream_receive_window`/`zero_length_cid` профиля найти `grep -rn "stream_receive_window\b\|zero_length_cid" crates/outline-transport/src` и поправить по смыслу (в тестах — `stream_receive_windows.largest()` или конкретное поле).

- [ ] **Step 5: Тесты.** `cargo test -p outline-transport --features h3 quic::` → PASS, в том числе `h3_chromium_transport_params_match_chrome`, `h3_safari_config_has_no_datagram_param`, `runtime_windows_do_not_change_advertised_parameters`, `safari_local_idle_timeout_applies_without_advertisement`, `zero_length_cid_connection_survives_client_rebind`.

- [ ] **Step 6: Сквозная проверка с нашим сервером.** Тест `advertised_cid_limit_above_queue_capacity_accepts_server_cids` из Task 1 гоняет 64 с 8-байтовыми CID; добавить в `crates/outline-transport/src/quic/tests/tls_config.rs` ещё один прогон на реальных профилях:

  ```rust
  /// Safari (64, zero-length CIDs) and Firefox (8, 3-byte CIDs) profiles keep a healthy
  /// connection to a quinn server that issues its 8 CIDs.
  #[tokio::test]
  async fn browser_profiles_accept_server_cids() {
      for tp in [&super::super::tp_profile::SAFARI, &super::super::tp_profile::FIREFOX] {
          let lb = loopback::Loopback::new();
          let server = lb.server.clone();
          let echo = tokio::spawn(async move {
              let conn = server.accept().await.unwrap().await.unwrap();
              let (mut send, mut recv) = conn.accept_bi().await.unwrap();
              let msg = recv.read_to_end(64).await.unwrap();
              send.write_all(&msg).await.unwrap();
              send.finish().unwrap();
              conn.closed().await
          });
          let transport = super::build_h3_transport(tp, super::RuntimeWindows::current(tp));
          let (_ep, conn) = lb.connect(tp.endpoint_config(), transport).await;
          tokio::time::sleep(std::time::Duration::from_millis(300)).await;
          let (mut send, mut recv) = conn.open_bi().await.unwrap();
          send.write_all(b"ping").await.unwrap();
          send.finish().unwrap();
          assert_eq!(recv.read_to_end(64).await.unwrap(), b"ping", "{}", tp.name);
          assert!(conn.close_reason().is_none(), "{}: {:?}", tp.name, conn.close_reason());
          assert!(conn.stats().frame_rx.new_connection_id >= 7, "{}", tp.name);
          conn.close(0u32.into(), b"done");
          echo.abort();
      }
  }
  ```

  Если сигнатура `build_h3_transport` отличается от `(tp, RuntimeWindows) -> quinn::TransportConfig` — подстроить вызов под неё, смысл тот же.

- [ ] **Step 7: Полный гейт** → зелёный. Не коммитить.

---

### Task 4: Документация и патч-артефакт

**Files:**
- Modify: `quinn-proto-0.11.15.patch`, `PATCHES.md`, `PATCHES.ru.md`, `AGENTS.md`, `bins/outline-ws-rust/CHANGELOG.md`, `bins/outline-ws-rust/CHANGELOG.ru.md`

- [ ] **Step 1: `PATCHES.md` / `PATCHES.ru.md`, раздел `## quinn-proto (0.11.15)`.**
  - Пункт 2 (browser-shaped-transport-parameters): `send_version_information` → `version_information` («RFC 9368: v1 as chosen version, `other_versions` from fixed versions and per-connection GREASE slots, optionally permuted»), убрать упоминание запрета формы `31*N+27`.
  - Новый пункт 3 **browser-order-and-firefox** (`src/config/transport.rs`, `src/transport_parameters.rs`, `src/cid_queue.rs`, `src/connection/mod.rs`, `src/connection/streams/{state,mod,recv}.rs`, `src/lib.rs`): `transport_parameter_order` (Shuffled / Fixed / Rotated; в Rotated сдвигаются только штатные параметры), `initial_stream_receive_windows` (кредит по классу потока, пулы освобождённых `Recv` по классам), `advertised_active_connection_id_limit` (кольцевой буфер remote CID на 8, проверка по объявленному лимиту с потолком 8, дефолт 5; больше 8 активных CID от пира → `CONNECTION_ID_LIMIT_ERROR`), `max_ack_delay_ms` (объявление + локальный ACK-таймер). Все дефолты — upstream; rng в дефолтном режиме расходуется как в upstream; сервер опции не использует.
  - Vendoring trim становится пунктом 4.
  - RU-версия — тот же смысл по-русски («носитель», «гейт» — по правилам терминологии).

- [ ] **Step 2: `AGENTS.md`.** Строка «`vendor/quinn-proto` = upstream 0.11.15 + два …» — привести число и перечень логических изменений в соответствие с `PATCHES.md`.

- [ ] **Step 3: CHANGELOG.** В `bins/outline-ws-rust/CHANGELOG.md` и `CHANGELOG.ru.md`, `[Unreleased]`, тем же стилем, что запись фазы B: Safari-профиль H3 пишет параметры в порядке Apple (циклический сдвиг, `0xff080808` последним) и объявляет `active_connection_id_limit = 64`; Firefox-профиль заменён замером Firefox 159 (фиксированный порядок, окна по направлениям, CID 3 байта, `max_ack_delay = 20` и такой же локальный ACK-таймер, `version_information` с v2, `0x1d`, `0xff02de1a`, `max_datagram_frame_size = 65535`).

- [ ] **Step 4: Патч-артефакт.** Перегенерировать `quinn-proto-0.11.15.patch` тем же способом и в том же формате заголовков, что сейчас (см. первые строки файла: `diff --git a/Cargo.toml b/Cargo.toml` …), против чистой копии crates.io `quinn-proto 0.11.15` из `~/.cargo/registry/src/*/quinn-proto-0.11.15`. Round-trip в новом уникальном каталоге scratchpad (`mktemp -d` внутри scratchpad, без `rm -rf`): скопировать чистый крейт, `patch -p1 < quinn-proto-0.11.15.patch`, затем `diff -r <копия>/src vendor/quinn-proto/src` и `diff <копия>/Cargo.toml vendor/quinn-proto/Cargo.toml` → пусто. Вывести в отчёт команды и результат.

- [ ] **Step 5: Полный гейт** → зелёный. Показать владельцу `git status` и `git diff --stat`. Не коммитить: коммит — по команде владельца.

---

## После выполнения

- Обновить память `quic-transport-params-vs-browsers`: остатки Safari закрыты, Firefox-профиль = замер Firefox 159; дальше — TLS ClientHello внутри Initial.
- Ручная проверка на проводе (по желанию владельца): прогнать наш клиент с `fingerprint_profile` Safari и Firefox против `scripts/quic-initial-sink.py`, сравнить tshark-разбор с замерами выше.
- Следующий план — TLS ClientHello (rustls против GREASE/ECH/ALPS браузеров).
