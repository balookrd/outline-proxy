# UDP по H3 DATAGRAM: честные метрики откатов, MTU QUIC и хвосты демультиплексора — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Сделать метрики UDP-over-H3-DATAGRAM правдивыми (клиент считает откаты по записям, сервер различает носитель и причину), показать MTU QUIC-соединений, перестать молча терять датаграммы в quinn и в демультиплексоре и раньше снимать маршрут датаграмм у закончившейся xhttp-сессии.

**Architecture:** Диагностика — `.superpowers/sdd/pf/xhttp-fallback-diagnosis.md`. Задачи 1–4 — только метрики и буфер приёма. Они не меняют провод и нужны, чтобы решение по задаче 8 (пол MTU на сервере) приняли по данным с прода. Задачи 5–6 переделывают общий демультиплексор `outline-wire::h3_datagram`: надгробия для снятых маршрутов и лимит очереди в байтах. Задача 7 снимает якорь датаграмм xhttp-сессии по концу uplink и учит janitor выселять сессию, у которой все пакеты идут датаграммами. Задача 8 — по решению владельца после раскатки 1–7.

**Tech Stack:** Rust 2024, quinn 0.11.9 + vendored quinn-proto, h3 (vendored), tokio, `prometheus` (клиент, `crates/outline-metrics`), `metrics` + `metrics-exporter-prometheus` (сервер, `bins/outline-ss-rust/src/metrics`), Grafana JSON.

## Global Constraints

- Комментарии в коде, сообщения коммитов — на английском. Без `Co-Authored-By` и любых пометок об авторстве Claude.
- Коммит и пуш — только по явной команде владельца. Ветки не создавать, работать в `main`.
- Тесты — в `<dir>/tests/<module>.rs`, подключение `#[cfg(test)] #[path = "tests/<module>.rs"] mod tests;`. Inline `mod tests { … }` не заводить.
- CHANGELOG и docs — парами EN/RU (`CHANGELOG.md` + `CHANGELOG.ru.md`, `README.md` + `README.ru.md`) в одном изменении.
- «носитель» (не «карьер»), «гейт» (не «ворота»).
- Не трогать `macos/` и `vendor/` — в этом плане ни один vendored-крейт не меняется.
- Не стейджить серию в общем индексе, пока владелец коммитит сам: `git add` только перечисленных файлов задачи и сразу `git commit`.
- Гейт перед каждым коммитом (ровно эти команды, из `AGENTS.md`):
  ```bash
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
    -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
    -p outline-tun -p outline-uplink -p outline-wire \
    -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  ```
  плюс тесты задачи. Перед пушем всей серии — `cargo test --workspace --exclude sockudo-ws`, `cargo check -p outline-ss-rust --no-default-features`, `cargo check -p outline-ws-rust --no-default-features`, e2e (`RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls --test 'e2e_*' -- --test-threads=1`) и `(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)`.
- Метки метрик — только `&'static str` из фиксированного набора; никаких id сессий, адресов, путей.
- Новые значения меток:
  - носитель: `"ws_h3"`, `"xhttp_h3"`;
  - `reason` откатов вниз на сервере: `"too_large"`, `"send_failed"`, `"unarmed"`; вверх: `"stream"`;
  - `reason` дропов демультиплексора: `"unknown_stream"`, `"closed_stream"`, `"malformed"`, `"queue_full"`, `"queue_stalled"` (клиент ещё `"early"`).
- Числа: `TOMBSTONE_TTL = 10 s`, `REGISTRATION_QUEUE_BYTES = 512 KiB`, `CONNECTION_QUEUE_BYTES = 4 MiB`, `DATAGRAM_QUEUE = 1024` (потолок в штуках), `QUEUE_STALL = 50 ms`, локальный буфер приёма датаграмм клиента `1 MiB` (advertised `max_datagram_frame_size` не меняется: 65536 Chromium / 65535 Firefox), период сэмпла пути `10 s`, бакеты MTU `[1200, 1250, 1280, 1300, 1350, 1380, 1400, 1420, 1440, 1452, 1500]`.

## Карта файлов

| Файл | Что меняется | Задача |
|---|---|---|
| `crates/outline-transport/src/h3/datagram.rs` | флаг «откат вниз считает протокол выше» | 1 |
| `crates/outline-transport/src/vless/udp.rs` | счёт отката вниз по записи VLESS | 1 |
| `crates/outline-transport/src/vless/tests/udp.rs` | гард 1:1 | 1 |
| `crates/outline-transport/src/quic/vendored.rs` | буфер приёма 1 МиБ | 2 |
| `crates/outline-transport/src/quic/tests/tls_config.rs` | гард буфера | 2 |
| `bins/outline-ss-rust/src/server/transport/h3_datagram.rs` | метка носителя в якоре, `DatagramTarget` со «взведён/нет», причина отката | 3 |
| `bins/outline-ss-rust/src/metrics/{mod,registry}.rs` | метки `transport`/`reason`; MTU | 3, 4 |
| `bins/outline-ss-rust/src/server/transport/{udp.rs,vless/mod.rs,vless_udp.rs,xhttp/mod.rs}` | проброс метки носителя | 3 |
| `crates/outline-wire/src/h3_datagram.rs` | сэмплы пути, надгробия, байтовый лимит | 4, 5, 6 |
| `crates/outline-metrics/src/{transport.rs,stub.rs,process.rs,registration/core.rs,registration/mod.rs,lib.rs}` | MTU-метрики клиента, новые reason | 4, 5, 6 |
| `crates/outline-transport/src/{h3/shared.rs,xhttp/h3_pool.rs}` | подключить сэмплы пути | 4 |
| `bins/outline-ss-rust/src/server/h3/http.rs` | сэмплы пути, новые reason | 4, 5, 6 |
| `bins/outline-ss-rust/src/server/transport/xhttp/{h3.rs,mod.rs}` | detach по концу uplink, janitor | 7 |
| `bins/outline-ss-rust/src/server/h3/mod.rs` | `min_mtu` | 8 |
| `bins/*/grafana/*-dashboard.json` | панели | 3, 4 |
| `bins/*/CHANGELOG{,.ru}.md`, `bins/*/README{,.ru}.md` | описание метрик | 1–8 |
| `bins/outline-ss-rust/src/server/tests/diag_xhttp_fallback.rs` | удалить (untracked) | 1 |

---

### Task 1: Клиент — откат VLESS вниз считается по записям, а не по кускам потока

Сейчас `H3DatagramChannel::recv_datagram_with_source` считает `fallback{direction="down"}` на каждое сообщение потокового канала. На xhttp_h3 VLESS-тело приходит кусками HTTP/3 DATA, запись режется на ~2 куска, и клиент завышает откаты в 2,04 раза (доказано `diag_client_counts_chunks_not_records_on_xhttp`). Для VLESS счёт переносим в `VlessUdpTransport::read_packet` — одна выделенная из потока запись = один откат. SS не трогаем: у SS-UDP на xhttp согласован `udp_records`, счёт уже 1:1.

**Files:**
- Modify: `crates/outline-transport/src/h3/datagram.rs`
- Modify: `crates/outline-transport/src/vless/udp.rs`
- Test: `crates/outline-transport/src/vless/tests/udp.rs`
- Modify: `bins/outline-ws-rust/CHANGELOG.md`, `bins/outline-ws-rust/CHANGELOG.ru.md`
- Delete: `bins/outline-ss-rust/src/server/tests/diag_xhttp_fallback.rs` (untracked, `rm`)

**Interfaces:**
- Produces: `H3DatagramChannel::counting_stream_down_above(self) -> Self`; поле `VlessUdpTransport::datagram_transport: Option<&'static str>`.

- [ ] **Step 1: Падающий тест**

В `crates/outline-transport/src/vless/tests/udp.rs` дописать (рядом с хелпером `dropped`):

```rust
/// Process-wide, like `dropped`: callers compare deltas.
fn down_fallbacks(transport: &str) -> f64 {
    let rendered = outline_metrics::render_prometheus(&[]).unwrap_or_default();
    let series = format!(
        "outline_ws_udp_h3_datagram_fallback_total{{direction=\"down\",proto=\"vless\",transport=\"{transport}\"}} "
    );
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(&series)?.parse().ok())
        .unwrap_or(0.0)
}

/// On a datagram-negotiated session the client counts one downlink fallback
/// per VLESS-UDP record that rode the stream, however the carrier chunked the
/// body (an xhttp body arrives in HTTP/3 DATA chunks that split records), and
/// none for the response header or a datagram.
#[tokio::test]
async fn counts_one_down_fallback_per_stream_record() {
    let mut transport = transport(&[
        // Header plus the head of the first record.
        (STREAM, &[VERSION_BYTE, 0, 0, 3, b'a']),
        (STREAM, b"bc"),
        // Second record split mid-length.
        (STREAM, &[0]),
        (STREAM, &[2, b'd', b'e']),
        (DATAGRAM, &[0, 1, b'x']),
        // Two whole records in one chunk.
        (STREAM, &[0, 1, b'f', 0, 1, b'g']),
    ]);
    transport.datagram_transport = Some("xhttp_h3");
    let before = down_fallbacks("xhttp_h3");
    for expected in [&b"abc"[..], b"de", b"x", b"f", b"g"] {
        assert_eq!(&transport.read_packet().await.unwrap()[..], expected);
    }
    if cfg!(feature = "metrics") {
        assert_eq!(down_fallbacks("xhttp_h3") - before, 4.0);
    }
}
```

Метка `xhttp_h3`/`vless` в unit-тестах `outline-transport` больше нигде не пишется (проверено: `h3/tests/datagram.rs` пишет только `ws_h3`/`ss`), поэтому точное `== 4.0` не флейкает.

- [ ] **Step 2: Убедиться, что падает**

Run: `cargo test -p outline-transport --features metrics,h3 counts_one_down_fallback_per_stream_record`
Expected: FAIL компиляции — `no field datagram_transport`.

- [ ] **Step 3: `H3DatagramChannel` — флаг**

В `crates/outline-transport/src/h3/datagram.rs` в `struct H3DatagramChannel` после `gate`:

```rust
    /// Whether a downlink packet that rode the stream is counted here as a
    /// fallback. Off when the protocol above counts it instead, because the
    /// stream channel's messages are not its packets (a VLESS-UDP body over
    /// xhttp arrives in HTTP/3 DATA chunks that split records).
    count_stream_down: bool,
```

В `new` — `count_stream_down: true,`. Рядом с `with_gate`:

```rust
    /// Leaves counting downlink packets that ride the stream to the protocol
    /// above (see `count_stream_down`).
    pub(crate) fn counting_stream_down_above(mut self) -> Self {
        self.count_stream_down = false;
        self
    }
```

В `recv_datagram_with_source`, ветка `Inbound::Stream(Ok(Some(packet)))`:

```rust
                Inbound::Stream(Ok(Some(packet))) => {
                    if self.count_stream_down {
                        metrics::record_udp_h3_datagram_fallback("down", self.transport, self.proto);
                    }
                    return Ok(Some((PacketSource::Stream, packet)));
                },
```

- [ ] **Step 4: `VlessUdpTransport` — счёт по записи**

В `crates/outline-transport/src/vless/udp.rs`, `struct VlessUdpTransport`, после `datagram_gate`:

```rust
    /// `transport` label of the datagram counters when the carrier agreed
    /// datagrams: every record split out of the stream then counts as one
    /// downlink fallback (the channel underneath counts chunks, not records).
    datagram_transport: Option<&'static str>,
```

В `from_channel` — `datagram_transport: None,`. В `from_websocket`:

```rust
        #[cfg(feature = "h3")]
        let (chan, datagram_gate, datagram_transport): (
            Arc<dyn crate::frame_io::DatagramChannel>,
            _,
            _,
        ) = match datagram {
            Some(binding) => {
                let gate = Arc::new(DatagramGate::default());
                let channel =
                    crate::h3::H3DatagramChannel::new(binding, chan, datagram_transport, "vless")
                        .with_gate(Arc::clone(&gate))
                        .counting_stream_down_above();
                (Arc::new(channel), Some(gate), Some(datagram_transport))
            },
            None => (chan, None, None),
        };
        #[cfg(not(feature = "h3"))]
        let (datagram_gate, datagram_transport) = (None, None);
        let mut transport = Self::from_channel(chan, uuid, target, source)?;
        transport.datagram_gate = datagram_gate;
        transport.datagram_transport = datagram_transport;
        Ok(transport)
```

Метод рядом с `fire_throttle`:

```rust
    /// Returns `payload`, a record split out of the stream, counting it as one
    /// downlink fallback on a datagram-negotiated session.
    fn stream_record(&self, payload: Bytes) -> Bytes {
        if let Some(transport) = self.datagram_transport {
            outline_metrics::record_udp_h3_datagram_fallback("down", transport, "vless");
        }
        payload
    }
```

В `read_packet` оба места, где запись выделяется из `state.buf` (верх цикла и низ после заголовка), вернуть через него: `return Ok(self.stream_record(payload));`. Ветку `PacketSource::Datagram` (`datagram_record`) не трогать.

- [ ] **Step 5: Тест проходит, старые тоже**

Run: `cargo test -p outline-transport --features metrics,h3 vless::`
Expected: PASS все.

- [ ] **Step 6: Межрепозиторный тест сервера не сломан**

Run: `cargo test -p outline-ss-rust --lib cross_repo_vless_h3_datagram`
Expected: PASS (их асерты клиента — `>=`, на ws_h3 счёт не изменился).

- [ ] **Step 7: Удалить диагностический тест**

```bash
rm bins/outline-ss-rust/src/server/tests/diag_xhttp_fallback.rs
```

Его гард перенесён в Step 1, остальные замеры описаны в отчёте диагностики.

- [ ] **Step 8: CHANGELOG ws EN/RU**

В `bins/outline-ws-rust/CHANGELOG.md`, раздел `## [Unreleased]` → `### Fixed`:

```markdown
- `outline_ws_udp_h3_datagram_fallback_total{direction="down",proto="vless"}`
  now counts one per VLESS-UDP record that rode the stream. It used to count
  HTTP/3 body chunks, which on `xhttp_h3` split a record about twice, so the
  xhttp_h3 VLESS fallback share on dashboards drops roughly by half; the traffic
  itself is unchanged.
```

В `CHANGELOG.ru.md` тот же пункт:

```markdown
- `outline_ws_udp_h3_datagram_fallback_total{direction="down",proto="vless"}`
  теперь считает по одному на каждую запись VLESS-UDP, ушедшую потоком. Раньше
  счётчик считал куски HTTP/3-тела, а на `xhttp_h3` запись режется примерно на
  два, поэтому доля откатов VLESS на xhttp_h3 на дашбордах упадёт почти вдвое;
  сам трафик не меняется.
```

(Если раздела `[Unreleased]` нет — создать сверху по формату файла.)

- [ ] **Step 9: Гейт и коммит**

fmt + clippy из Global Constraints, затем:

```bash
git add crates/outline-transport/src/h3/datagram.rs crates/outline-transport/src/vless/udp.rs \
  crates/outline-transport/src/vless/tests/udp.rs bins/outline-ws-rust/CHANGELOG.md bins/outline-ws-rust/CHANGELOG.ru.md
git commit -m "fix(metrics): count VLESS downlink datagram fallbacks per record, not per stream chunk"
```

---

### Task 2: Клиент — локальный буфер приёма датаграмм 1 МиБ

quinn держит непрочитанные входящие датаграммы в `datagram_receive_buffer_size` и молча выбрасывает старые при переполнении. У клиента он сейчас равен advertised `max_datagram_frame_size` (64 КиБ ≈ 47 пакетов). Достаточно короткого голода демультиплексора — и потеря невидима. Advertised-значение — часть отпечатка, его не трогаем: vendored quinn-proto уже разделяет их (`advertised_max_datagram_frame_size`).

**Files:**
- Modify: `crates/outline-transport/src/quic/vendored.rs:110-120`
- Test: `crates/outline-transport/src/quic/tests/tls_config.rs`
- Modify: `bins/outline-ws-rust/CHANGELOG.md`, `bins/outline-ws-rust/CHANGELOG.ru.md`

**Interfaces:**
- Consumes: `super::tls_config::H3_DATAGRAM_BUFFER_BYTES` (уже `1 << 20`).

- [ ] **Step 1: Падающий тест**

В конец `crates/outline-transport/src/quic/tests/tls_config.rs`:

```rust
/// The local datagram receive buffer is sized for a burst the demultiplexer has
/// not read yet (1 MiB), while the advertised `max_datagram_frame_size` stays
/// the browser's exact value (part of the fingerprint).
#[test]
fn datagram_receive_buffer_is_local_not_advertised() {
    use super::super::vendored::apply_browser_tp_options;

    for (profile, advertised) in [
        (&super::super::tp_profile::CHROMIUM, "65536"),
        (&super::super::tp_profile::FIREFOX, "65535"),
    ] {
        let mut transport = quinn::TransportConfig::default();
        apply_browser_tp_options(&mut transport, &profile.options);
        let debug = format!("{transport:?}");
        let field = |name: &str| -> String {
            let start = debug.find(&format!("{name}: ")).unwrap_or_else(|| panic!("{name} in {debug}"));
            debug[start..].split(", ").next().unwrap().to_owned()
        };
        assert!(
            field("datagram_receive_buffer_size").contains("1048576"),
            "{}",
            field("datagram_receive_buffer_size")
        );
        assert!(
            field("advertised_max_datagram_frame_size").contains(advertised),
            "{}",
            field("advertised_max_datagram_frame_size")
        );
    }
}
```

Если константа профиля Firefox называется иначе — взять имя из `crates/outline-transport/src/quic/tp_profile.rs` (та, у которой `datagram_frame_size: Some(65_535)`).

- [ ] **Step 2: Убедиться, что падает**

Run: `cargo test -p outline-transport --features h3 datagram_receive_buffer_is_local_not_advertised`
Expected: FAIL — `datagram_receive_buffer_size: Some(65536)`.

- [ ] **Step 3: Реализация**

В `vendored.rs`:

```rust
        Some(size) => {
            transport
                .datagram_send_buffer_size(super::tls_config::H3_DATAGRAM_BUFFER_BYTES)
                // Local only: room for datagrams the demultiplexer has not read
                // yet, so a short stall of its task does not silently drop
                // them. The peer sees `advertised_max_datagram_frame_size`.
                .datagram_receive_buffer_size(Some(super::tls_config::H3_DATAGRAM_BUFFER_BYTES))
                .advertised_max_datagram_frame_size(Some(quinn::VarInt::from_u32(size)));
        },
```

- [ ] **Step 4: Тесты проходят**

Run: `cargo test -p outline-transport --features h3 quic::`
Expected: PASS, включая `profile_options_match_measured_browsers`.

- [ ] **Step 5: CHANGELOG ws EN/RU** (`### Changed`)

EN:
```markdown
- The client keeps up to 1 MiB of received HTTP/3 datagrams that the
  demultiplexer has not read yet (was 64 KiB, about 47 packets, which quinn
  dropped silently on a short stall). The advertised `max_datagram_frame_size`
  is unchanged.
```
RU:
```markdown
- Клиент держит до 1 МиБ принятых HTTP/3-датаграмм, которые демультиплексор ещё
  не прочитал (было 64 КиБ — около 47 пакетов, и при коротком простое quinn
  молча их выбрасывал). Объявляемый `max_datagram_frame_size` не изменился.
```

- [ ] **Step 6: Гейт и коммит**

```bash
git add crates/outline-transport/src/quic/vendored.rs crates/outline-transport/src/quic/tests/tls_config.rs \
  bins/outline-ws-rust/CHANGELOG.md bins/outline-ws-rust/CHANGELOG.ru.md
git commit -m "fix(quic): give the client a 1 MiB local datagram receive buffer"
```

---

### Task 3: Сервер — метка носителя и причина отката

Серверные счётчики датаграмм не различают `ws_h3`/`xhttp_h3`, а откат не говорит, почему пакет ушёл в поток. Кроме того, пакеты VLESS до первой uplink-датаграммы (`LinkPolicy::AfterUplink`) уходят потоком как `NoTarget` и не считаются вовсе — клиент же их считает. Добавляем метку `transport` во все `outline_ss_udp_h3_datagram*` (кроме `dropped`), метку `reason` в `fallback_total` и считаем «невзведённые» пакеты как `reason="unarmed"`.

**Files:**
- Modify: `bins/outline-ss-rust/src/server/transport/h3_datagram.rs`
- Modify: `bins/outline-ss-rust/src/metrics/mod.rs:397-436`, `bins/outline-ss-rust/src/metrics/registry.rs:168-192`
- Modify: `bins/outline-ss-rust/src/server/transport/udp.rs` (≈1103-1145, 1288-1310, 1391, 1424, 1558)
- Modify: `bins/outline-ss-rust/src/server/transport/vless/mod.rs` (≈98-110, 192-225, 895)
- Modify: `bins/outline-ss-rust/src/server/transport/vless_udp.rs` (≈819-846)
- Modify: `bins/outline-ss-rust/src/server/transport/xhttp/mod.rs:525`, `xhttp/h3.rs:85-97`, `h3/http.rs:355-357`
- Test: `bins/outline-ss-rust/src/server/transport/tests/h3_datagram.rs`, `bins/outline-ss-rust/src/server/tests/cross_repo_vless_h3_datagram.rs`
- Modify: `bins/outline-ss-rust/grafana/outline-ss-rust-dashboard.json` (панели 213–215)
- Modify: `bins/outline-ss-rust/CHANGELOG{,.ru}.md`, `bins/outline-ss-rust/README{,.ru}.md` (если там перечислены метки этих метрик)

**Interfaces:**
- Produces:
  - `pub(in crate::server) const WS_H3_CARRIER: &str = "ws_h3";`, `XHTTP_H3_CARRIER: &str = "xhttp_h3";` в `h3_datagram.rs`;
  - `DatagramAnchor::new(carrier: &'static str) -> Self`, `DatagramAnchor::carrier(&self) -> &'static str`; `impl Default` удаляется;
  - `DatagramLink::carrier(&self) -> &'static str`;
  - `DatagramTarget` — struct: `empty()`, `load()`, `store(Option<Arc<DatagramPeer>>)` (снимает «невзведён»), `store_unarmed()`, `is_unarmed() -> bool`;
  - `Metrics::record_udp_h3_datagram(direction, transport, proto)`, `Metrics::record_udp_h3_datagram_fallback(direction, transport, proto, reason)`, `Metrics::record_udp_h3_datagram_session(transport, state)`;
  - `DownlinkSend::{NoTarget, Sent, Fallback}` без изменений.

- [ ] **Step 1: Падающий unit-тест «невзведённого» пакета**

В `bins/outline-ss-rust/src/server/transport/tests/h3_datagram.rs` (там уже есть хелперы на реальной паре quinn — использовать их; ниже имена `pair()`/`metrics()` подставить из файла):

```rust
/// A VLESS link that agreed datagrams but has not seen the first uplink one yet
/// sends downlink on the stream and counts it as an `unarmed` fallback, so the
/// server's fallback share matches what the client sees.
#[tokio::test]
async fn target_tracks_unarmed() {
    let target = DatagramTarget::empty();
    target.store_unarmed();
    assert!(target.load().is_none());
    assert!(target.is_unarmed());
    target.store(None);
    assert!(!target.is_unarmed());
}
```

и межрепозиторный в `cross_repo_vless_h3_datagram.rs`, функция + строка в `carrier_tests!`:

```rust
/// Before the first uplink datagram the server keeps VLESS downlink on the
/// stream and counts each packet as an `unarmed` fallback under its carrier.
async fn unarmed_downlink_is_counted_per_carrier(carrier: Carrier) -> Result<()> {
    let (upstream, _) = spawn_udp_echo().await?;
    let server = setup_vless_h3_server(true).await?;
    let transport = connect(&server, carrier, upstream).await?;
    // The header packet rides the stream; its echo comes back before any
    // uplink datagram armed the downlink.
    round_trip(&transport, b"ping").await?;
    let transport_label = carrier.label();
    assert_eq!(
        server.counter(SERVER_FALLBACK, &[DOWN, VLESS, transport_label, ("reason", "unarmed")]),
        1.0
    );
    transport.close().await?;
    Ok(())
}
```

```rust
            #[tokio::test]
            async fn unarmed_downlink_is_counted_per_carrier() -> Result<()> {
                super::unarmed_downlink_is_counted_per_carrier($carrier).await
            }
```

`carrier.label()` возвращает `("transport", "ws_h3"|"xhttp_h3")` — то же имя метки, что и у сервера.

- [ ] **Step 2: Убедиться, что падает**

Run: `cargo test -p outline-ss-rust --lib unarmed_downlink`
Expected: FAIL компиляции (`store_unarmed` нет).

- [ ] **Step 3: Метрики сервера**

`metrics/mod.rs`:

```rust
    /// One UDP packet carried as an HTTP/3 datagram. `direction` is `"up"` /
    /// `"down"`, `transport` the carrier (`"ws_h3"` / `"xhttp_h3"`), `proto`
    /// the app protocol label (`"ss"` / `"vless"`).
    pub fn record_udp_h3_datagram(
        &self,
        direction: &'static str,
        transport: &'static str,
        proto: &'static str,
    ) {
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_udp_h3_datagrams_total",
                "direction" => direction,
                "transport" => transport,
                "proto"     => proto
            )
            .increment(1);
        });
    }

    /// One UDP packet that rode the stream on a datagram-agreed session.
    /// `reason`: `"too_large"` (did not fit the route's datagram size),
    /// `"send_failed"` (quinn refused it), `"unarmed"` (VLESS before the first
    /// uplink datagram) for `"down"`; `"stream"` for `"up"` (the client sent it
    /// on the stream).
    pub fn record_udp_h3_datagram_fallback(
        &self,
        direction: &'static str,
        transport: &'static str,
        proto: &'static str,
        reason: &'static str,
    ) {
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_udp_h3_datagram_fallback_total",
                "direction" => direction,
                "transport" => transport,
                "proto"     => proto,
                "reason"    => reason
            )
            .increment(1);
        });
    }

    pub fn record_udp_h3_datagram_session(&self, transport: &'static str, state: &'static str) {
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_udp_h3_datagram_sessions_total",
                "transport" => transport,
                "state"     => state
            )
            .increment(1);
        });
    }
```

`registry.rs` — переписать описания трёх метрик, упомянув `transport` и (для fallback) все четыре значения `reason`.

- [ ] **Step 4: Носитель в якоре и `DatagramTarget`**

`h3_datagram.rs`:

```rust
/// `transport` label of the datagram counters for a CONNECT (WebSocket) carrier.
pub(in crate::server) const WS_H3_CARRIER: &str = "ws_h3";
/// `transport` label of the datagram counters for an xhttp carrier.
pub(in crate::server) const XHTTP_H3_CARRIER: &str = "xhttp_h3";

/// Where a relay sends downlink datagrams, plus whether its link agreed them
/// but waits for the first uplink one (`LinkPolicy::AfterUplink`), so a packet
/// that rides the stream meanwhile is counted.
#[derive(Default)]
pub(in crate::server) struct DatagramTarget {
    peer: ArcSwapOption<DatagramPeer>,
    unarmed: AtomicBool,
}

impl DatagramTarget {
    pub(in crate::server) fn empty() -> Self {
        Self::default()
    }

    pub(in crate::server) fn load(&self) -> arc_swap::Guard<Option<Arc<DatagramPeer>>> {
        self.peer.load()
    }

    /// Sets (or clears) the peer; either way the target is no longer unarmed.
    pub(in crate::server) fn store(&self, peer: Option<Arc<DatagramPeer>>) {
        self.unarmed.store(false, Ordering::Relaxed);
        self.peer.store(peer);
    }

    /// No peer yet, but datagrams are agreed and arm with the first uplink one.
    pub(in crate::server) fn store_unarmed(&self) {
        self.peer.store(None);
        self.unarmed.store(true, Ordering::Relaxed);
    }

    pub(in crate::server) fn is_unarmed(&self) -> bool {
        self.unarmed.load(Ordering::Relaxed)
    }
}
```

Удалить `pub(in crate::server) type DatagramTarget = ArcSwapOption<DatagramPeer>;`. Все вызовы `target.load()`/`target.store(..)`/`DatagramTarget::empty()` компилируются как есть.

В `DatagramLink::apply`, ветка `LinkPolicy::AfterUplink`: `self.target.store(None);` → `self.target.store_unarmed();`. Остальные ветки не трогать: `store(..)` сам снимает флаг.

`DatagramAnchor`: поле `carrier: &'static str`; `impl Default` заменить на

```rust
impl DatagramAnchor {
    /// `carrier` is the `transport` label of the datagram counters.
    pub(in crate::server) fn new(carrier: &'static str) -> Self {
        Self {
            pending: Mutex::default(),
            dirty: AtomicBool::default(),
            changed: Notify::new(),
            downlink: Arc::default(),
            last_uplink_nanos: AtomicU64::new(0),
            created: Instant::now(),
            carrier,
        }
    }

    pub(in crate::server) fn carrier(&self) -> &'static str {
        self.carrier
    }
```

`with_route` → `Arc::new(Self::new(WS_H3_CARRIER))`. В `xhttp/mod.rs` `XhttpSession::new`: `datagram: Arc::new(DatagramAnchor::new(XHTTP_H3_CARRIER)),`. `DatagramLink::carrier()` → `self.anchor.carrier()`.

`DatagramDownlink`: новое поле `carrier: &'static str`. В `udp.rs:~1288` и `vless/mod.rs:~98` — `carrier: anchor.carrier(),`. `send_record`:

```rust
        let target = self.target.load();
        let Some(peer) = target.as_deref() else {
            if self.target.is_unarmed() {
                self.metrics
                    .record_udp_h3_datagram_fallback("down", self.carrier, self.proto, "unarmed");
            }
            return DownlinkSend::NoTarget;
        };
        let framed = peer
            .connection
            .max_datagram_size()
            .and_then(|max| max.checked_sub(datagram_overhead(peer.quarter_stream_id)))
            .and_then(|room| carrier_padding::frame_datagram_message(scheme, record, room));
        let outcome = match framed {
            Some(framed) => self.try_send(peer, &framed, upstream_len),
            None => Err("too_large"),
        };
        match outcome {
            Ok(()) => {
                self.metrics.record_udp_h3_datagram("down", self.carrier, self.proto);
                DownlinkSend::Sent
            },
            Err(reason) => {
                self.metrics
                    .record_udp_h3_datagram_fallback("down", self.carrier, self.proto, reason);
                DownlinkSend::Fallback
            },
        }
```

`try_send` → `Result<(), &'static str>`: `if !fits { return Err("too_large"); }`, ошибка `send_datagram` → `Err("send_failed")`, в конце `Ok(())`.

- [ ] **Step 5: Uplink и sessions — метка носителя**

- `udp.rs`: `enum H3UplinkCounter { Datagram(&'static str), Fallback(&'static str) }` (поле — носитель). В местах 1391/1424 передать `datagram_link.as_ref().map_or(WS_H3_CARRIER, DatagramLink::carrier)` (ссылка на link там уже есть — `datagrams_agreed` вычисляется из него). В ingest:
  ```rust
  match h3_counter {
      Some(H3UplinkCounter::Datagram(carrier)) => {
          server.metrics.record_udp_h3_datagram("up", carrier, SS_PROTO_LABEL)
      },
      Some(H3UplinkCounter::Fallback(carrier)) => server
          .metrics
          .record_udp_h3_datagram_fallback("up", carrier, SS_PROTO_LABEL, "stream"),
      None => {},
  }
  ```
- `vless/mod.rs:~192`: рядом с `datagrams_agreed` взять `let carrier = datagram_link.as_ref().map(DatagramLink::carrier);` и в цикле `record_udp_h3_datagram_fallback("up", carrier.unwrap_or(WS_H3_CARRIER), VLESS_PROTO_LABEL, "stream")`.
- `vless_udp.rs::forward_vless_udp_datagram`: новый параметр `carrier: &'static str`, `metrics.record_udp_h3_datagram("up", carrier, VLESS_PROTO_LABEL)`. Вызывающий передаёт `link.carrier()` (датаграмма пришла через link).
- sessions: `xhttp/h3.rs:85,95` → `record_udp_h3_datagram_session(XHTTP_H3_CARRIER, ..)`; `h3/http.rs:355,357` → `WS_H3_CARRIER`; `DatagramLink::apply` → `self.anchor.carrier()`.

Компилятор укажет все оставшиеся вызовы — у каждой функции сменилась арность.

- [ ] **Step 6: Тесты сервера**

Новый счёт `unarmed` добавляет откат вниз на эхо пакета-заголовка VLESS, поэтому три точных асерта в `cross_repo_vless_h3_datagram.rs` (строки ≈197, ≈225, ≈350: `server.counter(SERVER_FALLBACK, &[DOWN, VLESS])` с `0.0`/`1.0`) сузить до `&[DOWN, VLESS, ("reason", "too_large")]` — они проверяют именно непомещающиеся пакеты. SS-асерты (`cross_repo_ss_h3_datagram.rs` ≈428/464/524) не трогать: у SS `LinkPolicy::Immediate`, `unarmed` там не бывает.

Run: `cargo test -p outline-ss-rust --lib h3_datagram`
Expected: PASS, включая новые. Остальные асерты `server.counter(..)` суммируют серии по подмножеству меток (`metric_value`), поэтому новые метки их не ломают.

- [ ] **Step 7: Grafana (ss)**

В `bins/outline-ss-rust/grafana/outline-ss-rust-dashboard.json` (python-скриптом, не руками; `json.dump(..., indent=2)` и сверить, что diff затрагивает только эти панели):
- id 213: `sum by (direction, transport, proto) (rate(outline_ss_udp_h3_datagrams_total{instance=~"$instance"}[$__rate_interval]))`, legend `{{direction}} {{transport}} {{proto}}`;
- id 214: `sum by (direction, transport, proto, reason) (rate(outline_ss_udp_h3_datagram_fallback_total{instance=~"$instance"}[$__rate_interval]))`, legend `{{direction}} {{transport}} {{proto}} {{reason}}`;
- id 215: в обоих `sum by (direction)` числителя и знаменателя заменить на `sum by (direction, transport)`, legend `{{direction}} {{transport}}`;
- id 217: `sum by (transport, state)`.

Проверка: `python3 -c "import json;json.load(open('bins/outline-ss-rust/grafana/outline-ss-rust-dashboard.json'))"`.

- [ ] **Step 8: Docs**

`bins/outline-ss-rust/CHANGELOG.md`/`.ru.md` (`### Changed`): метки `transport` у `outline_ss_udp_h3_datagram{s,_fallback,_sessions}_total`, `reason` у fallback со списком значений; новый счёт `unarmed` поднимет долю откатов VLESS вниз (раньше эти пакеты не считались). README EN/RU — если там есть таблица метрик с метками, обновить её; если нет, пропустить.

- [ ] **Step 9: Гейт и коммит**

```bash
git add bins/outline-ss-rust/src/server/transport/h3_datagram.rs bins/outline-ss-rust/src/metrics/mod.rs \
  bins/outline-ss-rust/src/metrics/registry.rs bins/outline-ss-rust/src/server/transport/udp.rs \
  bins/outline-ss-rust/src/server/transport/vless/mod.rs bins/outline-ss-rust/src/server/transport/vless_udp.rs \
  bins/outline-ss-rust/src/server/transport/xhttp/mod.rs bins/outline-ss-rust/src/server/transport/xhttp/h3.rs \
  bins/outline-ss-rust/src/server/h3/http.rs bins/outline-ss-rust/src/server/transport/tests/h3_datagram.rs \
  bins/outline-ss-rust/src/server/tests/cross_repo_vless_h3_datagram.rs \
  bins/outline-ss-rust/grafana/outline-ss-rust-dashboard.json bins/outline-ss-rust/CHANGELOG.md bins/outline-ss-rust/CHANGELOG.ru.md
git commit -m "feat(metrics): label server H3 datagram counters by carrier and fallback reason"
```

(+ README, если менялись.)

---

### Task 4: MTU пути QUIC в метриках (клиент и сервер)

Гипотеза остатка откатов: quinn после обнаружения black hole сбрасывает MTU к `min_mtu` = 1200, и запись в 1356 байт перестаёт влезать. quinn это знает (`connection.stats().path.{current_mtu, black_holes_detected, lost_plpmtud_probes}`), но никто не экспортирует. Сэмплер встраиваем в `DatagramDemux`: он есть ровно на соединениях с датаграммами, держит клон соединения и снимается вместе с ним (отдельная задача с клоном `quinn::Connection` помешала бы неявному закрытию соединения по drop — weak-handle в quinn 0.11.9 нет).

**Files:**
- Modify: `crates/outline-wire/src/h3_datagram.rs`
- Test: `crates/outline-wire/src/tests/h3_datagram.rs`
- Modify: `crates/outline-metrics/src/{transport.rs,stub.rs,process.rs,lib.rs,registration/core.rs,registration/mod.rs}`, `crates/outline-metrics/src/tests/mod.rs`
- Modify: `crates/outline-transport/src/h3/shared.rs:769`, `crates/outline-transport/src/xhttp/h3_pool.rs:360`
- Modify: `bins/outline-ss-rust/src/server/h3/http.rs:117-134`, `bins/outline-ss-rust/src/metrics/{mod.rs,registry.rs}`, `bins/outline-ss-rust/src/metrics/tests/mod.rs`
- Modify: оба `grafana/*-dashboard.json`, оба `CHANGELOG{,.ru}.md`, README EN/RU обоих бинарей (раздел метрик)

**Interfaces:**
- Produces (outline-wire, feature `h3-datagram`):
  ```rust
  pub struct PathSample { pub current_mtu: u16, pub black_holes: u64, pub lost_probes: u64 }
  pub type OnPathSample = Arc<dyn Fn(PathSample) + Send + Sync>;
  pub const PATH_SAMPLE_INTERVAL: Duration = Duration::from_secs(10);
  impl DatagramDemux {
      pub fn spawn_watched(connection, on_drop, on_path: OnPathSample) -> Arc<Self>;
  }
  ```
  `DatagramDemux::spawn` остаётся (без сэмплов).
- Produces (outline-metrics): `pub fn record_quic_path_sample(transport: &'static str, current_mtu: u16, black_holes: u64, lost_probes: u64)`.
- Produces (сервер): `Metrics::record_quic_path_sample(&self, current_mtu: u16, black_holes: u64, lost_probes: u64)`.

- [ ] **Step 1: Падающий тест сэмплера**

В `crates/outline-wire/src/tests/h3_datagram.rs`, модуль `demux`:

```rust
    /// A watched demux reports the path every interval, with black holes and
    /// lost probes as deltas since the previous sample, and once more when the
    /// connection closes.
    #[tokio::test]
    async fn watched_demux_samples_the_path() {
        let (client, server, _cep, _sep) = pair().await;
        let (_counts, on_drop) = counting();
        let samples = Arc::new(std::sync::Mutex::new(Vec::<PathSample>::new()));
        let sink = Arc::clone(&samples);
        let demux = DatagramDemux::spawn_watched_every(
            client,
            on_drop,
            Arc::new(move |s| sink.lock().unwrap().push(s)),
            Duration::from_millis(50),
        );
        tokio::time::sleep(Duration::from_millis(180)).await;
        let seen = samples.lock().unwrap().len();
        assert!(seen >= 2, "only {seen} samples");
        for s in samples.lock().unwrap().iter() {
            assert!(s.current_mtu >= 1200, "{s:?}");
            assert_eq!((s.black_holes, s.lost_probes), (0, 0), "{s:?}");
        }
        server.close(0u32.into(), b"bye");
        for _ in 0..200 {
            if samples.lock().unwrap().len() > seen {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(samples.lock().unwrap().len() > seen, "no final sample on close");
        drop(demux);
    }
```

- [ ] **Step 2: Убедиться, что падает**

Run: `cargo test -p outline-wire --features h3-datagram watched_demux_samples_the_path`
Expected: FAIL компиляции.

- [ ] **Step 3: Реализация в demux**

В `mod demux`:

```rust
    /// A QUIC connection's path MTU state; counts are deltas since the previous
    /// sample of the same connection.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PathSample {
        pub current_mtu: u16,
        pub black_holes: u64,
        pub lost_probes: u64,
    }

    pub type OnPathSample = Arc<dyn Fn(PathSample) + Send + Sync>;

    pub const PATH_SAMPLE_INTERVAL: Duration = Duration::from_secs(10);

    /// Samples `connection`'s path every `every` and once more when it closes.
    async fn watch_path(connection: quinn::Connection, every: Duration, on_path: OnPathSample) {
        let (mut black_holes, mut lost_probes) = (0, 0);
        loop {
            let closed = tokio::select! {
                _ = connection.closed() => true,
                () = tokio::time::sleep(every) => false,
            };
            let path = connection.stats().path;
            on_path(PathSample {
                current_mtu: path.current_mtu,
                black_holes: path.black_holes_detected.saturating_sub(black_holes),
                lost_probes: path.lost_plpmtud_probes.saturating_sub(lost_probes),
            });
            black_holes = path.black_holes_detected;
            lost_probes = path.lost_plpmtud_probes;
            if closed {
                return;
            }
        }
    }
```

`DatagramDemux` получает поле `path_watch: Option<JoinHandle<()>>`; в `Drop` — `if let Some(watch) = &self.path_watch { watch.abort(); }`. Существующее тело `spawn` переносится в приватный `fn spawn_inner(connection, on_drop, path: Option<(OnPathSample, Duration)>) -> Arc<Self>`, который при `Some` делает `tokio::spawn(watch_path(connection.clone(), every, on_path))`. Публичные:

```rust
        pub fn spawn(connection: quinn::Connection, on_drop: Arc<dyn Fn(DropReason) + Send + Sync>) -> Arc<Self> {
            Self::spawn_inner(connection, on_drop, None)
        }

        /// As [`Self::spawn`], also reporting the connection's path to `on_path`
        /// every [`PATH_SAMPLE_INTERVAL`].
        pub fn spawn_watched(
            connection: quinn::Connection,
            on_drop: Arc<dyn Fn(DropReason) + Send + Sync>,
            on_path: OnPathSample,
        ) -> Arc<Self> {
            Self::spawn_inner(connection, on_drop, Some((on_path, PATH_SAMPLE_INTERVAL)))
        }

        #[cfg(test)]
        pub(crate) fn spawn_watched_every(
            connection: quinn::Connection,
            on_drop: Arc<dyn Fn(DropReason) + Send + Sync>,
            on_path: OnPathSample,
            every: Duration,
        ) -> Arc<Self> {
            Self::spawn_inner(connection, on_drop, Some((on_path, every)))
        }
```

Экспорт: `pub use demux::{…, OnPathSample, PATH_SAMPLE_INTERVAL, PathSample};`. Импорт `std::time::Duration` в модуль.

- [ ] **Step 4: Тест проходит**

Run: `cargo test -p outline-wire --features h3-datagram demux::`
Expected: PASS все.

- [ ] **Step 5: Метрики клиента**

`registration/core.rs` — рядом с датаграммными:

```rust
    let quic_path_mtu_bytes = register_histogram!(
        registry,
        "outline_ws_quic_path_mtu_bytes",
        "Path MTU of HTTP/3 connections that carry UDP datagrams, sampled every \
         10 s per connection, by transport (ws_h3 / xhttp_h3). A sample at 1200 \
         after a black hole is what pushes 1300+ byte datagrams onto the stream.",
        ["transport"],
        1200.0, 1250.0, 1280.0, 1300.0, 1350.0, 1380.0, 1400.0, 1420.0, 1440.0, 1452.0, 1500.0
    );
    let quic_black_holes_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_quic_black_holes_total",
        "MTU black holes quinn detected on HTTP/3 connections that carry UDP \
         datagrams (each one drops the path MTU to the QUIC minimum), by transport.",
        ["transport"]
    );
    let quic_mtu_probes_lost_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_quic_mtu_probes_lost_total",
        "Lost DPLPMTUD probes on HTTP/3 connections that carry UDP datagrams, by transport.",
        ["transport"]
    );
```

(форму `register_histogram!` взять из `registration/probe.rs` — порядок аргументов там эталонный). Провести поля через `core.rs` → `registration/mod.rs` → `lib.rs` (`Metrics`), как у `udp_h3_datagram_dropped_total`. В `process.rs` — `reset()` всех трёх и pre-touch для `transport in ["ws_h3", "xhttp_h3"]`.

`transport.rs`:

```rust
/// One path sample of an HTTP/3 connection that carries UDP datagrams;
/// `black_holes` / `lost_probes` are deltas since its previous sample.
pub fn record_quic_path_sample(
    transport: &'static str,
    current_mtu: u16,
    black_holes: u64,
    lost_probes: u64,
) {
    METRICS
        .quic_path_mtu_bytes
        .with_label_values(&[transport])
        .observe(f64::from(current_mtu));
    METRICS.quic_black_holes_total.with_label_values(&[transport]).inc_by(black_holes);
    METRICS.quic_mtu_probes_lost_total.with_label_values(&[transport]).inc_by(lost_probes);
}
```

`stub.rs`: `pub fn record_quic_path_sample(_transport: &'static str, _current_mtu: u16, _black_holes: u64, _lost_probes: u64) {}`. Экспорт из `lib.rs` рядом с `record_udp_h3_datagram_dropped`.

Тест в `crates/outline-metrics/src/tests/mod.rs` рядом с `render_prometheus_exports_udp_h3_datagram_series`:

```rust
#[test]
fn render_prometheus_exports_quic_path_series() {
    record_quic_path_sample("xhttp_h3", 1200, 1, 2);
    let rendered = render_prometheus(&[]).unwrap();
    assert!(rendered.contains("outline_ws_quic_path_mtu_bytes_bucket{transport=\"xhttp_h3\",le=\"1200\"}"));
    assert!(rendered.contains("outline_ws_quic_black_holes_total{transport=\"xhttp_h3\"}"));
    assert!(rendered.contains("outline_ws_quic_mtu_probes_lost_total{transport=\"xhttp_h3\"}"));
}
```

- [ ] **Step 6: Подключить на клиенте**

`h3/shared.rs:769`:

```rust
    let datagrams = (offers_datagrams && connection_handle.max_datagram_size().is_some()).then(|| {
        DatagramDemux::spawn_watched(
            connection_handle.clone(),
            Arc::new(record_datagram_drop),
            Arc::new(|s: PathSample| {
                metrics::record_quic_path_sample("ws_h3", s.current_mtu, s.black_holes, s.lost_probes)
            }),
        )
    });
```

`xhttp/h3_pool.rs:360` — то же с `"xhttp_h3"`. Импорт `outline_wire::h3_datagram::PathSample`.

- [ ] **Step 7: Метрики и подключение на сервере**

`metrics/mod.rs`:

```rust
    /// One path sample of an HTTP/3 connection that may carry UDP datagrams;
    /// `black_holes` / `lost_probes` are deltas since its previous sample.
    pub fn record_quic_path_sample(&self, current_mtu: u16, black_holes: u64, lost_probes: u64) {
        with_local_recorder(&self.recorder, || {
            histogram!("outline_ss_quic_path_mtu_bytes").record(f64::from(current_mtu));
            counter!("outline_ss_quic_black_holes_total").increment(black_holes);
            counter!("outline_ss_quic_mtu_probes_lost_total").increment(lost_probes);
        });
    }
```

`registry.rs`: `const QUIC_PATH_MTU_BUCKETS: &[f64] = &[1200.0, 1250.0, 1280.0, 1300.0, 1350.0, 1380.0, 1400.0, 1420.0, 1440.0, 1452.0, 1500.0];`, `.set_buckets_for_metric(Matcher::Full("outline_ss_quic_path_mtu_bytes".into()), QUIC_PATH_MTU_BUCKETS).expect("invalid QUIC path MTU bucket config")`, три `describe_*!` по образцу соседних.

`h3/http.rs::h3_connection_datagrams`: `DatagramDemux::spawn(..)` → `spawn_watched(connection.clone(), on_drop, on_path)`, где

```rust
    let path_metrics = Arc::clone(&ctx.udp_server.metrics);
    let on_path = Arc::new(move |s: PathSample| {
        path_metrics.record_quic_path_sample(s.current_mtu, s.black_holes, s.lost_probes);
    });
```

Тест в `bins/outline-ss-rust/src/metrics/tests/mod.rs` (по образцу соседних тестов рендера): после `metrics.record_quic_path_sample(1200, 1, 0)` в выводе `render_prometheus()` есть `outline_ss_quic_path_mtu_bytes_bucket{le="1200"} 1` и `outline_ss_quic_black_holes_total 1`.

- [ ] **Step 8: Тесты**

Run: `cargo test -p outline-metrics` , `cargo test -p outline-transport --features metrics,h3 h3::`, `cargo test -p outline-ss-rust --lib metrics`, `cargo test -p outline-ss-rust --lib h3_datagram`
Expected: PASS.

- [ ] **Step 9: Grafana (обе)**

Python-скриптом в каждый дашборд добавить две панели сразу после «Dropped inbound H3 datagrams by reason» (тот же row, `gridPos` — следующая строка, `w: 12, h: 8`, новые уникальные `id`):

ws:
1. «QUIC path MTU of datagram connections (p10 / p50)», timeseries, unit `bytes`:
   - `histogram_quantile(0.1, sum by (le, transport) (rate(outline_ws_quic_path_mtu_bytes_bucket{job=~"$job",instance=~"$instance"}[$__rate_interval])))` legend `p10 {{transport}}`;
   - то же с `0.5`, legend `p50 {{transport}}`.
2. «QUIC MTU black holes / lost probes (rate)», timeseries, unit `ops`:
   - `sum by (transport) (rate(outline_ws_quic_black_holes_total{job=~"$job",instance=~"$instance"}[$__rate_interval]))` legend `black holes {{transport}}`;
   - `sum by (transport) (rate(outline_ws_quic_mtu_probes_lost_total{job=~"$job",instance=~"$instance"}[$__rate_interval]))` legend `lost probes {{transport}}`.

ss: то же с `outline_ss_quic_*`, фильтр `{instance=~"$instance"}`, без `by (transport)` (`sum by (le)` / `sum`).

Плюс ws-панель 346 «fell back to the stream»: оставить как есть (метки не менялись).

Проверка JSON — `python3 -c "import json;json.load(open(...))"` для обоих.

- [ ] **Step 10: Docs**

CHANGELOG EN/RU обоих бинарей (`### Added`): новые метрики, что значит сэмпл 1200 и как его читать вместе с fallback. README EN/RU — в разделе метрик рядом с `udp_h3_datagram*` добавить три новые строки (имя, метки, смысл).

- [ ] **Step 11: Гейт и коммит**

```bash
git add crates/outline-wire/src/h3_datagram.rs crates/outline-wire/src/tests/h3_datagram.rs \
  crates/outline-metrics/src crates/outline-transport/src/h3/shared.rs crates/outline-transport/src/xhttp/h3_pool.rs \
  bins/outline-ss-rust/src/server/h3/http.rs bins/outline-ss-rust/src/metrics \
  bins/outline-ss-rust/grafana/outline-ss-rust-dashboard.json bins/outline-ws-rust/grafana/outline-ws-rust-dashboard.json \
  bins/outline-ss-rust/CHANGELOG.md bins/outline-ss-rust/CHANGELOG.ru.md bins/outline-ws-rust/CHANGELOG.md bins/outline-ws-rust/CHANGELOG.ru.md \
  bins/outline-ss-rust/README.md bins/outline-ss-rust/README.ru.md bins/outline-ws-rust/README.md bins/outline-ws-rust/README.ru.md
git commit -m "feat(metrics): export the QUIC path MTU and black holes of datagram connections"
```

(`git add` каталога `crates/outline-metrics/src` — только если `git status` показывает там лишь файлы этой задачи; иначе перечислить файлы.)

---

### Task 5: Демультиплексор — надгробия для снятых маршрутов (`closed_stream`)

После штатного закрытия сессии сервер ещё RTT × pps шлёт датаграммы в снятый маршрут, и они считаются `unknown_stream` — так ожидаемый хвост неотличим от настоящей ошибки маршрутизации. Снятая регистрация оставляет надгробие на `TOMBSTONE_TTL = 10 s`; датаграммы для него считаются `closed_stream`.

**Files:**
- Modify: `crates/outline-wire/src/h3_datagram.rs`
- Test: `crates/outline-wire/src/tests/h3_datagram.rs`
- Modify: `crates/outline-transport/src/h3/shared.rs:816-822`, `crates/outline-metrics/src/{process.rs,registration/core.rs,transport.rs}` (описание/pre-touch reason)
- Modify: `bins/outline-ss-rust/src/server/h3/http.rs:126-130`, `bins/outline-ss-rust/src/metrics/{mod.rs,registry.rs}` (описание)
- Modify: оба `CHANGELOG{,.ru}.md`

**Interfaces:**
- Produces: `DropReason::ClosedStream`; `pub const TOMBSTONE_TTL: Duration`.

- [ ] **Step 1: Тесты**

В `counting()` теста добавить счётчик `closed: AtomicUsize` и ветку `DropReason::ClosedStream => c.closed.fetch_add(1, Ordering::SeqCst)`.

В `routes_by_stream_and_counts_drops` конец заменить:

```rust
        drop(reg1);
        server.send_datagram(encode_datagram(1, b"late")).unwrap();
        // The tail of a stream that just unregistered is expected, not a
        // routing error.
        wait_for(&counts.closed, 1).await;
        assert_eq!(counts.unknown.load(Ordering::SeqCst), 1);
```

Новый тест:

```rust
    /// A tombstone outlives its TTL only until the next datagram for the id,
    /// which then counts as unknown again.
    #[tokio::test]
    async fn tombstone_expires_into_unknown_stream() {
        let (client, server, _cep, _sep) = pair().await;
        let (counts, on_drop) = counting();
        let demux = DatagramDemux::spawn_with_ttl(client, on_drop, Duration::from_millis(100));
        drop(demux.register(1));
        server.send_datagram(encode_datagram(1, b"tail")).unwrap();
        wait_for(&counts.closed, 1).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        server.send_datagram(encode_datagram(1, b"stray")).unwrap();
        wait_for(&counts.unknown, 1).await;
        assert_eq!(counts.closed.load(Ordering::SeqCst), 1);
    }

    /// Registering an id again replaces its tombstone.
    #[tokio::test]
    async fn register_over_a_tombstone_routes_again() {
        let (client, server, _cep, _sep) = pair().await;
        let (_counts, on_drop) = counting();
        let demux = DatagramDemux::spawn(client, on_drop);
        drop(demux.register(1));
        let mut again = demux.register(1);
        server.send_datagram(encode_datagram(1, b"back")).unwrap();
        assert_eq!(&recv(&mut again.rx).await.unwrap()[..], b"back");
    }
```

- [ ] **Step 2: Убедиться, что падает**

Run: `cargo test -p outline-wire --features h3-datagram demux::`
Expected: FAIL компиляции (`ClosedStream`, `spawn_with_ttl`).

- [ ] **Step 3: Реализация**

```rust
    /// How long an unregistered stream's id keeps absorbing datagrams as
    /// [`DropReason::ClosedStream`]: the peer learns of the close about an RTT
    /// later and its queued datagrams drain after that.
    pub const TOMBSTONE_TTL: Duration = Duration::from_secs(10);

    pub enum DropReason {
        UnknownStream,
        /// For a stream that unregistered within [`TOMBSTONE_TTL`]: the expected
        /// tail of a closed session.
        ClosedStream,
        Malformed,
        QueueFull,
    }

    enum Route {
        Live { generation: u64, tx: mpsc::Sender<Bytes> },
        Closed(Instant),
    }

    struct Routes {
        map: HashMap<u64, Route>,
        next_generation: u64,
        closed: bool,
        tombstone_ttl: Duration,
    }

    impl Routes {
        fn new(tombstone_ttl: Duration) -> Self {
            Self { map: HashMap::new(), next_generation: 0, closed: false, tombstone_ttl }
        }

        /// Drops tombstones older than the TTL.
        fn prune(&mut self, now: Instant) {
            let ttl = self.tombstone_ttl;
            self.map
                .retain(|_, route| !matches!(route, Route::Closed(at) if now.duration_since(*at) >= ttl));
        }
    }

    enum Lookup {
        Live(mpsc::Sender<Bytes>),
        Closed,
        Unknown,
    }
```

`Instant` — `std::time::Instant`. Reader:

```rust
                    let lookup = {
                        let mut routes = task_routes.lock().expect("demux lock");
                        let ttl = routes.tombstone_ttl;
                        match routes.map.get(&id) {
                            Some(Route::Live { tx, .. }) => Lookup::Live(tx.clone()),
                            Some(Route::Closed(at)) if at.elapsed() < ttl => Lookup::Closed,
                            Some(Route::Closed(_)) => {
                                routes.map.remove(&id);
                                Lookup::Unknown
                            },
                            None => Lookup::Unknown,
                        }
                    };
                    match lookup {
                        Lookup::Live(tx) => {
                            if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(payload) {
                                on_drop(DropReason::QueueFull);
                            }
                        },
                        Lookup::Closed => on_drop(DropReason::ClosedStream),
                        Lookup::Unknown => on_drop(DropReason::UnknownStream),
                    }
```

`DatagramRegistration::drop`:

```rust
            let mut routes = self.demux.routes.lock().expect("demux lock");
            // A newer registration of the same id must keep its route.
            let current = matches!(
                routes.map.get(&self.id),
                Some(Route::Live { generation, .. }) if *generation == self.generation
            );
            if current {
                let now = Instant::now();
                routes.prune(now);
                routes.map.insert(self.id, Route::Closed(now));
            }
```

`register`: `routes.map.insert(quarter_stream_id, Route::Live { generation, tx });` (вставка затирает надгробие). Конец reader'а (`map.clear()`) без изменений. `spawn_inner` получает `tombstone_ttl: Duration`; `spawn`/`spawn_watched` передают `TOMBSTONE_TTL`; `#[cfg(test)] pub(crate) fn spawn_with_ttl(connection, on_drop, ttl)`. Экспорт `TOMBSTONE_TTL`.

Надгробий не больше, чем закрытий за 10 с (prune на каждом drop), — отдельный потолок не нужен.

- [ ] **Step 4: Маппинги причин**

- `crates/outline-transport/src/h3/shared.rs::record_datagram_drop`: `DropReason::ClosedStream => "closed_stream",`.
- `crates/outline-metrics`: в `process.rs` список reason pre-touch → `["unknown_stream", "closed_stream", "malformed", "queue_full", "early"]`; описания в `registration/core.rs` и doc у `record_udp_h3_datagram_dropped` дополнить `closed_stream`.
- `bins/outline-ss-rust/src/server/h3/http.rs`: `DropReason::ClosedStream => "closed_stream",`; описание в `registry.rs` и doc в `mod.rs`.
- Тест `bins/outline-ss-rust/src/server/transport/tests/h3_datagram.rs:245+` и `crates/outline-transport/src/h3/tests/datagram.rs:84` — если они матчат `DropReason` исчерпывающе или ждут `UnknownStream` после drop регистрации, привести к `ClosedStream` (компилятор/падение теста покажет).

- [ ] **Step 5: Тесты**

Run: `cargo test -p outline-wire --features h3-datagram`, `cargo test -p outline-transport --features metrics,h3 h3::`, `cargo test -p outline-ss-rust --lib h3_datagram`, `cargo test -p outline-metrics`
Expected: PASS.

- [ ] **Step 6: CHANGELOG EN/RU обоих** (`### Changed`): датаграммы для потока, снятого не более 10 с назад, считаются `reason="closed_stream"`, а не `unknown_stream`; `unknown_stream` теперь означает настоящую ошибку маршрутизации. Панель «Dropped inbound H3 datagrams by reason» уже группирует `by (reason)` — правка Grafana не нужна.

- [ ] **Step 7: Гейт и коммит**

```bash
git add crates/outline-wire/src/h3_datagram.rs crates/outline-wire/src/tests/h3_datagram.rs \
  crates/outline-transport/src/h3/shared.rs crates/outline-metrics/src/process.rs \
  crates/outline-metrics/src/registration/core.rs crates/outline-metrics/src/transport.rs \
  bins/outline-ss-rust/src/server/h3/http.rs bins/outline-ss-rust/src/metrics/mod.rs bins/outline-ss-rust/src/metrics/registry.rs \
  bins/outline-ss-rust/CHANGELOG.md bins/outline-ss-rust/CHANGELOG.ru.md bins/outline-ws-rust/CHANGELOG.md bins/outline-ws-rust/CHANGELOG.ru.md
git commit -m "feat(h3-datagram): tombstone unregistered streams so their tail counts as closed_stream"
```

(+ тестовые файлы из Step 4, если менялись.)

---

### Task 6: Демультиплексор — очередь в байтах и различение «потребитель стоит»

`queue_full` — это потребитель, который не читал дольше 256 пакетов (доказано: `queue_full = отправлено − 256`). Очередь по штукам одинаково мала для 1350-байтных пакетов на 50 Мбит/с и велика для мелких. Делаем лимит в байтах: 512 КиБ на регистрацию и 4 МиБ на соединение (32 сессии на одном xhttp-носителе не должны дать 16 МиБ), потолок 1024 штуки. При переполнении причина `queue_stalled`, если потребитель не читал дольше 50 мс, иначе `queue_full` (всплеск).

**Files:**
- Modify: `crates/outline-wire/src/h3_datagram.rs`
- Test: `crates/outline-wire/src/tests/h3_datagram.rs`
- Modify: вызовы `registration.rx.recv()`: `crates/outline-transport/src/h3/datagram.rs:94`, `bins/outline-ss-rust/src/server/transport/h3_datagram.rs:514`, тесты (`crates/outline-wire/src/tests/h3_datagram.rs`, `crates/outline-transport/src/h3/tests/datagram.rs`, `bins/outline-ss-rust/src/server/transport/tests/h3_datagram.rs` — `grep -rn '\.rx\b'`)
- Modify: маппинги/описания причин как в Task 5 Step 4 (`queue_stalled`)
- Modify: оба `CHANGELOG{,.ru}.md`

**Interfaces:**
- Produces:
  - `DatagramRegistration::recv(&mut self) -> impl Future<Output = Option<Bytes>>` (cancel-safe), `DatagramRegistration::try_recv(&mut self) -> Option<Bytes>`; поле `rx` становится приватным;
  - `DropReason::QueueStalled`;
  - `pub const REGISTRATION_QUEUE_BYTES: usize = 512 * 1024; pub const CONNECTION_QUEUE_BYTES: usize = 4 * 1024 * 1024; pub const DATAGRAM_QUEUE: usize = 1024; pub const QUEUE_STALL: Duration = Duration::from_millis(50);`.

- [ ] **Step 1: Тесты**

В `counting()` — счётчик `stalled` и ветка `DropReason::QueueStalled`. Заменить `recv(rx: &mut Receiver)` на

```rust
    async fn recv(reg: &mut DatagramRegistration) -> Option<Bytes> {
        tokio::time::timeout(Duration::from_secs(5), reg.recv()).await.unwrap()
    }
```

и во всех тестах `recv(&mut x.rx)` → `recv(&mut x)`, `reg.rx.try_recv().is_ok()` → `reg.try_recv().is_some()`. Тест `full_queue_drops_without_stopping_reader`: `counts.queue_full` → `counts.queue_full.load(..) + counts.stalled.load(..) >= 1`.

Новые:

```rust
    async fn wait_total(counts: &Counts, queued: impl Fn() -> usize, total: usize) {
        for _ in 0..300 {
            let dropped = counts.queue_full.load(Ordering::SeqCst) + counts.stalled.load(Ordering::SeqCst);
            if dropped + queued() >= total {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("datagrams never settled");
    }

    /// A registration nobody reads holds at most its byte budget; the rest drop
    /// as `queue_stalled` once the consumer has not read for `QUEUE_STALL`.
    #[tokio::test]
    async fn registration_queue_is_bounded_in_bytes() {
        let (client, server, _cep, _sep) = pair().await;
        let (counts, on_drop) = counting();
        let demux = DatagramDemux::spawn_with_limits(client, on_drop, 10_000, 1 << 20);
        let mut reg = demux.register(1);
        tokio::time::sleep(QUEUE_STALL * 2).await;
        for _ in 0..30 {
            server.send_datagram(encode_datagram(1, &[0u8; 1000])).unwrap();
        }
        wait_total(&counts, || demux.queued_bytes() / 1000, 30).await;
        assert_eq!(demux.queued_bytes(), 10_000);
        assert_eq!(counts.stalled.load(Ordering::SeqCst), 20);
        let mut read = 0;
        while reg.try_recv().is_some() {
            read += 1;
        }
        assert_eq!(read, 10);
        assert_eq!(demux.queued_bytes(), 0);
    }

    /// The connection budget caps the sum over registrations.
    #[tokio::test]
    async fn connection_budget_caps_all_registrations() {
        let (client, server, _cep, _sep) = pair().await;
        let (counts, on_drop) = counting();
        let demux = DatagramDemux::spawn_with_limits(client, on_drop, 10_000, 15_000);
        let mut a = demux.register(1);
        let mut b = demux.register(2);
        for id in [1, 2] {
            for _ in 0..10 {
                server.send_datagram(encode_datagram(id, &[0u8; 1000])).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        wait_total(&counts, || demux.queued_bytes() / 1000, 20).await;
        assert_eq!(demux.queued_bytes(), 15_000);
        let drain = |reg: &mut DatagramRegistration| std::iter::from_fn(|| reg.try_recv()).count();
        assert_eq!(drain(&mut a), 10);
        assert_eq!(drain(&mut b), 5);
    }

    /// Dropping a registration with queued datagrams returns their bytes.
    #[tokio::test]
    async fn dropped_registration_releases_its_bytes() {
        let (client, server, _cep, _sep) = pair().await;
        let (counts, on_drop) = counting();
        let demux = DatagramDemux::spawn_with_limits(client, on_drop, 10_000, 1 << 20);
        let reg = demux.register(1);
        for _ in 0..5 {
            server.send_datagram(encode_datagram(1, &[0u8; 1000])).unwrap();
        }
        wait_total(&counts, || demux.queued_bytes() / 1000, 5).await;
        drop(reg);
        assert_eq!(demux.queued_bytes(), 0);
    }
```

`Counts` в `wait_total` — тот же struct из `counting()`; он `Arc<Counts>`, передавать `&counts`.

- [ ] **Step 2: Убедиться, что падает**

Run: `cargo test -p outline-wire --features h3-datagram demux::`
Expected: FAIL компиляции.

- [ ] **Step 3: Реализация**

```rust
    /// Bytes one registration may hold unread.
    pub const REGISTRATION_QUEUE_BYTES: usize = 512 * 1024;
    /// Bytes all registrations of one connection may hold unread.
    pub const CONNECTION_QUEUE_BYTES: usize = 4 * 1024 * 1024;
    /// Unread datagrams one registration may hold, whatever their size.
    pub const DATAGRAM_QUEUE: usize = 1024;
    /// A consumer that has not read for this long when its queue overflows
    /// is stalled ([`DropReason::QueueStalled`]), not hit by a burst.
    pub const QUEUE_STALL: Duration = Duration::from_millis(50);

    pub enum DropReason {
        UnknownStream,
        ClosedStream,
        Malformed,
        /// The registration's queue overflowed while its consumer was reading.
        QueueFull,
        /// The registration's queue overflowed and its consumer had not read for
        /// [`QUEUE_STALL`].
        QueueStalled,
    }

    /// Accounting one registration shares with the reader.
    struct Queue {
        bytes: AtomicUsize,
        /// Last read, as nanos since the demux's `epoch`.
        last_read_nanos: AtomicU64,
    }

    #[derive(Clone, Copy)]
    struct Limits {
        registration_bytes: usize,
        connection_bytes: usize,
    }
```

`DatagramDemux` получает `queued: Arc<AtomicUsize>`, `epoch: Instant`, `limits: Limits`. `Route::Live { generation, tx, queue: Arc<Queue> }`, `Lookup::Live(tx, queue)`.

Хелперы на `DatagramDemux`:

```rust
        fn nanos_since_epoch(&self) -> u64 {
            u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
        }

        /// Bytes queued and not yet read, over all registrations.
        pub fn queued_bytes(&self) -> usize {
            self.queued.load(Ordering::Acquire)
        }
```

Reader получает `queued`, `epoch`, `limits` (копии/клоны) и в ветке `Lookup::Live(tx, queue)`:

```rust
                        Lookup::Live(tx, queue) => {
                            let len = payload.len();
                            let over = queue.bytes.load(Ordering::Acquire) + len > limits.registration_bytes
                                || queued.load(Ordering::Acquire) + len > limits.connection_bytes;
                            if over {
                                on_drop(overflow_reason(&queue, epoch));
                                continue;
                            }
                            queue.bytes.fetch_add(len, Ordering::AcqRel);
                            queued.fetch_add(len, Ordering::AcqRel);
                            match tx.try_send(payload) {
                                Ok(()) => {},
                                Err(error) => {
                                    queue.bytes.fetch_sub(len, Ordering::AcqRel);
                                    queued.fetch_sub(len, Ordering::AcqRel);
                                    // A closed queue (registration dropped) is silently ignored.
                                    if matches!(error, mpsc::error::TrySendError::Full(_)) {
                                        on_drop(overflow_reason(&queue, epoch));
                                    }
                                },
                            }
                        },
```

```rust
    fn overflow_reason(queue: &Queue, epoch: Instant) -> DropReason {
        let now = u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let idle = now.saturating_sub(queue.last_read_nanos.load(Ordering::Relaxed));
        if Duration::from_nanos(idle) >= QUEUE_STALL {
            DropReason::QueueStalled
        } else {
            DropReason::QueueFull
        }
    }
```

Один писатель (reader) и один читатель на регистрацию, поэтому проверка «load + len > limit» и затем `fetch_add` не гонится сама с собой; конкурирующий `fetch_sub` из `recv` только уменьшает значение.

`register`: `mpsc::channel(DATAGRAM_QUEUE)`, `queue = Arc::new(Queue { bytes: 0.into(), last_read_nanos: self.nanos_since_epoch().into() })` (регистрация считается «только что прочитанной»: свежая сессия не stalled), кладёт `Arc::clone(&queue)` в `Route::Live` и в `DatagramRegistration { rx, id, generation, demux, queue }`.

`DatagramRegistration`:

```rust
    pub struct DatagramRegistration {
        rx: mpsc::Receiver<Bytes>,
        id: u64,
        generation: u64,
        demux: Arc<DatagramDemux>,
        queue: Arc<Queue>,
    }

    impl DatagramRegistration {
        /// Next datagram; `None` once the connection closed or the id was
        /// registered again. Cancel-safe: the datagram is taken and accounted
        /// in the same poll.
        pub async fn recv(&mut self) -> Option<Bytes> {
            let datagram = self.rx.recv().await?;
            self.release(datagram.len());
            Some(datagram)
        }

        pub fn try_recv(&mut self) -> Option<Bytes> {
            let datagram = self.rx.try_recv().ok()?;
            self.release(datagram.len());
            Some(datagram)
        }

        fn release(&self, len: usize) {
            self.queue.bytes.fetch_sub(len, Ordering::AcqRel);
            self.demux.queued.fetch_sub(len, Ordering::AcqRel);
            self.queue.last_read_nanos.store(self.demux.nanos_since_epoch(), Ordering::Relaxed);
        }
    }
```

В `Drop` регистрации — до работы с `routes`:

```rust
            // Queued datagrams leave with the registration: return their bytes.
            self.rx.close();
            while let Ok(datagram) = self.rx.try_recv() {
                self.queue.bytes.fetch_sub(datagram.len(), Ordering::AcqRel);
                self.demux.queued.fetch_sub(datagram.len(), Ordering::AcqRel);
            }
```

`spawn_inner(connection, on_drop, path, tombstone_ttl, limits)`; публичные `spawn`/`spawn_watched` передают `Limits { registration_bytes: REGISTRATION_QUEUE_BYTES, connection_bytes: CONNECTION_QUEUE_BYTES }`; `#[cfg(test)] pub(crate) fn spawn_with_limits(connection, on_drop, registration_bytes, connection_bytes)`. Экспорт новых констант и `QUEUE_STALL`.

Память: в худшем случае ≤ 4 МиБ payload на соединение и только при стоящих потребителях; `Bytes` датаграммы может держать GRO-батч quinn (до ~64 КиБ), поэтому реальный пик выше payload, но ограничен тем же числом датаграмм (≤ 1024 на регистрацию).

- [ ] **Step 4: Перевести вызовы `rx.recv()`**

`crates/outline-transport/src/h3/datagram.rs::next_registered` и `bins/outline-ss-rust/src/server/transport/h3_datagram.rs::next_registered`: `registration.rx.recv().await` → `registration.recv().await`. Тесты — `grep -rn '\.rx\b' crates bins --include='*.rs'` и перевести на `recv()`/`try_recv()`.

- [ ] **Step 5: Маппинги причин**

Как в Task 5 Step 4, значение `"queue_stalled"` (клиент `record_datagram_drop`, сервер `h3/http.rs`, pre-touch в `outline-metrics/src/process.rs`, описания метрик в обоих бинарях).

- [ ] **Step 6: Тесты**

Run: `cargo test -p outline-wire --features h3-datagram`, `cargo test -p outline-transport --features metrics,h3`, `cargo test -p outline-ss-rust --lib h3_datagram`, `cargo test -p outline-ss-rust --lib cross_repo_`, `cargo test -p outline-metrics`
Expected: PASS.

- [ ] **Step 7: CHANGELOG EN/RU обоих** (`### Changed`): очередь приёма датаграмм на поток ограничена 512 КиБ (≤ 1024 пакета) и 4 МиБ на соединение вместо 256 пакетов; переполнение у потребителя, не читавшего 50 мс, считается `reason="queue_stalled"`, всплеск — по-прежнему `queue_full`.

- [ ] **Step 8: Гейт и коммит**

```bash
git add crates/outline-wire/src/h3_datagram.rs crates/outline-wire/src/tests/h3_datagram.rs \
  crates/outline-transport/src/h3/datagram.rs crates/outline-transport/src/h3/shared.rs \
  crates/outline-transport/src/h3/tests/datagram.rs crates/outline-metrics/src/process.rs \
  crates/outline-metrics/src/registration/core.rs crates/outline-metrics/src/transport.rs \
  bins/outline-ss-rust/src/server/transport/h3_datagram.rs bins/outline-ss-rust/src/server/transport/tests/h3_datagram.rs \
  bins/outline-ss-rust/src/server/h3/http.rs bins/outline-ss-rust/src/metrics/mod.rs bins/outline-ss-rust/src/metrics/registry.rs \
  bins/outline-ss-rust/CHANGELOG.md bins/outline-ss-rust/CHANGELOG.ru.md bins/outline-ws-rust/CHANGELOG.md bins/outline-ws-rust/CHANGELOG.ru.md
git commit -m "feat(h3-datagram): bound the demux queue in bytes and tell a stalled consumer from a burst"
```

---

### Task 7: Сервер xhttp — снимать маршрут датаграмм по концу uplink и выселять «немую» сессию

На xhttp сервер узнаёт о конце UDP-сессии поздно: packet-up — только когда закончится GET, stream-one — после park. Брошенный без FIN packet-up GET не замечается вовсе: все пакеты идут датаграммами, в GET ничего не пишется, а janitor держит сессию живой по keepalive релея. Так nuxt2 ~2 минуты слал в старый носитель. Снимаем якорь датаграмм сразу по FIN-POST и по концу тела stream-one, а janitor выселяет сессию, которая пользовалась датаграммами и не прислала ни одного uplink-пакета за окно `SESSION_IDLE_EVICTION` (180 с), даже при свежем keepalive.

Патч `vendor/h3` (`poll_stopped` для STOP_SENDING без записи) сюда не входит: `vendor/` не трогаем, а janitor закрывает тот же случай за ≤ 180 с.

**Files:**
- Modify: `bins/outline-ss-rust/src/server/transport/xhttp/h3.rs:446-448, 590-610`
- Modify: `bins/outline-ss-rust/src/server/transport/xhttp/mod.rs:590-610`
- Test: `bins/outline-ss-rust/src/server/transport/xhttp/tests/mod.rs`, `bins/outline-ss-rust/src/server/tests/cross_repo_vless_h3_datagram.rs`
- Modify: `bins/outline-ss-rust/CHANGELOG{,.ru}.md`

**Interfaces:**
- Consumes: `XhttpSession::detach_datagram()`, `DatagramAnchor::note_uplink()`/`last_uplink()`, `SESSION_IDLE_EVICTION`.

- [ ] **Step 1: Падающий тест janitor**

В `xhttp/tests/mod.rs` рядом с `stalled_downlink_evicted_despite_fresh_keepalive`:

```rust
/// A session whose UDP rides HTTP/3 datagrams queues nothing in the ring, so a
/// client that vanished without a FIN would live forever on the relay's
/// keepalive. Once it has sent datagrams, uplink silence for the whole window
/// evicts it despite a fresh keepalive.
#[tokio::test]
async fn silent_datagram_session_evicted_despite_fresh_keepalive() {
    let session = XhttpSession::new(Arc::from("silent"), None, None, None);
    session.datagram_anchor().note_uplink();
    tokio::time::sleep(Duration::from_millis(40)).await;
    session.touch_keepalive();
    let cutoff = Instant::now() - Duration::from_millis(20);
    assert!(session.is_evictable(cutoff));
}

/// The same session stays while its uplink datagrams keep coming.
#[tokio::test]
async fn datagram_session_with_recent_uplink_is_kept() {
    let session = XhttpSession::new(Arc::from("talking"), None, None, None);
    tokio::time::sleep(Duration::from_millis(40)).await;
    session.datagram_anchor().note_uplink();
    session.touch_keepalive();
    let cutoff = Instant::now() - Duration::from_millis(20);
    assert!(!session.is_evictable(cutoff));
}
```

- [ ] **Step 2: Убедиться, что падает**

Run: `cargo test -p outline-ss-rust --lib silent_datagram_session_evicted`
Expected: FAIL (`assertion failed: session.is_evictable(cutoff)`).

- [ ] **Step 3: Janitor**

В `is_evictable` после stall-клаузы:

```rust
        // A session whose UDP rides datagrams queues nothing in the ring, and
        // the relay's keepalive keeps it "alive" forever: a client that vanished
        // without a FIN (a GET abandoned on a dead carrier) would get downlink
        // datagrams for as long as its upstream talks. Once it has used them,
        // no uplink at all for the whole window is enough — a live UDP client
        // always sends something within it.
        if self.datagram.last_uplink().is_some() && progress < cutoff {
            return true;
        }
```

(`progress` выше уже включает `last_uplink`.) Обновить doc-комментарий `is_evictable`: «Three independent reasons», третья — «Datagram-silent».

- [ ] **Step 4: Падающий межрепозиторный тест на detach**

В `cross_repo_vless_h3_datagram.rs` (+ строка в `carrier_tests!`, но вызывать только для xhttp — для `ws_h3` RESET виден сразу и тест там тоже должен пройти, поэтому можно для всех трёх):

```rust
/// Once the client drops its transport, the server stops sending its downlink
/// datagrams within a short grace (FIN on packet-up, the body's end on
/// stream-one, RESET on ws), instead of when the anchor request ends.
async fn dropped_client_stops_downlink_datagrams(carrier: Carrier) -> Result<()> {
    let (upstream, _) = spawn_udp_blaster(BUSY_FITS).await?;
    let server = setup_vless_h3_server(true).await?;
    let transport = connect(&server, carrier, upstream).await?;
    transport.send_packet(b"ping").await?;
    downlink_flows(&transport, &[7u8; 64]).await?;
    transport.close().await?;
    drop(transport);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = server.counter(SERVER_DATAGRAMS, &[DOWN, VLESS]);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = server.counter(SERVER_DATAGRAMS, &[DOWN, VLESS]);
    assert_eq!(after - before, 0.0, "{carrier:?}: server kept sending datagrams to a closed client");
    Ok(())
}
```

`downlink_flows(&VlessUdpTransport, &[u8])` и `BUSY_FITS` уже есть в файле.

Run: `cargo test -p outline-ss-rust --lib dropped_client_stops_downlink_datagrams`
Expected: на xhttp FAIL (сервер шлёт до конца GET/park), на ws_h3 PASS. Если на xhttp тест проходит и без правки (FIN успевает закрыть релей), оставить его как гард и всё равно сделать Step 5 — он убирает зависимость от порядка seq и от park.

- [ ] **Step 5: Detach по концу uplink**

`xhttp/h3.rs`, POST:

```rust
    if fin {
        // The client dropped its transport: stop its downlink datagrams now,
        // not when the GET ends — which, for a GET abandoned on a dead
        // carrier, may be never.
        session.detach_datagram();
        session.close_uplink();
    }
```

stream-one, после цикла чтения тела:

```rust
        // The body ended: the client is gone, so its downlink datagrams stop
        // here rather than after the relay parks.
        if udp_datagram {
            session_for_uplink.detach_datagram();
        }
        session_for_uplink.close_uplink();
```

(`udp_datagram: bool` — `Copy`, захватывается замыканием `move`; если компилятор просит — `let detach_on_end = udp_datagram;` до `tokio::spawn`.) `release_anchor` остаётся: повторный `Detach` безвреден.

- [ ] **Step 6: Тесты**

Run: `cargo test -p outline-ss-rust --lib xhttp`, `cargo test -p outline-ss-rust --lib cross_repo_`
Expected: PASS все, включая resume-тесты (park/resume не зависят от якоря датаграмм — resume приносит новый якорь).

- [ ] **Step 7: CHANGELOG ss EN/RU** (`### Fixed`): xhttp_h3 перестаёт слать downlink-датаграммы сессии сразу по FIN-POST (packet-up) или концу тела (stream-one); сессия, пользовавшаяся датаграммами и молчавшая 180 с по uplink, выселяется даже при keepalive релея.

- [ ] **Step 8: Гейт и коммит**

```bash
git add bins/outline-ss-rust/src/server/transport/xhttp/h3.rs bins/outline-ss-rust/src/server/transport/xhttp/mod.rs \
  bins/outline-ss-rust/src/server/transport/xhttp/tests/mod.rs bins/outline-ss-rust/src/server/tests/cross_repo_vless_h3_datagram.rs \
  bins/outline-ss-rust/CHANGELOG.md bins/outline-ss-rust/CHANGELOG.ru.md
git commit -m "fix(xhttp): stop downlink datagrams at the uplink's end and evict datagram-silent sessions"
```

---

### Раскатка задач 1–7

1. Финальный гейт (Global Constraints, полный набор) → показать diff владельцу → коммиты уже есть, **пуш только по команде** → `gh run` до зелёного → `cargo clean` (корень и `android/rust`).
2. Изменения совместимы в обе стороны: провод не менялся. Порядок — серверы, затем клиенты, по одному узлу (`ops/deploy/deploy-binary.sh <host> <unit> <bin>`), с проверкой `journalctl` и `/metrics` после каждого. Рестарт прода — только с согласия владельца. Взаимная топология: рестарт `.102`/`.104` рвёт ногу cloud-пары и наоборот.
3. Grafana: `./ops/grafana/dashboards/deploy.sh --k3s` + `kubectl -n monitoring rollout restart deploy/grafana` (рестарт обязателен).
4. Через сутки снять с VictoriaMetrics:
   - доля откатов по `transport`/`reason` (сервер) и по `transport` (клиент) — должны сойтись;
   - `histogram_quantile(0.1, …quic_path_mtu_bytes…)` и `rate(…black_holes_total…)` по узлам;
   - `closed_stream` против `unknown_stream`, `queue_stalled` против `queue_full`.
   Итог записать в память `h3-datagram-padding-fallback.md` и показать владельцу — это вход для Task 8.

---

### Task 8 (по решению владельца после замеров): пол MTU сервера = initial_mtu

**Условие запуска:** после раскатки 1–7 на проде видны black holes (`outline_ss_quic_black_holes_total` растёт) и сэмплы MTU 1200 совпадают по времени с `fallback{reason="too_large",proto="vless"}`. Если black holes нет — задачу закрыть без кода.

Black hole сбрасывает MTU к `min_mtu` (1200), и 1356-байтная запись VLESS перестаёт влезать на ≥ 60 с (`black_hole_cooldown`). С `min_mtu = initial_mtu` (1400 по умолчанию или закреплённое `[server.h3].initial_mtu`) сброс идёт до 1400: room 1366–1369 ≥ 1356. Риск: на пути уже 1400 сервер после ложного black hole будет терять пакеты до 1400 — но такой хост обязан закреплять `initial_mtu`, комментарий в `h3/mod.rs` об этом уже говорит.

**Files:**
- Modify: `bins/outline-ss-rust/src/server/h3/mod.rs:162-169`
- Create: `bins/outline-ss-rust/src/server/h3/tests/mod.rs` (каталог уже есть — в нём `http.rs`), подключить в конце `bins/outline-ss-rust/src/server/h3/mod.rs` строкой `#[cfg(test)] mod tests;` (у `mod.rs` без `#[path]`).
- Modify: `bins/outline-ss-rust/CHANGELOG{,.ru}.md`, `bins/outline-ss-rust/README{,.ru}.md` (раздел `[server.h3].initial_mtu`)

- [ ] **Step 1: Падающий тест**

```rust
/// A black hole drops the path MTU to `min_mtu`; pinning it to the initial MTU
/// keeps 1356-byte VLESS datagrams fitting after one (default and pinned).
#[test]
fn min_mtu_follows_initial_mtu() {
    for (pinned, expected) in [(None, 1400u16), (Some(1280u16), 1280)] {
        let transport =
            super::build_h3_transport_config(&crate::config::TuningProfile::LARGE, pinned).unwrap();
        let debug = format!("{transport:?}");
        assert!(debug.contains(&format!("initial_mtu: {expected}")), "{debug}");
        assert!(debug.contains(&format!("min_mtu: {expected}")), "{debug}");
    }
}
```

Run: `cargo test -p outline-ss-rust --lib min_mtu_follows_initial_mtu` → FAIL (`min_mtu: 1200`).

- [ ] **Step 2: Реализация**

```rust
    transport.initial_mtu(initial_mtu);
    // A black hole resets the path to `min_mtu`. At quinn's 1200 a 1356-byte
    // VLESS datagram no longer fits and rides the stream for a whole cooldown;
    // the initial MTU is already known to get through (or pinned by the
    // operator because it does), so recover to it instead.
    transport.min_mtu(initial_mtu);
```

Run: тест → PASS; `cargo test -p outline-ss-rust --lib h3` → PASS.

- [ ] **Step 3: Docs, гейт, коммит**

CHANGELOG/README ss EN/RU: после black hole сервер опускает MTU не ниже `initial_mtu`; хост с путём меньше 1400 обязан закрепить `[server.h3].initial_mtu`.

```bash
git add bins/outline-ss-rust/src/server/h3/mod.rs bins/outline-ss-rust/src/server/h3/tests \
  bins/outline-ss-rust/CHANGELOG.md bins/outline-ss-rust/CHANGELOG.ru.md bins/outline-ss-rust/README.md bins/outline-ss-rust/README.ru.md
git commit -m "fix(h3): recover the path MTU to initial_mtu after a black hole"
```

Раскатка — только серверы, по одному, с наблюдением `quic_path_mtu_bytes` и `fallback{reason="too_large"}` после каждого.

---

## Вне плана (решения по данным или владельца)

- **Закрывать брошенный UDP-транспорт сразу при мягком переключении** и **не брать `flows.read()` в TUN reader на каждый пакет** — делать, только если после Task 6 `queue_stalled` окажется заметным и совпадёт по времени с переключениями (метрика `uplink_selected`). Сейчас это гипотезы из чтения кода.
- **Сокращение окна `AfterUplink`** (взводить цель по первому потоковому uplink после заголовка) — решение владельца; Task 3 даёт его цену в `reason="unarmed"`.
- **`poll_stopped` в `vendor/h3`** — `vendor/` не трогаем; Task 7 закрывает брошенный GET janitor'ом за ≤ 180 с.
- **Меньшие лимиты очереди на Android/NanoPi** — пока не нужны: 4 МиБ — худший случай при стоящих потребителях.
