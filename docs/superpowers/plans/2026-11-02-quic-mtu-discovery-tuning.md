# Точный поиск MTU пути QUIC (minimum_change 4) — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Цель:** чтобы DPLPMTUD quinn на клиенте и сервере доходил до реального MTU пути с точностью до 4 байт, а не останавливался на 20+ байт раньше. Тогда SS2022-запись 1350-байтного UDP-пакета (~1408 байт) влезает в H3-датаграмму на пути nuxt2 (UDP-payload ≤ 1448) в обе стороны.

**Архитектура:** quinn ищет MTU двоичным поиском и прекращает, когда следующий шаг меньше `MtuDiscoveryConfig::minimum_change` (по умолчанию 20). Меняем только этот параметр: сервер (`build_h3_transport_config` в `outline-ss-rust`) и клиент (`build_h3_transport` в `outline-transport`, общий для ws_h3 и xhttp_h3) получают `minimum_change = 4`. Верхняя граница (1452), стартовый MTU (сервер 1400, клиент 1200) и объявляемый `max_udp_payload_size` не меняются. Проверка — UDP-реле в тестах, которое отбрасывает датаграммы больше 1448 байт в одну сторону, как туннель провайдера nuxt2.

**Tech Stack:** Rust, quinn / vendored quinn-proto 0.11, tokio.

## Global Constraints

- Новое значение одно: `minimum_change = 4` (константы `H3_MTU_DISCOVERY_MINIMUM_CHANGE` на сервере и `QUIC_MTU_DISCOVERY_MINIMUM_CHANGE` на клиенте).
- НЕ менять: `H3_MAX_UDP_PAYLOAD_SIZE = 1452`, `H3_MTU_DISCOVERY_UPPER_BOUND = 1452`, `H3_DEFAULT_INITIAL_MTU = 1400`, `H3_MAX_INITIAL_MTU = 1452`, клиентский `initial_mtu` (1200 — часть отпечатка Chrome, тест `h3_initial_datagram_stays_1200_for_every_profile`), клиентский `upper_bound` (дефолт quinn 1452: выше Chrome не пробует). Подъём потолка до 1472 сознательно отложен — нужен только IPv6-адресам SS и меняет видимые параметры.
- Не трогать `vendor/` и `macos/`; кластерную mesh (`server/cluster/mesh/tls.rs`) не трогать.
- Комментарии в коде и сообщения коммитов — по-английски; документация — парами EN/RU в одном изменении.
- Тесты — в существующих файлах `tests/` рядом с модулями, без inline `#[cfg(test)] mod tests {}`.
- `git commit` / `git push` — только по явной команде владельца, коммитить `git commit -- <пути>`; в индексе бывает чужое.
- Гейт (как в CI): `cargo fmt --check -p …` по списку пакетов CI (не `--all`: он переформатирует `vendor/sockudo-ws`), `cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings`, `--no-default-features` для обоих бинарей, `cargo test --workspace --exclude sockudo-ws`, `cargo test -p outline-transport --all-features`, e2e с `--test-threads=1`, инварианты CI, Linux в docker (`rust:bookworm`, пустой `.cargo/config.toml`, target в docker volume, БЕЗ `RUN_E2E_FAILOVER` в общем прогоне).
- Прод не рестартить без согласия; парк раскатывать по одному узлу.

## Почему именно 4 (расчёт, для ревьюера)

Место в датаграмме ≈ MTU − 21 (QUIC: флаги 1, CID 0 у Chrome-профиля, номер пакета 4, тег 16) − 9 (`Datagram::SIZE_BOUND`) − 1…2 (quarter-stream-id) − 4 (заголовок паддинга на padded-путях) ≈ MTU − 36. SS2022-запись вниз = пакет + ~58 (IPv4-адрес); для 1350 → ~1408, нужен MTU ≥ 1444. VLESS: 1352 → MTU ≥ 1388.

Двоичный поиск на пути с пределом 1448 (вычислено по `vendor/quinn-proto/src/connection/mtud.rs::next_mtu_to_probe`):

| сторона | старт | `minimum_change` 20 | `minimum_change` 4 |
|---|---|---|---|
| сервер | 1400 | 1426, 1452✗ → стоп **1426** | 1426, 1439, 1445, 1452✗, 1448 → **1448** |
| клиент | 1200 | 1326, 1389, 1420, 1452✗ → стоп **1420** | 1326, 1389, 1420, 1436, 1444, 1448, 1452✗ → **1448** |

Замер на проде (2026-11-02): SS через nuxt2 `too_large` 6010 vs 8312 датаграмм (ws_h3), MTU nuxt2 p50 ≈ 1429; внутренние сегменты к .102 — 1350 байт.

## Файлы

- Modify: `bins/outline-ss-rust/src/server/constants.rs` — константа `H3_MTU_DISCOVERY_MINIMUM_CHANGE`.
- Modify: `bins/outline-ss-rust/src/server/h3/mod.rs` — применить её в `build_h3_transport_config`.
- Test: `bins/outline-ss-rust/src/server/tests/h3.rs` — реле `spawn_narrow_downlink` + тест сходимости.
- Modify: `crates/outline-transport/src/quic/tls_config.rs` — константа `QUIC_MTU_DISCOVERY_MINIMUM_CHANGE` и применение в `apply_quic_carrier_tuning`.
- Modify (test helper): `crates/outline-transport/src/quic/tests/loopback.rs` — `connect_via` и реле `narrow_uplink`.
- Test: `crates/outline-transport/src/quic/tests/tls_config.rs` — тест сходимости клиента.
- Docs: `bins/outline-ss-rust/README.md` / `README.ru.md` (абзац «Sizes» / «Размеры»), `bins/outline-ss-rust/CHANGELOG.md` / `.ru.md`, `bins/outline-ws-rust/CHANGELOG.md` / `.ru.md`.

---

### Task 1: Сервер — `minimum_change = 4`

**Files:**
- Modify: `bins/outline-ss-rust/src/server/constants.rs` (после `H3_MTU_DISCOVERY_UPPER_BOUND`, ~строка 55)
- Modify: `bins/outline-ss-rust/src/server/h3/mod.rs` (импорт констант ~строки 14-18; `build_h3_transport_config`, ~строки 163-169)
- Test: `bins/outline-ss-rust/src/server/tests/h3.rs` (в конец файла)
- Docs: `bins/outline-ss-rust/README.md:864`, `bins/outline-ss-rust/README.ru.md:869`, `bins/outline-ss-rust/CHANGELOG.md` и `.ru.md` (первый `### Changed` / `### Изменено` в `## Unreleased`)

**Interfaces:**
- Consumes: `build_h3_quinn_server_config(tls_config, &TuningProfile, Option<u16>) -> Result<quinn::ServerConfig>` (`server/h3/mod.rs`); тестовые `test_h3_server_tls()`, `test_h3_client_config(cert_der)`, `sample_config(addr)` из `server/tests/mod.rs`; `super::super::constants::H3_MAX_UDP_PAYLOAD_SIZE`.
- Produces: `pub(super) const H3_MTU_DISCOVERY_MINIMUM_CHANGE: u16 = 4;` в `server/constants.rs`.

- [ ] **Step 1: Написать падающий тест**

В конец `bins/outline-ss-rust/src/server/tests/h3.rs` добавить (импорты `Ipv4Addr`, `SocketAddr`, `Arc`, `quinn::Endpoint`, `tokio::net::UdpSocket`, `anyhow::{Context, Result}` в файле уже есть):

```rust
/// UDP relay standing in for a path narrower than both hosts (nuxt2 sits behind a
/// provider tunnel that carries at most 1448-byte UDP payloads): it forwards
/// datagrams both ways and drops every server→client datagram larger than `limit`.
async fn spawn_narrow_downlink(
    server: SocketAddr,
    limit: usize,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let front = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let back = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    back.connect(server).await?;
    let addr = front.local_addr()?;
    let task = tokio::spawn(async move {
        let mut client = None;
        let mut up = vec![0u8; 65_536];
        let mut down = vec![0u8; 65_536];
        loop {
            tokio::select! {
                Ok((n, from)) = front.recv_from(&mut up) => {
                    client = Some(from);
                    let _ = back.send(&up[..n]).await;
                }
                Ok(n) = back.recv(&mut down) => {
                    if n <= limit
                        && let Some(to) = client
                    {
                        let _ = front.send_to(&down[..n], to).await;
                    }
                }
            }
        }
    });
    Ok((addr, task))
}

/// Path MTU discovery on the production server config gets within a few bytes of
/// a narrow path instead of stopping ~20 short. On a 1448-byte path the default
/// step (20) settles at 1426, where an SS2022 record of a 1350-byte packet
/// (~1408 bytes plus ~36 of QUIC and datagram overhead) no longer fits a datagram.
#[tokio::test]
async fn mtu_discovery_gets_within_a_few_bytes_of_a_narrow_path() -> Result<()> {
    const PATH_LIMIT: u16 = 1448;
    let (tls_config, cert_der) = test_h3_server_tls()?;
    let probe_config = sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    let server_config = build_h3_quinn_server_config(tls_config, &probe_config.tuning, None)?;
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.max_udp_payload_size(super::super::constants::H3_MAX_UDP_PAYLOAD_SIZE)?;
    let socket = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let server = quinn::Endpoint::new(
        endpoint_config,
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    let (path, relay) = spawn_narrow_downlink(server.local_addr()?, PATH_LIMIT.into()).await?;

    let accept = tokio::spawn({
        let server = server.clone();
        async move { server.accept().await.context("server endpoint closed")?.await.map_err(anyhow::Error::from) }
    });
    let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    client.set_default_client_config(test_h3_client_config(cert_der)?);
    let _client_conn = client.connect(path, "localhost")?.await?;
    let conn = accept.await??;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut mtu = conn.stats().path.current_mtu;
    while mtu < 1444 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        mtu = conn.stats().path.current_mtu;
    }
    relay.abort();
    assert!(
        (1444..=PATH_LIMIT).contains(&mtu),
        "server path MTU settled at {mtu}, expected 1444..={PATH_LIMIT}"
    );
    Ok(())
}
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `cargo test -p outline-ss-rust --lib server::tests::h3::mtu_discovery_gets_within_a_few_bytes_of_a_narrow_path`
Expected: FAIL через ~10 с с `server path MTU settled at 1426, expected 1444..=1448` (если число другое, но < 1444 — тоже ожидаемо; если тест падает иначе — разобраться до правки кода).

- [ ] **Step 3: Константа**

В `bins/outline-ss-rust/src/server/constants.rs` сразу после `H3_MTU_DISCOVERY_UPPER_BOUND`:

```rust
/// Smallest step DPLPMTUD keeps searching with (quinn's default is 20). With 20
/// the binary search stops up to ~20 bytes short of the path: behind a provider
/// tunnel that carries 1448-byte UDP payloads it settles at 1426, where an
/// SS2022 record of a 1350-byte packet no longer fits a datagram. 4 costs one or
/// two extra probes per connection.
pub(super) const H3_MTU_DISCOVERY_MINIMUM_CHANGE: u16 = 4;
```

- [ ] **Step 4: Применить в транспорте сервера**

В `bins/outline-ss-rust/src/server/h3/mod.rs` добавить `H3_MTU_DISCOVERY_MINIMUM_CHANGE` в список импорта из `constants` (рядом с `H3_MTU_DISCOVERY_UPPER_BOUND`, порядок — как отсортирует `cargo fmt`), и заменить

```rust
    let mut mtu = quinn::MtuDiscoveryConfig::default();
    mtu.upper_bound(discovery_upper_bound);
    transport.mtu_discovery_config(Some(mtu));
```

на

```rust
    let mut mtu = quinn::MtuDiscoveryConfig::default();
    mtu.upper_bound(discovery_upper_bound)
        .minimum_change(H3_MTU_DISCOVERY_MINIMUM_CHANGE);
    transport.mtu_discovery_config(Some(mtu));
```

- [ ] **Step 5: Тест проходит, соседние не сломаны**

Run: `cargo test -p outline-ss-rust --lib server::tests::h3`
Expected: PASS, в т.ч. `mtu_discovery_gets_within_a_few_bytes_of_a_narrow_path`, `h3_max_udp_payload_size_is_1452`, `http3_datagram_client_sees_max_datagram_size_and_connect_works`.

- [ ] **Step 6: Документация сервера (EN/RU)**

`bins/outline-ss-rust/README.md`, абзац `- **Sizes.**` (~строка 864): после `starting MTU 1400 (...)` перед точкой в конце предложения не менять текст в скобках, а дописать новое предложение в конец пункта:
`Path MTU discovery probes up to 1452 in steps down to 4 bytes, so a narrower path (a provider tunnel) is found within a few bytes rather than up to 20 short.`

`bins/outline-ss-rust/README.ru.md`, пункт `- **Размеры.**` (~строка 869), в конец пункта:
`Поиск MTU пути пробует до 1452 с шагом до 4 байт, поэтому более узкий путь (туннель провайдера) находится с точностью до нескольких байт, а не с недобором до 20.`

`bins/outline-ss-rust/CHANGELOG.md`, `## Unreleased` → первый `### Changed`, первой строкой списка:

```markdown
- **QUIC path MTU discovery searches in 4-byte steps instead of 20.** quinn's binary search stopped as soon as the next step was under 20 bytes, so on a path narrower than the 1452 ceiling it settled up to ~20 bytes short: behind nuxt2's provider tunnel (1448-byte UDP payloads) at about 1426. An SS2022 record of a 1350-byte packet is ~1408 bytes and needs ~1444, so those packets rode the stream as `outline_ss_udp_h3_datagram_fallback_total{reason="too_large"}` (on nuxt2, 6,010 of 14,322 SS packets over `ws_h3` in two hours). The search now goes to within 4 bytes (1448 there) at the cost of one or two extra probes per connection. Upper bound (1452), starting MTU (1400) and the advertised `max_udp_payload_size` are unchanged.
```

`bins/outline-ss-rust/CHANGELOG.ru.md`, `## Unreleased` → первый `### Изменено`, первой строкой:

```markdown
- **Поиск MTU пути QUIC идёт с шагом 4 байта вместо 20.** Двоичный поиск quinn останавливался, как только следующий шаг становился меньше 20 байт, поэтому на пути уже потолка 1452 он замирал с недобором до ~20 байт: за туннелем провайдера nuxt2 (UDP-payload до 1448) — примерно на 1426. SS2022-запись 1350-байтного пакета занимает ~1408 байт и требует ~1444, поэтому такие пакеты шли по потоку как `outline_ss_udp_h3_datagram_fallback_total{reason="too_large"}` (на nuxt2 — 6010 из 14 322 SS-пакетов по `ws_h3` за два часа). Теперь поиск доходит до предела с точностью 4 байта (там — 1448) ценой одной-двух лишних проб на соединение. Верхняя граница (1452), стартовый MTU (1400) и объявляемый `max_udp_payload_size` не изменились.
```

- [ ] **Step 7: fmt + clippy пакета**

Run: `cargo fmt -p outline-ss-rust && cargo clippy -p outline-ss-rust --all-targets --no-deps -- -D warnings && cargo clippy -p outline-ss-rust --no-default-features --all-targets --no-deps -- -D warnings`
Expected: без предупреждений. Коммит — НЕ делать (только по команде владельца).

---

### Task 2: Клиент — `minimum_change = 4`

**Files:**
- Modify: `crates/outline-transport/src/quic/tls_config.rs` (`apply_quic_carrier_tuning`, ~строки 213-221)
- Modify: `crates/outline-transport/src/quic/tests/loopback.rs` (новые `connect_via` и `narrow_uplink`)
- Test: `crates/outline-transport/src/quic/tests/tls_config.rs` (в конец файла)
- Docs: `bins/outline-ws-rust/CHANGELOG.md` и `.ru.md` (первый `### Changed` / `### Изменено` в `## [Unreleased]`)

**Interfaces:**
- Consumes: `build_h3_transport(&QuicTpProfile, RuntimeWindows) -> quinn::TransportConfig`, `RuntimeWindows::current(&QuicTpProfile)`, `tp_profile::CHROMIUM` (всё в `crate::quic`); `loopback::Loopback { server, addr }`, `Loopback::connect_with_tls(...)`.
- Produces: `const QUIC_MTU_DISCOVERY_MINIMUM_CHANGE: u16 = 4;` (приватная, `quic/tls_config.rs`); `Loopback::connect_via(&self, via: SocketAddr, endpoint_config: quinn::EndpointConfig, transport: quinn::TransportConfig) -> (quinn::Endpoint, quinn::Connection)`; `pub(super) async fn narrow_uplink(server: SocketAddr, limit: usize) -> (SocketAddr, tokio::task::JoinHandle<()>)` в `quic/tests/loopback.rs`.

- [ ] **Step 1: Помощники в loopback**

В `crates/outline-transport/src/quic/tests/loopback.rs`:

1) Заменить тело `connect_with_tls` вызовом общего приватного метода и добавить `connect_via`:

```rust
    /// Like [`Loopback::connect`], with the client's QUIC TLS config `client_tls`.
    pub(super) async fn connect_with_tls(
        &self,
        client_tls: Arc<quinn::crypto::rustls::QuicClientConfig>,
        endpoint_config: quinn::EndpointConfig,
        transport: quinn::TransportConfig,
    ) -> (quinn::Endpoint, quinn::Connection) {
        self.dial(client_tls, endpoint_config, transport, self.addr).await
    }

    /// Like [`Loopback::connect`], dialling `via` (a relay in front of this server)
    /// instead of the server's own address.
    pub(super) async fn connect_via(
        &self,
        via: SocketAddr,
        endpoint_config: quinn::EndpointConfig,
        transport: quinn::TransportConfig,
    ) -> (quinn::Endpoint, quinn::Connection) {
        self.dial(self.client_tls.clone(), endpoint_config, transport, via).await
    }

    async fn dial(
        &self,
        client_tls: Arc<quinn::crypto::rustls::QuicClientConfig>,
        endpoint_config: quinn::EndpointConfig,
        transport: quinn::TransportConfig,
        target: SocketAddr,
    ) -> (quinn::Endpoint, quinn::Connection) {
        let mut client_config = quinn::ClientConfig::new(client_tls);
        client_config.transport_config(Arc::new(transport));
        let socket = UdpSocket::bind(loopback()).unwrap();
        let endpoint =
            quinn::Endpoint::new(endpoint_config, None, socket, Arc::new(quinn::TokioRuntime))
                .unwrap();
        let conn = endpoint
            .connect_with(client_config, target, "localhost")
            .unwrap()
            .await
            .unwrap();
        (endpoint, conn)
    }
```

(Тело прежнего `connect_with_tls` целиком переезжает в `dial`; его вызывают ещё `tls_profile.rs:70` и `tls_config.rs:1388` — сигнатура не меняется.)

2) В конец файла:

```rust
/// UDP relay standing in for a path narrower than both hosts: it forwards
/// datagrams both ways and drops every client→server datagram larger than `limit`.
pub(super) async fn narrow_uplink(
    server: SocketAddr,
    limit: usize,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let front = tokio::net::UdpSocket::bind(loopback()).await.unwrap();
    let back = tokio::net::UdpSocket::bind(loopback()).await.unwrap();
    back.connect(server).await.unwrap();
    let addr = front.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut client = None;
        let mut up = vec![0u8; 65_536];
        let mut down = vec![0u8; 65_536];
        loop {
            tokio::select! {
                Ok((n, from)) = front.recv_from(&mut up) => {
                    client = Some(from);
                    if n <= limit {
                        let _ = back.send(&up[..n]).await;
                    }
                }
                Ok(n) = back.recv(&mut down) => {
                    if let Some(to) = client {
                        let _ = front.send_to(&down[..n], to).await;
                    }
                }
            }
        }
    });
    (addr, task)
}
```

- [ ] **Step 2: Написать падающий тест**

В конец `crates/outline-transport/src/quic/tests/tls_config.rs`:

```rust
/// The H3 client transport's path MTU discovery gets within a few bytes of a
/// narrow uplink instead of stopping ~20 short: on a 1448-byte path quinn's
/// default step (20) settles at 1420, too small for an SS2022 record of a
/// 1350-byte packet (~1408 bytes plus ~36 of QUIC and datagram overhead).
#[tokio::test]
async fn h3_mtu_discovery_gets_within_a_few_bytes_of_a_narrow_path() {
    const PATH_LIMIT: u16 = 1448;
    let lb = loopback::Loopback::new();
    let (via, relay) = loopback::narrow_uplink(lb.addr, PATH_LIMIT.into()).await;
    let server = lb.server.clone();
    let accept = tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() });
    let tp = &super::super::tp_profile::CHROMIUM;
    let transport = super::build_h3_transport(tp, super::RuntimeWindows::current(tp));
    let (_ep, conn) = lb.connect_via(via, quinn::EndpointConfig::default(), transport).await;
    let _server_conn = accept.await.unwrap();

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut mtu = conn.stats().path.current_mtu;
    while mtu < 1444 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        mtu = conn.stats().path.current_mtu;
    }
    relay.abort();
    assert!(
        (1444..=PATH_LIMIT).contains(&mtu),
        "client path MTU settled at {mtu}, expected 1444..={PATH_LIMIT}"
    );
}
```

- [ ] **Step 3: Убедиться, что тест падает**

Run: `cargo test -p outline-transport --all-features quic::tls_config::tests::h3_mtu_discovery_gets_within_a_few_bytes_of_a_narrow_path`
Expected: FAIL через ~10 с с `client path MTU settled at 1420, expected 1444..=1448` (любое значение < 1444 — ожидаемо).

- [ ] **Step 4: Константа и применение**

В `crates/outline-transport/src/quic/tls_config.rs` над `fn apply_quic_carrier_tuning`:

```rust
/// Smallest step DPLPMTUD keeps searching with (quinn's default is 20). With 20
/// the binary search stops up to ~20 bytes short of the path: on a 1448-byte
/// uplink it settles at 1420, where an SS2022 record of a 1350-byte packet no
/// longer fits a datagram. The upper bound stays quinn's 1452 and the Initial
/// stays 1200, as Chrome's; only the search gets finer.
const QUIC_MTU_DISCOVERY_MINIMUM_CHANGE: u16 = 4;
```

В конец тела `apply_quic_carrier_tuning` (после строки с `congestion_controller_factory`):

```rust
    let mut mtu = quinn::MtuDiscoveryConfig::default();
    mtu.minimum_change(QUIC_MTU_DISCOVERY_MINIMUM_CHANGE);
    transport.mtu_discovery_config(Some(mtu));
```

И обновить doc-комментарий функции: `/// Apply carrier congestion control and path MTU discovery to a QUIC transport config (windows come`… — заменить слова `Apply carrier congestion control` на `Apply carrier congestion control and path MTU discovery`.

- [ ] **Step 5: Тест проходит, отпечаток не изменился**

Run: `cargo test -p outline-transport --all-features quic::`
Expected: PASS, в т.ч. новый тест, `h3_initial_datagram_stays_1200_for_every_profile`, `h3_chromium_transport_params_match_chrome`, `default_transport_keeps_upstream_parameter_shape`, `stream_window_grows_past_advertised_after_first_read` (последний использует переделанный `connect_with_tls`).

- [ ] **Step 6: CHANGELOG клиента (EN/RU)**

`bins/outline-ws-rust/CHANGELOG.md`, `## [Unreleased]` → первый `### Changed`, первой строкой:

```markdown
- **QUIC path MTU discovery searches in 4-byte steps instead of 20.** The H3 carrier (`ws_h3`, `xhttp_h3`) used quinn's default step, so on an uplink narrower than the 1452 ceiling the binary search settled up to ~20 bytes short (about 1420 behind a 1448-byte provider tunnel), too small for an SS2022 record of a 1350-byte packet (~1408 bytes); such packets rode the stream as `outline_ws_udp_h3_datagram_fallback_total{direction="up",reason="too_large"}`. The search now gets within 4 bytes at the cost of one or two extra probes per connection. The Initial size (1200), the probe ceiling (1452) and the transport parameters are unchanged, so the connection still looks like Chrome's.
```

`bins/outline-ws-rust/CHANGELOG.ru.md`, `## [Unreleased]` → первый `### Изменено`, первой строкой:

```markdown
- **Поиск MTU пути QUIC идёт с шагом 4 байта вместо 20.** H3-носитель (`ws_h3`, `xhttp_h3`) использовал шаг quinn по умолчанию, поэтому на uplink уже потолка 1452 двоичный поиск замирал с недобором до ~20 байт (около 1420 за туннелем провайдера на 1448), а этого мало для SS2022-записи 1350-байтного пакета (~1408 байт); такие пакеты шли по потоку как `outline_ws_udp_h3_datagram_fallback_total{direction="up",reason="too_large"}`. Теперь поиск доходит до предела с точностью 4 байта ценой одной-двух лишних проб на соединение. Размер Initial (1200), потолок проб (1452) и транспортные параметры не изменились — соединение по-прежнему выглядит как у Chrome.
```

- [ ] **Step 7: fmt + clippy пакета**

Run: `cargo fmt -p outline-transport && cargo clippy -p outline-transport --all-targets --all-features --no-deps -- -D warnings`
Expected: без предупреждений. Коммит — НЕ делать.

---

### Task 3: Гейт целиком

- [ ] **Step 1: fmt как в CI** (через `bash -c`, иначе zsh не разобьёт список пакетов)

Run: `bash -c 'cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto'`
Expected: exit 0. `git status` не должен показывать изменений в `vendor/`.

- [ ] **Step 2: clippy как в CI**

Run: `cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings && cargo clippy -p outline-ss-rust --no-default-features --all-targets --no-deps -- -D warnings && cargo clippy -p outline-ws-rust --no-default-features --all-targets --no-deps -- -D warnings`
Expected: exit 0.

- [ ] **Step 3: тесты**

Run: `cargo test --workspace --exclude sockudo-ws`, затем `cargo test -p outline-transport --all-features`, затем `RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls --test 'e2e_*' -- --test-threads=1`
Expected: 0 failed во всех трёх.

- [ ] **Step 4: android**

Run: `cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings`
Expected: exit 0.

- [ ] **Step 5: инварианты CI**

Выполнить шаги `invariant — …` из `.github/workflows/ci.yml` (job «feature matrix + monorepo invariants»), плюс `cargo check --workspace --exclude sockudo-ws`.
Expected: все `ok:`, ни одного `INVARIANT FAILED`.

- [ ] **Step 6: Linux в docker**

`rust:bookworm`, bind-mount пустого файла поверх `/w/.cargo/config.toml`, `CARGO_TARGET_DIR` в docker volume (не в репозиторий), `apt-get install -y cmake clang pkg-config`. Прогнать clippy и `cargo test --workspace --exclude sockudo-ws` БЕЗ `RUN_E2E_FAILOVER`, отдельно `cargo test -p outline-transport --all-features` и e2e с `RUN_E2E_FAILOVER=1 … --test-threads=1`.
Expected: 0 failed. На Linux quinn шлёт GSO-пачками — реле в тестах получает их уже разрезанными ядром, но если тест сходимости на Linux ведёт себя иначе, чем на macOS, разобраться до коммита.

- [ ] **Step 7: Сдать владельцу**

Показать `git diff --stat` и итоги гейта. Коммит — только по команде: одним коммитом `git commit -- <пути из списка «Файлы»>`, сообщение по-английски, без атрибуции, например `fix(quic): search the path MTU in 4-byte steps so SS records fit H3 datagrams on narrow paths`.

---

### Task 4: Раскатка и проверка эффекта (только с согласия владельца)

- [ ] **Step 1:** Сборка из закоммиченного `main`: `cargo zigbuild --release -p outline-ss-rust -p outline-ws-rust --target {x86_64,aarch64}-unknown-linux-musl`, бинари сразу копировать в staging.
- [ ] **Step 2:** Серверы по одному через `ops/deploy/deploy-binary.sh`, с уводом клиентов (`POST /control/activate … soft`) перед каждым exit-узлом и группы `russia` перед .104/.102; затем клиенты cloud1, cloud2, .104, .102. Проверка после каждого: юнит active, ERROR/panic = 0, uplink health = 1. Выбор uplink вернуть к состоянию до раскатки.
- [ ] **Step 3:** Через 1–2 ч сравнить в VictoriaMetrics с замером до (2026-11-02, окно 2 ч: nuxt2 SS `too_large` ws_h3 6010 / xhttp_h3 3704; MTU nuxt2 p50 ≈ 1429):
  - `histogram_quantile(0.5, sum by (instance,le)(increase(outline_ss_quic_path_mtu_bytes_bucket{instance="nuxt2"}[1h])))` — ожидается сдвиг в бакет 1440–1452;
  - `sum by (transport)(increase(outline_ss_udp_h3_datagram_fallback_total{instance="nuxt2",proto="ss",reason="too_large"}[2h]))` против `…datagrams_total{direction="down",proto="ss"}` — доля должна упасть в разы;
  - `sum by (instance)(increase(outline_ss_quic_mtu_probes_lost_total[1h]))` — рост ожидаем (больше проб у предела), но не на порядки.
- [ ] **Step 4:** Записать результат в память проекта (`h3-datagram-padding-fallback.md`).
