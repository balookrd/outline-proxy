# Спецификация и пошаговый план реализации: быстрое обнаружение недоступности аплинков (1–5 с), DPI-безопасное схлопывание каскада и Exit Affinity (Вариант Б)

**Дата:** 2026-11-25  
**Статус:** Готово к реализации (self-contained blueprint для выполнения по шагам)  
**Затронутые пакеты:** `outline-wire`, `outline-transport`, `outline-uplink`, `outline-tun`, `outline-client`, `outline-server`

---

## Инструкция для агента-исполнителя

Этот документ составлен так, чтобы его можно было выполнить последовательно без дополнительного исследования кодовой базы. При выполнении строго соблюдай правила монорепо (`AGENTS.md`):

1. **Никаких реальных доменов и IP парка в коде, тестах, комментариях и документации.** Используй только RFC 2606 / RFC 5737 (`fleet.example`, `exit-a.fleet.example`, `exit-b.fleet.example`, `relay-a.fleet.example`, `198.51.100.x`, `203.0.113.x`).
2. **Терминология в русских текстах:** `carrier` переводить как «носитель» или оставлять `carrier` (никогда не писать «карьер»); `gate` — «гейт» или `gate` (никогда не писать «ворота»).
3. **Очистка артефактов компиляции:** после прогона тестов каждой задачи удаляй промежуточные бинарники (`cargo clean -p <crate>` или очистка `target/debug/deps`), чтобы не забивать диск.
4. **Двуязычная документация:** при обновлении любого `docs/*.md` или `README.md` синхронно обновляй парный `*.ru.md`.
5. **Никаких деплоев на хосты без явной команды пользователя.**

---

## 1. Контекст, корневые причины задержки 30–120 с и целевая архитектура

### 1.1. Почему сейчас переключение при падении узла или маршрута занимает 30–120 секунд

1. **Единый 10-секундный бюджет на каждый шаг `DialPlan` (`crates/outline-transport/src/dial_timeouts.rs`):**
   - `fresh_connect_timeout()` по умолчанию равен `10s`.
   - При дозвоне по одному проводу в режиме `h3` (`connect_ws_h3_with_fallback` / `connect_xhttp_h3_with_fallback` в `crates/outline-transport/src/dial_plan.rs`) клиент последовательно ждёт:
     - `QUIC / H3` (`10s`) → фоллбэк на `TCP / H2` (`10s`) → фоллбэк на `TCP / H1.1` (`10s`).
   - Даже когда узел физически недоступен (blackhole на маршруте, `SYN` и `QUIC Initial` уходят в пустоту), после таймаута `TCP / H2` клиент всё равно делает вторую попытку `TCP / H1.1` на **тот же самый** `host:port`, теряя ещё 10 секунд. Итого до **30 секунд на один провод**.
2. **Слепой перебор всех 4 проводов (`ws_h3`, `xhttp_h3`, `ws_h2`, `xhttp_h2`) к одному и тому же `host:port` (`crates/outline-uplink/src/manager/wire_dial.rs`):**
   - В конфигурации парка все 4 провода одного аплинка смотрят на один и тот же серверный `host:port`.
   - `dial_over_wires` при `allow_fallbacks = true` перебирает все провода из `wire_order`. Если `host:port` недоступен на уровне L4, перебор 4 проводов занимает до `4 × 30s = 120s`.
3. **Гейт раунда проводов и `min_failures` в `report_runtime_failure_inner` (`crates/outline-uplink/src/manager/failures.rs`):**
   - При `shuffle_wires = true` (включено по умолчанию в `strict_active_uplink`) единичный сбой провода не увеличивает `consecutive_failures` аплинка, пока в текущем раунде не упадут все `total_wires` проводов (`wires_failed_in_round >= total_wires`).
4. **Задержка фонового пробника (`crates/outline-uplink/src/manager/failures.rs`, `probe/scheduler.rs`):**
   - Дебаунс пробуждения пробника `PROBE_WAKEUP_MIN_INTERVAL` захардкожен в `15s`.
   - В `run_probe_attempt_with_timeout` быстрая TCP-проверка `unreachable_uplink_endpoints` запускается **только после** того, как основной WS/HTTP-пробник уже упал по своему полному таймауту (до `21s`).
5. **Миграция живого TUN TCP-потока при `CarrierDeath` (`crates/outline-tun/src/tcp/engine/tasks/upstream/migrate.rs`):**
   - При обрыве носителя (`MigrationTrigger::CarrierDeath`) поток пытается переподключиться только к своему старому `plan.uplink_index`. Если старый аплинк умер целиком, поток не запрашивает резервный аплинк из `shared_resume`-кластера и рвётся.

### 1.2. Целевые требования и инварианты

1. **Время переключения 1–5 секунд при сохранении маскировки от DPI:**
   - Никакого параллельного веерного дозвона (fan-out) сразу по всем 4 проводам или всем серверам.
   - На сетевом уровне сбой должен выглядеть как естественное поведение браузера: **1 попытка QUIC Initial (`2.0 с`) → 1 попытка TCP SYN (`2.0 с`) → отказ от `host:port` (~4.0 с суммарно, либо ~2.0 с для `h2`-провода)**.
   - Если сервер ответил хотя бы одним UDP-пакетом (QUIC `ServerHello`/`Retry`) или завершил `TCP connect()` (L4 жив, идёт передача сертификатов и TLS/HTTP-рукопожатие), сохраняется полный бюджет `fresh_connect_timeout()` (`10s`), чтобы не рвать соединение на загруженных каналах.
2. **Две ветки поведения: Server/Desktop vs Android Battery-Safe:**
   - На серверной инфраструктуре и десктопах (Linux, macOS, Windows) при стандартном `dial_timeout = 10s` действуют быстрые пороги (`l4_connect_timeout = 2.0s`, `reused_h3_open_floor = 1.5s`, дебаунс пробуждения пробника `2s`, параллельный watchdog `endpoint_check` через `1.5–2.0s`).
   - На Android (`MobilePowerConfig.kt` + `DialTimeout.kt`) **энергопотребление не увеличивается**:
     - `probe.interval_secs >= 300`, `warm_standby = 0`, `loss_sample_interval_secs = 0` и растянутые H2/QUIC keepalive остаются без изменений.
     - `l4_connect_timeout()` масштабируется пропорционально `fresh_connect_timeout()` (`2/10` от общего бюджета с ограничением `1.5s..=15s`): на Wi-Fi/LTE (`10s`) → `2.0s`, на 3G (`30s`) → `6.0s`, на 2G (`60s`) → `12.0s`.
     - Дебаунс пробуждения пробника остаётся `15s`, когда `probe.interval >= 60s`.
     - Короткое замыкание мёртвого `host:port` (`EndpointUnreachable`) **экономит батарею** на Android: модем делает 1 QUIC + 1 TCP попытку вместо 12 пустых рукопожатий по 4 проводам в течение 120 секунд.
3. **Exit Affinity (Вариант Б) — замена точки входа при сохранении точки выхода:**
   - **Уровень 1 (тот же сервер, другой маршрут / ISP):** при автоматическом аварийном переключении (`SwitchIntent::Failover`) компаратор `failover_order` при равном весе (`weight`) отдаёт приоритет здоровому аплинку с тем же основным `host`, что и у упавшего активного аплинка (например, `exit-a-msk → exit-a-bee` раньше, чем `exit-b-msk`).
   - **Уровень 2 (сосед по кластеру как точка входа, исходный сервер как точка выхода через mesh `9443/udp`):** в кластерной группе с `shared_resume = true` после автоматического переключения (`SwitchIntent::Failover`) с сервера `A` на соседа `B`:
     - Живые сессии мигрируют на `B` через `X-Outline-Resume` и продолжают выходить в интернет через `A` по mesh `9443/udp`.
     - **Новые сессии** (TCP, SS-UDP, VLESS-UDP, VLESS-Mux) передают заголовок `X-Outline-Home-Affinity: <pinned_home_session_id>` (шаблонный `SessionId` с шардом сервера `A`).
     - Сервер `B` (edge) извлекает `ShardId` сервера `A`, генерирует новый уникальный `SessionId` с тем же `ShardId` сервера `A` и открывает новую сессию через mesh-стрим на сервере `A` (`FLAG_HOME_AFFINITY`).
     - Если сервер `A` полностью мёртв (не отвечает и по mesh `9443/udp` за `1.2s`), сервер `B` прозрачно открывает сессию локально у себя и возвращает `X-Outline-Session` со своим шардом `B` — клиент автоматически обновляет `pinned_home_id` на шард `B` и больше не ждёт мёртвый `A`.
   - **Сброс Exit Affinity при ручном и плановом переключении:**
     - Ручное переключение (`SwitchIntent::OperatorHard` через `/control/activate` или `/switch`) и плановый/ручной реселект (`SwitchIntent::OperatorSoft` в `reselect_at`, `reselect_interval`, `/control/reselect`) **полностью сбрасывают** `home_affinity_active = false` и `pinned_home_id = None`. Новые сессии после ручного или планового переключения выходят напрямую с нового выбранного сервера.

---

## 2. Архитектура изменений по компонентам

### 2.1. Двухфазные таймауты L4 и пула (`crates/outline-transport`)

#### A. `crates/outline-transport/src/dial_timeouts.rs`
Добавляем расчёт бюджета установки L4-соединения (`l4_connect_timeout`) и адаптивный пол открытия стрима в переиспользуемом H3-соединении (`reused_h3_open_floor`):

```rust
/// Share of the fresh-connect budget granted to bare L4 reachability
/// (TCP `connect()` or receiving the first UDP datagram of a QUIC handshake):
/// 2/10 of `fresh_connect_timeout()`, clamped to `[1500ms, 15s]`.
///
/// At the default 10s budget this is 2.0s; on Android 3G (30s) it scales to
/// 6.0s; on 2G (60s) to 12.0s.
const L4_CONNECT_NUMERATOR: u32 = 2;
const L4_CONNECT_DENOMINATOR: u32 = 10;
const MIN_L4_CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);
const MAX_L4_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Minimum floor for opening a stream on an existing shared H3 connection on
/// desktop/server (10s dial budget), scaling up to 3s on slow mobile links.
const MIN_REUSED_H3_OPEN_FLOOR: Duration = Duration::from_millis(1500);
const MAX_REUSED_H3_OPEN_FLOOR: Duration = Duration::from_secs(3);

pub fn l4_connect_timeout() -> Duration {
    let base = fresh_connect_timeout();
    let scaled = (base * L4_CONNECT_NUMERATOR) / L4_CONNECT_DENOMINATOR;
    scaled.clamp(MIN_L4_CONNECT_TIMEOUT, MAX_L4_CONNECT_TIMEOUT)
}

pub fn reused_h3_open_floor() -> Duration {
    let base = fresh_connect_timeout();
    let scaled = (base * 3) / 20;
    scaled.clamp(MIN_REUSED_H3_OPEN_FLOOR, MAX_REUSED_H3_OPEN_FLOOR)
}
```

В `reused_h3_open_budget(remaining: Duration) -> Duration` заменяем использование константы `REUSED_H3_OPEN_FLOOR` на `reused_h3_open_floor()` (константу `pub const REUSED_H3_OPEN_FLOOR: Duration = Duration::from_millis(1500);` оставляем для обратной совместимости экспортов).

#### B. Типизированные маркеры ошибок L4 в `crates/outline-transport/src/lib.rs`
Рядом с `DownstreamThrottle`, `WsClosed`, `TryAgain` (строки 75–135 `crates/outline-transport/src/lib.rs`) добавляем два маркера и экспортируем их из корня крейта:

```rust
/// Typed error marker attached when an L4 connection attempt (TCP `connect()`
/// or QUIC initial packet exchange before the peer sends a single UDP
/// datagram) times out or fails with an immediate OS reachability error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L4ConnectError;

impl fmt::Display for L4ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("L4 transport connect failed or timed out before peer response")
    }
}

impl std::error::Error for L4ConnectError {}

/// Typed error marker attached when a target `host:port` is unreachable at L4
/// across transport families (e.g. QUIC initial received 0 datagrams and TCP
/// `connect()` also failed at L4, or the highest configured TCP mode failed at
/// L4). Signals `outline-uplink` to skip remaining wires sharing the same
/// `host:port` and immediately trigger uplink failover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointUnreachable;

impl fmt::Display for EndpointUnreachable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("endpoint host:port is unreachable at L4")
    }
}

impl std::error::Error for EndpointUnreachable {}
```

В функции `pub(crate) async fn connect_tcp_socket(addr: SocketAddr, mark: SocketMark) -> Result<TcpStream>` (`crates/outline-transport/src/lib.rs:251-257`) оборачиваем вызов `outline_net::connect_tcp_socket` в `tokio::time::timeout(dial_timeouts::l4_connect_timeout(), ...)` и помечаем ошибки недоступности L4 маркером `L4ConnectError`:

```rust
fn is_l4_io_error(err: & std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::TimedOut
    )
}

pub(crate) async fn connect_tcp_socket(addr: SocketAddr, mark: SocketMark) -> Result<TcpStream> {
    let budget = dial_timeouts::l4_connect_timeout();
    match tokio::time::timeout(budget, outline_net::connect_tcp_socket(addr, mark)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(err)) => {
            let classify_l4 = err
                .chain()
                .find_map(|cause| cause.downcast_ref::<std::io::Error>())
                .is_some_and(is_l4_io_error);
            let err = if classify_l4 {
                err.context(L4ConnectError)
            } else {
                err
            };
            Err(err.context(TransportOperation::Connect { addr }))
        },
        Err(_elapsed) => Err(anyhow::anyhow!(
            "TCP connect to {addr} timed out after {budget:?}"
        )
        .context(L4ConnectError)
        .context(TransportOperation::Connect { addr })),
    }
}
```

#### C. Сохранение цепочки типизированных ошибок в `crates/outline-transport/src/shared_dial.rs`
В `resolve_and_dial` (`crates/outline-transport/src/shared_dial.rs:148-185`) при переборе DNS-адресов ошибка `dialer.establish(addr, &ctx).await` сейчас превращается в строку `errors.push(format!("{addr}: {e}"))`, из-за чего `find_typed::<L4ConnectError>` теряется!
Исправляем `resolve_and_dial`:

```rust
    let mut errors = Vec::new();
    let mut all_l4_errors = true;
    for addr in addrs {
        let _permit = dialer.acquire_permit().await?;
        match dialer.establish(addr, &ctx).await {
            Ok(conn) => return Ok(conn),
            Err(e) => {
                if crate::find_typed::<crate::L4ConnectError>(&e).is_none() {
                    all_l4_errors = false;
                }
                if let Some(secs) = dialer.retry_after_secs(&e) {
                    return Err(anyhow!(
                        "{} connection to {} refused with Retry-After={secs}s: {e:#}",
                        dialer.protocol_name(),
                        ctx.host,
                    )
                    .context(crate::DownstreamThrottle { retry_after_secs: secs }));
                }
                errors.push(format!("{addr}: {e:#}"));
            },
        }
    }

    let base_err = anyhow::Error::new(crate::TransportOperation::Connect {
        addr: SocketAddr::from(([0, 0, 0, 0], ctx.port)),
    });
    let base_err = if all_l4_errors && !errors.is_empty() {
        base_err.context(crate::L4ConnectError)
    } else {
        base_err
    };
    Err(base_err.context(format!(
        "failed to establish {} connection to {}:{} ({})",
        dialer.protocol_name(),
        ctx.host,
        ctx.port,
        errors.join("; ")
    )))
```

Также проверяем `crates/outline-transport/src/xhttp/h1.rs` и `crates/outline-transport/src/ws/connect.rs`: если там перебираются `addrs` в цикле с накоплением ошибок в `Vec<String>` или `last_error: Option<anyhow::Error>`, гарантируем, что `last_error` сохраняется как `anyhow::Error` (а не форматируется в строку с потерей типов) либо при `all_l4_errors` на итоговую ошибку навешивается `.context(crate::L4ConnectError)`.

#### D. Быстрый L4-watchdog для QUIC Initial без DPI-всплеска (`crates/outline-transport/src/quic/dial_race.rs`)
В `crates/outline-transport/src/quic/dial_race.rs`:
1. Меняем `pub(crate) const HEDGE_SCHEDULE: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(3)];` на однократный мягкий хедж до истечения 2-секундного L4-бюджета:
   ```rust
   pub(crate) const HEDGE_SCHEDULE: [Duration; 1] = [Duration::from_millis(800)];
   ```
   Это гарантирует не более 1 дополнительной попытки на другом эфемерном UDP-порту (отсутствие паттерна UDP-сканера для DPI).
2. В `race_handshake` (`crates/outline-transport/src/quic/dial_race.rs:84-177`) добавляем L4-watchdog по `crate::dial_timeouts::l4_connect_timeout()`:
   - Храним список `quinn::Connection` (или клонируем хэндлы `Connection` при старте каждой попытки в `connections: Vec<quinn::Connection>`). Для этого в `AttemptFuture` возвращаем `(quinn::Connection, BoxFuture<'a, Result<T>>)` из `spawn` или добавим альтернативный вход / проверку, либо проще:
   - В `connect_hedged` (`dial_race.rs:42-70`) в замыкании `attempt`: `connecting` (`quinn::Connecting`) до `.await` ещё не даёт `quinn::Connection`, но `endpoint.stats().udp_rx.datagrams` на свежесозданном клиентском `quinn::Endpoint` (`create_client_endpoint_with_socket` в `h3/shared.rs:781` и `xhttp/h3_pool.rs:341`, где под каждое QUIC-соединение создаётся свой клиентский `Endpoint`) считает **все принятые UDP-датаграммы** этого эндпоинта!
   - Проверяем `endpoint.stats().udp_rx.datagrams`: поскольку каждый вызов `connect_hedged` создаёт собственные клиентские `Endpoint` внутри `attempt`, достаточно в `connect_hedged` передавать счётчик принятых датаграмм или зарегистрировать созданные `Endpoint` в общем `Arc<Mutex<Vec<quinn::Endpoint>>>`:
     ```rust
     let endpoints: Arc<parking_lot::Mutex<Vec<quinn::Endpoint>>> =
         Arc::new(parking_lot::Mutex::new(Vec::new()));
     ```
     При создании `endpoint` внутри `attempt` добавляем `endpoints.lock().push(endpoint.clone())`.
   - В `race_handshake` взводим таймер `let l4_deadline = tokio::time::Instant::now() + crate::dial_timeouts::l4_connect_timeout(); let mut l4_checked = false;`.
   - Когда `tokio::time::sleep_until(l4_deadline)` срабатывает (`!l4_checked`):
     - Проверяем, пришёл ли хотя бы 1 UDP-пакет от сервера:
       `let rx_datagrams: u64 = endpoints.lock().iter().map(|ep| ep.stats().udp_rx.datagrams).sum();`
     - Если `rx_datagrams == 0`: немедленно прерываем все `in_flight` попытки и возвращаем:
       ```rust
       return Err(anyhow::anyhow!(
           "QUIC initial handshake with {server_name} ({remote}) received 0 UDP datagrams within {:?}",
           crate::dial_timeouts::l4_connect_timeout()
       )
       .context(crate::L4ConnectError));
       ```
     - Если `rx_datagrams > 0` (сервер живой на L4, прислал `ServerHello` / `Retry` / фрагменты сертификата): ставим `l4_checked = true` и даём рукопожатию спокойно завершиться в пределах полного `fresh_connect_timeout()` (`10s`).

#### E. Пропуск бессмысленного `HTTP/1.1` после L4-сбоя `H2` и пометка `EndpointUnreachable` (`crates/outline-transport/src/dial_plan.rs`)
В `crates/outline-transport/src/dial_plan.rs`:
1. В `connect_ws_h2_with_h1_fallback` (строки 474–507):
   - Если `connect_websocket_h2` вернул `Err(h2_error)` и `crate::find_typed::<crate::L4ConnectError>(&h2_error).is_some()`:
     - **Не вызываем** `connect_websocket_http1` (TCP `connect()` на этот `host:port` только что упал на уровне L4 — повторный `SYN` для HTTP/1.1 бессмысленен).
     - Сразу возвращаем `Err(h2_error.context(crate::EndpointUnreachable))`.
2. В `connect_xhttp_h2_with_h1_fallback` (строки 596–634):
   - Если `xhttp::connect_xhttp(..., TransportMode::XhttpH2, ...)` вернул `Err(h2_error)`:
     - При `find_typed::<DownstreamThrottle>(&h2_error).is_some()` — как и раньше, сразу возвращаем `Err(h2_error)`.
     - При `crate::find_typed::<crate::L4ConnectError>(&h2_error).is_some()` — **не вызываем** `TransportMode::XhttpH1`, сразу возвращаем `Err(h2_error.context(crate::EndpointUnreachable))`.
3. В `connect_websocket_http1` / прямом `XhttpH1` (когда провод сконфигурирован в режиме `http1`):
   - Если вызов вернул `Err(err)` с `L4ConnectError`, навешиваем `.context(crate::EndpointUnreachable)`.

**Результат для одного провода при недоступном `host:port`:**
- Провод `ws_h3` / `xhttp_h3`: `2.0s` (QUIC 0 datagrams) + `2.0s` (TCP H2 connect timeout, H1 пропущен) = **`4.0s`** (вместо `30.0s`) и ошибка помечена `EndpointUnreachable`.
- Провод `ws_h2` / `xhttp_h2`: `2.0s` (TCP H2 connect timeout, H1 пропущен) = **`2.0s`** (вместо `20.0s`) и ошибка помечена `EndpointUnreachable`.

---

### 2.2. Схлопывание каскада проводов и мгновенный фейловер (`crates/outline-uplink` и `crates/outline-tun`)

#### A. Пропуск остальных проводов с тем же мёртвым `host:port` (`crates/outline-uplink/src/manager/wire_dial.rs`)
В `crates/outline-uplink/src/manager/wire_dial.rs`:
Добавляем ключ L4-эндпоинта провода:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct WireEndpointKey {
    host: String,
    port: u16,
    fwmark: Option<u32>,
    dscp: Option<u8>,
    ipv6_first: bool,
    ipv4_only: bool,
}

fn wire_endpoint_key(
    candidate: &UplinkCandidate,
    wire: u8,
    transport: TransportKind,
) -> Option<WireEndpointKey> {
    let spec = WireSpec::of(&candidate.uplink, wire);
    let url = spec.dial_url(match transport {
        TransportKind::Tcp => TransportPlane::Tcp,
        TransportKind::Udp => TransportPlane::Udp,
    })?;
    let host = url.host_str()?.to_ascii_lowercase();
    let port = url.port_or_known_default()?;
    Some(WireEndpointKey {
        host,
        port,
        fwmark: spec.fwmark,
        dscp: spec.dscp,
        ipv6_first: candidate.uplink.ipv6_first,
        ipv4_only: candidate.uplink.ipv4_only,
    })
}
```

В `UplinkManager::dial_over_wires` (`wire_dial.rs:64-156`):
- Заводим `let mut dead_endpoints: std::collections::HashSet<WireEndpointKey> = std::collections::HashSet::new();`.
- Перед вызовом `build(wire).await`:
  ```rust
  let ep_key = wire_endpoint_key(candidate, wire, transport);
  if let Some(ref key) = ep_key
      && dead_endpoints.contains(key)
  {
      if allow_fallbacks {
          self.record_wire_outcome(candidate.index, transport, wire, false, total_wires);
      }
      debug!(
          uplink = %candidate.uplink.name,
          transport = transport.as_str(),
          wire_idx = wire,
          wire_name = wire_label(candidate, wire),
          host = %key.host,
          port = key.port,
          "skipping fallback wire pointing to already-unreachable L4 endpoint"
      );
      continue;
  }
  ```
- В ветке `Err(error)`:
  ```rust
  if outline_transport::find_typed::<outline_transport::EndpointUnreachable>(&error).is_some()
      && let Some(key) = ep_key
  {
      dead_endpoints.insert(key);
  }
  ```
- При формировании финальной ошибки (`Err(last_error.unwrap_or_else(...))`): поскольку `last_error` — это ошибка от реально выполненного `build(wire).await`, в её цепочке сохраняется маркер `EndpointUnreachable`.

**Результат:** все 4 провода мёртвого аплинка завершаются за **`2.0–4.0 с`** вместо `120 с`.

#### B. Немедленный перевод аплинка в `unhealthy` при `EndpointUnreachable` и адаптивный дебаунс пробника (`crates/outline-uplink/src/manager/failures.rs`)
В `crates/outline-uplink/src/manager/failures.rs`:
1. Вместо фиксированной константы `const PROBE_WAKEUP_MIN_INTERVAL: Duration = Duration::from_secs(15);` добавляем метод:
   ```rust
   const FAST_PROBE_WAKEUP_MIN_INTERVAL: Duration = Duration::from_secs(2);
   const BATTERY_SAFE_PROBE_WAKEUP_MIN_INTERVAL: Duration = Duration::from_secs(15);
   const BATTERY_SAFE_PROBE_INTERVAL_THRESHOLD: Duration = Duration::from_secs(60);

   fn probe_wakeup_min_interval(&self) -> Duration {
       if self.inner.probe.interval >= BATTERY_SAFE_PROBE_INTERVAL_THRESHOLD {
           BATTERY_SAFE_PROBE_WAKEUP_MIN_INTERVAL
       } else {
           FAST_PROBE_WAKEUP_MIN_INTERVAL
       }
   }
   ```
   На серверах и десктопах (`probe.interval = 10–15s`) пробник просыпается с дебаунсом **`2s`**; на Android (`probe.interval = 300s`) сохраняется **`15s`**.
2. В `report_runtime_failure_inner` (`failures.rs:289-435`):
   - Вычисляем:
     ```rust
     let endpoint_unreachable =
         outline_transport::find_typed::<outline_transport::EndpointUnreachable>(error).is_some();
     ```
   - Если `endpoint_unreachable` равен `true`, проверяем, все ли сконфигурированные провода этого `transport` смотрят на один и тот же `(host, port)` (или в раунде уже помечены все провода):
     ```rust
     let single_endpoint_uplink = self
         .inner
         .uplinks
         .get(index)
         .is_some_and(|u| uplink_shares_single_endpoint(u, transport));
     ```
     Где `uplink_shares_single_endpoint(uplink: &UplinkConfig, transport: TransportKind) -> bool` проверяет, что для всех `wire_idx` в `0..uplink.wires_len()` их `(host, port)` совпадают.
   - Когда `endpoint_unreachable && single_endpoint_uplink`:
     - Обходим гейт `shuffle_wires` и гейт `runtime_failure_threshold` (`min_failures`): сразу выставляем `plane.wires_failed_in_round = 0`, увеличиваем `plane.consecutive_failures = plane.consecutive_failures.max(threshold)`, выставляем `plane.healthy = Some(false)`, `plane.cooldown_until = Some(Instant::now() + self.inner.load_balancing.failure_cooldown)`.
     - Записываем `failover_trigger = Some((current_transport_rtt, plane.consecutive_failures))` для немедленного переключения активного аплинка и пробуждения пробника.

#### C. Параллельный L4-watchdog в фоновом пробнике (`crates/outline-uplink/src/manager/probe/scheduler.rs`)
В `run_probe_attempt_with_timeout` (`crates/outline-uplink/src/manager/probe/scheduler.rs:514-573`):
Сейчас `unreachable_uplink_endpoints` вызывается только *после* того, как `probe_task` завершился с ошибкой или по 21-секундному `attempt_budget`.
Добавляем параллельный watchdog, который запускается только если `probe_task` не успел завершиться за `probe.endpoint_check_timeout` (`1.5–2.0s`):

```rust
    let mut probe_task = tokio::spawn(async move {
        run_uplink_probe_once(&task_group, &task_uplink, &task_probe, &task_dns_cache).await
    });

    let endpoint_watchdog_delay = if probe.endpoint_check {
        probe.endpoint_check_timeout.max(Duration::from_millis(500))
    } else {
        attempt_budget + Duration::from_secs(1)
    };

    let outcome = tokio::select! {
        joined = tokio::time::timeout(attempt_budget, &mut probe_task) => {
            match joined {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(join_error)) => UplinkProbeOutcome {
                    tcp_ok: false,
                    udp_ok: false,
                    latency: None,
                    detail: format!("probe task failed: {join_error}"),
                },
                Err(_) => {
                    probe_task.abort();
                    let _ = probe_task.await;
                    UplinkProbeOutcome {
                        tcp_ok: false,
                        udp_ok: false,
                        latency: None,
                        detail: format!("probe timed out after {}ms", attempt_budget.as_millis()),
                    }
                }
            }
        }
        Some(endpoints) = async {
            tokio::time::sleep(endpoint_watchdog_delay).await;
            unreachable_uplink_endpoints(
                &dns_cache,
                &group,
                &uplink,
                probe.endpoint_check_timeout,
            )
            .await
        }, if probe.endpoint_check => {
            probe_task.abort();
            let _ = probe_task.await;
            UplinkProbeOutcome {
                tcp_ok: false,
                udp_ok: false,
                latency: None,
                detail: format!("probe aborted by L4 endpoint watchdog ({endpoints})"),
            }
        }
    };
```
Заметь: если живой узел отвечает на пробник быстрее `endpoint_check_timeout` (обычно за 50–300 мс), ветка `sleep(endpoint_watchdog_delay)` отменяется и **не создаёт ни одного лишнего TCP-соединения**. Если же узел завис в blackhole, через `~1.5–3.0 с` watchdog параллельно проверяет TCP L4 и мгновенно прерывает зависший 21-секундный пробник!

#### D. Спасение живых TUN TCP-потоков через резервный аплинк при смерти носителя (`crates/outline-tun/src/tcp/engine/tasks/upstream/migrate.rs`)
В `migrate_to_fresh_carrier` (`crates/outline-tun/src/tcp/engine/tasks/upstream/migrate.rs:141-215`):
Когда `trigger` равен `MigrationTrigger::CarrierDeath` и `redial_tcp_uplink_for_migration` на исходном `candidate` (`plan.uplink_index`) завершается ошибкой `Err(err)`:
1. Сообщаем менеджеру об ошибке рантайма:
   ```rust
   plan.manager
       .report_runtime_failure(plan.uplink_index, outline_uplink::TransportKind::Tcp, &err)
       .await;
   ```
2. Если `plan.manager.shared_resume()` включён (`true`), запрашиваем `let failovers = plan.manager.tcp_failover_candidates(&plan.target, plan.uplink_index).await;`.
3. Если в `failovers` найден здоровый альтернативный кандидат `alt` с `alt.index != plan.uplink_index`, выполняем `redial_tcp_uplink_for_migration(plan, &alt, None, resume_opts).await` (с тем же `plan.session_id`!) и устанавливаем `rebind_to = Some(alt.index)`.
4. Если исходный сервер `A` жив в кластере, а упал только маршрут клиент → `A`, соседний сервер `B` принимает `X-Outline-Resume` и пробрасывает живой TCP-поток через mesh `9443/udp` на `A` без разрыва клиентского соединения!

---

## 3. Разделение профилей: Server/Desktop vs Android Battery-Safe

Никаких новых обязательных полей в TOML не требуется — разделение работает автоматически от уже существующих бюджетов `DialTimeout.kt` и `probe.interval_secs` (`MobilePowerConfig.kt`):

| Параметр | Серверная инфраструктура и Desktop (Linux / macOS / Windows) | Android (`MobilePowerConfig.kt` + `DialTimeout.kt`) | Влияние на батарею Android |
|---|---|---|---|
| `fresh_connect_timeout()` | `10s` | Wi-Fi/LTE: `10s`, 3G: `30s`, 2G: `60s` | Без изменений |
| `l4_connect_timeout()` | **`2.0s`** (`10s × 2/10`) | Wi-Fi/LTE: **`2.0s`**, 3G: **`6.0s`**, 2G: **`12.0s`** | Адаптируется к типу радиосети |
| `reused_h3_open_floor()` | **`1.5s`** | Wi-Fi/LTE: **`1.5s`**, 3G/2G: **`3.0s`** | Не рвёт H3 при выходе модема из RRC Idle |
| Схлопывание 4 проводов при `EndpointUnreachable` | Включено (**`2–4s`** вместо `120s`) | Включено (**`2–4s`** на LTE вместо `120s`) | **Экономит батарею** (2 пакета вместо 12 рукопожатий) |
| `probe_wakeup_min_interval` | **`2s`** (т.к. `probe.interval < 60s`) | **`15s`** (т.к. `probe.interval = 300s >= 60s`) | Радиомодем не будится чаще прежнего |
| `warm_standby` / `loss_sample` | По конфигу узла | `0` / `0` (отключены в `MobilePowerConfig.kt`) | **0% дополнительного расхода** |

---

## 4. Exit Affinity (Вариант Б): замена точки входа при сохранении точки выхода и сброс при ручном/плановом переключении

### 4.1. Уровень 1 — Приоритет резервного маршрута к тому же серверу (`failover_order`)

В `crates/outline-uplink/src/manager/candidates.rs`:
1. Добавляем вспомогательную функцию извлечения основного хоста аплинка:
   ```rust
   pub(super) fn uplink_primary_host(
       uplink: &UplinkConfig,
       transport: TransportKind,
   ) -> Option<&str> {
       let primary_url = match transport {
           TransportKind::Tcp => uplink.tcp_dial_url().or_else(|| uplink.udp_dial_url()),
           TransportKind::Udp => uplink.udp_dial_url().or_else(|| uplink.tcp_dial_url()),
       };
       primary_url.and_then(|u| u.host_str())
   }
   ```
2. В `failover_order` (`candidates.rs:344-379`) добавляем параметр `failed_host: Option<&str>`:
   ```rust
   pub(super) fn failover_order(
       &self,
       left: &CandidateState,
       right: &CandidateState,
       gate_transport: TransportKind,
       failed_host: Option<&str>,
       now: Instant,
   ) -> Ordering
   ```
3. Внутри `failover_order`:
   - Порядок приоритетов:
     1. `healthy_first(left.healthy).cmp(&healthy_first(right.healthy)).reverse()`
     2. Оставшийся `cooldown` (`left_remaining.cmp(&right_remaining)`)
     3. Вес `higher_weight_first(left.uplink.weight, right.uplink.weight)` (основные линки `weight = 1.0` всегда выше резервных `weight = 0.25`)
     4. **Приоритет того же самого выходного хоста (`same_host_first`):**
        ```rust
        let left_same_host = failed_host.is_some_and(|h| {
            uplink_primary_host(&left.uplink, gate_transport)
                .is_some_and(|lh| lh.eq_ignore_ascii_case(h))
        });
        let right_same_host = failed_host.is_some_and(|h| {
            uplink_primary_host(&right.uplink, gate_transport)
                .is_some_and(|rh| rh.eq_ignore_ascii_case(h))
        });
        ```
        Сравниваем `left_same_host.cmp(&right_same_host).reverse()` **перед** сравнением `score` (RTT/penalty)!
     5. `left_score.cmp(&right_score)`
     6. `left.index.cmp(&right.index)`
4. Во всех местах вызова `failover_order` в `candidates.rs` передаём `failed_host`:
   - Хост текущего `current_active` (или `failed_index` в `strict_failover_target`), полученный через `current_active.and_then(|idx| self.inner.uplinks.get(idx)).and_then(|u| uplink_primary_host(u, gate_transport))`.

**Эффект на парке:** если на роутере отвалился `exit-a-msk` (`host = exit-a.fleet.example`, `weight = 1.0`), а `exit-a-bee` (`host = exit-a.fleet.example`, `weight = 1.0`) и `exit-b-msk` (`host = exit-b.fleet.example`, `weight = 1.0`) оба здоровы, роутер гарантированно переключится на `exit-a-bee` — точка входа (ISP) сменилась, а сервер выхода (`exit-a`) остался тем же самым даже без участия mesh.

---

### 4.2. Уровень 2 — Кластерная Mesh Exit Affinity для новых сессий (`x-outline-home-affinity`)

Когда все прямые маршруты к серверу `A` (`exit-a-msk`, `exit-a-bee`) недоступны для клиента, автоматический фейловер переключает активный аплинк на соседа по кластеру `B` (`exit-b-msk`, в группе с `shared_resume = true`).

#### Шаг 1. Заголовок протокола в `crates/outline-wire/src/resume.rs`
В `crates/outline-wire/src/resume.rs` (после `RESUME_SYMMETRIC_REPLAY_HEADER` на строке 39) добавляем константу:

```rust
/// Client → server request header carrying a previously-issued 128-bit
/// [`SessionId`] (32 lowercase hex chars) whose embedded [`ShardId`] identifies
/// the client's pinned home exit server in a `shared_resume` cluster.
///
/// Sent ONLY on brand-new sessions (when [`RESUME_REQUEST_HEADER`] is absent)
/// after an automatic failover (`SwitchIntent::Failover`) so that the new
/// ingress server relays the new session's egress to the original home exit
/// server over the cluster mesh (`9443/udp`).
pub const HOME_AFFINITY_HEADER: &str = "x-outline-home-affinity";
```

Реэкспортируем `HOME_AFFINITY_HEADER` в `crates/outline-transport/src/resumption.rs` (`pub use outline_wire::resume::{HOME_AFFINITY_HEADER, ...};`).

#### Шаг 2. Проброс `home_affinity` в `crates/outline-transport`
1. В `crates/outline-transport/src/dial_plan.rs`:
   - В `DialResumeOptions` (строка 38) добавляем поле:
     ```rust
     /// Optional template [`SessionId`] identifying the pinned home exit shard
     /// for brand-new sessions after an automatic cluster failover. Ignored
     /// when `resume_request` is `Some`.
     pub home_affinity: Option<SessionId>,
     ```
   - В `TransportDialOptions::xhttp_session_open` (`dial_plan.rs:116-123`) пробрасываем `home_affinity: self.resume.home_affinity`.
2. В `crates/outline-transport/src/resumption.rs`:
   - В `apply_resume_request_headers(headers: &mut HeaderMap, opts: DialResumeOptions)` (строка 96):
     ```rust
     if let Some(id) = opts.resume_request {
         if let Ok(v) = HeaderValue::from_str(&id.to_hex()) {
             headers.insert(HeaderName::from_static(RESUME_REQUEST_HEADER), v);
         }
         if let Some(acked) = opts.down_acked
             && let Ok(v) = HeaderValue::from_str(&acked.to_string())
         {
             headers.insert(HeaderName::from_static(RESUME_DOWN_ACKED_HEADER), v);
         }
     } else if let Some(affinity_id) = opts.home_affinity
         && let Ok(v) = HeaderValue::from_str(&affinity_id.to_hex())
     {
         headers.insert(HeaderName::from_static(HOME_AFFINITY_HEADER), v);
     }
     ```
3. В `crates/outline-transport/src/xhttp/mod.rs`:
   - В `pub(crate) struct SessionOpen` (строка 84) добавляем `pub(crate) home_affinity: Option<SessionId>,`.
   - В `build_session_request_headers` (строка 258): если `open.resume_request.is_none()`, при `let Some(affinity_id) = open.home_affinity` добавляем заголовок `(HOME_AFFINITY_HEADER, affinity_id.to_hex())`.
4. В `crates/outline-transport/src/udp_transport.rs` (`UdpWsTransport`), `crates/outline-transport/src/vless/udp.rs` (`VlessUdpWsTransport`), `crates/outline-transport/src/vless/udp_mux.rs` (`VlessUdpSessionMux`):
   - В `UdpWsTransport::connect_with_resume` и `VlessUdpWsTransport::connect_with_resume` принимаем `home_affinity: Option<SessionId>` (или через `DialResumeOptions`), передавая его в `DialResumeOptions { resume_capable, resume_request, down_acked: None, home_affinity }` при первичном подключении (когда `resume_request.is_none()`).
   - В `VlessUdpSessionMux` добавляем callback или поле `home_affinity_fn: Option<Arc<dyn Fn() -> Option<SessionId> + Send + Sync>>` и `on_session_id_fn: Option<Arc<dyn Fn(Option<SessionId>) + Send + Sync>>`, чтобы при открытии новой mux-сессии передавать актуальный `home_affinity` и записывать выданный сервером `issued_session_id()`.

#### Шаг 3. Состояние Exit Affinity в `UplinkManager` (`crates/outline-uplink`)
1. В `crates/outline-uplink/src/manager/state.rs`:
   - В структуру `UplinkManagerInner` добавляем два синхронных поля:
     ```rust
     /// Last server-issued `SessionId` encoding the current home server's
     /// `ShardId` in a `shared_resume` cluster group.
     pub(super) pinned_home_id: SyncMutex<Option<outline_transport::SessionId>>,
     /// `true` after an automatic `SwitchIntent::Failover` in a `shared_resume`
     /// group so brand-new sessions send `x-outline-home-affinity`. Cleared on
     /// manual (`OperatorHard`) or scheduled (`OperatorSoft`) switches.
     pub(super) home_affinity_active: AtomicBool,
     ```
   - Инициализируем их в `UplinkManagerInner::new`:
     `pinned_home_id: SyncMutex::new(None)`, `home_affinity_active: AtomicBool::new(false)`.
2. Добавляем публичные методы на `UplinkManager` (в `crates/outline-uplink/src/manager/state.rs` или `candidates.rs`):
   ```rust
   /// Record a server-issued `SessionId` from a freshly established carrier.
   ///
   /// - When `home_affinity_active` is `false` (normal direct routing), keeps
   ///   `pinned_home_id` updated with the current direct server's shard so a
   ///   future automatic failover knows which home shard to preserve.
   /// - When `home_affinity_active` is `true`, updates `pinned_home_id` with
   ///   the echoed `SessionId`: if the home shard was alive over mesh, the
   ///   edge echoed a `SessionId` with that same home shard; if the home shard
   ///   was dead over mesh, the edge fell back to local exit and echoed a
   ///   `SessionId` with the edge's own shard, automatically re-pinning future
   ///   sessions to the new live exit server.
   pub fn record_issued_session_id(&self, id: Option<outline_transport::SessionId>) {
       if !self.inner.load_balancing.shared_resume {
           return;
       }
       if let Some(sid) = id {
           *self.inner.pinned_home_id.lock() = Some(sid);
       }
   }

   /// Return the template `SessionId` to send in `x-outline-home-affinity` on
   /// brand-new sessions, if exit affinity is currently active.
   pub fn current_home_affinity(&self) -> Option<outline_transport::SessionId> {
       if !self.inner.load_balancing.shared_resume
           || !self.inner.home_affinity_active.load(Ordering::Acquire)
       {
           return None;
       }
       *self.inner.pinned_home_id.lock()
   }

   /// Clear pinned home exit affinity (invoked on manual or scheduled switch).
   pub fn clear_home_affinity(&self) {
       self.inner.home_affinity_active.store(false, Ordering::Release);
       *self.inner.pinned_home_id.lock() = None;
   }
   ```
3. Переключение и сброс в `set_active_uplink_index_for_transport` (`crates/outline-uplink/src/manager/candidates.rs:1389-1484`):
   - Когда `changed` равен `true`:
     - При `intent == SwitchIntent::Failover`:
       ```rust
       if self.inner.load_balancing.shared_resume
           && self.inner.pinned_home_id.lock().is_some()
       {
           self.inner.home_affinity_active.store(true, Ordering::Release);
           // Очищаем warm-standby на новом активном аплинке, чтобы заранее
           // прогретые соединения без заголовка x-outline-home-affinity не использовались.
           self.clear_standby(uplink_index, TransportKind::Tcp).await;
           self.clear_standby(uplink_index, TransportKind::Udp).await;
       }
       ```
     - При `intent == SwitchIntent::OperatorHard || intent == SwitchIntent::OperatorSoft`:
       ```rust
       self.clear_home_affinity();
       self.clear_standby(uplink_index, TransportKind::Tcp).await;
       self.clear_standby(uplink_index, TransportKind::Udp).await;
       ```
   - Важно: в `set_active_uplink_by_name` (`candidates.rs:766`, вызывается при ручном переключении пользователем через UI / API `/control/activate` и `/switch`) и в `reselect_global` / `reselect_per_uplink` (`crates/outline-uplink/src/manager/reselect.rs`, вызывается по расписанию `reselect_at`, `reselect_interval` и `/control/reselect`) также безусловно вызываем `self.clear_home_affinity();` перед или внутри смены активного аплинка (даже если `changed == false`, например пользователь вручную перевыбрал текущий активный сервер, чтобы отключить аффинити к старому выходу!).
   - В `reset_all_uplink_statuses` (`candidates.rs:820`) также вызываем `self.clear_home_affinity();`.
4. Подстановка `current_home_affinity()` и запись `record_issued_session_id(...)` при всех дозвонах в `crates/outline-uplink/src/manager/standby/mod.rs` и `standby/refill.rs`:
   - В `pool_resume_options` (`crates/outline-uplink/src/manager/standby/refill.rs:64-73`):
     ```rust
     pub(in crate::manager) fn pool_resume_options(&self) -> DialResumeOptions {
         DialResumeOptions {
             resume_capable: self.inner.load_balancing.shared_resume,
             resume_request: None,
             down_acked: None,
             home_affinity: self.current_home_affinity(),
         }
     }
     ```
   - В `connect_tcp_ws_fresh_internal` (`standby/mod.rs:367-420`): если `dial.resume.resume_request.is_none()` и `dial.resume.home_affinity.is_none()`, подставляем `dial.resume.home_affinity = self.current_home_affinity()`. После успешного дозвона (`Ok((ws, wire_idx))`) вызываем `self.record_issued_session_id(ws.issued_session_id());`.
   - В `acquire_udp_on_wire` (`standby/mod.rs:607-755`): передаём `self.current_home_affinity()` при создании `UdpWsTransport` / `VlessUdpWsTransport` / `VlessUdpSessionMux` и вызываем `self.record_issued_session_id(...)` при получении `issued_session_id`.

---

#### Шаг 4. Серверная обработка `x-outline-home-affinity` и открытие новой сессии через mesh (`bins/outline-server`)

##### A. Маршрутизация заголовка на Edge (`bins/outline-server/src/server/transport/resume_headers.rs`)
1. В `OrphanRegistry` (`bins/outline-server/src/server/resumption/mod.rs` вокруг `mint_session_id` на строке 498) добавляем метод генерации свежего уникального `SessionId` с заданным чужим `ShardId`:
   ```rust
   /// Mint a fresh unique [`SessionId`] stamped with a specific foreign
   /// `shard` (used when an edge node honours `x-outline-home-affinity` and
   /// relays a brand-new session to the client's pinned home shard).
   pub(in crate::server) fn mint_session_id_for_shard(
       &self,
       shard: ShardId,
   ) -> Option<SessionId> {
       let id = self.cluster_identity.as_ref()?;
       Some(SessionId::random_with_shard(&self.rng, &id.key, shard))
   }
   ```
2. В `EdgeResumeAdvert` (`bins/outline-server/src/server/transport/resume_headers.rs:78-96`) добавляем поле:
   ```rust
   /// `true` when this relay was triggered by `x-outline-home-affinity` for a
   /// brand-new session rather than `x-outline-resume` for a parked session.
   pub(in crate::server) home_affinity: bool,
   ```
3. В `edge_route(headers: &HeaderMap, registry: &OrphanRegistry) -> EdgeRoute` (`resume_headers.rs:103-147`):
   - Если `RESUME_REQUEST_HEADER` присутствует — логика без изменений (`home_affinity: false`).
   - Если `RESUME_REQUEST_HEADER` отсутствует, проверяем `HOME_AFFINITY_HEADER`:
     ```rust
     if let Some(affinity_id) = headers
         .get(outline_wire::resume::HOME_AFFINITY_HEADER)
         .and_then(|v| v.to_str().ok())
         .and_then(SessionId::parse_hex)
     {
         if let RouteDecision::Relay(shard) = decide(identity, affinity_id)
             && let Some(fresh_id) = registry.mint_session_id_for_shard(shard)
         {
             return EdgeRoute::Relay {
                 shard,
                 advert: EdgeResumeAdvert {
                     session_id: fresh_id,
                     resume_capable,
                     // Новая сессия НЕ ждёт префиксный фрейм ORSM в начале потока,
                     // но сам носитель поддерживает ack-prefix, поэтому HTTP-заголовок
                     // X-Outline-Resume-Ack-Prefix клиенту всё равно вернём.
                     ack_prefix: resume_capable && client_wants_ack_prefix(headers),
                     symmetric_replay: resume_capable && client_wants_symmetric_replay(headers),
                     down_acked: 0,
                     home_affinity: true,
                 },
             };
         }
     }
     ```
   - Почему важно сгенерировать `fresh_id` с тем же `shard`? Потому что клиент присылает один и тот же шаблонный `pinned_home_id` во всех новых параллельных TCP/UDP-сессиях. Благодаря `mint_session_id_for_shard(shard)` каждая новая сессия получает **свой собственный уникальный `SessionId`**, в котором зашифрован `shard` домашнего сервера `A`. Клиент получает этот `fresh_id` в `X-Outline-Session`, и если эта новая сессия позже сама оборвётся, домашний сервер `A` запаркует её в своём `OrphanRegistry` под её уникальным `fresh_id` без коллизий!

##### B. Расширение фрейминга mesh (`bins/outline-server/src/server/cluster/mesh/frame.rs`)
1. В `bins/outline-server/src/server/cluster/mesh/frame.rs`:
   - Добавляем флаг в `OpenHeader` (строки 42–47):
     ```rust
     const FLAG_HOME_AFFINITY: u8 = 0x20;
     ```
   - В `pub(in crate::server) struct OpenHeader` (строка 101) добавляем:
     ```rust
     /// When `true`, this mesh stream opens a brand-new session on the home
     /// node (Exit Affinity) rather than claiming an existing parked session
     /// from `OrphanRegistry`.
     pub(in crate::server) home_affinity: bool,
     ```
   - В `OpenHeader::encode` / `OpenHeader::decode` сериализуем и читаем `FLAG_HOME_AFFINITY`.
2. Добавляем компактный фрейм `FreshTargetFrame`, который передаётся от Edge к Home в Фазе 2 **только когда `header.home_affinity == true`** сразу после `UserFrame`:
   ```rust
   /// Target and session shape sent by the edge in Phase 2 when
   /// `OpenHeader::home_affinity` is `true`.
   #[derive(Debug, Clone, PartialEq, Eq)]
   pub(in crate::server) enum FreshSessionKind {
       /// SS-TCP or VLESS-TCP connection to `target`.
       Tcp(outline_wire::TargetAddr),
       /// SS-UDP session (each datagram carries its own SOCKS5 target header).
       SsUdp,
       /// Single-target VLESS-UDP session to `target`.
       VlessUdp(outline_wire::TargetAddr),
       /// Multiplexed VLESS-Mux (XUDP) session.
       VlessMux,
   }
   ```
   Функции записи и чтения в `frame.rs`:
   - `write_fresh_target_frame<W: AsyncWrite + Unpin>(writer: &mut W, kind: &FreshSessionKind) -> io::Result<()>`:
     - Байтовый тег: `1` + `target.to_wire_bytes()` (с u16 BE длиной адресных байт) для `Tcp(target)`; `2` (0 доп. байт) для `SsUdp`; `3` + `target.to_wire_bytes()` для `VlessUdp(target)`; `4` для `VlessMux`.
   - `read_fresh_target_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<FreshSessionKind>`: читает тег и при тегах `1` или `3` парсит `TargetAddr::from_wire_bytes(&buf)` (через `outline_wire::socks5::parse_target_addr`).

##### C. Таймаут и Фаза 2 на Edge (`bins/outline-server/src/server/transport/mesh_relay/edge.rs` и `upstream_source.rs`)
1. В `bins/outline-server/src/server/transport/mesh_relay/edge.rs`:
   - Добавляем сокращённый таймаут ожидания Фазы 1 для `home_affinity`:
     ```rust
     const HOME_AFFINITY_ACK_WAIT: Duration = Duration::from_millis(1200);
     ```
   - В `open_edge_relay`:
     - При формировании `OpenHeader`:
       - Если `advert.home_affinity` равен `true`, выставляем `home_affinity: true` и `ack_prefix: false` в `OpenHeader` (чтобы Home не слал `ORSM` ack-prefix фрейм в новую сессию!).
     - В `await_ack` используем `if advert.home_affinity { HOME_AFFINITY_ACK_WAIT } else { OPEN_ACK_WAIT }`.
     - Если домашний сервер `A` полностью выключен или недоступен по mesh `9443/udp`, через `1.2s` `open_edge_relay` возвращает `None`, и Edge автоматически открывает сессию локально (`UpstreamSource::Direct`) со своим собственным `local.issued_session_id`!
   - В `PendingMeshStream` сохраняем `pub(in crate::server) home_affinity: bool`.
   - Добавляем метод `PendingMeshStream::commit_fresh_user_and_target(mut self, user: &UserFrame, kind: &FreshSessionKind) -> io::Result<CommittedMeshStream>`, который пишет `write_user_frame(&mut self.send, user)` и следом `write_fresh_target_frame(&mut self.send, kind)`.
2. В `bins/outline-server/src/server/transport/upstream_source.rs`:
   - В `MeshUpstreamSetup` добавляем `pub(in crate::server) fn is_home_affinity(&self) -> bool { self.pending.as_ref().is_some_and(|p| p.home_affinity) }`.
   - Добавляем метод `pub(in crate::server) async fn attach_fresh(&mut self, user: UserFrame, kind: FreshSessionKind) -> io::Result<CommittedMeshStream>`.
   - В местах привязки (`tcp.rs`, `udp.rs`, `vless/tcp.rs`, `vless/udp.rs`, `vless_udp.rs`, `vless_mux/mod.rs`):
     - Для **SS-TCP** (`bins/outline-server/src/server/transport/tcp.rs:285-330` и `715-735`):
       - Когда `upstream.is_mesh()` и `setup.is_home_affinity()`: не закрываем сокет на первом чанке без target! Вместо этого ждём первый расшифрованный клиентский чанк (как в `UpstreamSource::Direct`), парсим из него `TargetAddr` через `parse_target_addr(&plaintext)` и вызываем `setup.attach_fresh(UserFrame { protocol: MeshProtocol::Ss, user: user_id }, FreshSessionKind::Tcp(target)).await`, после чего пересылаем остаток первого чанка (`&plaintext[consumed..]`) в `committed` mesh-стрим и переходим в `relay_attached_mesh_tcp`!
     - Для **SS-UDP** (`bins/outline-server/src/server/transport/udp.rs:435-485`):
       - Когда `setup.is_home_affinity()`, вызываем `setup.attach_fresh(UserFrame { protocol: MeshProtocol::Ss, user: user_id }, FreshSessionKind::SsUdp).await`.
     - Для **VLESS-TCP / VLESS-UDP / VLESS-Mux** (`bins/outline-server/src/server/transport/vless/mod.rs:344-420`, `vless/tcp.rs`, `vless/udp.rs`, `vless_udp.rs`):
       - Если `setup.is_home_affinity()`, в `handle_first_vless_frame` **не уходим** в ранний `relay_vless_over_mesh` до парсинга VLESS-заголовка (`CMD_TCP` / `CMD_UDP` / `MUX_TARGET_HOST`), потому что нам нужен `Command` и `TargetAddr` из первого VLESS-фрейма!
       - Парсим первый VLESS-фрейм (как в обычной ветке `Direct`), проверяем UUID пользователя, определяем команду (`CMD_TCP(target)`, `CMD_UDP(target)` или `MUX`), вызываем `setup.attach_fresh(UserFrame { protocol: MeshProtocol::Vless, user: user.id.clone() }, kind).await`, отправляем клиенту 2-байтовый VLESS response header (`[version, 0x00]`), пересылаем initial payload первого фрейма в `committed` mesh-стрим и запускаем двунаправленный проброс (`relay_vless_over_mesh_committed` / `relay_vless_udp_over_mesh_committed`).

##### D. Открытие свежей сессии на Home (`bins/outline-server/src/server/transport/mesh_relay/home.rs`)
В `bins/outline-server/src/server/transport/mesh_relay/home.rs`:
1. В `Services` (`home.rs:41-48`) добавляем список пользователей маршрута (или берём их из `tcp_server.users` / `udp_server.users` и `vless_users: Arc<[Arc<VlessUser>]>`), чтобы Home мог по `(UserFrame.protocol, UserFrame.user)` определить `fwmark: Option<u32>` и `user_counters: Option<Arc<UserTrafficCounters>>`.
   - Примечание: в `TcpShadowsocksServer` (`tcp.rs`) и `UdpShadowsocksServer` (`udp.rs`) пользователи уже лежат в `users: Arc<[UserKey]>`, где у каждого `UserKey` есть `id: Arc<str>`, `fwmark: Option<u32>`, `counters: Arc<UserTrafficCounters>`. Для VLESS в `Services` передаём `pub(in crate::server) vless_users: Vec<Arc<VlessUser>>` (собранный из всех `[[endpoint]]` в `bins/outline-server/src/server/mod.rs` при инициализации mesh listener).
2. В `serve_relayed` (`home.rs:94-215`):
   - Если `header.home_affinity` равен `true`:
     - **Фаза 1:** не вызываем `registry.probe_park` (парковки ещё нет, это новая сессия). Сразу отправляем `write_open_ack(&mut stream.send, header.committed_shape(), header.committed_shape().unwrap_or(MeshShape::Stream)).await`.
     - **Фаза 2:** читаем `let user_frame = read_user_frame(&mut stream.recv).await?;` и следом `let fresh_kind = read_fresh_target_frame(&mut stream.recv).await?;`.
     - Находим пользователя (`fwmark`, `user_counters`) по `user_frame`. Если пользователь не найден — пишем `write_data_done` с `CLOSE_USER_MISMATCH` и выходим.
     - В зависимости от `fresh_kind`:
       1. `FreshSessionKind::Tcp(target)`:
          - Подключаемся к целевому хосту с домашнего сервера:
            ```rust
            let tcp_stream = connect_tcp_target(
                services.tcp_server.dns_cache.as_ref(),
                &target,
                fwmark,
                services.tcp_server.prefer_ipv6,
                services.tcp_server.ipv4_only,
            )
            .await?;
            ```
          - Конструируем `ParkedTcp`:
            ```rust
            let parked = ParkedTcp {
                stream: tcp_stream,
                user_id: Arc::from(user_frame.user.as_str()),
                target: target.to_string(),
                fwmark,
                user_counters,
                upstream_bytes_acked: 0,
                downlink_ring: header
                    .symmetric_replay
                    .then(|| DownlinkRing::new(services.cluster.replay_ring_bytes)),
            };
            ```
          - Вызываем существующий `splice_plaintext_tcp(stream, parked, &header, session_id, services.cluster, services.registry).await`! При закрытии носителя `splice_plaintext_tcp` автоматически запаркует `ParkedTcp` на домашнем сервере под `session_id`!
       2. `FreshSessionKind::SsUdp`:
          - Конструируем `RelayedUdpIdentity`:
            ```rust
            let identity = RelayedUdpIdentity {
                user_id: Arc::from(user_frame.user.as_str()),
                fwmark,
                scope: Some(*session_id.as_bytes()),
            };
            ```
          - Вызываем существующий `splice_plaintext_udp(stream, &services.udp_server, identity, Vec::new(), session_id, services.cluster, services.registry).await`! Каждая датаграмма создаст NAT-запись на домашнем сервере со `scope = Some(*session_id.as_bytes())`, а при обрыве носителя ключи NAT запаркуются на Home под `session_id`.
       3. `FreshSessionKind::VlessUdp(target)`:
          - Резолвим `target` и открываем UDP-сокет на Home через `resolve_udp_target` + `bind_and_connect_udp(&services.udp_server, target_addr, fwmark)`.
          - Конструируем `ParkedVlessUdpSingle` и вызываем `splice_plaintext_vless_udp(stream, parked, session_id, services.cluster, services.registry).await`.
       4. `FreshSessionKind::VlessMux`:
          - Конструируем свежий `MuxState::new(Arc::from(user_frame.user.as_str()), fwmark, user_counters)` и вызываем `splice_plaintext_vless_mux(stream, mux_state, &services.tcp_server, &services.udp_server, session_id, services.cluster, services.registry).await`.

---

## 5. Пошаговый план реализации (Чек-лист задач для выполнения)

Выполняй задачи строго по порядку (Задача 1 → Задача 8). После каждой задачи запускай указанные тесты.

### Задача 1. Заголовок `HOME_AFFINITY_HEADER` в `outline-wire` и двухфазные таймауты L4 в `outline-transport`
- **Файлы:**
  - `crates/outline-wire/src/resume.rs`
  - `crates/outline-transport/src/dial_timeouts.rs`
  - `crates/outline-transport/src/lib.rs`
  - `crates/outline-transport/src/shared_dial.rs`
  - `crates/outline-transport/src/xhttp/h1.rs`
  - `crates/outline-transport/src/ws/connect.rs`
- **Что сделать:**
  1. Добавить `pub const HOME_AFFINITY_HEADER: &str = "x-outline-home-affinity";` в `crates/outline-wire/src/resume.rs`.
  2. В `crates/outline-transport/src/dial_timeouts.rs` добавить `l4_connect_timeout()` (`2/10` от `fresh_connect_timeout()`, clamp `1500ms..=15s`) и `reused_h3_open_floor()` (`3/20` от `fresh_connect_timeout()`, clamp `1500ms..=3s`), обновить `reused_h3_open_budget`.
  3. В `crates/outline-transport/src/lib.rs` объявить и экспортировать `L4ConnectError` и `EndpointUnreachable`, обернуть `connect_tcp_socket` в `tokio::time::timeout(dial_timeouts::l4_connect_timeout(), ...)` с навешиванием `.context(L4ConnectError)` при таймауте или L4 `io::Error`.
  4. В `crates/outline-transport/src/shared_dial.rs` (`resolve_and_dial`), `xhttp/h1.rs` и `ws/connect.rs` сохранить маркер `L4ConnectError` при ошибках дозвона по всем DNS-адресам.
- **Тесты (TDD):**
  - В `crates/outline-transport/src/dial_timeouts.rs`:
    - `l4_connect_timeout_is_2s_at_default_10s_budget`
    - `l4_connect_timeout_scales_for_mobile_3g_and_2g` (`30s → 6s`, `60s → 12s`)
    - `reused_h3_open_floor_is_1500ms_at_default_and_3s_on_slow_links`
  - Прогон: `cargo test -p outline-wire -p outline-transport`

### Задача 2. L4-watchdog в QUIC `dial_race.rs` и пропуск `HTTP/1.1` при `L4ConnectError` в `dial_plan.rs`
- **Файлы:**
  - `crates/outline-transport/src/quic/dial_race.rs`
  - `crates/outline-transport/src/h3/shared.rs`
  - `crates/outline-transport/src/xhttp/h3_pool.rs`
  - `crates/outline-transport/src/dial_plan.rs`
  - `crates/outline-transport/src/resumption.rs`
  - `crates/outline-transport/src/xhttp/mod.rs`
  - `crates/outline-transport/src/udp_transport.rs`
  - `crates/outline-transport/src/vless/udp.rs`
  - `crates/outline-transport/src/vless/udp_mux.rs`
- **Что сделать:**
  1. В `crates/outline-transport/src/quic/dial_race.rs` изменить `HEDGE_SCHEDULE` на `[Duration::from_millis(800)]` и добавить проверку по `l4_connect_timeout()`: если ни один клиентский `quinn::Endpoint` в гонке не получил ни одной UDP-датаграммы (`udp_rx.datagrams == 0`), прервать гонку с `.context(crate::L4ConnectError)`. Если получена хотя бы 1 датаграмма — продолжать ждать до полного `fresh_connect_timeout()`.
  2. В `crates/outline-transport/src/dial_plan.rs` в `connect_ws_h2_with_h1_fallback` и `connect_xhttp_h2_with_h1_fallback`: если `H2` упал с `L4ConnectError`, не вызывать `HTTP/1.1` и сразу возвращать `Err(h2_error.context(crate::EndpointUnreachable))`. При прямом `HTTP/1.1` навешивать `EndpointUnreachable` при `L4ConnectError`.
  3. Добавить `pub home_affinity: Option<SessionId>` в `DialResumeOptions` (`dial_plan.rs`) и `SessionOpen` (`xhttp/mod.rs`), пробросить запись заголовка `HOME_AFFINITY_HEADER` в `resumption::apply_resume_request_headers` и `xhttp::build_session_request_headers` (только когда `resume_request.is_none()`).
- **Тесты (TDD):**
  - В `crates/outline-transport/src/dial_plan.rs` и `resumption.rs`:
    - `apply_resume_request_headers_emits_home_affinity_only_when_resume_request_absent`
    - `h2_l4_connect_error_skips_h1_and_tags_endpoint_unreachable` (локальный закрытый TCP-порт на `127.0.0.1` мгновенно даёт `ConnectionRefused` → `L4ConnectError` → `EndpointUnreachable` без вызова H1).
  - Прогон: `cargo test -p outline-transport`

### Задача 3. Схлопывание каскада проводов, быстрый статус `unhealthy` и параллельный L4-watchdog пробника в `outline-uplink`
- **Файлы:**
  - `crates/outline-uplink/src/manager/wire_dial.rs`
  - `crates/outline-uplink/src/manager/failures.rs`
  - `crates/outline-uplink/src/manager/probe/scheduler.rs`
- **Что сделать:**
  1. В `wire_dial.rs` добавить `WireEndpointKey` и `dead_endpoints: HashSet<WireEndpointKey>`: если провод упал с `EndpointUnreachable`, пропускать все последующие провода в `wire_order`, смотрящие на тот же `(host, port, fwmark, dscp, ipv6_first, ipv4_only)`.
  2. В `failures.rs`:
     - Сделать `probe_wakeup_min_interval(&self)` адаптивным: `2s` при `probe.interval < 60s` и `15s` при `probe.interval >= 60s`.
     - В `report_runtime_failure_inner`: при `EndpointUnreachable` на аплинке, где все провода этого транспорта делят один `(host, port)`, сразу переводить плоскость в `healthy = Some(false)` с `cooldown_until`, обходя гейт раунда `shuffle_wires` и `min_failures`.
  3. В `probe/scheduler.rs` (`run_probe_attempt_with_timeout`): добавить параллельную ветку `tokio::select!` со сном `probe.endpoint_check_timeout` и вызовом `unreachable_uplink_endpoints`, прерывающую зависший `probe_task`.
- **Тесты (TDD):**
  - В `crates/outline-uplink/src/manager/`:
    - `dial_over_wires_skips_remaining_wires_on_endpoint_unreachable` (проверяем по атомарному счётчику вызовов `build(wire)`, что при возврате `EndpointUnreachable` на проводе 0 провода 1, 2, 3 не вызываются).
    - `endpoint_unreachable_flips_single_endpoint_uplink_unhealthy_immediately` (даже при `shuffle_wires = true` и `min_failures = 3`).
    - `probe_wakeup_min_interval_is_2s_for_desktop_and_15s_for_mobile`
  - Прогон: `cargo test -p outline-uplink`

### Задача 4. Exit Affinity Уровень 1 (`failover_order`) и клиентское состояние Уровня 2 (`pinned_home_id`) в `outline-uplink` и `outline-tun`
- **Файлы:**
  - `crates/outline-uplink/src/manager/candidates.rs`
  - `crates/outline-uplink/src/manager/state.rs`
  - `crates/outline-uplink/src/manager/reselect.rs`
  - `crates/outline-uplink/src/manager/standby/mod.rs`
  - `crates/outline-uplink/src/manager/standby/refill.rs`
  - `crates/outline-tun/src/tcp/engine/tasks/upstream/migrate.rs`
- **Что сделать:**
  1. В `candidates.rs` добавить `uplink_primary_host` и передавать `failed_host: Option<&str>` в `failover_order`: при равном статусе здоровья, `cooldown` и `weight` кандидат с тем же `host`, что у упавшего активного аплинка, побеждает кандидата с другим `host` независимо от разницы в RTT `score`.
  2. В `state.rs` добавить `pinned_home_id` и `home_affinity_active`, методы `record_issued_session_id`, `current_home_affinity`, `clear_home_affinity`.
  3. В `candidates.rs` (`set_active_uplink_index_for_transport`, `set_active_uplink_by_name`, `reset_all_uplink_statuses`) и `reselect.rs` (`reselect_global`, `reselect_per_uplink`):
     - Включать `home_affinity_active = true` при `SwitchIntent::Failover` в `shared_resume` группе (если `pinned_home_id.is_some()`), очищая warm-standby нового аплинка.
     - Вызывать `clear_home_affinity()` при `SwitchIntent::OperatorHard`, `SwitchIntent::OperatorSoft`, ручном `set_active_uplink_by_name` и плановом/ручном `reselect`.
  4. В `standby/mod.rs` и `standby/refill.rs` передавать `current_home_affinity()` при новых дозвонах и записывать `record_issued_session_id(ws.issued_session_id())`.
  5. В `crates/outline-tun/src/tcp/engine/tasks/upstream/migrate.rs` при ошибке `redial_tcp_uplink_for_migration` в `MigrationTrigger::CarrierDeath` и включённом `shared_resume` запрашивать `tcp_failover_candidates` и мигрировать поток на здоровый соседний аплинк с тем же `plan.session_id`.
- **Тесты (TDD):**
  - В `crates/outline-uplink/src/manager/candidates.rs`:
    - `failover_order_prefers_same_host_isp_backup_before_cluster_neighbor_of_equal_weight`
    - `home_affinity_activates_on_failover_and_clears_on_operator_and_reselect_switches`
  - Прогон: `cargo test -p outline-uplink -p outline-tun`

### Задача 5. Серверная поддержка `x-outline-home-affinity` и открытие новых сессий через mesh (`bins/outline-server`)
- **Файлы:**
  - `bins/outline-server/src/server/resumption/mod.rs`
  - `bins/outline-server/src/server/transport/resume_headers.rs`
  - `bins/outline-server/src/server/cluster/mesh/frame.rs`
  - `bins/outline-server/src/server/transport/mesh_relay/edge.rs`
  - `bins/outline-server/src/server/transport/mesh_relay/home.rs`
  - `bins/outline-server/src/server/transport/upstream_source.rs`
  - `bins/outline-server/src/server/transport/tcp.rs`
  - `bins/outline-server/src/server/transport/udp.rs`
  - `bins/outline-server/src/server/transport/vless/mod.rs`
  - `bins/outline-server/src/server/transport/vless/tcp.rs`
  - `bins/outline-server/src/server/transport/vless/udp.rs`
  - `bins/outline-server/src/server/transport/vless_udp.rs`
  - `bins/outline-server/src/server/mod.rs`
- **Что сделать:**
  1. Добавить `OrphanRegistry::mint_session_id_for_shard(&self, shard: ShardId) -> Option<SessionId>`.
  2. В `resume_headers.rs::edge_route` распознавать `HOME_AFFINITY_HEADER` (когда `RESUME_REQUEST_HEADER` отсутствует) и при `RouteDecision::Relay(shard)` возвращать `EdgeRoute::Relay` с `home_affinity: true` и свежесгенерированным `session_id` для этого `shard`.
  3. В `cluster/mesh/frame.rs` добавить `FLAG_HOME_AFFINITY = 0x20` в `OpenHeader` и фрейм `FreshSessionKind` (`write_fresh_target_frame` / `read_fresh_target_frame`).
  4. В `mesh_relay/edge.rs` использовать `HOME_AFFINITY_ACK_WAIT = 1200ms` при `advert.home_affinity == true`, отключать `ack_prefix` в `OpenHeader` для свежих сессий и добавить `commit_fresh_user_and_target`.
  5. В `upstream_source.rs`, `tcp.rs`, `udp.rs`, `vless/*`, `vless_udp.rs` при `setup.is_home_affinity()` передавать `(UserFrame, FreshSessionKind)` в `setup.attach_fresh(...)`.
  6. В `mesh_relay/home.rs::serve_relayed` при `header.home_affinity == true` сразу подтверждать Фазу 1 (`OPEN_ACK_ACCEPTED`), в Фазе 2 читать `UserFrame` + `FreshSessionKind`, открывать целевой сокет на Home и запускать соответствующий `splice_plaintext_*`.
- **Тесты (TDD):**
  - В `bins/outline-server/src/server/cluster/mesh/frame.rs`:
    - `open_header_roundtrips_home_affinity_flag`
    - `fresh_target_frame_roundtrips_all_variants`
  - В `bins/outline-server/src/server/transport/resume_headers.rs`:
    - `edge_route_relays_home_affinity_header_and_mints_unique_session_ids_with_home_shard`
  - Прогон: `cargo test -p outline-server`

### Задача 6. E2E-тест быстрого фейловера и Exit Affinity на реальных бинарях (`bins/outline-client/tests/`)
- **Файлы:**
  - `bins/outline-client/tests/e2e_failover.rs` (или новый тест в `bins/outline-client/tests/`)
- **Что сделать:**
  1. Добавить e2e-сценарий:
     - Два сервера `server_a` и `server_b` в одном кластере (`cluster.key`, `mesh.listen`, `mesh.peers`, у клиента `shared_resume = true`).
     - Клиент открывает первую TCP-сессию через `server_a`, запоминает `pinned_home_id` с шардом `server_a`.
     - Имитируется обрыв прямого доступа клиента к `server_a` (при этом `server_a` остаётся доступен для `server_b` по mesh `9443/udp`): фейловер клиента на `server_b` укладывается в `< 5 с`, а **новая** TCP-сессия, открытая клиентом через `server_b`, выходит на целевой echo-сервер с сокета `server_a` (через `x-outline-home-affinity` + mesh).
     - Затем вызывается ручное переключение (`/switch` или `set_active_uplink_by_name`) на `server_b` — проверяется, что аффинити сброшена и следующая новая сессия выходит напрямую с `server_b`.
- **Прогон:**
  - `RUN_E2E_FAILOVER=1 cargo test -p outline-client --features test-tls --test 'e2e_*' -- --test-threads=1`

### Задача 7. Синхронизация двуязычной документации (EN / RU)
- **Файлы:**
  - `docs/Failover-And-Load-Balancing-Guide.md` и `docs/Failover-And-Load-Balancing-Guide.ru.md`
  - `docs/Architecture.md` и `docs/Architecture.ru.md`
- **Что сделать:**
  1. Описать двухфазный L4-бюджет (`l4_connect_timeout` = 20% от `dial_timeout`, `1.5–15 с`), схлопывание каскада проводов по `EndpointUnreachable` и адаптивный профиль для Android.
  2. Описать двухуровневую Exit Affinity (Вариант Б): приоритет того же `host` в `failover_order`, заголовок `X-Outline-Home-Affinity` для сохранения точки выхода через mesh при аварийном переключении и автоматический сброс при ручном (`/control/activate`, `/switch`) или плановом (`reselect_at`, `reselect_interval`, `/control/reselect`) переключении.

### Задача 8. Полный CI-гейт, проверка отсутствия утечек доменов/IP и очистка `target/`
Выполнить все команды обязательного CI-гейта в точном порядке:

```bash
# 1. Проверка на отсутствие реальных доменов и IP в репозитории (вывод должен быть пустым)
git diff | grep -E 'beerloga|185\.78|77\.91|87\.242|176\.123|198\.18\.|198\.19\.' || true

# 2. Форматирование
cargo fmt --check -p outline-server -p outline-client -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto

# 3. Clippy
cargo clippy --workspace --exclude sockudo-ws --exclude outline-windows --all-targets --no-deps -- -D warnings

# 4. Unit и интеграционные тесты workspace
cargo test --workspace --exclude sockudo-ws --exclude outline-windows

# 5. E2E тесты фейловера и носителей
RUN_E2E_FAILOVER=1 cargo test -p outline-client --features test-tls --test 'e2e_*' -- --test-threads=1

# 6. Отдельный workspace Android
(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)
```
