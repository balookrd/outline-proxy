# PMTUD без лесенки: первая проба по кэшу MTU пути — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Цель:** убрать одинаковую на каждом соединении «лесенку» DPLPMTUD-проб (1326 → 1389 → 1420 → 1436 → 1444 → 1448 → 1452✗), которую пассивный DPI видит сразу после рукопожатия. В обычном случае соединение должно обходиться одной пробой: размером, уже подтверждённым для этого пути.

**Архитектура:** в vendored quinn-proto появляется `MtuDiscoveryConfig::first_probe(Option<u16>)`: первая проба поиска — заданный размер. Если она проходит, поиск закончен, и этот размер становится потолком соединения. Если не проходит, запускается обычный двоичный поиск ниже неё. Клиент (`outline-transport`) держит кэш подтверждённого MTU с ключом «сервер + порт + fwmark + хэш локального source IP», сохраняет его на диск рядом со `state_path` и передаёт значение из кэша в `first_probe` при каждом H3-dial (ws_h3 и xhttp_h3). Сервер получает опциональный `[server.h3].mtu_first_probe` (по умолчанию выключен).

**Tech Stack:** Rust (edition 2024), quinn 0.11 + vendored quinn-proto 0.11.15, tokio.

## Global Constraints

- Клиентский `initial_mtu` остаётся 1200: это часть отпечатка Chrome, тест `h3_initial_datagram_stays_1200_for_every_profile` не трогать. `first_probe` влияет только на пробы после рукопожатия, а не на Initial.
- НЕ менять: `upper_bound` (1452 на обеих сторонах), `minimum_change` (4), `H3_DEFAULT_INITIAL_MTU = 1400`, `H3_MAX_UDP_PAYLOAD_SIZE = 1452`, `MAX_PROBE_RETRANSMITS = 3`.
- Значение из кэша — ТОЛЬКО размер первой пробы. В `initial_mtu` его не подставлять ни при каких условиях: неподтверждённый большой MTU = «чёрная дыра» для данных при смене пути.
- `first_probe = None` (дефолт) должен давать поведение upstream байт в байт: существующие тесты `vendor/quinn-proto` проходят без правок.
- В кэш не писать значение соединения, на котором был black hole (`black_holes_detected > 0`), и значение, пока поиск не завершён (`plpmtud_settled == false`).
- `confirmed_at` записи обновляется только при изменении значения. Тогда запись стареет через TTL (3 суток), следующее соединение проходит полный поиск, и рост MTU пути обнаруживается.
- На диск писать только при изменении значения. Формат файла — текст, без новых зависимостей. Локальный IP в файл не попадает, только 64-битный хэш (FNV-1a).
- Тесты нашего кода — в `tests/` рядом с модулями (`#[cfg(test)] #[path = "tests/<name>.rs"] mod tests;`). Исключение: `vendor/quinn-proto` сохраняет upstream-раскладку (inline `mod tests` в `mtud.rs`), чтобы патч оставался минимальным.
- Комментарии в коде и сообщения коммитов — по-английски; документация — парами EN/RU в одном изменении.
- `git commit` / `git push` — только по явной команде владельца. Коммитить `git commit -- <пути>`: в индексе бывает чужое. Без трейлера `Co-Authored-By` и без подписи Claude Code.
- Гейт (как в CI): `cargo fmt --check -p <пакет>` по пакетам CI (не `--all`: он переформатирует `vendor/sockudo-ws`), `cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings`, сборка обоих бинарей с `--no-default-features`, `cargo test --workspace --exclude sockudo-ws`, `cargo test -p outline-transport --all-features`, инварианты CI, Linux в docker (`rust:bookworm`) ДО коммита.
- Прод не рестартить без согласия владельца; парк раскатывать по одному узлу.

## Почему так (расчёт для ревьюера)

Последовательность проб вычислена по `vendor/quinn-proto/src/connection/mtud.rs::next_mtu_to_probe`; ✗ — проба потеряна, quinn повторяет её 3 раза (`MAX_PROBE_RETRANSMITS`), прежде чем отказаться от размера.

| Сторона, путь | Сейчас | `first_probe` = подтверждённый | `first_probe` устарел |
|---|---|---|---|
| клиент, 1448, `first_probe` 1448 | 1326, 1389, 1420, 1436, 1444, 1448, 1452✗×3 — 9 пакетов | **1448 — 1 пакет** | — |
| клиент, 1440, `first_probe` 1448 | 1326, 1389, 1420, 1436, 1444✗×3, … | — | 1448✗×3, 1323, 1385, 1416, 1431, 1439, 1443✗×3 → 1439 |
| сервер, 1452, `first_probe` 1452 | 1426, 1439, 1445, 1452 — 4 | **1452 — 1** | — |
| сервер, 1448, `first_probe` 1452 | 1426, 1439, 1445, 1452✗×3, 1448 — 7 | — | 1452✗×3, 1425, 1438, 1444, 1451✗×3, 1447 — 10 |

Из таблицы следуют два решения:
1. **Нет «умного» дефолта.** Первая проба «сразу 1452» на пути 1448 хуже текущего поиска (две отвергнутые ступени вместо одной). Поэтому без кэша клиент ищет как раньше, а у сервера `mtu_first_probe` по умолчанию выключен: оператор ставит его там, где путь известен.
2. **Потолок после поиска.** Когда `first_probe` задан, верхняя граница завершённого поиска становится потолком соединения. Повторный поиск через `interval` (600 с) и после black hole идёт не выше потолка, поэтому лесенка 1448 → 1450 → 1452✗ не повторяется каждые 10 минут.

## Файлы

- Modify: `vendor/quinn-proto/src/config/transport.rs` — поле и setter `MtuDiscoveryConfig::first_probe`.
- Modify: `vendor/quinn-proto/src/connection/mtud.rs` — первая проба, потолок, `MtuDiscovery::settled()`; тесты в существующем inline `mod tests`.
- Modify: `vendor/quinn-proto/src/connection/stats.rs` — `PathStats::plpmtud_settled`.
- Modify: `vendor/quinn-proto/src/connection/mod.rs` — заполнение `plpmtud_settled` в `stats()`.
- Modify: `quinn-proto-0.11.15.patch`, `PATCHES.md`, `PATCHES.ru.md` — пункт 4 патча quinn-proto.
- Create: `crates/outline-transport/src/quic/pmtu_cache.rs` — кэш, ключ, сетевой идентификатор, запись на диск, recorder.
- Create: `crates/outline-transport/src/quic/tests/pmtu_cache.rs` — unit-тесты кэша.
- Modify: `crates/outline-transport/src/quic/mod.rs`, `crates/outline-transport/src/lib.rs` — модуль и экспорт `init_pmtu_cache`.
- Modify: `crates/outline-transport/src/quic/tls_config.rs` — `build_h3_transport_with_first_probe`, `h3_quic_client_config_with_first_probe`.
- Modify: `crates/outline-transport/src/quic/tests/tls_config.rs` — интеграционные тесты через `narrow_uplink`.
- Modify: `crates/outline-transport/src/h3/shared.rs` (`connect_h3_connection`), `crates/outline-transport/src/xhttp/h3_pool.rs` (`dial`) — подключение кэша.
- Modify: `bins/outline-ws-rust/src/lib.rs` — `init_pmtu_cache` из `state_path`.
- Modify (сервер): `bins/outline-ss-rust/src/config/file.rs`, `config/loader.rs`, `config/resolved.rs`, `server/h3/mod.rs`, `server/control/handlers.rs`, `server/control/persist.rs`; тест `bins/outline-ss-rust/src/server/tests/h3.rs`.
- Docs: `bins/outline-ws-rust/README{,.ru}.md`, `bins/outline-ws-rust/CHANGELOG{,.ru}.md`, `bins/outline-ss-rust/README{,.ru}.md`, `bins/outline-ss-rust/CHANGELOG{,.ru}.md`.

---

### Task 1: quinn-proto — `first_probe`, потолок поиска, `plpmtud_settled`

**Files:**
- Modify: `vendor/quinn-proto/src/config/transport.rs` (`MtuDiscoveryConfig`, ~строки 970-1030)
- Modify: `vendor/quinn-proto/src/connection/mtud.rs` (`MtuDiscovery`, `EnabledMtuDiscovery`, `SearchState`; тесты в `mod tests`, ~строка 519)
- Modify: `vendor/quinn-proto/src/connection/stats.rs:136-158`
- Modify: `vendor/quinn-proto/src/connection/mod.rs:1269-1275`
- Modify: `quinn-proto-0.11.15.patch`, `PATCHES.md`, `PATCHES.ru.md`

**Interfaces:**
- Produces: `quinn::MtuDiscoveryConfig::first_probe(&mut self, value: Option<u16>) -> &mut Self` (quinn реэкспортирует тип из quinn-proto); `quinn::PathStats::plpmtud_settled: bool` — `true`, когда поиск не идёт (discovery выключен или фаза `Complete`).

- [ ] **Step 1: Падающие тесты в `mtud.rs`**

Добавить в конец `mod tests` в `vendor/quinn-proto/src/connection/mtud.rs`:

```rust
    fn mtud_with_first_probe(first_probe: u16) -> MtuDiscovery {
        let mut config = MtuDiscoveryConfig::default();
        config.minimum_change(4).first_probe(Some(first_probe));
        MtuDiscovery::new(1_200, 1_200, None, config)
    }

    #[test]
    fn confirmed_first_probe_is_the_only_probe() {
        let mut mtud = mtud_with_first_probe(1_448);
        let probed = drive_to_completion(&mut mtud, Instant::now(), 1_448);
        assert_eq!(probed, [1_448]);
        assert_eq!(mtud.current_mtu(), 1_448);
        assert!(mtud.settled());
    }

    #[test]
    fn stale_first_probe_falls_back_to_binary_search_below_it() {
        let mut mtud = mtud_with_first_probe(1_448);
        let probed = drive_to_completion(&mut mtud, Instant::now(), 1_440);
        assert_eq!(&probed[..3], [1_448, 1_448, 1_448]);
        assert!(probed[3..].iter().all(|&size| size < 1_448), "{probed:?}");
        assert!((1_436..=1_440).contains(&mtud.current_mtu()), "{probed:?}");
    }

    #[test]
    fn later_searches_stay_under_the_ceiling() {
        let mut mtud = mtud_with_first_probe(1_448);
        let now = Instant::now();
        drive_to_completion(&mut mtud, now, 1_452);
        let later = now + Duration::from_secs(601);
        assert_eq!(mtud.poll_transmit(later, 100), None);
        assert_eq!(mtud.current_mtu(), 1_448);
    }

    #[test]
    fn first_probe_at_or_below_the_floor_is_ignored() {
        let mut mtud = mtud_with_first_probe(1_200);
        let probed = drive_to_completion(&mut mtud, Instant::now(), 1_452);
        assert_eq!(probed.first(), Some(&1_326), "{probed:?}");
    }

    #[test]
    fn first_probe_above_the_upper_bound_is_clamped() {
        let mut config = MtuDiscoveryConfig::default();
        config.upper_bound(1_400).first_probe(Some(1_452));
        let mut mtud = MtuDiscovery::new(1_200, 1_200, None, config);
        let probed = drive_to_completion(&mut mtud, Instant::now(), 1_452);
        assert_eq!(probed, [1_400]);
    }

    #[test]
    fn settled_tracks_the_search_phase() {
        let mut mtud = mtud_with_first_probe(1_448);
        assert!(!mtud.settled(), "phase Initial counts as not settled");
        assert_eq!(mtud.poll_transmit(Instant::now(), 1), Some(1_448));
        assert!(!mtud.settled());
        assert!(MtuDiscovery::disabled(1_200, 1_200).settled());
    }
```

- [ ] **Step 2: Убедиться, что тесты не компилируются**

Run: `cargo test -p quinn-proto --lib connection::mtud`
Expected: ошибка компиляции — `no method named first_probe` / `no method named settled`.

- [ ] **Step 3: Setter в `MtuDiscoveryConfig`**

В `vendor/quinn-proto/src/config/transport.rs` добавить поле в `pub struct MtuDiscoveryConfig` (после `minimum_change`):

```rust
    pub(crate) first_probe: Option<u16>,
```

метод в `impl MtuDiscoveryConfig` (после `minimum_change`):

```rust
    /// Size of the first probe of the first search (outline-proxy patch).
    ///
    /// When set, the first search probes this size before anything else. If the probe is
    /// acknowledged the search ends there, and that size caps every later search on the
    /// connection. If it is lost, the regular binary search runs below it, and the upper bound
    /// the search ends with caps later searches. Values at or below the current MTU are ignored;
    /// values above the upper bound are clamped to it. `None` (the default) keeps upstream
    /// behaviour.
    pub fn first_probe(&mut self, value: Option<u16>) -> &mut Self {
        self.first_probe = value.map(|v| v.min(MAX_UDP_PAYLOAD));
        self
    }
```

и `first_probe: None,` в `impl Default for MtuDiscoveryConfig`.

- [ ] **Step 4: Логика в `mtud.rs`**

`EnabledMtuDiscovery` — два новых поля и их инициализация:

```rust
struct EnabledMtuDiscovery {
    phase: Phase,
    peer_max_udp_payload_size: u16,
    config: MtuDiscoveryConfig,
    /// First probe for the first search; taken when that search starts.
    pending_first_probe: Option<u16>,
    /// Upper bound of the last completed search, kept only when `first_probe` is set.
    ceiling: Option<u16>,
}

impl EnabledMtuDiscovery {
    fn new(config: MtuDiscoveryConfig) -> Self {
        Self {
            phase: Phase::Initial,
            peer_max_udp_payload_size: MAX_UDP_PAYLOAD,
            pending_first_probe: config.first_probe,
            ceiling: None,
            config,
        }
    }
```

В `poll_transmit` оба места создания `SearchState::new(...)` заменить на:

```rust
            self.phase = Phase::Searching(SearchState::new(
                current_mtu,
                self.peer_max_udp_payload_size,
                &self.config,
                self.ceiling,
                self.pending_first_probe.take(),
            ));
```

и ветку завершения поиска (`else { let next_mtud_activation = ...`) — на:

```rust
            } else {
                if self.config.first_probe.is_some() {
                    self.ceiling = Some(state.upper_bound);
                }
                let next_mtud_activation = now + self.config.interval;
                self.phase = Phase::Complete(next_mtud_activation);
                return None;
            }
```

`SearchState` — два поля, новый конструктор и начало `next_mtu_to_probe`:

```rust
struct SearchState {
    // ... existing fields ...
    /// First probe still to send in this search, if any
    first_probe: Option<u16>,
    /// Whether the probe in flight (or just resolved) is the first probe
    probing_first: bool,
}

impl SearchState {
    fn new(
        mut lower_bound: u16,
        peer_max_udp_payload_size: u16,
        config: &MtuDiscoveryConfig,
        ceiling: Option<u16>,
        first_probe: Option<u16>,
    ) -> Self {
        lower_bound = lower_bound.min(peer_max_udp_payload_size);
        let upper_bound = config
            .upper_bound
            .min(ceiling.unwrap_or(u16::MAX))
            .clamp(lower_bound, peer_max_udp_payload_size);
        let first_probe = first_probe
            .map(|size| size.min(upper_bound))
            .filter(|&size| size > lower_bound);

        Self {
            in_flight_probe: None,
            lost_probe_count: 0,
            lower_bound,
            upper_bound,
            minimum_change: config.minimum_change,
            last_probed_mtu: lower_bound,
            first_probe,
            probing_first: false,
        }
    }

    fn next_mtu_to_probe(&mut self, last_probe_succeeded: bool) -> Option<u16> {
        debug_assert_eq!(self.in_flight_probe, None);

        if last_probe_succeeded {
            self.lower_bound = self.last_probed_mtu;
            if self.probing_first {
                // A confirmed first probe ends the search and caps the connection
                self.upper_bound = self.last_probed_mtu;
            }
        } else {
            self.upper_bound = self.last_probed_mtu - 1;
        }
        self.probing_first = false;

        if let Some(size) = self.first_probe.take() {
            self.probing_first = true;
            return Some(size);
        }

        // ... the existing binary search below stays unchanged ...
```

`MtuDiscovery` — метод рядом с `current_mtu()`:

```rust
    /// Whether no search is running: discovery is disabled or the last search completed
    pub(crate) fn settled(&self) -> bool {
        match &self.state {
            None => true,
            Some(state) => matches!(state.phase, Phase::Complete(_)),
        }
    }
```

- [ ] **Step 5: `PathStats::plpmtud_settled`**

В `vendor/quinn-proto/src/connection/stats.rs` после `current_mtu` в `PathStats`:

```rust
    /// Whether path MTU discovery is idle: disabled, or its last search completed
    /// (outline-proxy patch)
    pub plpmtud_settled: bool,
```

В `vendor/quinn-proto/src/connection/mod.rs`, `fn stats`, после `stats.path.current_mtu = ...`:

```rust
        stats.path.plpmtud_settled = self.path.mtud.settled();
```

- [ ] **Step 6: Тесты проходят, upstream-тесты не сломаны**

Run: `cargo test -p quinn-proto --lib`
Expected: PASS, включая все прежние тесты `connection::mtud::tests` и `tests::*`.

- [ ] **Step 7: Обновить патч и PATCHES**

Пересобрать `quinn-proto-0.11.15.patch` по процедуре из `PATCHES.md` (раздел о quinn-proto / rustls / hyper: чистый крейт с crates.io во временный git-репозиторий, копия vendored-файлов поверх, `git diff`; проверка `patch -p1` на другой чистой копии + `diff -r` пустой). В `PATCHES.md` в раздел `## quinn-proto (0.11.15)` добавить пункт:

```markdown
4. **mtud-first-probe** (`src/config/transport.rs`, `src/connection/mtud.rs`,
   `src/connection/stats.rs`, `src/connection/mod.rs`) — new
   `MtuDiscoveryConfig::first_probe(Option<u16>)`: the first search probes that size first;
   if it is acknowledged the search ends and the size caps later searches, otherwise the
   regular binary search runs below it and its final upper bound caps later searches.
   `PathStats::plpmtud_settled` reports whether no search is running. `None` (the default)
   keeps upstream behaviour. The H3 client takes the size from its path MTU cache; the
   server only with `[server.h3].mtu_first_probe`.
```

и тот же пункт по-русски в `PATCHES.ru.md`:

```markdown
4. **mtud-first-probe** (`src/config/transport.rs`, `src/connection/mtud.rs`,
   `src/connection/stats.rs`, `src/connection/mod.rs`) — новый
   `MtuDiscoveryConfig::first_probe(Option<u16>)`: первый поиск сначала пробует этот размер;
   если проба подтверждена, поиск заканчивается и размер становится потолком следующих поисков,
   иначе ниже него идёт обычный двоичный поиск, и его итоговая верхняя граница становится
   потолком. `PathStats::plpmtud_settled` сообщает, что поиск не идёт. `None` (по умолчанию)
   сохраняет поведение upstream. H3-клиент берёт размер из своего кэша MTU пути; сервер —
   только при `[server.h3].mtu_first_probe`.
```

- [ ] **Step 8: Коммит (только по команде владельца)**

```bash
git commit -m "feat(quinn-proto): probe a known path MTU first and cap later searches" -- vendor/quinn-proto/src quinn-proto-0.11.15.patch PATCHES.md PATCHES.ru.md
```

---

### Task 2: Кэш MTU пути в `outline-transport`

**Files:**
- Create: `crates/outline-transport/src/quic/pmtu_cache.rs`
- Create: `crates/outline-transport/src/quic/tests/pmtu_cache.rs`
- Modify: `crates/outline-transport/src/quic/mod.rs` (список модулей, экспорт)
- Modify: `crates/outline-transport/src/lib.rs:285` (реэкспорт рядом с `init_quic_udp_datagrams`)

**Interfaces:**
- Consumes: `quinn::PathStats::{current_mtu, plpmtud_settled, black_holes_detected}` (Task 1); `crate::bind_udp_socket(SocketAddr, Option<u32>) -> Result<std::net::UdpSocket>`; `crate::bind_addr_for(SocketAddr) -> SocketAddr`.
- Produces:
  - `pub fn init_pmtu_cache(path: Option<std::path::PathBuf>)` — однократная инициализация; `None` — кэш только в памяти.
  - `pub(crate) struct PmtuKey` + `PmtuKey::for_dial(server_name: &str, server_addr: SocketAddr, fwmark: Option<u32>) -> PmtuKey`.
  - `pub(crate) fn first_probe_for(key: &PmtuKey) -> Option<u16>`.
  - `pub(crate) fn spawn_recorder(connection: quinn::Connection, key: PmtuKey)`.
  - Внутреннее и для тестов: `PmtuCache::{new(Option<PathBuf>, Duration), hint(&self, &str, SystemTime) -> Option<u16>, record(&self, &str, u16, SystemTime) -> bool, flush(&self) -> std::io::Result<()>}`, `fn network_hash(ip: IpAddr) -> u64`.

- [ ] **Step 1: Падающие тесты**

`crates/outline-transport/src/quic/tests/pmtu_cache.rs`:

```rust
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use super::*;

const TTL: Duration = Duration::from_secs(3 * 24 * 3600);

fn temp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("pmtu-{name}-{}-{nanos}", std::process::id()))
}

#[test]
fn missing_entry_has_no_hint() {
    let cache = PmtuCache::new(None, TTL);
    assert_eq!(cache.hint("a:443|fw=-|net=0", SystemTime::now()), None);
}

#[test]
fn recorded_value_is_the_hint_until_it_expires() {
    let cache = PmtuCache::new(None, TTL);
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    assert!(cache.record("k", 1_448, t0));
    assert_eq!(cache.hint("k", t0 + TTL - Duration::from_secs(1)), Some(1_448));
    assert_eq!(cache.hint("k", t0 + TTL), None);
}

#[test]
fn same_value_does_not_refresh_the_entry() {
    let cache = PmtuCache::new(None, TTL);
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    assert!(cache.record("k", 1_448, t0));
    assert!(!cache.record("k", 1_448, t0 + Duration::from_secs(3600)));
    assert_eq!(cache.hint("k", t0 + TTL), None, "TTL counts from the first confirmation");
}

#[test]
fn changed_value_replaces_the_entry() {
    let cache = PmtuCache::new(None, TTL);
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    cache.record("k", 1_448, t0);
    assert!(cache.record("k", 1_439, t0 + Duration::from_secs(10)));
    assert_eq!(cache.hint("k", t0 + Duration::from_secs(20)), Some(1_439));
}

#[test]
fn entries_survive_a_restart() {
    let path = temp_path("roundtrip");
    let now = SystemTime::now();
    let cache = PmtuCache::new(Some(path.clone()), TTL);
    cache.record("host:443|fw=-|net=00000000deadbeef", 1_448, now);
    cache.flush().unwrap();

    let reloaded = PmtuCache::new(Some(path.clone()), TTL);
    assert_eq!(reloaded.hint("host:443|fw=-|net=00000000deadbeef", now), Some(1_448));
    let _ = std::fs::remove_file(path);
}

#[test]
fn corrupt_lines_are_skipped() {
    let path = temp_path("corrupt");
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    std::fs::write(&path, format!("garbage\nk\t1448\t{now}\nk2\tnot-a-number\t1\n")).unwrap();
    let cache = PmtuCache::new(Some(path.clone()), TTL);
    assert_eq!(cache.hint("k", SystemTime::now()), Some(1_448));
    assert_eq!(cache.hint("k2", SystemTime::now()), None);
    let _ = std::fs::remove_file(path);
}

#[test]
fn values_outside_the_quic_range_are_rejected() {
    let cache = PmtuCache::new(None, TTL);
    let now = SystemTime::now();
    assert!(!cache.record("k", 1_199, now));
    assert!(!cache.record("k", 1_453, now));
    assert_eq!(cache.hint("k", now), None);
}

#[test]
fn network_hash_differs_between_networks_and_is_stable() {
    let wifi = network_hash(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 23)));
    let lte = network_hash(IpAddr::V4(Ipv4Addr::new(10, 64, 12, 7)));
    assert_ne!(wifi, lte);
    assert_eq!(wifi, network_hash(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 23))));
}

#[test]
fn key_string_hides_the_local_address() {
    let key = PmtuKey { server: "example.com".into(), port: 443, fwmark: Some(18), net: 0xdead_beef };
    assert_eq!(key.as_str(), "example.com:443|fw=18|net=00000000deadbeef");
}
```

- [ ] **Step 2: Подключить модуль и убедиться, что тесты падают**

В `crates/outline-transport/src/quic/mod.rs` после `mod tls_config;`:

```rust
#[cfg(feature = "h3")]
pub(crate) mod pmtu_cache;
```

и экспорт рядом с `init_quic_udp_datagrams`:

```rust
#[cfg(feature = "h3")]
pub use pmtu_cache::init_pmtu_cache;
```

В `crates/outline-transport/src/lib.rs` рядом с реэкспортом `init_quic_udp_datagrams` (строка ~285):

```rust
#[cfg(feature = "h3")]
pub use quic::init_pmtu_cache;
```

Run: `cargo test -p outline-transport --all-features quic::pmtu_cache`
Expected: ошибка компиляции — файла `pmtu_cache.rs` нет.

- [ ] **Step 3: Реализация `pmtu_cache.rs`**

```rust
//! Path MTU cache for H3 dials.
//!
//! DPLPMTUD with no prior knowledge probes a fixed ladder of sizes after every
//! handshake (1326, 1389, 1420, ...), identical on every connection and visible
//! to a passive observer. The cache remembers the MTU a path settled at, keyed
//! by server, port, fwmark and a hash of the local source address (a stand-in
//! for "which network we are on"), and the next dial probes that size first
//! (`MtuDiscoveryConfig::first_probe`): one probe when the path is unchanged.
//!
//! The cached value is never used as the starting MTU: a stale entry costs one
//! rejected probe size, never lost data.

use std::collections::HashMap;
use std::hash::Hasher as _;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use parking_lot::Mutex;
use tracing::{debug, warn};

/// An entry expires this long after the path first settled at its value, so a
/// path that grew is found again by a full search.
const PMTU_CACHE_TTL: Duration = Duration::from_secs(3 * 24 * 3600);
/// QUIC floor and the H3 upper bound: anything else is not a value we probe.
const MIN_PMTU: u16 = 1200;
const MAX_PMTU: u16 = 1452;
/// Bound on entries; the oldest confirmation is evicted first.
const MAX_ENTRIES: usize = 256;
/// How often the recorder looks at a connection's path state.
const RECORD_INTERVAL: Duration = Duration::from_secs(10);

static CACHE: OnceLock<Arc<PmtuCache>> = OnceLock::new();

/// Initialise the path MTU cache once; `path` persists it across restarts,
/// `None` keeps it in memory only.
pub fn init_pmtu_cache(path: Option<PathBuf>) {
    CACHE.get_or_init(|| Arc::new(PmtuCache::new(path, PMTU_CACHE_TTL)));
}

fn cache() -> &'static Arc<PmtuCache> {
    CACHE.get_or_init(|| Arc::new(PmtuCache::new(None, PMTU_CACHE_TTL)))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PmtuKey {
    pub(crate) server: String,
    pub(crate) port: u16,
    pub(crate) fwmark: Option<u32>,
    pub(crate) net: u64,
}

impl PmtuKey {
    /// Key for a dial to `server_addr`; the network part is the hash of the
    /// local address the kernel would pick for it (0 if it cannot tell).
    pub(crate) fn for_dial(server_name: &str, server_addr: SocketAddr, fwmark: Option<u32>) -> Self {
        let net = local_source_ip(server_addr, fwmark).map(network_hash).unwrap_or(0);
        Self { server: server_name.to_owned(), port: server_addr.port(), fwmark, net }
    }

    pub(crate) fn as_str(&self) -> String {
        let fw = self.fwmark.map_or_else(|| "-".to_owned(), |m| m.to_string());
        format!("{}:{}|fw={fw}|net={:016x}", self.server, self.port, self.net)
    }
}

/// Source address the kernel picks for `server_addr` under `fwmark`, found by
/// connecting a throwaway UDP socket: `connect` on UDP only consults the
/// routing table and sends nothing.
fn local_source_ip(server_addr: SocketAddr, fwmark: Option<u32>) -> Option<IpAddr> {
    let socket = crate::bind_udp_socket(crate::bind_addr_for(server_addr), fwmark).ok()?;
    socket.connect(server_addr).ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

/// FNV-1a over the address octets: stable across builds, unlike `DefaultHasher`.
pub(crate) fn network_hash(ip: IpAddr) -> u64 {
    let octets: Vec<u8> = match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in octets {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

#[derive(Clone, Copy)]
struct Entry {
    mtu: u16,
    confirmed_at: u64,
}

pub(crate) struct PmtuCache {
    path: Option<PathBuf>,
    ttl: Duration,
    entries: Mutex<HashMap<String, Entry>>,
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl PmtuCache {
    pub(crate) fn new(path: Option<PathBuf>, ttl: Duration) -> Self {
        let entries = path.as_deref().map(load).unwrap_or_default();
        Self { path, ttl, entries: Mutex::new(entries) }
    }

    pub(crate) fn hint(&self, key: &str, now: SystemTime) -> Option<u16> {
        let entry = *self.entries.lock().get(key)?;
        (unix_secs(now) < entry.confirmed_at.saturating_add(self.ttl.as_secs())).then_some(entry.mtu)
    }

    /// Store `mtu` for `key`; returns whether the stored value changed (and the
    /// file needs a flush). The same value keeps its original `confirmed_at`.
    pub(crate) fn record(&self, key: &str, mtu: u16, now: SystemTime) -> bool {
        if !(MIN_PMTU..=MAX_PMTU).contains(&mtu) {
            return false;
        }
        let now_secs = unix_secs(now);
        let mut entries = self.entries.lock();
        let live = entries
            .get(key)
            .filter(|e| now_secs < e.confirmed_at.saturating_add(self.ttl.as_secs()));
        if live.is_some_and(|e| e.mtu == mtu) {
            return false;
        }
        entries.insert(key.to_owned(), Entry { mtu, confirmed_at: now_secs });
        if entries.len() > MAX_ENTRIES
            && let Some(oldest) =
                entries.iter().min_by_key(|(_, e)| e.confirmed_at).map(|(k, _)| k.clone())
        {
            entries.remove(&oldest);
        }
        true
    }

    /// Write the cache atomically (sibling `.tmp`, then rename). No-op in memory.
    pub(crate) fn flush(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let mut text = String::new();
        for (key, entry) in self.entries.lock().iter() {
            text.push_str(&format!("{key}\t{}\t{}\n", entry.mtu, entry.confirmed_at));
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)
    }
}

fn load(path: &std::path::Path) -> HashMap<String, Entry> {
    let Ok(text) = std::fs::read_to_string(path) else { return HashMap::new() };
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let key = fields.next()?;
            let mtu = fields.next()?.parse::<u16>().ok()?;
            let confirmed_at = fields.next()?.parse::<u64>().ok()?;
            (MIN_PMTU..=MAX_PMTU).contains(&mtu).then(|| (key.to_owned(), Entry { mtu, confirmed_at }))
        })
        .collect()
}

/// First probe for a dial on `key`, if the path has a live cached MTU.
pub(crate) fn first_probe_for(key: &PmtuKey) -> Option<u16> {
    cache().hint(&key.as_str(), SystemTime::now())
}

/// Watch `connection` and store the MTU its path settles at under `key`.
/// Skips samples taken mid-search and connections that saw a black hole.
pub(crate) fn spawn_recorder(connection: quinn::Connection, key: PmtuKey) {
    tokio::spawn(async move {
        let key = key.as_str();
        loop {
            let closed = tokio::select! {
                _ = connection.closed() => true,
                () = tokio::time::sleep(RECORD_INTERVAL) => false,
            };
            let path = connection.stats().path;
            if path.plpmtud_settled
                && path.black_holes_detected == 0
                && cache().record(&key, path.current_mtu, SystemTime::now())
            {
                debug!(key = %key, mtu = path.current_mtu, "path MTU cached");
                let cache = Arc::clone(cache());
                if let Err(error) = tokio::task::spawn_blocking(move || cache.flush())
                    .await
                    .unwrap_or_else(|e| Err(std::io::Error::other(e)))
                {
                    warn!(error = %error, "failed to persist path MTU cache");
                }
            }
            if closed {
                return;
            }
        }
    });
}

#[cfg(test)]
#[path = "tests/pmtu_cache.rs"]
mod tests;
```

Примечание для исполнителя: если `std::fs::write` во временный файл должен создаваться с правами 0600, как `state.toml`, используйте `std::fs::OpenOptions` с `std::os::unix::fs::OpenOptionsExt::mode(0o600)` под `#[cfg(unix)]`. Содержимое не секретное (имена серверов уже есть в конфиге), но права одинаковые с соседним state-файлом.

- [ ] **Step 4: Тесты проходят**

Run: `cargo test -p outline-transport --all-features quic::pmtu_cache`
Expected: PASS (9 тестов).

- [ ] **Step 5: Коммит (только по команде владельца)**

```bash
git commit -m "feat(transport): persistent path MTU cache keyed by server and local network" -- crates/outline-transport/src/quic/pmtu_cache.rs crates/outline-transport/src/quic/tests/pmtu_cache.rs crates/outline-transport/src/quic/mod.rs crates/outline-transport/src/lib.rs
```

---

### Task 3: H3-dial берёт первую пробу из кэша и пишет результат

**Files:**
- Modify: `crates/outline-transport/src/quic/tls_config.rs` (`build_h3_transport` ~169, `apply_quic_carrier_tuning` ~223, `h3_quic_client_config` ~252)
- Modify: `crates/outline-transport/src/quic/mod.rs` (экспорт новой функции)
- Modify: `crates/outline-transport/src/h3/shared.rs` (`connect_h3_connection`, ~строка 728)
- Modify: `crates/outline-transport/src/xhttp/h3_pool.rs` (`dial`, ~строка 312)
- Test: `crates/outline-transport/src/quic/tests/tls_config.rs` (рядом с `h3_mtu_discovery_gets_within_a_few_bytes_of_a_narrow_path`, ~строка 1770)

**Interfaces:**
- Consumes: `MtuDiscoveryConfig::first_probe`, `PathStats::plpmtud_settled` (Task 1); `PmtuKey::for_dial`, `first_probe_for`, `spawn_recorder` (Task 2); тестовые `loopback::Loopback::{new, connect_via}`, `loopback::narrow_uplink` из `quic/tests/loopback.rs`.
- Produces: `pub(crate) fn build_h3_transport_with_first_probe(tp: &QuicTpProfile, runtime: RuntimeWindows, first_probe: Option<u16>) -> quinn::TransportConfig`; `pub(crate) fn h3_quic_client_config_with_first_probe(first_probe: Option<u16>) -> quinn::ClientConfig`.

- [ ] **Step 1: Падающие интеграционные тесты**

В `crates/outline-transport/src/quic/tests/tls_config.rs` после `h3_mtu_discovery_gets_within_a_few_bytes_of_a_narrow_path`:

```rust
/// Dial a narrow-uplink loopback path with `first_probe` and wait until the
/// client's path MTU discovery settles. Returns the client's path stats.
async fn settle_with_first_probe(path_limit: u16, first_probe: Option<u16>) -> quinn::PathStats {
    let lb = loopback::Loopback::new();
    let (via, relay) = loopback::narrow_uplink(lb.addr, path_limit.into()).await;
    let server = lb.server.clone();
    let accept = tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() });
    let tp = &super::super::tp_profile::CHROMIUM;
    let transport = super::build_h3_transport_with_first_probe(
        tp,
        super::RuntimeWindows::current(tp),
        first_probe,
    );
    let (_ep, conn) = lb.connect_via(via, quinn::EndpointConfig::default(), transport).await;
    let _server_conn = accept.await.unwrap();

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut stats = conn.stats().path;
    while !(stats.plpmtud_settled && stats.sent_plpmtud_probes > 0)
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        stats = conn.stats().path;
    }
    relay.abort();
    stats
}

/// A cached path MTU that still holds costs one probe instead of the ladder.
#[tokio::test]
async fn h3_confirmed_first_probe_is_the_only_mtu_probe() {
    let stats = settle_with_first_probe(1448, Some(1448)).await;
    assert!(stats.plpmtud_settled, "{stats:?}");
    assert_eq!(stats.current_mtu, 1448, "{stats:?}");
    assert_eq!(stats.sent_plpmtud_probes, 1, "{stats:?}");
    assert_eq!(stats.lost_plpmtud_probes, 0, "{stats:?}");
}

/// A stale cached MTU (the path shrank) falls back to the binary search and
/// still lands within a few bytes of the path.
#[tokio::test]
async fn h3_stale_first_probe_still_finds_the_path_mtu() {
    let stats = settle_with_first_probe(1440, Some(1448)).await;
    assert!(stats.plpmtud_settled, "{stats:?}");
    assert!((1436..=1440).contains(&stats.current_mtu), "{stats:?}");
    assert!(stats.lost_plpmtud_probes >= 3, "{stats:?}");
}

/// With no cached value the client probes as before (regression guard for the
/// default path).
#[tokio::test]
async fn h3_without_first_probe_keeps_the_binary_search() {
    let stats = settle_with_first_probe(1448, None).await;
    assert!((1444..=1448).contains(&stats.current_mtu), "{stats:?}");
    assert!(stats.sent_plpmtud_probes > 3, "{stats:?}");
}
```

Run: `cargo test -p outline-transport --all-features quic::tls_config::tests::h3_`
Expected: ошибка компиляции — `build_h3_transport_with_first_probe` не найдена.

- [ ] **Step 2: Транспорт с первой пробой**

В `crates/outline-transport/src/quic/tls_config.rs`:

```rust
/// Full H3 client transport: browser-shaped transport parameters, runtime windows
/// granted after the handshake, keep-alive PING jitter and BBR.
pub(crate) fn build_h3_transport(
    tp: &super::tp_profile::QuicTpProfile,
    runtime: RuntimeWindows,
) -> quinn::TransportConfig {
    build_h3_transport_with_first_probe(tp, runtime, None)
}

/// [`build_h3_transport`] whose path MTU discovery probes `first_probe` before
/// anything else (a path MTU cached for this path), see `pmtu_cache`.
pub(crate) fn build_h3_transport_with_first_probe(
    tp: &super::tp_profile::QuicTpProfile,
    runtime: RuntimeWindows,
    first_probe: Option<u16>,
) -> quinn::TransportConfig {
    // ... the former body of `build_h3_transport`, with
    // `apply_quic_carrier_tuning(&mut transport);` replaced by
    // `apply_quic_carrier_tuning(&mut transport, first_probe);`
}
```

`apply_quic_carrier_tuning` получает параметр:

```rust
fn apply_quic_carrier_tuning(transport: &mut quinn::TransportConfig, first_probe: Option<u16>) {
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    let mut mtu = quinn::MtuDiscoveryConfig::default();
    mtu.minimum_change(QUIC_MTU_DISCOVERY_MINIMUM_CHANGE).first_probe(first_probe);
    transport.mtu_discovery_config(Some(mtu));
}
```

(комментарий про BBR над вызовом сохранить как есть).

Клиентский конфиг с первой пробой — после `h3_quic_client_config`:

```rust
/// [`h3_quic_client_config`] with path MTU discovery probing `first_probe`
/// first. `None` returns the cached config as is; `Some` clones it (TLS,
/// session tickets) and swaps in a transport built for this one dial, since
/// `quinn::TransportConfig` is not `Clone`.
pub(crate) fn h3_quic_client_config_with_first_probe(first_probe: Option<u16>) -> quinn::ClientConfig {
    let mut config = h3_quic_client_config();
    if first_probe.is_some() {
        let fp = crate::fingerprint_profile::current_dial_fingerprint();
        let tp = super::tp_profile::for_fingerprint(fp);
        config.transport_config(Arc::new(build_h3_transport_with_first_probe(
            tp,
            RuntimeWindows::current(tp),
            first_probe,
        )));
    }
    config
}
```

В `crates/outline-transport/src/quic/mod.rs` дополнить строку `pub(crate) use tls_config::{...}` именем `h3_quic_client_config_with_first_probe`.

- [ ] **Step 3: Тесты проходят**

Run: `cargo test -p outline-transport --all-features quic::tls_config::tests::h3_`
Expected: PASS, включая `h3_initial_datagram_stays_1200_for_every_profile` и `h3_mtu_discovery_gets_within_a_few_bytes_of_a_narrow_path`.

- [ ] **Step 4: Подключить кэш в ws_h3**

В `crates/outline-transport/src/h3/shared.rs`, `connect_h3_connection`, заменить:

```rust
    let client_config = crate::quic::h3_quic_client_config();
```

на:

```rust
    let pmtu_key = crate::quic::pmtu_cache::PmtuKey::for_dial(server_name, server_addr, fwmark);
    let client_config = crate::quic::h3_quic_client_config_with_first_probe(
        crate::quic::pmtu_cache::first_probe_for(&pmtu_key),
    );
```

и сразу после блока `let datagrams = ...;` добавить:

```rust
    crate::quic::pmtu_cache::spawn_recorder(connection_handle.clone(), pmtu_key);
```

- [ ] **Step 5: Подключить кэш в xhttp_h3**

В `crates/outline-transport/src/xhttp/h3_pool.rs`, `dial`, перед `let connecting = endpoint.connect_with(...)`:

```rust
    let pmtu_key = crate::quic::pmtu_cache::PmtuKey::for_dial(host, server_addr, fwmark);
```

аргумент `crate::quic::h3_quic_client_config()` в `connect_with` заменить на:

```rust
crate::quic::h3_quic_client_config_with_first_probe(crate::quic::pmtu_cache::first_probe_for(&pmtu_key))
```

и после блока `let datagrams = ...;`:

```rust
    crate::quic::pmtu_cache::spawn_recorder(connection.clone(), pmtu_key);
```

- [ ] **Step 6: Полный прогон крейта**

Run: `cargo test -p outline-transport --all-features && cargo clippy -p outline-transport --all-targets --all-features --no-deps -- -D warnings && cargo check -p outline-transport --no-default-features`
Expected: PASS, без предупреждений; без фичи `h3` модуль `pmtu_cache` не компилируется и не нужен.

- [ ] **Step 7: Коммит (только по команде владельца)**

```bash
git commit -m "feat(transport): probe the cached path MTU first on h3 dials" -- crates/outline-transport/src/quic/tls_config.rs crates/outline-transport/src/quic/mod.rs crates/outline-transport/src/quic/tests/tls_config.rs crates/outline-transport/src/h3/shared.rs crates/outline-transport/src/xhttp/h3_pool.rs
```

---

### Task 4: Клиент — файл кэша рядом со `state_path`, документация

**Files:**
- Modify: `bins/outline-ws-rust/src/lib.rs:85-100` (блок `#[cfg(feature = "h3")]`)
- Docs: `bins/outline-ws-rust/README.md` и `README.ru.md` (раздел `[quic]`, ~строка 799), `bins/outline-ws-rust/CHANGELOG.md` и `.ru.md` (`## Unreleased` → `### Added` / `### Добавлено`)

**Interfaces:**
- Consumes: `outline_transport::init_pmtu_cache(Option<PathBuf>)` (Task 2); `AppConfig::state_path: Option<PathBuf>` (`bins/outline-ws-rust/src/config/types.rs:51`; по умолчанию `<config>.state.toml`).

- [ ] **Step 1: Инициализация**

В `bins/outline-ws-rust/src/lib.rs`, в блоке `#[cfg(feature = "h3")]` после `init_quic_udp_datagrams`:

```rust
        // Path MTU cache next to the uplink state file (`client.state.toml` →
        // `client.state.pmtu`), so the first H3 dial after a restart probes the
        // MTU the path settled at instead of the full ladder.
        outline_transport::init_pmtu_cache(
            config.state_path.as_ref().map(|path| path.with_extension("pmtu")),
        );
```

- [ ] **Step 2: Проверка сборки и Android-пути**

Run: `cargo check -p outline-ws-rust && cargo check -p outline-ws-rust --no-default-features && (cd android/rust && cargo check)`
Expected: OK. Затем проверить, откуда Android берёт `state_path`: `grep -rn "state_path\|with_extension(\"state.toml\")" bins/outline-ws-rust/src/config/load/mod.rs android/rust/src`. Если Android запускает клиент через `load_config` с конфигом в каталоге приложения, файл `*.state.pmtu` ляжет туда же, и он доступен для записи. Если `state_path` на Android `None`, кэш работает только в памяти; это допустимо, отметить в CHANGELOG.

- [ ] **Step 3: Документация**

`bins/outline-ws-rust/README.md`, в описание раздела `[quic]` абзац:

```markdown
**Path MTU cache.** The client remembers the path MTU each H3 path settled at (keyed by server, port, fwmark and a hash of the local source address, i.e. the network it is on) in `<state_path>` with the extension `.pmtu` (default `<config>.state.pmtu`). The next dial on the same path probes that size first: one MTU probe instead of the 1326 → 1389 → 1420 → … ladder a passive observer would see on every connection. A stale value (the path shrank) costs one rejected probe size, after which the regular search runs below it. Entries expire 3 days after the path first settled at their value. The value is only ever the first probe; the Initial stays 1200 bytes.
```

`bins/outline-ws-rust/README.ru.md`, тот же абзац по-русски:

```markdown
**Кэш MTU пути.** Клиент запоминает MTU, на котором остановился каждый H3-путь (ключ — сервер, порт, fwmark и хэш локального source-адреса, то есть сеть, в которой он находится), в файле `<state_path>` с расширением `.pmtu` (по умолчанию `<config>.state.pmtu`). Следующее соединение по тому же пути первой пробой проверяет этот размер: одна MTU-проба вместо лесенки 1326 → 1389 → 1420 → …, которую пассивный наблюдатель видел бы на каждом соединении. Устаревшее значение (путь сузился) стоит одного отвергнутого размера, после чего ниже него идёт обычный поиск. Запись устаревает через 3 суток после того, как путь впервые подтвердил это значение. Значение используется только как первая проба; Initial остаётся 1200 байт.
```

`CHANGELOG.md` / `CHANGELOG.ru.md`, `## Unreleased`:

```markdown
- H3 carriers probe the cached path MTU first: one DPLPMTUD probe per connection on a known path instead of the full ladder. Cache file `<state_path>.pmtu`, 3-day TTL.
```

```markdown
- H3-носители первой пробой проверяют MTU пути из кэша: одна DPLPMTUD-проба на соединение на известном пути вместо всей лесенки. Файл кэша `<state_path>.pmtu`, срок жизни записи 3 суток.
```

- [ ] **Step 4: Коммит (только по команде владельца)**

```bash
git commit -m "feat(ws-rust): persist the h3 path MTU cache next to the state file" -- bins/outline-ws-rust/src/lib.rs bins/outline-ws-rust/README.md bins/outline-ws-rust/README.ru.md bins/outline-ws-rust/CHANGELOG.md bins/outline-ws-rust/CHANGELOG.ru.md
```

---

### Task 5: Сервер — опциональный `[server.h3].mtu_first_probe`

**Files:**
- Modify: `bins/outline-ss-rust/src/config/file.rs:139` (рядом с `initial_mtu`)
- Modify: `bins/outline-ss-rust/src/config/loader.rs:133`, `:290-320` (валидация рядом с `resolve_h3_initial_mtu`)
- Modify: `bins/outline-ss-rust/src/config/resolved.rs:79`
- Modify: `bins/outline-ss-rust/src/server/h3/mod.rs:39`, `:77`, `:104-171`
- Modify: `bins/outline-ss-rust/src/server/control/handlers.rs:253`, `:399`, `:409`; `bins/outline-ss-rust/src/server/control/persist.rs:268` — везде, где сейчас есть `h3_initial_mtu`, добавить парный `h3_mtu_first_probe` тем же образом (это полный список мест по `grep -rn h3_initial_mtu bins/outline-ss-rust/src`, без тестов)
- Test: `bins/outline-ss-rust/src/server/tests/h3.rs` (после `mtu_discovery_gets_within_a_few_bytes_of_a_narrow_path`), тест загрузчика — в существующий файл тестов `config/tests/` рядом с тестами `initial_mtu` (найти: `grep -rln "initial_mtu" bins/outline-ss-rust/src/config/tests`)
- Docs: `bins/outline-ss-rust/README.md:265` и `README.ru.md` (таблица ключей `[server.h3]`), `CHANGELOG{,.ru}.md`

**Interfaces:**
- Consumes: `MtuDiscoveryConfig::first_probe`, `PathStats::plpmtud_settled` (Task 1).
- Produces: `build_h3_quinn_server_config(tls_config, profile: &TuningProfile, pinned_initial_mtu: Option<u16>, mtu_first_probe: Option<u16>) -> Result<quinn::ServerConfig>`; `config::resolved::Config::h3_mtu_first_probe: Option<u16>`.

- [ ] **Step 1: Падающий серверный тест**

В `bins/outline-ss-rust/src/server/tests/h3.rs`:

```rust
/// `[server.h3].mtu_first_probe` on a path that carries it: the server sends a
/// single MTU probe instead of the 1426 → 1439 → 1445 → 1452 ladder.
#[tokio::test]
async fn mtu_first_probe_on_a_wide_path_is_the_only_probe() -> Result<()> {
    let (tls_config, cert_der) = test_h3_server_tls()?;
    let probe_config = sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    let server_config =
        build_h3_quinn_server_config(tls_config, &probe_config.tuning, None, Some(1452))?;
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.max_udp_payload_size(super::super::constants::H3_MAX_UDP_PAYLOAD_SIZE)?;
    let socket = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let server = quinn::Endpoint::new(
        endpoint_config,
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    let (path, relay) = spawn_narrow_downlink(server.local_addr()?, 65_535).await?;

    let accept = tokio::spawn({
        let server = server.clone();
        async move {
            server
                .accept()
                .await
                .context("server endpoint closed")?
                .await
                .map_err(anyhow::Error::from)
        }
    });
    let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    client.set_default_client_config(test_h3_client_config(cert_der)?);
    let _client_conn = client.connect(path, "localhost")?.await?;
    let conn = accept.await??;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut stats = conn.stats().path;
    while !(stats.plpmtud_settled && stats.sent_plpmtud_probes > 0)
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        stats = conn.stats().path;
    }
    relay.abort();
    assert_eq!(stats.current_mtu, 1452, "{stats:?}");
    assert_eq!(stats.sent_plpmtud_probes, 1, "{stats:?}");
    Ok(())
}
```

В существующий тест `mtu_discovery_gets_within_a_few_bytes_of_a_narrow_path` и во все прочие вызовы `build_h3_quinn_server_config(...)` добавить последний аргумент `None`.

Run: `cargo test -p outline-ss-rust mtu_`
Expected: ошибка компиляции — у `build_h3_quinn_server_config` 3 параметра.

- [ ] **Step 2: Конфиг и валидация**

`config/file.rs`, рядом с `initial_mtu` в секции `[server.h3]`:

```rust
    /// First DPLPMTUD probe size, a UDP payload size (1200–1452). Set it on a
    /// node whose clients' paths are known to carry that size: discovery then
    /// confirms it with one probe instead of a ladder. A path that does not
    /// carry it costs one rejected size before the regular search. Unset keeps
    /// the regular search. Ignored when `initial_mtu` is pinned.
    pub mtu_first_probe: Option<u16>,
```

`config/loader.rs`, рядом с `resolve_h3_initial_mtu`:

```rust
/// Validate `[server.h3].mtu_first_probe` (same bounds and units as `initial_mtu`).
fn resolve_h3_mtu_first_probe(input: Option<u16>) -> Result<Option<u16>> {
    let Some(value) = input else {
        return Ok(None);
    };
    if !(H3_MIN_INITIAL_MTU..=H3_MAX_INITIAL_MTU).contains(&value) {
        anyhow::bail!(
            "server.h3.mtu_first_probe must be between {H3_MIN_INITIAL_MTU} and \
             {H3_MAX_INITIAL_MTU} bytes (got {value}); it is a UDP payload size"
        );
    }
    Ok(Some(value))
}
```

и в сборке `Config` (строка ~133) рядом с `h3_initial_mtu`:

```rust
        h3_mtu_first_probe: resolve_h3_mtu_first_probe(server_h3.mtu_first_probe)?,
```

`config/resolved.rs` после `h3_initial_mtu`:

```rust
    /// `[server.h3].mtu_first_probe`: first DPLPMTUD probe size; `None` keeps
    /// the regular search.
    pub h3_mtu_first_probe: Option<u16>,
```

Новое поле `Config` ломает struct-литералы в тестах: добавить `h3_mtu_first_probe: None,` рядом с каждым `h3_initial_mtu: …,` в `bins/outline-ss-rust/src/metrics/tests/mod.rs`, `config/tests/validation.rs`, `server/nat/tests/mod.rs` (4 места), `server/tests/mod.rs`, `server/resumption/tests/registry.rs`, `server/control/tests/persist.rs` (полный список: `grep -rn "h3_initial_mtu:" bins/outline-ss-rust/src`).

Тест загрузчика — в файл тестов, где проверяется `initial_mtu`: значение 1452 принимается, 1199 и 1453 отклоняются с текстом `server.h3.mtu_first_probe must be between`. Скопировать структуру соседнего теста `initial_mtu` (тот же хелпер загрузки TOML), поменяв ключ.

- [ ] **Step 3: Применение в транспорте сервера**

`server/h3/mod.rs`: добавить параметр `mtu_first_probe: Option<u16>` в `build_h3_quinn_server_config` и `build_h3_transport_config`, передать его в обоих вызовах (строки ~39 и ~77) как `config.h3_mtu_first_probe`, и в `build_h3_transport_config` заменить настройку discovery на:

```rust
    let mut mtu = quinn::MtuDiscoveryConfig::default();
    mtu.upper_bound(discovery_upper_bound)
        .minimum_change(H3_MTU_DISCOVERY_MINIMUM_CHANGE)
        // A pinned host has upper_bound == initial_mtu, so quinn ignores the
        // first probe there (it is not above the current MTU).
        .first_probe(mtu_first_probe);
    transport.mtu_discovery_config(Some(mtu));
```

- [ ] **Step 4: Control API**

В `server/control/handlers.rs` (строки ~253, ~399, ~409) и `server/control/persist.rs` (~268) добавить поле `h3_mtu_first_probe: Option<u16>` рядом с `h3_initial_mtu`, заполняя его так же (`df.h3.as_ref().and_then(|h| h.mtu_first_probe)` и `state.config.h3_mtu_first_probe`). Если для `h3_initial_mtu` в `persist.rs` есть запись в TOML — повторить её для `mtu_first_probe` тем же кодом.

- [ ] **Step 5: Тесты и гейт сервера**

Run: `cargo test -p outline-ss-rust && cargo clippy -p outline-ss-rust --all-targets --no-deps -- -D warnings && cargo check -p outline-ss-rust --no-default-features`
Expected: PASS.

- [ ] **Step 6: Документация**

`bins/outline-ss-rust/README.md`, новая строка таблицы после `[server.h3].initial_mtu`:

```markdown
| `[server.h3].mtu_first_probe` | First path MTU discovery probe, as a **UDP payload** size (1200–1452). Set it on a node whose clients' paths are known to carry that size: discovery confirms it with one probe instead of the 1426 → 1439 → 1445 → 1452 ladder. A path that does not carry it costs one rejected size before the regular search, so do not set 1452 where clients sit behind a narrower tunnel (e.g. 1448). Unset keeps the regular search; ignored when `initial_mtu` is pinned |
```

`README.ru.md`:

```markdown
| `[server.h3].mtu_first_probe` | Первая проба поиска MTU пути, размер **UDP payload** (1200–1452). Ставить на узле, где пути клиентов заведомо пропускают этот размер: поиск подтверждает его одной пробой вместо лесенки 1426 → 1439 → 1445 → 1452. Путь, который его не пропускает, стоит одного отвергнутого размера перед обычным поиском, поэтому не ставить 1452 там, где клиенты за более узким туннелем (например, 1448). Без значения — обычный поиск; при закреплённом `initial_mtu` игнорируется |
```

`CHANGELOG.md` / `CHANGELOG.ru.md`, `## Unreleased`:

```markdown
- `[server.h3].mtu_first_probe`: optional first path MTU probe size; a known path is confirmed with one probe instead of a ladder. Off by default.
```

```markdown
- `[server.h3].mtu_first_probe`: необязательный размер первой пробы MTU пути; известный путь подтверждается одной пробой вместо лесенки. По умолчанию выключен.
```

- [ ] **Step 7: Коммит (только по команде владельца)**

```bash
git commit -m "feat(ss-rust): optional first path MTU probe for h3" -- bins/outline-ss-rust/src bins/outline-ss-rust/README.md bins/outline-ss-rust/README.ru.md bins/outline-ss-rust/CHANGELOG.md bins/outline-ss-rust/CHANGELOG.ru.md
```

---

### Task 6: Полный гейт, Linux в docker, выкатка

**Files:** нет изменений кода.

- [ ] **Step 1: Гейт workspace**

Run:
```bash
cargo fmt --check -p outline-transport -p outline-ws-rust -p outline-ss-rust
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
cargo check -p outline-ws-rust --no-default-features
cargo check -p outline-ss-rust --no-default-features
cargo test --workspace --exclude sockudo-ws
cargo test -p outline-transport --all-features
```
Expected: всё зелёное. Инварианты CI — прогнать скрипты из `.github/workflows` так же, как в CI (grep-инварианты ловят и комментарии).

- [ ] **Step 2: Linux в docker до коммита**

`local_source_ip` использует `connect` UDP-сокета с fwmark: на macOS fwmark недоступен, поэтому Linux-ветка проверяется только в docker (`rust:bookworm`, пустой `.cargo/config.toml`, target в docker volume, без `RUN_E2E_FAILOVER`): `cargo test -p outline-transport --all-features quic::` и `cargo test -p quinn-proto --lib`.

- [ ] **Step 3: Выкатка клиента (по одному узлу, с согласия владельца)**

Порядок: сначала один клиентский узел парка (свериться с `FLEET.local.md`, какие узлы запускают `outline-ws-rust`), через `ops/deploy/deploy-binary.sh`. Проверки на узле:
1. Через 1–2 минуты появился файл `<config>.state.pmtu`, в нём строки `сервер:порт|fw=…|net=…\t<mtu>\t<время>`.
2. `rate(outline_ws_quic_mtu_probes_lost_total[10m])` по транспортам `ws_h3`/`xhttp_h3` не выросла относительно дня до выкатки (на путях 1448 должна упасть: исчезает 1452✗×3 на каждом соединении).
3. Гистограмма MTU пути из `record_quic_path_sample` не сместилась вниз.
4. На WAN-интерфейсе узла: `tcpdump -nn -i <wan> udp and host <server_ip> -c 300` после рестарта (с согласия) — после рукопожатия одиночный пакет пробы нужного размера вместо серии 1326/1389/1420/….

Только после этого — следующий узел, затем сборки macOS и Android (на Android проверить, что файл `.state.pmtu` создаётся в каталоге приложения; если нет — кэш в памяти, отметить).

- [ ] **Step 4: Сервер**

Бинарь с Task 5 без `mtu_first_probe` в конфиге ведёт себя как раньше. Ставить ключ — отдельным решением владельца по узлам, после просмотра гистограммы MTU пути сервера: на узле, где почти все клиентские пути 1452, — `mtu_first_probe = 1452`; где заметная доля за туннелем 1448 — не ставить.
