# Истёкшая запись кэша MTU как первая проба без потолка — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Цель:** убрать ежечасную полную лесенку DPLPMTUD-проб на путях, чей MTU ниже 1452 (сейчас это nuxt2 = 1448). Для этого истёкшая запись кэша по-прежнему уходит первой пробой, но потолка соединению не ставит.

**Почему (замер 2026-11-04, после выкатки `92c3153f`):** `outline_ws_quic_mtu_probes_lost_total` на cloud1/cloud2 упал почти до нуля, но на .102/.104 остался на уровне 18–36/ч. Весь остаток приходится на путь к nuxt2:
- запись ниже 1452 живёт 1 ч, и подтверждение её не продлевает (`should_record`);
- поэтому раз в час дозвон к nuxt2 идёт без подсказки: полная лесенка 1326 → 1389 → 1420 → … (её видит DPI);
- соединение после такого дозвона остаётся без потолка и всю жизнь теряет по 3 пробы на каждом повторном поиске (раз в 600 с);
- запись nuxt2 на всех 4 клиентах перезаписана ровно через час после первой.

**Архитектура:** у первой пробы quinn-proto появляется режим «без потолка» (`MtuDiscoveryConfig::first_probe_caps(false)`).
- Если такая проба подтверждена, поиск продолжается вверх от неё, а не заканчивается на ней.
- Если отвергнута, поиск идёт ниже неё, как раньше.
- Потолок в этом режиме не ставится ни в одном исходе.

Кэш клиента различает два вида подсказки:
- **живая запись** — первая проба с потолком (как сейчас);
- **истёкшая запись** (младше 30 суток) — проба-«затравка» без потолка.

Соединение, остановившееся на своей затравке, записывает значение заново, и следующий час дозвоны опять идут с потолком. Решения владельца остаются в силе: потолок задаёт только первая проба, а заниженное значение не может жить дольше часа. Выросший путь затравка находит сама: она ищет вверх.

**Стек:** Rust, vendored `quinn-proto 0.11.15` (`vendor/quinn-proto`, `[patch.crates-io]`), `crates/outline-transport` (feature `h3`).

## Общие ограничения

- Комментарии в коде, коммиты и PR — на английском. План и диалог — на русском.
- Не коммитить и не пушить без явной команды владельца. Коммитить `git commit -- <paths>`: в общем индексе бывает чужое. Без `Co-Authored-By` и любой атрибуции Claude. Работа в `main`, без веток.
- Тесты outline-transport лежат в `quic/tests/*.rs` (`#[path]`). В vendored quinn-proto тесты inline, в стиле upstream.
- Обращения к патченному API quinn-proto — только через гейт `crates/outline-transport/src/quic/vendored.rs`. Серверный гейт `bins/outline-ss-rust/src/server/h3/vendored.rs` не меняется: сервер использует режим по умолчанию (с потолком).
- Документация меняется парами EN/RU: `PATCHES.md`/`PATCHES.ru.md`, `bins/outline-ws-rust/README.md`/`README.ru.md`, `CHANGELOG.md`/`CHANGELOG.ru.md`.
- В `workspace` тесты `quinn-proto` не компилируются (dev-dependencies обрезаны при вендоринге). Их гоняют во временной копии крейта (см. Task 1, шаг 2).
- Гейт перед коммитом, как в CI:
  - `cargo fmt --check -p outline-transport -p outline-ws-rust -p outline-ss-rust`;
  - `cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings`;
  - `cargo check -p outline-ws-rust --no-default-features` и `cargo check -p outline-ss-rust --no-default-features`;
  - `cargo test --workspace --exclude sockudo-ws` и `cargo test -p outline-transport --all-features`;
  - grep-инварианты CI;
  - Linux в docker (`rust:bookworm`) ДО коммита.
- Выкатка — только с согласия владельца, по одному узлу, через `ops/deploy/deploy-binary.sh`. Поведение меняется только у клиента. Сервер собирается с новым quinn-proto, но режим по умолчанию у него прежний, поэтому серверы не перевыкатываются.

---

### Task 1: quinn-proto — режим первой пробы без потолка

**Files:**
- Modify: `vendor/quinn-proto/src/config/transport.rs` (структура `MtuDiscoveryConfig` около стр. 1005; setter после `first_probe` около стр. 1065; `Default` около стр. 1071)
- Modify: `vendor/quinn-proto/src/connection/mtud.rs` (`on_probe_acked` около стр. 261, `on_probe_lost` около стр. 277, `SearchState` около стр. 308–400, inline-тесты в конце)
- Modify: `quinn-proto-0.11.15.patch`, `PATCHES.md`, `PATCHES.ru.md` (пункт 4 «mtud-first-probe»)

**Interfaces:**
- Produces: `MtuDiscoveryConfig::first_probe_caps(&mut self, value: bool) -> &mut Self`, по умолчанию `true` (текущее поведение).

- [ ] **Step 1: Написать падающие тесты** (в `mod tests` файла `mtud.rs`, рядом с `mtud_with_first_probe`)

```rust
    fn mtud_with_seed(first_probe: u16) -> MtuDiscovery {
        let mut config = MtuDiscoveryConfig::default();
        config
            .minimum_change(4)
            .first_probe(Some(first_probe))
            .first_probe_caps(false);
        MtuDiscovery::new(1_200, 1_200, None, config)
    }

    #[test]
    fn confirmed_seed_keeps_searching_upward() {
        let mut mtud = mtud_with_seed(1_448);
        let probed = drive_to_completion(&mut mtud, Instant::now(), 1_452);
        assert_eq!(probed, [1_448, 1_452]);
        assert_eq!(mtud.current_mtu(), 1_452);
        assert_eq!(mtud.state.as_ref().unwrap().ceiling, None);
    }

    #[test]
    fn confirmed_seed_on_its_own_path_costs_one_rejected_size() {
        let mut mtud = mtud_with_seed(1_448);
        let probed = drive_to_completion(&mut mtud, Instant::now(), 1_448);
        assert_eq!(probed, [1_448, 1_452, 1_452, 1_452]);
        assert_eq!(mtud.current_mtu(), 1_448);
        assert_eq!(mtud.state.as_ref().unwrap().ceiling, None);
    }

    #[test]
    fn rejected_seed_searches_below_it_and_leaves_no_ceiling() {
        let mut mtud = mtud_with_seed(1_448);
        let probed = drive_to_completion(&mut mtud, Instant::now(), 1_440);
        assert_eq!(&probed[..3], [1_448, 1_448, 1_448]);
        assert!(probed[3..].iter().all(|&size| size < 1_448), "{probed:?}");
        assert!((1_436..=1_440).contains(&mtud.current_mtu()), "{probed:?}");
        assert_eq!(mtud.state.as_ref().unwrap().ceiling, None);
    }

    #[test]
    fn later_searches_after_a_seed_are_not_capped() {
        let mut mtud = mtud_with_seed(1_448);
        let now = Instant::now();
        drive_to_completion(&mut mtud, now, 1_448);
        let later = now + Duration::from_secs(601);
        // The re-search probes above the seed again (no ceiling)
        assert_eq!(mtud.poll_transmit(later, 100), Some(1_452));
    }

    #[test]
    fn first_probe_caps_by_default() {
        assert!(MtuDiscoveryConfig::default().first_probe_caps);
    }
```

- [ ] **Step 2: Подготовить временную копию крейта и убедиться, что тесты падают**

```bash
Q=/private/tmp/claude-501/qp-seed && rm -rf $Q && mkdir -p $Q
tar xzf ~/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/quinn-proto-0.11.15.crate -C $Q
rsync -a --delete vendor/quinn-proto/src/ $Q/quinn-proto-0.11.15/src/
cd $Q/quinn-proto-0.11.15 && cargo test --lib connection::mtud
```

Ожидается ошибка компиляции: `no method named first_probe_caps` / `no field first_probe_caps`. Копия крейта нужна потому, что в ней сохранены upstream dev-dependencies. После каждой правки снова делать `rsync` (команда выше).

- [ ] **Step 3: Реализация в `config/transport.rs`**

В структуру `MtuDiscoveryConfig` после `first_probe` добавить поле:

```rust
    pub(crate) first_probe_caps: bool,
```

Setter сразу после `first_probe(...)`:

```rust
    /// Whether the outcome of [`first_probe`](Self::first_probe) caps the connection
    /// (outline-proxy patch). Defaults to `true`.
    ///
    /// With `false` the first probe is only a seed: if it is acknowledged the search keeps
    /// going upward from it instead of ending there, if it is lost (all retransmits) the
    /// search runs below it as usual, and no ceiling is set in either case, so later searches
    /// run as in upstream. Meant for a cached size that is old enough to be re-checked: it
    /// still replaces the ladder of probes, and a path that grew is still found.
    pub fn first_probe_caps(&mut self, value: bool) -> &mut Self {
        self.first_probe_caps = value;
        self
    }
```

В `Default` после `first_probe: None,` добавить `first_probe_caps: true,`.

- [ ] **Step 4: Реализация в `connection/mtud.rs`**

В `SearchState` добавить поле (после `probing_first`):

```rust
    /// Whether a confirmed first probe ends the search (`MtuDiscoveryConfig::first_probe_caps`)
    first_probe_caps: bool,
```

В `SearchState::new` в литерале `Self { ... }` добавить `first_probe_caps: config.first_probe_caps,`.

В `next_mtu_to_probe` заменить

```rust
            if self.probing_first {
                // A confirmed first probe ends the search and caps the connection
                self.upper_bound = self.last_probed_mtu;
            }
```

на

```rust
            if self.probing_first && self.first_probe_caps {
                // A confirmed first probe ends the search and caps the connection
                self.upper_bound = self.last_probed_mtu;
            }
```

В `EnabledMtuDiscovery::on_probe_acked` заменить условие `if state.probing_first {` на `if state.probing_first && state.first_probe_caps {`. Комментарий над ним дополнить: `// (and only when it caps: a seed sets none)`.

В `EnabledMtuDiscovery::on_probe_lost` заменить условие на `if state.probing_first && state.first_probe_caps && state.lost_probe_count >= MAX_PROBE_RETRANSMITS {`.

- [ ] **Step 5: Прогнать тесты во временной копии**

```bash
rsync -a --delete vendor/quinn-proto/src/ /private/tmp/claude-501/qp-seed/quinn-proto-0.11.15/src/
cd /private/tmp/claude-501/qp-seed/quinn-proto-0.11.15 && cargo test --lib
```

Ожидается: все тесты зелёные, включая 5 новых. До правки было 277. Затем в workspace выполнить `cargo check -p quinn-proto` и `cargo clippy -p quinn-proto --no-deps -- -D warnings`.

- [ ] **Step 6: Пересобрать патч-артефакт и обновить PATCHES**

По процедуре из `PATCHES.md`:
1. Распаковать чистый crates.io-крейт во временный git-репозиторий и закоммитить его как baseline.
2. Скопировать поверх `vendor/quinn-proto/src` и `Cargo.toml`; `git diff` даёт новый `quinn-proto-0.11.15.patch`.
3. Проверить: `patch -p1` на другой чистой копии, затем `diff -r src/`. Вывод должен быть пустым.

В `PATCHES.md`, пункт 4 «mtud-first-probe», после предложения про `None (the default) keeps upstream behaviour.` вставить:

```
   `MtuDiscoveryConfig::first_probe_caps(false)` turns the first probe into a seed: an
   acknowledged seed does not end the search (it continues upward from it), a rejected one
   searches below it as usual, and neither sets a ceiling. The H3 client seeds with an
   expired cache entry, so the hourly re-check of a low value costs one probe size instead
   of the ladder and still finds a path that grew.
```

В `PATCHES.ru.md` вставить тот же абзац по-русски на том же месте:

```
   `MtuDiscoveryConfig::first_probe_caps(false)` превращает первую пробу в затравку:
   подтверждённая затравка не заканчивает поиск (он продолжается вверх от неё),
   отвергнутая — поиск идёт ниже неё как обычно, и потолка не ставит ни то, ни другое.
   H3-клиент даёт затравкой истёкшую запись кэша, поэтому ежечасная перепроверка низкого
   значения стоит одного размера пробы вместо лесенки и всё равно находит выросший путь.
```

- [ ] **Step 7: Коммит (только по команде владельца)**

```bash
git commit -m "feat(quinn-proto): let the first MTU probe seed the search without capping it" -- vendor/quinn-proto/src quinn-proto-0.11.15.patch PATCHES.md PATCHES.ru.md
```

---

### Task 2: кэш MTU — истёкшая запись как затравка

**Files:**
- Modify: `crates/outline-transport/src/quic/vendored.rs` (тип `FirstProbe`, `set_mtu_first_probe`)
- Modify: `crates/outline-transport/src/quic/tls_config.rs` (стр. 173–201, 233–243, 287–304)
- Modify: `crates/outline-transport/src/quic/pmtu_cache.rs` (`hint`, `first_probe_for`, `should_record`, `spawn_recorder`, константа)
- Modify: `crates/outline-transport/src/quic/mod.rs` (если понадобится реэкспорт `FirstProbe` для `h3`/`xhttp`)
- Modify: `crates/outline-transport/src/h3/shared.rs:781-834`, `crates/outline-transport/src/xhttp/h3_pool.rs:343-391` (типы меняются, логика нет)
- Modify: `.github/workflows/ci.yml` (grep-инвариант quinn-proto), `AGENTS.md` (список патченного API, стр. ~294)
- Test: `crates/outline-transport/src/quic/tests/pmtu_cache.rs`, `crates/outline-transport/src/quic/tests/tls_config.rs` (стр. ~1794–1850)

**Interfaces:**
- Consumes: `MtuDiscoveryConfig::first_probe_caps(bool)` из Task 1.
- Produces:
  - `pub(crate) struct FirstProbe { pub(crate) size: u16, pub(crate) caps: bool }` в `quic/vendored.rs` с конструкторами `FirstProbe::capped(u16)` и `FirstProbe::seed(u16)`; derive `Debug, Clone, Copy, PartialEq, Eq`.
  - `vendored::set_mtu_first_probe(mtu: &mut quinn::MtuDiscoveryConfig, first_probe: Option<FirstProbe>)`.
  - `PmtuCache::hint(&self, key: &str, now: SystemTime) -> Option<FirstProbe>`.
  - `pmtu_cache::first_probe_for(&PmtuKey) -> Option<FirstProbe>`.
  - `pmtu_cache::should_record(first_probe: Option<FirstProbe>, settled_mtu: u16) -> bool`.
  - `spawn_recorder(connection, key, first_probe: Option<FirstProbe>)`.
  - `build_h3_transport_with_first_probe(tp, runtime, first_probe: Option<FirstProbe>)`.
  - `h3_quic_client_config_with_first_probe(first_probe: Option<FirstProbe>)`.

- [ ] **Step 1: Обновить тесты кэша** (`quic/tests/pmtu_cache.rs`)

В `use` добавить `use super::super::vendored::FirstProbe;` и константу `const SEED_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);`.

Изменить ожидания существующих тестов. Каждое `Some(N)` из `hint` становится `Some(FirstProbe::capped(N))`, а места, где сейчас ждут `None` после истечения TTL, ждут затравку:
- `upper_bound_value_is_the_hint_until_the_long_ttl_expires`: последняя строка — `assert_eq!(cache.hint("k", t0 + TTL), Some(FirstProbe::seed(1_452)));`.
- `value_below_the_upper_bound_expires_after_an_hour`: последняя строка — `assert_eq!(cache.hint("k", t0 + HOUR), Some(FirstProbe::seed(1_448)));`.
- `same_value_does_not_refresh_the_entry`: `Some(FirstProbe::seed(1_452))`, сообщение то же.
- `low_value_is_re_searched_an_hour_after_it_was_first_stored`: `Some(FirstProbe::seed(1_417))`; сообщение второго assert — `"a seeded connection stores an expired entry afresh"`.
- `ttl_class_follows_the_stored_value_across_changes`: строки с `None` → `Some(FirstProbe::seed(1_448))` и `Some(FirstProbe::seed(1_452))`.
- `values_outside_the_quic_range_are_rejected` и `missing_entry_has_no_hint`: `None` остаётся.

Тесты `should_record` переписать:

```rust
#[test]
fn recorder_skips_a_connection_that_settled_at_its_capping_first_probe() {
    assert!(!should_record(Some(FirstProbe::capped(1_417)), 1_417));
    assert!(!should_record(Some(FirstProbe::capped(1_452)), 1_452));
}

#[test]
fn recorder_stores_full_searches_seeds_and_changed_results() {
    assert!(should_record(None, 1_417), "no hint means a full search");
    assert!(should_record(Some(FirstProbe::capped(1_452)), 1_448), "the path shrank");
    assert!(should_record(Some(FirstProbe::capped(1_417)), 1_400), "the hint was clamped");
    assert!(
        should_record(Some(FirstProbe::seed(1_448)), 1_448),
        "a seed searched above itself, so settling there is a real observation"
    );
}
```

Новые тесты:

```rust
#[test]
fn expired_entry_is_a_seed_until_the_seed_age_limit() {
    let cache = PmtuCache::new(None, TTL);
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    assert!(cache.record("k", 1_448, t0));
    assert_eq!(cache.hint("k", t0 + HOUR), Some(FirstProbe::seed(1_448)));
    assert_eq!(
        cache.hint("k", t0 + SEED_MAX_AGE - Duration::from_secs(1)),
        Some(FirstProbe::seed(1_448))
    );
    assert_eq!(cache.hint("k", t0 + SEED_MAX_AGE), None, "too old to seed");
}

#[test]
fn seeded_result_restarts_the_capped_hour() {
    let cache = PmtuCache::new(None, TTL);
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let t1 = t0 + HOUR + Duration::from_secs(5);
    assert!(cache.record("k", 1_448, t0));
    assert_eq!(cache.hint("k", t1), Some(FirstProbe::seed(1_448)));
    assert!(cache.record("k", 1_448, t1), "the expired entry is stored afresh");
    assert_eq!(cache.hint("k", t1 + Duration::from_secs(1)), Some(FirstProbe::capped(1_448)));
    assert_eq!(cache.hint("k", t1 + HOUR), Some(FirstProbe::seed(1_448)));
}
```

- [ ] **Step 2: Обновить интеграционные тесты** (`quic/tests/tls_config.rs`)

`settle_with_first_probe(path_limit: u16, first_probe: Option<FirstProbe>)`; в вызовах существующих тестов `Some(1448)` → `Some(FirstProbe::capped(1448))`. В начало файла (или в функцию) добавить `use super::super::vendored::FirstProbe;`.

Новые тесты после `h3_without_first_probe_keeps_the_binary_search`:

```rust
/// An expired cached MTU seeds the search: one probe at the cached size, then
/// the search goes on upward and finds a path that grew. No ladder.
#[tokio::test]
async fn h3_seed_finds_a_path_that_grew() {
    let stats = settle_with_first_probe(1452, Some(FirstProbe::seed(1448))).await;
    assert!(stats.plpmtud_settled, "{stats:?}");
    assert_eq!(stats.current_mtu, 1452, "{stats:?}");
    assert_eq!(stats.sent_plpmtud_probes, 2, "{stats:?}");
    assert_eq!(stats.lost_plpmtud_probes, 0, "{stats:?}");
}

/// A seed on an unchanged path costs one rejected size above it, not the ladder.
#[tokio::test]
async fn h3_seed_on_an_unchanged_path_costs_one_rejected_size() {
    let stats = settle_with_first_probe(1448, Some(FirstProbe::seed(1448))).await;
    assert!(stats.plpmtud_settled, "{stats:?}");
    assert_eq!(stats.current_mtu, 1448, "{stats:?}");
    assert_eq!(stats.sent_plpmtud_probes, 4, "{stats:?}");
    assert_eq!(stats.lost_plpmtud_probes, 3, "{stats:?}");
}
```

Если `sent_plpmtud_probes` в quinn считает повторы иначе, сверить с фактическим числом на `h3_stale_first_probe_still_finds_the_path_mtu`: суть теста в том, что размеров ровно два (1448 и 1452), а не лесенка.

- [ ] **Step 3: Убедиться, что тесты не компилируются**

Run: `cargo test -p outline-transport --all-features quic::`
Expected: ошибки `cannot find type FirstProbe` / несовпадение типов.

- [ ] **Step 4: Гейт `quic/vendored.rs`**

Заменить `set_mtu_first_probe` на:

```rust
/// First DPLPMTUD probe of a dial (`MtuDiscoveryConfig::first_probe`). `caps` keeps the
/// probe's outcome as the connection's ceiling (`first_probe_caps`); a seed only replaces
/// the ladder and leaves the search free to go above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FirstProbe {
    pub(crate) size: u16,
    pub(crate) caps: bool,
}

impl FirstProbe {
    pub(crate) const fn capped(size: u16) -> Self {
        Self { size, caps: true }
    }

    pub(crate) const fn seed(size: u16) -> Self {
        Self { size, caps: false }
    }
}

/// `None` keeps upstream's binary search from the start.
pub(crate) fn set_mtu_first_probe(
    mtu: &mut quinn::MtuDiscoveryConfig,
    first_probe: Option<FirstProbe>,
) {
    mtu.first_probe(first_probe.map(|p| p.size))
        .first_probe_caps(first_probe.is_none_or(|p| p.caps));
}
```

- [ ] **Step 5: `tls_config.rs`**

Заменить тип `Option<u16>` на `Option<super::vendored::FirstProbe>` в трёх сигнатурах: `build_h3_transport_with_first_probe`, `apply_quic_carrier_tuning`, `h3_quic_client_config_with_first_probe`. Тела не меняются (`first_probe.is_some()` и проброс остаются как есть). В doc-комментарии `h3_quic_client_config_with_first_probe` заменить «probing `first_probe` first» на «probing `first_probe` first (capped or as a seed)».

Если `FirstProbe` нужен вне `quic` (в `h3/shared.rs`, `xhttp/h3_pool.rs` он используется только транзитом через `first_probe_for` → `spawn_recorder` и `h3_quic_client_config_with_first_probe`, так что явное имя типа там не понадобится), реэкспорт не добавлять.

- [ ] **Step 6: `pmtu_cache.rs`**

Добавить импорт `use super::vendored::FirstProbe;` и константу после `PMTU_CACHE_SHORT_TTL`:

```rust
/// An expired entry younger than this still seeds the next dial's search
/// (`FirstProbe::seed`): one probe at the old size instead of the ladder, with no
/// ceiling, so a path that grew or shrank is still found. Older entries (a network
/// not seen for a month) give no hint at all.
const PMTU_SEED_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);
```

`hint`:

```rust
    /// First probe for `key`: a live entry caps the connection at its value, an
    /// expired one younger than `PMTU_SEED_MAX_AGE` only seeds the search.
    pub(crate) fn hint(&self, key: &str, now: SystemTime) -> Option<FirstProbe> {
        let entry = *self.entries.lock().get(key)?;
        let now_secs = unix_secs(now);
        if self.is_live(&entry, now_secs) {
            Some(FirstProbe::capped(entry.mtu))
        } else if now_secs < entry.confirmed_at.saturating_add(PMTU_SEED_MAX_AGE.as_secs()) {
            Some(FirstProbe::seed(entry.mtu))
        } else {
            None
        }
    }
```

`first_probe_for` возвращает `Option<FirstProbe>` (тело то же).

`should_record` и его doc:

```rust
/// Whether a settled `settled_mtu` is worth storing for a dial that used
/// `first_probe`. A connection that settled exactly at its confirmed capping
/// first probe only proves that size works: that probe is its ceiling, so it
/// says nothing about larger sizes and must not refresh the entry (otherwise a
/// low value would never be re-checked while such a carrier lives). A seed
/// searched above itself, so wherever it settled is a real observation, as is a
/// full search (no hint) or a result different from the hint.
pub(crate) fn should_record(first_probe: Option<FirstProbe>, settled_mtu: u16) -> bool {
    !first_probe.is_some_and(|p| p.caps && p.size == settled_mtu)
}
```

`spawn_recorder(..., first_probe: Option<FirstProbe>)`; doc-строку «connections that settled at their own `first_probe`» дополнить словом «capping».

Doc модуля (шапка файла) дополнить абзацем:

```rust
//! A live entry is a capping first probe; an expired one (younger than
//! `PMTU_SEED_MAX_AGE`) is a seed that searches on above itself, so the periodic
//! re-check of an entry never falls back to the ladder.
```

Комментарии у `PMTU_CACHE_TTL` и `PMTU_CACHE_SHORT_TTL` поправить: «is found again by a full search» / «re-checked by a full search» → «is re-checked by a seeded search».

- [ ] **Step 7: CI-инвариант и AGENTS.md**

В `.github/workflows/ci.yml`, шаг `invariant — patched quinn-proto API only behind the gate module`, в регулярное выражение после `\.first_probe(` добавить `\|\.first_probe_caps(`, а в комментарий над шагом — `MtuDiscoveryConfig::first_probe_caps`. В `AGENTS.md` в перечень патченного API (около стр. 294) рядом с `MtuDiscoveryConfig::first_probe` добавить `MtuDiscoveryConfig::first_probe_caps`.

- [ ] **Step 8: Прогнать тесты и гейт**

```bash
cargo test -p outline-transport --all-features quic::
cargo test -p outline-transport --all-features
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
cargo check -p outline-ws-rust --no-default-features && cargo check -p outline-ss-rust --no-default-features
cargo fmt --check -p outline-transport -p outline-ws-rust -p outline-ss-rust
```

Отдельно прогнать grep-инвариант из `ci.yml` локально: он должен напечатать `ok: patched quinn-proto API stays behind the gate module`.

Ожидается: всё зелёное. В transport было 433 теста, станет 437: +2 в pmtu_cache и +2 интеграционных, а `should_record`-тесты переименованы, но их не стало больше.

- [ ] **Step 9: Коммит (только по команде владельца)**

```bash
git commit -m "feat(transport): seed the MTU search with an expired cache entry instead of the ladder" -- crates/outline-transport/src .github/workflows/ci.yml AGENTS.md
```

---

### Task 3: документация клиента

**Files:**
- Modify: `bins/outline-ws-rust/README.md:812`, `bins/outline-ws-rust/README.ru.md:812` (абзац «Path MTU cache» / «Кэш MTU пути»)
- Modify: `bins/outline-ws-rust/CHANGELOG.md`, `bins/outline-ws-rust/CHANGELOG.ru.md` (пункт «H3 path MTU cache» в `[Unreleased]`)

- [ ] **Step 1: README EN**

В абзаце заменить фрагмент от `The cached value is the first probe and, once confirmed, the connection's ceiling:` до `does not cap connections for days.` на:

```
A live cached value is the first probe and, once confirmed, the connection's ceiling. A value of 1452 (the H3 upper bound) stays live for 3 days after the path first settled at it; a value below 1452 for 1 hour, so a search that settled low after a spurious probe loss does not cap connections for days. An expired value (up to 30 days old) is still the first probe but only seeds the search: the search goes on above it and sets no ceiling, so a path that grew or shrank is found without the ladder, and the result is stored afresh.
```

- [ ] **Step 2: README RU** — тот же смысл на месте фрагмента от `Значение из кэша — это первая проба` до `сутками.`:

```
Живое значение из кэша — это первая проба, а после подтверждения — потолок соединения. Значение 1452 (верхняя граница H3) живо 3 суток с момента, когда путь впервые его подтвердил, значение ниже 1452 — 1 час: если поиск остановился низко из-за случайной потери пробы, он не ограничивает соединения сутками. Истёкшее значение (не старше 30 суток) всё равно уходит первой пробой, но только как затравка: поиск продолжается выше неё и потолка не ставит, поэтому выросший или сузившийся путь находится без лесенки, а результат записывается заново.
```

- [ ] **Step 3: CHANGELOG EN/RU**

В пункте «H3 path MTU cache» заменить `A confirmed first probe is the connection's ceiling, so values below 1452 are re-checked by a full search after 1 hour and 1452 after 3 days;` на `A confirmed first probe is the connection's ceiling while the entry is live (1 hour below 1452, 3 days at 1452); an expired entry up to 30 days old seeds the search without a ceiling, so the re-check costs one probe size instead of the ladder;`. В `CHANGELOG.ru.md` сделать ту же правку по-русски в соответствующем пункте.

- [ ] **Step 4: Коммит (только по команде владельца)**

```bash
git commit -m "docs(ws-rust): describe the seeded re-check of the path MTU cache" -- bins/outline-ws-rust/README.md bins/outline-ws-rust/README.ru.md bins/outline-ws-rust/CHANGELOG.md bins/outline-ws-rust/CHANGELOG.ru.md
```

---

### Task 4: Linux-проверка, пуш, выкатка клиентов (каждый шаг — по согласию владельца)

- [ ] **Step 1: Linux в docker ДО коммита**

Контейнер `rust:bookworm`, пустой `.cargo/config.toml`, target в docker volume, без `RUN_E2E_FAILOVER`:
- `cargo test -p outline-transport --all-features quic::`;
- `cargo test --workspace --exclude sockudo-ws`;
- `cargo test --lib` во временной копии quinn-proto.

Ожидается: всё зелёное.

- [ ] **Step 2: Пуш по команде владельца, затем `gh run list --limit 3` / `gh run watch`** — CI должен быть зелёным, включая feature-matrix и grep-инварианты.

- [ ] **Step 3: Выкатка только `outline-ws-rust`, по одному узлу**

Порядок cloud2 → cloud1 → .104 → .102, nightly-ассеты сверяются с `SHA256SUMS`, установка `ops/deploy/deploy-binary.sh <host> outline-ws-rust <binary>`. Серверы (`outline-ss-rust`) не перевыкатываются. Рестарт клиента рвёт только его собственные соединения, поэтому переводить соседей на другие ноги (`/control/activate`) не нужно. После каждого узла: ноги healthy, выбранные аплинки совпадают с исходными, `state.pmtu` на месте.

- [ ] **Step 4: Приёмка через сутки после выкатки**

Сравнить `sum by (instance) (increase(outline_ws_quic_mtu_probes_lost_total[1h]))` в VictoriaMetrics (`https://vm.k3s.beerloga.su`) с замером 2026-11-04. Ожидается:
- на .102/.104 остаток падает с 18–36/ч до единиц в час: 3 потери на затравочное соединение к nuxt2 раз в час плюс по 3 каждые 600 с, пока оно живёт;
- в `state.pmtu` записи nuxt2 обновляются раз в час, но по сети идут две пробы (1448, 1452×3), а не лесенка.

Проверка по сети (по желанию): `tcpdump` UDP к nuxt2 на клиенте после рукопожатия — пробы PING+PADDING размеров 1448/1452, без 1326/1389/1420.

---

## Что сознательно не делается

- **Затравочное соединение не получает потолок после поиска.** Потолок от любого завершённого поиска владелец уже отверг: случайная потеря закрепила бы заниженное значение. Поэтому одно соединение в час на путь ниже 1452 продолжает терять по 3 пробы каждые 600 с.
- **Сервер не меняется.** `[server.h3].mtu_first_probe` остаётся с потолком; режим затравки серверу не нужен, у него нет кэша.
