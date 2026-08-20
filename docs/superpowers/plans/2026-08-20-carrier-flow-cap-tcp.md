# Общий `max_carrier_flows` для TCP+UDP — план реализации

> **Для агентных исполнителей:** ОБЯЗАТЕЛЬНЫЙ СУБ-СКИЛЛ:
> superpowers:subagent-driven-development или superpowers:executing-plans.
> Шаги размечены чекбоксами (`- [ ]`).

**Цель:** сделать `[tun] max_carrier_flows` общим потолком на туннельные флоу
обоих протоколов, с LRU-эвикшном при упирании.

**Архитектура:** общий счётчик слотов (`CarrierSlots`) раздаётся обоим движкам по
образцу `dial_admission`; TCP заводит собственный индекс эвикшна только для
туннельных флоу; освобождение слота — в уже существующем `Drop for TcpFlowState`;
при `route_by_sni` слот переучитывается на флипе маршрута.

**Спека:** `docs/superpowers/specs/2026-08-20-carrier-flow-cap-tcp-design.md`

## Глобальные ограничения

- Дефолт `max_carrier_flows = 0` (выключено) не меняется.
- Общий счётчик — да; общий LRU-индекс — нет (ключи и действие эвикшна
  протоколозависимы). Каждый протокол вытесняет своих; если своих нет — отказ.
- Причина закрытия `"carrier_cap"` отдельно от существующего `"evicted"`.
- Тесты — в подкаталогах `tests/` рядом с модулем, без inline `#[cfg(test)] mod`.
- CI-гейт целиком и в порядке (fmt → clippy → test), `cargo fmt --all` НЕ гонять.
- Документация парами EN/RU в одном изменении.
- `git commit` — только по явной команде владельца; ветки не создавать.
- Прод не трогать; раскатка отдельно.

---

### Task 1: `CarrierSlots` + раздача обоим движкам + метрика

**Файлы:**
- Создать: `crates/outline-tun/src/carrier_slots.rs`
- Тест: `crates/outline-tun/src/tests/carrier_slots.rs`
- Изменить: `crates/outline-tun/src/lib.rs` (объявить модуль)
- Изменить: `crates/outline-tun/src/engine.rs:118-125` (создание и раздача)
- Изменить: `crates/outline-tun/src/tcp/engine/mod.rs:66` (поле + сеттер)
- Изменить: `crates/outline-tun/src/udp/engine.rs:110` (поле + сеттер)
- Изменить: `crates/outline-metrics/src/{registration/tun.rs,tun.rs,stub.rs,lib.rs}`

**Интерфейсы (Produces):**
```rust
pub(crate) struct CarrierSlots { used: AtomicUsize, cap: usize }
impl CarrierSlots {
    pub(crate) fn new(cap: usize) -> Self;
    pub(crate) fn cap(&self) -> usize;          // 0 = выключено
    pub(crate) fn in_use(&self) -> usize;
    pub(crate) fn try_acquire(&self) -> bool;   // false = мест нет
    pub(crate) fn release(&self);               // saturating
}
```

- [ ] **Шаг 1: Написать падающий тест**

`crates/outline-tun/src/tests/carrier_slots.rs`:

```rust
use super::super::carrier_slots::CarrierSlots;

#[test]
fn acquires_up_to_cap_then_refuses() {
    let slots = CarrierSlots::new(2);
    assert!(slots.try_acquire());
    assert!(slots.try_acquire());
    assert!(!slots.try_acquire(), "cap must bind");
    assert_eq!(slots.in_use(), 2);
    slots.release();
    assert!(slots.try_acquire(), "a released slot is reusable");
}

#[test]
fn zero_cap_means_disabled_and_never_refuses() {
    let slots = CarrierSlots::new(0);
    for _ in 0..1000 {
        assert!(slots.try_acquire());
    }
}

#[test]
fn release_saturates_at_zero() {
    let slots = CarrierSlots::new(4);
    slots.release();
    slots.release();
    assert_eq!(slots.in_use(), 0, "release must not wrap around");
    assert!(slots.try_acquire());
    assert_eq!(slots.in_use(), 1);
}
```

- [ ] **Шаг 2: Запустить — убедиться, что не компилируется/падает**

```bash
cargo test -p outline-tun carrier_slots
```
Ожидается: ошибка компиляции (модуля нет).

- [ ] **Шаг 3: Реализовать `CarrierSlots`**

`crates/outline-tun/src/carrier_slots.rs` — счётчик на `AtomicUsize` с CAS-циклом
в `try_acquire` (`fetch_update`), `release` через `fetch_update` с
`saturating_sub`. `cap == 0` — короткое замыкание в `try_acquire` (всегда `true`,
счётчик всё равно ведётся, чтобы gauge показывал реальное число носителей).
Подключить `#[cfg(test)] #[path = "tests/carrier_slots.rs"] mod tests;`.
Объявить `mod carrier_slots;` в `crates/outline-tun/src/lib.rs`.

- [ ] **Шаг 4: Тесты зелёные**

```bash
cargo test -p outline-tun carrier_slots
```

- [ ] **Шаг 5: Раздать обоим движкам**

В `crates/outline-tun/src/engine.rs` рядом с блоком `dial_admission` (118-125):

```rust
// One carrier-slot counter across both engines: `max_carrier_flows` bounds
// how many carriers live at once process-wide, not a per-protocol slice.
let carrier_slots = Arc::new(CarrierSlots::new(carrier_cap));
udp_engine.set_carrier_slots(Arc::clone(&carrier_slots));
tcp_engine.set_carrier_slots(carrier_slots);
```

где `carrier_cap` считается как у UDP сейчас (`udp/engine.rs:116-122`):
`0 → max_flows`, иначе `min(max_carrier_flows, max_flows)`.

Поля `carrier_slots: OnceLock<Arc<CarrierSlots>>` и сеттеры — в
`tcp/engine/mod.rs` (рядом с `dial_admission`, :66/:126) и `udp/engine.rs` (:110).

- [ ] **Шаг 6: Метрика занятых слотов**

Добавить gauge `outline_ws_tun_carrier_flows_active` (скаляр) по образцу
`outline_ws_tun_max_carrier_flows`: `registration/tun.rs` (поле рядом с :16,
`register_scalar!` рядом с :132-143, в struct-literal рядом с :345), поле в
`lib.rs` рядом с :159, сеттер в `tun.rs` рядом с :88, заглушка в `stub.rs:254`.
Обновить описание `outline_ws_tun_max_carrier_flows` (`registration/tun.rs:136`):
сейчас говорит «TUN UDP flows» — теперь лимит общий.

- [ ] **Шаг 7: Гейт**

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
cargo test --workspace --exclude sockudo-ws
```

---

### Task 2: UDP переходит на общий счётчик

**Файлы:** `crates/outline-tun/src/udp/lifecycle.rs:167,215`, `udp/engine.rs:116-122`
**Тест:** `crates/outline-tun/src/udp/tests/eviction.rs` (рядом с `:415`)

**Consumes:** `CarrierSlots` из Task 1.

- [ ] **Шаг 1: Тест — слоты, занятые «чужими», ужимают UDP**

В `udp/tests/eviction.rs`, по образцу `carrier_cap_binds_before_the_flow_table_limit`
(:415) и хелпера `build_engine_with_carrier_cap` (:295): построить движок с
cap = 2, занять один слот напрямую через общий `CarrierSlots`, убедиться, что
второй UDP-флоу вытесняет первый (а не создаётся третьим).

- [ ] **Шаг 2: Запустить — падает**

```bash
cargo test -p outline-tun udp::tests::eviction
```

- [ ] **Шаг 3: Заменить локальную проверку**

`udp/lifecycle.rs:167`: вместо `guard.len() >= self.inner.tunnelled_flow_cap()`
— `!slots.try_acquire()` (слот берётся при вставке), при неудаче — прежний
`evict_oldest_flow` + повторная попытка. Освобождение — там, где UDP-флоу
удаляется из таблицы (`close_flow_if_current`, idle-GC), симметрично инкременту.
Поле лога на `:215` — из `slots.cap()`.

- [ ] **Шаг 4: Тесты зелёные + прежние тесты UDP не сломаны**

```bash
cargo test -p outline-tun udp::
```

---

### Task 3: TCP занимает слот и вытесняет своих

**Файлы:**
- `crates/outline-tun/src/tcp/state_machine/types.rs` (флаг + `Drop` :575)
- `crates/outline-tun/src/tcp/engine/mod.rs` (поле `carrier_eviction_index`)
- `crates/outline-tun/src/tcp/engine/flow_ops.rs:190-217` (`insert_flow`)
- **Тест:** `crates/outline-tun/src/tcp/engine/tests/carrier_cap.rs` (новый файл,
  зарегистрировать в `tests/mod.rs:27-33`)

- [ ] **Шаг 1: Тесты (три) — падают**

По образцу `tun_tcp_flow_limit_uses_activity_eviction_index`
(`tcp/engine/tests/mod.rs:1245`) и хелпера `eviction_test_flow_state` (:1831):

1. `carrier_cap_binds_before_max_flows_on_tcp` — при `max_flows=8`,
   `max_carrier_flows=2` третий **туннельный** флоу вытесняет старейший
   туннельный.
2. `direct_tcp_flows_do_not_take_carrier_slots` — direct-флоу не уменьшают
   доступные слоты и не становятся жертвой.
3. `dropping_a_tcp_flow_releases_its_slot` — снос флоу любым путём возвращает
   слот (проверять через `in_use()`).

- [ ] **Шаг 2: Запустить — падают**

```bash
cargo test -p outline-tun tcp::engine::tests::carrier_cap
```

- [ ] **Шаг 3: Реализация**

- `types.rs`: поле `carrier_slot: Option<Arc<CarrierSlots>>` + `carrier_slot_held:
  bool` в `TcpFlowState`; в существующем `Drop` (:575) — `if carrier_slot_held {
  slots.release() }` рядом с расчётом `pending_budget_global`.
- `tcp/engine/mod.rs`: поле `carrier_eviction_index: FlowEvictionIndex` рядом с
  `eviction_index` (:45), инициализация рядом с `:97`.
- `flow_ops.rs::insert_flow` (:190): если маршрут `TunRoute::Group` — `try_acquire`;
  при отказе `while` по `carrier_eviction_index.pop_oldest()` →
  `abort_flow_with_rst_if_id(.., "carrier_cap")`, затем повторить; если индекс
  пуст — `bail!` (как сейчас при `max_flows`). При успехе — `carrier_slot_held =
  true` и `carrier_eviction_index.upsert(key, flow_id, last_seen)`.
- Держать `carrier_eviction_index` в синхроне со всеми путями удаления: там же,
  где сейчас `eviction_index.remove` (`flow_ops.rs:281` и `:313`).

- [ ] **Шаг 4: Тесты зелёные**

```bash
cargo test -p outline-tun tcp::
```

---

### Task 4: переучёт слота на флипе маршрута (`route_by_sni`)

**Файлы:** `crates/outline-tun/src/tcp/engine/tasks/upstream/connect.rs:199-232`
**Тест:** `crates/outline-tun/src/tcp/engine/tests/carrier_cap.rs` (дополнить)

- [ ] **Шаг 1: Тест — падает**

`sni_reresolve_keeps_carrier_slots_balanced`: флоу создан как `Group` (слот
занят), SNI-резолв меняет маршрут на `Direct` → `in_use()` уменьшается на 1 и
флоу исчезает из `carrier_eviction_index`; обратный флип `Direct → Group` слот
занимает. После серии флипов `in_use()` равен числу туннельных флоу.

- [ ] **Шаг 2: Запустить — падает**

```bash
cargo test -p outline-tun sni_reresolve_keeps_carrier_slots_balanced
```

- [ ] **Шаг 3: Реализация**

В `connect.rs` там, где перезаписывается `state.routing.route` (:224), сравнить
старый и новый вариант:
- было `Group`, стало `Direct` → `release()`, `carrier_slot_held = false`,
  `carrier_eviction_index.remove(key, flow_id)`;
- было `Direct`, стало `Group` → `try_acquire()` (при отказе — эвикшн своих, как
  в `insert_flow`), `carrier_slot_held = true`, `upsert` в индекс.

- [ ] **Шаг 4: Тесты зелёные**

```bash
cargo test -p outline-tun tcp::
```

---

### Task 5: документация

**Файлы:** `bins/outline-ws-rust/README.md:391-401`, `README.ru.md:389-399`,
`CHANGELOG.md`, `CHANGELOG.ru.md`

- [ ] **Шаг 1: README EN+RU**

Переписать описание `max_carrier_flows`: лимит теперь общий на туннельные TCP и
UDP флоу, при упирании — LRU-эвикшн старейшего туннельного флоу того же
протокола, direct-флоу в лимит не входят, `0` = выключено. Явно предупредить:
значение, подобранное когда лимит был UDP-only, после обновления станет вдвое
жёстче — пересмотреть при обновлении.

- [ ] **Шаг 2: CHANGELOG EN+RU**

Запись в `[Unreleased] → Changed` с тем же предупреждением и цифрами замера
(256 UDP + до 318 TCP = ~574 носителя на `.104`).

- [ ] **Шаг 3: Финальный гейт**

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
cargo test --workspace --exclude sockudo-ws
git status --short vendor/   # обязано быть пусто
```

- [ ] **Шаг 4: Показать diff, дождаться команды на коммит**

```bash
git status --short && git diff --stat
```
