# Вкладка редактирования конфига `uplink_groups` в `outline-ui` — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** добавить в WS-панель `outline-ui` вкладку Uplink groups — структурированный
CRUD-редактор секций `[[uplink_group]]` (типизированная форма: ключевые поля +
свёрнутые Advanced) с кнопкой Apply, применяющей правки без рестарта узла.

**Architecture:** снизу вверх, три слоя (data-plane слоя, как у routing, здесь
нет — группы уже hot-applyable через существующий `/control/apply`). (A) Новый
control-endpoint `/control/uplink_groups` в `outline-ws-rust` правит
`[[uplink_group]]` через `toml_edit` по образцу **`uplinks_crud`** (named-entry,
адресация по `name`, без `revision`-guard). (B) `outline-ui` проксирует новый
endpoint одной строкой через уже существующий `proxy_crud`. (C) Svelte-вкладка
Uplink groups + drawer + framework-free форм-логика.

**Tech Stack:** Rust 2024 (`toml_edit`, `toml`, `serde`, `hyper`, `axum` для
UI-прокси), Svelte 5 (runes) + TypeScript + Vitest.

Спека: [`docs/superpowers/specs/2026-08-14-outline-ui-uplink-groups-tab-design.md`](../specs/2026-08-14-outline-ui-uplink-groups-tab-design.md).

## Global Constraints

- Тесты живут в `<dir>/tests/<basename>.rs`; inline `#[cfg(test)] mod tests {}`
  запрещён. Rust-тест подключается через `#[cfg(test)] #[path = "tests/<name>.rs"] mod tests;`.
- Комментарии в коде, сообщения коммитов, PR — на английском. Общение с
  владельцем — на русском.
- `#[serde(deny_unknown_fields)]` на всех пользовательских payload/секциях.
- User-facing документация ведётся парами EN/RU и правится в одном изменении
  (`README.md` + `README.ru.md`).
- Секреты (пароли, PSK, UUID, токены) не логируются и не попадают в тесты.
  Группы секретов не содержат (чистая LB/health/reselect-политика), но `name`
  выше debug не логировать.
- `[[uplink_group]]` — **top-level** array-of-tables (не под `[outline]`).
  Аплинки — отдельная секция `[[outline.uplinks]]` с полем `group`.
- **Именование по `name` = identity.** PATCH не переименовывает; delete только
  пустой группы (`uplink_count == 0`); create — пустой группы (стейдж). Без
  `revision`-guard (last-write-wins на одной группе — как `uplinks_crud`).
- **Reorder групп — есть** (косметика конфига: меняет порядок в файле, не
  поведение — группы независимы, выбираются routing-правилом `via`). Отдельный
  endpoint `/control/uplink_groups/reorder` (body `{name, to}`) по образцу
  аплинков (`065eb38a`), с ОБЯЗАТЕЛЬНЫМ переназначением `position()`-слотов
  (фикс `01919141`, см. пункт про toml_edit) — иначе тихий no-op.
- **Подводный камень `toml_edit` (фикс `01919141`):** encoder рендерит
  array-of-tables по сохранённой `position()` каждой таблицы, НЕ по Vec-порядку.
  Create = `arr.push` (append), delete = `arr.remove`, update = merge in-place —
  этим переназначать `position` не нужно. **Reorder** переставляет элементы,
  поэтому ОБЯЗАН захватить `position()`-слоты и переназначить их в новом порядке
  (как `uplinks_crud::apply_reorder`). Во всех случаях **тесты мутаций проверяют
  рендер** (`doc.to_string()`), а не только `arr.len()`/Vec, чтобы поймать
  position-no-op.
- **CI-гейт перед коммитом — ровно эти команды, в этом порядке** (`fmt` падает
  первым и маскирует clippy):

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto
```

```bash
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
```

```bash
cargo test --workspace --exclude sockudo-ws
```

- Фронт-гейт (из `bins/outline-ui/frontend/`): `pnpm test` (Vitest) и
  `pnpm build` (сборка ассетов, встраиваемых в бинарь под фичей `embed-assets`).
- **Коммиты — только с явного разрешения владельца** (правило репо). Шаги
  «Commit» выполняются, когда разрешение получено; иначе изменения копятся в
  рабочем дереве, а владельцу показывается diff.

---

## Карта файлов

**Слой A — control API узла (`outline-ws-rust`):**
- Modify: `bins/outline-ws-rust/src/config/load/groups.rs` — `load_balancing_config_from_group` → `pub(crate)`.
- Modify: `bins/outline-ws-rust/src/config/load/mod.rs` — ре-экспорт валидатора за фичей `control`.
- Modify: `bins/outline-ws-rust/src/config/schema.rs` — `UplinkGroupSection` → `pub(crate)`.
- Modify: `bins/outline-ws-rust/src/config/mod.rs` — ре-экспорт `UplinkGroupSection` + валидатора.
- Create: `bins/outline-ws-rust/src/http/control/groups_crud/{mod,payload,mutate,list}.rs`.
- Modify: `bins/outline-ws-rust/src/http/control/mod.rs` — `mod groups_crud;`.
- Modify: `bins/outline-ws-rust/src/http/control/server.rs` — dispatch `/control/uplink_groups`.

**Слой B — outline-ui прокси:**
- Modify: `bins/outline-ui/src/ws/api.rs` — `groups_proxy`.
- Modify: `bins/outline-ui/src/ws/mod.rs` — роут `/dashboard/api/groups`.
- Modify: `bins/outline-ui/src/ws/tests/mod.rs` — тесты прокси.

**Слой C — фронт:**
- Modify: `bins/outline-ui/frontend/src/lib/types.ts` — типы групп.
- Modify: `bins/outline-ui/frontend/src/lib/api.ts` — `groupsList`, `groupsMutate`.
- Create: `bins/outline-ui/frontend/src/lib/groupForm.ts` + `groupForm.test.ts`.
- Create: `bins/outline-ui/frontend/src/features/ws/UplinkGroups.svelte` + `GroupDrawer.svelte`.
- Modify: `bins/outline-ui/frontend/src/App.svelte`, `components/layout/Sidebar.svelte` — навигация.

**Слой D — доки + ops:**
- Modify: `bins/outline-ui/README.md` + `README.ru.md`;
  `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md` + `.ru.md`.
- Modify: `ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml` — bump тега образа.

---

### Task 1: Экспонировать валидатор политики группы для переиспользования

`load_balancing_config_from_group(&UplinkGroupSection)` (`config/load/groups.rs:176`)
уже валидирует всю LB/reselect-политику одной группы (reselect ⊕ interval,
`reselect` требует `active_passive` + scope, `reselect_sync` требует `at`,
диапазоны). CRUD-endpoint переиспользует её на секции, собранной из `toml_edit`,
без построения целого `ConfigFile` — ровно как routing переиспользует
`load_routing_config` (коммит `986456b2`). Делаем функцию и тип видимыми за
фичей `control`.

**Files:**
- Modify: `bins/outline-ws-rust/src/config/load/groups.rs:176`
- Modify: `bins/outline-ws-rust/src/config/load/mod.rs:23-26`
- Modify: `bins/outline-ws-rust/src/config/schema.rs:540`
- Modify: `bins/outline-ws-rust/src/config/mod.rs:18-30`
- Test: `bins/outline-ws-rust/src/config/load/tests/groups.rs`

**Interfaces:**
- Produces:
  - `pub(crate) fn load_balancing_config_from_group(section: &UplinkGroupSection) -> Result<outline_uplink::LoadBalancingConfig>`
  - `pub(crate) use schema::UplinkGroupSection;` (за `#[cfg(feature = "control")]`)
  - `pub(crate) use load::load_balancing_config_from_group;` (за `#[cfg(feature = "control")]`)

- [ ] **Step 1: Написать падающий тест переиспользования**

Check whether `config/load/groups.rs` already attaches a test module (look at
its bottom for `#[cfg(test)] #[path = "tests/groups.rs"] mod tests;`). If it
does not, add it at the end of `groups.rs`:

```rust
#[cfg(test)]
#[path = "tests/groups.rs"]
mod tests;
```

Then create (or append to) `bins/outline-ws-rust/src/config/load/tests/groups.rs`:

```rust
use super::load_balancing_config_from_group;
use crate::config::schema::UplinkGroupSection;

fn parse_group(toml_str: &str) -> UplinkGroupSection {
    #[derive(serde::Deserialize)]
    struct Wrapper {
        uplink_group: Vec<UplinkGroupSection>,
    }
    let mut w: Wrapper = toml::from_str(toml_str).expect("valid group TOML");
    w.uplink_group.pop().expect("one group")
}

#[test]
fn validator_reuse_rejects_reselect_at_and_interval_together() {
    let g = parse_group(
        "[[uplink_group]]\nname = \"main\"\nmode = \"active_passive\"\n\
         routing_scope = \"global\"\nreselect_at = [\"03:00\"]\nreselect_interval = \"10h\"\n",
    );
    let err = load_balancing_config_from_group(&g).expect_err("at ⊕ interval");
    assert!(format!("{err:#}").contains("reselect"), "got: {err:#}");
}

#[test]
fn validator_reuse_accepts_valid_group() {
    let g = parse_group(
        "[[uplink_group]]\nname = \"main\"\nmode = \"active_active\"\nrouting_scope = \"per_flow\"\n",
    );
    load_balancing_config_from_group(&g).expect("valid group");
}
```

- [ ] **Step 2: Прогнать — не компилируется**

Run: `cargo test -p outline-ws-rust validator_reuse`
Expected: FAIL — `load_balancing_config_from_group` is a private `fn` and
`crate::config::schema::UplinkGroupSection` is `pub(super)`.

- [ ] **Step 3: Открыть видимость валидатора и типа**

In `bins/outline-ws-rust/src/config/load/groups.rs`, change the signature at
line 176 from `fn load_balancing_config_from_group(` to:

```rust
pub(crate) fn load_balancing_config_from_group(
```

In `bins/outline-ws-rust/src/config/schema.rs`, change line 540 from
`pub(super) struct UplinkGroupSection {` to:

```rust
pub(crate) struct UplinkGroupSection {
```

(Its fields stay `pub(super)` — `groups_crud` only constructs the section via
`toml::from_str` and hands it to the validator; it never reads the fields.)

In `bins/outline-ws-rust/src/config/load/mod.rs`, next to the existing
`#[cfg(feature = "control")] pub(crate) use routing::load_routing_config;`
(lines 23-24), add:

```rust
#[cfg(feature = "control")]
pub(crate) use groups::load_balancing_config_from_group;
```

In `bins/outline-ws-rust/src/config/mod.rs`, next to the existing
`#[cfg(feature = "control")] pub(crate) use schema::RouteSection;` (line 30) and
`pub(crate) use load::load_routing_config;` (line 28), add:

```rust
#[cfg(feature = "control")]
pub(crate) use load::load_balancing_config_from_group;
#[cfg(feature = "control")]
pub(crate) use schema::UplinkGroupSection;
```

- [ ] **Step 4: Прогнать — тесты зелёные**

Run: `cargo test -p outline-ws-rust validator_reuse config`
Expected: PASS — new `validator_reuse_*` plus all existing config-loader tests
(visibility-only change, behaviour identical).

- [ ] **Step 5: Гейт + commit**

```bash
cargo fmt --check -p outline-ws-rust && cargo clippy -p outline-ws-rust --all-targets --no-deps -- -D warnings && cargo test -p outline-ws-rust config
```
```bash
git add bins/outline-ws-rust/src/config/
git commit -m "refactor(config): expose group LB validator + UplinkGroupSection for control"
```

---

### Task 2: `groups_crud/payload.rs` — wire-типы и TOML-конверсия

Типы запросов/ответов для `/control/uplink_groups` и построение
`toml_edit::Table` из payload. `[[uplink_group]]` имеет ~52 поля политики —
вместо ручного пофайлового `payload_to_table` (как `uplinks_crud` для своих ~20)
payload round-trip'ится через `toml::to_string` (`toml` пропускает `None`-поля) →
`DocumentMut`. Одна декларация полей (`GroupPayload`) — единственный источник:
добавил поле сюда, и каждая конверсия его подхватила.

**Files:**
- Create: `bins/outline-ws-rust/src/http/control/groups_crud/payload.rs`
- Create: `bins/outline-ws-rust/src/http/control/groups_crud/mod.rs` (module stub; dispatcher lands in Task 3)
- Modify: `bins/outline-ws-rust/src/http/control/mod.rs` (add `mod groups_crud;`)
- Test: `bins/outline-ws-rust/src/http/control/groups_crud/tests/payload.rs`

**Interfaces:**
- Consumes: `crate::config::UplinkGroupSection` (Task 1), `config_edit::{render_table_with_arrays, table_to_json}`.
- Produces (all `pub(super)`):
  - `struct GroupPayload` (~52 `Option` fields, `deny_unknown_fields`)
  - `struct CreateBody { group: GroupPayload }`
  - `struct UpdateBody { name: String, patch: GroupPayload }`
  - `struct DeleteBody { name: String }`
  - `struct ReorderBody { name: String, to: usize }`
  - `struct GroupListEntry { name, uplink_count, config }`
  - `struct GroupsListResponse { groups: Vec<GroupListEntry> }`
  - `struct MutationResponse { name, action, apply_required, restart_required }` + `::staged(...)`
  - `fn payload_to_table(&GroupPayload) -> Result<Table, String>`
  - `fn merge_patch_into_table(&mut Table, &GroupPayload) -> Result<(), String>`
  - `fn table_to_section(&Table) -> Result<UplinkGroupSection, String>`

- [ ] **Step 1: Написать падающий тест**

Create `bins/outline-ws-rust/src/http/control/groups_crud/tests/payload.rs`:

```rust
use toml_edit::Table;

use super::payload::{GroupPayload, merge_patch_into_table, payload_to_table, table_to_section};
use crate::http::control::config_edit::render_table_with_arrays;

fn payload(json: &str) -> GroupPayload {
    serde_json::from_str(json).expect("valid payload")
}

#[test]
fn payload_round_trips_through_group_section() {
    let p = payload(r#"{"name":"main","mode":"active_active","routing_scope":"per_flow","warm_standby_tcp":1}"#);
    let table = payload_to_table(&p).expect("to table");
    let text = render_table_with_arrays(&table);
    // The exact shape the group validator will re-parse.
    let _section = table_to_section(&table).expect("parses as UplinkGroupSection");
    assert!(text.contains("mode = \"active_active\""), "got: {text}");
    assert!(text.contains("warm_standby_tcp = 1"), "got: {text}");
}

#[test]
fn deny_unknown_fields_rejects_typos() {
    let err = serde_json::from_str::<GroupPayload>(r#"{"moode":"active_active"}"#).unwrap_err();
    assert!(err.to_string().contains("unknown field"), "got: {err}");
}

#[test]
fn probe_sub_table_round_trips() {
    let p = payload(r#"{"name":"g","probe":{"interval_secs":60}}"#);
    let text = render_table_with_arrays(&payload_to_table(&p).expect("to table"));
    assert!(text.contains("[probe]"), "got: {text}");
    assert!(text.contains("interval_secs = 60"), "got: {text}");
    table_to_section(&payload_to_table(&p).expect("to table")).expect("probe parses");
}

#[test]
fn merge_patch_replaces_fields_and_ignores_name() {
    // existing table has mode + name; patch flips mode and (illegally) name.
    let mut existing: Table = payload_to_table(&payload(
        r#"{"name":"main","mode":"active_active"}"#,
    ))
    .expect("to table");
    merge_patch_into_table(&mut existing, &payload(r#"{"name":"renamed","mode":"active_passive"}"#))
        .expect("merge ok");
    let text = render_table_with_arrays(&existing);
    assert!(text.contains("mode = \"active_passive\""), "mode replaced: {text}");
    // name is identity — merge must leave the original on disk.
    assert!(text.contains("name = \"main\""), "name unchanged: {text}");
    assert!(!text.contains("renamed"), "name not overwritten: {text}");
}
```

- [ ] **Step 2: Прогнать — не компилируется**

Run: `cargo test -p outline-ws-rust groups_crud`
Expected: FAIL — module `groups_crud` doesn't exist yet.

- [ ] **Step 3: Написать `payload.rs`**

Create `bins/outline-ws-rust/src/http/control/groups_crud/payload.rs`:

```rust
//! Wire types + TOML conversion for `/control/uplink_groups`.
//!
//! A `[[uplink_group]]` is addressed by its `name` (identity), like
//! `uplinks_crud` addresses `[[outline.uplinks]]` — so, unlike index-addressed
//! `routes_crud`, there is no `revision` guard: a named lookup is stable across
//! concurrent edits (last-write-wins on the same group, the same trade-off the
//! uplink editor already ships).
//!
//! Group policy has ~52 fields. Rather than a hand-written field-by-field
//! `payload_to_table`, the payload round-trips through `toml::to_string` (which
//! omits `None` fields) → `DocumentMut`. `mode`/`routing_scope`/
//! `tcp_mid_session_retry_overflow_policy` are carried as raw strings (parsed
//! into their enums only when the rendered TOML is re-parsed as
//! `UplinkGroupSection`); `probe` is an opaque `toml::Value` sub-table whose own
//! `deny_unknown_fields` is enforced at that same re-parse. `deny_unknown_fields`
//! here makes a mistyped top-level key a 400, not a silently-dropped setting.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use toml_edit::{DocumentMut, Table};

use crate::config::UplinkGroupSection;
use crate::http::control::config_edit::render_table_with_arrays;
// Re-exported so `list.rs` can reach it as `super::payload::table_to_json`.
pub(super) use crate::http::control::config_edit::table_to_json;

/// Mirrors `crate::config::UplinkGroupSection`; every field optional. `toml`
/// omits `None` on serialize, so no per-field `skip_serializing_if` is needed.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GroupPayload {
    pub(super) name: Option<String>,
    pub(super) mode: Option<String>,
    pub(super) routing_scope: Option<String>,
    pub(super) shared_resume: Option<bool>,
    pub(super) sticky_ttl_secs: Option<u64>,
    pub(super) hysteresis_ms: Option<u64>,
    pub(super) failure_cooldown_secs: Option<u64>,
    pub(super) tcp_chunk0_failover_timeout_secs: Option<u64>,
    pub(super) warm_standby_tcp: Option<usize>,
    pub(super) warm_standby_udp: Option<usize>,
    pub(super) rtt_ewma_alpha: Option<f64>,
    pub(super) rtt_ewma_halflife_secs: Option<u64>,
    pub(super) loss_latency_penalty_k: Option<f64>,
    pub(super) loss_latency_inflation_max: Option<f64>,
    pub(super) loss_sample_interval_secs: Option<u64>,
    pub(super) loss_sample_min_packets: Option<u64>,
    pub(super) loss_ewma_alpha: Option<f64>,
    pub(super) failure_penalty_ms: Option<u64>,
    pub(super) failure_penalty_max_ms: Option<u64>,
    pub(super) failure_penalty_halflife_secs: Option<u64>,
    pub(super) mode_downgrade_secs: Option<u64>,
    pub(super) carrier_degraded_failover_secs: Option<u64>,
    pub(super) loss_failover_ratio: Option<f64>,
    pub(super) loss_failover_secs: Option<u64>,
    pub(super) runtime_failure_window_secs: Option<u64>,
    pub(super) chunk0_failure_window_secs: Option<u64>,
    pub(super) global_udp_strict_health: Option<bool>,
    pub(super) udp_ws_keepalive_secs: Option<u64>,
    pub(super) tcp_ws_keepalive_secs: Option<u64>,
    pub(super) tcp_ws_standby_keepalive_secs: Option<u64>,
    pub(super) tcp_active_keepalive_secs: Option<u64>,
    pub(super) warm_probe_keepalive_secs: Option<u64>,
    pub(super) auto_failback: Option<bool>,
    pub(super) health_weighted_selection: Option<bool>,
    pub(super) tun_wire_dial: Option<bool>,
    pub(super) health_weight_floor: Option<f64>,
    pub(super) vless_udp_max_sessions: Option<usize>,
    pub(super) vless_udp_session_idle_secs: Option<u64>,
    pub(super) vless_udp_janitor_interval_secs: Option<u64>,
    pub(super) tcp_mid_session_retry_buffer_bytes: Option<usize>,
    pub(super) tcp_mid_session_retry_budget: Option<u8>,
    pub(super) tcp_mid_session_retry_overflow_policy: Option<String>,
    pub(super) tcp_mid_session_retry_consume_timeout_secs: Option<u64>,
    pub(super) tcp_symmetric_replay_enabled: Option<bool>,
    pub(super) tcp_symmetric_replay_max_bytes: Option<usize>,
    pub(super) tun_suppress_icmp_reply_when_down: Option<bool>,
    pub(super) tun_icmp_liveness_window_secs: Option<u64>,
    pub(super) bypass_when_down: Option<bool>,
    pub(super) reselect_at: Option<Vec<String>>,
    pub(super) reselect_interval: Option<String>,
    pub(super) reselect_sync: Option<bool>,
    /// Opaque probe-override sub-table (validated as `ProbeSection` when the
    /// rendered TOML is re-parsed). Kept last so `toml::to_string` emits every
    /// scalar/array field before this `[probe]` table (TOML requires it).
    pub(super) probe: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub(super) struct CreateBody {
    pub(super) group: GroupPayload,
}

#[derive(Debug, Deserialize)]
pub(super) struct UpdateBody {
    pub(super) name: String,
    pub(super) patch: GroupPayload,
}

#[derive(Debug, Deserialize)]
pub(super) struct DeleteBody {
    pub(super) name: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReorderBody {
    pub(super) name: String,
    /// Target position of `name` among all groups (0-based, declaration order).
    /// Out-of-range is rejected. Group order is cosmetic (selection is by the
    /// routing `via` rule, not position), so this only rewrites on-disk order.
    pub(super) to: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct MutationResponse {
    pub(super) name: String,
    pub(super) action: &'static str,
    /// Whether clients should call `/control/apply` to activate this staged
    /// config-file change without restarting the process.
    pub(super) apply_required: bool,
    /// Back-compat activation hint for control states that cannot hot-apply.
    pub(super) restart_required: bool,
}

impl MutationResponse {
    pub(super) fn staged(name: String, action: &'static str, hot_apply_available: bool) -> Self {
        Self {
            name,
            action,
            apply_required: hot_apply_available,
            restart_required: !hot_apply_available,
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct GroupListEntry {
    pub(super) name: String,
    /// Number of `[[outline.uplinks]]` (and legacy top-level `[[uplinks]]`)
    /// carrying `group = name`. Drives the strict-delete gate and the empty-
    /// group hint in the UI.
    pub(super) uplink_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) config: Option<Value>,
}

#[derive(Debug, Serialize)]
pub(super) struct GroupsListResponse {
    pub(super) groups: Vec<GroupListEntry>,
}

/// Build a `[[uplink_group]]` table from a payload by serializing to TOML text
/// (which omits `None`) and re-parsing. Only fields the operator set land on
/// disk — nothing defaulted.
pub(super) fn payload_to_table(p: &GroupPayload) -> Result<Table, String> {
    let text = toml::to_string(p).map_err(|e| format!("serialize group payload: {e}"))?;
    let doc = text
        .parse::<DocumentMut>()
        .map_err(|e| format!("render group payload: {e}"))?;
    Ok(doc.as_table().clone())
}

/// PATCH merge: overwrite each field present in `patch` on `existing`, leaving
/// the rest untouched. `name` is identity and is never merged (a PATCH cannot
/// rename a group).
pub(super) fn merge_patch_into_table(
    existing: &mut Table,
    patch: &GroupPayload,
) -> Result<(), String> {
    let text = toml::to_string(patch).map_err(|e| format!("serialize group patch: {e}"))?;
    let doc = text
        .parse::<DocumentMut>()
        .map_err(|e| format!("render group patch: {e}"))?;
    for (key, item) in doc.as_table().iter() {
        if key == "name" {
            continue;
        }
        existing.insert(key, item.clone());
    }
    Ok(())
}

/// Parse a group table back into an `UplinkGroupSection` for validation. Goes
/// via TOML text (like `uplinks_crud::table_to_section`) so serde parses the
/// enums (`LoadBalancingMode`, `RoutingScope`, `OverflowPolicy`) and the nested
/// `ProbeSection` through their existing `Deserialize` impls.
pub(super) fn table_to_section(tbl: &Table) -> Result<UplinkGroupSection, String> {
    let text = render_table_with_arrays(tbl);
    toml::from_str::<UplinkGroupSection>(&text).map_err(|e| e.to_string())
}
```

Create the module stub `bins/outline-ws-rust/src/http/control/groups_crud/mod.rs`
(dispatcher lands in Task 3; for now declare submodules so the payload tests
compile):

```rust
mod payload;

#[cfg(test)]
#[path = "tests/payload.rs"]
mod tests;
```

Register the module in `bins/outline-ws-rust/src/http/control/mod.rs` next to
`mod uplinks_crud;` (line 14):

```rust
mod groups_crud;
```

If clippy flags any `payload.rs` item as unused until Task 3 wires them, add a
temporary `#![allow(dead_code)]` at the top of `groups_crud/mod.rs` and remove
it in Task 3's commit.

- [ ] **Step 4: Прогнать — тесты зелёные**

Run: `cargo test -p outline-ws-rust groups_crud`
Expected: PASS — all four payload tests.

- [ ] **Step 5: Гейт + commit**

```bash
cargo fmt --check -p outline-ws-rust && cargo clippy -p outline-ws-rust --all-targets --no-deps -- -D warnings && cargo test -p outline-ws-rust groups_crud
```
```bash
git add bins/outline-ws-rust/src/http/control/groups_crud/ bins/outline-ws-rust/src/http/control/mod.rs
git commit -m "feat(control): groups_crud payload types + TOML conversion"
```

---

### Task 3: `groups_crud/mutate.rs` + `mod.rs` — CRUD по имени

Read→mutate→validate→atomic-write, адресация по `name`. Пер-групповая политика
валидируется переиспользованным `load_balancing_config_from_group` (Task 1) —
staged-группа не может стать той, что не загрузится. Межгрупповые инварианты
(≥1 аплинк, ссылки аплинков) НЕ требуются на мутации — они проверяются при
Apply, что и позволяет создать пустую группу и наполнить её во вкладке Uplinks.
Delete строго-безопасен: непустую группу сервер отвергает.

**Files:**
- Create: `bins/outline-ws-rust/src/http/control/groups_crud/mutate.rs`
- Modify: `bins/outline-ws-rust/src/http/control/groups_crud/mod.rs` (dispatcher)
- Test: `bins/outline-ws-rust/src/http/control/groups_crud/tests/mutate.rs`

**Interfaces:**
- Consumes: `config_edit::{read_json, json_error_owned, write_document_atomic, status_for_mutator_error}`, `crate::config::load_balancing_config_from_group`, payload types (Task 2).
- Produces:
  - `pub(crate) async fn handle_groups(request, state: Arc<ControlState>) -> ControlResponse`
  - `pub(super) async fn handle_reorder(request, state: Arc<ControlState>) -> ControlResponse`
  - `pub(super) fn apply_create(&mut DocumentMut, &GroupPayload) -> Result<(), String>`
  - `pub(super) fn apply_update(&mut DocumentMut, name: &str, &GroupPayload) -> Result<(), String>`
  - `pub(super) fn apply_delete(&mut DocumentMut, name: &str) -> Result<(), String>`
  - `pub(super) fn apply_reorder(&mut ArrayOfTables, name: &str, to: usize) -> Result<(), String>`
  - `pub(super) fn get_or_init_uplink_groups(&mut DocumentMut) -> &mut ArrayOfTables`
  - `pub(super) fn find_group_index(&ArrayOfTables, name: &str) -> Option<usize>`
  - `pub(super) fn count_uplinks_for_group(&DocumentMut, group: &str) -> usize`

- [ ] **Step 1: Написать падающие тесты**

Create `bins/outline-ws-rust/src/http/control/groups_crud/tests/mutate.rs`.
Pure document-mutation unit tests (no HTTP). Per the Global Constraints, they
assert the **rendered** output (`doc.to_string()`), not just Vec/`arr.len()`:

```rust
use toml_edit::DocumentMut;

use super::mutate::{
    apply_create, apply_delete, apply_reorder, apply_update, count_uplinks_for_group,
    get_or_init_uplink_groups,
};
use super::payload::GroupPayload;

const BASE: &str = "\
[[uplink_group]]
name = \"main\"
mode = \"active_active\"

[[outline.uplinks]]
name = \"cloud1\"
group = \"main\"
transport = \"ss\"
";

fn doc() -> DocumentMut {
    BASE.parse::<DocumentMut>().unwrap()
}

fn payload(json: &str) -> GroupPayload {
    serde_json::from_str(json).unwrap()
}

#[test]
fn create_appends_group_to_rendered_doc() {
    let mut d = doc();
    apply_create(&mut d, &payload(r#"{"name":"backup","mode":"active_passive","routing_scope":"global"}"#))
        .expect("create ok");
    let text = d.to_string();
    // Assert the RENDERED document, not just Vec state (position-no-op guard).
    assert!(text.contains("name = \"backup\""), "backup group rendered: {text}");
    assert!(text.contains("mode = \"active_passive\""), "policy rendered: {text}");
    assert!(text.contains("name = \"main\""), "existing group preserved: {text}");
}

#[test]
fn create_rejects_duplicate_name() {
    let mut d = doc();
    let err = apply_create(&mut d, &payload(r#"{"name":"main","mode":"active_active"}"#))
        .expect_err("duplicate");
    assert!(err.contains("already exists"), "got: {err}");
}

#[test]
fn create_rejects_reserved_name() {
    let mut d = doc();
    let err = apply_create(&mut d, &payload(r#"{"name":"direct","mode":"active_active"}"#))
        .expect_err("reserved");
    assert!(err.contains("reserved"), "got: {err}");
}

#[test]
fn update_merges_policy_in_place() {
    let mut d = doc();
    apply_update(&mut d, "main", &payload(r#"{"routing_scope":"per_uplink"}"#)).expect("update ok");
    let text = d.to_string();
    assert!(text.contains("routing_scope = \"per_uplink\""), "new field rendered: {text}");
    assert!(text.contains("mode = \"active_active\""), "untouched field preserved: {text}");
}

#[test]
fn update_unknown_group_is_not_found() {
    let mut d = doc();
    let err = apply_update(&mut d, "ghost", &payload(r#"{"mode":"active_passive"}"#))
        .expect_err("missing");
    assert!(err.contains("not found"), "got: {err}");
}

#[test]
fn delete_nonempty_group_is_refused() {
    let mut d = doc();
    // "main" still owns uplink "cloud1".
    assert_eq!(count_uplinks_for_group(&d, "main"), 1);
    let err = apply_delete(&mut d, "main").expect_err("has uplinks");
    assert!(err.contains("uplink"), "got: {err}");
}

#[test]
fn delete_empty_group_removes_it_from_rendered_doc() {
    let mut d = doc();
    apply_create(&mut d, &payload(r#"{"name":"backup","mode":"active_passive"}"#)).expect("create");
    apply_delete(&mut d, "backup").expect("delete empty");
    let text = d.to_string();
    assert!(!text.contains("backup"), "backup gone from render: {text}");
    assert!(text.contains("name = \"main\""), "main preserved: {text}");
}

#[test]
fn update_rejects_invalid_policy() {
    let mut d = doc();
    // reselect requires active_passive; on an active_active group it must fail.
    let err = apply_update(&mut d, "main", &payload(r#"{"reselect_interval":"10h"}"#))
        .expect_err("reselect needs active_passive");
    assert!(!err.is_empty(), "got empty error");
}

#[test]
fn reorder_moves_group_and_renders_new_order() {
    let mut d = "[[uplink_group]]\nname = \"a\"\nmode = \"active_active\"\n\n\
                 [[uplink_group]]\nname = \"b\"\nmode = \"active_active\"\n\n\
                 [[uplink_group]]\nname = \"c\"\nmode = \"active_active\"\n"
        .parse::<DocumentMut>()
        .unwrap();
    {
        let arr = get_or_init_uplink_groups(&mut d);
        apply_reorder(arr, "c", 0).expect("reorder ok");
    }
    let text = d.to_string();
    // Assert the RENDERED order (positions reassigned), not just Vec order:
    // "c" must now precede "a", which precedes "b". Guards the position-no-op.
    let ia = text.find("name = \"a\"").expect("a present");
    let ib = text.find("name = \"b\"").expect("b present");
    let ic = text.find("name = \"c\"").expect("c present");
    assert!(ic < ia && ia < ib, "expected c,a,b order in render: {text}");
}

#[test]
fn reorder_target_out_of_range_is_rejected() {
    let mut d = doc();
    let arr = get_or_init_uplink_groups(&mut d);
    let err = apply_reorder(arr, "main", 5).expect_err("out of range");
    assert!(err.contains("out of range"), "got: {err}");
}
```

- [ ] **Step 2: Прогнать — не компилируется**

Run: `cargo test -p outline-ws-rust groups_crud::tests::mutate`
Expected: FAIL — `super::mutate` module and its functions don't exist.

- [ ] **Step 3: Написать `mutate.rs`**

Create `bins/outline-ws-rust/src/http/control/groups_crud/mutate.rs`:

```rust
//! Read→mutate→validate→write for `[[uplink_group]]`, addressed by `name`.

use std::sync::Arc;

use http::{Request, StatusCode};
use hyper::body::Incoming;
use tokio::fs;
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table};
use tracing::info;

use crate::config::load_balancing_config_from_group;
use crate::http::control::config_edit::{json_error_owned, read_json, write_document_atomic};
use crate::http::control::server::ControlState;
use crate::http::control::{ControlResponse, json_error, json_response, plain_response};

use super::payload::{
    CreateBody, DeleteBody, MutationResponse, ReorderBody, UpdateBody, merge_patch_into_table,
    payload_to_table, table_to_section,
};

const LABEL: &str = "/control/uplink_groups";

/// Metric-cardinality cap on groups — mirrors `MAX_UPLINK_GROUPS` in
/// `config/load/groups.rs`. Kept as a local literal (the loader's is a private
/// `const` inside a function); the value is the invariant, not the symbol.
const MAX_UPLINK_GROUPS: usize = 64;

pub(crate) async fn handle_groups(
    request: Request<Incoming>,
    state: Arc<ControlState>,
) -> ControlResponse {
    match *request.method() {
        http::Method::GET => super::list::handle_list(state, request.uri().query()).await,
        http::Method::POST => handle_create(request, state).await,
        http::Method::PATCH => handle_update(request, state).await,
        http::Method::DELETE => handle_delete(request, state).await,
        _ => plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "application/json; charset=utf-8",
            bytes::Bytes::from_static(br#"{"error":"use GET, POST, PATCH, or DELETE"}"#),
        ),
    }
}

async fn handle_create(request: Request<Incoming>, state: Arc<ControlState>) -> ControlResponse {
    let Some(path) = state.config_path.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            "config file path unknown; CRUD endpoints need on-disk config",
        );
    };
    let hot_apply_available = state.apply.is_some();
    let body: CreateBody = match read_json(request, LABEL).await {
        Ok(v) => v,
        Err(err) => return err,
    };
    let Some(name) = body.group.name.clone() else {
        return json_error(StatusCode::BAD_REQUEST, "group.name is required");
    };

    let _guard = state.config_write_lock.lock().await;
    let raw = match fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(error) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read config: {error}"),
            );
        },
    };
    let mut doc = match raw.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(error) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("config is not valid TOML: {error}"),
            );
        },
    };

    if let Err(msg) = apply_create(&mut doc, &body.group) {
        return json_error_owned(status_for_group_error(&msg), msg);
    }
    if let Err(error) = write_document_atomic(&path, &doc).await {
        return json_error_owned(StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}"));
    }
    info!(group = %name, "uplink group created via /control/uplink_groups");
    json_response(
        StatusCode::ACCEPTED,
        &MutationResponse::staged(name, "created", hot_apply_available),
    )
}

async fn handle_update(request: Request<Incoming>, state: Arc<ControlState>) -> ControlResponse {
    let Some(path) = state.config_path.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            "config file path unknown; CRUD endpoints need on-disk config",
        );
    };
    let hot_apply_available = state.apply.is_some();
    let body: UpdateBody = match read_json(request, LABEL).await {
        Ok(v) => v,
        Err(err) => return err,
    };

    let _guard = state.config_write_lock.lock().await;
    let raw = match fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(error) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read config: {error}"),
            );
        },
    };
    let mut doc = match raw.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(error) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("config is not valid TOML: {error}"),
            );
        },
    };

    if let Err(msg) = apply_update(&mut doc, &body.name, &body.patch) {
        return json_error_owned(status_for_group_error(&msg), msg);
    }
    if let Err(error) = write_document_atomic(&path, &doc).await {
        return json_error_owned(StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}"));
    }
    info!(group = %body.name, "uplink group updated via /control/uplink_groups");
    json_response(
        StatusCode::ACCEPTED,
        &MutationResponse::staged(body.name, "updated", hot_apply_available),
    )
}

async fn handle_delete(request: Request<Incoming>, state: Arc<ControlState>) -> ControlResponse {
    let Some(path) = state.config_path.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            "config file path unknown; CRUD endpoints need on-disk config",
        );
    };
    let hot_apply_available = state.apply.is_some();
    let body: DeleteBody = match read_json(request, LABEL).await {
        Ok(v) => v,
        Err(err) => return err,
    };

    let _guard = state.config_write_lock.lock().await;
    let raw = match fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(error) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read config: {error}"),
            );
        },
    };
    let mut doc = match raw.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(error) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("config is not valid TOML: {error}"),
            );
        },
    };

    if let Err(msg) = apply_delete(&mut doc, &body.name) {
        return json_error_owned(status_for_group_error(&msg), msg);
    }
    if let Err(error) = write_document_atomic(&path, &doc).await {
        return json_error_owned(StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}"));
    }
    info!(group = %body.name, "uplink group deleted via /control/uplink_groups");
    json_response(
        StatusCode::ACCEPTED,
        &MutationResponse::staged(body.name, "deleted", hot_apply_available),
    )
}

pub(super) async fn handle_reorder(
    request: Request<Incoming>,
    state: Arc<ControlState>,
) -> ControlResponse {
    let Some(path) = state.config_path.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            "config file path unknown; CRUD endpoints need on-disk config",
        );
    };
    let hot_apply_available = state.apply.is_some();
    let body: ReorderBody = match read_json(request, "/control/uplink_groups/reorder").await {
        Ok(v) => v,
        Err(err) => return err,
    };
    if body.name.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "name must be non-empty");
    }

    let _guard = state.config_write_lock.lock().await;
    let raw = match fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(error) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read config: {error}"),
            );
        },
    };
    let mut doc = match raw.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(error) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("config is not valid TOML: {error}"),
            );
        },
    };

    let arr = get_or_init_uplink_groups(&mut doc);
    if let Err(msg) = apply_reorder(arr, &body.name, body.to) {
        return json_error_owned(status_for_group_error(&msg), msg);
    }
    if let Err(error) = write_document_atomic(&path, &doc).await {
        return json_error_owned(StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}"));
    }
    info!(group = %body.name, to = body.to, "uplink group reordered via /control/uplink_groups/reorder");
    json_response(
        StatusCode::ACCEPTED,
        &MutationResponse::staged(body.name, "reordered", hot_apply_available),
    )
}

/// Map a mutator `Err(String)` to an HTTP status. `"not found"`→404,
/// `"already exists"`/`"has "`→409, else 400.
fn status_for_group_error(msg: &str) -> StatusCode {
    if msg.contains("not found") {
        StatusCode::NOT_FOUND
    } else if msg.contains("already exists") || msg.contains("uplinks; remove") {
        StatusCode::CONFLICT
    } else {
        StatusCode::BAD_REQUEST
    }
}

fn validate_group_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("group.name must be non-empty".to_string());
    }
    // `direct` / `drop` are reserved routing targets (config/load/mod.rs).
    if name.eq_ignore_ascii_case("direct") || name.eq_ignore_ascii_case("drop") {
        return Err(format!("group name \"{name}\" is reserved (direct/drop)"));
    }
    Ok(())
}

/// Round-trip the staged group table through the shared LB/reselect validator.
fn validate_group_policy(tbl: &Table) -> Result<(), String> {
    let section = table_to_section(tbl)?;
    load_balancing_config_from_group(&section)
        .map(|_| ())
        .map_err(|e| format!("{e:#}"))
}

pub(super) fn apply_create(doc: &mut DocumentMut, payload: &super::payload::GroupPayload) -> Result<(), String> {
    let name = payload.name.as_deref().ok_or("group.name is required")?;
    validate_group_name(name)?;
    let table = payload_to_table(payload)?;
    validate_group_policy(&table)?;
    let arr = get_or_init_uplink_groups(doc);
    if find_group_index(arr, name).is_some() {
        return Err(format!("uplink_group \"{name}\" already exists"));
    }
    if arr.len() >= MAX_UPLINK_GROUPS {
        return Err(format!(
            "too many uplink groups; maximum is {MAX_UPLINK_GROUPS} to bound metric cardinality"
        ));
    }
    // append (never insert-mid): position-based rendering stays correct without
    // reassigning slots — see the toml_edit note in Global Constraints.
    arr.push(table);
    Ok(())
}

pub(super) fn apply_update(
    doc: &mut DocumentMut,
    name: &str,
    patch: &super::payload::GroupPayload,
) -> Result<(), String> {
    validate_group_name(name)?;
    let arr = get_or_init_uplink_groups(doc);
    let idx = find_group_index(arr, name).ok_or_else(|| format!("uplink_group \"{name}\" not found"))?;
    merge_patch_into_table(arr.get_mut(idx).expect("index in bounds"), patch)?;
    validate_group_policy(arr.get(idx).expect("index in bounds"))?;
    Ok(())
}

pub(super) fn apply_delete(doc: &mut DocumentMut, name: &str) -> Result<(), String> {
    let count = count_uplinks_for_group(doc, name);
    let arr = get_or_init_uplink_groups(doc);
    let idx = find_group_index(arr, name).ok_or_else(|| format!("uplink_group \"{name}\" not found"))?;
    if count > 0 {
        return Err(format!(
            "uplink_group \"{name}\" has {count} uplinks; remove them first"
        ));
    }
    arr.remove(idx);
    Ok(())
}

/// Reorder group `name` to position `to` among all `[[uplink_group]]` tables.
/// toml_edit renders an array-of-tables by each table's stored `position` (its
/// source slot), NOT by Vec order — so capture the groups' position slots and
/// reassign them in the new order (same fix as routes'/uplinks' `apply_reorder`,
/// commit 01919141). Group order is cosmetic (routing `via` selects, not
/// position); this only rewrites the on-disk order.
pub(super) fn apply_reorder(arr: &mut ArrayOfTables, name: &str, to: usize) -> Result<(), String> {
    let n = arr.len();
    if n == 0 {
        return Err("no uplink groups on disk".to_string());
    }
    if to >= n {
        return Err(format!("reorder target {to} out of range ({n} group(s))"));
    }
    let from =
        find_group_index(arr, name).ok_or_else(|| format!("uplink_group \"{name}\" not found"))?;
    if from == to {
        return Ok(());
    }
    let mut slots: Vec<_> = arr.iter().filter_map(|t| t.position()).collect();
    slots.sort_unstable();
    let mut tables: Vec<Table> = arr.iter().cloned().collect();
    let moved = tables.remove(from);
    tables.insert(to, moved);
    for (k, t) in tables.iter_mut().enumerate() {
        if let Some(&pos) = slots.get(k) {
            t.set_position(pos);
        }
    }
    let mut rebuilt = ArrayOfTables::new();
    for t in tables {
        rebuilt.push(t);
    }
    *arr = rebuilt;
    Ok(())
}

/// Find the `[[uplink_group]]` whose `name == name`.
pub(super) fn find_group_index(arr: &ArrayOfTables, name: &str) -> Option<usize> {
    arr.iter()
        .position(|t| t.get("name").and_then(|v| v.as_str()) == Some(name))
}

/// Get or init the top-level `[[uplink_group]]` array-of-tables.
pub(super) fn get_or_init_uplink_groups(doc: &mut DocumentMut) -> &mut ArrayOfTables {
    if doc.get("uplink_group").and_then(Item::as_array_of_tables).is_none() {
        doc.insert("uplink_group", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    doc["uplink_group"]
        .as_array_of_tables_mut()
        .expect("uplink_group is an array-of-tables after insert")
}

/// Count uplinks assigned to `group` across both the canonical
/// `[[outline.uplinks]]` and any legacy top-level `[[uplinks]]` (either may
/// carry the `group` discriminator on disk before normalization).
pub(super) fn count_uplinks_for_group(doc: &DocumentMut, group: &str) -> usize {
    fn count_in(arr: Option<&ArrayOfTables>, group: &str) -> usize {
        arr.map(|a| {
            a.iter()
                .filter(|t| t.get("group").and_then(|v| v.as_str()) == Some(group))
                .count()
        })
        .unwrap_or(0)
    }
    let outline = doc
        .get("outline")
        .and_then(Item::as_table)
        .and_then(|o| o.get("uplinks"))
        .and_then(Item::as_array_of_tables);
    let legacy = doc.get("uplinks").and_then(Item::as_array_of_tables);
    count_in(outline, group) + count_in(legacy, group)
}
```

Replace the stub `groups_crud/mod.rs` with the wired module set:

```rust
//! CRUD for `[[uplink_group]]` policy sections in the running config file.
//!
//! Edits the on-disk TOML document in place (via `toml_edit`, preserving
//! comments/formatting). Changes are staged on disk: call `/control/apply` to
//! reload the file and hot-swap the live `UplinkRegistry`. If a control state
//! was built without an apply handle, a process restart is the fallback.
//! Addressed by `name` (identity): create appends, delete removes an empty
//! group, update merges policy in place — no reorder, no `revision`-guard.

mod list;
mod mutate;
mod payload;

pub(crate) use mutate::handle_groups;

#[cfg(test)]
#[path = "tests/mutate.rs"]
mod tests_mutate;
```

Wait — `payload.rs` already attaches `tests/payload.rs` via its own module. To
keep both test files attached, put the attachments on the submodules that own
them: leave `payload.rs`'s `#[cfg(test)] #[path = "tests/payload.rs"] mod tests;`
where Task 2 placed it (inside `payload.rs`), and attach `tests/mutate.rs` from
inside `mutate.rs` instead of `mod.rs`. Concretely, **remove** the
`tests_mutate` line above and instead append to the bottom of `mutate.rs`:

```rust
#[cfg(test)]
#[path = "tests/mutate.rs"]
mod tests;
```

and Task 2's `mod.rs` stub `#[cfg(test)] #[path = "tests/payload.rs"] mod tests;`
moves into `payload.rs`'s bottom too (if it isn't already there). Final
`groups_crud/mod.rs`:

```rust
//! (doc comment from the first mod.rs block above)

use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use hyper::body::Incoming;

use super::server::ControlState;
use super::{ControlResponse, plain_response};

mod list;
mod mutate;
mod payload;

pub(crate) use mutate::handle_groups;

/// `POST /control/uplink_groups/reorder` — move one group to a new position.
/// Split from `handle_groups` (like `/control/uplinks/reorder`) because reorder
/// takes a distinct `{name, to}` body rather than the CRUD shapes.
pub(crate) async fn handle_groups_reorder(
    request: Request<Incoming>,
    state: Arc<ControlState>,
) -> ControlResponse {
    if *request.method() != Method::POST {
        return plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "application/json; charset=utf-8",
            Bytes::from_static(br#"{"error":"use POST"}"#),
        );
    }
    mutate::handle_reorder(request, state).await
}
```

- [ ] **Step 4: Прогнать — тесты зелёные**

Run: `cargo test -p outline-ws-rust groups_crud`
Expected: PASS — payload tests (Task 2) + all mutate tests.

- [ ] **Step 5: Гейт + commit**

```bash
cargo fmt --check -p outline-ws-rust && cargo clippy -p outline-ws-rust --all-targets --no-deps -- -D warnings && cargo test -p outline-ws-rust groups_crud
```
```bash
git add bins/outline-ws-rust/src/http/control/groups_crud/
git commit -m "feat(control): groups_crud create/update/delete by name"
```

---

### Task 4: `groups_crud/list.rs` — GET со счётчиком аплинков

`GET /control/uplink_groups` читает config.toml (staged-состояние), отдаёт список
групп с их политикой (config как JSON) и `uplink_count`. Чисто файловое чтение,
как `routes_crud` list (не снапшоты) — нужно ровно то staged-состояние, что
редактирует форма. Опциональный фильтр `?name=` для single-item GET.

**Files:**
- Create: `bins/outline-ws-rust/src/http/control/groups_crud/list.rs`
- Modify: `bins/outline-ws-rust/src/http/control/groups_crud/mod.rs` (add `mod list;` — already declared in Task 3)
- Test: `bins/outline-ws-rust/src/http/control/groups_crud/tests/list.rs`

**Interfaces:**
- Consumes: `mutate::count_uplinks_for_group`, `payload::{GroupListEntry, GroupsListResponse, table_to_json}`.
- Produces: `pub(super) async fn handle_list(state: Arc<ControlState>, query: Option<&str>) -> ControlResponse`

- [ ] **Step 1: Написать падающий тест**

Create `bins/outline-ws-rust/src/http/control/groups_crud/tests/list.rs`. Test
the pure extraction helper (the HTTP wrapper is thin — its config-read path is
covered by the mutate suite's temp-file plumbing):

```rust
use toml_edit::DocumentMut;

use super::list::group_entries_from_doc;

const BASE: &str = "\
[[uplink_group]]
name = \"main\"
mode = \"active_active\"

[[uplink_group]]
name = \"backup\"
mode = \"active_passive\"

[[outline.uplinks]]
name = \"cloud1\"
group = \"main\"
transport = \"ss\"
";

#[test]
fn entries_carry_name_count_and_config() {
    let doc = BASE.parse::<DocumentMut>().unwrap();
    let entries = group_entries_from_doc(&doc);
    assert_eq!(entries.len(), 2);
    let main = entries.iter().find(|e| e.name == "main").expect("main present");
    assert_eq!(main.uplink_count, 1);
    assert!(main.config.is_some(), "config round-tripped");
    let backup = entries.iter().find(|e| e.name == "backup").expect("backup present");
    assert_eq!(backup.uplink_count, 0, "empty group counts zero");
}
```

- [ ] **Step 2: Прогнать — не компилируется**

Run: `cargo test -p outline-ws-rust groups_crud::tests`
Expected: FAIL — `super::list::group_entries_from_doc` doesn't exist.

- [ ] **Step 3: Написать `list.rs`**

Create `bins/outline-ws-rust/src/http/control/groups_crud/list.rs`:

```rust
//! Read-only `GET /control/uplink_groups` handler.

use std::sync::Arc;

use http::StatusCode;
use tokio::fs;
use toml_edit::{DocumentMut, Item};

use crate::http::control::server::ControlState;
use crate::http::control::{ControlResponse, json_error, json_response};

use super::mutate::count_uplinks_for_group;
use super::payload::{GroupListEntry, GroupsListResponse, table_to_json};

/// Extract one `GroupListEntry` per `[[uplink_group]]` on disk: name, uplink
/// count (across canonical + legacy uplink arrays), and the group's TOML table
/// as JSON for pre-filling the editor.
pub(super) fn group_entries_from_doc(doc: &DocumentMut) -> Vec<GroupListEntry> {
    let Some(groups) = doc.get("uplink_group").and_then(Item::as_array_of_tables) else {
        return Vec::new();
    };
    groups
        .iter()
        .filter_map(|tbl| {
            let name = tbl.get("name").and_then(|v| v.as_str())?.to_string();
            let uplink_count = count_uplinks_for_group(doc, &name);
            Some(GroupListEntry {
                name,
                uplink_count,
                config: table_to_json(tbl),
            })
        })
        .collect()
}

pub(super) async fn handle_list(state: Arc<ControlState>, query: Option<&str>) -> ControlResponse {
    let Some(path) = &state.config_path else {
        return json_error(
            StatusCode::CONFLICT,
            "config file path unknown; CRUD endpoints need on-disk config",
        );
    };
    let mut filter_name: Option<String> = None;
    if let Some(q) = query {
        for (key, value) in url::form_urlencoded::parse(q.as_bytes()) {
            if key.as_ref() == "name" {
                filter_name = Some(value.into_owned());
            }
        }
    }

    let raw = match fs::read_to_string(path).await {
        Ok(s) => s,
        Err(_) => {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to read config");
        },
    };
    let doc = match raw.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "config is not valid TOML"),
    };

    let mut entries = group_entries_from_doc(&doc);
    if let Some(name) = &filter_name {
        entries.retain(|e| &e.name == name);
        if entries.is_empty() {
            return json_error(StatusCode::NOT_FOUND, "uplink group not found");
        }
    }
    json_response(StatusCode::OK, &GroupsListResponse { groups: entries })
}
```

- [ ] **Step 4: Прогнать — тесты зелёные**

Run: `cargo test -p outline-ws-rust groups_crud`
Expected: PASS — `entries_carry_name_count_and_config` + Tasks 2/3 tests.

- [ ] **Step 5: Гейт + commit**

```bash
cargo fmt --check -p outline-ws-rust && cargo clippy -p outline-ws-rust --all-targets --no-deps -- -D warnings && cargo test -p outline-ws-rust groups_crud
```
```bash
git add bins/outline-ws-rust/src/http/control/groups_crud/
git commit -m "feat(control): groups_crud list with uplink_count"
```

---

### Task 5: Зарегистрировать `/control/uplink_groups` в control-сервере

Подключить диспетчер в `handle_request` (`server.rs`): и в `label_path`-match
(для метрик), и в dispatch-match. Тонкая обёртка — покрытие компиляцией +
существующими control-тестами + unit-тестами Tasks 3/4, которые зовут
handlers/helpers напрямую.

**Files:**
- Modify: `bins/outline-ws-rust/src/http/control/server.rs` (import + `handle_request` `label_path` and dispatch match arms)

**Interfaces:**
- Consumes: `groups_crud::{handle_groups, handle_groups_reorder}` (Task 3).

> Note (post-`main`-merge): `server.rs` now also carries a `/control/uplinks/reorder`
> arm and its import reads `use super::uplinks_crud::{handle_uplinks, handle_uplinks_reorder};`.
> Anchor the edits below by the neighbouring `"/control/uplinks"` arm, not by line
> number — the merge shifted them.

- [ ] **Step 1: Импорт диспетчера**

In `bins/outline-ws-rust/src/http/control/server.rs`, next to the existing
`use super::uplinks_crud::{handle_uplinks, handle_uplinks_reorder};` import, add:

```rust
use super::groups_crud::{handle_groups, handle_groups_reorder};
```

- [ ] **Step 2: Добавить путь в `label_path`-match**

In `handle_request`, in the `label_path` match, add next to the
`"/control/uplinks"` arm:

```rust
        "/control/uplink_groups" => "/control/uplink_groups",
        "/control/uplink_groups/reorder" => "/control/uplink_groups/reorder",
```

- [ ] **Step 3: Добавить dispatch-ветку**

In the dispatch match, next to the `"/control/uplinks"` arm, add:

```rust
        "/control/uplink_groups" => {
            let response = handle_groups(request, Arc::clone(&state)).await;
            record_metrics_http_request("/control/uplink_groups", response.status().as_u16());
            response
        },
        "/control/uplink_groups/reorder" => {
            let response = handle_groups_reorder(request, Arc::clone(&state)).await;
            record_metrics_http_request("/control/uplink_groups/reorder", response.status().as_u16());
            response
        },
```

- [ ] **Step 4: Прогнать — компиляция + control-тесты зелёные**

Run: `cargo test -p outline-ws-rust control`
Expected: PASS — existing control tests + groups_crud tests; new dispatch arm
compiles and routes.

- [ ] **Step 5: Гейт + commit**

```bash
cargo fmt --check -p outline-ws-rust && cargo clippy -p outline-ws-rust --all-targets --no-deps -- -D warnings && cargo test -p outline-ws-rust
```
```bash
git add bins/outline-ws-rust/src/http/control/server.rs
git commit -m "feat(control): route /control/uplink_groups to groups_crud"
```

---

### Task 6: Прокси `/ws/dashboard/api/groups` в `outline-ui`

`outline-ui` пробрасывает новый endpoint через уже существующий обобщённый
`proxy_crud` — одна строка, как `routes_proxy`. Токен узла инъектится серверно
(`backend.rs`), браузер его не видит.

**Files:**
- Modify: `bins/outline-ui/src/ws/api.rs` (add `groups_proxy` next to `routes_proxy`)
- Modify: `bins/outline-ui/src/ws/mod.rs` (add the `/dashboard/api/groups` route next to `/dashboard/api/routes`)
- Test: `bins/outline-ui/src/ws/tests/mod.rs`

**Interfaces:**
- Consumes: `proxy_crud`, `proxy_envelope_post` (`ws/api.rs`).
- Produces: `pub async fn groups_proxy(...)`, `pub async fn groups_reorder_proxy(State<WsState>, Bytes) -> Response`

- [ ] **Step 1: Написать падающий тест прокси**

Look at `bins/outline-ui/src/ws/tests/mod.rs` for the existing routes/uplinks
proxy tests (they spin up a mock control server and assert the forwarded path +
injected token). Add one modelled on the routes GET test, e.g.:

```rust
#[tokio::test]
async fn groups_get_forwards_instance_and_injects_token() {
    // Mirror the existing `routes_get_*` / `uplinks_get_*` test in this file:
    // start the mock backend, build the router, GET
    // `/ws/dashboard/api/groups?instance=<name>`, and assert the mock saw
    // `GET /control/uplink_groups` with `Authorization: Bearer <token>`.
    // Copy the closest existing test verbatim and swap the path segment
    // `routes` → `groups` and the control path `/control/routes` →
    // `/control/uplink_groups`.
}
```

(The exact harness — mock server builder, `WsState` construction, assertion
helper — is whatever the neighbouring `routes_*`/`uplinks_*` tests already use;
reuse it 1:1. If those tests live in a submodule with shared fixtures, add this
test beside them so it picks up the same fixtures.)

- [ ] **Step 2: Прогнать — не компилируется / падает**

Run: `cargo test -p outline-ui groups`
Expected: FAIL — `groups_proxy` doesn't exist and the route isn't registered.

- [ ] **Step 3: Добавить `groups_proxy`**

In `bins/outline-ui/src/ws/api.rs`, next to `routes_proxy`, add:

```rust
/// `GET|POST|PATCH|DELETE /dashboard/api/groups` — CRUD passthrough to
/// `/control/uplink_groups`. GET carries `instance` in the query; mutating
/// methods carry an `{instance, body}` envelope, same as uplinks/routes.
pub async fn groups_proxy(
    State(state): State<WsState>,
    method: Method,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    proxy_crud(&state, method, query, body, "/control/uplink_groups").await
}

/// `POST /dashboard/api/groups/reorder` — `{instance, body}` envelope to
/// `/control/uplink_groups/reorder`; `body` carries `{name, to}`, forwarded
/// verbatim (same envelope shape as routes/uplinks reorder, different path).
pub async fn groups_reorder_proxy(State(state): State<WsState>, body: Bytes) -> Response {
    proxy_envelope_post(&state, body, "/control/uplink_groups/reorder").await
}
```

- [ ] **Step 4: Зарегистрировать роут**

In `bins/outline-ui/src/ws/mod.rs`, next to the `/dashboard/api/routes` route, add:

```rust
        .route(
            "/dashboard/api/groups",
            get(api::groups_proxy)
                .post(api::groups_proxy)
                .patch(api::groups_proxy)
                .delete(api::groups_proxy),
        )
        .route("/dashboard/api/groups/reorder", post(api::groups_reorder_proxy))
```

- [ ] **Step 5: Прогнать — тест зелёный**

Run: `cargo test -p outline-ui groups`
Expected: PASS — the proxy forwards `/control/uplink_groups` with the injected
token.

- [ ] **Step 6: Гейт + commit**

```bash
cargo fmt --check -p outline-ui && cargo clippy -p outline-ui --all-targets --no-deps -- -D warnings && cargo test -p outline-ui
```
```bash
git add bins/outline-ui/src/ws/
git commit -m "feat(ui): proxy /ws/dashboard/api/groups to /control/uplink_groups"
```

---

### Task 7: Frontend — типы и API-обёртки групп

Зеркалим серверные структуры в `types.ts` и добавляем две API-функции в
`api.ts` (по образцу `uplinksList`/`uplinksMutate`; групп-reorder нет).

**Files:**
- Modify: `bins/outline-ui/frontend/src/lib/types.ts`
- Modify: `bins/outline-ui/frontend/src/lib/api.ts`

**Interfaces:**
- Produces: `GroupConfig`, `GroupEntry`, `GroupsListResponse`, `GroupMutationResponse`,
  `groupsList(i)`, `groupsMutate(method, i, body)`.

- [ ] **Step 1: Добавить типы в `types.ts`**

Append to `bins/outline-ui/frontend/src/lib/types.ts` (after the routing types
block at the bottom):

```ts
// WS uplink groups — GET /control/uplink_groups entries, proxied verbatim
// through /ws/dashboard/api/groups (groups_crud/list.rs GroupListEntry/
// GroupsListResponse). `config` mirrors the on-disk `[[uplink_group]]` table
// (table_to_json), absent when the config couldn't be read. Only the fields
// the form treats specially are named; the index signature carries the ~40
// Advanced policy fields (all optional, primitive-typed).
export interface GroupConfig {
  name?: string;
  mode?: string;
  routing_scope?: string;
  shared_resume?: boolean;
  warm_standby_tcp?: number;
  warm_standby_udp?: number;
  reselect_at?: string[];
  reselect_interval?: string;
  reselect_sync?: boolean;
  [k: string]: unknown;
}
export interface GroupEntry {
  name: string;
  // Number of [[outline.uplinks]] assigned to this group. Drives the strict
  // delete gate (disabled while > 0) and the empty-group apply hint.
  uplink_count: number;
  config?: GroupConfig | null;
}
export interface GroupsListResponse {
  groups: GroupEntry[];
}
// POST/PATCH/DELETE /control/uplink_groups response (groups_crud MutationResponse).
export interface GroupMutationResponse {
  name: string;
  action: string;
  apply_required?: boolean;
  restart_required?: boolean;
}
```

- [ ] **Step 2: Добавить API-обёртки в `api.ts`**

In `bins/outline-ui/frontend/src/lib/api.ts`, add `GroupsListResponse` and
`GroupMutationResponse` to the type import block at the top, then append after
the routing CRUD block at the bottom:

```ts
// WS uplink-group CRUD — proxied to /control/uplink_groups (ws/api.rs
// groups_proxy). GET carries `instance`; POST/PATCH/DELETE carry an
// {instance, body} envelope. Named-entry (by group name), no revision.
// Reorder is its own POST endpoint ({name, to}), like uplinks/routes reorder.
export const groupsList = (i: string) =>
  json<GroupsListResponse>(`/ws/dashboard/api/groups?${q(i)}`);
export const groupsMutate = (method: 'POST' | 'PATCH' | 'DELETE', i: string, body: unknown) =>
  json<GroupMutationResponse>(`/ws/dashboard/api/groups`, mutate(method, { instance: i, body }));
export const groupsReorder = (i: string, body: { name: string; to: number }) =>
  json<GroupMutationResponse>(`/ws/dashboard/api/groups/reorder`, mutate('POST', { instance: i, body }));
```

- [ ] **Step 3: Проверка сборки типов**

Run (from `bins/outline-ui/frontend/`): `pnpm exec tsc --noEmit`
Expected: PASS — no type errors (this task adds types only; consumers land in
Tasks 8-10).

- [ ] **Step 4: Гейт + commit**

```bash
cd bins/outline-ui/frontend && pnpm exec tsc --noEmit
```
```bash
git add bins/outline-ui/frontend/src/lib/types.ts bins/outline-ui/frontend/src/lib/api.ts
git commit -m "feat(ui): group CRUD types + api wrappers"
```

---

### Task 8: Frontend — framework-free форм-логика `groupForm.ts`

Сборка/валидация payload вне Svelte (unit-тестируемо, как `routeForm.ts`).
Ключевые поля типизированы явно (у них спец-UI: `<select>`, reselect-подсекция);
~40 Advanced-полей — **data-driven** через `ADVANCED_FIELDS` (дескрипторы
`{key, label, kind, section}`), чтобы и форма (Task 9), и `buildGroupPayload`
обходили их циклом, а не 40 явных веток. Один список полей — один источник.

**Files:**
- Create: `bins/outline-ui/frontend/src/lib/groupForm.ts`
- Create: `bins/outline-ui/frontend/src/lib/groupForm.test.ts`

**Interfaces:**
- Consumes: `GroupConfig` (Task 7).
- Produces: `ADVANCED_FIELDS`, `GroupFormFields`, `emptyGroupFields()`,
  `fieldsFromConfig(config)`, `validateGroupForm(f, editing)`,
  `buildGroupPayload(f, editing)`, plus the `MODES`/`SCOPES` option lists.

- [ ] **Step 1: Написать падающий тест**

Create `bins/outline-ui/frontend/src/lib/groupForm.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import {
  emptyGroupFields,
  fieldsFromConfig,
  validateGroupForm,
  buildGroupPayload,
} from './groupForm';
import type { GroupConfig } from './types';

describe('validateGroupForm', () => {
  it('create requires a name', () => {
    const f = { ...emptyGroupFields(), name: '' };
    expect(validateGroupForm(f, false)).toMatch(/name/i);
  });
  it('reselect requires active_passive mode', () => {
    const f = { ...emptyGroupFields(), name: 'g', mode: 'active_active', reselectMode: 'interval' as const, reselectInterval: '10h' };
    expect(validateGroupForm(f, false)).toMatch(/active_passive/);
  });
  it('reselect sync requires the at-schedule mode', () => {
    const f = { ...emptyGroupFields(), name: 'g', mode: 'active_passive', reselectMode: 'interval' as const, reselectInterval: '10h', reselectSync: true };
    expect(validateGroupForm(f, false)).toMatch(/sync/i);
  });
  it('accepts a plain active_active group', () => {
    const f = { ...emptyGroupFields(), name: 'g', mode: 'active_active', routingScope: 'per_flow' };
    expect(validateGroupForm(f, false)).toBeNull();
  });
});

describe('buildGroupPayload', () => {
  it('emits only set key fields', () => {
    const f = { ...emptyGroupFields(), name: 'main', mode: 'active_active', routingScope: 'per_flow' };
    expect(buildGroupPayload(f, false)).toEqual({ name: 'main', mode: 'active_active', routing_scope: 'per_flow' });
  });
  it('omits name on edit (identity is immutable)', () => {
    const f = { ...emptyGroupFields(), name: 'main', mode: 'active_passive' };
    expect(buildGroupPayload(f, true)).toEqual({ mode: 'active_passive' });
  });
  it('encodes reselect at-schedule with sync', () => {
    const f = {
      ...emptyGroupFields(),
      name: 'g', mode: 'active_passive', routingScope: 'global',
      reselectMode: 'at' as const, reselectAt: '03:00\n15:00', reselectSync: true,
    };
    expect(buildGroupPayload(f, false)).toEqual({
      name: 'g', mode: 'active_passive', routing_scope: 'global',
      reselect_at: ['03:00', '15:00'], reselect_sync: true,
    });
  });
  it('parses advanced fields by kind', () => {
    const f = { ...emptyGroupFields(), name: 'g', mode: 'active_active' };
    f.advanced.sticky_ttl_secs = '300';
    f.advanced.rtt_ewma_alpha = '0.3';
    f.advanced.auto_failback = 'false';
    expect(buildGroupPayload(f, false)).toEqual({
      name: 'g', mode: 'active_active',
      sticky_ttl_secs: 300, rtt_ewma_alpha: 0.3, auto_failback: false,
    });
  });
  it('round-trips advanced fields through fieldsFromConfig', () => {
    const cfg: GroupConfig = { name: 'g', mode: 'active_active', sticky_ttl_secs: 120, health_weighted_selection: true };
    expect(buildGroupPayload(fieldsFromConfig(cfg), true)).toEqual({
      mode: 'active_active', sticky_ttl_secs: 120, health_weighted_selection: true,
    });
  });
});
```

- [ ] **Step 2: Прогнать — не компилируется**

Run (from `bins/outline-ui/frontend/`): `pnpm test groupForm`
Expected: FAIL — `./groupForm` doesn't exist.

- [ ] **Step 3: Написать `groupForm.ts`**

Create `bins/outline-ui/frontend/src/lib/groupForm.ts`:

```ts
import type { GroupConfig } from './types';

export const MODES = ['active_active', 'active_passive'] as const;
export const SCOPES = ['per_flow', 'per_uplink', 'per_client', 'global'] as const;

export type ReselectMode = 'none' | 'at' | 'interval';
export type FieldKind = 'int' | 'float' | 'bool' | 'enum';

// Every `[[uplink_group]]` policy field NOT given a dedicated key control above
// (mode/routing_scope/shared_resume/warm_standby/reselect_*). `kind` drives
// both the input widget (Task 9) and the parse in buildGroupPayload/
// fieldsFromConfig — one list is the single source. `section` groups them into
// collapsible <details> blocks. Field names/kinds mirror
// bins/outline-ws-rust/src/config/schema.rs UplinkGroupSection.
export interface AdvancedField {
  key: string;
  label: string;
  kind: FieldKind;
  section: string;
  /// For kind==='enum'.
  options?: readonly string[];
}
export const ADVANCED_FIELDS: readonly AdvancedField[] = [
  // Failover / stickiness
  { key: 'sticky_ttl_secs', label: 'Sticky TTL (s)', kind: 'int', section: 'Failover' },
  { key: 'hysteresis_ms', label: 'Hysteresis (ms)', kind: 'int', section: 'Failover' },
  { key: 'failure_cooldown_secs', label: 'Failure cooldown (s)', kind: 'int', section: 'Failover' },
  { key: 'tcp_chunk0_failover_timeout_secs', label: 'TCP chunk-0 failover timeout (s)', kind: 'int', section: 'Failover' },
  { key: 'mode_downgrade_secs', label: 'Mode downgrade cooldown (s)', kind: 'int', section: 'Failover' },
  { key: 'carrier_degraded_failover_secs', label: 'Carrier-degraded failover (s)', kind: 'int', section: 'Failover' },
  { key: 'loss_failover_ratio', label: 'Loss failover ratio [0,1]', kind: 'float', section: 'Failover' },
  { key: 'loss_failover_secs', label: 'Loss failover hold (s)', kind: 'int', section: 'Failover' },
  { key: 'runtime_failure_window_secs', label: 'Runtime failure window (s)', kind: 'int', section: 'Failover' },
  { key: 'chunk0_failure_window_secs', label: 'Chunk-0 failure window (s)', kind: 'int', section: 'Failover' },
  { key: 'global_udp_strict_health', label: 'Global UDP strict health', kind: 'bool', section: 'Failover' },
  { key: 'auto_failback', label: 'Auto failback', kind: 'bool', section: 'Failover' },
  { key: 'health_weighted_selection', label: 'Health-weighted selection', kind: 'bool', section: 'Failover' },
  { key: 'health_weight_floor', label: 'Health weight floor [0,1]', kind: 'float', section: 'Failover' },
  { key: 'tun_wire_dial', label: 'TUN walks fallback wires', kind: 'bool', section: 'Failover' },
  // Scoring (RTT / loss)
  { key: 'rtt_ewma_alpha', label: 'RTT EWMA alpha', kind: 'float', section: 'Scoring' },
  { key: 'rtt_ewma_halflife_secs', label: 'RTT EWMA half-life (s)', kind: 'int', section: 'Scoring' },
  { key: 'loss_latency_penalty_k', label: 'Loss latency penalty k', kind: 'float', section: 'Scoring' },
  { key: 'loss_latency_inflation_max', label: 'Loss latency inflation max', kind: 'float', section: 'Scoring' },
  { key: 'loss_sample_interval_secs', label: 'Loss sample interval (s)', kind: 'int', section: 'Scoring' },
  { key: 'loss_sample_min_packets', label: 'Loss sample min packets', kind: 'int', section: 'Scoring' },
  { key: 'loss_ewma_alpha', label: 'Loss EWMA alpha', kind: 'float', section: 'Scoring' },
  { key: 'failure_penalty_ms', label: 'Failure penalty (ms)', kind: 'int', section: 'Scoring' },
  { key: 'failure_penalty_max_ms', label: 'Failure penalty max (ms)', kind: 'int', section: 'Scoring' },
  { key: 'failure_penalty_halflife_secs', label: 'Failure penalty half-life (s)', kind: 'int', section: 'Scoring' },
  // Keepalive
  { key: 'udp_ws_keepalive_secs', label: 'UDP WS keepalive (s)', kind: 'int', section: 'Keepalive' },
  { key: 'tcp_ws_keepalive_secs', label: 'TCP WS keepalive (s)', kind: 'int', section: 'Keepalive' },
  { key: 'tcp_ws_standby_keepalive_secs', label: 'TCP WS standby keepalive (s)', kind: 'int', section: 'Keepalive' },
  { key: 'tcp_active_keepalive_secs', label: 'TCP active keepalive (s)', kind: 'int', section: 'Keepalive' },
  { key: 'warm_probe_keepalive_secs', label: 'Warm probe keepalive (s)', kind: 'int', section: 'Keepalive' },
  // VLESS UDP mux
  { key: 'vless_udp_max_sessions', label: 'VLESS UDP max sessions', kind: 'int', section: 'VLESS UDP' },
  { key: 'vless_udp_session_idle_secs', label: 'VLESS UDP session idle (s)', kind: 'int', section: 'VLESS UDP' },
  { key: 'vless_udp_janitor_interval_secs', label: 'VLESS UDP janitor interval (s)', kind: 'int', section: 'VLESS UDP' },
  // TCP mid-session retry
  { key: 'tcp_mid_session_retry_buffer_bytes', label: 'Mid-session retry buffer (bytes)', kind: 'int', section: 'TCP retry' },
  { key: 'tcp_mid_session_retry_budget', label: 'Mid-session retry budget', kind: 'int', section: 'TCP retry' },
  { key: 'tcp_mid_session_retry_overflow_policy', label: 'Overflow policy', kind: 'enum', options: ['soft', 'hard'], section: 'TCP retry' },
  { key: 'tcp_mid_session_retry_consume_timeout_secs', label: 'Retry consume timeout (s)', kind: 'int', section: 'TCP retry' },
  { key: 'tcp_symmetric_replay_enabled', label: 'Symmetric replay enabled', kind: 'bool', section: 'TCP retry' },
  { key: 'tcp_symmetric_replay_max_bytes', label: 'Symmetric replay max (bytes)', kind: 'int', section: 'TCP retry' },
  // TUN when group is down
  { key: 'tun_suppress_icmp_reply_when_down', label: 'Suppress ICMP reply when down', kind: 'bool', section: 'TUN when down' },
  { key: 'tun_icmp_liveness_window_secs', label: 'ICMP liveness window (s)', kind: 'int', section: 'TUN when down' },
  { key: 'bypass_when_down', label: 'Bypass (direct) when down', kind: 'bool', section: 'TUN when down' },
];

export interface GroupFormFields {
  name: string;
  mode: string;
  routingScope: string;
  sharedResume: boolean;
  warmStandbyTcp: number | null;
  warmStandbyUdp: number | null;
  reselectMode: ReselectMode;
  reselectAt: string; // one HH:MM per line
  reselectInterval: string;
  reselectSync: boolean;
  // Raw string state for every ADVANCED_FIELDS key. bool → '' | 'true' | 'false'.
  advanced: Record<string, string>;
}

export function emptyGroupFields(): GroupFormFields {
  const advanced: Record<string, string> = {};
  for (const f of ADVANCED_FIELDS) advanced[f.key] = '';
  return {
    name: '',
    mode: 'active_active',
    routingScope: 'per_flow',
    sharedResume: false,
    warmStandbyTcp: null,
    warmStandbyUdp: null,
    reselectMode: 'none',
    reselectAt: '',
    reselectInterval: '',
    reselectSync: false,
    advanced,
  };
}

const lines = (s: string): string[] =>
  s.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);

export function fieldsFromConfig(config: GroupConfig | null | undefined): GroupFormFields {
  const c = (config ?? {}) as Record<string, unknown>;
  const f = emptyGroupFields();
  if (typeof c.name === 'string') f.name = c.name;
  if (typeof c.mode === 'string') f.mode = c.mode;
  if (typeof c.routing_scope === 'string') f.routingScope = c.routing_scope;
  if (typeof c.shared_resume === 'boolean') f.sharedResume = c.shared_resume;
  if (typeof c.warm_standby_tcp === 'number') f.warmStandbyTcp = c.warm_standby_tcp;
  if (typeof c.warm_standby_udp === 'number') f.warmStandbyUdp = c.warm_standby_udp;
  if (Array.isArray(c.reselect_at)) {
    f.reselectMode = 'at';
    f.reselectAt = (c.reselect_at as string[]).join('\n');
  } else if (typeof c.reselect_interval === 'string') {
    f.reselectMode = 'interval';
    f.reselectInterval = c.reselect_interval;
  }
  if (typeof c.reselect_sync === 'boolean') f.reselectSync = c.reselect_sync;
  for (const field of ADVANCED_FIELDS) {
    const v = c[field.key];
    if (v == null) continue;
    f.advanced[field.key] = String(v);
  }
  return f;
}

export function validateGroupForm(f: GroupFormFields, editing: boolean): string | null {
  if (!editing && !f.name.trim()) return 'name is required';
  if (f.name.trim().toLowerCase() === 'direct' || f.name.trim().toLowerCase() === 'drop') {
    return 'name "direct"/"drop" is reserved';
  }
  if (f.reselectMode !== 'none') {
    if (f.mode !== 'active_passive') return 'reselect requires mode = active_passive';
    if (f.routingScope !== 'global' && f.routingScope !== 'per_uplink') {
      return 'reselect requires routing_scope = global or per_uplink';
    }
    if (f.reselectMode === 'at' && lines(f.reselectAt).length === 0) return 'reselect times are required';
    if (f.reselectMode === 'interval' && !f.reselectInterval.trim()) return 'reselect interval is required';
    if (f.reselectSync && f.reselectMode !== 'at') return 'reselect sync requires the at-schedule mode';
  } else if (f.reselectSync) {
    return 'reselect sync requires the at-schedule mode';
  }
  return null;
}

export function buildGroupPayload(f: GroupFormFields, editing: boolean): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  // name is identity — sent only on create (server ignores it on PATCH anyway).
  if (!editing && f.name.trim()) out.name = f.name.trim();
  if (f.mode) out.mode = f.mode;
  if (f.routingScope) out.routing_scope = f.routingScope;
  if (f.sharedResume) out.shared_resume = true;
  if (f.warmStandbyTcp !== null) out.warm_standby_tcp = Math.trunc(f.warmStandbyTcp);
  if (f.warmStandbyUdp !== null) out.warm_standby_udp = Math.trunc(f.warmStandbyUdp);
  if (f.reselectMode === 'at') {
    const at = lines(f.reselectAt);
    if (at.length) out.reselect_at = at;
    if (f.reselectSync) out.reselect_sync = true;
  } else if (f.reselectMode === 'interval' && f.reselectInterval.trim()) {
    out.reselect_interval = f.reselectInterval.trim();
  }
  for (const field of ADVANCED_FIELDS) {
    const raw = (f.advanced[field.key] ?? '').trim();
    if (!raw) continue;
    if (field.kind === 'int') out[field.key] = Math.trunc(Number(raw));
    else if (field.kind === 'float') out[field.key] = Number(raw);
    else if (field.kind === 'bool') out[field.key] = raw === 'true';
    else out[field.key] = raw; // enum
  }
  return out;
}
```

- [ ] **Step 4: Прогнать — тесты зелёные**

Run (from `bins/outline-ui/frontend/`): `pnpm test groupForm`
Expected: PASS — all validate/build tests.

- [ ] **Step 5: Гейт + commit**

```bash
cd bins/outline-ui/frontend && pnpm test groupForm && pnpm exec tsc --noEmit
```
```bash
git add bins/outline-ui/frontend/src/lib/groupForm.ts bins/outline-ui/frontend/src/lib/groupForm.test.ts
git commit -m "feat(ui): framework-free group form logic + tests"
```

---

### Task 9: Frontend — `GroupDrawer.svelte` (форма политики)

Боковая панель-форма по образцу `UplinkDrawer.svelte`: ключевые поля видны
сразу (name только create, mode/scope `<select>`, warm_standby, shared_resume,
reselect-подсекция), Advanced — свёрнутые `<details>` по секциям
`ADVANCED_FIELDS`, инпуты рендерятся по `kind`. Драйвер отдаёт уже
провалидированный payload родителю (Task 10) через `onsave`.

**Files:**
- Create: `bins/outline-ui/frontend/src/features/ws/GroupDrawer.svelte`

**Interfaces:**
- Consumes: `groupForm.ts` (Task 8), `GroupEntry` (Task 7), `toast`.
- Produces: props `{ open, editingEntry, onclose, onsave }`; `onsave(payload, editingName)`.

- [ ] **Step 1: Написать `GroupDrawer.svelte`**

Create `bins/outline-ui/frontend/src/features/ws/GroupDrawer.svelte`. Mirrors
`UplinkDrawer.svelte`'s always-mounted backdrop/drawer + Escape/backdrop close +
`$effect`-repopulate-on-open; the body is group-specific:

```svelte
<script lang="ts">
  import { tick } from 'svelte';
  import type { GroupEntry } from '../../lib/types';
  import {
    ADVANCED_FIELDS,
    MODES,
    SCOPES,
    emptyGroupFields,
    fieldsFromConfig,
    validateGroupForm,
    buildGroupPayload,
    type GroupFormFields,
  } from '../../lib/groupForm';
  import { toast } from '../../lib/toast.svelte';

  let {
    open,
    editingEntry = null,
    onclose,
    onsave,
  }: {
    open: boolean;
    editingEntry?: GroupEntry | null;
    onclose: () => void;
    onsave: (payload: Record<string, unknown>, editingName: string | null) => Promise<void>;
  } = $props();

  const editing = $derived(editingEntry !== null);
  let fields = $state<GroupFormFields>(emptyGroupFields());
  let saving = $state(false);
  let nameInput: HTMLInputElement | undefined = $state();

  // Sections in declaration order (Failover, Scoring, Keepalive, …).
  const sections = $derived.by(() => {
    const seen: string[] = [];
    for (const f of ADVANCED_FIELDS) if (!seen.includes(f.section)) seen.push(f.section);
    return seen;
  });
  function fieldsIn(section: string) {
    return ADVANCED_FIELDS.filter((f) => f.section === section);
  }

  $effect(() => {
    if (!open) return;
    fields = editingEntry ? fieldsFromConfig(editingEntry.config) : emptyGroupFields();
    if (!editingEntry) tick().then(() => nameInput?.focus());
  });

  $effect(() => {
    if (!open) return;
    const onKeydown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onclose();
    };
    window.addEventListener('keydown', onKeydown);
    return () => window.removeEventListener('keydown', onKeydown);
  });
  function onBackdropClick(e: MouseEvent) {
    if (e.target === e.currentTarget) onclose();
  }

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    const error = validateGroupForm(fields, editing);
    if (error) {
      toast(error, 'error');
      return;
    }
    const payload = buildGroupPayload(fields, editing);
    saving = true;
    try {
      await onsave(payload, editing ? (editingEntry as GroupEntry).name : null);
    } finally {
      saving = false;
    }
  }
</script>

<div class="backdrop" class:open onclick={onBackdropClick} role="presentation"></div>
<aside class="drawer" class:open aria-hidden={!open}>
  <header>
    <h3>{#if editing}Edit group &quot;{editingEntry?.name}&quot;{:else}Add uplink group{/if}</h3>
    <span class="spacer"></span>
    <button class="iconbtn" type="button" aria-label="Close" onclick={onclose}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg>
    </button>
  </header>
  <form class="body" id="group-drawer-form" onsubmit={handleSubmit}>
    {#if !editing}
      <div class="fieldrow">
        <label for="group-name">Name</label>
        <input id="group-name" class="field-mono" type="text" bind:value={fields.name} bind:this={nameInput} required autocomplete="off" placeholder="main" />
        <span class="hint">Immutable after creation. Create the group empty, then add uplinks in the Uplinks tab.</span>
      </div>
    {/if}

    <div class="fieldrow">
      <label for="group-mode">Mode</label>
      <select id="group-mode" class="field-mono" bind:value={fields.mode}>
        {#each MODES as m}<option value={m}>{m}</option>{/each}
      </select>
    </div>
    <div class="fieldrow">
      <label for="group-scope">Routing scope</label>
      <select id="group-scope" class="field-mono" bind:value={fields.routingScope}>
        {#each SCOPES as s}<option value={s}>{s}</option>{/each}
      </select>
    </div>
    <div class="fieldrow">
      <label for="group-wstcp">Warm standby TCP</label>
      <input id="group-wstcp" class="field-mono" type="number" step="1" bind:value={fields.warmStandbyTcp} placeholder="default" />
    </div>
    <div class="fieldrow">
      <label for="group-wsudp">Warm standby UDP</label>
      <input id="group-wsudp" class="field-mono" type="number" step="1" bind:value={fields.warmStandbyUdp} placeholder="default" />
    </div>
    <div class="switch">
      <input id="group-cluster" type="checkbox" bind:checked={fields.sharedResume} />
      <label for="group-cluster">Shared resume (cluster)</label>
    </div>

    <fieldset class="fieldset">
      <legend>Reselect</legend>
      <div class="fieldrow">
        <label for="group-reselect-mode">Schedule</label>
        <select id="group-reselect-mode" class="field-mono" bind:value={fields.reselectMode}>
          <option value="none">none</option>
          <option value="at">at times (HH:MM)</option>
          <option value="interval">interval</option>
        </select>
      </div>
      {#if fields.reselectMode === 'at'}
        <div class="fieldrow">
          <label for="group-reselect-at">Times</label>
          <textarea id="group-reselect-at" class="field-mono" rows="3" bind:value={fields.reselectAt} placeholder="03:00&#10;15:00"></textarea>
          <span class="hint">One HH:MM (local time) per line.</span>
        </div>
        <div class="switch">
          <input id="group-reselect-sync" type="checkbox" bind:checked={fields.reselectSync} />
          <label for="group-reselect-sync">Sync order across nodes</label>
        </div>
      {:else if fields.reselectMode === 'interval'}
        <div class="fieldrow">
          <label for="group-reselect-interval">Interval</label>
          <input id="group-reselect-interval" class="field-mono" type="text" bind:value={fields.reselectInterval} placeholder="10h / 1h30m" />
        </div>
      {/if}
      <span class="hint">Reselect requires mode = active_passive and routing_scope = global/per_uplink.</span>
    </fieldset>

    {#each sections as section}
      <details class="fieldset">
        <summary>{section}</summary>
        {#each fieldsIn(section) as fld (fld.key)}
          <div class="fieldrow">
            <label for={`group-adv-${fld.key}`}>{fld.label}</label>
            {#if fld.kind === 'bool'}
              <select id={`group-adv-${fld.key}`} class="field-mono" bind:value={fields.advanced[fld.key]}>
                <option value="">default</option>
                <option value="true">true</option>
                <option value="false">false</option>
              </select>
            {:else if fld.kind === 'enum'}
              <select id={`group-adv-${fld.key}`} class="field-mono" bind:value={fields.advanced[fld.key]}>
                <option value="">default</option>
                {#each fld.options ?? [] as opt}<option value={opt}>{opt}</option>{/each}
              </select>
            {:else}
              <input id={`group-adv-${fld.key}`} class="field-mono" type="number" step={fld.kind === 'float' ? 'any' : '1'} bind:value={fields.advanced[fld.key]} placeholder="default" />
            {/if}
          </div>
        {/each}
      </details>
    {/each}
  </form>
  <div class="foot">
    <button class="btn ghost" type="button" onclick={onclose} disabled={saving}>Cancel</button>
    <button class="btn primary" type="submit" form="group-drawer-form" disabled={saving}>{editing ? 'Update' : 'Create'}</button>
  </div>
</aside>
```

Note: number `<input bind:value>` on a `Record<string,string>` slot coerces to a
string on write — that's intentional (Advanced state is all strings; parsing
happens in `buildGroupPayload` by `kind`). If Svelte's type-check complains about
binding a number input to a string, keep the binding and rely on the runtime
string coercion (matches how `UplinkDrawer.svelte` binds numeric fields through
string form state).

**Probe override — вне формы (первая версия, осознанно).** `GroupPayload`
принимает `probe` на сервере, но drawer его НЕ показывает: вложенный
`ProbeSection` (под-таблицы ws/http/dns/tcp/tls) непропорционально усложнил бы
форму сейчас. Оператор задаёт `[uplink_group.probe]` прямой правкой `config.toml`;
редактор группы round-trip'ит все прочие поля политики. Вернуться, если попросят
per-group probe в UI.

- [ ] **Step 2: Проверка сборки типов**

Run (from `bins/outline-ui/frontend/`): `pnpm exec tsc --noEmit && pnpm exec svelte-check --threshold error`
Expected: PASS — no type/svelte errors (component compiles; consumer lands in
Task 10).

- [ ] **Step 3: Гейт + commit**

```bash
cd bins/outline-ui/frontend && pnpm exec svelte-check --threshold error
```
```bash
git add bins/outline-ui/frontend/src/features/ws/GroupDrawer.svelte
git commit -m "feat(ui): GroupDrawer policy form (key fields + data-driven advanced)"
```

---

### Task 10: Frontend — `UplinkGroups.svelte` + навигация

Вкладка: таблица групп (name · uplink_count · policy-чипы · Edit/Delete), кнопка
Add group, applybar с Apply now и превентивной подсказкой про пустые группы,
drawer. Delete задизейблен при `uplink_count > 0` (сервер тоже отвергает).
Named-mutate (`groupsMutate`), **reorder** (`groupsReorder`, drag + ↑/↓ — как
`Uplinks.svelte`), dirty/apply-механика — как `Uplinks.svelte`, applyNow —
счётчики групп/аплинков (не routing-развилка).

**Files:**
- Create: `bins/outline-ui/frontend/src/features/ws/UplinkGroups.svelte`
- Modify: `bins/outline-ui/frontend/src/components/layout/Sidebar.svelte`
- Modify: `bins/outline-ui/frontend/src/App.svelte`

**Interfaces:**
- Consumes: `groupsList`/`groupsMutate`/`groupsReorder`/`apply` (Task 7),
  `GroupDrawer` (Task 9), `createPoll`, `toast`.

- [ ] **Step 1: Написать `UplinkGroups.svelte`**

Create `bins/outline-ui/frontend/src/features/ws/UplinkGroups.svelte`:

```svelte
<script lang="ts">
  import { onDestroy } from 'svelte';
  import { SvelteSet } from 'svelte/reactivity';
  import { groupsList, groupsMutate, groupsReorder, apply } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { toast } from '../../lib/toast.svelte';
  import type { GroupEntry, GroupsListResponse, GroupConfig, ApplyResult } from '../../lib/types';
  import InstanceSelector from '../../components/layout/InstanceSelector.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';
  import GroupDrawer from './GroupDrawer.svelte';

  let instance = $state('');
  let refreshSecs = $state(5);
  const refreshMs = $derived(Math.max(1000, refreshSecs * 1000));

  const groupsPoll = createPoll<GroupsListResponse>(
    () => (instance ? groupsList(instance) : Promise.resolve<GroupsListResponse>({ groups: [] })),
    () => refreshMs,
  );
  $effect(() => { void instance; groupsPoll.start(); });
  onDestroy(() => groupsPoll.stop());

  const entries = $derived<GroupEntry[]>(groupsPoll.data?.groups ?? []);
  // Preventive hint: a group staged with zero uplinks makes /control/apply fail
  // the "≥1 uplink per group" invariant. Surface the names before Apply.
  const emptyGroups = $derived(entries.filter((g) => g.uplink_count === 0).map((g) => g.name));

  const dirtyInstances = new SvelteSet<string>();
  const dirty = $derived(instance !== '' && dirtyInstances.has(instance));
  let mutating = $state(false);
  let applying = $state(false);
  const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));

  let drawerOpen = $state(false);
  let editingEntry = $state<GroupEntry | null>(null);
  function openCreate() { editingEntry = null; drawerOpen = true; }
  function openEdit(entry: GroupEntry) { editingEntry = entry; drawerOpen = true; }
  function closeDrawer() { drawerOpen = false; editingEntry = null; }

  async function saveGroup(payload: Record<string, unknown>, editingName: string | null) {
    mutating = true;
    try {
      if (editingName) {
        await groupsMutate('PATCH', instance, { name: editingName, patch: payload });
      } else {
        await groupsMutate('POST', instance, { group: payload });
      }
      dirtyInstances.add(instance);
      toast('Saved to config (not yet applied).');
      closeDrawer();
      await groupsPoll.refresh();
    } catch (e) { toast(errMsg(e), 'error'); }
    finally { mutating = false; }
  }

  async function removeGroup(entry: GroupEntry) {
    if (entry.uplink_count > 0) return; // UI guard; server also refuses (409)
    if (!confirm(`Delete uplink group "${entry.name}"?`)) return;
    mutating = true;
    try {
      await groupsMutate('DELETE', instance, { name: entry.name });
      dirtyInstances.add(instance);
      toast('Deleted from config (not yet applied).');
      await groupsPoll.refresh();
    } catch (e) { toast(errMsg(e), 'error'); }
    finally { mutating = false; }
  }

  // Reorder groups — cosmetic (rewrites config-file order only; selection is by
  // the routing `via` rule, not position). Drag a row or use ↑/↓; both drive
  // groupsReorder(name, to). Mirrors Uplinks.svelte's per-group row drag.
  let draggingName: string | null = $state(null);
  let dragOverName: string | null = $state(null);

  async function reorderTo(name: string, to: number) {
    mutating = true;
    try {
      await groupsReorder(instance, { name, to });
      dirtyInstances.add(instance);
      await groupsPoll.refresh();
    } catch (e) { toast(errMsg(e), 'error'); }
    finally { mutating = false; }
  }
  async function move(i: number, dir: -1 | 1) {
    const to = i + dir;
    if (to < 0 || to >= entries.length) return;
    await reorderTo(entries[i].name, to);
  }
  function handleDragStart(e: DragEvent, name: string) {
    draggingName = name;
    e.dataTransfer?.setData('text/plain', name);
    if (e.dataTransfer) e.dataTransfer.effectAllowed = 'move';
  }
  function handleDragOver(e: DragEvent, name: string) {
    if (draggingName === null) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
    dragOverName = name;
  }
  function handleDragLeave(name: string) {
    if (dragOverName === name) dragOverName = null;
  }
  async function handleDrop(e: DragEvent, targetIndex: number) {
    e.preventDefault();
    dragOverName = null;
    const from = draggingName;
    draggingName = null;
    if (from === null) return;
    const srcIdx = entries.findIndex((g) => g.name === from);
    if (srcIdx === -1 || srcIdx === targetIndex) return;
    await reorderTo(from, targetIndex);
  }
  function handleDragEnd() {
    draggingName = null;
    dragOverName = null;
  }

  async function applyNow() {
    applying = true;
    try {
      const result = (await apply(instance)) as ApplyResult;
      dirtyInstances.delete(instance);
      toast(`Applied: ${result.groups ?? '?'} groups, ${result.total_uplinks ?? '?'} uplinks.`);
      await groupsPoll.refresh();
    } catch (e) { toast(`Apply failed: ${errMsg(e)}`, 'error'); }
    finally { applying = false; }
  }

  interface Chip { text: string; tone?: 'info' | 'off'; }
  function chipsFor(c: GroupConfig | null | undefined): Chip[] {
    const chips: Chip[] = [];
    if (c?.mode) chips.push({ text: String(c.mode), tone: 'info' });
    if (c?.routing_scope) chips.push({ text: String(c.routing_scope) });
    if (c?.shared_resume) chips.push({ text: 'cluster' });
    if (Array.isArray(c?.reselect_at)) chips.push({ text: `reselect @${(c!.reselect_at as string[]).join(',')}` });
    else if (c?.reselect_interval) chips.push({ text: `reselect ${c.reselect_interval}` });
    if (c?.probe) chips.push({ text: 'probe' });
    return chips.length ? chips : [{ text: '—', tone: 'off' }];
  }
</script>

<section class="view active">
  <div class="page-head">
    <div>
      <h1>Uplink groups</h1>
      <p>Edit group policy (mode, scope, reselect, scoring), then hot-apply to the running instance.</p>
    </div>
    <div class="toolbar">
      <InstanceSelector base="/ws" bind:selected={instance} bind:refreshSecs={refreshSecs} />
    </div>
  </div>

  {#if !instance}
    <div class="empty">Select a client instance to load uplink groups.</div>
  {:else}
    <ErrorBanner message={groupsPoll.error} />

    {#if dirty}
      <div class="applybar">
        <span class="dot warn"></span>
        <strong>Pending changes</strong>
        <span class="pill">{instance}: staged, not yet applied</span>
        {#if emptyGroups.length}
          <span class="pill warn">Empty: {emptyGroups.join(', ')} — add uplinks (Uplinks tab) before applying</span>
        {/if}
        <div style="margin-left:auto; display:flex; gap:8px">
          <button class="btn primary sm" disabled={applying} onclick={applyNow}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg>
            Apply now
          </button>
        </div>
      </div>
    {/if}

    <div class="panel">
      <div class="group-head">
        <span class="gname">Groups</span>
        <span class="gcount">{entries.length}</span>
        <div class="right">
          <button class="btn sm" disabled={mutating} onclick={openCreate}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
            Add group
          </button>
        </div>
      </div>
      {#if entries.length}
        <table>
          <thead><tr><th>Group</th><th>Uplinks</th><th>Policy</th><th>Actions</th></tr></thead>
          <tbody>
            {#each entries as g, i (g.name)}
              <tr
                class:dragging={draggingName === g.name}
                class:drag-over={dragOverName === g.name && draggingName !== g.name}
                draggable={!mutating}
                ondragstart={(ev) => handleDragStart(ev, g.name)}
                ondragover={(ev) => handleDragOver(ev, g.name)}
                ondragleave={() => handleDragLeave(g.name)}
                ondrop={(ev) => handleDrop(ev, i)}
                ondragend={handleDragEnd}
              >
                <td>
                  <span class="route-idx">
                    <span class="drag-handle" aria-hidden="true" title="Drag to reorder">⠿</span>
                    {g.name}
                  </span>
                </td>
                <td>{g.uplink_count}</td>
                <td>
                  <div style="display:flex; flex-wrap:wrap; gap:4px">
                    {#each chipsFor(g.config) as c}<span class="chip {c.tone ?? ''}">{c.text}</span>{/each}
                  </div>
                </td>
                <td>
                  <div class="rowactions">
                    <button class="iconbtn" title="Move up" disabled={mutating || i === 0} aria-label={`Move ${g.name} up`} onclick={() => move(i, -1)}>↑</button>
                    <button class="iconbtn" title="Move down" disabled={mutating || i === entries.length - 1} aria-label={`Move ${g.name} down`} onclick={() => move(i, 1)}>↓</button>
                    <button class="iconbtn act-soft" title="Edit" disabled={mutating} aria-label={`Edit group ${g.name}`} onclick={() => openEdit(g)}>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
                    </button>
                    <button
                      class="iconbtn act-danger"
                      title={g.uplink_count > 0 ? 'Remove its uplinks first' : 'Delete'}
                      disabled={mutating || g.uplink_count > 0}
                      aria-label={`Delete group ${g.name}`}
                      onclick={() => removeGroup(g)}
                    >
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/></svg>
                    </button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else if !groupsPoll.error}
        <div class="empty">No uplink groups configured for this instance.</div>
      {/if}
    </div>
  {/if}
</section>

<GroupDrawer open={drawerOpen} {editingEntry} onclose={closeDrawer} onsave={saveGroup} />
```

- [ ] **Step 2: Пункт навигации в `Sidebar.svelte`**

In `bins/outline-ui/frontend/src/components/layout/Sidebar.svelte`, add a
`groupsActive` derived next to `routingActive` (line 6) and exclude it from
`topologyActive`:

```svelte
  const uplinksActive = $derived(route.path.startsWith('/ws/uplinks'));
  const routingActive = $derived(route.path.startsWith('/ws/routing'));
  const groupsActive = $derived(route.path.startsWith('/ws/groups'));
  const topologyActive = $derived(current === 'ws' && !uplinksActive && !routingActive && !groupsActive);
```

Then add a nav item after the Routing `div.navlink` (after line 74):

```svelte
  <div
    class="navlink"
    class:active={groupsActive}
    role="button"
    tabindex="0"
    onclick={() => go('/ws/groups')}
    onkeydown={(e) => onKey(e, '/ws/groups')}
  >
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><path d="M7 14v3a1 1 0 0 0 1 1h3"/></svg>
    Uplink groups
  </div>
```

- [ ] **Step 3: Ветка рендера в `App.svelte`**

In `bins/outline-ui/frontend/src/App.svelte`, add the import and derived flag,
then a render branch. Import next to `Routing` (line 8):

```svelte
  import UplinkGroups from './features/ws/UplinkGroups.svelte';
```

Flag next to `isRouting` (line 14):

```svelte
  const isGroups = $derived(route.path.startsWith('/ws/groups'));
```

Branch — place it before `isUplinks` (any order works since the paths are
disjoint, but keep it grouped with the other `/ws/*` sub-tabs):

```svelte
    {:else if isRouting}
      <Routing />
    {:else if isGroups}
      <UplinkGroups />
    {:else if isUplinks}
      <Uplinks />
```

- [ ] **Step 4: Прогнать фронт-гейт**

Run (from `bins/outline-ui/frontend/`):

```bash
cd bins/outline-ui/frontend && pnpm exec svelte-check --threshold error && pnpm test && pnpm build
```
Expected: PASS — type-check clean, all Vitest suites (incl. `groupForm`) green,
production bundle builds.

- [ ] **Step 5: Гейт + commit**

```bash
git add bins/outline-ui/frontend/src/features/ws/UplinkGroups.svelte bins/outline-ui/frontend/src/components/layout/Sidebar.svelte bins/outline-ui/frontend/src/App.svelte
git commit -m "feat(ui): Uplink groups tab with CRUD, reorder + apply"
```

---

### Task 11: Документация (EN/RU синхронно)

**Files:**
- Modify: `bins/outline-ui/README.md` + `bins/outline-ui/README.ru.md`
- Modify: `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md` + `.ru.md`

- [ ] **Step 1: outline-ui README (обе стороны)**

In `bins/outline-ui/README.md`, in the WS-panel tab list (near where Topology /
Uplinks / Routing are described), add a line:

> **Uplink groups** (`/ws/groups`) — CRUD editor for `[[uplink_group]]` policy
> (mode, routing scope, reselect, warm standby, cluster resume, and the advanced
> scoring/failover/keepalive knobs). Staged → **Apply now**, hot-applied without
> a node restart. A group is created empty; add its uplinks in the Uplinks tab.
> Delete is only allowed for a group with no uplinks.

Add the mirrored Russian line to `bins/outline-ui/README.ru.md` in the same spot:

> **Uplink groups** (`/ws/groups`) — CRUD-редактор политики `[[uplink_group]]`
> (mode, routing scope, reselect, тёплый резерв, cluster resume и продвинутые
> ручки scoring/failover/keepalive). Staged → **Apply now**, применяется без
> рестарта узла. Группа создаётся пустой; аплинки добавляются во вкладке Uplinks.
> Удаление разрешено только для группы без аплинков.

- [ ] **Step 2: UPLINK-CONFIGURATIONS (обе стороны)**

In `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md`, add a short section
documenting the new control endpoint (mirror the existing `/control/uplinks`
CRUD prose if present):

> ### `/control/uplink_groups` (CRUD)
> GET lists `[[uplink_group]]` sections (`{name, uplink_count, config}`); POST
> creates an (empty) group; PATCH merges policy into an existing group by name
> (name is immutable); DELETE removes a group that has no uplinks. All mutations
> stage the change to `config.toml`; `POST /control/apply` hot-applies the new
> group set (`registry.apply_new_groups`) without a restart. Per-group LB/reselect
> policy is validated on every mutation with the same loader used at startup.

Add the mirrored Russian section to `UPLINK-CONFIGURATIONS.ru.md`:

> ### `/control/uplink_groups` (CRUD)
> GET отдаёт секции `[[uplink_group]]` (`{name, uplink_count, config}`); POST
> создаёт (пустую) группу; PATCH мержит политику в существующую группу по имени
> (имя неизменяемо); DELETE удаляет группу без аплинков. Любая мутация стейджит
> изменение в `config.toml`; `POST /control/apply` применяет новый набор групп
> (`registry.apply_new_groups`) без рестарта. Пер-групповая LB/reselect-политика
> валидируется на каждой мутации тем же загрузчиком, что и на старте.

- [ ] **Step 3: Commit**

```bash
git add bins/outline-ui/README.md bins/outline-ui/README.ru.md bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.ru.md
git commit -m "docs: document uplink-groups tab and /control/uplink_groups (EN/RU)"
```

---

### Task 12: ops — bump тега образа outline-ui

`main` уже поднял образ до `1.0.4` (uplinks reorder). Эта вкладка — следующий
bump до `1.0.5`. **Сам деплой не выполняем** (правило: раскатка по отдельной
команде владельца); задача только правит манифест.

**Files:**
- Modify: `ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml`

- [ ] **Step 1: Bump тега**

In `ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml`, change the image tag
`registry.k3s.beerloga.su/outline-ui:1.0.4` → `:1.0.5`. (Verify the current tag
first — if `main` moved it again, bump from whatever is there.)

- [ ] **Step 2: Commit**

```bash
git add ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml
git commit -m "ops(ui): bump outline-ui image to 1.0.5 (uplink groups tab)"
```

---

## Финальная проверка (после всех задач)

Полный CI-гейт (как в Global Constraints), затем фронт-гейт:

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto && cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings && cargo test --workspace --exclude sockudo-ws
```
```bash
cd bins/outline-ui/frontend && pnpm test && pnpm build
```

**Раскатка (по команде владельца, не частью плана):** `pnpm build` →
`cargo ui-release-musl-aarch64 --features embed-assets` → `docker build` → push
в `registry.k3s.beerloga.su` → `kubectl -n monitoring rollout restart deploy/outline-ui`.

## Ручная проверка (smoke, после раскатки на тестовый инстанс)

1. Открыть `/ws/groups`, выбрать инстанс → таблица групп с `uplink_count` и
   policy-чипами.
2. Add group `test` (mode active_passive, scope global) → toast «Saved», строка
   появилась, `uplink_count = 0`, кнопка Delete активна, applybar показывает
   «Empty: test».
3. Apply now → toast-ошибка (пустая группа не проходит `load_config`), dirty
   остаётся. Ожидаемо.
4. Добавить аплинк в `test` (вкладка Uplinks) → вернуться, `uplink_count = 1`,
   Delete задизейблен. Apply now → «Applied: N groups, M uplinks».
5. Edit `test`: reselect at `03:00` + sync → Save → Apply → политика в
   `config.toml` узла (`grep -a reselect_at`).
6. Delete непустой группы (Uplinks убрать не до нуля) → кнопка disabled; попытка
   через API → 409.
7. Reorder: перетащить строку группы (или ↑/↓) → порядок в таблице меняется,
   инстанс dirty; после Apply — новый порядок `[[uplink_group]]` в `config.toml`
   узла (`grep -n uplink_group`), не тихий no-op (проверка position-fix).
