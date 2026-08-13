# Вкладка редактирования routing-конфига в `outline-ui` — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** добавить в WS-панель `outline-ui` вкладку Routing — структурированный
CRUD-редактор правил `[[route]]` с reorder и кнопкой Apply, применяющей правки
без рестарта узла.

**Architecture:** снизу вверх. (A) В `crates/outline-routing` появляется
подменяемая обёртка `SharedRoutingTable` (`ArcSwap<RoutingTable>`); TUN и SOCKS
держат её вместо голого `Arc<RoutingTable>`, а `impl Router` делает подмену
прозрачной для SOCKS. (B) Новый control-endpoint `/control/routes` в
`outline-ws-rust` правит `[[route]]` через `toml_edit` по образцу
`uplinks_crud`; `/control/apply` расширяется, чтобы пересобирать таблицу и
атомарно её подменять. (C) `outline-ui` проксирует новый endpoint. (D) Svelte-
вкладка Routing + drawer + framework-free форм-логика.

**Tech Stack:** Rust 2024 (`toml_edit`, `arc-swap`, `anyhow`, `hyper`, `axum`
для UI-прокси), Svelte 5 (runes) + TypeScript + Vitest.

Спека: [`docs/superpowers/specs/2026-08-13-outline-ui-routing-tab-design.md`](../specs/2026-08-13-outline-ui-routing-tab-design.md).

## Global Constraints

- Тесты живут в `<dir>/tests/<basename>.rs`; inline `#[cfg(test)] mod tests {}`
  запрещён. Rust-тест подключается через `#[cfg(test)] #[path = "tests/<name>.rs"] mod tests;`.
- Комментарии в коде, сообщения коммитов, PR — на английском. Общение с
  владельцем — на русском.
- `#[serde(deny_unknown_fields)]` на всех пользовательских секциях сохраняется.
- User-facing документация ведётся парами EN/RU и правится в одном изменении
  (`README.md` + `README.ru.md`).
- Секреты (пароли, PSK, UUID, токены) не логируются и не попадают в тесты;
  routing-правила секретов не содержат, но `via`/пути не логировать на уровне
  выше debug.
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
  `pnpm build` (сборка ассетов, которые встраиваются в бинарь под фичей
  `embed-assets`).
- **Коммиты выполняются только с явного разрешения владельца** (правило репо:
  `git commit` / `git push` без команды не запускать). Шаги «Commit» ниже
  выполняются, когда разрешение получено; иначе изменения накапливаются в
  рабочем дереве, а владельцу показывается diff.

---

## Карта файлов

**Слой A — data plane:**
- Create: `crates/outline-routing/src/shared.rs` — обёртка `SharedRoutingTable`.
- Modify: `crates/outline-routing/src/lib.rs` — модуль + ре-экспорт.
- Modify: `bins/outline-ws-rust/src/proxy/router.rs` — `impl Router for SharedRoutingTable`.
- Modify: `crates/outline-tun/src/routing.rs` — поле-обёртка + `.load()`.
- Modify: `bins/outline-ws-rust/src/bootstrap/mod.rs` — создание обёртки, wiring.

**Слой B — control API узла:**
- Modify: `bins/outline-ws-rust/src/config/schema.rs` — (тип `RouteSection` уже есть).
- Modify: `bins/outline-ws-rust/src/config/mod.rs` — ре-экспорт `RouteSection`, `load_routing_config`.
- Modify: `bins/outline-ws-rust/src/config/load/routing.rs` — сигнатура валидатора.
- Modify: `bins/outline-ws-rust/src/config/load/mod.rs` — вызов валидатора.
- Create: `bins/outline-ws-rust/src/http/control/config_edit.rs` — общие TOML/HTTP-хелперы.
- Modify: `bins/outline-ws-rust/src/http/control/uplinks_crud/*` — переключить на общие хелперы.
- Create: `bins/outline-ws-rust/src/http/control/routes_crud/{mod,payload,mutate}.rs`.
- Modify: `bins/outline-ws-rust/src/http/control/mod.rs` — `mod routes_crud;`.
- Modify: `bins/outline-ws-rust/src/http/control/server.rs` — dispatch `/control/routes`.
- Modify: `bins/outline-ws-rust/src/http/control/apply.rs` — hot-apply routing.

**Слой C — outline-ui прокси:**
- Modify: `bins/outline-ui/src/ws/api.rs` — `routes_proxy`, `routes_reorder_proxy`.
- Modify: `bins/outline-ui/src/ws/mod.rs` — роуты.

**Слой D — фронт:**
- Modify: `bins/outline-ui/frontend/src/lib/types.ts` — типы routing.
- Modify: `bins/outline-ui/frontend/src/lib/api.ts` — API-обёртки.
- Create: `bins/outline-ui/frontend/src/lib/routeForm.ts` + `routeForm.test.ts`.
- Create: `bins/outline-ui/frontend/src/features/ws/Routing.svelte` + `RouteDrawer.svelte`.
- Modify: `bins/outline-ui/frontend/src/App.svelte`, `lib/router.svelte.ts`,
  `components/layout/Sidebar.svelte` — навигация.

**Слой E — доки:**
- Modify: `bins/outline-ui/README.md` + `README.ru.md`; `bins/outline-ws-rust/README.md` + `README.ru.md`.

---

### Task 1: Обёртка `SharedRoutingTable` в `outline-routing`

Подменяемый держатель `RoutingTable` за `ArcSwap`, сохраняющий монотонность
`version` через подмену (иначе per-association кэши в SOCKS/TUN пропустят
инвалидацию). Изолированная единица: ничего ещё не потребляет её.

**Files:**
- Create: `crates/outline-routing/src/shared.rs`
- Modify: `crates/outline-routing/src/lib.rs`
- Test: `crates/outline-routing/src/tests/shared.rs`

**Interfaces:**
- Consumes: `RoutingTable` (`table.rs`), `arc_swap::ArcSwap`.
- Produces:
  - `SharedRoutingTable::new(table: RoutingTable) -> Arc<SharedRoutingTable>`
  - `SharedRoutingTable::load(&self) -> arc_swap::Guard<Arc<RoutingTable>>`
  - `SharedRoutingTable::load_full(&self) -> Arc<RoutingTable>`
  - `SharedRoutingTable::version(&self) -> u64`
  - `SharedRoutingTable::swap_preserving_version(&self, new: RoutingTable) -> Arc<RoutingTable>`
  - `SharedRoutingTable::resolve(&self, &TargetAddr) -> RouteDecision`
  - `SharedRoutingTable::resolve_versioned(&self, &TargetAddr) -> (RouteDecision, u64)`

- [ ] **Step 1: Написать падающий тест**

Create `crates/outline-routing/src/tests/shared.rs`:

```rust
use std::sync::atomic::Ordering;

use socks5_proto::TargetAddr;

use crate::config::{RouteRule, RouteTarget, RoutingTableConfig};
use crate::shared::SharedRoutingTable;
use crate::table::RoutingTable;

fn direct_only_config() -> RoutingTableConfig {
    RoutingTableConfig {
        rules: vec![RouteRule {
            inline_prefixes: vec!["10.0.0.0/8".to_string()],
            files: vec![],
            inline_domains: vec![],
            domain_files: vec![],
            file_poll: std::time::Duration::from_secs(60),
            target: RouteTarget::Direct,
            fallback: None,
            invert: false,
        }],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: None,
    }
}

fn drop_default_config() -> RoutingTableConfig {
    RoutingTableConfig {
        rules: vec![],
        default_target: RouteTarget::Drop,
        default_fallback: None,
    }
}

#[tokio::test]
async fn swap_preserves_version_monotonicity() {
    let first = RoutingTable::compile(&direct_only_config()).await.unwrap();
    // Simulate a table that has already been reloaded a few times.
    first.version.store(5, Ordering::Release);
    let shared = SharedRoutingTable::new(first);
    assert_eq!(shared.version(), 5);

    let second = RoutingTable::compile(&drop_default_config()).await.unwrap();
    assert_eq!(second.version.load(Ordering::Acquire), 0, "fresh compile starts at 0");

    shared.swap_preserving_version(second);
    assert_eq!(shared.version(), 6, "version must continue from the old table, not reset to 0");
}

#[tokio::test]
async fn resolve_reflects_the_swapped_table() {
    let shared = SharedRoutingTable::new(RoutingTable::compile(&direct_only_config()).await.unwrap());
    let ip: TargetAddr = "10.1.2.3:443".parse().unwrap();
    assert_eq!(shared.resolve(&ip).primary, RouteTarget::Direct);

    shared.swap_preserving_version(RoutingTable::compile(&drop_default_config()).await.unwrap());
    // 10.0.0.0/8 rule is gone; everything now hits the drop default.
    assert_eq!(shared.resolve(&ip).primary, RouteTarget::Drop);
}
```

- [ ] **Step 2: Прогнать — тест не компилируется (нет модуля)**

Run: `cargo test -p outline-routing shared`
Expected: FAIL — `unresolved import crate::shared` / `no field version` is
accessible.

Note: `RoutingTable.version` is `pub` already (`table.rs:58`), and
`RouteRule`/`RoutingTableConfig` fields are `pub`. If `version.store` in the
test can't reach it, that's the signal the field visibility is fine (it is —
`pub`), and the failure is only the missing `shared` module.

- [ ] **Step 3: Написать `SharedRoutingTable`**

Create `crates/outline-routing/src/shared.rs`:

```rust
//! Hot-swappable holder for a [`RoutingTable`].
//!
//! The table's per-rule CIDR/domain sets are already hot-reloadable in place
//! (see [`crate::table::spawn_route_watchers`]), but the *shape* of the table
//! — how many rules, their order, their targets — is fixed at compile time.
//! Applying edited `[[route]]` config therefore means compiling a whole new
//! table and swapping the pointer. Both the SOCKS dispatcher and the TUN
//! engine hold an `Arc<SharedRoutingTable>`, so one `store` is seen by both at
//! once — unlike the pre-swap design where each held an independent
//! `Arc<RoutingTable>` clone that could not be replaced from outside.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use arc_swap::ArcSwap;
use socks5_proto::TargetAddr;

use crate::table::{RouteDecision, RoutingTable};

#[derive(Debug)]
pub struct SharedRoutingTable {
    current: ArcSwap<RoutingTable>,
}

impl SharedRoutingTable {
    pub fn new(table: RoutingTable) -> Arc<Self> {
        Arc::new(Self { current: ArcSwap::from_pointee(table) })
    }

    /// Cheap read guard for the resolve path — no lock, no await.
    pub fn load(&self) -> arc_swap::Guard<Arc<RoutingTable>> {
        self.current.load()
    }

    /// Full `Arc` clone, needed to seed [`crate::table::spawn_route_watchers`]
    /// (which takes an owned `Arc<RoutingTable>`).
    pub fn load_full(&self) -> Arc<RoutingTable> {
        self.current.load_full()
    }

    pub fn version(&self) -> u64 {
        self.current.load().version()
    }

    /// Publish `new` as the live table, continuing the `version` counter from
    /// the outgoing table instead of letting a freshly-compiled table's `0`
    /// shadow a higher live version — which would make per-association caches
    /// tagged with the old (higher) version look "current" and skip
    /// re-resolution. The version is stamped BEFORE the store so no reader can
    /// observe the new table at its temporary `0`.
    pub fn swap_preserving_version(&self, new: RoutingTable) -> Arc<RoutingTable> {
        let next = self.current.load().version() + 1;
        new.version.store(next, Ordering::Release);
        let arc = Arc::new(new);
        self.current.store(Arc::clone(&arc));
        arc
    }

    pub fn resolve(&self, target: &TargetAddr) -> RouteDecision {
        self.current.load().resolve(target)
    }

    pub fn resolve_versioned(&self, target: &TargetAddr) -> (RouteDecision, u64) {
        self.current.load().resolve_versioned(target)
    }
}

#[cfg(test)]
#[path = "tests/shared.rs"]
mod tests;
```

Wire the module into `crates/outline-routing/src/lib.rs`. Find the existing
`mod table;` / `pub use table::…` block (around lines 12-17) and add alongside:

```rust
mod shared;
pub use shared::SharedRoutingTable;
```

`RoutingTable.version` is a `pub AtomicU64` field (`table.rs:58`), so
`new.version.store(...)` compiles from `shared.rs` without new accessors.

- [ ] **Step 4: Прогнать — тесты зелёные**

Run: `cargo test -p outline-routing shared`
Expected: PASS — both `swap_preserves_version_monotonicity` and
`resolve_reflects_the_swapped_table`.

- [ ] **Step 5: Гейт + commit**

```bash
cargo fmt --check -p outline-routing && cargo clippy -p outline-routing --all-targets --no-deps -- -D warnings && cargo test -p outline-routing
```
```bash
git add crates/outline-routing/src/shared.rs crates/outline-routing/src/lib.rs crates/outline-routing/src/tests/shared.rs
git commit -m "feat(routing): add SharedRoutingTable hot-swap holder"
```

---

### Task 2: Потребители держат `SharedRoutingTable` (TUN + SOCKS + bootstrap)

Переключить оба потребителя с `Arc<RoutingTable>` на `Arc<SharedRoutingTable>`.
SOCKS не меняется по коду вообще — обёртка реализует `Router`, поэтому
`ProxyConfig.router` просто получает обёртку. TUN держит `.load()` перед
резолвом (ему нужен `resolve_domain_or_ip`, которого нет в трейте `Router`).
Атомарная задача: смена типа через границы крейтов не компилируется наполовину.

**Files:**
- Modify: `bins/outline-ws-rust/src/proxy/router.rs` (add impl after line 53)
- Modify: `crates/outline-tun/src/routing.rs:22-116` (field type + resolve + version + `new`)
- Modify: `bins/outline-ws-rust/src/bootstrap/mod.rs:153-204,269-275`
- Test: existing `crates/outline-tun/src/tests/routing.rs`, `crates/outline-tun/src/udp/tests/*` (must stay green)

**Interfaces:**
- Consumes: `SharedRoutingTable` (Task 1).
- Produces:
  - `TunRouting::new(registry, routing: Option<Arc<SharedRoutingTable>>, direct_fwmark, ipsec_bypass)`
  - `impl crate::proxy::Router for outline_routing::SharedRoutingTable`

- [ ] **Step 1: `impl Router for SharedRoutingTable`**

In `bins/outline-ws-rust/src/proxy/router.rs`, after the existing
`impl Router for RoutingTable` block (ends line 53), add:

```rust
impl Router for outline_routing::SharedRoutingTable {
    fn version(&self) -> u64 {
        outline_routing::SharedRoutingTable::version(self)
    }

    fn resolve_versioned(&self, target: &TargetAddr) -> (RouteDecision, u64) {
        outline_routing::SharedRoutingTable::resolve_versioned(self, target)
    }

    fn resolve(&self, target: &TargetAddr) -> RouteDecision {
        outline_routing::SharedRoutingTable::resolve(self, target)
    }
}
```

Update the top `use` (line 11) to also import the wrapper:

```rust
use outline_routing::{RouteDecision, RoutingTable, SharedRoutingTable};
```
(and drop the `outline_routing::` prefixes above to `SharedRoutingTable` if you
prefer — either compiles; keep it explicit if clippy's `unused_imports`
complains).

- [ ] **Step 2: Переключить `TunRouting` на обёртку**

In `crates/outline-tun/src/routing.rs`:

1. Change the import (line 12):
```rust
use outline_routing::{RouteTarget, SharedRoutingTable};
```
(drop `RoutingTable` — no longer named directly here).

2. Change the field (line 24):
```rust
    routing: Option<Arc<SharedRoutingTable>>,
```

3. Change `new`'s parameter (line 77):
```rust
        routing: Option<Arc<SharedRoutingTable>>,
```

4. In `resolve_scoped` (line 148), the table is now behind the wrapper — take a
   read guard:
```rust
        let decision = table.load().resolve(target);
```

5. In `resolve_sni` (line 211):
```rust
        let decision = table.load().resolve_domain_or_ip(sni_host, Some(ip_target));
```

`routing_version` (line 114-116) needs no change: `SharedRoutingTable::version`
has the same name and signature as `RoutingTable::version`, so
`table.version()` still type-checks. `from_single_manager` (test-only, line 95)
keeps `routing: None` unchanged.

- [ ] **Step 3: Wiring в bootstrap**

In `bins/outline-ws-rust/src/bootstrap/mod.rs`, replace the compile block
(lines 153-163) so the compiled table is wrapped:

```rust
    let (shared_routing, _route_watchers) = if let Some(routing_cfg) = config.routing.clone() {
        let table = outline_routing::RoutingTable::compile(&routing_cfg)
            .await
            .context("failed to compile routing table")?;
        let shared = outline_routing::SharedRoutingTable::new(table);
        let guard = outline_routing::spawn_route_watchers(shared.load_full());
        (Some(shared), Some(guard))
    } else {
        (None, None)
    };
```

Update the TUN construction (line 199-204) — `shared_routing.clone()` is now
`Option<Arc<SharedRoutingTable>>`, exactly the new `TunRouting::new` param:

```rust
        let tun_routing = outline_tun::TunRouting::new(
            registry.clone(),
            shared_routing.clone(),
            config.direct_fwmark,
            ipsec_bypass,
        );
```

Update `ProxyConfig.router` (line 272) — cast the wrapper to `dyn Router`:

```rust
        router: shared_routing
            .clone()
            .map(|t| t as Arc<dyn crate::proxy::Router>),
```

Leave the `_route_watchers` guard binding as-is for now (Task 8 moves it into
`ApplyHandle` so apply can respawn it).

- [ ] **Step 4: Прогнать TUN + proxy тесты**

Run: `cargo test -p outline-tun -p outline-ws-rust routing`
Expected: PASS — existing routing/udp/tcp engine tests still green (behaviour
unchanged: one `.load()` indirection added on the resolve path).

- [ ] **Step 5: Полный гейт (смена типов через крейты) + commit**

```bash
cargo fmt --check -p outline-ws-rust -p outline-tun -p outline-routing && cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings && cargo test --workspace --exclude sockudo-ws
```
```bash
git add crates/outline-tun/src/routing.rs bins/outline-ws-rust/src/proxy/router.rs bins/outline-ws-rust/src/bootstrap/mod.rs
git commit -m "refactor(routing): consumers hold SharedRoutingTable wrapper"
```

---

### Task 3: Экспонировать валидатор routing для переиспользования

`load_routing_config` сейчас `pub(super)` и принимает `&ConfigFile`. CRUD-
endpoint должен прогонять ту же whole-list валидацию (ровно один `default`,
`via`→группа, `invert`⊕`domains`, fallback) на секциях, которые он собрал из
`toml_edit`-документа, без построения целого `ConfigFile`. Меняем сигнатуру на
приём `&[RouteSection]` + список имён групп и открываем видимость.

**Files:**
- Modify: `bins/outline-ws-rust/src/config/load/routing.rs:22-42`
- Modify: `bins/outline-ws-rust/src/config/load/mod.rs:65-66`
- Modify: `bins/outline-ws-rust/src/config/mod.rs:16-21`
- Test: `bins/outline-ws-rust/src/config/load/tests/routing.rs` (add one case)

**Interfaces:**
- Produces:
  - `pub(crate) fn load_routing_config(sections: Option<&[RouteSection]>, group_names: &[&str], config_dir: &Path) -> Result<Option<RoutingTableConfig>>`
  - `pub(crate) use schema::RouteSection;`

- [ ] **Step 1: Написать падающий тест переиспользования**

Add to `bins/outline-ws-rust/src/config/load/tests/routing.rs` (create the
file with the `#[path]` attachment if it doesn't exist — check
`config/load/routing.rs` bottom for an existing `#[cfg(test)] #[path = "tests/routing.rs"] mod tests;`; add it if missing):

```rust
use std::path::Path;

use serde::Deserialize;

use super::load_routing_config;
use crate::config::schema::RouteSection;

fn parse_sections(toml_str: &str) -> Vec<RouteSection> {
    #[derive(Deserialize)]
    struct Wrapper {
        route: Vec<RouteSection>,
    }
    toml::from_str::<Wrapper>(toml_str).expect("valid route TOML").route
}

#[test]
fn validator_reuse_rejects_two_defaults() {
    let sections = parse_sections(
        "[[route]]\ndefault = true\nvia = \"main\"\n\
         [[route]]\ndefault = true\nvia = \"main\"\n",
    );
    let err = load_routing_config(Some(&sections), &["main"], Path::new("/tmp"))
        .expect_err("two defaults must be rejected");
    assert!(format!("{err:#}").contains("default = true"), "got: {err:#}");
}

#[test]
fn validator_reuse_accepts_valid_list() {
    let sections = parse_sections(
        "[[route]]\nprefixes = [\"10.0.0.0/8\"]\nvia = \"direct\"\n\
         [[route]]\ndefault = true\nvia = \"main\"\n",
    );
    let table = load_routing_config(Some(&sections), &["main"], Path::new("/tmp"))
        .expect("valid list")
        .expect("some table");
    assert_eq!(table.rules.len(), 1);
}
```

- [ ] **Step 2: Прогнать — тест не компилируется**

Run: `cargo test -p outline-ws-rust validator_reuse`
Expected: FAIL — `load_routing_config` takes `Option<&ConfigFile>`, and
`crate::config::schema::RouteSection` is private.

- [ ] **Step 3: Изменить сигнатуру валидатора**

In `bins/outline-ws-rust/src/config/load/routing.rs`, change the signature
(lines 22-26) and the two lines that currently read from `file`:

```rust
pub(crate) fn load_routing_config(
    sections: Option<&[RouteSection]>,
    group_names: &[&str],
    config_dir: &Path,
) -> Result<Option<RoutingTableConfig>> {
    let Some(route_sections) = sections else {
        return Ok(None);
    };
```

Delete the old group-name derivation (was line 42:
`let group_names: Vec<&str> = groups.iter()...`) — it's now a parameter. Every
downstream use of `group_names` already refers to a `&[&str]`, so the body
below is unchanged. Ensure the `RouteSection` import at the top of the file
resolves (it's in the same crate: `use crate::config::schema::RouteSection;` if
not already imported).

- [ ] **Step 4: Обновить единственного caller**

In `bins/outline-ws-rust/src/config/load/mod.rs` (lines 65-66):

```rust
    let groups = groups::load_groups(outline.as_ref(), file.as_ref(), args)?;
    let group_names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();
    let routing = routing::load_routing_config(
        file.as_ref().and_then(|f| f.route.as_deref()),
        &group_names,
        config_dir,
    )?;
```

- [ ] **Step 5: Открыть `RouteSection`**

In `bins/outline-ws-rust/src/config/mod.rs`, next to the existing
`pub(crate) use schema::UplinkSection;` (line 21) and
`pub(crate) use load::validate_uplink_section;` (line 19), add:

```rust
pub(crate) use load::load_routing_config;
pub(crate) use schema::RouteSection;
```

`load_routing_config` must be reachable as `crate::config::load_routing_config`
from the control layer. It currently lives in the private `load` submodule;
the re-export above surfaces it. (`RouteSection`'s fields stay `pub(super)` —
the round-trip only ever `toml::from_str`s into it, never reads its fields
across modules.)

- [ ] **Step 6: Прогнать — тесты зелёные, config-suite не сломан**

Run: `cargo test -p outline-ws-rust config`
Expected: PASS — new `validator_reuse_*` plus all existing config/routing
loader tests (the caller change is signature-only, behaviour identical).

- [ ] **Step 7: Гейт + commit**

```bash
cargo fmt --check -p outline-ws-rust && cargo clippy -p outline-ws-rust --all-targets --no-deps -- -D warnings && cargo test -p outline-ws-rust config
```
```bash
git add bins/outline-ws-rust/src/config/
git commit -m "refactor(config): load_routing_config takes route sections + group names"
```

---

### Task 4: Общие TOML/HTTP-хелперы для CRUD-эндпоинтов

`routes_crud` и `uplinks_crud` делят один и тот же скелет правки config.toml.
Выносим переиспользуемые куски в `control/config_edit.rs` (`pub(crate)`), затем
переключаем `uplinks_crud` на них — единый источник для атомарной записи,
round-trip рендера и error→status маппинга, чтобы routing-CRUD не расходился с
uplink-CRUD в этих тонкостях (напр. рендер вложенных `ArrayOfTables`).

**Files:**
- Create: `bins/outline-ws-rust/src/http/control/config_edit.rs`
- Modify: `bins/outline-ws-rust/src/http/control/mod.rs` (add `mod config_edit;`)
- Modify: `bins/outline-ws-rust/src/http/control/uplinks_crud/io.rs`,
  `payload.rs`, `mutate.rs` (import shared, drop local copies)
- Test: existing `uplinks_crud` tests must stay green

**Interfaces:**
- Produces (all `pub(crate)` in `config_edit`):
  - `async fn read_json<T: DeserializeOwned>(request, label: &'static str) -> Result<T, ControlResponse>`
  - `fn json_error_owned(status: StatusCode, message: String) -> ControlResponse`
  - `async fn write_document_atomic(path: &Path, doc: &DocumentMut) -> anyhow::Result<()>`
  - `fn render_table_with_arrays(tbl: &Table) -> String`
  - `fn table_to_json(tbl: &Table) -> Option<serde_json::Value>`
  - `fn status_for_mutator_error(msg: &str) -> StatusCode` (`"not found"`→404, `"already exists"`→409, else 400)

- [ ] **Step 1: Создать `config_edit.rs`**

Create `bins/outline-ws-rust/src/http/control/config_edit.rs`:

```rust
//! Shared building blocks for control endpoints that edit `config.toml`
//! in place (`uplinks_crud`, `routes_crud`). Keeps the atomic-write,
//! round-trip-render and error→status conventions identical across both so a
//! second editor can't drift from the first on subtle TOML details (nested
//! `ArrayOfTables` header rendering in particular).

use std::path::Path;

use anyhow::Context;
use http::{Request, StatusCode};
use hyper::body::Incoming;
use serde::Serialize;
use serde::de::DeserializeOwned;
use toml_edit::{DocumentMut, Table};

use crate::http::body::read_limited_body;
use crate::http::control::{ControlResponse, json_response};

/// Bounded-body read + JSON deserialize. `label` is the metrics/path tag
/// forwarded to `read_limited_body` (413 on over-limit, 400 on read error).
pub(crate) async fn read_json<T: DeserializeOwned>(
    request: Request<Incoming>,
    label: &'static str,
) -> Result<T, ControlResponse> {
    let body = read_limited_body(request.into_body(), label).await?;
    serde_json::from_slice::<T>(&body)
        .map_err(|e| json_error_owned(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")))
}

/// Owned-`String` error responder (counterpart to `json_error`'s `&'static str`).
pub(crate) fn json_error_owned(status: StatusCode, message: String) -> ControlResponse {
    #[derive(Serialize)]
    struct Owned {
        error: String,
    }
    json_response(status, &Owned { error: message })
}

/// Serialize `doc` and write it over `path` atomically at 0600, offloading the
/// blocking write. `config.toml` holds secrets, so a plain write+rename would
/// widen mode to the umask and open a world-readable window.
pub(crate) async fn write_document_atomic(path: &Path, doc: &DocumentMut) -> anyhow::Result<()> {
    let contents = doc.to_string();
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::fs_util::atomic_write(&path, contents.as_bytes()))
        .await
        .context("config write task panicked")?
}

/// Render a standalone `Table` to TOML text with nested `ArrayOfTables`
/// headers intact. `Table::to_string()` alone can't render array-of-tables
/// items because their headers need the parent path, which a detached table
/// doesn't know — so wrap it in a fresh document first.
pub(crate) fn render_table_with_arrays(tbl: &Table) -> String {
    let mut doc = DocumentMut::new();
    let root = doc.as_table_mut();
    for (key, item) in tbl.iter() {
        root.insert(key, item.clone());
    }
    doc.to_string()
}

/// Round-trip a `Table` to a `serde_json::Value` (via TOML text). `None` on
/// round-trip failure — callers surface it as "config unreadable" rather than
/// an error.
pub(crate) fn table_to_json(tbl: &Table) -> Option<serde_json::Value> {
    let text = render_table_with_arrays(tbl);
    let toml_value: toml::Value = toml::from_str(&text).ok()?;
    serde_json::to_value(toml_value).ok()
}

/// Map a mutator closure's `Err(String)` to an HTTP status by substring
/// convention: `"not found"`→404, `"already exists"`→409, else 400.
pub(crate) fn status_for_mutator_error(msg: &str) -> StatusCode {
    if msg.contains("not found") {
        StatusCode::NOT_FOUND
    } else if msg.contains("already exists") {
        StatusCode::CONFLICT
    } else {
        StatusCode::BAD_REQUEST
    }
}
```

Register it in `bins/outline-ws-rust/src/http/control/mod.rs` next to
`mod uplinks_crud;` (line 12):

```rust
mod config_edit;
```

- [ ] **Step 2: Переключить `uplinks_crud` на общие хелперы**

- In `uplinks_crud/io.rs`: delete `read_json` and `json_error_owned` (the whole
  file's body). Keep the file only if something else lives there; otherwise
  delete `io.rs` and drop `mod io;` from `uplinks_crud/mod.rs`. Update
  `uplinks_crud/mutate.rs`'s import `use super::io::{json_error_owned, read_json};`
  to `use crate::http::control::config_edit::{json_error_owned, read_json};`.
  `read_json` now takes a `label` arg — update call sites to
  `read_json(request, "/control/uplinks").await`.
- In `uplinks_crud/payload.rs`: delete `render_table_with_arrays` and
  `table_to_json`; `use crate::http::control::config_edit::{render_table_with_arrays, table_to_json};`.
- In `uplinks_crud/mutate.rs`: delete `write_document_atomic`; import it from
  `config_edit`. Replace the inline error-mapping in `mutate_config_file`
  (the `if msg.contains("not found") … else …` block) with
  `let status = crate::http::control::config_edit::status_for_mutator_error(&msg); (status, msg)`.

- [ ] **Step 3: Прогнать — uplinks CRUD не сломан**

Run: `cargo test -p outline-ws-rust uplinks`
Expected: PASS — every existing `uplinks_crud` test green (pure extraction, no
behaviour change).

- [ ] **Step 4: Гейт + commit**

```bash
cargo fmt --check -p outline-ws-rust && cargo clippy -p outline-ws-rust --all-targets --no-deps -- -D warnings && cargo test -p outline-ws-rust
```
```bash
git add bins/outline-ws-rust/src/http/control/
git commit -m "refactor(control): extract shared config-edit helpers"
```

---

### Task 5: `routes_crud/payload.rs` — wire-типы и TOML-конверсия

Типы запросов/ответов для `/control/routes` и построение `toml_edit::Table` из
правила. Routes адресуются индексом (нет имён), `[[route]]` — top-level массив.
`revision` — детерминированный хэш секции для оптимистичной блокировки (без
крипто-зависимостей: FNV-1a).

**Files:**
- Create: `bins/outline-ws-rust/src/http/control/routes_crud/payload.rs`
- Create: `bins/outline-ws-rust/src/http/control/routes_crud/mod.rs` (module stub; filled in Task 6)
- Test: `bins/outline-ws-rust/src/http/control/routes_crud/tests/payload.rs`

**Interfaces:**
- Produces (all `pub(super)` unless noted):
  - `struct RoutePayload` (13 `Option` fields, `deny_unknown_fields`)
  - `struct CreateBody { rule: RoutePayload, at_index: Option<usize>, revision: String }`
  - `struct UpdateBody { index: usize, rule: RoutePayload, revision: String }`
  - `struct DeleteBody { index: usize, revision: String }`
  - `struct ReorderBody { from: usize, to: usize, revision: String }`
  - `struct RouteListEntry { index: usize, is_default: bool, config: Option<Value> }`
  - `struct RoutesListResponse { routes: Vec<RouteListEntry>, groups: Vec<String>, revision: String }`
  - `struct MutationResponse { action, index, apply_required, restart_required, revision }`
  - `fn payload_to_table(&RoutePayload) -> Table`
  - `fn route_revision(&ArrayOfTables) -> String`

- [ ] **Step 1: Написать падающий тест**

Create `bins/outline-ws-rust/src/http/control/routes_crud/tests/payload.rs`:

```rust
use toml_edit::ArrayOfTables;

use super::{RoutePayload, payload_to_table, route_revision};
use crate::config::RouteSection;
use crate::http::control::config_edit::render_table_with_arrays;

fn payload(json: &str) -> RoutePayload {
    serde_json::from_str(json).expect("valid payload")
}

#[test]
fn payload_round_trips_through_route_section() {
    let p = payload(
        r#"{"prefixes":["10.0.0.0/8","192.168.0.0/16"],"via":"direct","invert":false}"#,
    );
    let table = payload_to_table(&p);
    let text = render_table_with_arrays(&table);
    // The exact shape the whole-list validator will re-parse.
    let section: RouteSection = toml::from_str(&text).expect("parses as RouteSection");
    let _ = section; // fields are pub(super); reaching here proves the round-trip.
    assert!(text.contains("via = \"direct\""), "got: {text}");
    assert!(text.contains("10.0.0.0/8"), "got: {text}");
}

#[test]
fn default_rule_serializes_without_matchers() {
    let p = payload(r#"{"default":true,"via":"main"}"#);
    let text = render_table_with_arrays(&payload_to_table(&p));
    assert!(text.contains("default = true"));
    assert!(!text.contains("prefixes"));
}

#[test]
fn deny_unknown_fields_rejects_typos() {
    let err = serde_json::from_str::<RoutePayload>(r#"{"viaa":"main"}"#).unwrap_err();
    assert!(err.to_string().contains("unknown field"), "got: {err}");
}

#[test]
fn revision_is_stable_and_content_sensitive() {
    let mut arr = ArrayOfTables::new();
    arr.push(payload_to_table(&payload(r#"{"default":true,"via":"main"}"#)));
    let r1 = route_revision(&arr);
    let r2 = route_revision(&arr);
    assert_eq!(r1, r2, "same content → same revision");

    arr.push(payload_to_table(&payload(r#"{"prefixes":["10.0.0.0/8"],"via":"direct"}"#)));
    assert_ne!(r1, route_revision(&arr), "changed content → changed revision");
}
```

- [ ] **Step 2: Прогнать — не компилируется**

Run: `cargo test -p outline-ws-rust routes_crud`
Expected: FAIL — module `routes_crud` doesn't exist yet.

- [ ] **Step 3: Написать `payload.rs`**

Create `bins/outline-ws-rust/src/http/control/routes_crud/payload.rs`:

```rust
//! Wire types + TOML conversion for `/control/routes`.
//!
//! A `[[route]]` rule has no identity key — it is addressed by its index in
//! the top-level `route` array. `revision` is a content hash of that array,
//! sent back on every mutation so a stale index (a concurrent edit shifted the
//! rows) is rejected with 409 instead of moving the wrong rule.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use toml_edit::{Array, ArrayOfTables, Item, Table};

use crate::http::control::config_edit::render_table_with_arrays;

/// Mirrors `crate::config::RouteSection`; every field optional. Paths arrive as
/// JSON strings (deserialized into `PathBuf` only later, when the rendered TOML
/// is re-parsed as `RouteSection`). `deny_unknown_fields` so a mistyped key is
/// a 400, not a silently-dropped rule.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoutePayload {
    pub(super) prefixes: Option<Vec<String>>,
    pub(super) file: Option<String>,
    pub(super) files: Option<Vec<String>>,
    pub(super) domains: Option<Vec<String>>,
    pub(super) domain_file: Option<String>,
    pub(super) domain_files: Option<Vec<String>>,
    pub(super) file_poll_secs: Option<u64>,
    pub(super) default: Option<bool>,
    pub(super) via: Option<String>,
    pub(super) fallback_via: Option<String>,
    pub(super) fallback_direct: Option<bool>,
    pub(super) fallback_drop: Option<bool>,
    pub(super) invert: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(super) struct CreateBody {
    pub(super) rule: RoutePayload,
    /// Insert position; `None` → append just before the `default` rule.
    pub(super) at_index: Option<usize>,
    pub(super) revision: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct UpdateBody {
    pub(super) index: usize,
    pub(super) rule: RoutePayload,
    pub(super) revision: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct DeleteBody {
    pub(super) index: usize,
    pub(super) revision: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReorderBody {
    pub(super) from: usize,
    pub(super) to: usize,
    pub(super) revision: String,
}

#[derive(Debug, Serialize)]
pub(super) struct RouteListEntry {
    pub(super) index: usize,
    pub(super) is_default: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) config: Option<Value>,
}

#[derive(Debug, Serialize)]
pub(super) struct RoutesListResponse {
    pub(super) routes: Vec<RouteListEntry>,
    pub(super) groups: Vec<String>,
    pub(super) revision: String,
}

#[derive(Debug, Serialize)]
pub(super) struct MutationResponse {
    pub(super) action: &'static str,
    pub(super) index: usize,
    pub(super) apply_required: bool,
    pub(super) restart_required: bool,
    pub(super) revision: String,
}

impl MutationResponse {
    pub(super) fn staged(
        action: &'static str,
        index: usize,
        hot_apply_available: bool,
        revision: String,
    ) -> Self {
        Self {
            action,
            index,
            apply_required: hot_apply_available,
            restart_required: !hot_apply_available,
            revision,
        }
    }
}

fn str_array(values: &[String]) -> Value {
    let mut arr = Array::new();
    for v in values {
        arr.push(v.as_str());
    }
    Value::Array(arr)
}

/// Build a `[[route]]` table from a payload. Only `Some` fields are emitted, so
/// a rule carries exactly what the operator set — nothing defaulted onto disk.
pub(super) fn payload_to_table(p: &RoutePayload) -> Table {
    let mut t = Table::new();
    if let Some(v) = &p.prefixes {
        t.insert("prefixes", Item::Value(str_array(v)));
    }
    if let Some(v) = &p.file {
        t.insert("file", Item::Value(v.as_str().into()));
    }
    if let Some(v) = &p.files {
        t.insert("files", Item::Value(str_array(v)));
    }
    if let Some(v) = &p.domains {
        t.insert("domains", Item::Value(str_array(v)));
    }
    if let Some(v) = &p.domain_file {
        t.insert("domain_file", Item::Value(v.as_str().into()));
    }
    if let Some(v) = &p.domain_files {
        t.insert("domain_files", Item::Value(str_array(v)));
    }
    if let Some(v) = p.file_poll_secs {
        t.insert("file_poll_secs", Item::Value((v as i64).into()));
    }
    if let Some(v) = p.default {
        t.insert("default", Item::Value(v.into()));
    }
    if let Some(v) = &p.via {
        t.insert("via", Item::Value(v.as_str().into()));
    }
    if let Some(v) = &p.fallback_via {
        t.insert("fallback_via", Item::Value(v.as_str().into()));
    }
    if let Some(v) = p.fallback_direct {
        t.insert("fallback_direct", Item::Value(v.into()));
    }
    if let Some(v) = p.fallback_drop {
        t.insert("fallback_drop", Item::Value(v.into()));
    }
    if let Some(v) = p.invert {
        t.insert("invert", Item::Value(v.into()));
    }
    t
}

/// Is this table the `default = true` rule?
pub(super) fn table_is_default(t: &Table) -> bool {
    t.get("default").and_then(|i| i.as_bool()).unwrap_or(false)
}

/// FNV-1a (64-bit) over the rendered array text. Deterministic and
/// dependency-free — enough to detect a concurrent edit between a GET and a
/// mutation. Not security-sensitive.
pub(super) fn route_revision(arr: &ArrayOfTables) -> String {
    let mut doc = toml_edit::DocumentMut::new();
    let mut aot = ArrayOfTables::new();
    for t in arr.iter() {
        aot.push(t.clone());
    }
    doc.insert("route", Item::ArrayOfTables(aot));
    let text = doc.to_string();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// One `RouteListEntry`'s `config` object from its on-disk table.
pub(super) fn route_table_to_json(t: &Table) -> Option<Value> {
    let text = render_table_with_arrays(t);
    let toml_value: toml::Value = toml::from_str(&text).ok()?;
    serde_json::to_value(toml_value).ok()
}
```

Create the module stub `bins/outline-ws-rust/src/http/control/routes_crud/mod.rs`
(dispatcher lands in Task 6; for now just declare submodules so the payload
tests compile):

```rust
mod payload;

#[cfg(test)]
#[path = "tests/payload.rs"]
mod tests;
```

Register the module in `bins/outline-ws-rust/src/http/control/mod.rs` next to
`mod config_edit;`:

```rust
mod routes_crud;
```

If clippy flags `payload_to_table`/`route_revision`/etc. as unused until Task 6
wires them, add a temporary `#![allow(dead_code)]` at the top of
`routes_crud/mod.rs` and remove it in Task 6's commit.

- [ ] **Step 4: Прогнать — тесты зелёные**

Run: `cargo test -p outline-ws-rust routes_crud`
Expected: PASS — all four payload tests.

- [ ] **Step 5: Гейт + commit**

```bash
cargo fmt --check -p outline-ws-rust && cargo clippy -p outline-ws-rust --all-targets --no-deps -- -D warnings && cargo test -p outline-ws-rust routes_crud
```
```bash
git add bins/outline-ws-rust/src/http/control/routes_crud/ bins/outline-ws-rust/src/http/control/mod.rs
git commit -m "feat(control): routes_crud payload types + TOML conversion"
```

---

### Task 6: `routes_crud/mutate.rs` + `mod.rs` — CRUD, reorder, revision-guard

Read→mutate→whole-list-validate→atomic-write, addressing rules by index.
Whole-list validation reuses `load_routing_config` (Task 3) so a staged config
can never be one that fails to boot. `default` rule is protected (undeletable,
matchers can't be added, `default` can't be cleared). Every mutation checks the
client's `revision` against the on-disk array and returns 409 on mismatch.

**Files:**
- Create: `bins/outline-ws-rust/src/http/control/routes_crud/mutate.rs`
- Modify: `bins/outline-ws-rust/src/http/control/routes_crud/mod.rs` (dispatcher)
- Test: `bins/outline-ws-rust/src/http/control/routes_crud/tests/mutate.rs`

**Interfaces:**
- Consumes: `config_edit::{read_json, json_error_owned, write_document_atomic, status_for_mutator_error}`, `crate::config::load_routing_config`, payload types (Task 5).
- Produces:
  - `pub(crate) async fn handle_routes(request, state: Arc<ControlState>) -> ControlResponse`
  - `pub(crate) async fn handle_routes_reorder(request, state: Arc<ControlState>) -> ControlResponse`

- [ ] **Step 1: Написать падающие тесты**

Create `bins/outline-ws-rust/src/http/control/routes_crud/tests/mutate.rs`.
These are pure document-mutation unit tests (no HTTP), exercising the shared
helpers Task 6 introduces. Mirror the `uplinks_crud` test style (a temp
`config.toml`, call the helper, re-read):

```rust
use std::path::Path;

use toml_edit::DocumentMut;

use super::mutate::{
    apply_create, apply_delete, apply_reorder, group_names_in_doc, validate_route_array,
};
use super::payload::{RoutePayload, route_revision};

const BASE: &str = "\
[[uplink_group]]
name = \"main\"

[[route]]
prefixes = [\"10.0.0.0/8\"]
via = \"direct\"

[[route]]
default = true
via = \"main\"
";

fn doc() -> DocumentMut {
    BASE.parse::<DocumentMut>().unwrap()
}

fn payload(json: &str) -> RoutePayload {
    serde_json::from_str(json).unwrap()
}

#[test]
fn create_inserts_before_default_by_default() {
    let mut d = doc();
    apply_create(&mut d, &payload(r#"{"domains":["ads.example"],"via":"drop"}"#), None)
        .expect("create ok");
    let arr = d.get("route").unwrap().as_array_of_tables().unwrap();
    assert_eq!(arr.len(), 3);
    // New rule sits at index 1, default stays last.
    assert_eq!(arr.get(1).unwrap().get("via").unwrap().as_str(), Some("drop"));
    assert!(arr.get(2).unwrap().get("default").unwrap().as_bool().unwrap());
}

#[test]
fn delete_default_is_refused() {
    let mut d = doc();
    let err = apply_delete(&mut d, 1).expect_err("default index");
    assert!(err.contains("default"), "got: {err}");
}

#[test]
fn reorder_moves_rule() {
    let mut d = doc();
    apply_reorder(&mut d, 0, 1).expect("reorder ok");
    let arr = d.get("route").unwrap().as_array_of_tables().unwrap();
    // default moved to front, direct rule to index 1.
    assert!(arr.get(0).unwrap().get("default").unwrap().as_bool().unwrap());
}

#[test]
fn validate_rejects_via_to_unknown_group() {
    let mut d = doc();
    apply_create(&mut d, &payload(r#"{"prefixes":["1.2.3.0/24"],"via":"ghost"}"#), Some(0))
        .expect("staged");
    let groups = group_names_in_doc(&d);
    let names: Vec<&str> = groups.iter().map(String::as_str).collect();
    let err = validate_route_array(&d, &names, Path::new("/tmp")).expect_err("bad via");
    assert!(format!("{err:#}").contains("ghost") || format!("{err:#}").contains("group"), "got: {err:#}");
}

#[test]
fn group_names_are_extracted() {
    assert_eq!(group_names_in_doc(&doc()), vec!["main".to_string()]);
}
```

- [ ] **Step 2: Прогнать — не компилируется**

Run: `cargo test -p outline-ws-rust routes_crud::tests::mutate`
Expected: FAIL — `super::mutate` module and its functions don't exist.

- [ ] **Step 3: Написать `mutate.rs`**

Create `bins/outline-ws-rust/src/http/control/routes_crud/mutate.rs`:

```rust
//! Read→mutate→validate→write for `[[route]]`, addressed by array index.

use std::path::Path;
use std::sync::Arc;

use http::{Request, StatusCode};
use hyper::body::Incoming;
use toml_edit::{ArrayOfTables, DocumentMut, Item};
use tracing::info;

use crate::config::{RouteSection, load_routing_config};
use crate::http::control::config_edit::{json_error_owned, read_json, write_document_atomic};
use crate::http::control::server::ControlState;
use crate::http::control::{ControlResponse, json_error, json_response};

use super::payload::{
    CreateBody, DeleteBody, MutationResponse, ReorderBody, RoutePayload, UpdateBody,
    payload_to_table, route_revision, table_is_default,
};

const LABEL: &str = "/control/routes";

/// Read-only accessor to the `route` array (empty when absent).
fn route_array(doc: &DocumentMut) -> Option<&ArrayOfTables> {
    doc.get("route").and_then(Item::as_array_of_tables)
}

fn route_array_mut(doc: &mut DocumentMut) -> &mut ArrayOfTables {
    if doc.get("route").and_then(Item::as_array_of_tables).is_none() {
        doc.insert("route", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    doc["route"].as_array_of_tables_mut().expect("just ensured")
}

/// Names of every `[[uplink_group]]` declared on disk — the set `via` may
/// reference, mirroring what `load_config` would pass the validator.
pub(super) fn group_names_in_doc(doc: &DocumentMut) -> Vec<String> {
    let Some(groups) = doc.get("uplink_group").and_then(Item::as_array_of_tables) else {
        return Vec::new();
    };
    groups
        .iter()
        .filter_map(|t| t.get("name").and_then(|v| v.as_str()).map(str::to_string))
        .collect()
}

/// Index of the `default = true` rule, if any.
fn default_index(arr: &ArrayOfTables) -> Option<usize> {
    arr.iter().position(table_is_default)
}

pub(super) fn apply_create(
    doc: &mut DocumentMut,
    rule: &RoutePayload,
    at_index: Option<usize>,
) -> Result<usize, String> {
    let table = payload_to_table(rule);
    let arr = route_array_mut(doc);
    // Default insert position: just before the default rule (so it stays the
    // catch-all), or at the end when there is no default yet.
    let pos = match at_index {
        Some(i) if i <= arr.len() => i,
        Some(_) => return Err("at_index out of range".to_string()),
        None => default_index(arr).unwrap_or(arr.len()),
    };
    // ArrayOfTables has no insert-at; rebuild with the new table spliced in.
    let mut rebuilt = ArrayOfTables::new();
    for (i, t) in arr.iter().enumerate() {
        if i == pos {
            rebuilt.push(table.clone());
        }
        rebuilt.push(t.clone());
    }
    if pos >= arr.len() {
        rebuilt.push(table);
    }
    *arr = rebuilt;
    Ok(pos)
}

pub(super) fn apply_update(
    doc: &mut DocumentMut,
    index: usize,
    rule: &RoutePayload,
) -> Result<(), String> {
    let arr = route_array_mut(doc);
    let existing = arr.get(index).ok_or_else(|| "route index not found".to_string())?;
    let was_default = table_is_default(existing);
    let now_default = rule.default.unwrap_or(false);
    // The default rule is positional-catch-all and unique; the UI edits only
    // its via/fallback. Refuse structural changes to it here so a staged edit
    // can't produce a second default or a default with matchers.
    if was_default && !now_default {
        return Err("cannot clear `default` on the default rule".to_string());
    }
    if was_default
        && (rule.prefixes.is_some()
            || rule.file.is_some()
            || rule.files.is_some()
            || rule.domains.is_some()
            || rule.domain_file.is_some()
            || rule.domain_files.is_some())
    {
        return Err("the default rule must not set matchers".to_string());
    }
    let table = payload_to_table(rule);
    // Full replace (not merge): a field the drawer cleared must disappear.
    *arr.get_mut(index).expect("checked above") = table;
    Ok(())
}

pub(super) fn apply_delete(doc: &mut DocumentMut, index: usize) -> Result<(), String> {
    let arr = route_array_mut(doc);
    let target = arr.get(index).ok_or_else(|| "route index not found".to_string())?;
    if table_is_default(target) {
        return Err("cannot delete the `default` rule".to_string());
    }
    let mut rebuilt = ArrayOfTables::new();
    for (i, t) in arr.iter().enumerate() {
        if i != index {
            rebuilt.push(t.clone());
        }
    }
    *arr = rebuilt;
    Ok(())
}

pub(super) fn apply_reorder(doc: &mut DocumentMut, from: usize, to: usize) -> Result<(), String> {
    let arr = route_array_mut(doc);
    let len = arr.len();
    if from >= len || to >= len {
        return Err("reorder index not found".to_string());
    }
    let mut tables: Vec<_> = arr.iter().cloned().collect();
    let moved = tables.remove(from);
    tables.insert(to, moved);
    let mut rebuilt = ArrayOfTables::new();
    for t in tables {
        rebuilt.push(t);
    }
    *arr = rebuilt;
    Ok(())
}

/// Whole-list semantic validation: render the `route` array back to sections
/// and run the same validator the config loader uses. Guarantees a staged
/// config still boots (exactly one default, `via`→known group, invert⊕domains,
/// ≤1 fallback).
pub(super) fn validate_route_array(
    doc: &DocumentMut,
    group_names: &[&str],
    config_dir: &Path,
) -> anyhow::Result<()> {
    let Some(arr) = route_array(doc) else {
        return Ok(()); // no [[route]] section at all is valid (routing disabled)
    };
    #[derive(serde::Deserialize)]
    struct Wrapper {
        route: Vec<RouteSection>,
    }
    let mut wrap_doc = DocumentMut::new();
    let mut aot = ArrayOfTables::new();
    for t in arr.iter() {
        aot.push(t.clone());
    }
    wrap_doc.insert("route", Item::ArrayOfTables(aot));
    let sections = toml::from_str::<Wrapper>(&wrap_doc.to_string())
        .map_err(|e| anyhow::anyhow!("route rule is invalid: {e}"))?
        .route;
    load_routing_config(Some(&sections), group_names, config_dir)?;
    Ok(())
}

/// Method dispatch for `/control/routes`.
pub(crate) async fn handle_routes(
    request: Request<Incoming>,
    state: Arc<ControlState>,
) -> ControlResponse {
    match *request.method() {
        http::Method::GET => super::list::handle_list(state).await,
        http::Method::POST => mutate(request, state, MutateKind::Create).await,
        http::Method::PATCH => mutate(request, state, MutateKind::Update).await,
        http::Method::DELETE => mutate(request, state, MutateKind::Delete).await,
        _ => json_error(StatusCode::METHOD_NOT_ALLOWED, "use GET, POST, PATCH, or DELETE"),
    }
}

pub(crate) async fn handle_routes_reorder(
    request: Request<Incoming>,
    state: Arc<ControlState>,
) -> ControlResponse {
    if *request.method() != http::Method::POST {
        return json_error(StatusCode::METHOD_NOT_ALLOWED, "use POST");
    }
    mutate(request, state, MutateKind::Reorder).await
}

enum MutateKind {
    Create,
    Update,
    Delete,
    Reorder,
}

async fn mutate(
    request: Request<Incoming>,
    state: Arc<ControlState>,
    kind: MutateKind,
) -> ControlResponse {
    let Some(path) = state.config_path.clone() else {
        return json_error(StatusCode::CONFLICT, "config file path unknown; CRUD needs on-disk config");
    };
    let hot_apply_available = state.apply.is_some();
    let config_dir = path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();

    // Deserialize the kind-specific body.
    enum Parsed {
        Create(CreateBody),
        Update(UpdateBody),
        Delete(DeleteBody),
        Reorder(ReorderBody),
    }
    let parsed = match kind {
        MutateKind::Create => match read_json::<CreateBody>(request, LABEL).await {
            Ok(b) => Parsed::Create(b),
            Err(r) => return r,
        },
        MutateKind::Update => match read_json::<UpdateBody>(request, LABEL).await {
            Ok(b) => Parsed::Update(b),
            Err(r) => return r,
        },
        MutateKind::Delete => match read_json::<DeleteBody>(request, LABEL).await {
            Ok(b) => Parsed::Delete(b),
            Err(r) => return r,
        },
        MutateKind::Reorder => match read_json::<ReorderBody>(request, LABEL).await {
            Ok(b) => Parsed::Reorder(b),
            Err(r) => return r,
        },
    };
    let client_revision = match &parsed {
        Parsed::Create(b) => &b.revision,
        Parsed::Update(b) => &b.revision,
        Parsed::Delete(b) => &b.revision,
        Parsed::Reorder(b) => &b.revision,
    }
    .clone();

    let _guard = state.config_write_lock.lock().await;
    let raw = match tokio::fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(e) => return json_error_owned(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to read config: {e}")),
    };
    let mut doc = match raw.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(e) => return json_error_owned(StatusCode::INTERNAL_SERVER_ERROR, format!("config is not valid TOML: {e}")),
    };

    // Optimistic-concurrency check against the current on-disk array.
    let current_revision = route_array(&doc).map(route_revision).unwrap_or_default();
    if current_revision != client_revision {
        return json_error(StatusCode::CONFLICT, "config changed since it was read; reload and retry");
    }

    let (action, index) = match &parsed {
        Parsed::Create(b) => match apply_create(&mut doc, &b.rule, b.at_index) {
            Ok(i) => ("created", i),
            Err(msg) => return json_error_owned(StatusCode::BAD_REQUEST, msg),
        },
        Parsed::Update(b) => match apply_update(&mut doc, b.index, &b.rule) {
            Ok(()) => ("updated", b.index),
            Err(msg) => return json_error_owned(status_for(&msg), msg),
        },
        Parsed::Delete(b) => match apply_delete(&mut doc, b.index) {
            Ok(()) => ("deleted", b.index),
            Err(msg) => return json_error_owned(status_for(&msg), msg),
        },
        Parsed::Reorder(b) => match apply_reorder(&mut doc, b.from, b.to) {
            Ok(()) => ("reordered", b.to),
            Err(msg) => return json_error_owned(status_for(&msg), msg),
        },
    };

    // Whole-list validation before writing: never stage a config that won't boot.
    let groups = group_names_in_doc(&doc);
    let group_refs: Vec<&str> = groups.iter().map(String::as_str).collect();
    if let Err(e) = validate_route_array(&doc, &group_refs, &config_dir) {
        return json_error_owned(StatusCode::BAD_REQUEST, format!("{e:#}"));
    }

    if let Err(e) = write_document_atomic(&path, &doc).await {
        return json_error_owned(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"));
    }

    let new_revision = route_array(&doc).map(route_revision).unwrap_or_default();
    info!(action, index, "route staged");
    json_response(
        StatusCode::ACCEPTED,
        &MutationResponse::staged(action, index, hot_apply_available, new_revision),
    )
}

/// Route index/range errors map to 404; everything else (business rules like
/// "cannot delete the default rule") to 400.
fn status_for(msg: &str) -> StatusCode {
    if msg.contains("not found") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::BAD_REQUEST
    }
}

#[cfg(test)]
#[path = "tests/mutate.rs"]
mod tests;
```

This listing IS the complete `mutate.rs` in one piece: the helpers (`route_array`,
`route_array_mut`, `group_names_in_doc`, `default_index`, `apply_create` /
`apply_update` / `apply_delete` / `apply_reorder`, `validate_route_array`), the
dispatcher (`handle_routes` / `handle_routes_reorder`), the `MutateKind` enum,
the single `mutate` HTTP flow, and `status_for`. There is no stub and no second
`mutate`. `LABEL` is `const LABEL: &str = "/control/routes";` declared in the
imports block near the top of the file (shown earlier in this step).

- [ ] **Step 4: Написать `list.rs`**

Create `bins/outline-ws-rust/src/http/control/routes_crud/list.rs`:

```rust
//! `GET /control/routes` — reads the on-disk `[[route]]` array (staged state),
//! indexes each rule, and reports the declared group names for the `via`
//! picker. There is no live routing snapshot to read, so this reflects the
//! config file, which is exactly what the editor needs.

use std::sync::Arc;

use http::StatusCode;
use toml_edit::{DocumentMut, Item};

use crate::http::control::config_edit::json_error_owned;
use crate::http::control::server::ControlState;
use crate::http::control::{ControlResponse, json_error, json_response};

use super::mutate::group_names_in_doc;
use super::payload::{
    RouteListEntry, RoutesListResponse, route_revision, route_table_to_json, table_is_default,
};

pub(super) async fn handle_list(state: Arc<ControlState>) -> ControlResponse {
    let Some(path) = state.config_path.clone() else {
        return json_error(StatusCode::CONFLICT, "config file path unknown");
    };
    let raw = match tokio::fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(e) => return json_error_owned(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to read config: {e}")),
    };
    let doc = match raw.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(e) => return json_error_owned(StatusCode::INTERNAL_SERVER_ERROR, format!("config is not valid TOML: {e}")),
    };
    let arr = doc.get("route").and_then(Item::as_array_of_tables);
    let routes = arr
        .map(|a| {
            a.iter()
                .enumerate()
                .map(|(index, t)| RouteListEntry {
                    index,
                    is_default: table_is_default(t),
                    config: route_table_to_json(t),
                })
                .collect()
        })
        .unwrap_or_default();
    let revision = arr.map(route_revision).unwrap_or_default();
    json_response(
        StatusCode::OK,
        &RoutesListResponse { routes, groups: group_names_in_doc(&doc), revision },
    )
}
```

Update `routes_crud/mod.rs` to the final module set:

```rust
mod list;
mod mutate;
mod payload;

pub(crate) use mutate::{handle_routes, handle_routes_reorder};
```

Notes on `mod.rs`:
- Do NOT re-attach the payload tests here. Task 5 attached them from
  `payload.rs` itself (the `#[cfg(test)] #[path = "tests/payload.rs"] mod tests;`
  lives in `payload.rs`). The mutate tests are likewise attached from the end of
  the `mutate.rs` listing above. So `mod.rs` declares only the three submodules
  plus the `handle_routes` / `handle_routes_reorder` re-export — attaching a test
  path here too would double-include the same file and fail to compile.
- Remove the temporary `#![allow(dead_code)]` Task 5 put at the top of `mod.rs`:
  every payload helper now has a real consumer in `mutate.rs` / `list.rs`.

- [ ] **Step 5: Прогнать — mutate + payload тесты зелёные**

Run: `cargo test -p outline-ws-rust routes_crud`
Expected: PASS — payload tests (Task 5) and the five mutate unit tests.

- [ ] **Step 6: Гейт + commit**

```bash
cargo fmt --check -p outline-ws-rust && cargo clippy -p outline-ws-rust --all-targets --no-deps -- -D warnings && cargo test -p outline-ws-rust routes_crud
```
```bash
git add bins/outline-ws-rust/src/http/control/routes_crud/
git commit -m "feat(control): routes_crud CRUD + reorder + revision guard"
```

---

### Task 7: Подключить `/control/routes` в диспетчер control-сервера

Проводка нового endpoint в `handle_request`: путь-лейблы + dispatch-арки для
`/control/routes` (full `ControlState`, как uplinks) и `/control/routes/reorder`.

**Files:**
- Modify: `bins/outline-ws-rust/src/http/control/server.rs:25,127-137,144-202`

**Interfaces:**
- Consumes: `routes_crud::{handle_routes, handle_routes_reorder}` (Task 6).

- [ ] **Step 1: Импорт**

In `server.rs`, next to `use super::uplinks_crud::handle_uplinks;` (line 25):

```rust
use super::routes_crud::{handle_routes, handle_routes_reorder};
```

- [ ] **Step 2: Path labels**

In the `label_path` match (lines 127-137), add after the `/control/uplinks`
arm:

```rust
        "/control/routes" => "/control/routes",
        "/control/routes/reorder" => "/control/routes/reorder",
```

- [ ] **Step 3: Dispatch arms**

In the dispatch `match label_path` (lines 144-202), add after the
`/control/uplinks` arm (mirrors it — routes CRUD needs full `ControlState`):

```rust
        "/control/routes" => {
            let response = handle_routes(request, Arc::clone(&state)).await;
            record_metrics_http_request("/control/routes", response.status().as_u16());
            response
        },
        "/control/routes/reorder" => {
            let response = handle_routes_reorder(request, Arc::clone(&state)).await;
            record_metrics_http_request("/control/routes/reorder", response.status().as_u16());
            response
        },
```

- [ ] **Step 3b: Снять временные `allow`, добавленные в Task 6**

Wiring the two arms above makes `handle_routes` / `handle_routes_reorder`
reachable from non-test code, so the dead-code bridges Task 6 added are now stale.
Remove both:
- In `bins/outline-ws-rust/src/http/control/routes_crud/mutate.rs`: the
  `#[allow(dead_code)]` (with its `TODO(task-7)` comment) on `handle_routes` and
  `handle_routes_reorder`.
- In `bins/outline-ws-rust/src/http/control/routes_crud/mod.rs`: the
  `#[allow(unused_imports)]` (with its `TODO(task-7)` comment) on the
  `pub(crate) use mutate::{handle_routes, handle_routes_reorder};` line.

The full-crate clippy `-D warnings` in Step 5 confirms nothing else still reads as
dead code once these come off (if it flags a remaining unreachable helper, that's
a real wiring gap to chase, not a reason to re-add the blanket allow).

- [ ] **Step 4: Smoke-тест вручную (endpoint отвечает под авторизацией)**

Build and run against a throwaway config, then verify auth + a GET:

```bash
cargo build -p outline-ws-rust --features control
```

Create `/tmp/routes-smoke.toml` with one group + a `[[route]]` default, run the
binary with `--control-listen 127.0.0.1:19191` and a known token, then:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:19191/control/routes         # 401 (no token)
curl -s -H "Authorization: Bearer <token>" http://127.0.0.1:19191/control/routes        # 200 {"routes":[...],"groups":["main"],"revision":"..."}
```
Expected: `401` without the bearer token, `200` with it and a JSON body listing
the default rule.

- [ ] **Step 5: Гейт + commit**

```bash
cargo fmt --check -p outline-ws-rust && cargo clippy -p outline-ws-rust --all-targets --no-deps -- -D warnings && cargo test -p outline-ws-rust
```
```bash
git add bins/outline-ws-rust/src/http/control/server.rs \
  bins/outline-ws-rust/src/http/control/routes_crud/mutate.rs \
  bins/outline-ws-rust/src/http/control/routes_crud/mod.rs
git commit -m "feat(control): dispatch /control/routes and /reorder"
```

---

### Task 8: Hot-apply routing в `/control/apply`

`/control/apply` пересобирает `RoutingTable` из перечитанного config и атомарно
подменяет её в общей обёртке; file-watchers пересоздаются на новой таблице.
Требует, чтобы routing был сконфижен при старте (обёртка присутствует) — иначе
первое включение routing остаётся restart-only (краевой случай, отражается в
ответе).

**Files:**
- Modify: `bins/outline-ws-rust/src/http/control/apply.rs:8-12,33-51,53-114`
- Modify: `bins/outline-ws-rust/src/bootstrap/mod.rs:153-163,245-263`
- Test: `bins/outline-ws-rust/src/http/control/tests/apply_routing.rs`

**Interfaces:**
- Consumes: `SharedRoutingTable` (Task 1), `RouteWatchersGuard`,
  `spawn_route_watchers`, `RoutingTable::compile`.
- Produces:
  - `ApplyHandle` gains `shared_routing: Option<Arc<SharedRoutingTable>>` and
    `route_watchers: Arc<tokio::sync::Mutex<Option<RouteWatchersGuard>>>`.
  - `pub(super) async fn rebuild_routing(shared: &SharedRoutingTable, cfg: &RoutingTableConfig, watchers: &tokio::sync::Mutex<Option<RouteWatchersGuard>>) -> anyhow::Result<usize>`

- [ ] **Step 1: Написать падающий тест на пересборку**

Create `bins/outline-ws-rust/src/http/control/tests/apply_routing.rs` (attach via
`#[cfg(test)] #[path = "tests/apply_routing.rs"] mod tests;` at the bottom of
`apply.rs` if no test module is attached there yet):

```rust
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use outline_routing::config::{RouteRule, RouteTarget, RoutingTableConfig};
use outline_routing::{RoutingTable, SharedRoutingTable};
use socks5_proto::TargetAddr;
use tokio::sync::Mutex;

use super::rebuild_routing;

fn cfg(default: RouteTarget) -> RoutingTableConfig {
    RoutingTableConfig { rules: vec![], default_target: default, default_fallback: None }
}

fn cfg_direct_10() -> RoutingTableConfig {
    RoutingTableConfig {
        rules: vec![RouteRule {
            inline_prefixes: vec!["10.0.0.0/8".to_string()],
            files: vec![],
            inline_domains: vec![],
            domain_files: vec![],
            file_poll: Duration::from_secs(60),
            target: RouteTarget::Direct,
            fallback: None,
            invert: false,
        }],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: None,
    }
}

#[tokio::test]
async fn rebuild_swaps_the_live_table() {
    let shared = SharedRoutingTable::new(RoutingTable::compile(&cfg(RouteTarget::Drop)).await.unwrap());
    let watchers = Mutex::new(None);
    // TargetAddr has no FromStr — construct it directly (see tests/table.rs).
    let ip = TargetAddr::IpV4(Ipv4Addr::new(10, 1, 2, 3), 443);
    assert_eq!(shared.resolve(&ip).primary, RouteTarget::Drop);

    let count = rebuild_routing(&shared, &cfg_direct_10(), &watchers).await.unwrap();
    assert_eq!(count, 1, "one non-default rule");
    assert_eq!(shared.resolve(&ip).primary, RouteTarget::Direct, "new table is live");
    assert!(shared.version() >= 1, "version advanced");
}
```

- [ ] **Step 2: Прогнать — не компилируется**

Run: `cargo test -p outline-ws-rust apply_routing`
Expected: FAIL — `rebuild_routing` doesn't exist; `ApplyHandle` has no routing
fields.

- [ ] **Step 3: `rebuild_routing` + `ApplyHandle` поля**

In `apply.rs`, extend the struct (lines 33-43):

```rust
pub struct ApplyHandle {
    pub config_path: PathBuf,
    pub args: Args,
    pub dns_cache: Arc<outline_transport::DnsCache>,
    pub state_store: Option<Arc<outline_uplink::StateStore>>,
    pub registry: UplinkRegistry,
    /// Present when `[[route]]` was configured at startup; `None` means routing
    /// changes are restart-only (first-time enable can't hot-swap into a table
    /// that never existed).
    pub shared_routing: Option<Arc<outline_routing::SharedRoutingTable>>,
    /// The live per-rule file watchers. Replaced on every routing apply so a
    /// new table's files get watched and the old table's watchers stop.
    pub route_watchers: Arc<tokio::sync::Mutex<Option<outline_routing::RouteWatchersGuard>>>,
    pub lock: Mutex<()>,
}
```

Add the routing rebuild helper (place above `handle_apply`):

```rust
/// Compile `cfg` into a fresh table, publish it into `shared` (preserving the
/// version counter), and respawn the file watchers on the new table. Returns
/// the non-default rule count for the response. On compile error the live
/// table is left untouched.
pub(super) async fn rebuild_routing(
    shared: &outline_routing::SharedRoutingTable,
    cfg: &outline_routing::config::RoutingTableConfig,
    watchers: &tokio::sync::Mutex<Option<outline_routing::RouteWatchersGuard>>,
) -> anyhow::Result<usize> {
    let table = outline_routing::RoutingTable::compile(cfg)
        .await
        .context("failed to compile routing table")?;
    let rule_count = cfg.rules.len();
    // Stop the OLD table's file watchers BEFORE the swap. Those watchers bump
    // the old table's `version` on mtime change, and `swap_preserving_version`
    // reads that version (non-atomically) to seed the new table's. If a watcher
    // bumped it in the read→store window, the new table could be stamped with a
    // version a per-association cache already holds — the cache would then look
    // current and skip re-resolution against the new table. Dropping the guard
    // here makes the seed read stable. `/control/apply` is serialized by its own
    // mutex, so no second apply races this; the watcher is the only other writer.
    let mut slot = watchers.lock().await;
    *slot = None; // drop old guard → old watchers stop bumping the old version
    let new_arc = shared.swap_preserving_version(table);
    *slot = Some(outline_routing::spawn_route_watchers(new_arc));
    Ok(rule_count)
}
```

Add `use anyhow::Context;` if not already imported at the top of `apply.rs`.
Also (Task 1 review Minor #2 carry-forward): update the doc comment on
`RoutingTable.version` at `crates/outline-routing/src/table.rs:54-58` — it now
has a second bumping path (`SharedRoutingTable::swap_preserving_version`), not
only `spawn_route_watchers`. Add one line noting the swap path.

- [ ] **Step 4: Вызвать из `handle_apply` + расширить ответ**

In `handle_apply`, after the `apply_new_groups` block (around line 98) and
before reading back the group summary, add:

```rust
    // Hot-apply routing when it was configured at startup. The reloaded
    // `new_config.routing` is already in scope.
    let routes_applied = match (&handle.shared_routing, &new_config.routing) {
        (Some(shared), Some(routing_cfg)) => {
            match rebuild_routing(shared, routing_cfg, &handle.route_watchers).await {
                Ok(n) => Some(n),
                Err(e) => {
                    return json_error_owned(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("routing apply failed: {e:#}"),
                    );
                },
            }
        },
        // routing not configured at startup, or removed from config → nothing
        // to hot-swap (first-time enable / full disable stays restart-only).
        _ => None,
    };
```

Extend `ApplyResponse` (lines 45-51) with:

```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    routes_applied: Option<usize>,
```

and set it in the returned struct (lines 105-113): `routes_applied,`.

Update the docstring (lines 8-12): remove `routing` from the "requires a full
restart" list and note it is now hot-applied when configured at startup.

- [ ] **Step 5: Wiring в bootstrap**

In `bootstrap/mod.rs`, turn the `_route_watchers` guard (Task 2, lines 153-163)
into a shared slot so `ApplyHandle` can replace it while `run_with_config` keeps
it alive:

```rust
    let route_watchers = Arc::new(tokio::sync::Mutex::new(
        // Seeded below when routing is configured.
        None::<outline_routing::RouteWatchersGuard>,
    ));
    let shared_routing = if let Some(routing_cfg) = config.routing.clone() {
        let table = outline_routing::RoutingTable::compile(&routing_cfg)
            .await
            .context("failed to compile routing table")?;
        let shared = outline_routing::SharedRoutingTable::new(table);
        *route_watchers.lock().await = Some(outline_routing::spawn_route_watchers(shared.load_full()));
        Some(shared)
    } else {
        None
    };
    // Keep the watcher slot alive for the whole process; ApplyHandle holds a
    // clone and swaps its contents on each routing apply.
    let _route_watchers_holder = Arc::clone(&route_watchers);
```

Pass both into `ApplyHandle` (lines 247-256):

```rust
        let apply = control.config_path.clone().map(|path| {
            Arc::new(ApplyHandle {
                config_path: path,
                args: args.clone(),
                dns_cache: Arc::clone(&dns_cache),
                state_store: state_store_for_apply.clone(),
                registry: registry.clone(),
                shared_routing: shared_routing.clone(),
                route_watchers: Arc::clone(&route_watchers),
                lock: tokio::sync::Mutex::new(()),
            })
        });
```

The earlier `let (shared_routing, _route_watchers) = …` block from Task 2 is
replaced by this one — there is now a single routing-init site. TUN and
`ProxyConfig.router` still read `shared_routing.clone()` exactly as Task 2 wired
them.

- [ ] **Step 6: Прогнать — rebuild тест зелёный + весь suite**

Run: `cargo test -p outline-ws-rust apply_routing`
Expected: PASS — `rebuild_swaps_the_live_table`.

- [ ] **Step 7: Полный гейт + commit**

```bash
cargo fmt --check -p outline-ws-rust && cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings && cargo test --workspace --exclude sockudo-ws
```
```bash
git add bins/outline-ws-rust/src/http/control/apply.rs bins/outline-ws-rust/src/bootstrap/mod.rs
git commit -m "feat(control): hot-apply routing table on /control/apply"
```

---

### Task 9: Прокси `/ws/dashboard/api/routes` в `outline-ui`

Passthrough к `/control/routes` и `/control/routes/reorder`, клон
`uplinks_proxy`. Токен узла инъектится серверно; `backend.rs` не меняется.

**Files:**
- Modify: `bins/outline-ui/src/ws/api.rs` (add `routes_proxy`, `routes_reorder_proxy`)
- Modify: `bins/outline-ui/src/ws/mod.rs` (routes)
- Test: `bins/outline-ui/src/ws/tests/mod.rs` (add a routes proxy case mirroring the uplinks one)

**Interfaces:**
- Produces: handlers `routes_proxy`, `routes_reorder_proxy`.

- [ ] **Step 1: Хендлеры**

In `bins/outline-ui/src/ws/api.rs`, add after `uplinks_proxy` (line 378). The
GET/mutation passthrough is identical to `uplinks_proxy` but targets
`/control/routes`; factor the shared body out or copy the shape. Minimal copy:

```rust
/// `GET|POST|PATCH|DELETE /dashboard/api/routes` — CRUD passthrough to
/// `/control/routes`. GET carries `instance` in the query; mutating methods
/// carry an `{instance, body}` envelope, same as uplinks.
pub async fn routes_proxy(
    State(state): State<WsState>,
    method: Method,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    proxy_crud(&state, method, query, body, "/control/routes").await
}

/// `POST /dashboard/api/routes/reorder` — `{instance, body}` envelope to
/// `/control/routes/reorder`.
pub async fn routes_reorder_proxy(State(state): State<WsState>, body: Bytes) -> Response {
    proxy_envelope_post(&state, body, "/control/routes/reorder").await
}
```

Extract the generic passthrough from `uplinks_proxy`'s body into two helpers
(so uplinks and routes share one implementation):

```rust
/// Shared CRUD passthrough: GET forwards `instance`+filters as query; the
/// mutating methods carry an `{instance, body}` envelope. Verbatim behaviour of
/// the original `uplinks_proxy`, parameterized by the control `path`.
async fn proxy_crud(
    state: &WsState,
    method: Method,
    query: Option<String>,
    body: Bytes,
    path: &str,
) -> Response {
    // ... body moved verbatim from uplinks_proxy (ws/api.rs:322-377), with the
    // literal "/control/uplinks" replaced by the `path` argument ...
}

/// Shared `{instance}`-or-`{instance, body}` POST passthrough.
async fn proxy_envelope_post(state: &WsState, body: Bytes, path: &str) -> Response {
    // ... same envelope parsing as apply_proxy (ws/api.rs:382-409), POSTing the
    // inner `body` to `path` ...
}
```

Then rewrite `uplinks_proxy` as `proxy_crud(&state, method, query, body, "/control/uplinks").await`
to prove the extraction is behaviour-preserving.

- [ ] **Step 2: Роуты**

In `bins/outline-ui/src/ws/mod.rs::router` (lines 20-37), add before
`.fallback(...)`:

```rust
        .route(
            "/dashboard/api/routes",
            get(api::routes_proxy)
                .post(api::routes_proxy)
                .patch(api::routes_proxy)
                .delete(api::routes_proxy),
        )
        .route("/dashboard/api/routes/reorder", post(api::routes_reorder_proxy))
```

- [ ] **Step 3: Тест прокси**

In `bins/outline-ui/src/ws/tests/mod.rs`, add a test mirroring the existing
uplinks-proxy test: a mock instance control server that records the path/method,
a GET `/ws/dashboard/api/routes?instance=X` asserting it hit `/control/routes`
with the injected bearer token, and a POST envelope asserting the inner body is
forwarded. (Copy the uplinks-proxy test harness in that file, swap the path.)

```rust
#[tokio::test]
async fn routes_proxy_forwards_get_with_token() {
    // mirror uplinks_proxy_forwards_get_with_token: mock control server,
    // assert method GET, path "/control/routes", Authorization: Bearer <token>.
}
```

- [ ] **Step 4: Прогнать**

Run: `cargo test -p outline-ui routes`
Expected: PASS.

- [ ] **Step 5: Гейт + commit**

```bash
cargo fmt --check -p outline-ui && cargo clippy -p outline-ui --all-targets --no-deps -- -D warnings && cargo test -p outline-ui
```
```bash
git add bins/outline-ui/src/ws/
git commit -m "feat(ui): proxy /ws/dashboard/api/routes to control API"
```

---

### Task 10: Фронт-типы + API-обёртки

**Files:**
- Modify: `bins/outline-ui/frontend/src/lib/types.ts`
- Modify: `bins/outline-ui/frontend/src/lib/api.ts`

**Interfaces:**
- Produces: `RouteConfig`, `RouteEntry`, `RoutesListResponse`; `routesList`,
  `routesMutate`, `routesReorder`.

- [ ] **Step 1: Типы**

Append to `bins/outline-ui/frontend/src/lib/types.ts`:

```ts
// WS routing — GET /control/routes entries, proxied verbatim through
// /ws/dashboard/api/routes (routes_crud/list.rs RouteListEntry/RoutesListResponse).
// `config` mirrors the on-disk `[[route]]` table (route_table_to_json), absent
// when the config couldn't be read.
export interface RouteConfig {
  prefixes?: string[];
  file?: string;
  files?: string[];
  domains?: string[];
  domain_file?: string;
  domain_files?: string[];
  file_poll_secs?: number;
  default?: boolean;
  via?: string;
  fallback_via?: string;
  fallback_direct?: boolean;
  fallback_drop?: boolean;
  invert?: boolean;
  [k: string]: unknown;
}
export interface RouteEntry {
  index: number;
  is_default: boolean;
  config?: RouteConfig | null;
}
export interface RoutesListResponse {
  routes: RouteEntry[];
  groups: string[];
  revision: string;
}
// POST/PATCH/DELETE /control/routes response (routes_crud MutationResponse).
export interface RouteMutationResponse {
  action: string;
  index: number;
  apply_required?: boolean;
  restart_required?: boolean;
  revision: string;
}
```

- [ ] **Step 2: API-обёртки**

Append to `bins/outline-ui/frontend/src/lib/api.ts` (after the uplinks block,
line 63), importing the new types at the top:

```ts
// WS routing CRUD — proxied to /control/routes (ws/api.rs routes_proxy). GET
// carries `instance`; POST/PATCH/DELETE carry an {instance, body} envelope;
// reorder is its own POST endpoint. `body` always includes the `revision`
// last read, so a concurrent edit is rejected 409 instead of moving the wrong
// rule (routes_crud mutate revision-guard).
export const routesList = (i: string) =>
  json<RoutesListResponse>(`/ws/dashboard/api/routes?${q(i)}`);
export const routesMutate = (method: 'POST' | 'PATCH' | 'DELETE', i: string, body: unknown) =>
  json<RouteMutationResponse>(`/ws/dashboard/api/routes`, mutate(method, { instance: i, body }));
export const routesReorder = (i: string, body: unknown) =>
  json<RouteMutationResponse>(`/ws/dashboard/api/routes/reorder`, mutate('POST', { instance: i, body }));
```

Add `RoutesListResponse, RouteMutationResponse` to the `import type { … }` block
at the top of `api.ts`.

- [ ] **Step 3: Проверка типов + commit**

```bash
cd bins/outline-ui/frontend && pnpm run check
```
Expected: no type errors.
```bash
git add bins/outline-ui/frontend/src/lib/types.ts bins/outline-ui/frontend/src/lib/api.ts
git commit -m "feat(ui): routing types + api wrappers"
```

---

### Task 11: `routeForm.ts` — framework-free форм-логика + тесты

Сборка/валидация payload вне Svelte, unit-тестируемо (как `uplinkForm.ts`).

**Files:**
- Create: `bins/outline-ui/frontend/src/lib/routeForm.ts`
- Create: `bins/outline-ui/frontend/src/lib/routeForm.test.ts`

**Interfaces:**
- Produces: `RouteFormFields`, `emptyRouteFields`, `fieldsFromConfig`,
  `validateRouteForm`, `buildRoutePayload`, `TARGET_KINDS`.

- [ ] **Step 1: Написать падающие тесты**

Create `bins/outline-ui/frontend/src/lib/routeForm.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import {
  emptyRouteFields,
  fieldsFromConfig,
  validateRouteForm,
  buildRoutePayload,
} from './routeForm';
import type { RouteConfig } from './types';

describe('validateRouteForm', () => {
  it('non-default rule requires via', () => {
    const f = { ...emptyRouteFields(), prefixes: '10.0.0.0/8' };
    expect(validateRouteForm({ ...f, via: '' })).toMatch(/via/);
  });
  it('non-default rule requires at least one matcher', () => {
    const f = { ...emptyRouteFields(), via: 'main' };
    expect(validateRouteForm(f)).toMatch(/matcher|prefix|domain/i);
  });
  it('default rule needs no matcher', () => {
    const f = { ...emptyRouteFields(), isDefault: true, via: 'main' };
    expect(validateRouteForm(f)).toBeNull();
  });
  it('invert with domains is rejected client-side', () => {
    const f = { ...emptyRouteFields(), prefixes: '10.0.0.0/8', domains: 'x.example', via: 'drop', invert: true };
    expect(validateRouteForm(f)).toMatch(/invert/i);
  });
});

describe('buildRoutePayload', () => {
  it('splits textarea lines into arrays, drops blanks', () => {
    const f = { ...emptyRouteFields(), prefixes: '10.0.0.0/8\n\n192.168.0.0/16 ', via: 'direct' };
    expect(buildRoutePayload(f)).toEqual({ prefixes: ['10.0.0.0/8', '192.168.0.0/16'], via: 'direct' });
  });
  it('default rule omits matchers', () => {
    const f = { ...emptyRouteFields(), isDefault: true, via: 'main', prefixes: 'ignored' };
    expect(buildRoutePayload(f)).toEqual({ default: true, via: 'main' });
  });
  it('encodes fallback kind', () => {
    const f = { ...emptyRouteFields(), prefixes: '1.2.3.0/24', via: 'main', fallbackKind: 'direct' as const };
    expect(buildRoutePayload(f)).toEqual({ prefixes: ['1.2.3.0/24'], via: 'main', fallback_direct: true });
  });
  it('round-trips a config through fieldsFromConfig', () => {
    const cfg: RouteConfig = { prefixes: ['10.0.0.0/8'], via: 'direct', invert: false };
    expect(buildRoutePayload(fieldsFromConfig(cfg))).toEqual({ prefixes: ['10.0.0.0/8'], via: 'direct' });
  });
});
```

- [ ] **Step 2: Прогнать — падает**

Run: `cd bins/outline-ui/frontend && pnpm test routeForm`
Expected: FAIL — module not found.

- [ ] **Step 3: Написать `routeForm.ts`**

Create `bins/outline-ui/frontend/src/lib/routeForm.ts`:

```ts
import type { RouteConfig } from './types';

// Target kinds for the `via` picker beyond the concrete group names the server
// reports: the two reserved words a rule can also target.
export const TARGET_KINDS = ['direct', 'drop'] as const;

export type FallbackKind = '' | 'direct' | 'drop' | 'via';

// Plain-string form state (textareas for the list fields), framework-free so
// payload-building is unit-testable without mounting Svelte. Mirrors the
// server's RoutePayload (routes_crud/payload.rs).
export interface RouteFormFields {
  isDefault: boolean;
  // One entry per line; blanks ignored.
  prefixes: string;
  files: string;
  domains: string;
  domainFiles: string;
  filePollSecs: number | null;
  invert: boolean;
  // Group name, or a reserved 'direct' / 'drop'.
  via: string;
  fallbackKind: FallbackKind;
  fallbackVia: string;
}

export function emptyRouteFields(): RouteFormFields {
  return {
    isDefault: false,
    prefixes: '',
    files: '',
    domains: '',
    domainFiles: '',
    filePollSecs: null,
    invert: false,
    via: '',
    fallbackKind: '',
    fallbackVia: '',
  };
}

const lines = (s: string): string[] =>
  s.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);

const asText = (v: unknown): string => (Array.isArray(v) ? (v as string[]).join('\n') : '');

export function fieldsFromConfig(config: RouteConfig | null | undefined): RouteFormFields {
  const c = config ?? {};
  let fallbackKind: FallbackKind = '';
  if (c.fallback_direct) fallbackKind = 'direct';
  else if (c.fallback_drop) fallbackKind = 'drop';
  else if (typeof c.fallback_via === 'string') fallbackKind = 'via';
  // A single `file`/`domain_file` folds into the multi-line textarea alongside
  // the list form — both render as one entry per line on save.
  const prefixText = asText(c.prefixes);
  const fileText = [c.file, ...(c.files ?? [])].filter((x): x is string => !!x).join('\n');
  const domText = asText(c.domains);
  const domFileText = [c.domain_file, ...(c.domain_files ?? [])].filter((x): x is string => !!x).join('\n');
  return {
    isDefault: c.default === true,
    prefixes: prefixText,
    files: fileText,
    domains: domText,
    domainFiles: domFileText,
    filePollSecs: typeof c.file_poll_secs === 'number' ? c.file_poll_secs : null,
    invert: c.invert === true,
    via: typeof c.via === 'string' ? c.via : '',
    fallbackKind,
    fallbackVia: typeof c.fallback_via === 'string' ? c.fallback_via : '',
  };
}

export function validateRouteForm(f: RouteFormFields): string | null {
  if (!f.via.trim()) return 'via is required';
  if (f.isDefault) return null; // default rule: via only, no matchers
  const hasMatcher =
    lines(f.prefixes).length > 0 ||
    lines(f.files).length > 0 ||
    lines(f.domains).length > 0 ||
    lines(f.domainFiles).length > 0;
  if (!hasMatcher) return 'a non-default rule needs at least one prefix/file/domain matcher';
  if (f.invert && (lines(f.domains).length > 0 || lines(f.domainFiles).length > 0)) {
    return 'invert applies to CIDR prefixes only — it cannot combine with domains';
  }
  if (f.fallbackKind === 'via' && !f.fallbackVia.trim()) return 'fallback group is required';
  return null;
}

export function buildRoutePayload(f: RouteFormFields): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (f.isDefault) {
    out.default = true;
    out.via = f.via.trim();
    return applyFallback(out, f);
  }
  const prefixes = lines(f.prefixes);
  const files = lines(f.files);
  const domains = lines(f.domains);
  const domainFiles = lines(f.domainFiles);
  if (prefixes.length) out.prefixes = prefixes;
  if (files.length) out.files = files;
  if (domains.length) out.domains = domains;
  if (domainFiles.length) out.domain_files = domainFiles;
  if (f.filePollSecs !== null) out.file_poll_secs = Math.trunc(f.filePollSecs);
  if (f.invert) out.invert = true;
  out.via = f.via.trim();
  return applyFallback(out, f);
}

function applyFallback(out: Record<string, unknown>, f: RouteFormFields): Record<string, unknown> {
  if (f.fallbackKind === 'direct') out.fallback_direct = true;
  else if (f.fallbackKind === 'drop') out.fallback_drop = true;
  else if (f.fallbackKind === 'via' && f.fallbackVia.trim()) out.fallback_via = f.fallbackVia.trim();
  return out;
}
```

- [ ] **Step 4: Прогнать — зелёные**

Run: `cd bins/outline-ui/frontend && pnpm test routeForm`
Expected: PASS — all form tests.

- [ ] **Step 5: Commit**

```bash
cd bins/outline-ui/frontend && pnpm test routeForm && pnpm run check
```
```bash
git add bins/outline-ui/frontend/src/lib/routeForm.ts bins/outline-ui/frontend/src/lib/routeForm.test.ts
git commit -m "feat(ui): framework-free route form logic + tests"
```

---

### Task 12: Вкладка `Routing.svelte` + `RouteDrawer.svelte` + навигация

Вкладка правил с reorder ↑/↓, add/edit/delete, drawer формы и apply-баром.
Порядок правят стрелки; drawer вставляет новое правило перед `default`.

**Files:**
- Create: `bins/outline-ui/frontend/src/features/ws/Routing.svelte`
- Create: `bins/outline-ui/frontend/src/features/ws/RouteDrawer.svelte`
- Modify: `bins/outline-ui/frontend/src/components/layout/Sidebar.svelte`
- Modify: `bins/outline-ui/frontend/src/App.svelte`

**Interfaces:**
- Consumes: `routesList`, `routesMutate`, `routesReorder`, `apply` (api.ts);
  `routeForm.ts`; `RouteEntry`/`RoutesListResponse` (types.ts).

- [ ] **Step 1: Навигация — Sidebar**

In `components/layout/Sidebar.svelte`, add a `routingActive` derived and a
navlink. Update `topologyActive` so it's off on the routing route:

```svelte
  const uplinksActive = $derived(route.path.startsWith('/ws/uplinks'));
  const routingActive = $derived(route.path.startsWith('/ws/routing'));
  const topologyActive = $derived(current === 'ws' && !uplinksActive && !routingActive);
```

Add the navlink after the Uplinks one (line 62):

```svelte
  <div
    class="navlink"
    class:active={routingActive}
    role="button"
    tabindex="0"
    onclick={() => go('/ws/routing')}
    onkeydown={(e) => onKey(e, '/ws/routing')}
  >
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg>
    Routing
  </div>
```

- [ ] **Step 2: App.svelte — маршрут**

In `App.svelte`, add the import and route branch:

```svelte
  import Routing from './features/ws/Routing.svelte';
  // ...
  const isUplinks = $derived(route.path.startsWith('/ws/uplinks'));
  const isRouting = $derived(route.path.startsWith('/ws/routing'));
```

In the `{#if}` chain, add before the Topology fallback:

```svelte
    {:else if isRouting}
      <Routing />
    {:else if isUplinks}
      <Uplinks />
```

- [ ] **Step 3: `Routing.svelte`**

Create `bins/outline-ui/frontend/src/features/ws/Routing.svelte`:

```svelte
<script lang="ts">
  import { onDestroy } from 'svelte';
  import { SvelteSet } from 'svelte/reactivity';
  import { routesList, routesMutate, routesReorder, apply } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { toast } from '../../lib/toast.svelte';
  import type { RouteEntry, RoutesListResponse, RouteConfig, ApplyResult } from '../../lib/types';
  import { buildRoutePayload, type RouteFormFields } from '../../lib/routeForm';
  import InstanceSelector from '../../components/layout/InstanceSelector.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';
  import RouteDrawer from './RouteDrawer.svelte';

  let instance = $state('');
  let refreshSecs = $state(5);
  const refreshMs = $derived(Math.max(1000, refreshSecs * 1000));

  const routesPoll = createPoll<RoutesListResponse>(
    () => (instance ? routesList(instance) : Promise.resolve<RoutesListResponse>({ routes: [], groups: [], revision: '' })),
    () => refreshMs,
  );
  $effect(() => { void instance; routesPoll.start(); });
  onDestroy(() => routesPoll.stop());

  const entries = $derived<RouteEntry[]>(routesPoll.data?.routes ?? []);
  const groups = $derived<string[]>(routesPoll.data?.groups ?? []);
  const revision = $derived(routesPoll.data?.revision ?? '');

  const dirtyInstances = new SvelteSet<string>();
  const dirty = $derived(instance !== '' && dirtyInstances.has(instance));
  let mutating = $state(false);
  let applying = $state(false);

  const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));

  let drawerOpen = $state(false);
  let editingEntry = $state<RouteEntry | null>(null);
  function openCreate() { editingEntry = null; drawerOpen = true; }
  function openEdit(entry: RouteEntry) { editingEntry = entry; drawerOpen = true; }
  function closeDrawer() { drawerOpen = false; editingEntry = null; }

  // Drawer hands back a validated payload; parent owns the API call.
  async function saveRoute(payload: Record<string, unknown>, editingIndex: number | null) {
    mutating = true;
    try {
      if (editingIndex !== null) {
        await routesMutate('PATCH', instance, { index: editingIndex, rule: payload, revision });
      } else {
        await routesMutate('POST', instance, { rule: payload, revision });
      }
      dirtyInstances.add(instance);
      toast('Saved to config (not yet applied).');
      closeDrawer();
      await routesPoll.refresh();
    } catch (e) { toast(errMsg(e), 'error'); }
    finally { mutating = false; }
  }

  async function removeRoute(entry: RouteEntry) {
    if (!confirm(`Delete route #${entry.index}?`)) return;
    mutating = true;
    try {
      await routesMutate('DELETE', instance, { index: entry.index, revision });
      dirtyInstances.add(instance);
      toast('Deleted from config (not yet applied).');
      await routesPoll.refresh();
    } catch (e) { toast(errMsg(e), 'error'); }
    finally { mutating = false; }
  }

  async function move(entry: RouteEntry, dir: -1 | 1) {
    const to = entry.index + dir;
    if (to < 0 || to >= entries.length) return;
    mutating = true;
    try {
      await routesReorder(instance, { from: entry.index, to, revision });
      dirtyInstances.add(instance);
      await routesPoll.refresh();
    } catch (e) { toast(errMsg(e), 'error'); }
    finally { mutating = false; }
  }

  async function applyNow() {
    applying = true;
    try {
      await apply(instance) as ApplyResult;
      dirtyInstances.delete(instance);
      toast('Applied to the running instance.');
      await routesPoll.refresh();
    } catch (e) { toast(`Apply failed: ${errMsg(e)}`, 'error'); }
    finally { applying = false; }
  }

  interface Chip { text: string; tone?: 'info' | 'off'; }
  function chipsFor(c: RouteConfig | null | undefined): Chip[] {
    const chips: Chip[] = [];
    if (c?.default) chips.push({ text: 'default', tone: 'info' });
    for (const p of c?.prefixes ?? []) chips.push({ text: p });
    if (c?.file) chips.push({ text: `file ${c.file}` });
    for (const f of c?.files ?? []) chips.push({ text: `file ${f}` });
    for (const d of c?.domains ?? []) chips.push({ text: d });
    if (c?.domain_file) chips.push({ text: `domains ${c.domain_file}` });
    for (const f of c?.domain_files ?? []) chips.push({ text: `domains ${f}` });
    if (c?.invert) chips.push({ text: 'invert' });
    return chips.length ? chips : [{ text: '—', tone: 'off' }];
  }
  function targetText(c: RouteConfig | null | undefined): string {
    let t = c?.via ?? '?';
    if (c?.fallback_via) t += ` → ${c.fallback_via}`;
    else if (c?.fallback_direct) t += ' → direct';
    else if (c?.fallback_drop) t += ' → drop';
    return t;
  }
</script>

<section class="view active">
  <div class="page-head">
    <div>
      <h1>Routing</h1>
      <p>Edit policy routes (first-match-wins), then hot-apply to the running instance.</p>
    </div>
    <div class="toolbar">
      <InstanceSelector base="/ws" bind:selected={instance} bind:refreshSecs={refreshSecs} />
    </div>
  </div>

  {#if !instance}
    <div class="empty">Select a client instance to load routes.</div>
  {:else}
    <ErrorBanner message={routesPoll.error} />

    {#if dirty}
      <div class="applybar">
        <span class="dot warn"></span>
        <strong>Pending changes</strong>
        <span class="pill">{instance}: staged, not yet applied</span>
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
        <span class="gname">Rules</span>
        <span class="gcount">{entries.length}</span>
        <div class="right">
          <button class="btn sm" disabled={mutating} onclick={openCreate}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
            Add rule
          </button>
        </div>
      </div>
      {#if entries.length}
        <table>
          <thead><tr><th>#</th><th>Matchers</th><th>Target</th><th>Actions</th></tr></thead>
          <tbody>
            {#each entries as e (e.index)}
              <tr>
                <td>{e.index}</td>
                <td>
                  <div style="display:flex; flex-wrap:wrap; gap:4px">
                    {#each chipsFor(e.config) as c}<span class="chip {c.tone ?? ''}">{c.text}</span>{/each}
                  </div>
                </td>
                <td>{targetText(e.config)}</td>
                <td>
                  <div class="rowactions">
                    <button class="iconbtn" title="Move up" disabled={mutating || e.index === 0} aria-label="Move up" onclick={() => move(e, -1)}>↑</button>
                    <button class="iconbtn" title="Move down" disabled={mutating || e.index === entries.length - 1} aria-label="Move down" onclick={() => move(e, 1)}>↓</button>
                    <button class="iconbtn act-soft" title="Edit" disabled={mutating} aria-label="Edit" onclick={() => openEdit(e)}>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
                    </button>
                    <button class="iconbtn act-danger" title="Delete" disabled={mutating || e.is_default} aria-label="Delete" onclick={() => removeRoute(e)}>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/></svg>
                    </button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else if !routesPoll.error}
        <div class="empty">No routes configured for this instance.</div>
      {/if}
    </div>
  {/if}
</section>

<RouteDrawer open={drawerOpen} {groups} {editingEntry} onclose={closeDrawer} onsave={saveRoute} />
```

- [ ] **Step 4: `RouteDrawer.svelte`**

Create `bins/outline-ui/frontend/src/features/ws/RouteDrawer.svelte`:

```svelte
<script lang="ts">
  import type { RouteEntry } from '../../lib/types';
  import {
    emptyRouteFields, fieldsFromConfig, validateRouteForm, buildRoutePayload,
    TARGET_KINDS, type RouteFormFields, type FallbackKind,
  } from '../../lib/routeForm';
  import { toast } from '../../lib/toast.svelte';

  let { open, groups, editingEntry = null, onclose, onsave }: {
    open: boolean;
    groups: string[];
    editingEntry?: RouteEntry | null;
    onclose: () => void;
    onsave: (payload: Record<string, unknown>, editingIndex: number | null) => Promise<void>;
  } = $props();

  const editing = $derived(editingEntry !== null);
  let fields = $state<RouteFormFields>(emptyRouteFields());
  let saving = $state(false);

  // Repopulate on open only (never mid-edit from a poll refresh).
  $effect(() => {
    if (!open) return;
    fields = editingEntry ? fieldsFromConfig(editingEntry.config) : emptyRouteFields();
  });

  $effect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onclose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });
  function onBackdrop(e: MouseEvent) { if (e.target === e.currentTarget) onclose(); }

  // `via` picker: reserved targets + reported group names.
  const viaOptions = $derived<string[]>([...TARGET_KINDS, ...groups]);
  const fallbackKinds: { value: FallbackKind; label: string }[] = [
    { value: '', label: '— none —' },
    { value: 'via', label: 'group' },
    { value: 'direct', label: 'direct' },
    { value: 'drop', label: 'drop' },
  ];

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    const err = validateRouteForm(fields);
    if (err) { toast(err, 'error'); return; }
    saving = true;
    try {
      await onsave(buildRoutePayload(fields), editing ? (editingEntry as RouteEntry).index : null);
    } finally { saving = false; }
  }
</script>

<div class="backdrop" class:open onclick={onBackdrop} role="presentation"></div>
<aside class="drawer" class:open aria-hidden={!open}>
  <header>
    <h3>{editing ? `Edit route #${editingEntry?.index}` : 'Add route'}</h3>
    <span class="spacer"></span>
    <button class="iconbtn" type="button" aria-label="Close" onclick={onclose}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg>
    </button>
  </header>
  <form class="body" id="route-drawer-form" onsubmit={handleSubmit}>
    <div class="switch">
      <input id="route-default" type="checkbox" bind:checked={fields.isDefault} disabled={editing && editingEntry?.is_default} />
      <label for="route-default">Default rule (catch-all; no matchers)</label>
    </div>

    <div class="fieldrow">
      <label for="route-via">Target (via)</label>
      <select id="route-via" class="field-mono" bind:value={fields.via}>
        <option value="">— pick —</option>
        {#each viaOptions as v}<option value={v}>{v}</option>{/each}
      </select>
      <span class="hint">A group name, or reserved <code>direct</code> / <code>drop</code>.</span>
    </div>

    {#if !fields.isDefault}
      <fieldset class="fieldset">
        <legend>Matchers (one per line)</legend>
        <div class="fieldrow">
          <label for="route-prefixes">CIDR prefixes</label>
          <textarea id="route-prefixes" class="field-mono" rows="3" bind:value={fields.prefixes} placeholder="10.0.0.0/8"></textarea>
        </div>
        <div class="fieldrow">
          <label for="route-files">Prefix files</label>
          <textarea id="route-files" class="field-mono" rows="2" bind:value={fields.files} placeholder="/etc/outline-ws-rust/geoip-cn.list"></textarea>
        </div>
        <div class="fieldrow">
          <label for="route-domains">Domain suffixes</label>
          <textarea id="route-domains" class="field-mono" rows="3" bind:value={fields.domains} placeholder="example.com"></textarea>
        </div>
        <div class="fieldrow">
          <label for="route-domain-files">Domain files</label>
          <textarea id="route-domain-files" class="field-mono" rows="2" bind:value={fields.domainFiles}></textarea>
        </div>
        <div class="fieldrow">
          <label for="route-poll">File poll (secs)</label>
          <input id="route-poll" class="field-mono" type="number" step="1" bind:value={fields.filePollSecs} placeholder="60" />
        </div>
        <div class="switch">
          <input id="route-invert" type="checkbox" bind:checked={fields.invert} />
          <label for="route-invert">Invert (match addresses NOT in the CIDR set; CIDR-only)</label>
        </div>
      </fieldset>
    {/if}

    <fieldset class="fieldset">
      <legend>Fallback (when the via group has no healthy uplink)</legend>
      <div class="fieldrow">
        <label for="route-fb-kind">Fallback</label>
        <select id="route-fb-kind" class="field-mono" bind:value={fields.fallbackKind}>
          {#each fallbackKinds as k}<option value={k.value}>{k.label}</option>{/each}
        </select>
      </div>
      {#if fields.fallbackKind === 'via'}
        <div class="fieldrow">
          <label for="route-fb-via">Fallback group</label>
          <select id="route-fb-via" class="field-mono" bind:value={fields.fallbackVia}>
            <option value="">— pick —</option>
            {#each groups as g}<option value={g}>{g}</option>{/each}
          </select>
        </div>
      {/if}
    </fieldset>
  </form>
  <div class="foot">
    <button class="btn ghost" type="button" onclick={onclose} disabled={saving}>Cancel</button>
    <button class="btn primary" type="submit" form="route-drawer-form" disabled={saving}>{editing ? 'Update' : 'Create'}</button>
  </div>
</aside>
```

- [ ] **Step 5: Прогнать фронт-гейт + собрать**

```bash
cd bins/outline-ui/frontend && pnpm run check && pnpm exec vitest run && pnpm run build
```
Expected: type-check clean, all Vitest suites green, production build emits
assets into `dist/` (embedded by the Rust binary under `embed-assets`).
Note: `pnpm test` is a silent no-op here — package.json has no `test` script;
CI uses `pnpm exec vitest run` (ci.yml:212), which is what to run.

- [ ] **Step 6: Визуальная проверка**

Run the UI service against a client instance with `[[route]]` configured, open
`/ws/routing`: the default rule shows last with a disabled Delete; add a rule,
reorder it with ↑/↓, edit it, then "Apply now" and confirm the toast. Verify a
stale-revision case (edit in two tabs) surfaces the 409 "config changed" toast.

- [ ] **Step 7: Commit**

```bash
git add bins/outline-ui/frontend/src/features/ws/Routing.svelte bins/outline-ui/frontend/src/features/ws/RouteDrawer.svelte bins/outline-ui/frontend/src/components/layout/Sidebar.svelte bins/outline-ui/frontend/src/App.svelte
git commit -m "feat(ui): Routing tab with CRUD, reorder, and apply"
```

---

### Task 13: Документация EN/RU

**Files:**
- Modify: `bins/outline-ui/README.md`, `bins/outline-ui/README.ru.md`
- Modify: `bins/outline-ws-rust/README.md`, `bins/outline-ws-rust/README.ru.md`

- [ ] **Step 1: outline-ui README (обе стороны)**

In the WS-dashboard section of both `README.md` and `README.ru.md`, add a line
for the Routing tab: it edits `[[route]]` policy rules on the instance, supports
reorder (first-match-wins), and hot-applies via the same "Apply" button as
Uplinks. Keep EN and RU in lockstep (same section, same facts).

- [ ] **Step 2: outline-ws-rust README + apply docs (обе стороны)**

In both `bins/outline-ws-rust/README.md` and `README.ru.md`, update the Policy
routing / control-API section: `[[route]]` is now editable via
`/control/routes` (GET/POST/PATCH/DELETE + `/control/routes/reorder`) and
hot-applied by `/control/apply` when routing was configured at startup
(no restart needed). Note the first-time-enable caveat (adding `[[route]]` to a
node that started without it stays restart-only).

- [ ] **Step 3: Свериться, что пары синхронны**

Skim both `.md`/`.ru.md` pairs — every new fact present on both sides, no
one-sided section.

- [ ] **Step 4: Commit**

```bash
git add bins/outline-ui/README.md bins/outline-ui/README.ru.md bins/outline-ws-rust/README.md bins/outline-ws-rust/README.ru.md
git commit -m "docs: document routing tab and hot-apply (EN/RU)"
```

---

## Self-Review

Проверка плана против спеки (после написания, свежим взглядом):

**Покрытие спеки:**
- Слой A (data plane hot-swap) → Tasks 1–2, 8. `SharedRoutingTable`,
  `swap_preserving_version`, TUN API, watchers respawn — покрыто.
- Слой B (control API) → Tasks 3–8. `routes_crud`, `revision`-guard, `default`
  защита, whole-list валидация, hot-apply — покрыто.
- Слой C (прокси) → Task 9.
- Слой D (фронт) → Tasks 10–12.
- Тесты/доки → в каждой задаче + Task 13.
- Риски из спеки: perf TUN `.load()` (Task 2 Step 4 прогоняет TUN-тесты; нагрузку
  проверять отдельно — отмечено в спеке); version continuity (Task 1, 8 тесты);
  порядок apply групп/routing (Task 8: routing после групп, ошибка не откатывает
  группы); toml_edit top-level массив (Tasks 5–6 тесты рендера/reorder).

**Открытый долг реализатору (не блокеры, но проверить по ходу):**
- Task 6 `mutate.rs` в тексте показан двухчастно (helpers → HTTP-flow); в
  итоговом файле — ровно один `mutate`. Реализатор удаляет stub из Step 3 и
  оставляет Step 3b.
- Task 9 — извлечение `proxy_crud`/`proxy_envelope_post` из `uplinks_proxy`:
  тело перенести дословно, заменив литерал пути на параметр; прогон uplinks-
  тестов доказывает сохранение поведения.
- `ProxyConfig.router` остаётся `Option<Arc<dyn Router>>` — SOCKS-код
  (`dispatcher.rs`, `udp/routing.rs`) не меняется, обёртка подставляется как
  `dyn Router`.

**Согласованность типов:** `SharedRoutingTable` (Task 1) — сигнатуры совпадают в
Tasks 2/8. `RoutePayload`/`route_revision` (Task 5) — используются в Task 6.
`routesList`/`routesMutate`/`routesReorder` (Task 10) — в Task 12. Envelope
`{instance, body}` (Task 9) ↔ `mutate()` helper фронта (Task 10/12).

---

## Порядок и зависимости задач

```
Task 1 (SharedRoutingTable)
  └─ Task 2 (потребители + bootstrap wiring)
       └─ Task 8 (hot-apply) ── нужен также Task 3
Task 3 (валидатор reuse) ─┬─ Task 6 (routes_crud mutate)
Task 4 (shared helpers) ──┤
Task 5 (routes payload) ──┘
  Task 6 └─ Task 7 (dispatch)
              └─ Task 8 (apply) ── нужен Task 1/2
Task 9 (ui proxy) ── нужен Task 7
  └─ Task 10 (types+api) └─ Task 11 (routeForm) └─ Task 12 (Svelte)
Task 13 (docs) — последней
```

Рекомендуемый линейный порядок: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 →
12 → 13. Слой data plane (1,2,8) можно вести параллельно control-слою (3–7) до
точки, где Task 8 сводит их вместе.

## Execution Handoff

План сохранён в `docs/superpowers/plans/2026-08-13-outline-ui-routing-tab.md`.
Два способа исполнения:

1. **Subagent-Driven (рекомендуется)** — свежий субагент на задачу, ревью между
   задачами, быстрая итерация (навык `superpowers:subagent-driven-development`).
2. **Inline Execution** — задачи в этой сессии батчами с чек-поинтами (навык
   `superpowers:executing-plans`).
