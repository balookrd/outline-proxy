# Scheduled Uplink Reselection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automatic weighted-random re-selection (forced move) of the strict active uplink on a wall-clock schedule (`reselect_at = ["03:00","10:10"]`) or fixed interval (`reselect_interval = "10h"`), via soft-switch when `shared_resume` is on, plus a manual `POST /control/reselect` endpoint, metrics, dashboard button, Grafana panel, and EN/RU docs.

**Architecture:** A new `crates/outline-uplink/src/manager/reselect.rs` module holds the outcome enum, the weighted pick (reusing `penalty_weight` + `weighted_pick_with_rng` from `penalty.rs`), the commit path (mirroring the carrier-degraded automatic soft switch — **no** status reset), the pure wall-clock slot helper, and the scheduler loops (modeled on `spawn_shuffle_timer_loops`). Config keys live in `LoadBalancingConfig` / `LoadBalancingSection` with validation in the loader. Control plane and dashboard mirror `/control/activate` patterns.

**Tech Stack:** Rust 2024 workspace, tokio, serde/toml, prometheus (outline-metrics), libc (`localtime_r` — first wall-clock scheduling in the repo, no chrono/time dependency).

**Spec:** `docs/superpowers/specs/2026-07-27-scheduled-uplink-reselect-design.md`

## Global Constraints

- **NO git commits or pushes** — the owner commits manually. At each "checkpoint" step run the verification commands and show `git status --short` + summary instead of committing. (Owner's global rule overrides the plan template's commit steps.)
- CI gate before finishing (from root `AGENTS.md`):
  ```bash
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust \
    -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
    -p outline-tun -p outline-uplink -p outline-wire \
    -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  cargo test --workspace --exclude sockudo-ws
  ```
- After `cargo fmt --all`: check `git status --short vendor` and revert any vendor-only format churn.
- Tests live in `tests/` subdirs next to the module (`<dir>/tests/<basename>.rs`, `#[cfg(test)] #[path = "tests/<basename>.rs"] mod tests;`), NOT inline `mod tests {}`.
- Every new `unsafe` block carries a concrete `// SAFETY:` comment (clippy `undocumented_unsafe_blocks` is `-D warnings` in CI).
- EN and RU docs updated in the same change (`*.md` / `*.ru.md`).
- New metric recorders need a no-op twin in `crates/outline-metrics/src/stub.rs`; metric labels low-cardinality, path labels `&'static str`.
- Control endpoints read bodies via `crate::http::body::read_limited_body`.
- Comments/code in English; do not log secrets.
- `LoadBalancingConfig` is constructed as a literal in ~25 test files across the workspace — adding fields requires updating ALL literals (`grep -rn "LoadBalancingConfig {" crates bins`).

---

### Task 1: Metric `outline_ws_uplink_reselect_total`

**Files:**
- Modify: `crates/outline-metrics/src/registration/uplink.rs` (field in `UplinkFields` ~line 128, registration next to `soft_switch_total` ~line 439, struct return ~line 504)
- Modify: `crates/outline-metrics/src/registration/mod.rs` (wire the field into the global struct — find where `soft_switch_total` is mapped, ~line 72)
- Modify: `crates/outline-metrics/src/lib.rs` (field `uplink_reselect_total: IntCounterVec` next to `soft_switch_total` ~line 231; re-export `record_uplink_reselect` next to `record_soft_switch` ~line 68)
- Modify: `crates/outline-metrics/src/transport.rs` (recorder next to `record_soft_switch` ~line 336)
- Modify: `crates/outline-metrics/src/stub.rs` (no-op twin next to line 171)
- Test: `crates/outline-metrics/src/tests/mod.rs` (exposition-text case, follow the existing pattern at lines 120–135)

**Interfaces:**
- Produces: `outline_metrics::record_uplink_reselect(group: &str, outcome: &'static str)` — callable from `outline-uplink` (which already calls `record_failover` / `record_soft_switch` unconditionally; the stub keeps no-metrics builds compiling).
- Metric: `outline_ws_uplink_reselect_total{group, outcome}`, outcomes `switched` / `no_candidate` / `skipped`.

- [ ] **Step 1: Write the failing test** — in `crates/outline-metrics/src/tests/mod.rs`, copy the shape of the existing exposition assertion test:

```rust
#[test]
fn uplink_reselect_total_renders() {
    crate::record_uplink_reselect("main", "switched");
    let text = render_for_test();
    assert!(
        text.contains("outline_ws_uplink_reselect_total{group=\"main\",outcome=\"switched\"} 1"),
        "reselect counter missing from exposition:\n{text}"
    );
}
```

(Adapt the render helper name to whatever the neighboring tests at lines 120–135 actually use.)

- [ ] **Step 2: Run it, expect compile failure** — `cargo test -p outline-metrics uplink_reselect` → fails: `record_uplink_reselect` not found.
- [ ] **Step 3: Implement.** Registration in `registration/uplink.rs`:

```rust
let uplink_reselect_total = register_labeled!(
    registry,
    IntCounterVec,
    "outline_ws_uplink_reselect_total",
    "Scheduled / manual weighted-random re-selection of the strict active uplink, by \
     outcome. `switched` = the active slot moved to a new weighted-random pick (the \
     current active is always excluded — a forced rotation); `no_candidate` = no \
     healthy, enabled candidate besides the current active existed, nothing changed; \
     `skipped` = the group is not in active_passive mode so re-selection does not apply.",
    ["group", "outcome"]
);
```

Add `pub(super) uplink_reselect_total: IntCounterVec,` to `UplinkFields`, return it from the builder, wire through `registration/mod.rs` and the `lib.rs` struct exactly like `soft_switch_total`. Recorder in `transport.rs`:

```rust
/// Record a scheduled/manual weighted re-selection attempt for a group
/// (`switched`, `no_candidate`, `skipped`). See `outline_ws_uplink_reselect_total`.
pub fn record_uplink_reselect(group: &str, outcome: &'static str) {
    METRICS.uplink_reselect_total.with_label_values(&[group, outcome]).inc();
}
```

Stub twin in `stub.rs`:

```rust
pub fn record_uplink_reselect(_group: &str, _outcome: &'static str) {}
```

- [ ] **Step 4: Verify** — `cargo test -p outline-metrics` → PASS; `cargo check -p outline-metrics --no-default-features` (stub path) → OK.
- [ ] **Step 5: Checkpoint** — show `git status --short`.

---

### Task 2: Core weighted reselect in `UplinkManager`

**Files:**
- Create: `crates/outline-uplink/src/manager/reselect.rs`
- Modify: `crates/outline-uplink/src/manager/mod.rs` (add `mod reselect;` next to the other submodule declarations; re-export `ReselectOutcome`)
- Modify: `crates/outline-uplink/src/lib.rs` (public re-export `ReselectOutcome` next to the other manager types)
- Test: `crates/outline-uplink/src/manager/tests/reselect.rs`

**Interfaces:**
- Consumes: `penalty_weight`, `weighted_pick_with_rng` (`crate::penalty`); `selection_health`, `cooldown_active`, `strict_gate_transport` (`crate::selection`); `set_active_uplink_index_for_transport`, `store_sticky_route`, `strict_route_key` (see usage at `manager/candidates.rs:732-745` — import `strict_route_key` from wherever it is defined, grep it); `self.inner.{active_uplinks, admin_enabled, with_status, uplinks, load_balancing, group_name}`; `outline_metrics::record_uplink_reselect` (Task 1).
- Produces:
  - `pub enum ReselectOutcome { Switched { from: Option<String>, to: String, soft: bool }, NoCandidate, Skipped { reason: &'static str } }` with `pub fn metric_label(&self) -> &'static str`.
  - `pub async fn UplinkManager::reselect_active_uplink(&self, reason: &str, soft: bool) -> ReselectOutcome` (records the metric itself).
  - `pub(crate) async fn reselect_active_uplink_with_rng<R: rand::Rng + ?Sized>(&self, reason: &str, soft: bool, rng: &mut R) -> ReselectOutcome` (no metric — test seam).

- [ ] **Step 1: Write failing tests** in `manager/tests/reselect.rs`. Reuse the builder style of `manager/tests/active_wire.rs` (`UplinkManager::new_for_test`, the `UplinkConfig`/`ProbeConfig`/`LoadBalancingConfig` literal helpers — copy them, but make the uplink helper parametric in name and drop the fallbacks: `fallbacks: vec![]`), with `lb()` returning `mode: LoadBalancingMode::ActivePassive, routing_scope: RoutingScope::Global`. Use `rand::rngs::StdRng::seed_from_u64` for determinism. Tests:

```rust
#[tokio::test]
async fn skipped_outside_active_passive() {
    // lb with mode: ActiveActive
    let mgr = manager_active_active(vec![uplink("a"), uplink("b")]);
    let mut rng = StdRng::seed_from_u64(1);
    let outcome = mgr.reselect_active_uplink_with_rng("test", true, &mut rng).await;
    assert!(matches!(outcome, ReselectOutcome::Skipped { .. }));
}

#[tokio::test]
async fn forced_roll_moves_off_the_active() {
    let mgr = manager_strict(vec![uplink("a"), uplink("b"), uplink("c")]);
    mgr.initialize_strict_active_selection().await; // active := index 0 ("a")
    let before = mgr.active_uplinks_snapshot().global;
    let mut rng = StdRng::seed_from_u64(1);
    let outcome = mgr.reselect_active_uplink_with_rng("test", false, &mut rng).await;
    let ReselectOutcome::Switched { to, soft, .. } = outcome else {
        panic!("expected Switched, got {outcome:?}");
    };
    assert!(!soft, "shared_resume off => soft clamped to false");
    let after = mgr.active_uplinks_snapshot().global;
    assert_ne!(after, before, "forced roll must move the active slot");
    assert_eq!(mgr.uplinks()[after.unwrap()].name, to);
}

#[tokio::test]
async fn single_uplink_group_has_no_candidate() {
    let mgr = manager_strict(vec![uplink("a")]);
    mgr.initialize_strict_active_selection().await;
    let mut rng = StdRng::seed_from_u64(1);
    let outcome = mgr.reselect_active_uplink_with_rng("test", true, &mut rng).await;
    assert!(matches!(outcome, ReselectOutcome::NoCandidate));
}

#[tokio::test]
async fn admin_disabled_uplinks_are_excluded() {
    let mgr = manager_strict(vec![uplink("a"), uplink("b"), uplink("c")]);
    mgr.initialize_strict_active_selection().await; // active = "a"
    mgr.set_uplink_enabled_by_name("b", false).await.unwrap();
    // Only "c" remains eligible — every seed must land on it.
    for seed in 0..20 {
        let mut rng = StdRng::seed_from_u64(seed);
        // Re-activate "a" so the exclusion set stays {a(active), b(disabled)}.
        mgr.set_active_uplink_by_name("a", None, false).await.unwrap();
        let outcome = mgr.reselect_active_uplink_with_rng("test", false, &mut rng).await;
        let ReselectOutcome::Switched { to, .. } = outcome else { panic!() };
        assert_eq!(to, "c");
    }
}

#[tokio::test]
async fn soft_bit_follows_shared_resume() {
    // lb with shared_resume: true
    let mgr = manager_strict_shared_resume(vec![uplink("a"), uplink("b")]);
    mgr.initialize_strict_active_selection().await;
    let mut rng = StdRng::seed_from_u64(1);
    let ReselectOutcome::Switched { soft, .. } =
        mgr.reselect_active_uplink_with_rng("test", true, &mut rng).await
    else { panic!() };
    assert!(soft);
    assert!(mgr.active_uplinks_snapshot().soft, "published snapshot carries the soft bit");
}

#[tokio::test]
async fn penalised_candidate_is_picked_less_often() {
    // 3 uplinks, active = "a"; heavy uplink-level penalty on "b" (test hook below).
    // Over ~2000 seeded trials "c" must win clearly more often than "b",
    // but "b" must still win sometimes (health_weight_floor keeps it reachable).
    let mut b_wins = 0u32;
    let mut c_wins = 0u32;
    for seed in 0..2000 {
        let mgr = manager_strict(vec![uplink("a"), uplink("b"), uplink("c")]);
        mgr.initialize_strict_active_selection().await;
        mgr.test_add_uplink_penalty(1, TransportKind::Tcp, 60);
        let mut rng = StdRng::seed_from_u64(seed);
        match mgr.reselect_active_uplink_with_rng("test", false, &mut rng).await {
            ReselectOutcome::Switched { to, .. } if to == "b" => b_wins += 1,
            ReselectOutcome::Switched { to, .. } if to == "c" => c_wins += 1,
            other => panic!("unexpected: {other:?}"),
        }
    }
    assert!(c_wins > b_wins * 4, "penalty must bias away from b: b={b_wins} c={c_wins}");
    assert!(b_wins > 0, "floor keeps the penalised uplink reachable");
}
```

Register the test module at the bottom of `reselect.rs`:

```rust
#[cfg(test)]
#[path = "tests/reselect.rs"]
mod tests;
```

- [ ] **Step 2: Run** `cargo test -p outline-uplink reselect` → compile failure (module missing).
- [ ] **Step 3: Implement `manager/reselect.rs`.** Sketch (adapt imports/visibility to the crate's actual paths — e.g. `strict_route_key` and the `PerTransportStatus` field access are `pub(crate)`):

```rust
//! Weighted-random forced re-selection of the strict active uplink.
//!
//! Scheduled (`reselect_at` / `reselect_interval`) or manual
//! (`POST /control/reselect`) rotation of the active_passive slot: the current
//! active is excluded, the winner is drawn with probability proportional to
//! `penalty_weight × configured weight` among healthy, enabled, non-cooldown
//! candidates. The commit mirrors the carrier-degraded automatic soft switch
//! (`manager/candidates.rs`): move the slot(s), reseed the sticky route, keep
//! all accumulated health/EWMA/penalty state (NO `reset_all_uplink_statuses`).

#[derive(Debug, Clone)]
pub enum ReselectOutcome {
    Switched { from: Option<String>, to: String, soft: bool },
    NoCandidate,
    Skipped { reason: &'static str },
}

impl ReselectOutcome {
    pub fn metric_label(&self) -> &'static str {
        match self {
            Self::Switched { .. } => "switched",
            Self::NoCandidate => "no_candidate",
            Self::Skipped { .. } => "skipped",
        }
    }
}

impl UplinkManager {
    pub async fn reselect_active_uplink(&self, reason: &str, soft: bool) -> ReselectOutcome {
        let outcome =
            self.reselect_active_uplink_with_rng(reason, soft, &mut rand::rng()).await;
        outline_metrics::record_uplink_reselect(self.group_name(), outcome.metric_label());
        outcome
    }

    pub(crate) async fn reselect_active_uplink_with_rng<R: Rng + ?Sized>(
        &self,
        reason: &str,
        soft: bool,
        rng: &mut R,
    ) -> ReselectOutcome {
        if self.inner.load_balancing.mode != LoadBalancingMode::ActivePassive {
            return ReselectOutcome::Skipped { reason: "not active_passive" };
        }
        let scope = self.inner.load_balancing.routing_scope;
        // Exclude every currently-active slot (global + per-transport): a
        // forced rotation must land elsewhere.
        let (cur_global, cur_tcp, cur_udp) = {
            let active = self.inner.active_uplinks.read().await;
            (active.global, active.tcp, active.udp)
        };
        let current: Vec<usize> =
            [cur_global, cur_tcp, cur_udp].into_iter().flatten().collect();
        let gate = strict_gate_transport(scope, TransportKind::Tcp);
        let now = Instant::now();
        let floor = self.inner.load_balancing.health_weight_floor;
        let mut candidates: Vec<usize> = Vec::new();
        let mut weights: Vec<f64> = Vec::new();
        for (index, uplink) in self.inner.uplinks.iter().enumerate() {
            if current.contains(&index) || !self.inner.admin_enabled(index) {
                continue;
            }
            let weight = self.inner.with_status(index, |status| {
                let eligible = selection_health(
                    status, uplink, gate, now, scope, &self.inner.load_balancing,
                ) && !cooldown_active(status, gate, now);
                eligible.then(|| {
                    let ts = match gate {
                        TransportKind::Tcp => &status.tcp,
                        TransportKind::Udp => &status.udp,
                    };
                    penalty_weight(&ts.penalty, now, &self.inner.load_balancing, floor)
                        * uplink.weight.max(0.0)
                })
            });
            if let Some(weight) = weight {
                candidates.push(index);
                weights.push(weight);
            }
        }
        let Some(pos) = weighted_pick_with_rng(&weights, rng) else {
            return ReselectOutcome::NoCandidate;
        };
        let target = candidates[pos];
        let applied_soft = soft && self.inner.load_balancing.shared_resume;
        let from = cur_global.or(cur_tcp).map(|i| self.inner.uplinks[i].name.clone());
        let to = self.inner.uplinks[target].name.clone();
        // Same commit shape as the carrier-degraded soft failover: slot +
        // sticky reseed, health state untouched.
        if self.strict_global_active_uplink() {
            self.set_active_uplink_index_for_transport(
                TransportKind::Tcp, target, reason, applied_soft,
            ).await;
            let key = strict_route_key(TransportKind::Tcp, scope);
            self.store_sticky_route(&key, target).await;
        } else if self.strict_per_uplink_active_uplink() {
            for t in [TransportKind::Tcp, TransportKind::Udp] {
                self.set_active_uplink_index_for_transport(t, target, reason, applied_soft)
                    .await;
                let key = strict_route_key(t, scope);
                self.store_sticky_route(&key, target).await;
            }
        }
        info!(
            group = %self.inner.group_name,
            from = ?from,
            to = %to,
            soft = applied_soft,
            reason,
            "weighted re-selection moved the strict active uplink",
        );
        ReselectOutcome::Switched { from, to, soft: applied_soft }
    }
}
```

Add the test hook next to the existing `test_add_wire_penalty` (find it in the manager, same file/pattern):

```rust
/// Test hook: add `secs` of uplink-level failure penalty on one transport.
pub fn test_add_uplink_penalty(&self, index: usize, transport: TransportKind, secs: u64) {
    let now = Instant::now();
    self.inner.with_status_mut(index, |status| {
        let ts = match transport {
            TransportKind::Tcp => &mut status.tcp,
            TransportKind::Udp => &mut status.udp,
        };
        ts.penalty.value_secs = secs as f64;
        ts.penalty.updated_at = Some(now);
    });
}
```

Note: if `new_for_test` / `initialize_strict_active_selection` leave probe health at `None`, `selection_health` may rely on `fallback_bootstrap_allowed` — if the health filter rejects unknown-health candidates in tests, set health explicitly via an existing test hook (grep `for_test` in `manager/`) instead of weakening the filter.

- [ ] **Step 4: Run** `cargo test -p outline-uplink reselect` → PASS; `cargo check -p outline-uplink` → OK.
- [ ] **Step 5: Checkpoint** — `git status --short`.

---

### Task 3: Config keys `reselect_at` / `reselect_interval`

**Files:**
- Modify: `crates/outline-uplink/src/config.rs` (two fields on `LoadBalancingConfig`, ~line 785 near `auto_failback`)
- Modify: **every** `LoadBalancingConfig {` literal — `grep -rn "LoadBalancingConfig {" crates bins` (~25 files listed in Global Constraints; add `reselect_at: Vec::new(), reselect_interval: None,`)
- Modify: `bins/outline-ws-rust/src/config/schema.rs` (`LoadBalancingSection`, ~line 830 near `auto_failback`)
- Modify: `bins/outline-ws-rust/src/config/load/balancing.rs` (validation + parsing + `parse_wall_clock`)
- Modify: `bins/outline-ws-rust/src/config/load/groups.rs` (shim `load_balancing_config_from_group`, lines 179–219: two fields)
- Modify: `bins/outline-ws-rust/src/config/load/uplinks/mod.rs` (`parse_human_duration` at line 374: add a `key: &str` parameter, replace the hardcoded `shuffle_timer` in its error strings with `{key}`, make it visible to `balancing.rs` — `pub(in crate::config::load)`; update its existing call sites and tests)
- Test: config tests — put loader tests in `bins/outline-ws-rust/src/config/load/tests/balancing.rs` hooked from `balancing.rs` via `#[cfg(test)] #[path = "tests/balancing.rs"] mod tests;` (create the dir if absent)

**Interfaces:**
- Produces on `LoadBalancingConfig`:
  - `pub reselect_at: Vec<(u8, u8)>` — sorted, deduped `(hour, minute)` local-time slots; empty = disabled.
  - `pub reselect_interval: Option<Duration>` — fixed period; `None` = disabled.
- TOML keys (both `[load_balancing]` and per-`[[uplink_group]]`): `reselect_at = ["HH:MM", ...]`, `reselect_interval = "10h"`.
- Validation: both set → error; either set with `mode != active_passive` → error; bad `HH:MM` → error.

- [ ] **Step 1: Failing tests** in `load/tests/balancing.rs` (deserialize `LoadBalancingSection` from TOML snippets — it derives `Deserialize`):

```rust
use super::*;

fn section(toml_str: &str) -> LoadBalancingSection {
    toml::from_str(toml_str).expect("valid section TOML")
}

#[test]
fn reselect_at_parses_sorts_and_dedups() {
    let lb = section(r#"
        mode = "active_passive"
        reselect_at = ["10:10", "03:00", "10:10"]
    "#);
    let config = load_balancing_config(Some(&lb)).unwrap();
    assert_eq!(config.reselect_at, vec![(3, 0), (10, 10)]);
    assert_eq!(config.reselect_interval, None);
}

#[test]
fn reselect_interval_parses_human_duration() {
    let lb = section(r#"
        mode = "active_passive"
        reselect_interval = "10h"
    "#);
    let config = load_balancing_config(Some(&lb)).unwrap();
    assert_eq!(config.reselect_interval, Some(Duration::from_secs(36_000)));
    assert!(config.reselect_at.is_empty());
}

#[test]
fn reselect_keys_are_mutually_exclusive() {
    let lb = section(r#"
        mode = "active_passive"
        reselect_at = ["03:00"]
        reselect_interval = "10h"
    "#);
    let err = load_balancing_config(Some(&lb)).unwrap_err().to_string();
    assert!(err.contains("mutually exclusive"), "{err}");
}

#[test]
fn reselect_requires_active_passive() {
    let lb = section(r#"reselect_at = ["03:00"]"#); // mode defaults to active_active
    let err = load_balancing_config(Some(&lb)).unwrap_err().to_string();
    assert!(err.contains("active_passive"), "{err}");
}

#[test]
fn reselect_at_rejects_malformed_entries() {
    for bad in ["3", "24:00", "03:60", "aa:bb", ""] {
        let lb = section(&format!("mode = \"active_passive\"\nreselect_at = [\"{bad}\"]"));
        assert!(load_balancing_config(Some(&lb)).is_err(), "accepted {bad:?}");
    }
}
```

- [ ] **Step 2: Run** `cargo test -p outline-ws-rust balancing` → compile failure (unknown fields).
- [ ] **Step 3: Implement.**

`config.rs` (doc comments in the file's style):

```rust
/// Wall-clock re-selection slots (system local time) at which the strict
/// active uplink is re-drawn weighted-randomly among healthy candidates,
/// excluding the current active (forced rotation). Sorted, deduped
/// `(hour, minute)`. Empty = disabled. Mutually exclusive with
/// `reselect_interval`; only valid in `active_passive` mode. The switch is
/// always requested soft and clamps to hard when `shared_resume` is off.
pub reselect_at: Vec<(u8, u8)>,
/// Fixed period between automatic weighted re-selections (monotonic timer
/// from loop start). `None` = disabled. Mutually exclusive with
/// `reselect_at`; only valid in `active_passive` mode.
pub reselect_interval: Option<Duration>,
```

`schema.rs` `LoadBalancingSection`:

```rust
/// Wall-clock times (`"HH:MM"`, system local time) at which the strict
/// active uplink is re-selected (weighted-random, forced move; soft switch
/// when the group has `shared_resume`). Mutually exclusive with
/// `reselect_interval`. Requires `mode = "active_passive"`.
pub(super) reselect_at: Option<Vec<String>>,
/// Period between automatic re-selections ("10h", "1h30m", bare seconds).
/// Mutually exclusive with `reselect_at`. Requires `mode = "active_passive"`.
pub(super) reselect_interval: Option<String>,
```

`balancing.rs` — before the `Ok(LoadBalancingConfig { ... })`, bind `mode` once and validate (then use the binding for the struct's `mode` field too):

```rust
let mode = lb.and_then(|l| l.mode).unwrap_or(LoadBalancingMode::ActiveActive);
let has_reselect_at = lb.and_then(|l| l.reselect_at.as_ref()).is_some_and(|v| !v.is_empty());
let has_reselect_interval = lb.and_then(|l| l.reselect_interval.as_ref()).is_some();
if has_reselect_at && has_reselect_interval {
    bail!("load_balancing.reselect_at and load_balancing.reselect_interval are mutually exclusive");
}
if (has_reselect_at || has_reselect_interval) && mode != LoadBalancingMode::ActivePassive {
    bail!(
        "load_balancing.reselect_at / reselect_interval require mode = \"active_passive\" \
         (scheduled re-selection moves the strict active slot, which only exists there)"
    );
}
```

Struct fields:

```rust
reselect_at: {
    let mut slots = Vec::new();
    for entry in lb.and_then(|l| l.reselect_at.as_ref()).into_iter().flatten() {
        slots.push(parse_wall_clock(entry)?);
    }
    slots.sort_unstable();
    slots.dedup();
    slots
},
reselect_interval: lb
    .and_then(|l| l.reselect_interval.as_deref())
    .map(|s| parse_human_duration("reselect_interval", s))
    .transpose()?,
```

`parse_wall_clock` in `balancing.rs`:

```rust
/// Parse a `"HH:MM"` local-time slot for `reselect_at`.
fn parse_wall_clock(input: &str) -> Result<(u8, u8)> {
    let parse = |part: &str, what: &str| -> Result<u8> {
        if part.is_empty() || part.len() > 2 || !part.chars().all(|c| c.is_ascii_digit()) {
            bail!("load_balancing.reselect_at entry \"{input}\": invalid {what}");
        }
        Ok(part.parse().expect("digits only, len <= 2"))
    };
    let Some((h, m)) = input.split_once(':') else {
        bail!("load_balancing.reselect_at entry \"{input}\" must be \"HH:MM\"");
    };
    let (hours, minutes) = (parse(h, "hours")?, parse(m, "minutes")?);
    if hours > 23 || minutes > 59 {
        bail!("load_balancing.reselect_at entry \"{input}\" out of range (00:00 - 23:59)");
    }
    Ok((hours, minutes))
}
```

`parse_human_duration` refactor in `uplinks/mod.rs`: signature `pub(in crate::config::load) fn parse_human_duration(key: &str, input: &str) -> Result<Duration>`, error strings become e.g. `bail!("{key} = \"{input}\" must be a non-zero duration")`; update the `shuffle_timer` call site(s) to pass `"shuffle_timer"` and fix its tests. Import it in `balancing.rs` (`use super::uplinks::parse_human_duration;` — adjust to actual module paths/visibility).

Shim `groups.rs` — add to the `LoadBalancingSection` literal:

```rust
reselect_at: section.reselect_at.clone(),
reselect_interval: section.reselect_interval.clone(),
```

(Requires the same two fields added to `UplinkGroupSection` in `schema.rs` — mirror the doc comments; check how neighboring LB fields are declared there and follow suit.)

Then update every `LoadBalancingConfig {` literal across the workspace with the two new fields.

- [ ] **Step 4: Run** `cargo test -p outline-ws-rust balancing` → PASS; `cargo test -p outline-uplink` → PASS (literals fixed); `cargo check --workspace --exclude sockudo-ws` → OK.
- [ ] **Step 5: Checkpoint** — `git status --short`.

---

### Task 4: Scheduler loops (interval + wall-clock)

**Files:**
- Modify: `crates/outline-uplink/src/manager/reselect.rs` (pure `due_slot` helper, `local_day_and_secs`, `spawn_reselect_timer_loops`)
- Modify: `crates/outline-uplink/Cargo.toml` (add `libc = "0.2"` to `[dependencies]` — not currently a dep of this crate)
- Modify: `crates/outline-uplink/src/registry.rs` (wrapper next to `spawn_shuffle_timer_loops` at line 204; **and** the respawn list in `apply_new_groups` ~line 341 — grep `spawn_shuffle_timer_loops` inside it and add ours alongside)
- Modify: `bins/outline-ws-rust/src/bootstrap/mod.rs` (one line after `registry.spawn_shuffle_timer_loops();` at ~line 143)
- Test: `crates/outline-uplink/src/manager/tests/reselect.rs` (extend with `due_slot` unit tests)

**Interfaces:**
- Consumes: `UplinkManager::reselect_active_uplink` (Task 2), `LoadBalancingConfig::{reselect_at, reselect_interval}` (Task 3), `self.shutdown_rx()` (same channel as `spawn_shuffle_timer_loops` — group-scoped, dies on hot-apply, respawned by `apply_new_groups`).
- Produces: `pub fn UplinkManager::spawn_reselect_timer_loops(&self)`, `pub fn UplinkRegistry::spawn_reselect_timer_loops(&self)`, `pub(crate) fn due_slot(day_key: i64, secs_of_day: u32, slots: &[(u8, u8)], last_fired: Option<(i64, usize)>) -> Option<usize>`.

- [ ] **Step 1: Failing tests** for the pure helper (append to `tests/reselect.rs`):

```rust
#[test]
fn due_slot_fires_within_tolerance_only() {
    let slots = [(3, 0), (10, 10)];
    // 03:00:00 exact and up to +90 s fire slot 0; before or beyond do not.
    assert_eq!(due_slot(700, 3 * 3600, &slots, None), Some(0));
    assert_eq!(due_slot(700, 3 * 3600 + 90, &slots, None), Some(0));
    assert_eq!(due_slot(700, 3 * 3600 - 1, &slots, None), None, "never early");
    assert_eq!(due_slot(700, 3 * 3600 + 91, &slots, None), None, "missed slot is skipped");
}

#[test]
fn due_slot_does_not_double_fire() {
    let slots = [(3, 0)];
    assert_eq!(due_slot(700, 3 * 3600 + 10, &slots, Some((700, 0))), None);
    // ...but the same slot fires again on the next day.
    assert_eq!(due_slot(701, 3 * 3600 + 10, &slots, Some((700, 0))), Some(0));
}

#[test]
fn due_slot_handles_multiple_slots_independently() {
    let slots = [(3, 0), (10, 10)];
    assert_eq!(due_slot(700, 10 * 3600 + 10 * 60, &slots, Some((700, 0))), Some(1));
}
```

- [ ] **Step 2: Run** `cargo test -p outline-uplink due_slot` → compile failure.
- [ ] **Step 3: Implement** in `reselect.rs`:

```rust
/// How far past a `reselect_at` slot the tick may observe it and still fire.
/// The loop ticks every `WALL_CLOCK_TICK`, so anything comfortably above the
/// tick period works; beyond the tolerance a slot missed during suspend is
/// skipped rather than fired retroactively.
pub(crate) const RESELECT_SLOT_TOLERANCE_SECS: u32 = 90;
const WALL_CLOCK_TICK: Duration = Duration::from_secs(30);

/// Pure slot arbiter for the wall-clock loop: returns the index of a slot
/// that is due *now* (within tolerance after its time) and has not already
/// fired today (`last_fired` = `(day_key, slot_index)` of the last firing).
pub(crate) fn due_slot(
    day_key: i64,
    secs_of_day: u32,
    slots: &[(u8, u8)],
    last_fired: Option<(i64, usize)>,
) -> Option<usize> {
    slots.iter().enumerate().find_map(|(i, &(h, m))| {
        let slot_secs = u32::from(h) * 3600 + u32::from(m) * 60;
        let due = secs_of_day >= slot_secs
            && secs_of_day - slot_secs <= RESELECT_SLOT_TOLERANCE_SECS;
        (due && last_fired != Some((day_key, i))).then_some(i)
    })
}

/// Local calendar day key + seconds since local midnight. Uses
/// `libc::localtime_r` directly — the repo has no chrono/time dependency and
/// targets unix only. Returns `None` if the libc call fails.
fn local_day_and_secs() -> Option<(i64, u32)> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?;
    let t = now.as_secs() as libc::time_t;
    // SAFETY: `libc::tm` is a plain-old-data `repr(C)` struct for which the
    // all-zero bit pattern is a valid value of every field; `localtime_r`
    // fully overwrites it on success and we only read it after the null check.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `&t` and `&mut tm` are valid, non-aliasing pointers for the
    // duration of the call; `localtime_r` (the thread-safe variant) does not
    // retain either pointer past its return.
    let res = unsafe { libc::localtime_r(&t, &mut tm) };
    if res.is_null() {
        return None;
    }
    let secs = tm.tm_hour as u32 * 3600 + tm.tm_min as u32 * 60 + tm.tm_sec as u32;
    // Unique per local calendar day (tm_yday < 366).
    Some(((i64::from(tm.tm_year)) * 366 + i64::from(tm.tm_yday), secs))
}

impl UplinkManager {
    /// Spawn the scheduled re-selection loop for this group, if configured.
    /// Interval mode: plain monotonic sleep. Wall-clock mode: tick every 30 s
    /// and compare local time against the configured slots — survives NTP
    /// jumps, DST shifts and suspend (a slot slept through simply does not
    /// fire). Honours the manager's group-scoped shutdown channel, so the
    /// loop dies on hot-apply and is respawned for the new managers.
    pub fn spawn_reselect_timer_loops(&self) {
        let lb = &self.inner.load_balancing;
        if lb.mode != LoadBalancingMode::ActivePassive {
            return; // config validation rejects this, but hot-apply is belt-and-braces
        }
        if let Some(interval) = lb.reselect_interval {
            let manager = self.clone();
            let mut shutdown = self.shutdown_rx();
            info!(
                group = %self.inner.group_name,
                interval_secs = interval.as_secs(),
                "scheduled uplink re-selection loop spawned (interval mode)",
            );
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown.changed() => break,
                        _ = sleep(interval) => {}
                    }
                    manager.reselect_active_uplink("scheduled_reselect", true).await;
                }
            });
        }
        if !lb.reselect_at.is_empty() {
            let slots = lb.reselect_at.clone();
            let manager = self.clone();
            let mut shutdown = self.shutdown_rx();
            info!(
                group = %self.inner.group_name,
                slots = ?slots,
                "scheduled uplink re-selection loop spawned (wall-clock mode)",
            );
            tokio::spawn(async move {
                let mut last_fired: Option<(i64, usize)> = None;
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown.changed() => break,
                        _ = sleep(WALL_CLOCK_TICK) => {}
                    }
                    let Some((day_key, secs)) = local_day_and_secs() else { continue };
                    if let Some(slot) = due_slot(day_key, secs, &slots, last_fired) {
                        last_fired = Some((day_key, slot));
                        manager.reselect_active_uplink("scheduled_reselect", true).await;
                    }
                }
            });
        }
    }
}
```

Registry wrapper (next to `spawn_shuffle_timer_loops`, `registry.rs:204`):

```rust
/// Spawn one scheduled re-selection loop per group that has `reselect_at`
/// or `reselect_interval` configured. No-op for other groups. See
/// [`UplinkManager::spawn_reselect_timer_loops`].
pub fn spawn_reselect_timer_loops(&self) {
    for group in self.state.load().groups.iter() {
        group.manager.spawn_reselect_timer_loops();
    }
}
```

Add `registry.spawn_reselect_timer_loops();` in `bootstrap/mod.rs` after `spawn_shuffle_timer_loops()` AND in `apply_new_groups` where the other per-group loops are respawned (grep — if `apply_new_groups` respawns via a shared helper that already calls `spawn_shuffle_timer_loops`, add ours there instead).

- [ ] **Step 4: Run** `cargo test -p outline-uplink` → PASS; `cargo check -p outline-ws-rust` → OK.
- [ ] **Step 5: Checkpoint** — `git status --short`.

---

### Task 5: `POST /control/reselect` + dashboard button

**Files:**
- Modify: `crates/outline-uplink/src/registry.rs` (new `reselect_group` method next to `set_active_uplink_by_name` at line 254)
- Modify: `bins/outline-ws-rust/src/http/control/handlers.rs` (request/response types + handler next to `handle_activate` at line 160)
- Modify: `bins/outline-ws-rust/src/http/control/server.rs` (label arm at lines 126–135, route arm at ~line 168)
- Modify: `bins/outline-ws-rust/src/http/dashboard/api.rs` (proxy — mirror the `/control/activate` proxy pattern at lines 366–390 / 128–170)
- Modify: `bins/outline-ws-rust/src/http/dashboard/dashboard.html` (a "⟳ Reselect" group-level button next to the existing "⇄ Soft switch" one; NOT gated on `cluster_resume_enabled` — reselect works on non-cluster groups too, as a hard switch)
- Modify: `bins/outline-ws-rust/README.md` + `README.ru.md` (control endpoint list, EN ~lines 979–991 and the RU mirror)
- Test: `bins/outline-ws-rust/src/http/control/tests/mod.rs` (handler tests, follow the file's existing patterns)

**Interfaces:**
- Consumes: `UplinkManager::reselect_active_uplink` + `ReselectOutcome` (Task 2).
- Produces:
  - `pub async fn UplinkRegistry::reselect_group(&self, group: &str, soft: bool) -> Result<ReselectOutcome>`
  - `POST /control/reselect` body `{"group": "main", "soft": true}` (`soft` defaults to `true`), 200 response `{"group","outcome","from"?,"to"?,"soft"}`, 400 on unknown group / invalid JSON / empty group.

- [ ] **Step 1: Failing tests** in `http/control/tests/mod.rs` (reuse the file's existing registry/manager fixtures; check how `activate_from_json` is tested there and mirror it):

```rust
#[tokio::test]
async fn reselect_rejects_unknown_group() {
    let uplinks = test_registry(); // reuse the file's fixture helper
    let response = reselect_from_json(br#"{"group":"nope"}"#, uplinks).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reselect_reports_outcome() {
    // strict two-uplink fixture; after init, reselect must switch or
    // legitimately report no_candidate — assert the response shape.
    let uplinks = test_registry_strict();
    let response = reselect_from_json(br#"{"group":"main","soft":true}"#, uplinks).await;
    assert_eq!(response.status(), StatusCode::OK);
    // body contains "outcome":"switched" or "no_candidate"
}
```

- [ ] **Step 2: Run** `cargo test -p outline-ws-rust control` → compile failure.
- [ ] **Step 3: Implement.** Registry:

```rust
/// Weighted-random forced re-selection of the strict active uplink for
/// `group` ("reselect now"): same code path the scheduled loops use. `soft`
/// requests session migration via cluster resume; clamped to a hard switch
/// off-cluster. See [`UplinkManager::reselect_active_uplink`].
pub async fn reselect_group(&self, group: &str, soft: bool) -> Result<ReselectOutcome> {
    let state = self.state.load();
    let manager = state
        .by_name
        .get(group)
        .map(|&i| state.groups[i].manager.clone())
        .ok_or_else(|| anyhow::anyhow!("uplink group \"{}\" not found", group))?;
    Ok(manager.reselect_active_uplink("manual_reselect", soft).await)
}
```

Handler (`handlers.rs`):

```rust
#[derive(Debug, Deserialize)]
pub(crate) struct ReselectRequest {
    pub(crate) group: String,
    /// Soft switch (migrate live sessions via cluster resume) — the default;
    /// clamped to hard off-cluster, mirroring the scheduler's behaviour.
    #[serde(default = "default_reselect_soft")]
    pub(crate) soft: bool,
}

fn default_reselect_soft() -> bool {
    true
}

#[derive(Debug, Serialize)]
struct ReselectResponse {
    group: String,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    soft: bool,
}

pub(crate) async fn handle_reselect(
    request: Request<Incoming>,
    uplinks: UplinkRegistry,
) -> ControlResponse {
    if let Some(response) = require_method(request.method(), Method::POST, "POST") {
        return response;
    }
    let body = match read_limited_body(request.into_body(), "/control/reselect").await {
        Ok(body) => body,
        Err(response) => return response,
    };
    reselect_from_json(&body, uplinks).await
}

pub(crate) async fn reselect_from_json(body: &[u8], uplinks: UplinkRegistry) -> ControlResponse {
    let payload: ReselectRequest = match serde_json::from_slice(body) {
        Ok(payload) => payload,
        Err(error) => {
            let msg = format!("invalid JSON: {error}");
            return json_response(StatusCode::BAD_REQUEST, &serde_json::json!({ "error": msg }));
        },
    };
    if payload.group.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "\"group\" is required");
    }
    match uplinks.reselect_group(payload.group.trim(), payload.soft).await {
        Ok(outcome) => {
            info!(group = %payload.group, ?outcome, "manual weighted re-selection via /control/reselect");
            let (from, to, soft) = match &outcome {
                outline_uplink::ReselectOutcome::Switched { from, to, soft } => {
                    (from.clone(), Some(to.clone()), *soft)
                },
                _ => (None, None, false),
            };
            json_response(
                StatusCode::OK,
                &ReselectResponse {
                    group: payload.group.trim().to_string(),
                    outcome: outcome.metric_label(),
                    from,
                    to,
                    soft,
                },
            )
        },
        Err(error) => {
            warn!(error = %format!("{error:#}"), "manual /control/reselect failed");
            let msg = format!("{error}");
            json_response(StatusCode::BAD_REQUEST, &serde_json::json!({ "error": msg }))
        },
    }
}
```

`server.rs`: add `"/control/reselect" => "/control/reselect",` to the label match and a route arm mirroring `/control/activate`:

```rust
"/control/reselect" => {
    let response = handle_reselect(request, state.uplinks.clone()).await;
    record_metrics_http_request("/control/reselect", response.status().as_u16());
    response
},
```

Dashboard: proxy `/api/reselect` → `reselect_from_json` following the activate proxy in `api.rs` (lines 366–390 / 128–170), and a per-group "⟳ Reselect" button in `dashboard.html` next to the soft-switch button (confirm-prompt like the existing buttons; on success re-fetch topology). README EN/RU: add the endpoint with a one-line description and example body to the control-plane list.

- [ ] **Step 4: Run** `cargo test -p outline-ws-rust control` → PASS; `cargo check -p outline-ws-rust --no-default-features` → OK (control/dashboard features off must still compile).
- [ ] **Step 5: Checkpoint** — `git status --short`.

---

### Task 6: Docs, config example, CHANGELOG, Grafana

**Files:**
- Modify: `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md` + `.ru.md` (LB key table ~line 568: two rows; new subsection "Scheduled re-selection" near the soft-switch section ~lines 680–705)
- Modify: `bins/outline-ws-rust/README.md` + `README.ru.md` (feature bullet ~line 121; knob prose near line 618)
- Modify: `bins/outline-ws-rust/config.toml` (commented example near the LB section, e.g. by `health_weighted_selection` ~line 393)
- Modify: `bins/outline-ws-rust/CHANGELOG.md` + `CHANGELOG.ru.md` (entry under the unreleased section, matching the file's format)
- Modify: `bins/outline-ws-rust/grafana/outline-ws-rust-dashboard.json` (new timeseries panel next to the failover/soft-switch panels)

**Interfaces:** none (docs only). RU terminology: «перевыбор» for re-selection, «носитель»/carrier (never «карьер»), keep key names/labels in Latin.

- [ ] **Step 1: `config.toml` example** (commented, in the LB block):

```toml
# Scheduled weighted re-selection of the strict active uplink (active_passive
# only). Random but biased by probe quality; the current active is always
# excluded (forced rotation); soft switch when the group has shared_resume.
# The two keys are mutually exclusive.
# reselect_at = ["03:00", "10:10"]   # wall-clock slots, system local time
# reselect_interval = "10h"          # ...or a fixed period ("90m", "1h30m", seconds)
```

- [ ] **Step 2: UPLINK-CONFIGURATIONS EN/RU.** Table rows for `reselect_at` / `reselect_interval` (defaults: unset/disabled). Subsection covering: semantics (weighted-random by `penalty_weight × weight` with `health_weight_floor`, forced move, healthy/enabled/non-cooldown candidates only, `no_candidate` no-op), scheduling (local time, ±90 s tolerance, missed-during-suspend slots skipped; interval is monotonic), soft-switch clamp (`shared_resume`), **interaction warning**: with `auto_failback = true` the next probe cycle may revert a reselect that landed on a lower-weight uplink — use equal weights or keep `auto_failback` off with this feature; state is NOT reset (unlike `/control/activate`), and `/control/reselect` as the manual trigger. Port every paragraph to the `.ru.md` side.
- [ ] **Step 3: README EN/RU** — feature bullet + endpoint already added in Task 5; add knob mention in the LB prose. CHANGELOG EN/RU entry.
- [ ] **Step 4: Grafana panel.** In the dashboard JSON, find the row containing the failover/soft-switch panels (search `outline_ws_soft_switch_total` / `uplink_failovers_total`), pick the next unused panel `id` (`grep '"id":' | sort -n`), and add a timeseries panel:

```json
{
  "title": "Uplink re-selections (scheduled/manual)",
  "type": "timeseries",
  "id": <NEXT_FREE_ID>,
  "targets": [
    {
      "expr": "sum by (group, outcome) (increase(outline_ws_uplink_reselect_total[$__rate_interval]))",
      "legendFormat": "{{group}} {{outcome}}"
    }
  ]
}
```

Copy `datasource`, `fieldConfig`, `gridPos` conventions from the neighboring soft-switch/failover panel and place it in the same row (adjust `gridPos` to the free slot). Validate the JSON: `python3 -m json.tool <file> >/dev/null`.

- [ ] **Step 5: Checkpoint** — `git status --short`; skim EN and RU renders side by side for parity.

---

### Task 7: Full gate

- [ ] **Step 1:** `cargo fmt --all`, then `git status --short vendor` → revert any vendor churn (`git checkout -- vendor` if only format noise).
- [ ] **Step 2:** Run the CI gate exactly (see Global Constraints): fmt --check with the explicit package list, clippy `--workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings`, `cargo test --workspace --exclude sockudo-ws`.
- [ ] **Step 3:** Feature matrix: `cargo check -p outline-ws-rust --no-default-features`.
- [ ] **Step 4:** Show final `git status --short` + diff summary (`git diff --stat`) and STOP — no commit; the owner commits manually.
