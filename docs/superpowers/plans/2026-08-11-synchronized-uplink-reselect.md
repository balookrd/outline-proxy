# Synchronized Uplink Reselection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new `load_balancing.reselect_sync` flag that makes two independent
nodes with the same group config pick the *same* active uplink — so external
clients reaching either node leave from one egress address — without any
tunnel, coordinator, or shared state between them.

**Architecture:** A new `crates/outline-uplink/src/manager/sync_order.rs`
derives a per-slot seed with BLAKE3 from `(group name, uplink names, local day
key, slot index)`, turns it into a full preference order via the existing
`weighted_permutation_with_rng` (configured `weight` only — no local penalty
state), and picks the first locally-healthy uplink from that order, excluding
the previous slot's deterministic winner. `reselect_global` /
`reselect_per_uplink` call it instead of the OS-seeded draw when the flag is
on, and `initialize_strict_active_selection` routes startup through the same
path so a restart cannot resurrect a mid-day leg.

**Tech Stack:** Rust 2024 workspace, tokio, rand (`StdRng::seed_from_u64`),
blake3 (already in the workspace via `outline-wire` / `shadowsocks-crypto`),
libc `localtime_r` (existing, in `manager/reselect.rs`).

**Spec:** `docs/superpowers/specs/2026-08-11-synchronized-uplink-reselect-design.md`

## Global Constraints

- **NO git commits or pushes** — the owner commits manually. Where the template
  says "commit", run the verification commands and show `git status --short`
  plus a summary instead. (Owner's global rule overrides the plan template.)
- CI gate before finishing (from root `AGENTS.md`), in this order — `fmt` fails
  first and masks clippy:
  ```bash
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust \
    -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
    -p outline-tun -p outline-uplink -p outline-wire \
    -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  cargo test --workspace --exclude sockudo-ws
  ```
- After `cargo fmt --all`: check `git status --short vendor` and revert any
  vendor-only format churn.
- Tests live in `tests/` subdirs next to the module
  (`<dir>/tests/<basename>.rs` + `#[cfg(test)] #[path = "tests/<basename>.rs"] mod tests;`),
  never inline `mod tests {}`.
- Comments and code in English. Do not log secrets. Metric labels stay
  low-cardinality — this feature adds **no new metric**.
- `LoadBalancingConfig` is built as a struct literal in ~79 places across the
  workspace (`rg -c "LoadBalancingConfig \{" crates bins`). Adding a field
  breaks every one of them; `cargo check --workspace --exclude sockudo-ws`
  enumerates them, and each needs `reselect_sync: false,`.
- EN and RU docs updated in the same change (`*.md` / `*.ru.md`).
- No new external dependency beyond `blake3`, which is already a workspace
  member's dependency at version `1.8`.

---

### Task 1: `reselect_sync` config key

**Files:**
- Modify: `crates/outline-uplink/src/config.rs` (add field at the end of
  `LoadBalancingConfig`, next to `reselect_at` / `reselect_interval` ~line 1082)
- Modify: `bins/outline-ws-rust/src/config/schema.rs` (`UplinkGroupSection`
  ~line 704, next to `reselect_at`; `LoadBalancingSection` ~line 975, same
  place)
- Modify: `bins/outline-ws-rust/src/config/load/groups.rs` (~line 229, the shim
  that copies group fields into `LoadBalancingSection`)
- Modify: `bins/outline-ws-rust/src/config/load/balancing.rs` (validation next
  to the existing `reselect_at`/`reselect_interval` checks ~lines 50–67; field
  init ~line 301)
- Modify: every `LoadBalancingConfig { .. }` literal the compiler flags
- Test: `bins/outline-ws-rust/src/config/load/tests/balancing.rs`

**Interfaces:**
- Produces: `LoadBalancingConfig.reselect_sync: bool` (default `false`), read by
  every later task.

- [ ] **Step 1: Write the failing tests** in
  `bins/outline-ws-rust/src/config/load/tests/balancing.rs`. The file has no
  struct literals — `LoadBalancingSection` carries no `Default` and is built
  from TOML through the existing `section()` helper at the top of the file:

```rust
#[test]
fn reselect_sync_requires_reselect_at() {
    let lb = section(
        r#"
        mode = "active_passive"
        routing_scope = "global"
        reselect_sync = true
    "#,
    );
    let err = load_balancing_config(Some(&lb)).unwrap_err().to_string();
    assert!(err.contains("reselect_sync requires load_balancing.reselect_at"), "{err}");
}

#[test]
fn reselect_sync_rejects_interval_mode() {
    // reselect_interval counts from each process's own start, so two nodes
    // fire at different instants and no shared seed can reconcile them.
    let lb = section(
        r#"
        mode = "active_passive"
        routing_scope = "global"
        reselect_interval = "10h"
        reselect_sync = true
    "#,
    );
    let err = load_balancing_config(Some(&lb)).unwrap_err().to_string();
    assert!(err.contains("reselect_sync requires load_balancing.reselect_at"), "{err}");
}

#[test]
fn reselect_sync_accepts_wall_clock_slots() {
    let lb = section(
        r#"
        mode = "active_passive"
        routing_scope = "global"
        reselect_at = ["03:20"]
        reselect_sync = true
    "#,
    );
    let config = load_balancing_config(Some(&lb)).unwrap();
    assert!(config.reselect_sync);
    assert_eq!(config.reselect_at, vec![(3, 20)]);
}

#[test]
fn reselect_sync_defaults_off() {
    let config = load_balancing_config(None).unwrap();
    assert!(!config.reselect_sync, "the flag must be opt-in");
}
```

- [ ] **Step 2: Run them, expect compile failure**

Run: `cargo test -p outline-ws-rust reselect_sync`
Expected: FAIL — `no field named reselect_sync`.

- [ ] **Step 3: Add the config field.** In `crates/outline-uplink/src/config.rs`,
  after `reselect_interval`:

```rust
    /// Make scheduled re-selection agree across independent nodes: instead of
    /// an OS-seeded draw, every node derives the same per-slot order from
    /// `(group name, uplink names, local day, slot index)` and takes the first
    /// locally healthy uplink from it. Two nodes with the same group config
    /// therefore land on the same uplink without talking to each other, which
    /// is what keeps a shared client population on one egress address.
    ///
    /// Requires `reselect_at` (the slot key is what both sides agree on;
    /// `reselect_interval` fires relative to process start and cannot agree).
    /// Health stays local, so a node whose leg dies still leaves on its own.
    pub reselect_sync: bool,
```

In `schema.rs`, in **both** `UplinkGroupSection` and `LoadBalancingSection`,
next to `reselect_at`:

```rust
    /// Derive the scheduled re-selection order deterministically so nodes
    /// sharing this group config pick the same uplink. Requires `reselect_at`.
    /// Default: `false`.
    pub(super) reselect_sync: Option<bool>,
```

In `groups.rs`, next to `reselect_at: section.reselect_at.clone(),`:

```rust
        reselect_sync: section.reselect_sync,
```

In `balancing.rs`, after the existing mutual-exclusion / mode checks
(~line 67), before `Ok(LoadBalancingConfig {`:

```rust
    let reselect_sync = lb.and_then(|l| l.reselect_sync).unwrap_or(false);
    if reselect_sync && !has_reselect_at {
        bail!(
            "load_balancing.reselect_sync requires load_balancing.reselect_at: the shared \
             (day, slot) key is what makes two nodes agree, and reselect_interval fires \
             relative to each process's own start instead"
        );
    }
```

and in the returned struct, next to `reselect_interval`:

```rust
        reselect_sync,
```

- [ ] **Step 4: Fix every other literal.**

Run: `cargo check --workspace --exclude sockudo-ws 2>&1 | rg "missing field .reselect_sync"`
Add `reselect_sync: false,` to each reported literal (they are test fixtures;
put it next to the existing `reselect_at` line so the diff reads as one block).

- [ ] **Step 5: Run the tests**

Run: `cargo test -p outline-ws-rust reselect_sync`
Expected: PASS (3 tests).

- [ ] **Step 6: Checkpoint** — run `cargo check --workspace --exclude sockudo-ws`,
  then show `git status --short` and a one-line summary. Do not commit.

---

### Task 2: Slot keys (pure helpers)

**Files:**
- Create: `crates/outline-uplink/src/manager/sync_order.rs`
- Create: `crates/outline-uplink/src/manager/tests/sync_order.rs`
- Modify: `crates/outline-uplink/src/manager/mod.rs` (declare the module next to
  `pub(crate) mod reselect;` at line 11)

**Interfaces:**
- Produces: `SlotKey { day_key: i64, slot: usize }`,
  `current_slot_key(day_key: i64, secs_of_day: u32, slots: &[(u8, u8)]) -> Option<SlotKey>`,
  `previous_slot_key(key: SlotKey, slots: &[(u8, u8)]) -> SlotKey`.
- Consumes: `slots` are the loader's sorted+deduped `reselect_at` values.

- [ ] **Step 1: Write the failing tests** in
  `crates/outline-uplink/src/manager/tests/sync_order.rs`:

```rust
//! Deterministic cross-node re-selection order: slot keys, seed, order, pick.

use super::super::sync_order::{SlotKey, current_slot_key, previous_slot_key};

const SLOTS: [(u8, u8); 2] = [(3, 20), (15, 0)];

#[test]
fn current_slot_key_picks_the_latest_slot_already_passed() {
    // 04:00 local — past 03:20, before 15:00.
    let key = current_slot_key(100, 4 * 3600, &SLOTS).expect("slots configured");
    assert_eq!(key, SlotKey { day_key: 100, slot: 0 });

    // 16:00 local — past both.
    let key = current_slot_key(100, 16 * 3600, &SLOTS).expect("slots configured");
    assert_eq!(key, SlotKey { day_key: 100, slot: 1 });
}

#[test]
fn current_slot_key_before_the_first_slot_belongs_to_yesterday() {
    // 01:00 local — today's 03:20 has not fired yet, so the decision in force
    // is still yesterday's last slot. Without this a node restarting after
    // midnight would compute a different key than one that kept running.
    let key = current_slot_key(100, 3600, &SLOTS).expect("slots configured");
    assert_eq!(key, SlotKey { day_key: 99, slot: 1 });
}

#[test]
fn current_slot_key_is_none_without_slots() {
    assert!(current_slot_key(100, 3600, &[]).is_none());
}

#[test]
fn previous_slot_key_walks_back_across_the_day_boundary() {
    let same_day = previous_slot_key(SlotKey { day_key: 100, slot: 1 }, &SLOTS);
    assert_eq!(same_day, SlotKey { day_key: 100, slot: 0 });

    let wrapped = previous_slot_key(SlotKey { day_key: 100, slot: 0 }, &SLOTS);
    assert_eq!(wrapped, SlotKey { day_key: 99, slot: 1 });
}
```

- [ ] **Step 2: Run them, expect failure**

Run: `cargo test -p outline-uplink sync_order`
Expected: FAIL — unresolved module `sync_order`.

- [ ] **Step 3: Create the module** `crates/outline-uplink/src/manager/sync_order.rs`:

```rust
//! Deterministic re-selection order shared by independent nodes.
//!
//! `reselect_at` rotation is normally an OS-seeded draw over locally-weighted
//! candidates, so two nodes running the same config land on different uplinks
//! and their users leave from different egress addresses. Under
//! `LoadBalancingConfig::reselect_sync` the draw is replaced by a function of
//! data every node already agrees on — group name, uplink names, the local
//! calendar day and the slot index — so agreement needs no communication.
//!
//! Health, cooldown and admin state stay strictly local: they filter the
//! shared order rather than shape it. That is deliberate — a node whose leg
//! dies must leave immediately, without waiting for anyone.

/// One firing of the wall-clock schedule: the local calendar day it belongs
/// to plus the index of the slot within the group's sorted `reselect_at`.
/// Two nodes in the same timezone compute the same `SlotKey` for the same
/// instant, which is the whole basis of their agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SlotKey {
    pub(crate) day_key: i64,
    pub(crate) slot: usize,
}

/// The slot whose decision is currently in force: the last one at or before
/// `secs_of_day`, or — before the day's first slot — the previous day's last
/// slot. Returns `None` only when no slots are configured, which the config
/// loader already refuses in combination with `reselect_sync`.
///
/// `slots` must be sorted ascending; the loader sorts and dedups `reselect_at`.
pub(crate) fn current_slot_key(
    day_key: i64,
    secs_of_day: u32,
    slots: &[(u8, u8)],
) -> Option<SlotKey> {
    let last = slots.len().checked_sub(1)?;
    let passed = slots
        .iter()
        .rposition(|&(h, m)| u32::from(h) * 3600 + u32::from(m) * 60 <= secs_of_day);
    Some(match passed {
        Some(slot) => SlotKey { day_key, slot },
        None => SlotKey { day_key: day_key - 1, slot: last },
    })
}

/// The firing before `key`. Used for the rotation exclusion: the previous
/// slot's deterministic winner is what today's draw must move away from, and
/// unlike "the current active uplink" it is identical on every node.
pub(crate) fn previous_slot_key(key: SlotKey, slots: &[(u8, u8)]) -> SlotKey {
    match key.slot.checked_sub(1) {
        Some(slot) => SlotKey { day_key: key.day_key, slot },
        None => SlotKey {
            day_key: key.day_key - 1,
            slot: slots.len().saturating_sub(1),
        },
    }
}

#[cfg(test)]
#[path = "tests/sync_order.rs"]
mod tests;
```

In `crates/outline-uplink/src/manager/mod.rs`, next to line 11:

```rust
    pub(crate) mod sync_order;
```

`local_day_and_secs` (`manager/reselect.rs:142`) stays private: the only caller
that needs the clock is `sync_target`, which Task 5 adds to `reselect.rs`
itself. `sync_order.rs` takes the day key as an argument, which is also what
makes it testable without touching the system clock.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p outline-uplink sync_order`
Expected: PASS (4 tests).

- [ ] **Step 5: Checkpoint** — `cargo clippy -p outline-uplink --all-targets --no-deps -- -D warnings`,
  then `git status --short`. Do not commit.

---

### Task 3: Seed and order

**Files:**
- Modify: `crates/outline-uplink/Cargo.toml` (add `blake3` to `[dependencies]`)
- Modify: `crates/outline-uplink/src/manager/sync_order.rs`
- Modify: `crates/outline-uplink/src/manager/tests/sync_order.rs`

**Interfaces:**
- Consumes: `SlotKey` (Task 2), `crate::penalty::weighted_permutation_with_rng`
  (`pub(crate)`, `crates/outline-uplink/src/penalty.rs:112`).
- Produces: `sync_seed(group: &str, uplink_names: &[&str], key: SlotKey) -> u64`
  and `UplinkManager::sync_order(&self, key: SlotKey) -> Vec<usize>` — a
  permutation of every uplink index, most-preferred first.

- [ ] **Step 1: Write the failing tests** — append to
  `crates/outline-uplink/src/manager/tests/sync_order.rs`:

```rust
use super::super::sync_order::sync_seed;

#[test]
fn sync_seed_is_stable_for_the_same_inputs() {
    let key = SlotKey { day_key: 100, slot: 0 };
    let a = sync_seed("main", &["nuxt", "nuxt2", "senko"], key);
    let b = sync_seed("main", &["nuxt", "nuxt2", "senko"], key);
    assert_eq!(a, b, "same inputs must produce the same seed on every node");
}

#[test]
fn sync_seed_separates_days_slots_groups_and_uplink_sets() {
    let base = sync_seed("main", &["nuxt", "nuxt2"], SlotKey { day_key: 100, slot: 0 });
    assert_ne!(base, sync_seed("main", &["nuxt", "nuxt2"], SlotKey { day_key: 101, slot: 0 }));
    assert_ne!(base, sync_seed("main", &["nuxt", "nuxt2"], SlotKey { day_key: 100, slot: 1 }));
    assert_ne!(base, sync_seed("russia", &["nuxt", "nuxt2"], SlotKey { day_key: 100, slot: 0 }));
    assert_ne!(base, sync_seed("main", &["nuxt", "nuxt2", "senko"], SlotKey { day_key: 100, slot: 0 }));
}

#[test]
fn sync_seed_does_not_confuse_concatenated_names() {
    // Without a separator "ab" + "c" and "a" + "bc" hash identically, which
    // would silently merge two different fleets into one sync domain.
    let key = SlotKey { day_key: 100, slot: 0 };
    assert_ne!(sync_seed("main", &["ab", "c"], key), sync_seed("main", &["a", "bc"], key));
}
```

And a manager-level test in the same file. The two test modules are siblings
and share no private helpers, so copy `uplink()`
(`manager/tests/reselect.rs:23-52`), `probe()` (`:62-82`) and `lb()`
(`:84-136`) verbatim into this file's header along with their imports — `lb()`
already carries every `LoadBalancingConfig` field, including the
`reselect_sync: false` added in Task 1:

```rust
#[tokio::test]
async fn sync_order_is_a_full_permutation_and_agrees_across_managers() {
    let names = vec![uplink("a"), uplink("b"), uplink("c")];
    let one = manager_sync(names.clone());
    let two = manager_sync(names);
    let key = SlotKey { day_key: 100, slot: 0 };

    let order = one.sync_order(key);
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, vec![0, 1, 2], "every uplink must appear exactly once");
    assert_eq!(order, two.sync_order(key), "two nodes must derive the same order");
    assert_ne!(
        order,
        one.sync_order(SlotKey { day_key: 101, slot: 0 }),
        "a new day must be able to reshuffle"
    );
}
```

with the fixture:

```rust
/// Strict `active_passive` group with `reselect_sync` on and every uplink
/// pre-marked TCP-healthy (global scope gates on TCP).
fn manager_sync(uplinks: Vec<UplinkConfig>) -> UplinkManager {
    let cfg = LoadBalancingConfig {
        reselect_at: vec![(3, 20)],
        reselect_sync: true,
        ..lb()
    };
    let mgr = UplinkManager::new_for_test("main", uplinks, probe(), cfg).unwrap();
    for index in 0..mgr.uplinks().len() {
        mgr.inner.with_status_mut(index, |status| {
            status.tcp.healthy = Some(true);
        });
    }
    mgr
}
```

- [ ] **Step 2: Run them, expect failure**

Run: `cargo test -p outline-uplink sync_order`
Expected: FAIL — `sync_seed` / `sync_order` not found.

- [ ] **Step 3: Add the dependency.** In `crates/outline-uplink/Cargo.toml`,
  alphabetically in `[dependencies]` (after `base64`):

```toml
blake3 = "1.8"
```

- [ ] **Step 4: Implement** in `sync_order.rs`, above the `#[cfg(test)]` block:

```rust
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::penalty::weighted_permutation_with_rng;
use crate::types::UplinkManager;

/// BLAKE3 derive-key context. Bump the version suffix only for a deliberate,
/// fleet-wide reshuffle: changing it makes every node compute a new order, and
/// nodes on mixed builds disagree until all of them are updated.
const SYNC_SEED_CONTEXT: &str = "outline-ws-rust reselect-sync seed v1";

/// Seed shared by every node that agrees on `(group, uplink names, slot)`.
///
/// Names are NUL-separated so `["ab", "c"]` and `["a", "bc"]` cannot collide —
/// a collision would merge two configurations into one sync domain silently.
/// Nothing secret goes in: the order is derived from configuration, not from
/// credentials.
pub(crate) fn sync_seed(group: &str, uplink_names: &[&str], key: SlotKey) -> u64 {
    let mut hasher = blake3::Hasher::new_derive_key(SYNC_SEED_CONTEXT);
    hasher.update(group.as_bytes());
    hasher.update(&[0]);
    for name in uplink_names {
        hasher.update(name.as_bytes());
        hasher.update(&[0]);
    }
    hasher.update(&key.day_key.to_le_bytes());
    // `usize` is widened explicitly: the seed must not depend on the pointer
    // width of the node computing it.
    hasher.update(&(key.slot as u64).to_le_bytes());
    let digest = hasher.finalize();
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(head)
}

impl UplinkManager {
    /// Preference order for `key`: a permutation of every uplink index, most
    /// preferred first, weighted by the **configured** `weight` alone.
    ///
    /// Local penalty/health state is deliberately absent — it differs per node
    /// and would defeat the shared seed. Health filters this order later, in
    /// [`Self::sync_pick`].
    pub(crate) fn sync_order(&self, key: SlotKey) -> Vec<usize> {
        let names: Vec<&str> = self.inner.uplinks.iter().map(|u| u.name.as_str()).collect();
        let seed = sync_seed(self.group_name(), &names, key);
        let weights: Vec<f64> = self.inner.uplinks.iter().map(|u| u.weight.max(0.0)).collect();
        let mut rng = StdRng::seed_from_u64(seed);
        weighted_permutation_with_rng(&weights, &mut rng)
    }
}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p outline-uplink sync_order`
Expected: PASS (8 tests).

- [ ] **Step 6: Checkpoint** — `cargo clippy -p outline-uplink --all-targets --no-deps -- -D warnings`,
  then `git status --short`. Do not commit.

---

### Task 4: `sync_pick` — health-filtered winner with advisory exclusion

**Files:**
- Modify: `crates/outline-uplink/src/manager/sync_order.rs`
- Modify: `crates/outline-uplink/src/manager/tests/sync_order.rs`

**Interfaces:**
- Consumes: `sync_order` (Task 3);
  `crate::selection::{selection_health, cooldown_active, supports_transport_for_scope}`;
  `self.inner.admin_enabled(index)`; `self.inner.with_status(index, f)`.
- Produces:
  `UplinkManager::sync_pick(&self, key: SlotKey, gate: TransportKind, scope: RoutingScope, now: Instant) -> Option<usize>`.

- [ ] **Step 1: Write the failing tests** — append to
  `crates/outline-uplink/src/manager/tests/sync_order.rs`:

```rust
use tokio::time::Instant;

use crate::config::RoutingScope;
use crate::types::TransportKind;

/// The pick both nodes must reach: first healthy entry of the day's order,
/// minus the previous slot's deterministic winner.
fn expected_pick(mgr: &UplinkManager, key: SlotKey) -> usize {
    let excluded = mgr
        .sync_order(previous_slot_key(key, &[(3, 20)]))
        .first()
        .copied()
        .expect("non-empty group");
    mgr.sync_order(key)
        .into_iter()
        .find(|&i| Some(i) != Some(excluded))
        .expect("more than one uplink")
}

#[tokio::test]
async fn sync_pick_agrees_across_managers_and_skips_the_previous_winner() {
    let names = vec![uplink("a"), uplink("b"), uplink("c")];
    let one = manager_sync(names.clone());
    let two = manager_sync(names);
    let key = SlotKey { day_key: 100, slot: 0 };
    let now = Instant::now();

    let pick = one.sync_pick(key, TransportKind::Tcp, RoutingScope::Global, now);
    assert_eq!(pick, Some(expected_pick(&one, key)));
    assert_eq!(
        pick,
        two.sync_pick(key, TransportKind::Tcp, RoutingScope::Global, now),
        "independent nodes must reach the same pick"
    );
}

#[tokio::test]
async fn sync_pick_skips_an_unhealthy_leg() {
    let mgr = manager_sync(vec![uplink("a"), uplink("b"), uplink("c")]);
    let key = SlotKey { day_key: 100, slot: 0 };
    let now = Instant::now();
    let first = mgr.sync_pick(key, TransportKind::Tcp, RoutingScope::Global, now).unwrap();

    mgr.inner.with_status_mut(first, |status| {
        status.tcp.healthy = Some(false);
    });

    let after = mgr.sync_pick(key, TransportKind::Tcp, RoutingScope::Global, now).unwrap();
    assert_ne!(after, first, "a dead leg must not win its own slot");
}

#[tokio::test]
async fn sync_pick_drops_the_exclusion_rather_than_returning_nothing() {
    // Only the previously-winning uplink is healthy: both nodes must still
    // converge on it instead of reporting "no candidate" and drifting apart.
    let mgr = manager_sync(vec![uplink("a"), uplink("b")]);
    let key = SlotKey { day_key: 100, slot: 0 };
    let now = Instant::now();
    let excluded = mgr.sync_order(previous_slot_key(key, &[(3, 20)]))[0];
    for index in 0..mgr.uplinks().len() {
        if index != excluded {
            mgr.inner.with_status_mut(index, |status| {
                status.tcp.healthy = Some(false);
            });
        }
    }

    let pick = mgr.sync_pick(key, TransportKind::Tcp, RoutingScope::Global, now);
    assert_eq!(pick, Some(excluded), "advisory exclusion must yield to reality");
}

#[tokio::test]
async fn sync_pick_returns_none_when_everything_is_down() {
    let mgr = manager_sync(vec![uplink("a"), uplink("b")]);
    for index in 0..mgr.uplinks().len() {
        mgr.inner.with_status_mut(index, |status| {
            status.tcp.healthy = Some(false);
        });
    }
    let pick = mgr.sync_pick(
        SlotKey { day_key: 100, slot: 0 },
        TransportKind::Tcp,
        RoutingScope::Global,
        Instant::now(),
    );
    assert_eq!(pick, None);
}
```

- [ ] **Step 2: Run them, expect failure**

Run: `cargo test -p outline-uplink sync_pick`
Expected: FAIL — `sync_pick` not found.

- [ ] **Step 3: Implement** in `sync_order.rs`, inside the existing
  `impl UplinkManager` block:

```rust
    /// The uplink this slot selects on this node: the first entry of the
    /// shared order that is locally usable, skipping the previous slot's
    /// deterministic winner so a slot still rotates.
    ///
    /// The exclusion is advisory. Enforcing it when nothing else is healthy
    /// would leave the node either idle or on a stale leg while its twin sat
    /// on the one working uplink — exactly the divergence this feature exists
    /// to prevent — so it is dropped in that case.
    pub(crate) fn sync_pick(
        &self,
        key: SlotKey,
        gate: TransportKind,
        scope: RoutingScope,
        now: Instant,
    ) -> Option<usize> {
        let order = self.sync_order(key);
        let previous = previous_slot_key(key, &self.inner.load_balancing.reselect_at);
        let excluded = self.sync_order(previous).first().copied();
        self.first_eligible(&order, gate, scope, now, excluded)
            .or_else(|| self.first_eligible(&order, gate, scope, now, None))
    }

    /// First index of `order` that this node may actually use right now:
    /// administratively enabled, able to carry `gate` under `scope`, health-
    /// eligible and not cooling down. Mirrors the filter in
    /// `draw_reselect_candidate`, minus the weighting.
    fn first_eligible(
        &self,
        order: &[usize],
        gate: TransportKind,
        scope: RoutingScope,
        now: Instant,
        exclude: Option<usize>,
    ) -> Option<usize> {
        order.iter().copied().find(|&index| {
            if exclude == Some(index) || !self.inner.admin_enabled(index) {
                return false;
            }
            let uplink = &self.inner.uplinks[index];
            if !supports_transport_for_scope(uplink, gate, scope) {
                return false;
            }
            self.inner.with_status(index, |status| {
                selection_health(status, uplink, gate, now, scope, &self.inner.load_balancing)
                    && !cooldown_active(status, gate, now)
            })
        })
    }
```

with the imports at the top of the file:

```rust
use tokio::time::Instant;

use crate::config::RoutingScope;
use crate::selection::{cooldown_active, selection_health, supports_transport_for_scope};
use crate::types::TransportKind;
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p outline-uplink sync_`
Expected: PASS (12 tests).

- [ ] **Step 5: Checkpoint** — `cargo clippy -p outline-uplink --all-targets --no-deps -- -D warnings`,
  then `git status --short`. Do not commit.

---

### Task 5: Wire the flag into re-selection

**Files:**
- Modify: `crates/outline-uplink/src/manager/reselect.rs` (`reselect_global`
  ~line 352, `reselect_per_uplink` ~line 402)
- Modify: `crates/outline-uplink/src/manager/tests/reselect.rs`

**Interfaces:**
- Consumes: `sync_pick` (Task 4), `current_slot_key` (Task 2), and the existing
  private `local_day_and_secs` in this same file (`reselect.rs:142`).
- Produces: unchanged public surface — `reselect_active_uplink` /
  `reselect_active_uplink_with_rng` keep their signatures; only the internal
  target choice changes when `reselect_sync` is on. New outcome text:
  `ReselectOutcome::Skipped { reason: "already on the slot's uplink" }`.

- [ ] **Step 1: Write the failing tests** — append to
  `crates/outline-uplink/src/manager/tests/reselect.rs`, and add the local
  fixture (this file already has `uplink()`, `probe()`, `lb()`):

```rust
fn manager_sync(uplinks: Vec<UplinkConfig>) -> UplinkManager {
    let cfg = LoadBalancingConfig {
        reselect_at: vec![(3, 20)],
        reselect_sync: true,
        ..lb()
    };
    let mgr = UplinkManager::new_for_test("main", uplinks, probe(), cfg).unwrap();
    for index in 0..mgr.uplinks().len() {
        mgr.inner.with_status_mut(index, |status| {
            status.tcp.healthy = Some(true);
        });
    }
    mgr
}

#[tokio::test]
async fn sync_reselect_lands_two_nodes_on_the_same_uplink() {
    let names = vec![uplink("a"), uplink("b"), uplink("c")];
    let one = manager_sync(names.clone());
    let two = manager_sync(names);
    // Start them deliberately apart, the way a night of independent rotation
    // leaves the real fleet.
    one.initialize_strict_active_selection().await;
    two.set_active_uplink_by_name("c", None, false).await.unwrap();

    let mut rng = StdRng::seed_from_u64(1);
    one.reselect_active_uplink_with_rng("test", false, &mut rng).await;
    let mut rng = StdRng::seed_from_u64(999); // a different local RNG must not matter
    two.reselect_active_uplink_with_rng("test", false, &mut rng).await;

    let left = one.active_uplinks_snapshot().global.expect("selected");
    let right = two.active_uplinks_snapshot().global.expect("selected");
    assert_eq!(
        one.uplinks()[left].name,
        two.uplinks()[right].name,
        "reselect_sync must converge independent nodes"
    );
}

#[tokio::test]
async fn sync_reselect_is_idempotent_within_a_slot() {
    let mgr = manager_sync(vec![uplink("a"), uplink("b"), uplink("c")]);
    let mut rng = StdRng::seed_from_u64(1);
    mgr.reselect_active_uplink_with_rng("test", false, &mut rng).await;
    let first = mgr.active_uplinks_snapshot().global;

    let outcome = mgr.reselect_active_uplink_with_rng("test", false, &mut rng).await;
    assert!(
        matches!(outcome, ReselectOutcome::Skipped { .. }),
        "re-applying the same slot decision must not move the slot: {outcome:?}"
    );
    assert_eq!(mgr.active_uplinks_snapshot().global, first);
}

#[tokio::test]
async fn sync_reselect_reports_no_candidate_when_everything_is_down() {
    let mgr = manager_sync(vec![uplink("a"), uplink("b")]);
    for index in 0..mgr.uplinks().len() {
        mgr.inner.with_status_mut(index, |status| {
            status.tcp.healthy = Some(false);
        });
    }
    let mut rng = StdRng::seed_from_u64(1);
    let outcome = mgr.reselect_active_uplink_with_rng("test", false, &mut rng).await;
    assert!(matches!(outcome, ReselectOutcome::NoCandidate), "got {outcome:?}");
}
```

`set_active_uplink_by_name(name, transport: Option<TransportKind>, soft: bool)`
lives in `crates/outline-uplink/src/manager/candidates.rs:1203` and returns
`Result<(usize, bool)>`; `None` transport moves the global slot, which is what
this fixture needs.

- [ ] **Step 2: Run them, expect failure**

Run: `cargo test -p outline-uplink sync_reselect`
Expected: FAIL — the two managers land on different uplinks (the OS-seeded draw
is still in force) and the idempotence test sees a second move.

- [ ] **Step 3: Implement** — in `reselect_global`, replace the target
  computation (currently `let Some(target) = self.draw_reselect_candidate(...)`):

```rust
        let current = self.inner.active_uplinks.read().await.global;
        let target = if self.inner.load_balancing.reselect_sync {
            let Some(target) = self.sync_target(gate, scope) else {
                return ReselectOutcome::NoCandidate;
            };
            if current == Some(target) {
                return ReselectOutcome::Skipped { reason: "already on the slot's uplink" };
            }
            target
        } else {
            let Some(target) = self.draw_reselect_candidate(gate, scope, current, rng) else {
                return ReselectOutcome::NoCandidate;
            };
            target
        };
```

and extend the existing `info!` with the mode so two nodes can be compared from
logs alone:

```rust
        info!(
            group = %self.inner.group_name,
            from = ?from,
            to = %to,
            soft,
            reason,
            sync = self.inner.load_balancing.reselect_sync,
            "weighted re-selection moved the strict active uplink (global)",
        );
```

In `reselect_per_uplink`, do the same for each transport — replace
`let tcp_target = self.draw_reselect_candidate(tcp_gate, scope, cur_tcp, rng);`
(and the UDP twin) with:

```rust
        let sync = self.inner.load_balancing.reselect_sync;
        let tcp_target = if sync {
            self.sync_target(tcp_gate, scope).filter(|&t| cur_tcp != Some(t))
        } else {
            self.draw_reselect_candidate(tcp_gate, scope, cur_tcp, rng)
        };
        let udp_target = if sync {
            self.sync_target(udp_gate, scope).filter(|&t| cur_udp != Some(t))
        } else {
            self.draw_reselect_candidate(udp_gate, scope, cur_udp, rng)
        };
```

Under `sync`, "no move needed" and "nothing eligible" both collapse to `None`
here, so a fully-converged per-uplink group reports `NoCandidate` rather than
`Skipped`. That is acceptable: the fleet configuration this feature targets is
`routing_scope = "global"`, and both outcomes are no-ops. Note it in the
method's doc comment.

Add the small resolver next to `draw_reselect_candidate`:

```rust
    /// Today's slot decision for `gate`, or `None` when the clock is
    /// unreadable, no slots are configured (the loader forbids that with
    /// `reselect_sync`) or nothing is currently eligible.
    fn sync_target(&self, gate: TransportKind, scope: RoutingScope) -> Option<usize> {
        let (day_key, secs) = local_day_and_secs()?;
        let key = current_slot_key(day_key, secs, &self.inner.load_balancing.reselect_at)?;
        self.sync_pick(key, gate, scope, Instant::now())
    }
```

with imports in `reselect.rs`:

```rust
use crate::manager::sync_order::current_slot_key;
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p outline-uplink reselect`
Expected: PASS — the three new tests plus every pre-existing reselect test
(the flag defaults to `false`, so the old behaviour is untouched).

- [ ] **Step 5: Checkpoint** — `cargo clippy -p outline-uplink --all-targets --no-deps -- -D warnings`,
  then `git status --short`. Do not commit.

---

### Task 6: Startup selection under the flag

**Files:**
- Modify: `crates/outline-uplink/src/manager/mod.rs`
  (`initialize_strict_active_selection`, lines 43–101)
- Modify: `crates/outline-uplink/src/manager/tests/reselect.rs`

**Interfaces:**
- Consumes: `reselect_active_uplink` (Task 5).
- Produces: no new API. Behaviour: with `reselect_sync`, startup probes and
  then applies the slot decision, overriding any restored-from-state active.

- [ ] **Step 1: Write the failing test** — append to
  `crates/outline-uplink/src/manager/tests/reselect.rs`:

```rust
#[tokio::test]
async fn sync_startup_overrides_a_restored_active_uplink() {
    // A node restarting mid-day restores the leg it was last on. Under
    // reselect_sync that leg is exactly what must NOT come back: it may be a
    // failover leftover its twin never followed.
    let uplinks = vec![uplink("a"), uplink("b"), uplink("c")];
    let cfg = LoadBalancingConfig {
        reselect_at: vec![(3, 20)],
        reselect_sync: true,
        ..lb()
    };
    let restored = UplinkManager::new_with_state(
        "main",
        uplinks.clone(),
        probe(),
        cfg.clone(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
        None,
        Some("c".to_string()),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    for index in 0..restored.uplinks().len() {
        restored.inner.with_status_mut(index, |status| {
            status.tcp.healthy = Some(true);
        });
    }
    assert_eq!(restored.active_uplinks_snapshot().global, Some(2), "fixture starts on \"c\"");

    restored.initialize_strict_active_selection().await;

    let fresh = manager_sync(uplinks);
    fresh.initialize_strict_active_selection().await;
    assert_eq!(
        restored.active_uplinks_snapshot().global,
        fresh.active_uplinks_snapshot().global,
        "a restarted node must land where a fresh one does"
    );
}
```

- [ ] **Step 2: Run it, expect failure**

Run: `cargo test -p outline-uplink sync_startup`
Expected: FAIL — the restored manager stays on `"c"` (index 2) because the
current code returns early for an already-selected active slot.

- [ ] **Step 3: Implement** — at the top of
  `initialize_strict_active_selection`, after the strict-scope guard
  (`crates/outline-uplink/src/manager/mod.rs:44-46`) and **before** the
  `already_selected` probe-skip logic:

```rust
        // Under `reselect_sync` the slot decision — not the state store — owns
        // the choice. A restored active is precisely the mid-day leg a restart
        // must not resurrect (see `manager/sync_order.rs`), so probe first and
        // then apply the slot decision, overriding whatever was restored.
        // Probing is unconditional here: the ordinary path may skip it because
        // a restored selection is already made, but a slot decision needs
        // health to be known before it can pick.
        if self.inner.load_balancing.reselect_sync {
            if self.inner.probe.enabled() {
                self.probe_all().await;
            }
            self.reselect_active_uplink("startup_sync", true).await;
            return;
        }
```

Note in the doc comment that this path records one
`outline_ws_uplink_reselect_total{outcome}` sample at startup — intended, it
makes "which leg did this node boot onto" visible without a new metric.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p outline-uplink`
Expected: PASS — the new startup test plus the whole crate's suite.

- [ ] **Step 5: Checkpoint** — full CI gate from Global Constraints, then
  `git status --short`. Do not commit.

---

### Task 7: Documentation (EN + RU)

**Files:**
- Modify: `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md` (key table
  ~line 613, "Scheduled re-selection" section ~line 766) and
  `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.ru.md` (same places)
- Modify: `bins/outline-ws-rust/README.md` (feature list ~line 154, detail
  ~line 829) and `bins/outline-ws-rust/README.ru.md`
- Modify: `bins/outline-ws-rust/CHANGELOG.md` and `CHANGELOG.ru.md` (top
  Unreleased section)
- Modify: `bins/outline-ws-rust/config.toml` (commented example next to the
  `reselect_at` example)

**Interfaces:**
- Consumes: the final behaviour from Tasks 1–6. No code changes here.

- [ ] **Step 1: Key table row** — in `UPLINK-CONFIGURATIONS.md`, after the
  `reselect_interval` row:

```markdown
| `reselect_sync`                      | `false`            | bool  | derive the scheduled re-selection order deterministically from group name, uplink names, local day and slot index, so independent nodes sharing this group config pick the same uplink. Requires `reselect_at`. See "Synchronized re-selection" below |
```

- [ ] **Step 2: New section** after "Scheduled re-selection":

````markdown
**Synchronized re-selection (`reselect_sync`).**

```toml
[[uplink_group]]
name = "main"
mode = "active_passive"
reselect_at = ["03:20"]
reselect_sync = true
```

Two nodes that serve the same users — a cloned pair behind one hostname, say —
normally rotate independently: each seeds its own draw from the OS, so after
the first slot they sit on different uplinks and their clients leave from
different egress addresses. `reselect_sync` replaces the draw with a function
of data both nodes already have: the group name, the uplink names, the local
calendar day and the slot index, hashed into a seed and turned into a full
preference order. The active uplink is the first entry of that order which is
healthy *on this node*.

- **No coordination.** Nothing is exchanged between the nodes; a dead
  neighbour changes nothing.
- **Health stays local.** A node whose leg dies fails over immediately, on its
  own. If only one node sees the failure, the two diverge until the next slot —
  there is no intra-day re-convergence.
- **Rotation is preserved** by excluding the previous slot's deterministic
  winner. The exclusion is dropped when it would leave nothing healthy.
- **Startup follows the slot, not the state store.** A restarted node lands
  where a freshly started one does, instead of resuming the leg it happened to
  be on.
- **`POST /control/reselect` becomes idempotent within a slot**: it re-applies
  today's decision (outcome `skipped` when already correct) rather than drawing
  something new. Pressing it on both nodes is the fastest way to converge them
  without waiting for the next slot.

Requirements and caveats: `reselect_at` is mandatory (`reselect_interval` fires
relative to each process's own start and cannot agree); all nodes of one sync
domain must share a timezone, since slots and the day key are local time; and
the uplink list is part of the seed, so adding a leg on one node only moves it
into a different sync domain. The order is derived from configuration, not from
secrets — it is reproducible by anyone who knows the uplink names.
````

- [ ] **Step 3: Mirror both edits into `UPLINK-CONFIGURATIONS.ru.md`** at the
  same anchors, in Russian, keeping code/keys in Latin script. Per the
  repository's terminology rules do not calque technical terms: "sync domain" →
  «домен синхронизации», "slot" → «слот», "seed" → «сид».

- [ ] **Step 4: README (EN + RU)** — extend the scheduled-re-selection bullet
  (~line 154 EN) with:

```markdown
  `reselect_sync = true` makes the rotation deterministic instead of random, so independent nodes sharing a group config land on the same uplink (one egress address for a shared client population) with no coordination between them.
```

and add this paragraph after the `**Scheduled re-selection:**` block
(~line 829):

```markdown
**Synchronized re-selection:** `load_balancing.reselect_sync = true` (requires `reselect_at`) replaces the weighted-random draw with a deterministic one: the slot's preference order is derived from the group name, the uplink names, the local calendar day and the slot index, and the active uplink becomes the first entry of that order that is healthy on this node. Independent nodes carrying the same group config therefore choose the same uplink without exchanging anything, which keeps a client population that reaches either node on a single egress address. Health, cooldown and admin state stay local — a node whose leg dies fails over immediately, and if only one node sees the failure the pair stays split until the next slot. Startup applies the slot decision over any restored-from-state active, and `POST /control/reselect` becomes idempotent within a slot. All nodes of one sync domain must share a timezone. See [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md) "Synchronized re-selection".
```

Mirror it into `README.ru.md` at the same anchor, in Russian.

- [ ] **Step 5: CHANGELOG (EN + RU)** — one entry under the unreleased
  heading, following the existing entry style (problem → mechanism → caveats):

```markdown
- **Deterministic, cross-node-agreeing scheduled re-selection (`load_balancing.reselect_sync`, requires `reselect_at`).** Nodes sharing a group config rotated independently — each seeded its draw from the OS and excluded its own current active — so a cloned pair drifted onto different uplinks after the first slot and its clients left from different egress addresses. With the flag on, the slot's order is derived from `(group name, uplink names, local day, slot index)` via BLAKE3 and the configured `weight` alone, and the active uplink is the first entry of that order that is healthy locally. Nothing is exchanged between nodes. Health, cooldown and admin state stay local, so a node whose leg dies still fails over immediately — and if only one node sees the failure the pair diverges until the next slot (there is no intra-day re-convergence). Rotation is preserved by excluding the previous slot's deterministic winner, dropped when it would leave nothing healthy. Startup applies the slot decision over any restored-from-state active, so a restart cannot resurrect a mid-day leg. `POST /control/reselect` becomes idempotent within a slot (outcome `skipped` when already correct). Requires all nodes of a sync domain to share a timezone.
```

- [ ] **Step 6: `config.toml` example** — next to the existing commented
  `reselect_at` line:

```toml
# reselect_sync = true            # same choice on every node with this group config
```

- [ ] **Step 7: Verify docs parity**

Run: `rg -c "reselect_sync" bins/outline-ws-rust/README.md bins/outline-ws-rust/README.ru.md bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.ru.md bins/outline-ws-rust/CHANGELOG.md bins/outline-ws-rust/CHANGELOG.ru.md`
Expected: every file listed with a non-zero count.

- [ ] **Step 8: Full CI gate** — run all four commands from Global Constraints,
  then `git status --short`. Do not commit.

---

### Task 8: Fleet rollout (owner-gated, not part of the code change)

**Files:**
- Modify (on the nodes, not in the repo): `/etc/outline-ws-rust/config.toml` on
  `cloud1` and `cloud2`

**Interfaces:**
- Consumes: a built `outline-ws-rust` binary carrying Tasks 1–6.

> **Do not start this task without the owner's explicit go-ahead for each
> node.** Restarting a client node breaks the neighbour's uplink leg
> (`fleet-mutual-uplink-topology`), and the fleet rule is one node at a time.

- [ ] **Step 1: Build** — `cargo ws-release-musl-x86_64` (both nodes are
  x86_64 Ubuntu 24.04). Confirm the target triple against
  `ssh sysadm@cloud1.beerloga.su uname -m` before deploying.
- [ ] **Step 2: Deploy to `cloud1`** via `ops/deploy/deploy-binary.sh` (it
  backs up, rotates and auto-reverts on a failed health check).
- [ ] **Step 3: Add the flag on `cloud1`** — in the `[[uplink_group]]` block
  named `main`, next to `reselect_at`:

```toml
reselect_sync = true
```

Edit with `sudo sh -c "cat new > config.toml"`, not `sudo tee <` and not `cp`:
the file is `640 outline-ws-rust:outline-ws-rust` and the redirect form reads
it without sudo. `reselect_sync` is read at group build time, so it needs a
restart or `/control/apply` — same as `reselect_at`.

- [ ] **Step 4: Verify `cloud1` alone** — the node logs
  `weighted re-selection ... sync=true` on the manual trigger:

```bash
curl -s -XPOST localhost:9191/control/reselect -d '{"group":"main"}' -H 'content-type: application/json'
```

- [ ] **Step 5: Repeat Steps 2–4 for `cloud2`** — only after `cloud1` is
  confirmed healthy, and only with fresh owner approval.
- [ ] **Step 6: Confirm convergence** — on both nodes:

```bash
curl -s localhost:9091/metrics | rg '^outline_ws_uplink_open_connections\{group="main"'
```

Expected: the same `uplink=` label on both. Re-check after the next 03:20 slot,
and confirm `outline_ws_uplink_reselect_total{outcome="switched"}` advanced on
both nodes in the same window.

---

## Self-Review Notes

Spec coverage check performed against
`docs/superpowers/specs/2026-08-11-synchronized-uplink-reselect-design.md`:

| Spec section | Task |
|---|---|
| Config (`reselect_sync`, gating, sync domain) | 1 |
| Deterministic daily order (seed, weights, order) | 2, 3 |
| Winner + advisory exclusion | 4 |
| Idempotent no-op / manual trigger | 5 |
| Startup selection incl. persisted override + probe | 6 |
| Failover unchanged (flag-off path untouched) | 5 (regression tests) |
| Observability (`sync` in the log line, no new metric) | 5 |
| Docs EN+RU | 7 |
| Rollout | 8 |

Deliberately **not** implemented, per the spec: `reselect_sync_key` (YAGNI),
intra-day convergence, and any change to the `russia` group or to `.102`/`.104`.
