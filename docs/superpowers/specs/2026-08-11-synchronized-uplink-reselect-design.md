# Synchronized uplink reselection (design)

Date: 2026-08-11
Status: approved by owner (chat)

## Goal

Two client nodes that serve the same external users (`cloud1`, `cloud2` — clones
with an identical `main` group) must keep the **same active uplink**, so a
third-party client (happ / Outline) leaves for the internet from one public
address no matter which node it happened to reach.

Agreement is reached by **determinism, not by communication**: each node
computes the same daily preference order on its own. No tunnel between the
nodes, no coordinator, no shared state — a dead neighbour changes nothing.

## Non-goals

- **Not** the server-side mesh cluster (`[cluster]` in `outline-ss-rust`). It
  routes to a home shard only for a presented resume id (`cluster::decide`
  returns `Local` for `resume_id: None`), and external happ/Outline clients
  never present one. It solves session continuity, not ingress pinning.
- No tunnel / anycast between `cloud1` and `cloud2`, no external coordinator
  driving `/control/activate`.
- No intra-day convergence: nodes that diverge mid-day re-converge at the next
  `reselect_at` slot, not before. Accepted by the owner as the price of fewer
  switches.
- No change to failover, health, loss or cooldown logic.
- No behaviour change where the flag is off — `.102` / `.104` keep their
  staggered, independent rotation.
- No change to the `russia` group (no rotation there; both nodes already agree).

## Background — why the nodes diverge today

Both nodes carry the same `main` group: `mode = "active_passive"`,
`auto_failback = false`, `reselect_at = ["03:20"]`, `shared_resume = true`.
Three independent sources of locality make the nightly rotation disagree:

- `reselect_active_uplink` seeds `StdRng::from_os_rng()`
  (`manager/reselect.rs`) — the draw is independent per node.
- `draw_reselect_candidate` excludes **the current active** — which is already
  different once the nodes have diverged, so divergence is self-sustaining.
- Candidate weights use `penalty_weight(...)` — accumulated local health state.

Observed on 2026-08-11: `cloud1` on `nuxt`, `cloud2` on `nuxt2`, i.e. two
different egress addresses for the same user population.

## Config (per-group `load_balancing`)

- `reselect_sync = true` — new bool, default `false`.
- Valid only with `mode = "active_passive"` and a non-empty `reselect_at`;
  any other combination is a validation error. In particular
  `reselect_interval` is rejected: its monotonic timer fires relative to
  process start, so two nodes rotate at different wall-clock instants and a
  shared seed would not make them agree.
- The **sync domain** is `(group name, uplink names)` — no new secret. Nodes
  whose group carries the same name and the same uplink list agree; a node with
  a different uplink set is automatically in a different domain.
- Nodes in one sync domain must share a timezone (slots and the day key are
  local time). `cloud1` / `cloud2` are both `Europe/Moscow`.

## Deterministic daily order

Replaces the OS-seeded draw when `reselect_sync` is on:

- **Seed**: `blake3::derive_key("outline-ws-rust reselect-sync v1", …)` over
  `group_name`, the uplink names in configured order, the local `day_key` and
  the slot index; first 8 bytes feed `StdRng::seed_from_u64`.
- **Weights**: configured `uplink.weight` only. `penalty_weight` and
  `health_weight_floor` are deliberately excluded — they are per-node state and
  would defeat the shared seed.
- **Order**: `weighted_permutation_with_rng` (already in `penalty.rs`) turns
  those weights into a full preference order, not a single pick.
- **Winner**: the first uplink of that order which is locally `admin_enabled`,
  passes `selection_health` and is not in cooldown. Health stays strictly local
  — this is what lets a node abandon a dead leg without waiting for anyone.
- **Rotation is preserved** by excluding the *deterministic* winner of the
  previous slot: `order[0]` computed for the previous slot index (or the last
  slot of `day_key - 1` for the first slot of a day), taken **without** any
  health filtering so every node computes the same exclusion. This replaces
  "exclude the current active", which is itself a divergence source.
- The exclusion is **advisory**: if dropping it is the only way to have a
  healthy candidate, it is dropped, so both nodes still land on the single
  surviving leg. Only when no uplink is healthy at all does the outcome stay
  `NoCandidate` (unchanged no-op semantics).
- The commit path is untouched: slot move + sticky reseed, no
  `reset_all_uplink_statuses`, soft bit clamped by `shared_resume` as today.
- The manual `POST /control/reselect` goes through the same order, which makes
  it **idempotent within a slot**: pressing it twice on one node does not move
  the leg again, and pressing it on both nodes converges them. That is a
  deliberate consequence — under this flag the button means "re-apply today's
  decision", not "draw something new".

## Startup selection

With `reselect_sync` on, initial strict selection (process start and
`/control/apply` re-spawn) takes the active uplink from **today's order**
instead of `initial_strict_order`. Without this, every binary rollout or VPS
reboot re-splits the pair immediately. This places no live traffic — it is the
first choice, not a mid-day migration — so it does not contradict the
"wait for the next slot" decision above.

## Failover stays local

Health-, loss- and cooldown-driven failover is unchanged: immediate, local, no
coordination. `auto_failback = false` stays as configured, and there is no
intra-day return to the daily leg. A one-sided failover therefore leaves the
nodes on different legs until the next slot — accepted.

## Observability

- `outline_ws_uplink_reselect_total{group, outcome}` keeps its existing labels
  and outcomes; no new metric.
- The `info!` line emitted on a move gains `sync = true` and the resolved order,
  so two nodes can be compared from logs alone after a rotation.

## Risks

- **Simultaneous rotation.** The pair loses its stagger and now migrates at the
  same instant. `shared_resume` is on for `main`, so sessions migrate softly.
- **Predictable order.** The daily order derives from group and uplink names
  plus the date — no secret material, but also no longer unpredictable to
  anyone who knows the config. Follow-up if it ever matters: an optional
  `reselect_sync_key` mixed into the seed. Not implemented (YAGNI).
- **One-sided divergence** (a leg blocked from only one provider) persists for
  up to a day. This is the owner's explicit trade-off, not an oversight.
- **Config drift** between the two nodes silently splits the sync domain — the
  uplink list is part of the seed, so an extra leg on one node changes its
  whole order. Verification below is the guard.

## Tests

Unit tests live in `tests/` subdirs next to the modules, per repo convention.

- Seed/order determinism: identical inputs → identical order; a different
  `day_key`, group name or uplink list → different order.
- Previous-slot exclusion: computed without health, stable across nodes;
  dropped when it would leave no healthy candidate.
- Winner selection: first healthy in order; disabled / unhealthy / cooling-down
  legs skipped; all-unhealthy → `NoCandidate`.
- Startup selection uses today's order under the flag, `initial_strict_order`
  without it.
- Config: default `false`, `active_passive` gate, `reselect_at` requirement,
  `reselect_interval` rejection.
- Existing seeded-RNG reselect tests keep passing unchanged (flag off).

## Docs

EN + RU in the same change: `UPLINK-CONFIGURATIONS.md(.ru)` (key table + a
section on the sync domain and its timezone requirement), `README.md(.ru)`
feature list, `config.toml` example, `CHANGELOG.md(.ru)`.

## Rollout

1. Build `outline-ws-rust` (musl) and deploy via `ops/deploy/deploy-binary.sh`
   to `cloud1` and `cloud2` only.
2. Add `reselect_sync = true` to the `main` group on both nodes; leave `.102` /
   `.104` untouched.
3. Optional immediate convergence: `POST /control/reselect` on both — under the
   flag the manual trigger uses the same daily order, so both land on the same
   leg without waiting for 03:20.
4. Verify: `outline_ws_uplink_open_connections{group="main"}` names the same
   uplink on both nodes, and again after the next 03:20 slot.
