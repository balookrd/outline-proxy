# Scheduled uplink reselection (design)

Date: 2026-07-27
Status: approved by owner (chat)

## Goal

Automatic periodic re-selection of the active uplink in strict (`active_passive`)
groups: random but weighted by probe quality, on a wall-clock schedule
(`03:00`, `10:10`) or a fixed interval (`10h`), using the existing soft-switch
mechanism when available (`shared_resume`), falling back to a hard switch
otherwise. Plus a manual trigger endpoint.

## Non-goals

- No changes to non-strict load-balancing modes (per-flow/per-client/per-uplink).
- No UDP soft-migration work (soft bit is TCP-pinned-relay-only today; unchanged).
- No new external dependencies (no chrono/time crates).

## Config (per-group `load_balancing`)

- `reselect_at = ["03:00", "10:10"]` — list of `HH:MM`, system local time.
- `reselect_interval = "10h"` — human-readable duration (`parse_human_duration`),
  monotonic timer from loop start / previous firing.
- Mutually exclusive: both set → validation error (`bail!`).
- Neither set → feature disabled (default).
- Only valid with `mode = "active_passive"`; any other mode → validation error.
- No `reselect_soft` key: the scheduler always requests soft; it is clamped to
  hard when `shared_resume` is off (existing clamp), i.e. "soft-switch when
  available".

## Reselection semantics (forced move)

New manager method `reselect_active_uplink(reason, soft)`:

- Candidates: all uplinks of the group **except the current active global
  slot**, filtered by `admin_enabled`, `selection_health`, and not in cooldown.
- Weight: `penalty_weight(penalty) × uplink.weight`, with existing
  `health_weight_floor` (same formula as wire/carrier health-weighting).
- Winner via `weighted_pick_with_rng`; committed for both transports
  (global slot) through `set_active_uplink_index_for_transport` with reason
  `scheduled_reselect` / `manual_reselect` and `soft = requested && shared_resume`.
- **No** `reset_all_uplink_statuses()` — follow the carrier-degraded-failover
  precedent, not the manual `/control/activate` path: planned rotation must not
  wipe accumulated health/EWMA/penalty state.
- No healthy candidate besides current → no-op, outcome `no_candidate`.

## Scheduler

- `UplinkRegistry::spawn_reselect_timer_loops` modeled on
  `spawn_shuffle_timer_loops`; group-scoped shutdown (dies on `/control/apply`,
  respawned by `apply_new_groups`); one call added in `bootstrap/mod.rs`.
- Interval mode: `tokio::select! { shutdown / sleep(interval) }`.
- Wall-clock mode (first in repo, no new deps): local time via
  `libc::localtime_r` (single `unsafe` with a concrete `// SAFETY:` per the
  `undocumented_unsafe_blocks` gate). Loop sleeps in ≤60 s steps and compares
  `SystemTime` against the nearest `HH:MM` slot — survives NTP jumps, DST
  changes and suspend. A slot missed during sleep does not fire retroactively
  (fire only within ±90 s tolerance, double-fire guarded by "date+slot" memory).
- Next-slot computation is a pure helper under unit tests.

## Manual trigger

- `POST /control/reselect`, JSON `{"group": "...", "soft": true?}` (default
  true) next to `/control/activate`, body via `read_limited_body`.
  Response: `{group, outcome, from, to, soft}`.
- Dashboard API proxy + "⟳ Reselect" button in topology, following the
  existing "⇄ Soft switch" pattern.

## Observability

- Counter `outline_ws_uplink_reselect_total{group, outcome}` with outcomes
  `switched` / `no_candidate` / `skipped`; registered via `register_labeled!`
  with a mandatory stub twin. Existing `record_soft_switch`/`record_failover`
  keep counting the maneuver itself.
- Exposition-text test case in `crates/outline-metrics/src/tests/`.
- Grafana: panels for `outline_ws_uplink_reselect_total` (rate by outcome +
  last-switch table/timeline) in
  `bins/outline-ws-rust/grafana/outline-ws-rust-dashboard.json`, placed near
  the existing failover/soft-switch panels.

## Docs & tests

- EN+RU in the same change: `UPLINK-CONFIGURATIONS.md(.ru)` (LB key table +
  new section), `README.md(.ru)` (features + control endpoint list),
  `config.toml` example, `CHANGELOG.md(.ru)`.
- Tests in `tests/` subdirs next to modules: config parse/validation
  (mutual exclusion, `HH:MM`, mode gate), candidate filtering & weights
  (deterministic RNG), next-slot wall-clock helper, `/control/reselect`
  handler.
