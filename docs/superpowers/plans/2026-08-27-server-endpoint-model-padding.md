# Server endpoint model + padding-as-attribute — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the server's per-user path model with a startup-only global endpoint list `[[endpoint]]{path, kind, padded}`; users become pure credentials that work on every endpoint of their kind; carrier-padding becomes an endpoint attribute instead of a separate `[padding] paths` list.

**Architecture:** A new `EndpointConfig{path, kind: EndpointKind, padded}` is the single source of truth for carrier paths. One route-building helper turns the endpoint list + the global user pools (SS `UserKey`s, VLESS `VlessUser`s) into the six `RouteRegistry` maps; both `services.rs` (startup) and `control/manager.rs` (live user mutation) call it. The `bootstrap/axum.rs` router and H3 frozen path-sets are unchanged — they already iterate `RouteRegistry.keys()`. Padding's process-global resolver is unchanged; only the source of its padded-path set moves from `[padding].paths` to the endpoints with `padded = true`.

**Tech Stack:** Rust (edition 2024), tokio, axum, serde/toml, Cargo workspace `outline-proxy`. Binary touched: `outline-ss-rust`. Client e2e in `outline-ws-rust/tests` are updated to the new server config format.

**Design doc:** `docs/superpowers/specs/2026-08-27-server-endpoint-model-padding-design.md`

## Global Constraints

- Tests live in `<dir>/tests/<basename>.rs` wired with `#[cfg(test)] #[path = "tests/<basename>.rs"] mod tests;` — never inline `#[cfg(test)] mod tests { … }`.
- Code comments, commit messages and PR text in English; chat and reasoning in Russian.
- Never add a `Co-Authored-By: Claude` trailer or a "Generated with Claude Code" footer to anything.
- Commit each task when its gate is green, using the message given in that task's final step. **Never `git push`** — that needs a separate explicit command from the owner, every time.
- Work directly on `main`. Do not create feature branches.
- CI gate, run locally in this exact order before any commit:
  ```bash
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  cargo test --workspace --exclude sockudo-ws
  ```
  Plus, since this touches feature-gated code paths: `cargo check -p outline-ss-rust --no-default-features`.
- `rustfmt.toml` sets 100 columns; do not reformat `vendor/*`.
- Every `unsafe` block carries a concrete `// SAFETY:` comment. This plan adds none.
- User-facing docs are bilingual: any change to `*.md` needs the matching `*.ru.md` in the same commit.
- This change is **breaking for the server config**: old `[websocket] ws_path_*` / `[[users]] ws_path_*` / `[padding] enabled|paths` stop parsing (`deny_unknown_fields`). Production node configs are rewritten by hand at deploy time, one node at a time. No production restart, deploy, or `POST /control/apply` without explicit owner approval, every single time.
- `EndpointKind` → route-map targets (memorize; used across Tasks 2, 4, 5):
  | kind | maps | user pool |
  |---|---|---|
  | `ws_ss` (combined) | `tcp` + `udp` | SS |
  | `ws_ss_tcp` | `tcp` | SS |
  | `ws_ss_udp` | `udp` | SS |
  | `ws_vless` | `vless` | VLESS |
  | `xhttp_ss` (combined) | `xhttp_ss` + `xhttp_ss_udp` | SS |
  | `xhttp_ss_tcp` | `xhttp_ss` | SS |
  | `xhttp_ss_udp` | `xhttp_ss_udp` | SS |
  | `xhttp_vless` | `xhttp_vless` | VLESS |

---

### Task 1: `EndpointKind` + `[[endpoint]]` parsing (additive)

Introduce the endpoint types and parse them. Nothing consumes them yet; old path fields still work, so the tree compiles and every existing test still passes.

**Files:**
- Create: `bins/outline-ss-rust/src/config/endpoint.rs`
- Create: `bins/outline-ss-rust/src/config/tests/endpoint.rs`
- Modify: `bins/outline-ss-rust/src/config/mod.rs` (add `mod endpoint;` + re-export `EndpointConfig`, `EndpointKind`)
- Modify: `bins/outline-ss-rust/src/config/file.rs` (add `EndpointSection` + `endpoints` field on `FileConfig` at :12-49)
- Modify: `bins/outline-ss-rust/src/config/resolved.rs` (add `endpoints: Vec<EndpointConfig>` to `Config` at :41-164)
- Modify: `bins/outline-ss-rust/src/config/loader.rs` (resolve `endpoints` in the `Config { … }` literal at :87-178)

**Interfaces:**
- Produces:
  - `EndpointKind` (enum, `Copy`): `WsSs, WsSsTcp, WsSsUdp, WsVless, XhttpSs, XhttpSsTcp, XhttpSsUdp, XhttpVless`, `#[serde(rename_all = "snake_case")]`.
    - `fn is_ss(self) -> bool` (all `*_ss*` variants), `fn is_vless(self) -> bool`.
    - `fn is_combined(self) -> bool` (`WsSs | XhttpSs`).
  - `EndpointConfig { pub path: String, pub kind: EndpointKind, pub padded: bool }`.
  - `EndpointSection` (`pub(super)`, `Deserialize`, `deny_unknown_fields`) with `path: String`, `kind: EndpointKind`, `#[serde(default)] padded: bool`.
  - `Config.endpoints: Vec<EndpointConfig>` — consumed by Tasks 2, 3, 4, 5.

- [ ] **Step 1: Write the failing test**

Create `bins/outline-ss-rust/src/config/tests/endpoint.rs`:

```rust
use super::super::endpoint::{EndpointKind, EndpointSection};

#[test]
fn kind_parses_snake_case_and_reports_family() {
    let s: EndpointSection =
        toml::from_str(r#"path = "/pss"
kind = "ws_ss"
padded = true"#)
            .unwrap();
    assert_eq!(s.path, "/pss");
    assert_eq!(s.kind, EndpointKind::WsSs);
    assert!(s.padded);
    assert!(s.kind.is_ss() && s.kind.is_combined() && !s.kind.is_vless());
}

#[test]
fn padded_defaults_to_false() {
    let s: EndpointSection = toml::from_str(r#"path = "/tcp"
kind = "ws_ss_tcp""#)
        .unwrap();
    assert!(!s.padded);
    assert!(!s.kind.is_combined());
}

#[test]
fn unknown_field_is_rejected() {
    let err = toml::from_str::<EndpointSection>(r#"path = "/x"
kind = "ws_vless"
padde = true"#)
        .unwrap_err();
    assert!(err.to_string().contains("padde") || err.to_string().contains("unknown"));
}

#[test]
fn all_eight_kinds_round_trip() {
    for (s, k) in [
        ("ws_ss", EndpointKind::WsSs),
        ("ws_ss_tcp", EndpointKind::WsSsTcp),
        ("ws_ss_udp", EndpointKind::WsSsUdp),
        ("ws_vless", EndpointKind::WsVless),
        ("xhttp_ss", EndpointKind::XhttpSs),
        ("xhttp_ss_tcp", EndpointKind::XhttpSsTcp),
        ("xhttp_ss_udp", EndpointKind::XhttpSsUdp),
        ("xhttp_vless", EndpointKind::XhttpVless),
    ] {
        let parsed: EndpointSection =
            toml::from_str(&format!("path = \"/p\"\nkind = \"{s}\"")).unwrap();
        assert_eq!(parsed.kind, k, "kind {s}");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p outline-ss-rust config::endpoint`
Expected: FAIL — `config::endpoint` module does not exist.

- [ ] **Step 3: Create `endpoint.rs`**

Create `bins/outline-ss-rust/src/config/endpoint.rs`:

```rust
//! The server's carrier-endpoint model. A single global list of
//! `{path, kind, padded}` records replaces the old per-user path fields and the
//! separate `[padding] paths` list. Endpoints are startup-only; users are pure
//! credentials that work on every endpoint of their kind.

use serde::{Deserialize, Serialize};

/// Carrier + transport shape of one endpoint. `snake_case` on the wire so the
/// TOML reads `kind = "ws_ss"`. The variant fixes both the carrier family
/// (WS vs XHTTP) and the Shadowsocks/VLESS shape; the HTTP version (h1/h2/h3)
/// is chosen by the listener, not the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    /// Combined SS-over-WS: one path carries both TCP and UDP legs.
    WsSs,
    /// Split SS-over-WS, TCP leg.
    WsSsTcp,
    /// Split SS-over-WS, UDP leg.
    WsSsUdp,
    /// VLESS-over-WS.
    WsVless,
    /// Combined SS-over-XHTTP: one base carries both legs.
    XhttpSs,
    /// Split SS-over-XHTTP, TCP leg.
    XhttpSsTcp,
    /// Split SS-over-XHTTP, UDP leg.
    XhttpSsUdp,
    /// VLESS-over-XHTTP.
    XhttpVless,
}

impl EndpointKind {
    /// True for every Shadowsocks kind (pool = SS `UserKey`s).
    pub fn is_ss(self) -> bool {
        !self.is_vless()
    }

    /// True for the two VLESS kinds (pool = `VlessUser`s).
    pub fn is_vless(self) -> bool {
        matches!(self, EndpointKind::WsVless | EndpointKind::XhttpVless)
    }

    /// A combined SS kind carries both legs on one path, so it populates two
    /// route maps and `bootstrap/axum.rs` registers a `<base>/{token}` upgrade.
    pub fn is_combined(self) -> bool {
        matches!(self, EndpointKind::WsSs | EndpointKind::XhttpSs)
    }
}

/// Resolved endpoint: the runtime form after config load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointConfig {
    pub path: String,
    pub kind: EndpointKind,
    pub padded: bool,
}

#[cfg(test)]
#[path = "tests/endpoint.rs"]
mod tests;
```

Add to `bins/outline-ss-rust/src/config/file.rs` after the other `*Section` structs (near `TlsCertSection` :144):

```rust
/// One `[[endpoint]]` entry: a carrier path, its kind, and whether it pads.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EndpointSection {
    pub path: String,
    pub kind: super::endpoint::EndpointKind,
    #[serde(default)]
    pub padded: bool,
}
```

And add the field to `FileConfig` (:12-49), next to `users`. The TOML key must be singular `[[endpoint]]` (the whole design uses it), so rename it off the plural field name:

```rust
    #[serde(default, rename = "endpoint")]
    pub endpoints: Option<Vec<EndpointSection>>,
```

- [ ] **Step 4: Wire mod + resolve**

In `bins/outline-ss-rust/src/config/mod.rs` add `mod endpoint;` and extend the `resolved`/`endpoint` re-exports:

```rust
pub use endpoint::{EndpointConfig, EndpointKind};
```

(Keep it beside the existing `pub use resolved::{Config, PaddingConfig, …};` line.)

In `bins/outline-ss-rust/src/config/resolved.rs`, add to `struct Config` (:41-164):

```rust
    /// Carrier endpoints (startup-only). The single source of truth for paths.
    pub endpoints: Vec<EndpointConfig>,
```

In `bins/outline-ss-rust/src/config/loader.rs`, inside `AppMode::load`'s `Config { … }` literal (:87-178), add:

```rust
        endpoints: file
            .endpoints
            .unwrap_or_default()
            .into_iter()
            .map(|e| EndpointConfig { path: e.path, kind: e.kind, padded: e.padded })
            .collect(),
```

Add `use crate::config::endpoint::EndpointConfig;` (or the crate-local path) at the top of `loader.rs` if not already imported.

- [ ] **Step 5: Run tests to verify they pass + full gate**

Run: `cargo test -p outline-ss-rust config::endpoint`
Expected: PASS (4 tests).

Then the full gate (fmt / clippy / test / no-default-features) from Global Constraints. Expected: green — this task is purely additive.

- [ ] **Step 6: Commit**

```bash
git add bins/outline-ss-rust/src/config/endpoint.rs bins/outline-ss-rust/src/config/tests/endpoint.rs bins/outline-ss-rust/src/config/mod.rs bins/outline-ss-rust/src/config/file.rs bins/outline-ss-rust/src/config/resolved.rs bins/outline-ss-rust/src/config/loader.rs
git commit -m "feat(config): add [[endpoint]] list and EndpointKind (unused)"
```

---

### Task 2: Endpoint-driven route building; switch startup

Add one helper that builds the six `RouteRegistry` maps from the endpoint list plus the global user pools, and point `services.rs` at it. Delete the now-dead stage-1 builders. `manager.rs` still uses the stage-2 builders (handled in Task 4). `bootstrap/axum.rs` and H3 are untouched — they read `RouteRegistry.keys()`.

**Files:**
- Create: `bins/outline-ss-rust/src/server/endpoint_routes.rs`
- Create: `bins/outline-ss-rust/src/server/tests/endpoint_routes.rs`
- Modify: `bins/outline-ss-rust/src/server/mod.rs` (add `mod endpoint_routes;`)
- Modify: `bins/outline-ss-rust/src/server/services.rs:71-187` (`build`: call the helper; assemble SS/VLESS pools)
- Modify: `bins/outline-ss-rust/src/server/setup.rs` (delete stage-1 builders `build_user_routes`, `build_vless_user_routes`, `build_vless_xhttp_user_routes`, `build_ss_xhttp_user_routes`, `build_ss_xhttp_udp_user_routes` and their `describe_*` + `UserRoute`/`VlessUserRoute`/`VlessXhttpUserRoute`/`SsXhttpUserRoute` structs; keep `build_transport_route_map`, `build_vless_transport_route_map`, `build_xhttp_vless_route_map`, `build_xhttp_ss_route_map`, `user_keys` — still used by manager until Task 4)

**Interfaces:**
- Consumes: `EndpointConfig`, `EndpointKind` (Task 1); `UserKey` (`crypto/user_key.rs`), `VlessUser` (`protocol/vless.rs`); `TransportRoute`, `VlessTransportRoute`, `RouteRegistry` (`server/state.rs`); `PeerUserCache`, `TCP_PEER_USER_CACHE_CAPACITY`.
- Produces (all `pub(super)` in `endpoint_routes.rs`; consumed by `services.rs` here and `control/manager.rs` in Task 4):
  - `fn build_route_registry(endpoints: &[EndpointConfig], ss_users: &[UserKey], vless_users: &[VlessUser]) -> RouteRegistry`.
  - `fn build_ss_user_pool(entries: &[UserEntry], default_method: CipherKind) -> anyhow::Result<Vec<UserKey>>` and `fn build_vless_user_pool(entries: &[UserEntry]) -> anyhow::Result<Vec<VlessUser>>` — resolve creds from user entries.
  - private `ss_user_pool` / `vless_user_pool` — shared `Arc` pool + candidate labels cloned into each route.

- [ ] **Step 1: Write the failing test**

Create `bins/outline-ss-rust/src/server/tests/endpoint_routes.rs`:

```rust
use crate::config::{EndpointConfig, EndpointKind};
use crate::crypto::user_key::UserKey;
use super::super::endpoint_routes::build_route_registry;

fn ss_user(id: &str) -> UserKey {
    UserKey::new(id.to_owned(), "pw", None, crate::config::CipherKind::Aes128Gcm, None).unwrap()
}

fn ep(path: &str, kind: EndpointKind, padded: bool) -> EndpointConfig {
    EndpointConfig { path: path.to_owned(), kind, padded }
}

#[test]
fn combined_ws_ss_populates_both_tcp_and_udp() {
    let eps = [ep("/pss", EndpointKind::WsSs, true)];
    let reg = build_route_registry(&eps, &[ss_user("alice"), ss_user("bob")], &[]);
    assert!(reg.tcp.contains_key("/pss"), "combined lands in tcp");
    assert!(reg.udp.contains_key("/pss"), "combined lands in udp");
    assert_eq!(reg.tcp["/pss"].users.len(), 2, "pool = every ss user");
}

#[test]
fn split_kinds_land_in_one_map_each() {
    let eps = [
        ep("/tcp", EndpointKind::WsSsTcp, false),
        ep("/udp", EndpointKind::WsSsUdp, false),
    ];
    let reg = build_route_registry(&eps, &[ss_user("a")], &[]);
    assert!(reg.tcp.contains_key("/tcp") && !reg.udp.contains_key("/tcp"));
    assert!(reg.udp.contains_key("/udp") && !reg.tcp.contains_key("/udp"));
}

#[test]
fn ss_endpoint_does_not_pull_vless_users_and_vice_versa() {
    let eps = [ep("/vl", EndpointKind::WsVless, false), ep("/tcp", EndpointKind::WsSsTcp, false)];
    let reg = build_route_registry(&eps, &[ss_user("a")], &[]);
    assert_eq!(reg.tcp["/tcp"].users.len(), 1);
    assert!(reg.vless.get("/vl").map(|r| r.users.is_empty()).unwrap_or(true));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p outline-ss-rust server::endpoint_routes`
Expected: FAIL — `endpoint_routes` module / `build_route_registry` not found.

- [ ] **Step 3: Write `endpoint_routes.rs`**

Create `bins/outline-ss-rust/src/server/endpoint_routes.rs`:

```rust
//! Turns the startup endpoint list + the global user pools into the six
//! `RouteRegistry` maps. One place, shared by startup (`services::build`) and
//! live user mutation (`control::manager::rebuild_snapshots`).
//!
//! Because users work on every endpoint of their kind, the pool for an SS
//! endpoint is *all* SS users and for a VLESS endpoint *all* VLESS users —
//! independent of the path. The pooling that `build_transport_route_map` used
//! to do per-path (`grouped.entry(path).push(user)`) collapses to "clone the
//! whole pool into each route"; only `peer_user_cache` is fresh per route.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::config::{EndpointConfig, EndpointKind};
use crate::crypto::user_key::UserKey;
use crate::protocol::vless::VlessUser;

use super::constants::TCP_PEER_USER_CACHE_CAPACITY;
use super::state::{
    PeerUserCache, RouteRegistry, TransportRoute, VlessTransportRoute,
};

/// Shared SS pool + candidate labels, cloned into each SS route.
pub(super) fn ss_user_pool(users: &[UserKey]) -> (Arc<[UserKey]>, Arc<[Arc<str>]>) {
    let candidates: Vec<Arc<str>> = users.iter().map(|u| u.log_label()).collect();
    (Arc::from(users.to_vec().into_boxed_slice()), Arc::from(candidates.into_boxed_slice()))
}

/// Shared VLESS pool + candidate labels.
pub(super) fn vless_user_pool(users: &[VlessUser]) -> (Arc<[VlessUser]>, Arc<[Arc<str>]>) {
    let candidates: Vec<Arc<str>> = users.iter().map(|u| u.label_arc()).collect();
    (Arc::from(users.to_vec().into_boxed_slice()), Arc::from(candidates.into_boxed_slice()))
}

fn ss_route(pool: &Arc<[UserKey]>, candidates: &Arc<[Arc<str>]>) -> Arc<TransportRoute> {
    Arc::new(TransportRoute {
        users: Arc::clone(pool),
        candidate_users: Arc::clone(candidates),
        peer_user_cache: Arc::new(PeerUserCache::with_capacity(TCP_PEER_USER_CACHE_CAPACITY)),
    })
}

fn vless_route(pool: &Arc<[VlessUser]>, candidates: &Arc<[Arc<str>]>) -> Arc<VlessTransportRoute> {
    Arc::new(VlessTransportRoute { users: Arc::clone(pool), candidate_users: Arc::clone(candidates) })
}

/// Build the six route maps from the endpoint list and the global pools.
pub(super) fn build_route_registry(
    endpoints: &[EndpointConfig],
    ss_users: &[UserKey],
    vless_users: &[VlessUser],
) -> RouteRegistry {
    let (ss_pool, ss_candidates) = ss_user_pool(ss_users);
    let (vless_pool, vless_candidates) = vless_user_pool(vless_users);

    let mut tcp = BTreeMap::new();
    let mut udp = BTreeMap::new();
    let mut vless = BTreeMap::new();
    let mut xhttp_vless = BTreeMap::new();
    let mut xhttp_ss = BTreeMap::new();
    let mut xhttp_ss_udp = BTreeMap::new();

    for ep in endpoints {
        let p = ep.path.clone();
        match ep.kind {
            EndpointKind::WsSs => {
                tcp.insert(p.clone(), ss_route(&ss_pool, &ss_candidates));
                udp.insert(p, ss_route(&ss_pool, &ss_candidates));
            }
            EndpointKind::WsSsTcp => {
                tcp.insert(p, ss_route(&ss_pool, &ss_candidates));
            }
            EndpointKind::WsSsUdp => {
                udp.insert(p, ss_route(&ss_pool, &ss_candidates));
            }
            EndpointKind::WsVless => {
                vless.insert(p, vless_route(&vless_pool, &vless_candidates));
            }
            EndpointKind::XhttpSs => {
                xhttp_ss.insert(p.clone(), ss_route(&ss_pool, &ss_candidates));
                xhttp_ss_udp.insert(p, ss_route(&ss_pool, &ss_candidates));
            }
            EndpointKind::XhttpSsTcp => {
                xhttp_ss.insert(p, ss_route(&ss_pool, &ss_candidates));
            }
            EndpointKind::XhttpSsUdp => {
                xhttp_ss_udp.insert(p, ss_route(&ss_pool, &ss_candidates));
            }
            EndpointKind::XhttpVless => {
                xhttp_vless.insert(p, vless_route(&vless_pool, &vless_candidates));
            }
        }
    }

    RouteRegistry {
        tcp: Arc::new(tcp),
        udp: Arc::new(udp),
        vless: Arc::new(vless),
        xhttp_vless: Arc::new(xhttp_vless),
        xhttp_ss: Arc::new(xhttp_ss),
        xhttp_ss_udp: Arc::new(xhttp_ss_udp),
    }
}

/// Every password-bearing user as an SS `UserKey`. Shared by startup and the
/// control-plane rebuild, so the derivation lives in one place.
pub(super) fn build_ss_user_pool(
    entries: &[UserEntry],
    default_method: CipherKind,
) -> anyhow::Result<Vec<UserKey>> {
    entries
        .iter()
        .filter(|e| e.password.is_some())
        .map(|entry| {
            let method = entry.effective_method(default_method);
            let aliases = entry.build_ip_aliases()?;
            let password = entry.password.as_deref().expect("filtered to password-bearing");
            Ok(UserKey::new(entry.id.clone(), password, entry.fwmark, method, aliases)?)
        })
        .collect()
}

/// Every `vless_id` user as a `VlessUser`.
pub(super) fn build_vless_user_pool(entries: &[UserEntry]) -> anyhow::Result<Vec<VlessUser>> {
    entries
        .iter()
        .filter_map(|e| e.vless_id.clone().map(|id| (e, id)))
        .map(|(entry, vless_id)| {
            let aliases = entry.build_ip_aliases()?;
            Ok(VlessUser::new(vless_id, Arc::from(entry.id.as_str()), entry.fwmark, aliases)?)
        })
        .collect()
}

#[cfg(test)]
#[path = "tests/endpoint_routes.rs"]
mod tests;
```

Add the imports these need at the top of `endpoint_routes.rs`: `use crate::config::{CipherKind, UserEntry};`.

> Note: confirm the exact import paths (`PeerUserCache`, `TransportRoute`, `VlessTransportRoute`, `RouteRegistry`, `TCP_PEER_USER_CACHE_CAPACITY`, `UserKey::log_label`, `VlessUser::label_arc`) against `state.rs`, `constants.rs`, `crypto/user_key.rs`, `protocol/vless.rs`. If `RouteRegistry`'s fields are `pub(super)` in `state.rs`, this module is under `crate::server`, so they are visible.

Register the module in `bins/outline-ss-rust/src/server/mod.rs`:

```rust
mod endpoint_routes;
```

- [ ] **Step 4: Switch `services::build` to the helper**

In `bins/outline-ss-rust/src/server/services.rs`, replace the stage-1/stage-2 block (:78-112) with pool assembly + one helper call. The SS pool is the password-bearing users (same set `user_keys` produced); the VLESS pool is every `vless_id` user. Keep the existing warn-and-skip loop (:88-104) for vless users with no transport (it now checks endpoint availability — simplest: keep warning on `config.endpoints` emptiness of vless kinds, or drop the per-user path check since users are path-independent; **drop the loop** — a vless user is simply in the pool and answers on any vless endpoint):

```rust
    // SS pool: every enabled password-bearing user. VLESS pool: every vless_id user.
    let ss_users: Vec<UserKey> = build_ss_user_pool(config)?;
    let vless_users: Vec<VlessUser> = build_vless_user_pool(config)?;
    let users: Arc<[UserKey]> = Arc::from(ss_users.clone().into_boxed_slice());
    let registry = super::endpoint_routes::build_route_registry(
        &config.endpoints,
        &ss_users,
        &vless_users,
    );
    let tcp_routes = Arc::clone(&registry.tcp);
    let udp_routes = Arc::clone(&registry.udp);
    let vless_routes = Arc::clone(&registry.vless);
    let xhttp_vless_routes = Arc::clone(&registry.xhttp_vless);
    let xhttp_ss_routes = Arc::clone(&registry.xhttp_ss);
    let xhttp_ss_udp_routes = Arc::clone(&registry.xhttp_ss_udp);
```

The pool builders `build_ss_user_pool` / `build_vless_user_pool` are defined **in `endpoint_routes.rs`** (Step 3), `pub(super)`, taking already-resolved user entries so both `services.rs` and `control/manager.rs` (Task 4) share them. In `services.rs` call them as:

```rust
    let effective = config.effective_users()?;               // dedup by id, enabled only
    let ss_users = super::endpoint_routes::build_ss_user_pool(&effective, config.method)?;
    let vless_users = super::endpoint_routes::build_vless_user_pool(&effective)?;
```

> `Built` still carries the six `Arc<BTreeMap…>` and `auth_users`; keep those fields, just source them from `registry` above.

- [ ] **Step 5: Delete dead stage-1 builders in `setup.rs`**

Remove the **stage-1 builder functions** `build_user_routes`, `build_vless_user_routes`, `build_vless_xhttp_user_routes`, `build_ss_xhttp_user_routes`, `build_ss_xhttp_udp_user_routes` (only `services.rs` called them; it no longer does). **Keep for now** (all still used by `manager.rs::rebuild_snapshots`, which hand-builds these records until Task 4): the `UserRoute`/`VlessUserRoute`/`VlessXhttpUserRoute`/`SsXhttpUserRoute` structs, the stage-2 builders `build_transport_route_map`, `build_vless_transport_route_map`, `build_xhttp_vless_route_map`, `build_xhttp_ss_route_map`, and `user_keys`. The `describe_*_user_routes` helpers: delete the ones whose only builder you removed, or keep any still referenced by `manager.rs`/logging — let the compiler's dead-code warning decide (the gate is `-D warnings`, so remove whatever it flags). Everything kept here is deleted in Task 4.

- [ ] **Step 6: Fix existing startup tests to use endpoints**

Server integration tests that set `ws_path_*` in a `Config` literal or TOML and expect a live route must now set `endpoints`. Find them: `rg -l 'ws_path_tcp|ws_path_ss' bins/outline-ss-rust/src --glob '*/tests/*'`. For each, replace the path fields with an `endpoints` vec of `EndpointConfig`. (The bulk of these are in `server/tests/mod.rs` helpers — update the shared config builder there once.)

- [ ] **Step 7: Gate + commit**

Run the full gate. Expected: green (existing behaviour preserved through the new source; combined still hits both maps so axum/H3 registration is unchanged).

```bash
git add bins/outline-ss-rust/src/server/endpoint_routes.rs bins/outline-ss-rust/src/server/tests/endpoint_routes.rs bins/outline-ss-rust/src/server/mod.rs bins/outline-ss-rust/src/server/services.rs bins/outline-ss-rust/src/server/setup.rs bins/outline-ss-rust/src/server/tests/
git commit -m "feat(server): build routes from the endpoint list at startup"
```

---

### Task 3: Padding sourced from endpoints

Move the padded-path set from `[padding].paths` to the endpoints with `padded = true`. Drop `PaddingConfig.enabled`. The 14 `scheme_for_path` / `cover_for_path` / `throttle_params_for_path` call-sites and `carrier_padding.rs` are untouched — only the set's source changes.

**Files:**
- Modify: `bins/outline-ss-rust/src/config/resolved.rs` (`PaddingConfig` :257-389 — drop `enabled`; `paths` becomes derived `padded_paths`; `applies_to`/`scheme_for_path`/`cover_enabled` drop the `enabled` gate)
- Modify: `bins/outline-ss-rust/src/config/file.rs` (`PaddingSection` :378-427 — remove `enabled` :382 and `paths` :400)
- Modify: `bins/outline-ss-rust/src/config/loader.rs` (fill `padding.padded_paths` from `config.endpoints`)
- Modify: `bins/outline-ss-rust/src/config/tests/*` (padding parsing tests)

**Interfaces:**
- Consumes: `Config.endpoints` (Task 1).
- Produces: `PaddingConfig { min_bytes, max_bytes, cover, cover_jitter_*, throttle_*, padded_paths: Vec<String> }`; `applies_to(path)` = `padded_paths.iter().any(|p| p == path)`; unchanged `scheme()`, `scheme_for_path`, `cover_enabled`, `throttle_*` (minus the `enabled &&`).

- [ ] **Step 1: Write the failing test**

Add to `bins/outline-ss-rust/src/config/tests/validation.rs` (or the existing padding test file):

```rust
#[test]
fn padding_scheme_resolves_for_padded_endpoints_only() {
    let toml = r#"
[server]
listen = "127.0.0.1:0"

[shadowsocks]
method = "chacha20-ietf-poly1305"

[[endpoint]]
path = "/pss"
kind = "ws_ss"
padded = true

[[endpoint]]
path = "/plain"
kind = "ws_ss_tcp"

[padding]
max_bytes = 128

[[users]]
id = "a"
password = "pw"
"#;
    let cfg = parse(toml).unwrap();   // same full-TOML→Config helper the file already uses
    assert!(cfg.padding.scheme_for_path("/pss").is_enabled(), "padded endpoint pads");
    assert!(!cfg.padding.scheme_for_path("/plain").is_enabled(), "plain endpoint stays plain");
    assert_eq!(cfg.padding.padded_paths, vec!["/pss".to_string()]);
}
```

> `parse` = the crate's existing "parse a full TOML into `Config`" test helper (find it with `rg 'fn .*toml.*Config|load_from_str' bins/outline-ss-rust/src/config`); if none exists, add a small one via the loader path the other config tests use, and reuse it in Task 5. Match the surrounding test file's style.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p outline-ss-rust padding_scheme_resolves`
Expected: FAIL — `padded_paths` field missing / `[padding] paths` still required.

- [ ] **Step 3: Rework `PaddingConfig`**

In `resolved.rs`: remove `pub enabled: bool` (:259) and rename `pub paths: Vec<String>` (:269) to `pub padded_paths: Vec<String>`. Update `Default` (:283-304) — drop `enabled`, `paths: Vec::new()` → `padded_paths: Vec::new()`. Update `from_section` (:307-353) — drop `enabled` and `paths` reads. Update methods:

```rust
    /// The wire-codec scheme this resolves to. Always the configured range now;
    /// per-path gating is `scheme_for_path`.
    pub fn scheme(&self) -> outline_wire::padding::PaddingScheme {
        outline_wire::padding::PaddingScheme::new(self.min_bytes, self.max_bytes)
    }

    pub fn cover_enabled(&self) -> bool {
        self.cover
    }

    /// Whether the endpoint matched at `path` pads.
    pub fn applies_to(&self, path: &str) -> bool {
        self.padded_paths.iter().any(|p| p == path)
    }

    pub fn scheme_for_path(&self, path: &str) -> outline_wire::padding::PaddingScheme {
        if self.applies_to(path) {
            self.scheme()
        } else {
            outline_wire::padding::PaddingScheme::disabled()
        }
    }
```

> `carrier_padding.rs::cover_for_path` calls `p.cover_enabled() && p.applies_to(path)` — still correct. `scheme_for_path` returning a `new(min,max)` scheme when `max_bytes == 0` is already `disabled()` via `PaddingScheme::new`/`is_enabled`, so an all-zero `[padding]` with a padded endpoint yields no framing — matches today.

- [ ] **Step 4: Drop `enabled`/`paths` from `PaddingSection`; fill `padded_paths` in loader**

In `file.rs` `PaddingSection`, delete `enabled` (:382) and `paths` (:400).

In `loader.rs`, after building `endpoints` and `padding` (:172), set the derived set. Change `padding: PaddingConfig::from_section(...)` to build the config then fill it:

```rust
        padding: {
            let mut p = PaddingConfig::from_section(file.padding.unwrap_or_default());
            p.padded_paths = resolved_endpoints
                .iter()
                .filter(|e| e.padded)
                .map(|e| e.path.clone())
                .collect();
            p
        },
```

> This requires `endpoints` to be resolved into a local `resolved_endpoints` before the `padding` field in the literal. If the struct-literal ordering makes that awkward, resolve `endpoints` into a `let resolved_endpoints = …;` above the `Config { … }` literal and use it for both the `endpoints:` and `padding:` fields.

- [ ] **Step 5: Run tests + gate**

Run: `cargo test -p outline-ss-rust padding`
Expected: PASS. Then full gate.

- [ ] **Step 6: Commit**

```bash
git add bins/outline-ss-rust/src/config/resolved.rs bins/outline-ss-rust/src/config/file.rs bins/outline-ss-rust/src/config/loader.rs bins/outline-ss-rust/src/config/tests/
git commit -m "feat(config): source carrier padding from padded endpoints, drop [padding] enabled/paths"
```

---

### Task 4: Control-plane on endpoints; users are pure creds

Rewrite `manager.rs` to hold the startup endpoint list, rebuild routes via `build_route_registry`, and drop every path field/check. `persist.rs` needs no change (serde-driven). Then delete the stage-2 builders + `UserRoute` family from `setup.rs`.

**Files:**
- Modify: `bins/outline-ss-rust/src/server/control/manager.rs` (remove `default_*_path*` :46-53, `allowed_*_path*` :57-62, `AllowedRoutePaths` :153-160; `new` loses the `allowed` arg, gains `endpoints`; `validate_new` drops path checks; `rebuild_snapshots` uses `build_route_registry`; `UserView`/`UserPatch`/`ServerDefaults` drop path fields)
- Modify: `bins/outline-ss-rust/src/server/mod.rs:110-133` (drop `AllowedRoutePaths` construction; pass `config.endpoints` to `UserManager::new`)
- Modify: `bins/outline-ss-rust/src/server/setup.rs` (delete the stage-2 builders `build_transport_route_map`, `build_vless_transport_route_map`, `build_xhttp_vless_route_map`, `build_xhttp_ss_route_map`, `user_keys`, the remaining `describe_*_user_routes`, and the `UserRoute`/`VlessUserRoute`/`VlessXhttpUserRoute`/`SsXhttpUserRoute` structs — all dead once manager uses `build_route_registry`. If `setup.rs` is now empty, delete it and its `mod setup;`)
- Modify: `bins/outline-ss-rust/src/server/control/tests/*` (manager/persist tests: users without paths)

**Interfaces:**
- Consumes: `build_route_registry`, `ss_user_pool`, `vless_user_pool` (Task 2); `Config.endpoints`.
- Produces: `UserManager` holding `endpoints: Arc<[EndpointConfig]>`, `default_method: CipherKind`, `config_path`; `UserManager::new(config, routes, auth_users)` (no `allowed` arg).

- [ ] **Step 1: Write/adjust the failing test**

First read `bins/outline-ss-rust/src/server/control/tests/manager.rs` to see how the harness builds a `UserManager` (the existing `create_keeps_users_the_runtime_does_not_hold` test is the model — note whether it constructs `UserManager::new` directly or through a helper, and how it reads the published `RouteRegistry` from the `routes` `ArcSwap`). Then add a test that builds a manager with **two SS endpoints** (`/a`, `/b`, both `WsSsTcp`) and **one password user**, and asserts the user is pooled on **both**:

```rust
#[test]
fn user_pool_answers_on_every_endpoint_of_its_kind() {
    let endpoints = vec![
        crate::config::EndpointConfig { path: "/a".into(), kind: crate::config::EndpointKind::WsSsTcp, padded: false },
        crate::config::EndpointConfig { path: "/b".into(), kind: crate::config::EndpointKind::WsSsTcp, padded: false },
    ];
    // Build the manager exactly as create_keeps_users_the_runtime_does_not_hold does,
    // but pass `endpoints` (the new UserManager::new signature) and one password user.
    let mgr = /* harness constructor from the model test, with `endpoints` */;
    let reg = mgr.routes.load();   // the ArcSwap<RouteRegistry> the harness exposes
    assert_eq!(reg.tcp["/a"].users.len(), 1);
    assert_eq!(reg.tcp["/b"].users.len(), 1);
}
```

The single `/* harness constructor … */` line is the only spot the implementer fills from the model test; everything else is concrete. The point being tested: with per-user paths gone, one user shows up in every same-kind endpoint's pool.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p outline-ss-rust control::` (or the specific test name)
Expected: FAIL to compile — `UserManager::new` still takes `allowed`, still reads path fields.

- [ ] **Step 3: Strip paths from the `UserManager` struct + `new`**

Delete fields `default_ws_path_*`/`default_xhttp_path_*` (:46-53), `allowed_*_path*` (:57-62), and the `AllowedRoutePaths` struct (:153-160). Add `endpoints: Arc<[EndpointConfig]>`. Change the constructor:

```rust
pub(super) fn new(
    config: &Config,
    routes: RoutesSnapshot,
    auth_users: AuthUsersSnapshot,
) -> Self {
    Self {
        inner: Mutex::new(Inner { users: config.users.clone() }),
        routes,
        auth_users,
        default_method: config.method,
        endpoints: Arc::from(config.endpoints.clone().into_boxed_slice()),
        config_path: /* unchanged */,
    }
}
```

- [ ] **Step 4: Gut path checks from `validate_new`; rework `rebuild_snapshots`**

`validate_new` (:294-455): keep only the empty-id bail (:295-297), the "must have password OR vless_id" bail (:298-300), and `build_ip_aliases` (:451-453). Delete every `allowed_*`/`default_*` path block (:301-448).

`rebuild_snapshots` (:482-602): keep the dup-id + alias validation (:485-496). Replace the hand-built `UserRoute`/`SsXhttpUserRoute`/`VlessUserRoute`/`VlessXhttpUserRoute` construction + stage-2 calls (:498-581) with the shared builders from Task 2 (`users` here is the manager's current `Vec<UserEntry>`; apply the same effective-users filtering the old code did, or reuse `Config::effective_users`'s dedup logic on the snapshot set):

```rust
    use crate::server::endpoint_routes::{build_route_registry, build_ss_user_pool, build_vless_user_pool};
    let ss_users = build_ss_user_pool(users, self.default_method)?;
    let vless_users = build_vless_user_pool(users)?;
    let registry = build_route_registry(&self.endpoints, &ss_users, &vless_users);
    let auth_keys: Arc<[UserKey]> = Arc::from(ss_users.into_boxed_slice());
    (registry, auth_keys)
```

> This is exactly the duplication the routing map flagged (setup.rs vs manager.rs both built routes): after this task both call `build_route_registry`. Keep `commit`'s validate→disk→publish order (:464-480) exactly.

- [ ] **Step 5: Drop path fields from `UserView`, `UserPatch`, `ServerDefaults`**

`UserView` (:70-100): delete path fields (:79-93) and their copies in `From<&UserEntry>` (:109-116). `UserPatch` (:605-620): delete path fields (:611-617) and their `apply_to` copies (:636-659). `ServerDefaults` (:129-146) + `defaults()` (:204-216): collapse to `{ method }` (or delete the `GET /control/defaults` payload's path fields).

- [ ] **Step 6: Update `mod.rs` caller + delete dead stage-2 builders**

`server/mod.rs:110-133`: delete the `AllowedRoutePaths` construction from `built.*.keys()`; call `UserManager::new(config, routes, auth_users)`.

`setup.rs`: delete the stage-2 builders (`build_transport_route_map`, `build_vless_transport_route_map`, `build_xhttp_vless_route_map`, `build_xhttp_ss_route_map`), `user_keys`, the remaining `describe_*_user_routes`, and the `UserRoute`/`VlessUserRoute`/`VlessXhttpUserRoute`/`SsXhttpUserRoute` structs — all now unused. Remove any Task-2 `#[allow(dead_code)]`. If nothing is left in `setup.rs`, delete the file and its `mod setup;` declaration.

- [ ] **Step 7: Fix control tests + gate**

Update `control/tests/manager.rs` and `control/tests/persist.rs` fixtures: users carry no paths; the manager is constructed with an `endpoints` vec. Verify the persist guard test (`create_keeps_users_the_runtime_does_not_hold`) still passes — the invariant is field-agnostic. Full gate.

- [ ] **Step 8: Commit**

```bash
git add bins/outline-ss-rust/src/server/control/ bins/outline-ss-rust/src/server/mod.rs bins/outline-ss-rust/src/server/setup.rs bins/outline-ss-rust/src/server/endpoint_routes.rs
git commit -m "feat(control): endpoints are startup-only, users are pure credentials"
```

---

### Task 5: Validation on endpoints

Rewrite `Config::validate`'s path logic to iterate the endpoint list instead of per-user effective paths. Drop the `[padding] enabled requires paths` check.

**Files:**
- Modify: `bins/outline-ss-rust/src/config/validation.rs:12-369`
- Modify: `bins/outline-ss-rust/src/config/tests/validation.rs`

**Interfaces:**
- Consumes: `Config.endpoints`, `EndpointKind`.
- Produces: no new types; `validate` now rejects duplicate endpoint paths, cross-kind path conflicts, and warns on an endpoint kind with no matching users.

- [ ] **Step 1: Write failing tests**

Add to `bins/outline-ss-rust/src/config/tests/validation.rs`. Use the same full-TOML→`Config` parse the neighbouring tests in this file already use (find it with `rg 'fn .*toml.*Config|load_from_str|from_str::<FileConfig>' bins/outline-ss-rust/src/config` and reuse it — call it `parse(toml)` below):

```rust
fn base(endpoints: &str) -> String {
    format!(
        "[server]\nlisten = \"127.0.0.1:0\"\n\
         [shadowsocks]\nmethod = \"chacha20-ietf-poly1305\"\n\
         {endpoints}\n\
         [[users]]\nid = \"a\"\npassword = \"pw\"\n"
    )
}

#[test]
fn duplicate_endpoint_path_is_rejected() {
    let toml = base(
        "[[endpoint]]\npath = \"/x\"\nkind = \"ws_ss_tcp\"\n\
         [[endpoint]]\npath = \"/x\"\nkind = \"ws_vless\"\n",
    );
    let err = parse(&toml).unwrap_err();
    assert!(err.to_string().contains("duplicate") || err.to_string().contains("distinct"));
}

#[test]
fn tcp_and_udp_endpoints_may_not_share_a_path() {
    let toml = base(
        "[[endpoint]]\npath = \"/x\"\nkind = \"ws_ss_tcp\"\n\
         [[endpoint]]\npath = \"/x\"\nkind = \"ws_ss_udp\"\n",
    );
    assert!(parse(&toml).is_err());
}

#[test]
fn combined_ss_endpoint_is_accepted() {
    let toml = base("[[endpoint]]\npath = \"/pss\"\nkind = \"ws_ss\"\npadded = true\n");
    assert!(parse(&toml).is_ok());
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p outline-ss-rust validation`
Expected: FAIL — old validation still keys on per-user paths / `[padding].paths`.

- [ ] **Step 3: Rewrite the path section of `validate`**

Replace the WS/VLESS/XHTTP path-set collection (:44-305) and the padding check (:37-42) with endpoint-driven sets. Build one `BTreeSet` per route-map target by walking `self.endpoints` and expanding combined kinds into both targets (mirror the Global-Constraints table). Then run the same distinct-conflict checks between sets. Key rules to preserve:

- Duplicate `path` across endpoints → `bail!`.
- `tcp` ∩ `udp`, `tcp`/`udp`/`vless` mutual distinctness, `xhttp_*` distinctness — same conflicts the old code checked, now between endpoint-derived sets.
- `http_root_auth` vs `"/"` check (:294-305) — keep, but over the endpoint paths.
- Warn (not bail) when an endpoint kind is SS but no password user exists, or VLESS but no vless_id user exists.

Delete the padding block at :37-42 entirely.

- [ ] **Step 4: Run + gate**

Run: `cargo test -p outline-ss-rust validation`
Expected: PASS. Full gate.

- [ ] **Step 5: Commit**

```bash
git add bins/outline-ss-rust/src/config/validation.rs bins/outline-ss-rust/src/config/tests/validation.rs
git commit -m "feat(config): validate endpoints instead of per-user paths"
```

---

### Task 6: Breaking cleanup — delete the old path model

Now that nothing consumes them, delete the old path fields. This is the breaking commit: old configs stop parsing.

**Files:**
- Modify: `bins/outline-ss-rust/src/config/file.rs` (delete `WebsocketSection` :177-210 and `FileConfig.websocket` :22)
- Modify: `bins/outline-ss-rust/src/config/user_entry.rs` (delete 8 path fields :46-76 and 8 `effective_*` methods :101-144; keep `id, password, fwmark, method, vless_id, enabled, aliases`, `is_enabled`, `effective_method`, `build_ip_aliases`, `validate_ip_aliases`)
- Modify: `bins/outline-ss-rust/src/config/resolved.rs` (delete `Config.ws_path_*`/`xhttp_path_*` :112-131)
- Modify: `bins/outline-ss-rust/src/config/loader.rs` (delete the path-splice :140-153 and the `let websocket = …` unpack :55)
- Modify: `bins/outline-ss-rust/src/server/setup.rs` + the ~10 test files calling them — Task 2 left `build_user_routes` and `user_keys` `#[cfg(test)]`-gated, and they DEPEND on `UserEntry::effective_*` + `Config.ws_path_*`, both deleted in this task. Migrate the per-user-path routing tests onto the endpoint model (or delete them) and remove these gated builders here, or the crate will not compile. (This is the retirement point flagged in Task 2's review.)
- Modify: `bins/outline-ss-rust/src/config/tests/*` (any remaining references)

**Interfaces:**
- Consumes: nothing new.
- Produces: `UserEntry` = pure creds; `Config` has no path fields; `[websocket]` / `[[users]] ws_path_*` / `[padding] enabled|paths` are unknown fields → parse error.

- [ ] **Step 1: Write the failing test**

Add to `bins/outline-ss-rust/src/config/tests/file.rs`:

```rust
#[test]
fn legacy_websocket_paths_are_rejected() {
    let toml = "[websocket]\nws_path_tcp = \"/tcp\"\n";
    assert!(toml::from_str::<crate::config::file::FileConfig>(toml).is_err());
}

#[test]
fn legacy_user_path_is_rejected() {
    let toml = "[[users]]\nid = \"a\"\npassword = \"p\"\nws_path_tcp = \"/a\"\n";
    assert!(toml::from_str::<crate::config::file::FileConfig>(toml).is_err());
}

#[test]
fn legacy_padding_paths_key_is_rejected() {
    let toml = "[padding]\npaths = [\"/x\"]\n";
    assert!(toml::from_str::<crate::config::file::FileConfig>(toml).is_err());
}
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p outline-ss-rust config::tests::file`
Expected: FAIL — the legacy keys still parse (fields still present).

- [ ] **Step 3: Delete the fields**

Delete as listed in **Files**. After deleting `WebsocketSection`, remove its `use`/reference sites. `UserEntry` loses the 8 path fields and 8 `effective_*` — the compiler will point at any straggler reference (there should be none after Tasks 2/4/5). `deny_unknown_fields` on `WebsocketSection` is gone with the struct; on `UserEntry`/`PaddingSection` it now rejects the old keys, which is the intended breaking behaviour.

- [ ] **Step 4: Run + gate**

Run: `cargo test -p outline-ss-rust config::tests::file`
Expected: PASS. Full gate — the whole binary must compile with zero path-field references left.

- [ ] **Step 5: Commit**

```bash
git add bins/outline-ss-rust/src/config/
git commit -m "refactor(config)!: remove per-user paths and [websocket]; endpoints are the only path source"
```

---

### Task 7: Client e2e + config builder on endpoints

The client-side e2e (`outline-ws-rust/tests`) spin up a real server; their `ServerConfig` builder must emit `[[endpoint]]` + `[padding]` params instead of `[websocket]` + `[padding] paths`.

**Files:**
- Modify: `bins/outline-ws-rust/tests/support/config_builder.rs` (`ServerConfig` :36-190 — replace `ws_path_*`/`xhttp_path_*` fields and `render` with endpoints; `all_paths` emits endpoints; `with_padding(paths, cover)` marks those endpoints `padded = true` and emits `[padding]` params only)
- Modify: `bins/outline-ws-rust/tests/e2e_padding.rs` (8 tests — no behavioural change, they call the updated builder)

**Interfaces:**
- The client's own `[padding]` block (`ClientConfig::with_padding_default`) is unchanged — the client is out of scope.

- [ ] **Step 1: Update the `ServerConfig` builder**

Replace the `ws_path_*`/`xhttp_path_*` fields with an endpoint list keyed by the same `PATH_*` constants and a set of padded paths. `render()` emits:

```rust
// for each endpoint:
writeln!(s, "\n[[endpoint]]\npath = \"{path}\"\nkind = \"{kind}\"{}",
    if padded { "\npadded = true" } else { "" });
// then, if any padded and padding is on:
writeln!(s, "\n[padding]\nmax_bytes = 256");
if cover { writeln!(s, "cover = true"); }
```

`all_paths()` registers: `PATH_SS_TCP`→`ws_ss_tcp`, `PATH_SS_UDP`→`ws_ss_udp`, `PATH_VLESS_WS`→`ws_vless`, `PATH_SS_XHTTP`→`xhttp_ss_tcp`, `PATH_VLESS_XHTTP`→`xhttp_vless`. `with_combined_ss_ws_path()` adds `PATH_SS_WS_COMBINED`→`ws_ss`. `with_padding(paths, cover)` flips `padded = true` on the endpoints whose path is in `paths` and records `cover`.

> Verify each test's `with_padding(&[…])` argument names a path that `all_paths()`/`with_combined_ss_ws_path()` actually registered as an endpoint, so the padded flag lands on a real endpoint.

- [ ] **Step 2: Run the e2e**

Run: `RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --test e2e_padding` (add `--features test-tls` for the H3 cases, per the memory note).
Expected: all 8 padding e2e PASS against the new server config format.

- [ ] **Step 3: Gate + commit**

Full gate (workspace test included).

```bash
git add bins/outline-ws-rust/tests/support/config_builder.rs bins/outline-ws-rust/tests/e2e_padding.rs
git commit -m "test(e2e): drive the server with [[endpoint]] + padded flags"
```

---

### Task 8: Documentation (EN + RU)

Rewrite the user-facing docs for the endpoint model. Bilingual, same commit.

**Files:**
- Modify: `bins/outline-ss-rust/config.toml` (replace `[websocket]` path block :116-131 and the `[padding]` block :223-243 with `[[endpoint]]` examples + `[padding]` params; drop per-user `ws_path_*` from `[[users]]` :268-313)
- Modify: `docs/PADDING.md` + `docs/PADDING.ru.md` (padding is now an endpoint attribute; no `[padding] paths`)
- Modify: `bins/outline-ss-rust/README.md` + `README.ru.md` (endpoint model; users are creds)
- Modify: `CHANGELOG.md` + `CHANGELOG.ru.md` (breaking-change entry)
- Modify: `bins/outline-ss-rust/AGENTS.md` (new invariant: endpoints startup-only, users path-independent, padding = endpoint attribute; the H3-path-registry note now covers endpoints)

- [ ] **Step 1: Rewrite `config.toml`**

Replace `[websocket]` with a set of `[[endpoint]]` blocks covering split, combined, vless, and xhttp — each with `kind` and, where illustrative, `padded = true`. Replace `[padding]` with params only (no `enabled`/`paths`). Strip `ws_path_*` from every `[[users]]` entry (alice/carol/dave) and add a comment that users work on every endpoint of their kind. Example endpoint block:

```toml
[[endpoint]]
path = "/tcp"
kind = "ws_ss_tcp"

[[endpoint]]
path = "/pss"
kind = "ws_ss"
padded = true

[padding]
# Parameters only; an endpoint pads iff it sets padded = true.
min_bytes = 0
max_bytes = 256
cover = false
```

- [ ] **Step 2: Rewrite `docs/PADDING.md` + `.ru.md`**

State the new model: padding is turned on per endpoint via `padded = true`; `[padding]` holds only parameters; still config-synchronised with the client (a padded endpoint needs a padding-enabled client); third-party clients use non-padded endpoints. Keep both language versions in lockstep.

- [ ] **Step 3: README + CHANGELOG + AGENTS (both languages)**

README: the endpoint model, users as pure credentials, the `EndpointKind` table. CHANGELOG: a `BREAKING` entry — `[websocket]`, per-user `ws_path_*`, and `[padding] enabled/paths` removed; migrate to `[[endpoint]]`. AGENTS: add the invariant paragraph.

- [ ] **Step 4: Commit**

No code, so no `cargo` gate; just confirm Markdown renders and both language versions match.

```bash
git add bins/outline-ss-rust/config.toml docs/PADDING.md docs/PADDING.ru.md bins/outline-ss-rust/README.md bins/outline-ss-rust/README.ru.md CHANGELOG.md CHANGELOG.ru.md bins/outline-ss-rust/AGENTS.md
git commit -m "docs: document the endpoint model and endpoint-attribute padding"
```

---

## Post-plan notes

- **Deploy (owner-gated):** the binary + node config change together (breaking). Rewrite each node's `config.toml` (paths → `[[endpoint]]`, drop per-user paths, `[padding]` params only) at deploy time, one node at a time, clients moved off the touched node, via `ops/deploy/deploy-binary.sh`. No restart without explicit approval.
- **Client unchanged:** `outline-ws-rust` per-uplink `padding` + URL stay; a padded client URL must point at a `padded` server endpoint (same contract as before).
- **Access-key generation (Python ops, breaks — coordinate before deploy):** the binary parses-and-ignores `[access_keys]` (`config/loader.rs:57`), so nothing in this Rust plan touches it. But `ops/access-keys/artifacts.py` reads per-user paths (`user.ws_path_tcp/udp/ss/vless`, `xhttp_path_*`) to build each client's Outline URL — those fields vanish in Task 6, so the generator must be reworked to pick an endpoint by kind (users are now path-independent; decide which endpoint's path lands in a user's URL — e.g. the first endpoint of each needed kind, or a per-run choice). This is Python ops outside this plan; sequence it with the node rollout or key generation fails. Not started here.
- **Out of scope:** wire protocol, on-wire negotiation, hot-add endpoints via control, raw SS/VLESS-over-QUIC, the `ops/access-keys` Python rework (flagged above).
