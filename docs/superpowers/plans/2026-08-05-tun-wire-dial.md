# TUN fallback-wire dialing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the TUN ingress onto the fallback-wire machinery in both planes, with the warm-standby pool following the active wire, behind a default-off gate.

**Architecture:** A new `WireSpec` projects one carrier (primary or fallback) into the fields a dial needs. The single internal dial entry point per plane is parameterised by wire and works through `WireSpec`; a shared `dial_over_wires` helper walks the wire chain and is used by both ingresses. The warm pool is dialed on the active wire and drained when the active wire moves.

**Tech Stack:** Rust (edition 2024), tokio, Cargo workspace `outline-proxy`. Crates touched: `outline-uplink`, `outline-tun`, binary `outline-ws-rust`.

**Design doc:** `docs/superpowers/specs/2026-08-05-tun-wire-dial-design.md`

## Global Constraints

- Tests live in `<dir>/tests/<basename>.rs` wired with `#[cfg(test)] #[path = "tests/<basename>.rs"] mod tests;` — never inline `#[cfg(test)] mod tests { … }`.
- Code comments, commit messages and PR text in English; chat and reasoning in Russian.
- Never add a `Co-Authored-By: Claude` trailer or a "Generated with Claude Code" footer to anything.
- Commit each task when its gate is green, using the message given in that task's final step. **Never `git push`** — that needs a separate explicit command from the owner, every time.
- Work directly on `main`. Do not create feature branches.
- CI gate, run locally in this exact order before any commit:
  ```bash
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  cargo test --workspace --exclude sockudo-ws
  ```
- `rustfmt.toml` sets 100 columns; do not reformat `vendor/*`.
- Every `unsafe` block carries a concrete `// SAFETY:` comment. This plan adds none.
- User-facing docs are bilingual: any change to `*.md` needs the matching `*.ru.md` in the same commit.
- No production restart, deploy, or `POST /control/apply` without explicit owner approval, every single time.

---

### Task 1: `WireSpec` — the projection of one carrier

**Files:**
- Create: `crates/outline-uplink/src/wire_spec.rs`
- Create: `crates/outline-uplink/src/tests/wire_spec.rs`
- Modify: `crates/outline-uplink/src/lib.rs` (add `mod wire_spec;` and re-export)

**Interfaces:**
- Consumes: `UplinkConfig`, `FallbackTransport`, `SsPathKind`, `TransportMode`, `UplinkTransport`, `CipherKind` from `crate::config`.
- Produces: `WireSpec<'a>` with `from_uplink`, `from_fallback`, `dial_url`, `dial_mode`, `combined_ss_kind`, `supports_udp`, and the `Plane` enum. Tasks 3–10 all consume this.

- [ ] **Step 1: Write the failing test**

Create `crates/outline-uplink/src/tests/wire_spec.rs`:

```rust
use url::Url;

use crate::config::{SsPathKind, TransportMode, UplinkTransport};
use crate::wire_spec::{Plane, WireSpec};

use super::sample_uplink_config;

#[test]
fn from_uplink_projects_the_primary_wire() {
    let uplink = sample_uplink_config();
    let spec = WireSpec::from_uplink(&uplink);

    assert_eq!(spec.wire, 0, "the primary wire is always index 0");
    assert_eq!(spec.name, uplink.name, "a wire reports its parent's name");
    assert_eq!(spec.transport, UplinkTransport::Vless);
    assert_eq!(spec.dial_mode(Plane::Tcp), uplink.tcp_dial_mode());
    assert_eq!(spec.dial_url(Plane::Tcp), uplink.tcp_dial_url());
}

#[test]
fn from_fallback_projects_the_fallback_wire_but_keeps_the_parent_name() {
    let mut uplink = sample_uplink_config();
    let fallback = crate::config::FallbackTransport {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://example.test/ss").unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH3,
        udp_ws_url: Some(Url::parse("wss://example.test/ssu").unwrap()),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH3,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH3,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        vless_id: None,
        cipher: uplink.cipher,
        password: "fallback-secret".to_string(),
        fwmark: Some(42),
        ipv6_first: true,
        fingerprint_profile: None,
    };
    uplink.fallbacks.push(fallback);

    let spec = WireSpec::from_fallback(&uplink.name, 1, &uplink.fallbacks[0]);

    assert_eq!(spec.wire, 1);
    assert_eq!(spec.name, uplink.name, "a fallback shares its parent's identity");
    assert_eq!(spec.transport, UplinkTransport::Ss, "but dials its own family");
    assert_eq!(spec.password, "fallback-secret", "and its own credentials");
    assert_eq!(spec.fwmark, Some(42));
    assert!(spec.ipv6_first);
    assert!(spec.supports_udp());
}

#[test]
fn combined_ss_discriminator_comes_from_the_wire_not_the_parent() {
    let mut uplink = sample_uplink_config();
    uplink.ss_ws_url = Some(Url::parse("wss://example.test/combined").unwrap());
    uplink.ss_mode = Some(TransportMode::WsH3);
    uplink.transport = UplinkTransport::Ss;
    uplink.fallbacks.push(crate::config::FallbackTransport {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://example.test/split-tcp").unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH3,
        udp_ws_url: Some(Url::parse("wss://example.test/split-udp").unwrap()),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH3,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH3,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        vless_id: None,
        cipher: uplink.cipher,
        password: "split".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    });

    let primary = WireSpec::from_uplink(&uplink);
    let fallback = WireSpec::from_fallback(&uplink.name, 1, &uplink.fallbacks[0]);

    assert_eq!(
        primary.combined_ss_kind(SsPathKind::Udp),
        Some(SsPathKind::Udp),
        "the parent is combined-SS, so its legs carry the discriminator"
    );
    assert_eq!(
        fallback.combined_ss_kind(SsPathKind::Udp),
        None,
        "the fallback uses split paths — a pool filled with the wrong leg drops every \
         reused datagram"
    );
}
```

Add the shared fixture to `crates/outline-uplink/src/tests/mod.rs` if it is not already there — check first with `grep -n "fn sample_uplink_config" crates/outline-uplink/src/tests/mod.rs`. If absent, append:

```rust
/// A minimal VLESS uplink for wire-projection tests: one primary carrier, no
/// fallbacks. Callers push their own fallbacks.
pub(crate) fn sample_uplink_config() -> crate::config::UplinkConfig {
    let mut uplink = crate::config::UplinkConfig::default();
    uplink.name = "nuxt".to_string();
    uplink.transport = crate::config::UplinkTransport::Vless;
    uplink.vless_mode = crate::config::TransportMode::XhttpH3;
    uplink.vless_xhttp_url = Some(url::Url::parse("https://example.test/x").unwrap());
    uplink.vless_id = Some([7u8; 16]);
    uplink
}
```

If `UplinkConfig` has no `Default`, build it field-by-field instead — run `grep -n "impl Default for UplinkConfig" crates/outline-uplink/src/config.rs` to check, and mirror the literal at `crates/outline-uplink/src/config.rs:445` (the existing constructor with `fallbacks: Vec::new()`).

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-uplink wire_spec`
Expected: FAIL — `unresolved import crate::wire_spec` / `module wire_spec not found`.

- [ ] **Step 3: Write the implementation**

Create `crates/outline-uplink/src/wire_spec.rs`:

```rust
//! One carrier's dial shape, projected out of whichever wire is being dialed.
//!
//! A wire is not an uplink. It carries its own transport family, URL, mode and
//! credentials, but it shares the parent's identity — name, weight, group — for
//! scoring, metrics and logging. This projection is what lets one dial path
//! serve the primary carrier and every fallback without reading
//! `candidate.uplink` directly: a dial path that reads the uplink cannot help
//! but target the primary, which is how the TUN ingress ended up unable to use
//! fallback wires at all.
//!
//! Padding is deliberately absent: it is configured per uplink
//! (`UplinkConfig::padding`), not per wire, so the padding scope stays wrapped
//! around the parent by the callers.

use url::Url;

use crate::config::{
    CipherKind, FallbackTransport, SsPathKind, TransportMode, UplinkConfig, UplinkTransport,
};

/// Which plane a dial is for. `WireSpec` holds both planes' URLs and modes
/// because one wire can serve both (VLESS muxes them; combined-SS shares one
/// URL), and the caller picks per dial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plane {
    Tcp,
    Udp,
}

/// The dial shape of a single wire. Borrowed from the config it projects, so it
/// is cheap to build per dial and never clones credentials.
#[derive(Clone, Copy, Debug)]
pub struct WireSpec<'a> {
    /// Parent uplink's display name — the same for every wire on it.
    pub name: &'a str,
    /// `0` for the primary carrier, `i` for `fallbacks[i - 1]`.
    pub wire: u8,
    pub transport: UplinkTransport,
    pub cipher: CipherKind,
    pub password: &'a str,
    pub vless_id: Option<[u8; 16]>,
    pub fwmark: Option<u32>,
    pub ipv6_first: bool,
    pub fingerprint_profile: Option<outline_transport::FingerprintProfileStrategy>,
    tcp_url: Option<&'a Url>,
    udp_url: Option<&'a Url>,
    tcp_mode: TransportMode,
    udp_mode: TransportMode,
    combined_ss: bool,
}

impl<'a> WireSpec<'a> {
    /// Project the primary carrier — wire `0`.
    pub fn from_uplink(uplink: &'a UplinkConfig) -> Self {
        Self {
            name: &uplink.name,
            wire: 0,
            transport: uplink.transport,
            cipher: uplink.cipher,
            password: &uplink.password,
            vless_id: uplink.vless_id,
            fwmark: uplink.fwmark,
            ipv6_first: uplink.ipv6_first,
            fingerprint_profile: uplink.fingerprint_profile,
            tcp_url: uplink.tcp_dial_url(),
            udp_url: uplink.udp_dial_url(),
            tcp_mode: uplink.tcp_dial_mode(),
            udp_mode: uplink.udp_dial_mode(),
            combined_ss: uplink.is_combined_ss(),
        }
    }

    /// Project `fallbacks[wire - 1]`. `parent_name` is the uplink's name: a
    /// fallback shares its parent's identity everywhere except the wire shape.
    pub fn from_fallback(parent_name: &'a str, wire: u8, fallback: &'a FallbackTransport) -> Self {
        Self {
            name: parent_name,
            wire,
            transport: fallback.transport,
            cipher: fallback.cipher,
            password: &fallback.password,
            vless_id: fallback.vless_id,
            fwmark: fallback.fwmark,
            ipv6_first: fallback.ipv6_first,
            fingerprint_profile: fallback.fingerprint_profile,
            tcp_url: fallback.tcp_dial_url(),
            udp_url: fallback.udp_dial_url(),
            tcp_mode: fallback.tcp_dial_mode(),
            udp_mode: fallback.udp_dial_mode(),
            combined_ss: fallback.is_combined_ss(),
        }
    }

    /// Project wire `wire` of `uplink`: `0` is the primary, anything else
    /// indexes `fallbacks`. `None` when the index is past the end.
    pub fn of(uplink: &'a UplinkConfig, wire: u8) -> Option<Self> {
        if wire == 0 {
            return Some(Self::from_uplink(uplink));
        }
        let fallback = uplink.fallbacks.get((wire - 1) as usize)?;
        Some(Self::from_fallback(&uplink.name, wire, fallback))
    }

    pub fn dial_url(&self, plane: Plane) -> Option<&'a Url> {
        match plane {
            Plane::Tcp => self.tcp_url,
            Plane::Udp => self.udp_url,
        }
    }

    pub fn dial_mode(&self, plane: Plane) -> TransportMode {
        match plane {
            Plane::Tcp => self.tcp_mode,
            Plane::Udp => self.udp_mode,
        }
    }

    /// The combined-SS discriminator for `leg`, or `None` when this wire uses
    /// the default split paths. Taken from the wire, never from the parent: a
    /// pool filled with the other leg's streams silently drops every reused
    /// datagram.
    pub fn combined_ss_kind(&self, leg: SsPathKind) -> Option<SsPathKind> {
        self.combined_ss.then_some(leg)
    }

    /// Whether this wire has a UDP path configured at all.
    pub fn supports_udp(&self) -> bool {
        self.udp_url.is_some()
    }

    /// Whether this wire's family can be dialed by the WS-family dial paths.
    pub fn is_ws_family(&self) -> bool {
        matches!(self.transport, UplinkTransport::Ss | UplinkTransport::Vless)
    }
}

#[cfg(test)]
#[path = "tests/wire_spec.rs"]
mod tests;
```

`FallbackTransport` needs `tcp_dial_mode` / `udp_dial_mode` if it does not have them — check with `grep -n "fn tcp_dial_mode" crates/outline-uplink/src/config.rs`; the `impl FallbackTransport` block at `config.rs:125` already has `tcp_dial_url`, `udp_dial_url`, `is_combined_ss` and `combined_ss_kind`. If the mode helpers are missing, add them to that block mirroring `UplinkConfig::tcp_dial_mode` at `config.rs:184`:

```rust
    pub fn tcp_dial_mode(&self) -> TransportMode {
        match self.transport {
            UplinkTransport::Vless => self.vless_mode,
            UplinkTransport::Ss if self.is_combined_ss() => self.ss_mode.unwrap_or(self.tcp_mode),
            _ => self.tcp_mode,
        }
    }

    pub fn udp_dial_mode(&self) -> TransportMode {
        match self.transport {
            UplinkTransport::Vless => self.vless_mode,
            UplinkTransport::Ss if self.is_combined_ss() => self.ss_mode.unwrap_or(self.udp_mode),
            _ => self.udp_mode,
        }
    }
```

Wire the module into `crates/outline-uplink/src/lib.rs` beside the other `mod` declarations:

```rust
pub mod wire_spec;
pub use wire_spec::{Plane, WireSpec};
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p outline-uplink wire_spec`
Expected: PASS, 3 tests.

- [ ] **Step 5: Run the full gate**

Run the three CI commands from Global Constraints.
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add crates/outline-uplink/src/wire_spec.rs crates/outline-uplink/src/tests/wire_spec.rs crates/outline-uplink/src/lib.rs crates/outline-uplink/src/config.rs crates/outline-uplink/src/tests/mod.rs
git diff --cached
```

Commit message:

```
feat(uplink): project a single wire's dial shape into WireSpec

Every dial path today reads candidate.uplink directly, which is the same
as saying "primary" — a fallback wire can only be dialed by code that
knows to reach into uplink.fallbacks itself. WireSpec projects either
side into one shape, so the dial core can be parameterised by wire
without each caller re-deriving URLs, modes and credentials.
```

---

### Task 2: The `tun_wire_dial` gate

**Files:**
- Modify: `crates/outline-uplink/src/config.rs` (add field to `LoadBalancingConfig`, near `health_weighted_selection` at line 869)
- Modify: `bins/outline-ws-rust/src/config/schema.rs:626` and `:898` (global and per-group raw sections)
- Modify: `bins/outline-ws-rust/src/config/load/balancing.rs:202` (resolution)
- Modify: `bins/outline-ws-rust/src/config/load/groups.rs:211` (per-group merge)
- Modify: every test literal of `LoadBalancingConfig` (~16 files; enumerate with the grep below)
- Test: `bins/outline-ws-rust/src/config/tests/load.rs` (or the existing config-load test module — locate with `grep -rn "health_weighted_selection" bins/outline-ws-rust/src/config/tests/`)

**Interfaces:**
- Produces: `LoadBalancingConfig::tun_wire_dial: bool`, default `false`. Tasks 6, 7 and 8 gate on it.

- [ ] **Step 1: Write the failing test**

Add to the config-load test module:

```rust
#[test]
fn tun_wire_dial_defaults_to_off() {
    let config = load_test_config(
        r#"
        [[outline.uplinks]]
        name = "nuxt"
        group = "main"
        transport = "vless"
        vless_ws_url = "wss://example.test/v"
        vless_mode = "ws_h3"
        vless_id = "ad9951e3-8f5d-497f-b785-7a94dabdd597"

        [[uplink_group]]
        name = "main"
        "#,
    );
    assert!(
        !config.groups["main"].load_balancing.tun_wire_dial,
        "the TUN wire chain ships inert: a deployed binary must be \
         indistinguishable from the previous one until the flag is set"
    );
}

#[test]
fn tun_wire_dial_can_be_enabled_per_group() {
    let config = load_test_config(
        r#"
        [[outline.uplinks]]
        name = "nuxt"
        group = "main"
        transport = "vless"
        vless_ws_url = "wss://example.test/v"
        vless_mode = "ws_h3"
        vless_id = "ad9951e3-8f5d-497f-b785-7a94dabdd597"

        [[uplink_group]]
        name = "main"

        [uplink_group.load_balancing]
        tun_wire_dial = true
        "#,
    );
    assert!(config.groups["main"].load_balancing.tun_wire_dial);
}
```

Match `load_test_config`'s real name and the config-shape helpers already used in that module — read the neighbouring tests first rather than assuming this helper exists.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-ws-rust tun_wire_dial`
Expected: FAIL — `no field tun_wire_dial on type LoadBalancingConfig`.

- [ ] **Step 3: Write the implementation**

In `crates/outline-uplink/src/config.rs`, beside `health_weighted_selection`:

```rust
    /// Let the TUN ingress dial the uplink's fallback wires, instead of always
    /// dialing the primary carrier.
    ///
    /// Default `false`, and deliberately so. The wire chain has only ever been
    /// reachable from the SOCKS ingress, which the fleet does not use; turning
    /// it on for TUN makes `shuffle_wires` genuinely rotate carriers, so
    /// traffic starts flowing over wires that have never carried it. That is
    /// the point of the feature, but it is not a change to make silently on
    /// every node at once — the flag exists so the binary can be deployed
    /// inert and enabled one node at a time.
    ///
    /// With this off, the TUN dial order degenerates to `[0]` and the warm
    /// pool stays on the primary wire, which is exactly today's behaviour.
    pub tun_wire_dial: bool,
```

In `bins/outline-ws-rust/src/config/schema.rs`, add to **both** raw sections (the global one at ~626 and the per-group one at ~898):

```rust
    /// Let the TUN ingress walk the fallback-wire chain. Default: `false`.
    pub(super) tun_wire_dial: Option<bool>,
```

In `bins/outline-ws-rust/src/config/load/balancing.rs`, beside the `health_weighted_selection` line:

```rust
        // Default: `false` — the TUN ingress keeps dialing the primary wire
        // only, as it always has. See `LoadBalancingConfig::tun_wire_dial`.
        tun_wire_dial: lb.and_then(|l| l.tun_wire_dial).unwrap_or(false),
```

In `bins/outline-ws-rust/src/config/load/groups.rs`, beside line 211:

```rust
        tun_wire_dial: section.tun_wire_dial,
```

Then fix every test literal. Enumerate them:

```bash
grep -rln "health_weighted_selection:" --include='*.rs' crates/ bins/
```

Each of those files constructs a `LoadBalancingConfig` literal; add `tun_wire_dial: false,` next to `health_weighted_selection`. Known list at time of writing: `crates/outline-uplink/src/tests/registry.rs`, `src/tests/fallback.rs`, `src/tests/mod.rs`, `src/manager/tests/snapshot.rs`, `src/manager/tests/reselect.rs`, `src/manager/tests/sticky.rs`, `src/manager/tests/candidates.rs`, `src/manager/standby/tests/mod.rs`, `src/manager/probe/tests/endpoint.rs`, `src/manager/probe/tests/wire.rs`, plus the rest the grep reports — do not trust this list over the grep.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p outline-ws-rust tun_wire_dial`
Expected: PASS, 2 tests.

- [ ] **Step 5: Run the full gate**

Run the three CI commands. `cargo test --workspace` is what proves no literal was missed.

- [ ] **Step 6: Commit**

Commit message:

```
feat(uplink): add the tun_wire_dial gate, default off

The TUN wire chain changes which carriers traffic actually flows over,
so it ships inert: with the flag off the dial order degenerates to [0]
and the warm pool stays on the primary wire, which is today's behaviour
exactly. Enabling proceeds one node at a time.
```

---

### Task 3: The TCP dial core takes a wire

**Files:**
- Modify: `crates/outline-uplink/src/manager/standby/mod.rs:49` (`FreshTcpDial`), `:363` (`tcp_dial_mode_for`), `:375` (`connect_tcp_ws_fresh_internal`), `:194` (`connect_tcp_ws_fresh`)
- Test: `crates/outline-uplink/src/manager/standby/tests/wire_dial_tcp.rs` (new)
- Modify: `crates/outline-uplink/src/manager/standby/mod.rs` (register the new test module)

**Interfaces:**
- Consumes: `WireSpec`, `Plane` (Task 1).
- Produces: `UplinkManager::connect_tcp_ws_fresh_on_wire(&self, candidate: &UplinkCandidate, wire: u8, source: &'static str) -> Result<TransportStream>`. Task 5 calls it.

- [ ] **Step 1: Write the failing test**

Create `crates/outline-uplink/src/manager/standby/tests/wire_dial_tcp.rs`:

```rust
//! A fallback-wire TCP dial must attribute itself to the wire it dialed —
//! its loss probe, its RTT sample and any carrier downgrade it observes.
//! Attributing them to the parent's primary slot is the bug class this
//! whole change exists to remove: it is how a fallback ended up capping
//! primary's carrier-descent slot, and how the loss verdict ended up in a
//! slot nobody reads.

use crate::types::TransportKind;

use super::sample_manager_with_fallbacks;

#[tokio::test]
async fn a_fallback_wire_dial_registers_its_probe_under_that_wire() {
    let manager = sample_manager_with_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    // The dial itself cannot succeed against a config pointing at an
    // unroutable host; what this asserts is the attribution recorded on the
    // way, which happens before the dial can fail.
    let _ = manager.connect_tcp_ws_fresh_on_wire(&candidate, 2, "test").await;

    let registered = manager.registered_loss_probe_wires_for_test(0, TransportKind::Tcp);
    assert!(
        !registered.contains(&0),
        "a wire-2 dial must not file its probe under the primary wire"
    );
}
```

If `sample_manager_with_fallbacks`, `tcp_candidates_for_test` or `registered_loss_probe_wires_for_test` do not exist, add them to `crates/outline-uplink/src/manager/standby/tests/mod.rs` as `pub(super)` helpers — read that file first and follow its existing manager-construction pattern rather than inventing a second one.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-uplink wire_dial_tcp`
Expected: FAIL — `no method named connect_tcp_ws_fresh_on_wire`.

- [ ] **Step 3: Write the implementation**

Add `wire` to `FreshTcpDial` (`standby/mod.rs:49`):

```rust
struct FreshTcpDial {
    resume_request: Option<SessionId>,
    ack_prefix_requested: bool,
    symmetric_replay_requested: bool,
    client_acked_offset: u64,
    bypass_mode_downgrade: bool,
    /// Which wire to dial: `0` is the uplink's primary carrier, `i` is
    /// `fallbacks[i - 1]`. Every existing constructor passes `0`, which is
    /// what it has always done implicitly.
    wire: u8,
}
```

Update `tcp_dial_mode_for` to work per wire:

```rust
    async fn tcp_dial_mode_for(
        &self,
        candidate: &UplinkCandidate,
        spec: &crate::WireSpec<'_>,
        bypass_mode_downgrade: bool,
    ) -> crate::config::TransportMode {
        if bypass_mode_downgrade {
            spec.dial_mode(crate::Plane::Tcp)
        } else {
            self.effective_tcp_mode_for_wire(candidate.index, spec.wire).await
        }
    }
```

Rewrite the body of `connect_tcp_ws_fresh_internal` to work through the spec:

```rust
    async fn connect_tcp_ws_fresh_internal(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
        dial: FreshTcpDial,
    ) -> Result<TransportStream> {
        let cache = self.inner.dns_cache.as_ref();
        let spec = crate::WireSpec::of(&candidate.uplink, dial.wire).ok_or_else(|| {
            anyhow!("uplink {} has no wire {}", candidate.uplink.name, dial.wire)
        })?;
        if !spec.is_ws_family() {
            bail!(
                "uplink {} wire {} does not use websocket transport",
                spec.name,
                spec.wire
            );
        }
        metrics::record_warm_standby_acquire("tcp", &self.inner.group_name, spec.name, "miss");
        let mode = self.tcp_dial_mode_for(candidate, &spec, dial.bypass_mode_downgrade).await;
        debug!(
            uplink = %spec.name,
            wire = spec.wire,
            mode = %mode,
            ack_prefix_requested = dial.ack_prefix_requested,
            bypass_mode_downgrade = dial.bypass_mode_downgrade,
            "no warm-standby TCP websocket available, dialing on-demand"
        );
        let url = spec.dial_url(crate::Plane::Tcp).ok_or_else(|| {
            anyhow!("uplink {} wire {} missing tcp dial URL", spec.name, spec.wire)
        })?;
        let started = Instant::now();
        let ws = crate::dial::dial_in_uplink_scope(
            &candidate.uplink,
            connect_transport(
                TransportDialOptions::new(cache, url, mode, source)
                    .with_network(DialNetworkOptions {
                        fwmark: spec.fwmark,
                        ipv6_first: spec.ipv6_first,
                    })
                    .with_combined_ss_kind(spec.combined_ss_kind(SsPathKind::Tcp))
                    .with_resume(resume_options(&dial)),
            ),
        )
        .await
        .with_context(|| TransportOperation::Connect { target: format!("to {}", url) })?;
        // Attribution follows the wire that was actually dialed. Filing this
        // under the primary wire — which is what this function did while it
        // could only ever dial the primary — puts the loss verdict in a slot
        // that nothing reads once `active_wire` moves, and lets one carrier's
        // descent cap another's.
        self.register_carrier_loss_probe(
            candidate.index,
            spec.wire,
            TransportKind::Tcp,
            ws.loss_probe(),
        );
        self.report_connection_latency_for_wire(
            candidate.index,
            TransportKind::Tcp,
            spec.wire,
            started.elapsed(),
        )
        .await;
        if let Some(requested) = ws.downgraded_from() {
            self.note_silent_transport_fallback_for_wire(
                candidate.index,
                TransportKind::Tcp,
                spec.wire,
                requested,
            );
        }
        Ok(ws)
    }
```

`report_connection_latency_for_wire` may not exist. Check with `grep -n "fn report_connection_latency" crates/outline-uplink/src/manager/*.rs`. If only the parent-level version exists, add a per-wire sibling next to it that feeds `record_wire_rtt` (the per-wire EWMA already used by the fallback-wire probe at `manager/probe/wire.rs`) and delegates to the existing function when `wire == 0`.

Add the new public entry point next to `connect_tcp_ws_fresh` (`standby/mod.rs:194`):

```rust
    /// Dial `wire` on `candidate` as a fresh session, bypassing the warm pool.
    /// `wire = 0` is the primary carrier and is what every pre-existing caller
    /// gets through [`Self::connect_tcp_ws_fresh`].
    pub async fn connect_tcp_ws_fresh_on_wire(
        &self,
        candidate: &UplinkCandidate,
        wire: u8,
        source: &'static str,
    ) -> Result<TransportStream> {
        self.connect_tcp_ws_fresh_internal(
            candidate,
            source,
            FreshTcpDial { wire, ..FreshTcpDial::default() },
        )
        .await
    }
```

If `FreshTcpDial` has no `Default`, derive one (`#[derive(Default)]`) — all its fields are `Option`, `bool` and `u64`. Then set `wire: 0` in every existing construction site; `grep -n "FreshTcpDial {" crates/outline-uplink/src/manager/standby/mod.rs` lists them.

Register the test module beside the existing ones in `standby/mod.rs`:

```rust
#[cfg(test)]
#[path = "tests/wire_dial_tcp.rs"]
mod wire_dial_tcp_tests;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p outline-uplink wire_dial_tcp`
Expected: PASS.

- [ ] **Step 5: Run the full gate**

Expected: all green. Existing standby tests must still pass unchanged — this task adds a parameter whose default reproduces the old behaviour.

- [ ] **Step 6: Commit**

Commit message:

```
feat(uplink): dial a chosen wire on the TCP plane, attributing it correctly

The one internal TCP dial entry point now resolves a WireSpec instead of
reading candidate.uplink, so it can target any wire. Attribution follows:
the loss probe, the RTT sample and any observed carrier downgrade land in
the dialed wire's slot rather than in primary's.
```

---

### Task 4: The UDP dial core takes a wire, including VLESS

**Files:**
- Modify: `crates/outline-uplink/src/manager/standby/mod.rs:486` (`acquire_udp_standby_or_connect_with_store` and its VLESS branch at ~505–660)
- Test: `crates/outline-uplink/src/manager/standby/tests/wire_dial_udp.rs` (new)

**Interfaces:**
- Consumes: `WireSpec`, `Plane` (Task 1).
- Produces: `UplinkManager::acquire_udp_on_wire(&self, candidate: &UplinkCandidate, wire: u8, source: &'static str, resume_store: &UdpResumeStore) -> Result<UdpSessionTransport>`. Task 5 calls it.

- [ ] **Step 1: Write the failing test**

Create `crates/outline-uplink/src/manager/standby/tests/wire_dial_udp.rs`:

```rust
//! VLESS on a fallback wire used to be rejected outright: the QUIC mux was
//! built from the parent uplink's fields, so a fallback could only be SS.
//! On a fleet whose primary *and* first fallback are both VLESS, that left
//! the UDP plane with no usable fallback at all.

use crate::types::TransportKind;

use super::{sample_manager_with_vless_fallback, udp_candidate_for_test};

#[tokio::test]
async fn a_vless_fallback_wire_is_dialable_on_udp() {
    let manager = sample_manager_with_vless_fallback().await;
    let candidate = udp_candidate_for_test(&manager, 0).await;

    let result = manager
        .acquire_udp_on_wire(
            &candidate,
            1,
            "test",
            &outline_transport::UdpResumeStore::ProcessWide,
        )
        .await;

    // The dial cannot complete against an unroutable test host; what must
    // not happen is a rejection on the grounds of the wire's family.
    if let Err(error) = result {
        let rendered = format!("{error:#}");
        assert!(
            !rendered.contains("not supported") && !rendered.contains("unsupported"),
            "a VLESS fallback wire must be dialable, got: {rendered}"
        );
    }
}

#[tokio::test]
async fn a_wire_without_a_udp_path_is_rejected_by_index_not_by_family() {
    let manager = sample_manager_with_vless_fallback().await;
    let candidate = udp_candidate_for_test(&manager, 0).await;

    let error = manager
        .acquire_udp_on_wire(
            &candidate,
            9,
            "test",
            &outline_transport::UdpResumeStore::ProcessWide,
        )
        .await
        .expect_err("wire 9 does not exist");

    assert!(format!("{error:#}").contains("wire 9"));
    let _ = TransportKind::Udp;
}
```

Add `sample_manager_with_vless_fallback` and `udp_candidate_for_test` to `standby/tests/mod.rs` following the construction pattern already there.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-uplink wire_dial_udp`
Expected: FAIL — `no method named acquire_udp_on_wire`.

- [ ] **Step 3: Write the implementation**

Rename the existing function's body into a wire-aware one and keep the old entry points as wrappers:

```rust
    pub async fn acquire_udp_standby_or_connect_with_store(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
        resume_store: &outline_transport::UdpResumeStore,
    ) -> Result<UdpSessionTransport> {
        self.acquire_udp_on_wire(candidate, 0, source, resume_store).await
    }

    /// Acquire a UDP carrier on `wire`. `wire = 0` is the primary carrier and
    /// reproduces the behaviour every existing caller has.
    pub async fn acquire_udp_on_wire(
        &self,
        candidate: &UplinkCandidate,
        wire: u8,
        source: &'static str,
        resume_store: &outline_transport::UdpResumeStore,
    ) -> Result<UdpSessionTransport> {
        let spec = crate::WireSpec::of(&candidate.uplink, wire)
            .ok_or_else(|| anyhow!("uplink {} has no wire {}", candidate.uplink.name, wire))?;
        // … existing body, with every read of `candidate.uplink` replaced …
    }
```

Inside the body, replace exactly these reads:

| Was | Becomes |
|---|---|
| `candidate.uplink.transport == UplinkTransport::Vless` | `spec.transport == UplinkTransport::Vless` |
| `candidate.uplink.udp_dial_url()` | `spec.dial_url(crate::Plane::Udp)` |
| `candidate.uplink.vless_id` | `spec.vless_id` |
| `self.effective_udp_mode(candidate.index)` | `self.effective_udp_mode_for_wire(candidate.index, spec.wire)` |
| `candidate.uplink.fwmark` | `spec.fwmark` |
| `candidate.uplink.ipv6_first` | `spec.ipv6_first` |
| `candidate.uplink.cipher` / `.password` | `spec.cipher` / `spec.password` |
| `candidate.uplink.combined_ss_kind(SsPathKind::Udp)` | `spec.combined_ss_kind(SsPathKind::Udp)` |
| `candidate.uplink.name` in messages and labels | `spec.name` |

Two callbacks capture the wire so their notifications land in the right slot:

```rust
            let probe_manager = self.clone();
            let probe_index = candidate.index;
            let probe_wire = spec.wire;
            let on_carrier: outline_transport::VlessUdpCarrierNotifier =
                Arc::new(move |probe: Option<outline_transport::CarrierLossProbe>| {
                    probe_manager.register_carrier_loss_probe(
                        probe_index,
                        probe_wire,
                        TransportKind::Udp,
                        probe,
                    );
                });

            let manager = self.clone();
            let index = candidate.index;
            let downgrade_wire = spec.wire;
            let on_downgrade: outline_transport::VlessUdpDowngradeNotifier =
                Arc::new(move |requested: outline_transport::TransportMode| {
                    manager.note_silent_transport_fallback_for_wire(
                        index,
                        TransportKind::Udp,
                        downgrade_wire,
                        requested,
                    );
                });
```

Leave `with_uplink_padding_scope(&candidate.uplink, …)` on the parent: padding is configured per uplink, not per wire.

The warm-standby branch (`self.standby_ctx(candidate.index, TransportKind::Udp)`) stays as it is in this task — Task 8 moves the pool onto the active wire. Until then a non-zero wire must not take from the pool; guard it:

```rust
        // The pool is filled on the primary wire until Task 8 moves it; a
        // fallback-wire acquire must never be handed a primary-wire stream.
        if spec.wire == 0 {
            let ctx = self.standby_ctx(candidate.index, TransportKind::Udp).await;
            if let Some(ws) = ctx.try_take_alive(&candidate.uplink.name).await {
                // … existing pooled path …
            }
        }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p outline-uplink wire_dial_udp`
Expected: PASS, 2 tests.

- [ ] **Step 5: Run the full gate**

Expected: all green.

- [ ] **Step 6: Commit**

Commit message:

```
feat(uplink): dial a chosen wire on the UDP plane, VLESS included

The QUIC mux was built out of the parent uplink's fields, so a fallback
wire could only ever be SS — on a fleet whose primary and first fallback
are both VLESS that left the UDP plane with no usable fallback at all.
Building it from a WireSpec removes the restriction rather than
special-casing it.
```

---

### Task 5: The shared wire loop

**Files:**
- Create: `crates/outline-uplink/src/manager/wire_dial.rs`
- Create: `crates/outline-uplink/src/manager/tests/wire_dial.rs`
- Modify: `crates/outline-uplink/src/manager/mod.rs` (register the module)

**Interfaces:**
- Consumes: `wire_dial_order`, `record_wire_outcome` (both existing), `connect_tcp_ws_fresh_on_wire` (Task 3), `acquire_udp_on_wire` (Task 4).
- Produces: `WireAttempt<T>` (`Built(T)` / `NotApplicable`) and `UplinkManager::dial_over_wires<T, F, Fut>(&self, candidate: &UplinkCandidate, transport: TransportKind, allow_fallbacks: bool, build: F) -> Result<(T, u8)>` where `F: FnMut(u8) -> Fut, Fut: Future<Output = Result<WireAttempt<T>>>`. Tasks 6, 7 and 10 call it.
- `allow_fallbacks` is the caller's decision, not the helper's: the TUN ingress passes `load_balancing().tun_wire_dial` because its wire support is what ships gated, while the SOCKS ingress passes `true` because it has walked the chain for as long as the chain has existed. A helper that read the gate itself would silently strip SOCKS of its fallbacks the moment Task 10 routes it through here.

- [ ] **Step 1: Write the failing test**

Create `crates/outline-uplink/src/manager/tests/wire_dial.rs`:

```rust
//! The wire loop's contract, which is easy to get subtly wrong in two ways:
//! a failure *after* the dial (the SS handshake, say) must retire the wire
//! just as a failed dial does, and exhausting the chain must surface one
//! error without any intermediate parent-level runtime failure — otherwise
//! one broken carrier flaps the whole uplink out of the candidate set.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::manager::wire_dial::WireAttempt;
use crate::types::TransportKind;

use super::sample_manager_with_three_fallbacks;

#[tokio::test]
async fn a_build_failure_advances_the_chain_just_like_a_dial_failure() {
    let manager = sample_manager_with_three_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;
    let attempts = Arc::new(AtomicUsize::new(0));

    let seen = Arc::clone(&attempts);
    let result: Result<(u8, u8)> = manager
        .dial_over_wires(&candidate, TransportKind::Tcp, true, move |wire| {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                if wire == 3 {
                    Ok(WireAttempt::Built(wire))
                } else {
                    // Stands in for an SS handshake that fails after a
                    // perfectly successful dial.
                    Err(anyhow!("handshake failed on wire {wire}"))
                }
            }
        })
        .await;

    let (value, wire) = result.expect("wire 3 succeeds");
    assert_eq!(value, 3);
    assert_eq!(wire, 3, "the winning wire is reported to the caller");
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        4,
        "every wire is tried once, in order, until one builds"
    );
}

#[tokio::test]
async fn exhausting_every_wire_yields_one_error() {
    let manager = sample_manager_with_three_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    let result: Result<(u8, u8)> = manager
        .dial_over_wires(&candidate, TransportKind::Tcp, true, |wire| async move {
            Err(anyhow!("wire {wire} is down"))
        })
        .await;

    let error = result.expect_err("no wire can build");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("all wires failed"),
        "the caller needs one error it can attribute to the uplink, got: {rendered}"
    );
}

#[tokio::test]
async fn a_not_applicable_wire_is_skipped_without_recording_an_outcome() {
    let manager = sample_manager_with_three_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    let (value, wire) = manager
        .dial_over_wires(&candidate, TransportKind::Tcp, true, |wire| async move {
            if wire == 0 {
                Ok(WireAttempt::NotApplicable)
            } else {
                Ok(WireAttempt::Built(wire))
            }
        })
        .await
        .expect("a later wire builds");

    assert_eq!(value, wire);
    assert_ne!(wire, 0);
    assert_eq!(
        manager.wire_outcome_count_for_test(0, TransportKind::Tcp, 0),
        0,
        "a wire that never ran must not move its own state machine"
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-uplink manager::tests::wire_dial`
Expected: FAIL — `no method named dial_over_wires`.

- [ ] **Step 3: Write the implementation**

Create `crates/outline-uplink/src/manager/wire_dial.rs`:

```rust
//! Walking an uplink's wire chain, once, for both ingresses.
//!
//! The loop lives here rather than in each ingress because the two things it
//! must get right are the two things a second copy gets wrong. First, a wire
//! is retired on the outcome of the *whole* attempt — dial plus transport
//! assembly — because an SS handshake that fails after a clean dial means that
//! wire is just as unusable. Second, the parent uplink is only reported as
//! failing once every one of its wires has failed: a single broken carrier
//! must not flap the uplink out of the candidate set, which is what makes
//! within-uplink failover worth having at all.

use anyhow::{Context, Result, anyhow};
use tracing::debug;

use crate::types::{TransportKind, UplinkCandidate, UplinkManager};

/// What one wire attempt concluded.
pub enum WireAttempt<T> {
    /// The wire built a working transport.
    Built(T),
    /// The wire is not applicable on this plane at all — no UDP path
    /// configured, say. Not a failure: it never ran, so it must not move the
    /// wire's state machine. Spelling this as a variant rather than as an
    /// error keeps "this wire is broken" and "this wire was never a candidate"
    /// apart, which the wire weights depend on.
    NotApplicable,
}

impl UplinkManager {
    /// Try each wire of `candidate` in the manager's preferred order, handing
    /// each one to `build`. Returns the first successful build together with
    /// the wire it landed on.
    ///
    /// `build` owns the dial *and* the transport assembly for one wire —
    /// see the module docs for why the split matters. Callers differ in what
    /// they assemble (SS versus VLESS, TUN versus SOCKS binding), which is why
    /// this takes a closure rather than returning a raw stream. The closure is
    /// called at most once per wire and its future is awaited before the next
    /// call, so it may borrow freely from the caller's scope.
    pub async fn dial_over_wires<T, F, Fut>(
        &self,
        candidate: &UplinkCandidate,
        transport: TransportKind,
        allow_fallbacks: bool,
        mut build: F,
    ) -> Result<(T, u8)>
    where
        F: FnMut(u8) -> Fut,
        Fut: std::future::Future<Output = Result<WireAttempt<T>>>,
    {
        let total_wires = 1 + candidate.uplink.fallbacks.len();
        let order = if allow_fallbacks && total_wires > 1 {
            self.wire_dial_order(candidate.index, transport, total_wires)
        } else {
            // Caller opted out, or there is nothing to fall back to: the
            // primary wire, exactly as before this loop existed. The gate
            // belongs to the caller — see this method's doc — because only the
            // TUN ingress's wire support is new enough to need gating.
            vec![0]
        };

        let mut last_err: Option<anyhow::Error> = None;
        for &wire in &order {
            match build(wire).await {
                Ok(WireAttempt::NotApplicable) => {
                    // Deliberately no `record_wire_outcome`: nothing was
                    // attempted, so there is no outcome. Recording a failure
                    // here would teach the wire weights that a wire is broken
                    // when it was only ever irrelevant on this plane.
                    debug!(
                        uplink = %candidate.uplink.name,
                        wire,
                        "wire is not applicable on this plane, skipping",
                    );
                },
                Ok(WireAttempt::Built(value)) => {
                    self.record_wire_outcome(candidate.index, transport, wire, true, total_wires);
                    if wire != 0 {
                        debug!(
                            uplink = %candidate.uplink.name,
                            wire,
                            "fallback wire dial succeeded",
                        );
                    }
                    return Ok((value, wire));
                },
                Err(error) => {
                    self.record_wire_outcome(candidate.index, transport, wire, false, total_wires);
                    debug!(
                        uplink = %candidate.uplink.name,
                        wire,
                        error = %format!("{error:#}"),
                        "wire dial failed, trying the next one",
                    );
                    last_err = Some(error);
                },
            }
        }

        Err(last_err
            .unwrap_or_else(|| anyhow!("no wires configured"))
            .context(format!("all wires failed on uplink {}", candidate.uplink.name)))
    }
}

#[cfg(test)]
#[path = "tests/wire_dial.rs"]
mod tests;
```

Register in `crates/outline-uplink/src/manager/mod.rs` beside the sibling modules:

```rust
mod wire_dial;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p outline-uplink manager::tests::wire_dial`
Expected: PASS, 3 tests. The fixture needs no gate setting — these tests pass `allow_fallbacks: true` directly, since the gate belongs to the caller.

- [ ] **Step 5: Run the full gate**

- [ ] **Step 6: Commit**

Commit message:

```
feat(uplink): walk the wire chain in one shared loop

Both ingresses need the same two properties: a wire retires on the
outcome of dial plus transport assembly, not of the dial alone, and the
parent uplink is only reported failing once every wire has failed. A
second copy of the loop is exactly where those get lost.
```

---

### Task 6: TUN TCP dials the wire chain

**Files:**
- Modify: `crates/outline-tun/src/tcp/engine/connect.rs:247` (`connect_tcp_uplink_inner`)
- Test: `crates/outline-tun/src/tcp/engine/tasks/upstream/tests/connect.rs` (extend)

**Interfaces:**
- Consumes: `dial_over_wires` (Task 5), `connect_tcp_ws_fresh_on_wire` (Task 3).
- Produces: no new API; TUN TCP flows now land on a wire chosen by the manager.

- [ ] **Step 1: Write the failing test**

Extend the upstream connect test module:

```rust
#[tokio::test]
async fn tun_tcp_falls_back_to_a_sibling_wire_before_leaving_the_uplink() {
    let harness = TunConnectHarness::with_dead_primary_wire().await;

    let connected = harness.connect_flow("example.test:443").await.expect("flow connects");

    assert_eq!(
        connected.uplink_name, "nuxt",
        "a dead primary carrier must not cost the whole uplink"
    );
    assert_ne!(connected.wire_index, 0, "the flow landed on a fallback wire");
}
```

Build `TunConnectHarness::with_dead_primary_wire` on whatever fixture the existing tests in that file use — read them first. It must set `tun_wire_dial: true`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-tun falls_back_to_a_sibling_wire`
Expected: FAIL — the flow either fails outright or reports the sibling uplink, because TUN dials the primary only.

- [ ] **Step 3: Write the implementation**

Replace `connect_tcp_uplink_inner` in `crates/outline-tun/src/tcp/engine/connect.rs`:

```rust
async fn connect_tcp_uplink_inner(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
) -> Result<(TcpWriter, TcpReader, Option<SessionId>)> {
    let keepalive_interval = uplinks.load_balancing().tcp_ws_keepalive_interval;
    // The TUN ingress's wire support is what ships gated; the helper itself
    // stays neutral so the SOCKS path keeps the chain it has always had.
    let wires_enabled = uplinks.load_balancing().tun_wire_dial;

    let (built, _wire) = uplinks
        .dial_over_wires(candidate, TransportKind::Tcp, wires_enabled, |wire| async move {
            // Credentials come from the wire being dialed, not from the
            // parent: an SS fallback behind a VLESS primary must be set up
            // with its own family, cipher and password.
            let spec = outline_uplink::WireSpec::of(&candidate.uplink, wire)
                .ok_or_else(|| anyhow!("uplink {} has no wire {wire}", candidate.uplink.name))?;

            // Variant A, primary wire only: a warm-standby connection. If it
            // turns out to be stale (fails before any server bytes arrive)
            // discard it silently and fall through to a fresh dial, without
            // recording a runtime failure. The pool only holds primary-wire
            // carriers until Task 8 teaches it to follow the active wire.
            // `try_take_tcp_standby` still has its single-argument shape
            // here; Task 8 gives it a wire and removes this guard.
            if wire == 0
                && let Some(ws) = uplinks.try_take_tcp_standby(candidate).await
            {
                let binding = tun_tcp_binding(uplinks, &candidate.uplink.name);
                match do_tcp_ss_setup(ws, &spec, target, keepalive_interval, binding, false).await
                {
                    Ok(v) => return Ok(WireAttempt::Built(v)),
                    Err(e) => {
                        debug!(
                            uplink = %candidate.uplink.name,
                            error = %format!("{e:#}"),
                            "stale standby TCP pool connection, retrying with fresh dial"
                        );
                    },
                }
            }

            let ws = uplinks.connect_tcp_ws_fresh_on_wire(candidate, wire, "tun_tcp").await?;
            let binding = tun_tcp_binding(uplinks, &candidate.uplink.name);
            do_tcp_ss_setup(ws, &spec, target, keepalive_interval, binding, false)
                .await
                .map(WireAttempt::Built)
        })
        .await?;

    Ok(built)
}
```

This requires changing `do_tcp_ss_setup`'s second parameter in the same file from `&outline_uplink::UplinkConfig` to `&outline_uplink::WireSpec<'_>`. Inside it, read `spec.transport`, `spec.cipher`, `spec.password`, `spec.vless_id` and `spec.name` where it reads `uplink.transport`, `uplink.cipher`, `uplink.password`, `uplink.vless_id` and `uplink.name` today. This mirrors what `WireSetup` already does on the SOCKS path.

Its other caller in this file, `redial_tcp_uplink_for_migration_inner`, must be updated to pass a `WireSpec` too — pass `&outline_uplink::WireSpec::from_uplink(&candidate.uplink)` for now; Task 9 replaces that with the flow's own wire.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p outline-tun falls_back_to_a_sibling_wire`
Expected: PASS.

- [ ] **Step 5: Run the full gate**

Expected: all green, and every pre-existing TUN test unchanged — with the gate off the loop yields `[0]`.

- [ ] **Step 6: Commit**

Commit message:

```
feat(tun): dial the uplink's wire chain on TCP flows

A TUN flow could only ever reach an uplink's primary carrier, so a
carrier broken by DPI cost the whole server rather than one wire of it.
The setup helper now takes a WireSpec, so a fallback of a different
family is handed its own credentials instead of the parent's.
```

---

### Task 7: TUN UDP dials the wire chain

**Files:**
- Modify: `crates/outline-tun/src/udp/lifecycle.rs:1049` (fresh acquire) and `:614` (soft-switch redial)
- Test: `crates/outline-tun/src/udp/tests/lifecycle.rs` (extend; locate the existing UDP test module first)

**Interfaces:**
- Consumes: `dial_over_wires` (Task 5), `acquire_udp_on_wire` (Task 4).

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn tun_udp_skips_a_wire_with_no_udp_path() {
    let harness = TunUdpHarness::with_tcp_only_first_fallback().await;

    let transport = harness.acquire("1.1.1.1:53").await.expect("a UDP carrier is acquired");

    assert_ne!(
        transport.wire_index, 1,
        "wire 1 has no UDP path configured and must be skipped, not dialed and failed"
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-tun skips_a_wire_with_no_udp_path`
Expected: FAIL — `wire_index` is always 0 today, or the harness method does not exist yet.

- [ ] **Step 3: Write the implementation**

At `lifecycle.rs:1049`, replace the direct acquire:

```rust
        let wires_enabled = manager.load_balancing().tun_wire_dial;
        let acquired = manager
            .dial_over_wires(&candidate, TransportKind::Udp, wires_enabled, |wire| async move {
                let spec = outline_uplink::WireSpec::of(&candidate.uplink, wire)
                    .ok_or_else(|| anyhow!("uplink {} has no wire {wire}", candidate.uplink.name))?;
                // A wire with no UDP path is not a failure of that wire — it
                // was never dialable on this plane. Skipping without an
                // outcome keeps it out of the wire state machine entirely.
                if !spec.supports_udp() {
                    return Ok(WireAttempt::NotApplicable);
                }
                manager
                    .acquire_udp_on_wire(&candidate, wire, "tun_udp", resume_store)
                    .await
                    .map(WireAttempt::Built)
            })
            .await;
```

`WireAttempt::NotApplicable` is what keeps a wire with no UDP path out of the wire state machine entirely — it was never dialable on this plane, so recording a failure would teach the weights that it is broken. The variant comes from Task 5; nothing new is needed here.

At `lifecycle.rs:614` (the soft-switch redial), dial the flow's current wire rather than the primary:

```rust
        let wire = manager.active_wire(candidate.index, TransportKind::Udp);
        let connected = manager
            .acquire_udp_on_wire(&candidate, wire, "tun_udp", resume_store)
            .await;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p outline-tun skips_a_wire_with_no_udp_path`
Expected: PASS.

- [ ] **Step 5: Run the full gate**

- [ ] **Step 6: Commit**

Commit message:

```
feat(tun): dial the uplink's wire chain on UDP flows

A wire with no UDP path is skipped rather than dialed and failed: it was
never applicable on this plane, so moving its state machine would teach
the wire chain a failure that did not happen.
```

---

### Task 8: The warm pool follows the active wire

**Files:**
- Modify: `crates/outline-uplink/src/manager/standby_pool.rs:126` (`StandbyPool` — add the wire marker)
- Modify: `crates/outline-uplink/src/manager/standby/ctx.rs:52` (`standby_ctx`)
- Modify: `crates/outline-uplink/src/manager/standby/refill.rs:24` (`pool_ss_leg`) and `:192` (the combined-SS dial)
- Modify: `crates/outline-tun/src/tcp/engine/connect.rs` (drop the `wire == 0` guard on the pool take from Task 6)
- Modify: `crates/outline-uplink/src/manager/standby/mod.rs` (drop the `wire == 0` guard on the UDP pool take from Task 4)
- Test: `crates/outline-uplink/src/manager/standby/tests/pool_wire.rs` (new)

**Interfaces:**
- Consumes: `WireSpec` (Task 1), `active_wire` (existing).
- Produces: `StandbyPool::wire` marker semantics; no new public API.

- [ ] **Step 1: Write the failing test**

Create `crates/outline-uplink/src/manager/standby/tests/pool_wire.rs`:

```rust
//! The pool is prewarmed on one wire. When the active wire moves — a shuffle
//! reroll, a failover — the pooled carriers belong to a wire nobody is
//! landing on any more. Handing one out would put a flow on a carrier the
//! manager does not consider active, which is precisely the split this whole
//! change removes.

use crate::types::TransportKind;

use super::sample_manager_with_three_fallbacks;

#[tokio::test]
async fn a_pool_filled_on_another_wire_is_drained_rather_than_handed_out() {
    let manager = sample_manager_with_three_fallbacks().await;
    manager.fill_pool_for_test(0, TransportKind::Tcp, 0, 2).await;
    assert_eq!(manager.pool_len_for_test(0, TransportKind::Tcp), 2);

    manager.set_active_wire_for_test(0, TransportKind::Tcp, 2);
    let candidate = manager.tcp_candidates_for_test(0).await;
    let taken = manager.try_take_tcp_standby(&candidate, 2).await;

    assert!(taken.is_none(), "a wire-0 carrier must not serve a wire-2 flow");
    assert_eq!(
        manager.pool_len_for_test(0, TransportKind::Tcp),
        0,
        "the stale pool is drained so the refill can repopulate on the active wire"
    );
}

#[tokio::test]
async fn asking_for_a_wire_the_pool_does_not_serve_does_not_drain_it() {
    let manager = sample_manager_with_three_fallbacks().await;
    manager.set_active_wire_for_test(0, TransportKind::Tcp, 0);
    manager.fill_pool_for_test(0, TransportKind::Tcp, 0, 2).await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    let taken = manager.try_take_tcp_standby(&candidate, 3).await;

    assert!(taken.is_none(), "wire 3 is not what the pool holds");
    assert_eq!(
        manager.pool_len_for_test(0, TransportKind::Tcp),
        2,
        "draining here would fight the refill loop forever: drain, refill on \
         the active wire, drain again on the next take for another wire"
    );
}

#[tokio::test]
async fn the_pool_dials_the_active_wire_on_refill() {
    let manager = sample_manager_with_three_fallbacks().await;
    manager.set_active_wire_for_test(0, TransportKind::Tcp, 2);

    let ctx = manager.standby_ctx_for_test(0, TransportKind::Tcp).await;

    assert_eq!(
        ctx.wire, 2,
        "refill must prewarm the wire flows will actually land on"
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-uplink pool_wire`
Expected: FAIL — `StandbyCtx` has no `wire` field; the take returns a pooled stream regardless of wire.

- [ ] **Step 3: Write the implementation**

Add the marker to `StandbyPool`:

```rust
    /// Which wire the pooled carriers were dialed on. `shuffle_wires` and
    /// wire failover both move the active wire underneath a filled pool, and a
    /// carrier from the old wire must never be handed to a flow that the
    /// manager considers to be landing on the new one.
    pub(crate) tcp_wire: AtomicU8,
    pub(crate) udp_wire: AtomicU8,
```

Add `wire` to `StandbyCtx` and source URL and mode per wire in `standby_ctx`:

```rust
        // With the gate off the pool must stay exactly where it is today —
        // on the primary wire. `shuffle_timer` moves `active_wire` regardless
        // of the gate, so reading it unconditionally would prewarm a wire that
        // nothing dials, and every take would miss.
        let wire = if lb.tun_wire_dial { self.active_wire(index, transport) } else { 0 };
        let spec = crate::WireSpec::of(uplink, wire).unwrap_or_else(|| {
            // An active wire past the end of the chain is a bug in the wire
            // state machine, not a reason to stop prewarming: fall back to the
            // primary rather than leaving the pool cold.
            crate::WireSpec::from_uplink(uplink)
        });
        match transport {
            TransportKind::Tcp => StandbyCtx {
                manager: self,
                uplink,
                index,
                transport,
                wire: spec.wire,
                pool: &pool.tcp,
                refill_lock: &pool.tcp_refill,
                label: "tcp",
                refill_source: "standby_tcp",
                desired: lb.warm_standby_tcp,
                url: spec.dial_url(crate::Plane::Tcp),
                mode: self.effective_tcp_mode_for_wire(index, spec.wire).await,
                combined_ss: spec.combined_ss_kind(SsPathKind::Tcp),
            },
            // … UDP arm mirrors this with Plane::Udp, warm_standby_udp,
            //   effective_udp_mode_for_wire and SsPathKind::Udp …
        }
```

`try_take_alive` gains a `wanted: u8` parameter — the wire the caller is dialing — and distinguishes two cases that must not be conflated:

```rust
        // Asking for a wire the pool is not prewarming is not a staleness
        // problem: the pool belongs to the active wire, and this caller wants
        // a different one. Draining here would fight the refill loop in a
        // permanent cycle — drain, refill on the active wire, drain again on
        // the next take for another wire.
        if wanted != self.wire {
            return None;
        }
        // The marker names the wire these carriers were dialed on. A mismatch
        // means the active wire moved under a filled pool: drain it so the
        // refill repopulates on the wire flows are landing on now.
        let filled_on = self.pool_wire_marker().load(Ordering::Relaxed);
        if filled_on != self.wire {
            let drained = self.pool.drain_all().await;
            if drained > 0 {
                debug!(
                    uplink = %self.uplink.name,
                    transport = self.label,
                    filled_on,
                    active = self.wire,
                    drained,
                    "draining a warm pool filled on a wire that is no longer active",
                );
            }
            self.pool_wire_marker().store(self.wire, Ordering::Relaxed);
            self.record_acquire("wire_changed");
            return None;
        }
```

In `refill.rs`, take the combined-SS discriminator from the ctx rather than the parent:

```rust
                        .with_combined_ss_kind(self.combined_ss)
```

and delete `pool_ss_leg`'s use of `self.uplink.combined_ss_kind(...)` — the leg still selects `SsPathKind::Tcp` or `SsPathKind::Udp`, but whether the discriminator applies at all is now the wire's property.

Register the loss probe filed by a pool take under `ctx.wire` rather than the literal `0` in `standby/mod.rs:178`, `:433`, `:577` and `:658` — grep for `register_carrier_loss_probe` in that file and replace every literal `0` with the wire actually dialed.

Finally drop the two temporary `wire == 0` guards: the one in `acquire_udp_on_wire` (Task 4) and the one in `connect_tcp_uplink_inner` (Task 6). The wire the caller wants now travels into the take itself, which answers `None` for any wire the pool is not prewarming:

```rust
            if let Some(ws) = uplinks.try_take_tcp_standby(candidate, wire).await
```

`try_take_tcp_standby` and its UDP sibling gain the same `wire` parameter and pass it through to `try_take_alive`. Every existing caller — the SOCKS primary path included — passes the wire it is dialing, which for `connect_tcp_uplink_primary` is `0`.

`drain_all` may not exist on `TrackedDeque` — check with `grep -n "fn drain\|fn clear" crates/outline-uplink/src/manager/standby_pool.rs` and add one that pops every entry, dropping each stream, and returns the count.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p outline-uplink pool_wire`
Expected: PASS, 3 tests.

- [ ] **Step 5: Run the full gate**

- [ ] **Step 6: Commit**

Commit message:

```
fix(uplink): prewarm the wire flows actually land on

The warm pool was always dialed on the primary carrier, so with the wire
chain live every rotation would have sent each new flow through a fresh
dial while a pool of unusable carriers sat beside it. The pool now
follows the active wire and drains when that wire moves; the combined-SS
leg discriminator comes from the wire, since a pool filled with the other
leg's streams silently drops every reused datagram.
```

---

### Task 8b: The active wire leads the health-weighted dial order

**Files:**
- Modify: `crates/outline-uplink/src/manager/active_wire.rs:158` (`wire_dial_order`, the `health_weighted_selection` branch)
- Test: `crates/outline-uplink/src/manager/tests/active_wire.rs` (or the existing test module covering `wire_dial_order` — locate it first)

**Interfaces:**
- Consumes: `wire_weight`, `weighted_permutation_with_rng` (both existing).
- Produces: no new API. `wire_dial_order` keeps its signature and its guarantee of returning a complete permutation.

**Why this exists.** Task 8 put the warm pool on the active wire. But
`wire_dial_order`'s health-weighted branch deliberately ignores `active_wire`
and returns a weighted random permutation — and `health_weighted_selection`
defaults to `true`. So the wire dialed first is frequently not the wire the
pool is warming: the take misses, and every flow pays a fresh dial, which is
exactly what Task 8 set out to remove. The same split is why the carrier-loss
metric vanished from the fleet's dashboards for ~60% of wall-clock time —
`active_wire` did not mean "the wire new sessions land on".

This makes it mean that again, without giving up liveness weighting for the
rest of the chain.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn the_active_wire_leads_the_health_weighted_order() {
    let manager = manager_with_four_wires_and_health_weighting().await;
    manager.set_active_wire_for_test(0, TransportKind::Tcp, 2);

    // Weighted order is random in its tail, so assert the invariant over
    // several draws rather than one: the head is pinned, the tail is a
    // permutation of everything else.
    for _ in 0..16 {
        let order = manager.wire_dial_order(0, TransportKind::Tcp, 4);
        assert_eq!(order[0], 2, "the pool is warmed on the active wire, so it must be dialed first");
        let mut rest = order[1..].to_vec();
        rest.sort_unstable();
        assert_eq!(rest, vec![0, 1, 3], "every other wire still appears exactly once");
    }
}

#[tokio::test]
async fn an_out_of_range_active_wire_does_not_break_the_order() {
    let manager = manager_with_four_wires_and_health_weighting().await;
    manager.set_active_wire_for_test(0, TransportKind::Tcp, 9);

    let order = manager.wire_dial_order(0, TransportKind::Tcp, 4);

    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, vec![0, 1, 2, 3], "a stale active wire must not drop or duplicate a wire");
}
```

Match the fixture helpers the existing `wire_dial_order` tests already use; the
assertions are the requirement.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p outline-uplink active_wire_leads`
Expected: FAIL — the active wire currently leads only by chance.

- [ ] **Step 3: Write the implementation**

In the `health_weighted_selection` branch of `wire_dial_order`, keep the
weighted permutation for the chain, then lift the active wire to the front:

```rust
            let mut order: Vec<u8> = weighted_permutation_with_rng(&weights, &mut rng)
                .into_iter()
                .map(|i| i as u8)
                .collect();
            // The warm pool is prewarmed on the active wire (see
            // `standby_ctx`), so dialing anything else first throws that
            // prewarm away and pays a fresh dial per flow. Liveness weighting
            // still orders the rest of the chain — this only pins the head,
            // which is what makes `active_wire` mean "the wire new sessions
            // land on" rather than a number nothing consults.
            let active = self.active_wire(uplink_index, transport);
            if let Some(pos) = order.iter().position(|&w| w == active) {
                order[..=pos].rotate_right(1);
            }
            debug_assert_eq!(order.len(), total_wires);
            return order;
```

`position` returning `None` — an active wire past the end of the chain, which
the non-weighted branch defends against with its own cap — leaves the weighted
order untouched rather than panicking.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p outline-uplink active_wire_leads`
Expected: PASS.

- [ ] **Step 5: Run the full gate**

Note this changes the SOCKS ingress's dial order too, not only TUN's — it is
not behind `tun_wire_dial`. That is deliberate: the pin is a correction to what
`active_wire` means, and the SOCKS path reads the same field. Every
pre-existing test must still pass; if one asserted the old free-permutation
behaviour, report it rather than editing its expectation.

- [ ] **Step 6: Commit**

Commit message:

```
fix(uplink): dial the active wire first under health weighting

The health-weighted branch of wire_dial_order ignored active_wire, so the
wire dialed first was rarely the wire the warm pool had been prewarming —
every flow paid a fresh dial while a usable pool sat beside it. Liveness
weighting still orders the rest of the chain; only the head is pinned.
```

---

### Task 9: A live TCP flow migrates onto its own wire

**Files:**
- Modify: `crates/outline-tun/src/tcp/engine/connect.rs:172` (`redial_tcp_uplink_for_migration_inner`)
- Modify: `crates/outline-uplink/src/manager/standby/mod.rs:317`, `:340` (migrate helpers gain a wire)
- Test: `crates/outline-tun/src/tcp/engine/tasks/upstream/tests/migrate.rs` (extend)

**Interfaces:**
- Consumes: `connect_tcp_ws_fresh_on_wire` (Task 3), `active_wire` (existing).

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn a_migrating_flow_redials_its_active_wire_not_the_primary() {
    let harness = TunMigrateHarness::new().await;
    harness.set_active_wire(TransportKind::Tcp, 2);

    let redial = harness.migrate_flow().await.expect("the flow migrates");

    assert_eq!(
        redial.wire_index, 2,
        "redialing the primary would slam a carrier this flow never used, and \
         its failure would surface as a runtime failure on the parent uplink"
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-tun redials_its_active_wire`
Expected: FAIL — the redial reports wire 0.

- [ ] **Step 3: Write the implementation**

Give the two migrate helpers a wire parameter, mirroring Task 3:

```rust
    pub async fn connect_tcp_ws_migrate_with_ack_prefix_on_wire(
        &self,
        candidate: &UplinkCandidate,
        wire: u8,
        source: &'static str,
        resume_request: Option<SessionId>,
    ) -> Result<TransportStream> {
        self.connect_tcp_ws_fresh_internal(
            candidate,
            source,
            FreshTcpDial {
                wire,
                resume_request,
                ack_prefix_requested: true,
                bypass_mode_downgrade: true,
                ..FreshTcpDial::default()
            },
        )
        .await
    }
```

and the symmetric-replay sibling likewise, carrying `symmetric_replay_requested: true` and `client_acked_offset`. Keep the existing no-wire methods as wrappers passing `0`.

In `redial_tcp_uplink_for_migration_inner`, resolve the wire and the spec:

```rust
    let wire = uplinks.active_wire(candidate.index, TransportKind::Tcp);
    let spec = outline_uplink::WireSpec::of(&candidate.uplink, wire)
        .ok_or_else(|| anyhow!("uplink {} has no wire {wire}", candidate.uplink.name))?;
    if !spec.is_ws_family() {
        bail!(
            "carrier migration needs a WS-family wire (SS-WS or VLESS-WS); uplink {} wire {} \
             uses transport {:?}",
            spec.name,
            wire,
            spec.transport,
        );
    }
```

then pass `wire` to the migrate helper and `&spec` to `do_tcp_ss_setup`. Move the family check that currently sits in `redial_tcp_uplink_for_migration` (line 146, which tests `candidate.uplink.transport`) into this inner function so it tests the wire being dialed.

A wire change here can change proxy protocol; the server allows cross-protocol resume on the byte-stream path, so no client-side gate is needed. Note it in the function's doc comment.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p outline-tun redials_its_active_wire`
Expected: PASS.

- [ ] **Step 5: Run the full gate**

- [ ] **Step 6: Commit**

Commit message:

```
fix(tun): migrate a flow onto its own wire, not onto primary

A flow living on a fallback wire redialed the primary URL when its
carrier died. That dial usually fails, and its failure surfaces as a
runtime failure on the parent uplink — the false flap the active-wire
state machine exists to prevent.
```

---

### Task 10: The SOCKS path joins the shared loop

**Files:**
- Modify: `bins/outline-ws-rust/src/proxy/tcp/failover.rs:171` (`connect_tcp_uplink_inner`), `:705` (`connect_tcp_fallback_fresh` — delete), `:839` (`WireSetup` — delete)
- Modify: `bins/outline-ws-rust/src/proxy/udp/transport.rs:40` (`acquire_udp_with_fallbacks`), and delete `dial_udp_fallback`
- Modify: `bins/outline-ws-rust/src/proxy/tcp/connect/failover_step.rs:63` (keep its own loop — it walks *untried* wires, which is a different traversal; leave it, but have it call `connect_tcp_specific_wire` which now routes through the shared dial)

**Interfaces:**
- Consumes: everything from Tasks 1–5.
- Produces: one implementation of fallback dialing in the tree instead of two.

- [ ] **Step 1: Write the failing test**

The behaviour is already covered by the SOCKS fallback tests; this task must not change it. Pin that explicitly first — add to the SOCKS failover test module:

```rust
#[tokio::test]
async fn socks_fallback_still_reports_the_wire_it_landed_on() {
    let harness = SocksFailoverHarness::with_dead_primary_wire().await;

    let connected = harness.connect("example.test:443").await.expect("flow connects");

    assert_ne!(connected.wire_index, 0);
    assert_eq!(connected.source, TcpUplinkSource::FreshDial);
}
```

- [ ] **Step 2: Run the test to verify it passes on the current code**

Run: `cargo test -p outline-ws-rust socks_fallback_still_reports`
Expected: PASS before the refactor. This is a characterisation test — it must stay green through the change.

- [ ] **Step 3: Do the refactor**

Rewrite `connect_tcp_uplink_inner` in `failover.rs` to use `dial_over_wires`, passing `allow_fallbacks: true` — the SOCKS path is not gated, it has walked the chain for as long as the chain has existed, and `tun_wire_dial` governs the TUN ingress only. The closure does what `connect_tcp_fallback_fresh` did: resolve the `WireSpec`, dial via `connect_tcp_ws_fresh_on_wire` (wire 0 still goes through `connect_tcp_uplink_primary` for the pool), then `do_tcp_ss_setup` with `&spec`.

Delete `connect_tcp_fallback_fresh` and `WireSetup`; replace every `WireSetup::from_uplink(x)` with `WireSpec::from_uplink(x)` and every `WireSetup::from_fallback(name, fb)` with `WireSpec::from_fallback(name, wire, fb)`. `do_tcp_ss_setup` in this file already takes `&WireSetup<'_>`, so the change is the type and the two extra fields it can now read.

In `proxy/udp/transport.rs`, replace `acquire_udp_with_fallbacks`'s hand-written loop with `dial_over_wires` (again `allow_fallbacks: true`), its closure calling `acquire_udp_on_wire` and returning `WireAttempt::NotApplicable` for a wire whose `supports_udp()` is false. Delete `dial_udp_fallback` and the doc paragraph stating that VLESS is unsupported as a UDP fallback — Task 4 removed that restriction.

- [ ] **Step 4: Run the tests to verify nothing changed**

Run: `cargo test -p outline-ws-rust`
Expected: PASS, including `socks_fallback_still_reports_the_wire_it_landed_on` and every pre-existing fallback test.

- [ ] **Step 5: Run the full gate**

- [ ] **Step 6: Commit**

Commit message:

```
refactor(proxy): dial fallback wires through the shared loop

The SOCKS path grew its own fallback dialing because the manager could
only dial primary. With the dial core wire-aware, the second
implementation is just a place for the two to drift apart — which is how
the TUN ingress ended up with no wire support at all. VLESS as a UDP
fallback stops being a documented gap.
```

---

### Task 11: End-to-end coverage and documentation

**Files:**
- Modify: the e2e failover harness (locate with `grep -rln "e2e" --include='*.rs' crates/ bins/ | head`)
- Modify: `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md` and `.ru.md`
- Modify: `CHANGELOG.md` and `CHANGELOG.ru.md`

- [ ] **Step 1: Write the e2e test**

```rust
#[tokio::test]
async fn a_dead_primary_carrier_stays_within_the_uplink() {
    let fleet = E2eFleet::builder()
        .uplink_with_wires("nuxt", &["vless/xhttp_h3", "vless/ws_h3", "ss/ws_h3"])
        .uplink_with_wires("senko", &["vless/xhttp_h3"])
        .tun_wire_dial(true)
        .build()
        .await;
    fleet.kill_wire("nuxt", 0);

    let flow = fleet.open_tun_tcp_flow("example.test:443").await.expect("flow connects");

    assert_eq!(flow.uplink, "nuxt", "a broken carrier costs one wire, not the server");
    assert_ne!(flow.wire, 0);
    assert_eq!(
        fleet.runtime_failures("nuxt"),
        0,
        "one broken wire must not flap the uplink out of the candidate set"
    );
}
```

Match the existing harness's builder API rather than inventing this one — read it first.

- [ ] **Step 2: Run it to verify it fails, then passes**

Run: `cargo test -p outline-ws-rust a_dead_primary_carrier_stays_within_the_uplink`
Expected: it should pass on the code from Tasks 1–10. If it fails, the failure is a real gap — fix it before continuing rather than adjusting the test.

- [ ] **Step 3: Update `UPLINK-CONFIGURATIONS.md`**

Find the section describing `fallbacks` and `shuffle_wires` and correct its reach. The current text does not say the wire chain was SOCKS-only. Add:

```markdown
### Which ingress walks the wire chain

Until `tun_wire_dial` the fallback-wire chain was reachable only from the
SOCKS ingress. A TUN flow always dialed the uplink's primary carrier, so a
broken primary cost the whole uplink and `shuffle_wires` rotated nothing —
it moved `active_wire` while every dial kept going to wire 0.

With `[load_balancing] tun_wire_dial = true` the TUN ingress walks the same
chain in both planes, the warm-standby pool is prewarmed on the active wire
and drained when that wire moves, and a live flow whose carrier dies
migrates onto its own wire. The flag defaults to `false`.

UDP migration of a live flow is limited to wires of the same proxy
protocol: the server does not transfer datagram or mux parks across
protocols.
```

Write the RU counterpart in `UPLINK-CONFIGURATIONS.ru.md` in the same commit — the same content, not a summary. Use «носитель» for carrier, never «карьер».

- [ ] **Step 4: Update both CHANGELOGs**

Add an entry to `CHANGELOG.md` and the matching one to `CHANGELOG.ru.md`.

- [ ] **Step 5: Run the full gate**

- [ ] **Step 6: Commit**

Commit message:

```
docs(uplink): document which ingress walks the wire chain

The fallback-wire chain was reachable only from the SOCKS ingress, which
the docs never said — so a config with three fallbacks and shuffle_wires
read as configured redundancy while dialing wire 0 every time.
```

---

## Rollout (owner-driven, after all tasks land)

Not part of the implementation tasks; recorded so it is not improvised later.

1. Deploy the binary with `tun_wire_dial` unset. It must be indistinguishable from the current one — confirm via `carrier_loss_ratio` still tracking `active_wire == 0` and no change in `transport_connects_total` by source.
2. Enable on `.102` only, one node, with all four clients moved off it first. Deploy via `ops/deploy/deploy-binary.sh`. No restart without explicit approval.
3. Confirm the three signs from the design doc: loss-probe registrations with `wire != 0`; `active_wire_rtt_ewma` published for non-zero wires; `carrier_loss_ratio` no longer disappearing when `active_wire_index` leaves 0.
4. Watch `outline_ss_orphan_resume_*` on the servers: with rotation live, cross-protocol resume stops being rare.
5. Only then consider the remaining nodes, one at a time.
