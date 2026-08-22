//! Process-wide handle to the running client's uplink registry, so an embedder
//! (Android `VpnService`) can read the *currently active* carrier without a
//! metrics/control HTTP surface.
//!
//! `bootstrap` publishes the registry here right after it is built and clears
//! it on shutdown; [`active_carriers`] reads the default group's active TCP and
//! UDP wires and reports each one's effective transport mode (`ws_h3`,
//! `xhttp_h2`, …). All of this rides ungated core accessors, so it works in the
//! slim Android build where the `metrics` feature — and its Prometheus byte
//! counters — is compiled out.

use std::sync::{Mutex, OnceLock};

use outline_uplink::{TransportKind, UplinkManager, UplinkRegistry};

/// The active client's registry, or `None` while no client is running. Stored
/// as a cheap `UplinkRegistry` clone (an `Arc` handle), swapped on start/stop.
static ACTIVE: OnceLock<Mutex<Option<UplinkRegistry>>> = OnceLock::new();

fn slot() -> &'static Mutex<Option<UplinkRegistry>> {
    ACTIVE.get_or_init(|| Mutex::new(None))
}

/// Publish the running client's registry. Called once from `bootstrap` after
/// the registry is built; a second call (a fresh start after a stop that never
/// cleared) simply overwrites the stale handle.
pub fn set_active_registry(registry: UplinkRegistry) {
    *slot().lock().expect("status registry mutex poisoned") = Some(registry);
}

/// Drop the published registry. Safe to call when nothing is set.
pub fn clear_active_registry() {
    *slot().lock().expect("status registry mutex poisoned") = None;
}

/// The active carrier on one transport: the transport family and the effective
/// carrier mode of the wire currently carrying it. These are independent axes — either family
/// (`ss` / `vless`) can ride either carrier (`ws_*` / `xhttp_*`), so both are
/// needed to name the carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carrier {
    /// Transport family: `"ss"` or `"vless"`.
    pub family: String,
    /// Effective transport mode: `ws_h1`/`ws_h2`/`ws_h3`/`xhttp_h1`/`xhttp_h2`/
    /// `xhttp_h3`.
    pub mode: String,
}

/// The active carriers for each transport in the default group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierStatus {
    /// Default group name the carriers belong to.
    pub group: String,
    /// Carrier the wire new TCP sessions currently land on.
    pub tcp: Option<Carrier>,
    /// Carrier the wire new UDP sessions currently land on.
    pub udp: Option<Carrier>,
    /// Whether the tunnel still has a usable path, as opposed to a *proven*
    /// outage. `false` only when every uplink is confirmed down on both TCP and
    /// UDP; an uplink whose health is not established yet (freshly started, no
    /// probe cycle or traffic so far) keeps this `true`, so a starting tunnel
    /// reads as connecting rather than flashing "no link".
    pub has_live_link: bool,
}

/// Read the default group's active TCP/UDP carriers, or `None` if no client is
/// running. Async: the effective-mode lookup awaits the manager's internal
/// state locks. Cheap enough to poll every couple of seconds.
pub async fn active_carriers() -> Option<CarrierStatus> {
    let registry = slot().lock().expect("status registry mutex poisoned").clone()?;
    let manager = registry.default_group();
    let group = manager.group_name().to_string();
    let tcp = active_carrier(&manager, TransportKind::Tcp).await;
    let udp = active_carrier(&manager, TransportKind::Udp).await;
    // Status reports a *proven* outage, not "nothing proven healthy yet":
    // `has_any_healthy` (what routing gates on) is false during the startup
    // window before any probe or traffic, which would surface as a spurious
    // "no link". Both transports must be confirmed down for that claim.
    let has_live_link = !(manager.link_confirmed_down(TransportKind::Tcp).await
        && manager.link_confirmed_down(TransportKind::Udp).await);
    Some(CarrierStatus { group, tcp, udp, has_live_link })
}

/// The active carrier for `transport`: the family and effective mode of the wire
/// that transport's new sessions land on. Resolves the active uplink
/// (strict-active selection, falling back to the global active uplink), then
/// that uplink's active wire, then reads both axes off that wire — folding in
/// its mode-downgrade slot.
async fn active_carrier(manager: &UplinkManager, transport: TransportKind) -> Option<Carrier> {
    let index = match manager.active_uplink_index_for_transport(transport).await {
        Some(index) => index,
        None => manager.global_active_uplink_index().await?,
    };
    // Resolve the wire first: a fallback chain mixes families (a VLESS primary
    // with `ss://` fallbacks is the standard generated shape), so the family
    // belongs to the wire that is actually carrying this transport, not to the
    // parent uplink.
    let wire = manager.active_wire(index, transport);
    let family = manager.wire_transport(index, wire)?;
    let mode = match transport {
        TransportKind::Tcp => manager.effective_tcp_mode_for_wire(index, wire).await,
        TransportKind::Udp => manager.effective_udp_mode_for_wire(index, wire).await,
    };
    Some(Carrier { family, mode: mode.to_string() })
}
