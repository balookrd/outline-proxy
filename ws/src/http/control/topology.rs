use serde::Serialize;

use outline_metrics::{UplinkManagerSnapshot, UplinkSnapshot};

/// One per-wire entry in [`ControlUplinkTopology::configured_wire_chain`].
/// Surfaces the configured + effective TCP / UDP transport mode strings,
/// per-wire downgrade flags, and per-wire XHTTP submode state for primary
/// (index 0) and each fallback (index `1..`). Shadowsocks wires have
/// `*_mode` / `*_mode_effective` unset — their TCP/UDP shape is fixed
/// by the address fields, not a mode enum. `*_xhttp_submode` is unset
/// for non-XHTTP wires (only VLESS / XHTTP carriers have a submode axis).
#[derive(Debug, Clone, Serialize)]
struct WireChainEntry {
    transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_mode_effective: Option<String>,
    #[serde(skip_serializing_if = "is_false_ref")]
    tcp_downgrade_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_xhttp_submode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_xhttp_submode_effective: Option<String>,
    #[serde(skip_serializing_if = "is_false_ref")]
    tcp_xhttp_submode_downgrade_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_mode_effective: Option<String>,
    #[serde(skip_serializing_if = "is_false_ref")]
    udp_downgrade_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_xhttp_submode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_xhttp_submode_effective: Option<String>,
    #[serde(skip_serializing_if = "is_false_ref")]
    udp_xhttp_submode_downgrade_active: bool,
}

fn is_false_ref(v: &bool) -> bool {
    !*v
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ControlTopologyResponse {
    pub(crate) instance: ControlInstanceTopology,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ControlInstanceTopology {
    pub(crate) groups: Vec<ControlGroupTopology>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ControlGroupTopology {
    name: String,
    generated_at_unix_ms: u128,
    load_balancing_mode: String,
    routing_scope: String,
    auto_failback: bool,
    global_active_uplink: Option<String>,
    global_active_reason: Option<String>,
    tcp_active_uplink: Option<String>,
    tcp_active_reason: Option<String>,
    udp_active_uplink: Option<String>,
    udp_active_reason: Option<String>,
    uplinks: Vec<ControlUplinkTopology>,
}

#[derive(Debug, Clone, Serialize)]
struct ControlUplinkTopology {
    index: usize,
    name: String,
    transport: String,
    tcp_mode: Option<String>,
    udp_mode: Option<String>,
    /// Effective TCP mode after applying the H3/QUIC → H2 auto-downgrade
    /// window. Equals `tcp_mode` when no downgrade is active.
    tcp_mode_effective: Option<String>,
    /// Effective UDP mode after applying the H3/QUIC → H2 auto-downgrade
    /// window. Equals `udp_mode` when no downgrade is active.
    udp_mode_effective: Option<String>,
    tcp_downgrade_active: bool,
    udp_downgrade_active: bool,
    /// XHTTP submode the dial URL configures (`packet-up` /
    /// `stream-one`). `None` for non-VLESS uplinks. Mirrors
    /// `tcp_mode` / `udp_mode` but on the orthogonal submode axis.
    tcp_xhttp_submode: Option<String>,
    udp_xhttp_submode: Option<String>,
    /// Effective XHTTP submode after applying the per-host stream-one
    /// block. Equals the configured submode unless the cache holds a
    /// fresh stream-one failure for this host, in which case it
    /// degrades to `packet-up`. `None` outside the XHTTP family.
    tcp_xhttp_submode_effective: Option<String>,
    udp_xhttp_submode_effective: Option<String>,
    /// True while a recent stream-one failure has clamped this dial URL
    /// to `packet-up` in the per-host cache. Mirrors `tcp_downgrade_active`
    /// / `udp_downgrade_active` but on the submode axis.
    tcp_xhttp_submode_downgrade_active: bool,
    udp_xhttp_submode_downgrade_active: bool,
    weight: f64,
    tcp_score_ms: Option<u128>,
    udp_score_ms: Option<u128>,
    /// Smoothed per-transport probe RTT (EWMA over `rtt_ewma_alpha`).
    /// Independent of `selection_score`, which in `routing_scope = "global"`
    /// is one combined value per uplink and is therefore equal across
    /// transports. The dashboard surfaces these so the operator sees real
    /// per-transport latency.
    tcp_rtt_ewma_ms: Option<u128>,
    udp_rtt_ewma_ms: Option<u128>,
    /// RTT EWMA for the wire that **new TCP sessions** currently land on.
    /// Mirrors `tcp_rtt_ewma_ms` when active is primary; reads the
    /// per-fallback-wire slot when the dial loop / probe walk has flipped
    /// onto a fallback. Surfaced separately so the dashboard can render
    /// the latency of the wire actually carrying traffic without breaking
    /// Prometheus consumers that already rely on `tcp_rtt_ewma_ms`'s
    /// primary-only semantics.
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_active_wire_rtt_ewma_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_active_wire_rtt_ewma_ms: Option<u128>,
    tcp_healthy: Option<bool>,
    udp_healthy: Option<bool>,
    /// Effective health on this transport — true when probe-confirmed OR
    /// (for uplinks with at least one fallback) when any wire has dialed
    /// successfully within the runtime-failure window. The "is this
    /// uplink delivering traffic?" signal the dashboard reads to colour
    /// the row, distinct from `tcp_healthy` which reflects only the
    /// primary wire's probe verdict.
    tcp_health_effective: Option<bool>,
    udp_health_effective: Option<bool>,
    last_error: Option<String>,
    active_global: bool,
    active_global_reason: Option<String>,
    active_tcp: bool,
    active_tcp_reason: Option<String>,
    active_udp: bool,
    active_udp_reason: Option<String>,
    /// Configured per-uplink fallback transports (`[[outline.uplinks.fallbacks]]`).
    /// Empty when the uplink is single-wire. The dashboard renders these as the
    /// `primary → fb[0] → fb[1]` chain pill below the protocol cell.
    configured_fallbacks: Vec<String>,
    /// Fully-resolved view of every wire on this uplink (primary + fallbacks)
    /// with the configured TCP / UDP modes per wire. Used by the dashboard
    /// to render the active-wire mode in the top pill (e.g. `VLESS/WS/H2`)
    /// instead of just the bare transport. Empty for single-wire uplinks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    configured_wire_chain: Vec<WireChainEntry>,
    /// Index into `[primary, fallbacks[0], …]` of the wire currently carrying
    /// TCP traffic. Always `0` for single-wire uplinks.
    tcp_active_wire: u8,
    udp_active_wire: u8,
    /// Remaining auto-failback pin time on the active wire when it is *not* the
    /// primary, in ms. `None` when the primary is active or no pin is in flight.
    tcp_active_wire_pin_remaining_ms: Option<u128>,
    udp_active_wire_pin_remaining_ms: Option<u128>,
    /// Effective browser-fingerprint diversification strategy on this
    /// uplink (per-uplink override if set, otherwise process-wide default).
    /// Lowercase snake_case: `none` / `per_host_stable` / `random`. The
    /// dashboard reads this to colour the chip; the field is omitted
    /// from JSON when it equals `none` so older snapshot consumers
    /// (and the common opt-out deployment) keep the same wire shape
    /// they had before this field landed.
    #[serde(skip_serializing_if = "is_none_strategy")]
    fingerprint_profile_strategy: String,
    /// Active profile name (`chrome-130-macos`, `firefox-130-windows`,
    /// `safari-17-macos`, `edge-130-windows`, …) for the uplink's
    /// primary dial URL under the effective strategy. The dashboard
    /// renders this directly inside the FP chip so the operator sees
    /// the actual identity on the wire instead of just the strategy
    /// token. `Some("random")` for `random` strategy (rotation, no
    /// stable identity); absent for `none` strategy or
    /// Shadowsocks-over-raw-socket uplinks where no URL-based dial
    /// path engages the fingerprint module.
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint_profile_name: Option<String>,
}

fn is_none_strategy(s: &str) -> bool {
    s == "none"
}

/// Resolve the effective submode for one direction. Returns the
/// configured shape unchanged unless a stream-one block is live in the
/// per-host cache, in which case stream-one degrades to packet-up.
/// `None` when the uplink is not XHTTP (the configured field is also
/// `None` in that case, so the dashboard shows nothing on the submode
/// pill).
fn effective_submode(
    configured: Option<&str>,
    block_active: bool,
) -> Option<String> {
    let cfg = configured?;
    if block_active && cfg == "stream-one" {
        Some("packet-up".to_string())
    } else {
        Some(cfg.to_string())
    }
}

fn effective_mode(
    transport: &str,
    configured: Option<&str>,
    downgrade_active: bool,
    capped_to: Option<&str>,
) -> Option<String> {
    let mode = configured?;
    let supports_downgrade = matches!(transport, "ws" | "vless");
    if !(downgrade_active && supports_downgrade) {
        return Some(mode.to_string());
    }
    // Source of truth is the per-uplink `mode_downgrade_capped_to`
    // surfaced via the snapshot — family-aware (`WsH2` for `WsH3` /
    // `Quic`, `XhttpH2` for `XhttpH3`, `XhttpH1` for `XhttpH2`) and
    // multi-step-aware (a second failure on the already-capped
    // carrier lowers `capped_to` one rank further). Fall back to the
    // configured mode if the cap field is missing — defensive: the
    // window-active flag is meaningful on its own and a corrupted
    // payload should not strand the dashboard on a stale entry.
    Some(capped_to.unwrap_or(mode).to_string())
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct ControlSummaryResponse {
    pub(crate) groups_total: usize,
    pub(crate) uplinks_total: usize,
    pub(crate) tcp_healthy: usize,
    pub(crate) tcp_unhealthy: usize,
    pub(crate) udp_healthy: usize,
    pub(crate) udp_unhealthy: usize,
    pub(crate) active_global: usize,
    pub(crate) active_tcp: usize,
    pub(crate) active_udp: usize,
}

pub(crate) fn build_instance_topology(
    snapshots: &[UplinkManagerSnapshot],
) -> ControlInstanceTopology {
    ControlInstanceTopology {
        groups: snapshots.iter().map(build_group_topology).collect(),
    }
}

fn build_group_topology(snapshot: &UplinkManagerSnapshot) -> ControlGroupTopology {
    ControlGroupTopology {
        name: snapshot.group.clone(),
        generated_at_unix_ms: snapshot.generated_at_unix_ms,
        load_balancing_mode: snapshot.load_balancing_mode.clone(),
        routing_scope: snapshot.routing_scope.clone(),
        auto_failback: snapshot.auto_failback,
        global_active_uplink: snapshot.global_active_uplink.clone(),
        global_active_reason: snapshot.global_active_reason.clone(),
        tcp_active_uplink: snapshot.tcp_active_uplink.clone(),
        tcp_active_reason: snapshot.tcp_active_reason.clone(),
        udp_active_uplink: snapshot.udp_active_uplink.clone(),
        udp_active_reason: snapshot.udp_active_reason.clone(),
        uplinks: snapshot
            .uplinks
            .iter()
            .map(|uplink| build_uplink_topology(snapshot, uplink))
            .collect(),
    }
}

fn build_uplink_topology(
    snapshot: &UplinkManagerSnapshot,
    uplink: &UplinkSnapshot,
) -> ControlUplinkTopology {
    let tcp_downgrade_active = uplink.h3_tcp_downgrade_until_ms.is_some_and(|ms| ms > 0);
    let udp_downgrade_active = uplink.h3_udp_downgrade_until_ms.is_some_and(|ms| ms > 0);
    let tcp_mode_effective = effective_mode(
        &uplink.transport,
        uplink.tcp_mode.as_deref(),
        tcp_downgrade_active,
        uplink.tcp_mode_capped_to.as_deref(),
    );
    let udp_mode_effective = effective_mode(
        &uplink.transport,
        uplink.udp_mode.as_deref(),
        udp_downgrade_active,
        uplink.udp_mode_capped_to.as_deref(),
    );
    let tcp_xhttp_submode_downgrade_active =
        uplink.tcp_xhttp_submode_block_remaining_ms.is_some_and(|ms| ms > 0);
    let udp_xhttp_submode_downgrade_active =
        uplink.udp_xhttp_submode_block_remaining_ms.is_some_and(|ms| ms > 0);
    let tcp_xhttp_submode_effective = effective_submode(
        uplink.tcp_xhttp_submode.as_deref(),
        tcp_xhttp_submode_downgrade_active,
    );
    let udp_xhttp_submode_effective = effective_submode(
        uplink.udp_xhttp_submode.as_deref(),
        udp_xhttp_submode_downgrade_active,
    );
    ControlUplinkTopology {
        index: uplink.index,
        name: uplink.name.clone(),
        transport: uplink.transport.clone(),
        tcp_mode: uplink.tcp_mode.clone(),
        udp_mode: uplink.udp_mode.clone(),
        tcp_mode_effective,
        udp_mode_effective,
        tcp_downgrade_active,
        udp_downgrade_active,
        tcp_xhttp_submode: uplink.tcp_xhttp_submode.clone(),
        udp_xhttp_submode: uplink.udp_xhttp_submode.clone(),
        tcp_xhttp_submode_effective,
        udp_xhttp_submode_effective,
        tcp_xhttp_submode_downgrade_active,
        udp_xhttp_submode_downgrade_active,
        weight: uplink.weight,
        tcp_score_ms: uplink.tcp_score_ms,
        udp_score_ms: uplink.udp_score_ms,
        tcp_rtt_ewma_ms: uplink.tcp_rtt_ewma_ms,
        udp_rtt_ewma_ms: uplink.udp_rtt_ewma_ms,
        tcp_active_wire_rtt_ewma_ms: uplink.tcp_active_wire_rtt_ewma_ms,
        udp_active_wire_rtt_ewma_ms: uplink.udp_active_wire_rtt_ewma_ms,
        tcp_healthy: uplink.tcp_healthy,
        tcp_health_effective: uplink.tcp_health_effective,
        udp_health_effective: uplink.udp_health_effective,
        udp_healthy: uplink.udp_healthy,
        last_error: uplink.last_error.clone(),
        active_global: snapshot.global_active_uplink.as_deref() == Some(uplink.name.as_str()),
        active_global_reason: (snapshot.global_active_uplink.as_deref()
            == Some(uplink.name.as_str()))
        .then(|| snapshot.global_active_reason.clone())
        .flatten(),
        active_tcp: snapshot.tcp_active_uplink.as_deref() == Some(uplink.name.as_str()),
        active_tcp_reason: (snapshot.tcp_active_uplink.as_deref() == Some(uplink.name.as_str()))
            .then(|| snapshot.tcp_active_reason.clone())
            .flatten(),
        active_udp: snapshot.udp_active_uplink.as_deref() == Some(uplink.name.as_str()),
        active_udp_reason: (snapshot.udp_active_uplink.as_deref() == Some(uplink.name.as_str()))
            .then(|| snapshot.udp_active_reason.clone())
            .flatten(),
        configured_fallbacks: uplink.configured_fallbacks.clone(),
        configured_wire_chain: uplink
            .configured_wire_chain
            .iter()
            .map(|wire| {
                // Submode-effective mirrors the per-uplink computation:
                // configured submode unchanged unless a stream-one block
                // remains live in the per-host cache, in which case
                // stream-one collapses to packet-up. Reuses the existing
                // helper so the per-wire view is consistent with the
                // legacy top-level fields.
                let tcp_sub_dg = wire
                    .tcp_xhttp_submode_block_remaining_ms
                    .is_some_and(|ms| ms > 0);
                let udp_sub_dg = wire
                    .udp_xhttp_submode_block_remaining_ms
                    .is_some_and(|ms| ms > 0);
                let tcp_sub_eff = effective_submode(wire.tcp_xhttp_submode.as_deref(), tcp_sub_dg);
                let udp_sub_eff = effective_submode(wire.udp_xhttp_submode.as_deref(), udp_sub_dg);
                WireChainEntry {
                    transport: wire.transport.clone(),
                    tcp_mode: wire.tcp_mode.clone(),
                    tcp_mode_effective: wire.tcp_mode_effective.clone(),
                    tcp_downgrade_active: wire.tcp_downgrade_active,
                    tcp_xhttp_submode: wire.tcp_xhttp_submode.clone(),
                    tcp_xhttp_submode_effective: tcp_sub_eff,
                    tcp_xhttp_submode_downgrade_active: tcp_sub_dg,
                    udp_mode: wire.udp_mode.clone(),
                    udp_mode_effective: wire.udp_mode_effective.clone(),
                    udp_downgrade_active: wire.udp_downgrade_active,
                    udp_xhttp_submode: wire.udp_xhttp_submode.clone(),
                    udp_xhttp_submode_effective: udp_sub_eff,
                    udp_xhttp_submode_downgrade_active: udp_sub_dg,
                }
            })
            .collect(),
        tcp_active_wire: uplink.tcp_active_wire,
        udp_active_wire: uplink.udp_active_wire,
        tcp_active_wire_pin_remaining_ms: uplink.tcp_active_wire_pin_remaining_ms,
        udp_active_wire_pin_remaining_ms: uplink.udp_active_wire_pin_remaining_ms,
        fingerprint_profile_strategy: uplink.fingerprint_profile_strategy.clone(),
        fingerprint_profile_name: uplink.fingerprint_profile_name.clone(),
    }
}

pub(crate) fn build_summary(snapshots: &[UplinkManagerSnapshot]) -> ControlSummaryResponse {
    let mut summary = ControlSummaryResponse {
        groups_total: snapshots.len(),
        uplinks_total: 0,
        tcp_healthy: 0,
        tcp_unhealthy: 0,
        udp_healthy: 0,
        udp_unhealthy: 0,
        active_global: 0,
        active_tcp: 0,
        active_udp: 0,
    };

    for group in snapshots {
        summary.uplinks_total += group.uplinks.len();
        if group.global_active_uplink.is_some() {
            summary.active_global += 1;
        }
        if group.tcp_active_uplink.is_some() {
            summary.active_tcp += 1;
        }
        if group.udp_active_uplink.is_some() {
            summary.active_udp += 1;
        }
        for uplink in &group.uplinks {
            match uplink.tcp_healthy {
                Some(true) => summary.tcp_healthy += 1,
                Some(false) => summary.tcp_unhealthy += 1,
                None => {},
            }
            match uplink.udp_healthy {
                Some(true) => summary.udp_healthy += 1,
                Some(false) => summary.udp_unhealthy += 1,
                None => {},
            }
        }
    }
    summary
}
