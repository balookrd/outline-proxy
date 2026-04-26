use serde::Serialize;

use outline_metrics::{UplinkManagerSnapshot, UplinkSnapshot};

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
    tcp_ws_mode: Option<String>,
    udp_ws_mode: Option<String>,
    /// Effective TCP mode after applying the H3/QUIC → H2 auto-downgrade
    /// window. Equals `tcp_ws_mode` when no downgrade is active.
    tcp_ws_mode_effective: Option<String>,
    /// Effective UDP mode after applying the H3/QUIC → H2 auto-downgrade
    /// window. Equals `udp_ws_mode` when no downgrade is active.
    udp_ws_mode_effective: Option<String>,
    tcp_downgrade_active: bool,
    udp_downgrade_active: bool,
    weight: f64,
    tcp_healthy: Option<bool>,
    udp_healthy: Option<bool>,
    last_error: Option<String>,
    active_global: bool,
    active_global_reason: Option<String>,
    active_tcp: bool,
    active_tcp_reason: Option<String>,
    active_udp: bool,
    active_udp_reason: Option<String>,
}

fn effective_mode(
    transport: &str,
    configured: Option<&str>,
    downgrade_active: bool,
) -> Option<String> {
    let mode = configured?;
    let supports_downgrade = matches!(transport, "ws" | "vless");
    let advanced = matches!(mode, "h3" | "quic");
    if downgrade_active && supports_downgrade && advanced {
        Some("h2".to_string())
    } else {
        Some(mode.to_string())
    }
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
    let tcp_ws_mode_effective =
        effective_mode(&uplink.transport, uplink.tcp_ws_mode.as_deref(), tcp_downgrade_active);
    let udp_ws_mode_effective =
        effective_mode(&uplink.transport, uplink.udp_ws_mode.as_deref(), udp_downgrade_active);
    ControlUplinkTopology {
        index: uplink.index,
        name: uplink.name.clone(),
        transport: uplink.transport.clone(),
        tcp_ws_mode: uplink.tcp_ws_mode.clone(),
        udp_ws_mode: uplink.udp_ws_mode.clone(),
        tcp_ws_mode_effective,
        udp_ws_mode_effective,
        tcp_downgrade_active,
        udp_downgrade_active,
        weight: uplink.weight,
        tcp_healthy: uplink.tcp_healthy,
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
