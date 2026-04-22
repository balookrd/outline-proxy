use std::time::Duration;

use tokio::time::Instant;

use crate::config::{LoadBalancingConfig, RoutingScope};

use super::types::{TransportKind, Uplink, UplinkStatus};
use super::utils::current_penalty;

pub(crate) fn effective_health(
    status: &UplinkStatus,
    transport: TransportKind,
    now: Instant,
) -> bool {
    status.of(transport).healthy == Some(true) && !cooldown_active(status, transport, now)
}

pub(crate) fn supports_transport_for_scope(
    uplink: &Uplink,
    transport: TransportKind,
    scope: RoutingScope,
) -> bool {
    match scope {
        RoutingScope::Global => match transport {
            TransportKind::Tcp => true,
            TransportKind::Udp => uplink.supports_udp(),
        },
        _ => match transport {
            TransportKind::Tcp => true,
            TransportKind::Udp => uplink.supports_udp(),
        },
    }
}

pub(crate) fn selection_health(
    status: &UplinkStatus,
    transport: TransportKind,
    now: Instant,
    scope: RoutingScope,
) -> bool {
    match scope {
        RoutingScope::Global => effective_health(status, TransportKind::Tcp, now),
        _ => effective_health(status, transport, now),
    }
}

pub(crate) fn strict_gate_transport(
    scope: RoutingScope,
    transport: TransportKind,
) -> TransportKind {
    match scope {
        RoutingScope::Global => TransportKind::Tcp,
        RoutingScope::PerUplink | RoutingScope::PerFlow => transport,
    }
}

pub(crate) fn cooldown_active(
    status: &UplinkStatus,
    transport: TransportKind,
    now: Instant,
) -> bool {
    status.of(transport).cooldown_until.is_some_and(|until| until > now)
}

pub(crate) fn cooldown_remaining(
    status: &UplinkStatus,
    transport: TransportKind,
    now: Instant,
) -> Duration {
    status
        .of(transport)
        .cooldown_until
        .map_or(Duration::ZERO, |t| t.saturating_duration_since(now))
}

pub(crate) fn effective_latency(
    status: &UplinkStatus,
    transport: TransportKind,
    now: Instant,
    config: &LoadBalancingConfig,
) -> Option<Duration> {
    let ts = status.of(transport);
    let base = scoring_base_latency(status, transport);
    let mut penalty = current_penalty(&ts.penalty, now, config);
    // While an H3 downgrade is active for this transport, add failure_penalty_max
    // on top of the existing penalty.  This keeps the uplink's score high enough
    // that active-active flows (per-flow scope) prefer the backup uplink and do not
    // switch back to the primary while it is operating in H2 fallback mode.
    //
    // Without this, the primary's score recovers as good H2 latency feeds into
    // the EWMA and the failure penalty decays, causing flows to shift back to
    // primary.  Once h3_downgrade_until expires, those flows then try H3,
    // encounter the same failure, and the whole cycle repeats.
    if ts.h3_downgrade_until.is_some_and(|t| t > now) {
        let extra = config.failure_penalty_max;
        penalty = Some(penalty.unwrap_or_default().saturating_add(extra));
    }
    match (base, penalty) {
        (Some(base), Some(penalty)) => Some(base.saturating_add(penalty)),
        (Some(base), None) => Some(base),
        (None, Some(penalty)) => Some(penalty),
        (None, None) => None,
    }
}

pub(crate) fn scoring_base_latency(
    status: &UplinkStatus,
    transport: TransportKind,
) -> Option<Duration> {
    let ts = status.of(transport);
    ts.rtt_ewma.or(ts.latency)
}

pub(crate) fn weighted_latency_score(base: Option<Duration>, weight: f64) -> Option<Duration> {
    let base = base?;
    let weight = weight.max(0.000_001);
    Some(Duration::from_secs_f64(base.as_secs_f64() / weight))
}

pub(crate) fn score_latency(
    status: &UplinkStatus,
    weight: f64,
    transport: TransportKind,
    now: Instant,
    config: &LoadBalancingConfig,
) -> Option<Duration> {
    weighted_latency_score(effective_latency(status, transport, now, config), weight)
}

pub(crate) fn base_score_latency(
    status: &UplinkStatus,
    weight: f64,
    transport: TransportKind,
) -> Option<Duration> {
    weighted_latency_score(scoring_base_latency(status, transport), weight)
}

pub(crate) fn selection_score(
    status: &UplinkStatus,
    weight: f64,
    transport: TransportKind,
    now: Instant,
    config: &LoadBalancingConfig,
    scope: RoutingScope,
) -> Option<Duration> {
    match scope {
        RoutingScope::Global => global_selection_score_latency(status, weight, now, config),
        RoutingScope::PerUplink => base_score_latency(status, weight, transport),
        RoutingScope::PerFlow => score_latency(status, weight, transport, now, config),
    }
}

pub(crate) fn global_selection_score_latency(
    status: &UplinkStatus,
    weight: f64,
    _now: Instant,
    _config: &LoadBalancingConfig,
) -> Option<Duration> {
    let tcp_score = base_score_latency(status, weight, TransportKind::Tcp);
    let udp_score = base_score_latency(status, weight, TransportKind::Udp);

    match (tcp_score, udp_score) {
        // Global routing should primarily follow TCP quality.
        // UDP only acts as a weak tie-breaker and should not dominate selection.
        // Penalties are intentionally excluded here; strict global switching should
        // be driven by cooldown/failover rather than decayed score history.
        (Some(tcp), Some(udp)) => {
            Some(Duration::from_secs_f64(tcp.as_secs_f64() + udp.as_secs_f64() * 0.05))
        },
        (Some(tcp), None) => Some(tcp),
        (None, Some(udp)) => Some(udp),
        (None, None) => None,
    }
}
