use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate::config::{LoadBalancingConfig, LoadBalancingMode, RoutingScope, UplinkConfig};

use super::types::{PenaltyState, TransportKind, UplinkStatus};

pub(super) fn effective_health(status: &UplinkStatus, transport: TransportKind, now: Instant) -> bool {
    match transport {
        TransportKind::Tcp => {
            status.tcp_healthy == Some(true) && !cooldown_active(status, transport, now)
        }
        TransportKind::Udp => {
            status.udp_healthy == Some(true) && !cooldown_active(status, transport, now)
        }
    }
}

pub(super) fn supports_transport_for_scope(
    uplink: &Arc<UplinkConfig>,
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

pub(super) fn selection_health(
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

pub(super) fn strict_gate_transport(scope: RoutingScope, transport: TransportKind) -> TransportKind {
    match scope {
        RoutingScope::Global => TransportKind::Tcp,
        RoutingScope::PerUplink | RoutingScope::PerFlow => transport,
    }
}

pub(super) fn cooldown_active(status: &UplinkStatus, transport: TransportKind, now: Instant) -> bool {
    match transport {
        TransportKind::Tcp => status.cooldown_until_tcp.is_some_and(|until| until > now),
        TransportKind::Udp => status.cooldown_until_udp.is_some_and(|until| until > now),
    }
}

pub(super) fn effective_latency(
    status: &UplinkStatus,
    transport: TransportKind,
    now: Instant,
    config: &LoadBalancingConfig,
) -> Option<Duration> {
    let base = scoring_base_latency(status, transport);
    let mut penalty = current_penalty(
        match transport {
            TransportKind::Tcp => &status.tcp_penalty,
            TransportKind::Udp => &status.udp_penalty,
        },
        now,
        config,
    );
    // While an H3 TCP downgrade is active, add failure_penalty_max on top of
    // the existing penalty.  This keeps the uplink's score high enough that
    // active-active flows (per-flow scope) prefer the backup uplink and do not
    // switch back to the primary while it is operating in H2 fallback mode.
    //
    // Without this, the primary's score recovers as good H2 latency feeds into
    // the EWMA and the failure penalty decays, causing flows to shift back to
    // primary.  Once h3_tcp_downgrade_until expires, those flows then try H3,
    // encounter the same failure, and the whole cycle repeats.
    if matches!(transport, TransportKind::Tcp)
        && status.h3_tcp_downgrade_until.is_some_and(|t| t > now)
    {
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

pub(super) fn scoring_base_latency(status: &UplinkStatus, transport: TransportKind) -> Option<Duration> {
    match transport {
        TransportKind::Tcp => status.tcp_rtt_ewma.or(status.tcp_latency),
        TransportKind::Udp => status.udp_rtt_ewma.or(status.udp_latency),
    }
}

pub(super) fn weighted_latency_score(base: Option<Duration>, weight: f64) -> Option<Duration> {
    let base = base?;
    let weight = weight.max(0.000_001);
    Some(Duration::from_secs_f64(base.as_secs_f64() / weight))
}

pub(super) fn score_latency(
    status: &UplinkStatus,
    weight: f64,
    transport: TransportKind,
    now: Instant,
    config: &LoadBalancingConfig,
) -> Option<Duration> {
    weighted_latency_score(effective_latency(status, transport, now, config), weight)
}

pub(super) fn base_score_latency(
    status: &UplinkStatus,
    weight: f64,
    transport: TransportKind,
) -> Option<Duration> {
    weighted_latency_score(scoring_base_latency(status, transport), weight)
}

pub(super) fn selection_score(
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

pub(super) fn global_selection_score_latency(
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
        (Some(tcp), Some(udp)) => Some(Duration::from_secs_f64(
            tcp.as_secs_f64() + udp.as_secs_f64() * 0.05,
        )),
        (Some(tcp), None) => Some(tcp),
        (None, Some(udp)) => Some(udp),
        (None, None) => None,
    }
}

pub(super) fn update_rtt_ewma(current: &mut Option<Duration>, sample: Option<Duration>, alpha: f64) {
    let Some(sample) = sample else {
        return;
    };
    *current = Some(match *current {
        Some(existing) => Duration::from_secs_f64(
            existing.as_secs_f64() * (1.0 - alpha) + sample.as_secs_f64() * alpha,
        ),
        None => sample,
    });
}

pub(super) fn current_penalty(
    state: &PenaltyState,
    now: Instant,
    config: &LoadBalancingConfig,
) -> Option<Duration> {
    let updated_at = state.updated_at?;
    if state.value_secs <= 0.0 {
        return None;
    }
    let elapsed = now.saturating_duration_since(updated_at).as_secs_f64();
    let halflife = config.failure_penalty_halflife.as_secs_f64().max(1.0);
    let value_secs = state.value_secs * 0.5_f64.powf(elapsed / halflife);
    if value_secs < 0.001 {
        None
    } else {
        Some(Duration::from_secs_f64(
            value_secs.min(config.failure_penalty_max.as_secs_f64()),
        ))
    }
}

pub(super) fn add_penalty(state: &mut PenaltyState, now: Instant, config: &LoadBalancingConfig) {
    let current = current_penalty(state, now, config)
        .unwrap_or_default()
        .as_secs_f64();
    let next = (current + config.failure_penalty.as_secs_f64())
        .min(config.failure_penalty_max.as_secs_f64());
    state.value_secs = next;
    state.updated_at = Some(now);
}

pub(super) fn duration_to_millis_option(value: Option<Duration>) -> Option<u128> {
    value.map(|v| v.as_millis())
}

pub(super) fn routing_key(
    transport: TransportKind,
    target: Option<&crate::types::TargetAddr>,
    scope: RoutingScope,
) -> super::types::RoutingKey {
    use super::types::RoutingKey;
    match target {
        _ if matches!(scope, RoutingScope::Global) => RoutingKey::Global,
        _ if matches!(scope, RoutingScope::PerUplink) => RoutingKey::TransportGlobal(transport),
        Some(target) => RoutingKey::Target {
            transport,
            target: target.clone(),
        },
        None => RoutingKey::Default(transport),
    }
}

pub(super) fn strict_route_key(transport: TransportKind, scope: RoutingScope) -> super::types::RoutingKey {
    use super::types::RoutingKey;
    match scope {
        RoutingScope::Global => RoutingKey::Global,
        RoutingScope::PerUplink => RoutingKey::TransportGlobal(transport),
        RoutingScope::PerFlow => RoutingKey::Default(transport),
    }
}

pub(super) fn transport_key_prefix(transport: TransportKind) -> &'static str {
    match transport {
        TransportKind::Tcp => "Tcp",
        TransportKind::Udp => "Udp",
    }
}

pub(super) fn load_balancing_mode_name(mode: LoadBalancingMode) -> &'static str {
    match mode {
        LoadBalancingMode::ActiveActive => "active_active",
        LoadBalancingMode::ActivePassive => "active_passive",
    }
}

pub(super) fn routing_scope_name(scope: RoutingScope) -> &'static str {
    match scope {
        RoutingScope::PerFlow => "per_flow",
        RoutingScope::PerUplink => "per_uplink",
        RoutingScope::Global => "global",
    }
}

pub(super) fn rightless_bool(value: bool) -> u8 {
    if value { 1 } else { 0 }
}

pub(super) fn mark_probe_wakeup(
    last_wakeup: &mut Option<Instant>,
    now: Instant,
    min_interval: Duration,
) -> bool {
    if last_wakeup.is_some_and(|prev| now.duration_since(prev) < min_interval) {
        return false;
    }
    *last_wakeup = Some(now);
    true
}

pub(super) fn classify_runtime_failure_cause(error_text: &str) -> &'static str {
    crate::error_text::classify_runtime_failure_cause(error_text)
}

pub(super) fn classify_runtime_failure_signature(error_text: &str) -> &'static str {
    crate::error_text::classify_runtime_failure_signature(error_text)
}

pub(super) fn normalize_other_runtime_failure_detail(error_text: &str) -> String {
    let first_line = error_text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("other");
    let mut normalized = String::with_capacity(first_line.len().min(48));
    let mut prev_underscore = false;
    for ch in first_line.to_ascii_lowercase().chars() {
        let mapped = if ch.is_ascii_alphabetic() {
            ch
        } else if ch.is_ascii_digit() {
            '#'
        } else {
            '_'
        };
        if mapped == '_' {
            if prev_underscore {
                continue;
            }
            prev_underscore = true;
        } else {
            prev_underscore = false;
        }
        normalized.push(mapped);
        if normalized.len() >= 48 {
            break;
        }
    }
    let normalized = normalized
        .trim_matches('_')
        .chars()
        .take(48)
        .collect::<String>();
    if normalized.is_empty() {
        "other".to_string()
    } else {
        normalized
    }
}
