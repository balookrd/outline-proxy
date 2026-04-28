use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::time::Instant;

use crate::config::{LoadBalancingConfig, LoadBalancingMode, RoutingScope};
use socks5_proto::TargetAddr;

use super::types::{PenaltyState, RoutingKey, TransportKind};

pub(crate) use outline_transport::collections::{maybe_shrink_hash_map, maybe_shrink_vecdeque};

/// Maximum number of distinct normalized `detail` label values that the
/// `uplink_runtime_failure_other_details_total` metric may track globally.
///
/// `normalize_other_runtime_failure_detail` routes errors that did not match
/// any known signature through this limit.  Once `MAX_DETAIL_CARDINALITY`
/// unique values have been observed, further unseen values are replaced by the
/// sentinel `"other_overflow"` so that a burst of novel error texts cannot
/// cause unbounded growth in the Prometheus label cardinality.
///
/// 64 is intentionally conservative: any deployment with more than 64
/// distinct *un-classifiable* error patterns has a far bigger problem than
/// metric cardinality.
const MAX_DETAIL_CARDINALITY: usize = 64;

static DETAIL_SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

pub(crate) fn update_rtt_ewma(
    current: &mut Option<Duration>,
    sample: Option<Duration>,
    alpha: f64,
) {
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

pub(crate) fn current_penalty(
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

pub(crate) fn add_penalty(state: &mut PenaltyState, now: Instant, config: &LoadBalancingConfig) {
    let current = current_penalty(state, now, config).unwrap_or_default().as_secs_f64();
    let next = (current + config.failure_penalty.as_secs_f64())
        .min(config.failure_penalty_max.as_secs_f64());
    state.value_secs = next;
    state.updated_at = Some(now);
}

pub(crate) fn duration_to_millis_option(value: Option<Duration>) -> Option<u128> {
    value.map(|v| v.as_millis())
}

pub(crate) fn routing_key(
    transport: TransportKind,
    target: Option<&TargetAddr>,
    scope: RoutingScope,
) -> RoutingKey {
    match target {
        _ if matches!(scope, RoutingScope::Global) => RoutingKey::Global,
        _ if matches!(scope, RoutingScope::PerUplink) => RoutingKey::TransportGlobal(transport),
        Some(target) => RoutingKey::Target { transport, target: target.clone() },
        None => RoutingKey::Default(transport),
    }
}

pub(crate) fn strict_route_key(transport: TransportKind, scope: RoutingScope) -> RoutingKey {
    match scope {
        RoutingScope::Global => RoutingKey::Global,
        RoutingScope::PerUplink => RoutingKey::TransportGlobal(transport),
        RoutingScope::PerFlow => RoutingKey::Default(transport),
    }
}

pub(crate) fn transport_key_prefix(transport: TransportKind) -> &'static str {
    match transport {
        TransportKind::Tcp => "Tcp",
        TransportKind::Udp => "Udp",
    }
}

pub(crate) fn load_balancing_mode_name(mode: LoadBalancingMode) -> &'static str {
    match mode {
        LoadBalancingMode::ActiveActive => "active_active",
        LoadBalancingMode::ActivePassive => "active_passive",
    }
}

pub(crate) fn routing_scope_name(scope: RoutingScope) -> &'static str {
    match scope {
        RoutingScope::PerFlow => "per_flow",
        RoutingScope::PerUplink => "per_uplink",
        RoutingScope::Global => "global",
    }
}

pub(crate) fn rightless_bool(value: bool) -> u8 {
    if value { 1 } else { 0 }
}

pub(crate) fn mark_probe_wakeup(
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

pub(crate) fn classify_runtime_failure_cause(error: &anyhow::Error) -> &'static str {
    crate::error_text::classify_runtime_failure_cause(error)
}

pub(crate) fn classify_runtime_failure_signature(error: &anyhow::Error) -> &'static str {
    crate::error_text::classify_runtime_failure_signature(error)
}

pub(crate) fn normalize_other_runtime_failure_detail(error_text: &str) -> String {
    let normalized = normalize_detail_string(error_text);
    intern_detail(normalized)
}

/// Normalize an error string to a compact, metric-safe token.
/// Returns `[a-z_#]+`, max 48 characters, digits replaced by `#`.
fn normalize_detail_string(error_text: &str) -> String {
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
    let normalized = normalized.trim_matches('_').chars().take(48).collect::<String>();
    if normalized.is_empty() {
        "other".to_string()
    } else {
        normalized
    }
}

/// Guard against unbounded Prometheus label cardinality.
///
/// Returns `detail` unchanged if it has been seen before or if the global
/// pool has not yet reached `MAX_DETAIL_CARDINALITY`.  Once the cap is hit,
/// any *new* unseen value is replaced by `"other_overflow"` so the number
/// of distinct `detail` label values emitted to Prometheus is bounded.
fn intern_detail(detail: String) -> String {
    let pool = DETAIL_SEEN.get_or_init(|| Mutex::new(HashSet::new()));
    // Unwrap: poisoning can only happen on panic inside the lock, which we
    // never do.  Recovering from a poisoned mutex is not worth the complexity.
    let mut seen = pool.lock().unwrap_or_else(|e| e.into_inner());
    if seen.contains(&detail) {
        return detail;
    }
    if seen.len() >= MAX_DETAIL_CARDINALITY {
        return "other_overflow".to_string();
    }
    seen.insert(detail.clone());
    detail
}

#[cfg(test)]
#[path = "tests/utils.rs"]
mod tests;
