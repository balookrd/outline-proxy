use super::{METRICS, Metrics};
use anyhow::{Context, Result};
use prometheus::{Encoder, TextEncoder};
use std::sync::{LazyLock, Mutex};

use crate::snapshot_types::UplinkManagerSnapshot;

// Serialises the reset → repopulate → gather sequence so concurrent scrapes
// never observe a registry that is partially reset.  Encoding runs on owned
// MetricFamily data after the lock is released.
static RENDER_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

// Stable label set for `uplink_mode_downgrade_capped_to_info` — must
// stay in sync with `Display for outline_transport::TransportMode`.
// Adding a new TransportMode variant requires extending this list so
// that `mode` label values cover every cap the dispatcher can pick.
const MODE_DOWNGRADE_CAP_LABELS: &[&str] = &[
    "ws_h1",
    "ws_h2",
    "ws_h3",
    "quic",
    "xhttp_h1",
    "xhttp_h2",
    "xhttp_h3",
];

// Stable label set for `uplink_fingerprint_profile_strategy_info` —
// must stay in sync with `outline_transport::FingerprintProfileStrategy::as_str`
// (which is itself the wire-format contract for the snapshot's
// `fingerprint_profile_strategy` field). Adding a new strategy
// variant means extending this list so the gauge publishes a 0 row
// for the inactive ones; otherwise a stale 1 from a prior scrape
// could linger.
const FINGERPRINT_STRATEGY_LABELS: &[&str] =
    &["none", "per_host_stable", "process_stable", "random"];

impl Metrics {
    fn update_snapshot_metrics(&self, snapshots: &[UplinkManagerSnapshot]) {
        self.uplink_health.reset();
        self.uplink_health_effective.reset();
        self.uplink_latency_seconds.reset();
        self.uplink_rtt_ewma_seconds.reset();
        self.uplink_active_wire_rtt_ewma_seconds.reset();
        self.uplink_penalty_seconds.reset();
        self.uplink_effective_latency_seconds.reset();
        self.uplink_score_seconds.reset();
        self.uplink_weight.reset();
        self.uplink_cooldown_seconds.reset();
        self.uplink_standby_ready.reset();
        self.uplink_active_wire_index.reset();
        self.uplink_active_wire_pin_remaining_seconds.reset();
        self.uplink_mode_downgrade_remaining_seconds.reset();
        self.uplink_mode_downgrade_capped_to_info.reset();
        self.uplink_configured_fallbacks_count.reset();
        self.sticky_routes_by_uplink.reset();
        self.sticky_routes_total.reset();
        self.selection_mode_info.reset();
        self.routing_scope_info.reset();
        self.global_active_uplink_info.reset();
        self.per_uplink_active_uplink_info.reset();
        self.uplink_fingerprint_profile_strategy_info.reset();

        for snapshot in snapshots {
            self.update_group_metrics(snapshot);
        }
    }

    fn update_group_metrics(&self, snapshot: &UplinkManagerSnapshot) {
        let group = snapshot.group.as_str();
        self.sticky_routes_total
            .with_label_values(&[group])
            .set(i64::try_from(snapshot.sticky_routes.len()).unwrap_or(i64::MAX));
        for mode in ["active_active", "active_passive"] {
            self.selection_mode_info.with_label_values(&[group, mode]).set(0);
        }
        self.selection_mode_info
            .with_label_values(&[group, &snapshot.load_balancing_mode])
            .set(1);
        for scope in ["per_flow", "per_uplink", "global"] {
            self.routing_scope_info.with_label_values(&[group, scope]).set(0);
        }
        self.routing_scope_info
            .with_label_values(&[group, &snapshot.routing_scope])
            .set(1);

        for uplink in &snapshot.uplinks {
            self.global_active_uplink_info
                .with_label_values(&[group, &uplink.name])
                .set(0);
            for proto in ["tcp", "udp"] {
                self.per_uplink_active_uplink_info
                    .with_label_values(&[group, proto, &uplink.name])
                    .set(0);
            }
            self.uplink_weight
                .with_label_values(&[group, &uplink.name])
                .set(uplink.weight);
            if let Some(tcp_healthy) = uplink.tcp_healthy {
                self.uplink_health
                    .with_label_values(&[group, "tcp", &uplink.name])
                    .set(if tcp_healthy { 1.0 } else { 0.0 });
            }
            if let Some(udp_healthy) = uplink.udp_healthy {
                self.uplink_health
                    .with_label_values(&[group, "udp", &uplink.name])
                    .set(if udp_healthy { 1.0 } else { 0.0 });
            }
            if let Some(tcp_eff) = uplink.tcp_health_effective {
                self.uplink_health_effective
                    .with_label_values(&[group, "tcp", &uplink.name])
                    .set(if tcp_eff { 1.0 } else { 0.0 });
            }
            if let Some(udp_eff) = uplink.udp_health_effective {
                self.uplink_health_effective
                    .with_label_values(&[group, "udp", &uplink.name])
                    .set(if udp_eff { 1.0 } else { 0.0 });
            }

            if let Some(latency_ms) = uplink.tcp_latency_ms {
                self.uplink_latency_seconds
                    .with_label_values(&[group, "tcp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
            if let Some(latency_ms) = uplink.udp_latency_ms {
                self.uplink_latency_seconds
                    .with_label_values(&[group, "udp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
            if let Some(latency_ms) = uplink.tcp_rtt_ewma_ms {
                self.uplink_rtt_ewma_seconds
                    .with_label_values(&[group, "tcp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
            if let Some(latency_ms) = uplink.udp_rtt_ewma_ms {
                self.uplink_rtt_ewma_seconds
                    .with_label_values(&[group, "udp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
            // Active-wire RTT EWMA — primary's slot when active is on
            // wire 0, otherwise the per-fallback-wire slot. Operators
            // graphing / alerting against the wire actually carrying
            // traffic use this gauge instead of the legacy primary-only
            // `uplink_rtt_ewma_seconds`.
            if let Some(latency_ms) = uplink.tcp_active_wire_rtt_ewma_ms {
                self.uplink_active_wire_rtt_ewma_seconds
                    .with_label_values(&[group, "tcp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
            if let Some(latency_ms) = uplink.udp_active_wire_rtt_ewma_ms {
                self.uplink_active_wire_rtt_ewma_seconds
                    .with_label_values(&[group, "udp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
            if let Some(penalty_ms) = uplink.tcp_penalty_ms {
                self.uplink_penalty_seconds
                    .with_label_values(&[group, "tcp", &uplink.name])
                    .set(penalty_ms as f64 / 1000.0);
            }
            if let Some(penalty_ms) = uplink.udp_penalty_ms {
                self.uplink_penalty_seconds
                    .with_label_values(&[group, "udp", &uplink.name])
                    .set(penalty_ms as f64 / 1000.0);
            }
            if let Some(latency_ms) = uplink.tcp_effective_latency_ms {
                self.uplink_effective_latency_seconds
                    .with_label_values(&[group, "tcp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
            if let Some(latency_ms) = uplink.udp_effective_latency_ms {
                self.uplink_effective_latency_seconds
                    .with_label_values(&[group, "udp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
            if let Some(score_ms) = uplink.tcp_score_ms {
                self.uplink_score_seconds
                    .with_label_values(&[group, "tcp", &uplink.name])
                    .set(score_ms as f64 / 1000.0);
            }
            if let Some(score_ms) = uplink.udp_score_ms {
                self.uplink_score_seconds
                    .with_label_values(&[group, "udp", &uplink.name])
                    .set(score_ms as f64 / 1000.0);
            }
            if let Some(cooldown_ms) = uplink.cooldown_tcp_ms {
                self.uplink_cooldown_seconds
                    .with_label_values(&[group, "tcp", &uplink.name])
                    .set(cooldown_ms as f64 / 1000.0);
            }
            if let Some(cooldown_ms) = uplink.cooldown_udp_ms {
                self.uplink_cooldown_seconds
                    .with_label_values(&[group, "udp", &uplink.name])
                    .set(cooldown_ms as f64 / 1000.0);
            }

            // Mode-downgrade window state. Both gauges are emitted only
            // when a window is active so a healthy uplink does not pollute
            // the namespace with always-zero series. The cap label set
            // covers every TransportMode variant the dispatcher can pick
            // as a fallback ceiling; only the active cap is set to 1.
            if let Some(remaining_ms) = uplink.h3_tcp_downgrade_until_ms {
                self.uplink_mode_downgrade_remaining_seconds
                    .with_label_values(&[group, "tcp", &uplink.name])
                    .set(remaining_ms as f64 / 1000.0);
            }
            if let Some(remaining_ms) = uplink.h3_udp_downgrade_until_ms {
                self.uplink_mode_downgrade_remaining_seconds
                    .with_label_values(&[group, "udp", &uplink.name])
                    .set(remaining_ms as f64 / 1000.0);
            }
            if let Some(cap) = uplink.tcp_mode_capped_to.as_deref() {
                for mode in MODE_DOWNGRADE_CAP_LABELS {
                    self.uplink_mode_downgrade_capped_to_info
                        .with_label_values(&[group, "tcp", &uplink.name, mode])
                        .set(if *mode == cap { 1 } else { 0 });
                }
            }
            if let Some(cap) = uplink.udp_mode_capped_to.as_deref() {
                for mode in MODE_DOWNGRADE_CAP_LABELS {
                    self.uplink_mode_downgrade_capped_to_info
                        .with_label_values(&[group, "udp", &uplink.name, mode])
                        .set(if *mode == cap { 1 } else { 0 });
                }
            }

            self.uplink_standby_ready
                .with_label_values(&[group, "tcp", &uplink.name])
                .set(i64::try_from(uplink.standby_tcp_ready).unwrap_or(i64::MAX));
            self.uplink_standby_ready
                .with_label_values(&[group, "udp", &uplink.name])
                .set(i64::try_from(uplink.standby_udp_ready).unwrap_or(i64::MAX));

            // Fingerprint-profile strategy: low-cardinality info gauge.
            // Published unconditionally so an operator can confirm the
            // knob landed even when the strategy is `none` (the default
            // — silence here would be ambiguous between "feature off"
            // and "snapshot pipeline broken").
            for label in FINGERPRINT_STRATEGY_LABELS {
                self.uplink_fingerprint_profile_strategy_info
                    .with_label_values(&[group, &uplink.name, label])
                    .set(if *label == uplink.fingerprint_profile_strategy {
                        1
                    } else {
                        0
                    });
            }

            // Active-wire visibility: published unconditionally for uplinks
            // with at least one fallback so dashboards can pin a panel on
            // every uplink that *can* enter sticky-fallback. Single-wire
            // uplinks are skipped — for them the value would always be 0
            // and the metric would just clutter the namespace.
            if !uplink.configured_fallbacks.is_empty() {
                self.uplink_active_wire_index
                    .with_label_values(&[group, "tcp", &uplink.name])
                    .set(uplink.tcp_active_wire as i64);
                self.uplink_active_wire_index
                    .with_label_values(&[group, "udp", &uplink.name])
                    .set(uplink.udp_active_wire as i64);
                self.uplink_configured_fallbacks_count
                    .with_label_values(&[group, &uplink.name])
                    .set(i64::try_from(uplink.configured_fallbacks.len()).unwrap_or(i64::MAX));
                if let Some(remaining_ms) = uplink.tcp_active_wire_pin_remaining_ms {
                    self.uplink_active_wire_pin_remaining_seconds
                        .with_label_values(&[group, "tcp", &uplink.name])
                        .set(remaining_ms as f64 / 1000.0);
                }
                if let Some(remaining_ms) = uplink.udp_active_wire_pin_remaining_ms {
                    self.uplink_active_wire_pin_remaining_seconds
                        .with_label_values(&[group, "udp", &uplink.name])
                        .set(remaining_ms as f64 / 1000.0);
                }
            }
        }
        if let Some(global_active_uplink) = &snapshot.global_active_uplink {
            self.global_active_uplink_info
                .with_label_values(&[group, global_active_uplink])
                .set(1);
        }
        if let Some(tcp_active) = &snapshot.tcp_active_uplink {
            self.per_uplink_active_uplink_info
                .with_label_values(&[group, "tcp", tcp_active])
                .set(1);
        }
        if let Some(udp_active) = &snapshot.udp_active_uplink {
            self.per_uplink_active_uplink_info
                .with_label_values(&[group, "udp", udp_active])
                .set(1);
        }

        for sticky in &snapshot.sticky_routes {
            self.sticky_routes_by_uplink
                .with_label_values(&[group, &sticky.uplink_name])
                .inc();
        }
    }
}

pub fn render_prometheus(snapshots: &[UplinkManagerSnapshot]) -> Result<String> {
    let metric_families = {
        let _guard = RENDER_LOCK.lock().expect("render lock poisoned");
        METRICS.update_snapshot_metrics(snapshots);
        METRICS.registry.gather()
    };
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .context("failed to encode prometheus metrics")?;
    String::from_utf8(buffer).context("failed to encode metrics output as UTF-8")
}
