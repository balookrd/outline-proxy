use super::{METRICS, Metrics};
use anyhow::{Context, Result};
use prometheus::{Encoder, TextEncoder};
use std::sync::{LazyLock, Mutex};

use crate::snapshot_types::UplinkManagerSnapshot;

// Serialises the reset → repopulate → gather sequence so concurrent scrapes
// never observe a registry that is partially reset.  Encoding runs on owned
// MetricFamily data after the lock is released.
static RENDER_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

impl Metrics {
    fn update_snapshot_metrics(&self, snapshots: &[UplinkManagerSnapshot]) {
        self.uplink_health.reset();
        self.uplink_latency_seconds.reset();
        self.uplink_rtt_ewma_seconds.reset();
        self.uplink_penalty_seconds.reset();
        self.uplink_effective_latency_seconds.reset();
        self.uplink_score_seconds.reset();
        self.uplink_weight.reset();
        self.uplink_cooldown_seconds.reset();
        self.uplink_standby_ready.reset();
        self.sticky_routes_by_uplink.reset();
        self.sticky_routes_total.reset();
        self.selection_mode_info.reset();
        self.routing_scope_info.reset();
        self.global_active_uplink_info.reset();
        self.per_uplink_active_uplink_info.reset();

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

            self.uplink_standby_ready
                .with_label_values(&[group, "tcp", &uplink.name])
                .set(i64::try_from(uplink.standby_tcp_ready).unwrap_or(i64::MAX));
            self.uplink_standby_ready
                .with_label_values(&[group, "udp", &uplink.name])
                .set(i64::try_from(uplink.standby_udp_ready).unwrap_or(i64::MAX));
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
