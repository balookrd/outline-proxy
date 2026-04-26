use std::{
    sync::{Arc, atomic::Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use metrics::{counter, gauge, with_local_recorder};

use super::Metrics;
use crate::metrics::process_memory::append_to_prometheus_output;

pub(super) fn render_prometheus(metrics: &Metrics) -> String {
    let now = unix_timestamp_seconds();
    let ttl = metrics.client_active_ttl_secs as i64;
    let seen_snapshot: Vec<(Arc<str>, i64)> = metrics
        .client_last_seen
        .iter()
        .map(|entry| (Arc::clone(entry.key()), entry.value().load(Ordering::Relaxed)))
        .collect();

    with_local_recorder(&metrics.recorder, || {
        counter!("outline_ss_metrics_scrapes_total").increment(1);
        gauge!("outline_ss_uptime_seconds").set(metrics.started_at.elapsed().as_secs_f64());
        for (user, seen_at) in &seen_snapshot {
            let active = *seen_at > 0 && now.saturating_sub(*seen_at) <= ttl;
            if active {
                gauge!("outline_ss_client_active", "user" => Arc::clone(user)).set(1.0);
                gauge!("outline_ss_client_up", "user" => Arc::clone(user)).set(1.0);
            } else {
                metrics.client_last_seen.remove(user);
            }
        }
    });

    let mut out = metrics.handle.render();

    if let Some(snapshot) = metrics.process_memory_snapshot.read().clone() {
        append_to_prometheus_output(&mut out, &snapshot);
    }

    out
}

pub(super) fn unix_timestamp_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
