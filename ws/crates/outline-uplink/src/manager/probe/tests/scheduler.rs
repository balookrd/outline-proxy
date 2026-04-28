use std::time::Duration;

use tokio::time::Instant;

use crate::types::UplinkStatus;

use super::should_skip_probe_cycle_for_recent_activity;

#[test]
fn recent_healthy_traffic_skips_probe_without_cooldown() {
    let now = Instant::now();
    let status = UplinkStatus {
        tcp: crate::types::PerTransportStatus {
            healthy: Some(true),
            last_active: Some(now - Duration::from_secs(1)),
            ..Default::default()
        },
        ..UplinkStatus::default()
    };

    assert!(should_skip_probe_cycle_for_recent_activity(
        &status,
        now,
        Duration::from_secs(30),
    ));
}

#[test]
fn active_cooldown_prevents_probe_skip_even_with_recent_traffic() {
    let now = Instant::now();
    let status = UplinkStatus {
        tcp: crate::types::PerTransportStatus {
            healthy: Some(true),
            last_active: Some(now - Duration::from_secs(1)),
            cooldown_until: Some(now + Duration::from_secs(10)),
            ..Default::default()
        },
        ..UplinkStatus::default()
    };

    assert!(!should_skip_probe_cycle_for_recent_activity(
        &status,
        now,
        Duration::from_secs(30),
    ));
}
