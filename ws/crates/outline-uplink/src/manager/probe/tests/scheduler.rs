use std::time::Duration;

use tokio::time::Instant;

use crate::manager::status::{PerTransportStatus, UplinkStatus};

use super::should_skip_probe_cycle_for_recent_activity;

const CHUNK0_WINDOW: Duration = Duration::from_secs(300);
const LIVENESS_INTERVAL: Duration = Duration::from_secs(300);

#[test]
fn recent_healthy_traffic_skips_probe_without_cooldown() {
    let now = Instant::now();
    let status = UplinkStatus {
        tcp: PerTransportStatus {
            healthy: Some(true),
            last_active: Some(now - Duration::from_secs(1)),
            ..Default::default()
        },
        // Pretend a full probe just ran so the liveness override does not
        // engage — this test focuses on the activity gate.
        last_full_probe_at: Some(now - Duration::from_secs(1)),
        ..UplinkStatus::default()
    };

    assert!(should_skip_probe_cycle_for_recent_activity(
        &status,
        now,
        Duration::from_secs(30),
        CHUNK0_WINDOW,
        LIVENESS_INTERVAL,
    ));
}

#[test]
fn active_cooldown_prevents_probe_skip_even_with_recent_traffic() {
    let now = Instant::now();
    let status = UplinkStatus {
        tcp: PerTransportStatus {
            healthy: Some(true),
            last_active: Some(now - Duration::from_secs(1)),
            cooldown_until: Some(now + Duration::from_secs(10)),
            ..Default::default()
        },
        last_full_probe_at: Some(now - Duration::from_secs(1)),
        ..UplinkStatus::default()
    };

    assert!(!should_skip_probe_cycle_for_recent_activity(
        &status,
        now,
        Duration::from_secs(30),
        CHUNK0_WINDOW,
        LIVENESS_INTERVAL,
    ));
}

#[test]
fn recent_chunk0_failure_keeps_probe_running_even_with_active_traffic() {
    // Even if real traffic is flowing through the uplink (rescued by
    // failover_step on a fallback wire), a chunk-0 failure observed
    // recently means the probe signal should run so health and
    // mode-downgrade state can catch up. The activity-based skip is
    // overridden in this case.
    let now = Instant::now();
    let status = UplinkStatus {
        tcp: PerTransportStatus {
            healthy: Some(true),
            last_active: Some(now - Duration::from_secs(1)),
            last_chunk0_failure_at: Some(now - Duration::from_secs(30)),
            ..Default::default()
        },
        last_full_probe_at: Some(now - Duration::from_secs(1)),
        ..UplinkStatus::default()
    };

    assert!(!should_skip_probe_cycle_for_recent_activity(
        &status,
        now,
        Duration::from_secs(30),
        CHUNK0_WINDOW,
        LIVENESS_INTERVAL,
    ));
}

#[test]
fn chunk0_streak_above_zero_keeps_probe_running() {
    // Same override but driven by an in-flight chunk-0 streak rather
    // than a timestamp inside the window. Useful when the operator
    // sets `chunk0_failure_window_secs = 0` (disables the timestamp
    // path) but still wants the streak counter to gate the skip.
    let now = Instant::now();
    let status = UplinkStatus {
        tcp: PerTransportStatus {
            healthy: Some(true),
            last_active: Some(now - Duration::from_secs(1)),
            chunk0_consecutive_failures: 1,
            ..Default::default()
        },
        last_full_probe_at: Some(now - Duration::from_secs(1)),
        ..UplinkStatus::default()
    };

    assert!(!should_skip_probe_cycle_for_recent_activity(
        &status,
        now,
        Duration::from_secs(30),
        CHUNK0_WINDOW,
        LIVENESS_INTERVAL,
    ));
}

#[test]
fn stale_chunk0_failure_does_not_block_probe_skip() {
    // Chunk-0 failure that is older than `chunk0_failure_window` should
    // NOT keep the probe running — the signal is no longer fresh.
    let now = Instant::now();
    let status = UplinkStatus {
        tcp: PerTransportStatus {
            healthy: Some(true),
            last_active: Some(now - Duration::from_secs(1)),
            // Older than CHUNK0_WINDOW (5 min)
            last_chunk0_failure_at: Some(now - Duration::from_secs(600)),
            ..Default::default()
        },
        last_full_probe_at: Some(now - Duration::from_secs(1)),
        ..UplinkStatus::default()
    };

    assert!(should_skip_probe_cycle_for_recent_activity(
        &status,
        now,
        Duration::from_secs(30),
        CHUNK0_WINDOW,
        LIVENESS_INTERVAL,
    ));
}

#[test]
fn liveness_override_forces_probe_when_full_cycle_stale() {
    // Healthy traffic flowing, no chunk-0 issues, no cooldown — would
    // normally skip. But the last full probe ran longer ago than
    // `liveness_interval`, so the override forces a cycle to pulse
    // probe metrics on the dashboard.
    let now = Instant::now();
    let status = UplinkStatus {
        tcp: PerTransportStatus {
            healthy: Some(true),
            last_active: Some(now - Duration::from_secs(1)),
            ..Default::default()
        },
        // Longer ago than LIVENESS_INTERVAL (5 min).
        last_full_probe_at: Some(now - Duration::from_secs(600)),
        ..UplinkStatus::default()
    };

    assert!(!should_skip_probe_cycle_for_recent_activity(
        &status,
        now,
        Duration::from_secs(30),
        CHUNK0_WINDOW,
        LIVENESS_INTERVAL,
    ));
}

#[test]
fn liveness_override_engages_on_first_cycle_after_start() {
    // First cycle ever: `last_full_probe_at` is None. Liveness override
    // must engage so the very first cycle is never skipped — without
    // this, a uplink that goes hot immediately at process start would
    // silence its first probe and operators would see a delay before
    // any probe metric appears.
    let now = Instant::now();
    let status = UplinkStatus {
        tcp: PerTransportStatus {
            healthy: Some(true),
            last_active: Some(now - Duration::from_secs(1)),
            ..Default::default()
        },
        last_full_probe_at: None,
        ..UplinkStatus::default()
    };

    assert!(!should_skip_probe_cycle_for_recent_activity(
        &status,
        now,
        Duration::from_secs(30),
        CHUNK0_WINDOW,
        LIVENESS_INTERVAL,
    ));
}

#[test]
fn liveness_zero_disables_override() {
    // Liveness interval of zero means "no liveness pulse" — legacy
    // behaviour where skip can hold indefinitely as long as traffic
    // flows and uplink is healthy.
    let now = Instant::now();
    let status = UplinkStatus {
        tcp: PerTransportStatus {
            healthy: Some(true),
            last_active: Some(now - Duration::from_secs(1)),
            ..Default::default()
        },
        // None — would normally engage the liveness override, but
        // disabling it via Duration::ZERO must keep the regular skip
        // path active.
        last_full_probe_at: None,
        ..UplinkStatus::default()
    };

    assert!(should_skip_probe_cycle_for_recent_activity(
        &status,
        now,
        Duration::from_secs(30),
        CHUNK0_WINDOW,
        Duration::ZERO,
    ));
}
