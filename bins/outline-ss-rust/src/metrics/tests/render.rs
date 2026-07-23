use std::sync::atomic::Ordering;

use super::*;
use crate::metrics::tests::test_config;

#[test]
fn expired_client_gauges_are_zeroed_before_eviction() {
    let metrics = Metrics::new(&test_config());
    metrics.record_client_last_seen("ghost");

    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains("outline_ss_client_active{user=\"ghost\"} 1"),
        "a freshly seen client must render as active:\n{rendered}",
    );

    // Age the entry past `client_active_ttl_secs` so the next scrape treats it
    // as expired.
    let stale = unix_timestamp_seconds() - metrics.client_active_ttl_secs as i64 - 1;
    metrics
        .client_last_seen
        .get("ghost")
        .expect("entry recorded above")
        .store(stale, Ordering::Relaxed);

    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains("outline_ss_client_active{user=\"ghost\"} 0"),
        "an expired client must render as inactive, not stay pinned at 1:\n{rendered}",
    );
    assert!(
        rendered.contains("outline_ss_client_up{user=\"ghost\"} 0"),
        "the online-state alias must follow outline_ss_client_active:\n{rendered}",
    );
    assert!(
        !metrics.client_last_seen.contains_key("ghost"),
        "the expired entry must still be dropped from the bookkeeping map",
    );
}
