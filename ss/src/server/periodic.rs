//! Background maintenance tasks: NAT eviction, IPv6 refresh, DNS sweep.

use std::sync::Arc;

use tokio::time::Duration;
use tracing::debug;

use crate::{clock, config::Config, outbound::OutboundIpv6};

use super::{
    constants::{
        DNS_CACHE_STALE_GRACE_SECS, DNS_CACHE_SWEEP_INTERVAL_SECS, NAT_EVICTION_INTERVAL_SECS,
    },
    services::Built,
    shutdown::ShutdownSignal,
};

pub(super) fn spawn_maintenance(built: &Built, config: &Config, mut shutdown: ShutdownSignal) {
    // Wall-clock cache: one Relaxed store per second instead of a syscall on every hot-path read.
    {
        let mut sd = shutdown.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = sd.cancelled() => break,
                    _ = interval.tick() => clock::tick(),
                }
            }
        });
    }

    // NAT entry eviction + replay-filter sweep.
    {
        let nat_table = Arc::clone(&built.nat_table);
        let replay = Arc::clone(&built.replay_store);
        let metrics = Arc::clone(&built.metrics);
        let mut sd = shutdown.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(NAT_EVICTION_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                tokio::select! {
                    biased;
                    _ = sd.cancelled() => break,
                    _ = interval.tick() => {
                        nat_table.evict_idle(&metrics);
                        let purged = replay.evict_idle();
                        if purged > 0 {
                            debug!(purged, "swept idle udp replay-filter sessions");
                        }
                    }
                }
            }
        });
    }

    // Outbound IPv6 interface re-enumeration (interface mode only).
    if let Some(OutboundIpv6::Interface(source)) = built.outbound_ipv6.as_deref() {
        let source = Arc::clone(source);
        let period = Duration::from_secs(config.outbound_ipv6_refresh_secs);
        let mut sd = shutdown.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // skip the immediate tick; initial pool came from bind()
            loop {
                tokio::select! {
                    biased;
                    _ = sd.cancelled() => break,
                    _ = interval.tick() => source.refresh(),
                }
            }
        });
    }

    // DNS cache stale-grace sweep.
    {
        let dns_cache = Arc::clone(&built.dns_cache);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(DNS_CACHE_SWEEP_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        let purged = dns_cache
                            .sweep_expired(Duration::from_secs(DNS_CACHE_STALE_GRACE_SECS));
                        if purged > 0 {
                            debug!(purged, "swept expired dns cache entries");
                        }
                    }
                }
            }
        });
    }
}
