//! Background maintenance tasks: NAT eviction, IPv6 refresh, DNS sweep.

use std::{future::Future, panic::AssertUnwindSafe, sync::Arc};

use futures_util::FutureExt;
use tokio::time::Duration;
use tracing::{debug, error};

use crate::{clock, config::Config, metrics::Metrics, outbound::OutboundIpv6};

use super::{
    constants::{
        DNS_CACHE_STALE_GRACE_SECS, DNS_CACHE_SWEEP_INTERVAL_SECS, NAT_EVICTION_INTERVAL_SECS,
    },
    services::Built,
    shutdown::{ShutdownSender, ShutdownSignal},
};

pub(super) fn spawn_maintenance(
    built: &Built,
    config: &Config,
    shutdown: ShutdownSignal,
    shutdown_sender: Arc<ShutdownSender>,
) {
    // Wall-clock cache: one Relaxed store per second instead of a syscall on every hot-path read.
    {
        let mut sd = shutdown.clone();
        spawn_supervised(
            "wall_clock_tick",
            Arc::clone(&built.services.metrics),
            Arc::clone(&shutdown_sender),
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        biased;
                        _ = sd.cancelled() => break,
                        _ = interval.tick() => clock::tick(),
                    }
                }
            },
        );
    }

    // NAT entry eviction + replay-filter sweep.
    {
        let nat_table = Arc::clone(&built.services.udp.nat_table);
        let replay = Arc::clone(&built.services.udp.replay_store);
        let metrics = Arc::clone(&built.services.metrics);
        let mut sd = shutdown.clone();
        spawn_supervised(
            "nat_eviction",
            Arc::clone(&built.services.metrics),
            Arc::clone(&shutdown_sender),
            async move {
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
            },
        );
    }

    // Outbound IPv6 interface re-enumeration (interface mode only).
    if let Some(OutboundIpv6::Interface(source)) = built.services.outbound_ipv6.as_deref() {
        let source = Arc::clone(source);
        let period = Duration::from_secs(config.outbound_ipv6_refresh_secs);
        let mut sd = shutdown.clone();
        spawn_supervised(
            "ipv6_refresh",
            Arc::clone(&built.services.metrics),
            Arc::clone(&shutdown_sender),
            async move {
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
            },
        );
    }

    // DNS cache stale-grace sweep.
    {
        let dns_cache = Arc::clone(&built.services.dns_cache);
        let mut sd = shutdown.clone();
        spawn_supervised(
            "dns_cache_sweep",
            Arc::clone(&built.services.metrics),
            shutdown_sender,
            async move {
                let mut interval =
                    tokio::time::interval(Duration::from_secs(DNS_CACHE_SWEEP_INTERVAL_SECS));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                interval.tick().await;
                loop {
                    tokio::select! {
                        biased;
                        _ = sd.cancelled() => break,
                        _ = interval.tick() => {
                            let purged = dns_cache
                                .sweep_expired(Duration::from_secs(DNS_CACHE_STALE_GRACE_SECS));
                            if purged > 0 {
                                debug!(purged, "swept expired dns cache entries");
                            }
                        }
                    }
                }
            },
        );
    }
}

/// Spawns a maintenance task whose panic is caught, logged, counted, and
/// converted into a graceful shutdown. Dropping the `JoinHandle` is intentional:
/// supervision happens inside the wrapper, not via `.await` on the handle.
fn spawn_supervised<F>(
    task: &'static str,
    metrics: Arc<Metrics>,
    shutdown_sender: Arc<ShutdownSender>,
    fut: F,
) where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(panic) = AssertUnwindSafe(fut).catch_unwind().await {
            let msg = panic_message(&panic);
            error!(task, panic = %msg, "maintenance task panicked; triggering shutdown");
            metrics.record_maintenance_task_panic(task);
            shutdown_sender.send();
        }
    });
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_owned()
    }
}
