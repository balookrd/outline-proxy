//! Carrier-loss sampling: registration at dial time, and the timer that turns
//! cumulative carrier counters into a per-wire verdict on the status.

use tokio::time::{Instant, sleep};
use tracing::{debug, info};

use outline_transport::CarrierLossProbe;

use crate::loss::{CarrierLossRegistry, LossCollection};
use crate::manager::status::UplinkStatus;
use crate::types::{TransportKind, UplinkManager};

/// Fold one sampling pass's `collection` into `status`: apply cumulative
/// loss windows and wire-emptied resets exactly as before, then advance the
/// loss-elevated episode for both transports. Pure and synchronous — no
/// registry, no lock beyond what the caller already holds — so it is
/// directly testable against a synthetic [`LossCollection`], without a live
/// carrier registry (which on non-Linux needs no probes at all, and on
/// Linux needs real sockets).
///
/// Stamps [`crate::manager::status::PerTransportStatus::loss_last_qualifying_at`]
/// with `(wire, now)` whenever a window in `collection` targets the
/// transport's *currently active* wire and actually met `min_packets` (i.e.
/// `record_wire_loss_window` returned `true`) — see that field's doc for why
/// the wire identity travels with the timestamp, and for why this is what
/// `update_loss_elevated_since` gates freshness on. Called
/// unconditionally, once per uplink per tick, even when `collection` is
/// completely empty: an uplink with no live carrier at all still needs its
/// (possibly stale) episode reassessed every tick, or a warm-standby whose
/// carrier goes quiet would keep an old episode frozen indefinitely instead
/// of it aging out past `max_staleness`.
fn apply_loss_collection(
    status: &mut UplinkStatus,
    collection: &LossCollection,
    min_packets: u64,
    alpha: f64,
    loss_failover_ratio: f64,
    max_staleness: std::time::Duration,
    now: Instant,
) {
    for window in &collection.windows {
        let per = match window.transport {
            TransportKind::Tcp => &mut status.tcp,
            TransportKind::Udp => &mut status.udp,
        };
        let is_active_wire = window.wire == per.active_wire;
        let qualified =
            per.record_wire_loss_window(window.wire, window.sent, window.lost, min_packets, alpha);
        if is_active_wire && qualified {
            per.loss_last_qualifying_at = Some((window.wire, now));
        }
    }
    for (transport, wire) in &collection.emptied_wires {
        let per = match transport {
            TransportKind::Tcp => &mut status.tcp,
            TransportKind::Udp => &mut status.udp,
        };
        per.reset_wire_loss(*wire);
    }
    status
        .tcp
        .update_loss_elevated_since(loss_failover_ratio, now, max_staleness);
    status
        .udp
        .update_loss_elevated_since(loss_failover_ratio, now, max_staleness);
}

impl UplinkManager {
    /// File a freshly dialed carrier's loss probe under the uplink and wire
    /// that dialed it. Called from the dial paths that already report the dial
    /// latency, so the two signals always describe the same carrier.
    ///
    /// Best-effort by construction: a `None` probe (non-Linux build, carrier
    /// family without a reachable socket) simply contributes no signal, and no
    /// dial ever fails because loss could not be measured.
    pub fn register_carrier_loss_probe(
        &self,
        index: usize,
        wire: u8,
        transport: TransportKind,
        probe: Option<CarrierLossProbe>,
    ) {
        let uplink = self.inner.uplinks.get(index).map(|u| u.name.as_str()).unwrap_or("?");
        let Some(probe) = probe else {
            // Worth a line rather than a silent return: a carrier family that
            // cannot surrender a probe (xhttp_h1, VLESS-UDP, a non-Linux
            // build) is indistinguishable at the metrics layer from one that
            // is measured and clean, and "no series" then has two very
            // different causes with no way to tell them apart.
            debug!(uplink, wire, ?transport, "carrier loss probe unavailable, not registered");
            return;
        };
        let Some(slot) = self.inner.carrier_loss.get(index) else {
            return;
        };
        let identity = probe.identity();
        let live = {
            let mut registry = slot.lock();
            registry.register(transport, wire, probe);
            registry.len()
        };
        debug!(uplink, wire, ?transport, identity, live, "carrier loss probe filed");
    }

    /// Hand this manager's live probe registries over, keyed by uplink name.
    /// Leaves the manager with empty ones — the caller is taking ownership,
    /// not copying.
    ///
    /// Exists because `/control/apply` rebuilds every manager while carriers
    /// keep running, and a probe is only ever filed when a carrier is dialed
    /// or handed out of the warm pool. Without carrying the registries across
    /// the rebuild, any carrier that outlives an apply is never observed
    /// again: short-lived ones are re-registered within minutes and hide the
    /// problem, but a long-lived one — a video stream's UDP session — may not
    /// be dialed again for hours. On the fleet's busiest node that showed up
    /// as the UDP plane going permanently silent after an apply while still
    /// carrying 17.9 MiB/min.
    pub(crate) fn take_carrier_loss_registries(&self) -> Vec<(String, CarrierLossRegistry)> {
        self.inner
            .uplinks
            .iter()
            .enumerate()
            .filter_map(|(index, uplink)| {
                let slot = self.inner.carrier_loss.get(index)?;
                let taken = std::mem::take(&mut *slot.lock());
                Some((uplink.name.clone(), taken))
            })
            .collect()
    }

    /// Adopt registries handed over by a displaced manager, matching by uplink
    /// *name* rather than by index: a hot-apply may add, remove or reorder
    /// uplinks, and an index-keyed hand-off would then attribute one uplink's
    /// carriers to another. An uplink whose name is absent from `from` simply
    /// starts empty, which is what happens for a newly added one.
    pub(crate) fn adopt_carrier_loss_registries(&self, from: Vec<(String, CarrierLossRegistry)>) {
        for (name, registry) in from {
            let Some(index) = self.inner.uplinks.iter().position(|u| u.name == name) else {
                continue;
            };
            let Some(slot) = self.inner.carrier_loss.get(index) else {
                continue;
            };
            *slot.lock() = registry;
        }
    }

    /// One sampling pass over every uplink: difference each live carrier's
    /// counters, fold the per-wire totals into the status, reset any wire
    /// that just lost its last registered carrier (see
    /// [`crate::loss::CarrierLossRegistry::collect_windows`]), and advance
    /// the loss-elevated episode used by the loss-driven strict-mode
    /// failover — see [`apply_loss_collection`].
    pub(crate) async fn sample_carrier_loss_once(&self) {
        let min_packets = self.inner.load_balancing.loss_sample_min_packets;
        let alpha = self.inner.load_balancing.loss_ewma_alpha;
        let loss_failover_ratio = self.inner.load_balancing.loss_failover_ratio;
        // See `LoadBalancingConfig::loss_max_staleness` for what this bounds
        // and why the active-episode and candidate-filter freshness checks
        // share one definition of it.
        let max_staleness = self.inner.load_balancing.loss_max_staleness();
        let now = Instant::now();
        for index in 0..self.inner.uplinks.len() {
            let Some(slot) = self.inner.carrier_loss.get(index) else {
                continue;
            };
            let collection = slot.lock().collect_windows();
            // Called on every tick, including a fully empty collection: an
            // uplink whose loss-elevated episode is stale (no live carrier
            // at all, or a warm-standby carrier that stopped producing
            // qualifying windows) still needs that staleness reassessed
            // every tick, or the episode would freeze instead of aging out.
            self.inner.with_status_mut(index, |status| {
                apply_loss_collection(
                    status,
                    &collection,
                    min_packets,
                    alpha,
                    loss_failover_ratio,
                    max_staleness,
                    now,
                );
            });
            if !collection.windows.is_empty() || !collection.emptied_wires.is_empty() {
                debug!(
                    uplink = %self.inner.uplinks[index].name,
                    windows = collection.windows.len(),
                    emptied_wires = collection.emptied_wires.len(),
                    "carrier loss sampled"
                );
            }
        }
    }

    /// Spawn the sampling timer for this group. One task per group, dying on
    /// the group's shutdown channel exactly like the shuffle timer, so a
    /// `/control/apply` hot-swap does not leave an orphan sampling a config
    /// that no longer exists.
    pub fn spawn_loss_sampler_loop(&self) {
        let interval = self.inner.load_balancing.loss_sample_interval;
        // `loss_sample_interval_secs = 0` is the documented off switch (see
        // `bins/outline-ws-rust/src/config/load/balancing.rs` and
        // `UPLINK-CONFIGURATIONS.md`): carriers still register probes and the
        // registry still tracks them, but nothing ever differences the
        // counters or publishes a verdict. Not spawning the loop at all
        // avoids a task that would otherwise busy-loop on a zero-length
        // sleep.
        //
        // A consequence of never running this loop: eviction of dead/idle
        // probes happens only inside `collect_windows`, which nothing calls
        // with the loop off, so each (uplink, transport, wire) can accumulate
        // up to `crate::loss::MAX_PROBES_PER_WIRE` duplicated descriptors
        // (TCP fds, QUIC `Weak` slots) before the registry's own
        // newest-wins bound in `CarrierLossRegistry::register` starts
        // pushing the oldest out to make room for the next dial. Bounded and
        // self-limiting — no unbounded growth — but worth knowing before
        // treating this switch as a completely free no-op.
        if interval.is_zero() {
            return;
        }
        let manager = self.clone();
        let mut shutdown = self.shutdown_rx();
        info!(
            group = %self.inner.group_name,
            interval_secs = interval.as_secs(),
            "carrier loss sampling loop spawned",
        );
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    _ = sleep(interval) => {}
                }
                manager.sample_carrier_loss_once().await;
            }
        });
    }
}

#[cfg(test)]
#[path = "tests/loss_sampler.rs"]
mod tests;
