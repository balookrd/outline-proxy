//! Carrier-loss sampling: registration at dial time, and the timer that turns
//! cumulative carrier counters into a per-wire verdict on the status.

use tokio::time::sleep;
use tracing::{debug, info};

use outline_transport::CarrierLossProbe;

use crate::types::{TransportKind, UplinkManager};

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
        let Some(probe) = probe else { return };
        let Some(slot) = self.inner.carrier_loss.get(index) else {
            return;
        };
        slot.lock().register(transport, wire, probe);
    }

    /// One sampling pass over every uplink: difference each live carrier's
    /// counters, fold the per-wire totals into the status, and reset any
    /// wire that just lost its last registered carrier — see
    /// [`crate::loss::CarrierLossRegistry::collect_windows`].
    pub(crate) async fn sample_carrier_loss_once(&self) {
        let min_packets = self.inner.load_balancing.loss_sample_min_packets;
        let alpha = self.inner.load_balancing.loss_ewma_alpha;
        for index in 0..self.inner.uplinks.len() {
            let Some(slot) = self.inner.carrier_loss.get(index) else {
                continue;
            };
            let collection = slot.lock().collect_windows();
            if collection.windows.is_empty() && collection.emptied_wires.is_empty() {
                continue;
            }
            self.inner.with_status_mut(index, |status| {
                for window in &collection.windows {
                    let per = match window.transport {
                        TransportKind::Tcp => &mut status.tcp,
                        TransportKind::Udp => &mut status.udp,
                    };
                    per.record_wire_loss_window(
                        window.wire,
                        window.sent,
                        window.lost,
                        min_packets,
                        alpha,
                    );
                }
                for (transport, wire) in &collection.emptied_wires {
                    let per = match transport {
                        TransportKind::Tcp => &mut status.tcp,
                        TransportKind::Udp => &mut status.udp,
                    };
                    per.reset_wire_loss(*wire);
                }
            });
            debug!(
                uplink = %self.inner.uplinks[index].name,
                windows = collection.windows.len(),
                emptied_wires = collection.emptied_wires.len(),
                "carrier loss sampled"
            );
        }
    }

    /// Spawn the sampling timer for this group. One task per group, dying on
    /// the group's shutdown channel exactly like the shuffle timer, so a
    /// `/control/apply` hot-swap does not leave an orphan sampling a config
    /// that no longer exists.
    pub fn spawn_loss_sampler_loop(&self) {
        let interval = self.inner.load_balancing.loss_sample_interval;
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
