//! Per-wire carrier-loss accounting.
//!
//! Split in two because of what each half may hold. [`LossEwma`] is numbers
//! only and lives inside `UplinkStatus`, which is cloned on every snapshot.
//! [`CarrierLossRegistry`] holds live descriptors (`OwnedFd` is not `Clone`)
//! and therefore lives beside the statuses, sampled by the loss loop.

use outline_transport::CarrierLossProbe;

use crate::types::TransportKind;

/// Maximum live probes retained per (transport, wire). A busy uplink dials
/// constantly and every dial registers; without a bound the registry would
/// grow with the dial rate. Newest win — they are the carriers actually
/// carrying traffic.
// Only `CarrierLossRegistry::register` reads this, and that method is
// itself unwired from production until Task 6's sampling loop calls it.
#[allow(dead_code)]
pub(crate) const MAX_PROBES_PER_WIRE: usize = 8;

/// Smoothed loss ratio for one wire, plus the volume it was derived from.
// Not yet held by `UplinkStatus` (Task 5) — until then this type is
// exercised only by its own tests.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LossEwma {
    ratio: Option<f64>,
    observed_packets: u64,
}

#[allow(dead_code)] // see the struct-level allow above
impl LossEwma {
    pub(crate) fn ratio(&self) -> Option<f64> {
        self.ratio
    }

    /// Cumulative packets this verdict is based on. Published so a dashboard
    /// can tell "no loss" apart from "no data".
    pub(crate) fn observed_packets(&self) -> u64 {
        self.observed_packets
    }

    /// Fold one sampling window into the EWMA. A window carrying fewer than
    /// `min_packets` sends is discarded outright: on a near-idle carrier the
    /// ratio is dominated by rounding, and feeding it would let an idle uplink
    /// look catastrophically lossy.
    pub(crate) fn record_window(&mut self, sent: u64, lost: u64, min_packets: u64, alpha: f64) {
        if sent < min_packets.max(1) {
            return;
        }
        let ratio = (lost as f64 / sent as f64).clamp(0.0, 1.0);
        self.observed_packets = self.observed_packets.saturating_add(sent);
        self.ratio = Some(match self.ratio {
            // First qualifying window seeds the estimate with itself: blending
            // against an implicit zero would understate a path that was
            // already lossy before sampling started.
            None => ratio,
            Some(current) => current + alpha * (ratio - current),
        });
    }

    /// Latency multiplier for scoring: `1 + k · loss`, clamped to `cap`.
    /// `k = 0` yields exactly `1.0`, which is what keeps the default build's
    /// selection identical to today's.
    pub(crate) fn inflation(&self, k: f64, cap: f64) -> f64 {
        if k <= 0.0 {
            return 1.0;
        }
        let loss = self.ratio.unwrap_or(0.0);
        (1.0 + k * loss).clamp(1.0, cap.max(1.0))
    }
}

/// One wire's traffic during a single sampling window.
// Not yet consumed by a sampling loop (Task 6) — until then only
// `CarrierLossRegistry::collect_windows` (also unwired) produces it.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LossWindow {
    pub(crate) transport: TransportKind,
    pub(crate) wire: u8,
    pub(crate) sent: u64,
    pub(crate) lost: u64,
}

// Only constructed by `CarrierLossRegistry::register`, itself unwired from
// production until Task 6.
#[allow(dead_code)]
struct ProbeEntry {
    transport: TransportKind,
    wire: u8,
    /// Identity of the carrier underneath, from `CarrierLossProbe::identity()`.
    /// A shared H2/H3 connection backs many sessions and each of them
    /// registers, so without this the same socket's traffic would be counted
    /// once per session: the ratio would survive (numerator and denominator
    /// scale together) but the observed volume would not, and
    /// `loss_sample_min_packets` would be cleared N times too easily.
    identity: u64,
    probe: CarrierLossProbe,
    /// Previous reading, so the next tick can difference against it. `None`
    /// until the first successful sample.
    last: Option<(u64, u64)>,
}

/// Live probes for one uplink, keyed by (transport, wire).
// Not yet held by `UplinkManagerInner` (Task 6) — until then this type is
// exercised only by its own tests.
#[allow(dead_code)]
#[derive(Default)]
pub(crate) struct CarrierLossRegistry {
    entries: Vec<ProbeEntry>,
}

#[allow(dead_code)] // see the struct-level allow above
impl CarrierLossRegistry {
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// File a probe under the wire that dialed it, evicting the oldest entry
    /// for that wire once the bound is reached.
    ///
    /// A live carrier already registered under this (transport, wire) is
    /// dropped on the floor: one shared H2/H3 connection is handed to many
    /// sessions, and counting its counters once per session would inflate the
    /// observed volume the minimum-volume threshold is measured against.
    ///
    /// A *dead* entry with the same identity is replaced instead. A TCP
    /// identity is the connection's 4-tuple, and the kernel hands the same
    /// ephemeral port out again once a socket is gone — so an identity match
    /// against a dead entry means a new carrier inherited a dead one's
    /// address, not a duplicate registration. Ignoring it would leave the live
    /// carrier unobserved until the sampling tick happened to evict the
    /// corpse.
    pub(crate) fn register(&mut self, transport: TransportKind, wire: u8, probe: CarrierLossProbe) {
        let identity = probe.identity();
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.transport == transport && e.wire == wire && e.identity == identity)
        {
            if self.entries[pos].probe.sample().is_some_and(|s| s.alive) {
                return;
            }
            self.entries.remove(pos);
        }
        let count = self
            .entries
            .iter()
            .filter(|e| e.transport == transport && e.wire == wire)
            .count();
        if count >= MAX_PROBES_PER_WIRE
            && let Some(pos) = self
                .entries
                .iter()
                .position(|e| e.transport == transport && e.wire == wire)
        {
            self.entries.remove(pos);
        }
        self.entries.push(ProbeEntry {
            transport,
            wire,
            identity,
            probe,
            last: None,
        });
    }

    /// Sample every live probe, difference against the previous reading, and
    /// return one aggregated window per (transport, wire). Dead or
    /// unreadable carriers are evicted here — that eviction is what closes
    /// their duplicated descriptors.
    pub(crate) fn collect_windows(&mut self) -> Vec<LossWindow> {
        let mut windows: Vec<LossWindow> = Vec::new();
        self.entries.retain_mut(|entry| {
            let Some(sample) = entry.probe.sample() else {
                return false;
            };
            if let Some((prev_sent, prev_lost)) = entry.last {
                // Counters are cumulative and monotonic within one connection;
                // `saturating_sub` is belt-and-braces against a kernel that
                // reports a narrower field after a wrap.
                let sent = sample.sent.saturating_sub(prev_sent);
                let lost = sample.lost.saturating_sub(prev_lost);
                if sent > 0 {
                    match windows
                        .iter_mut()
                        .find(|w| w.transport == entry.transport && w.wire == entry.wire)
                    {
                        Some(window) => {
                            window.sent += sent;
                            window.lost += lost;
                        },
                        None => windows.push(LossWindow {
                            transport: entry.transport,
                            wire: entry.wire,
                            sent,
                            lost,
                        }),
                    }
                }
            }
            entry.last = Some((sample.sent, sample.lost));
            sample.alive
        });
        windows
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    use outline_transport::CarrierLossProbe;

    /// A probe over an established loopback pair. The returned listener and
    /// streams must be kept alive by the caller — dropping them closes the
    /// carrier and the probe starts reporting `alive = false`.
    pub(crate) async fn live_pair()
    -> (CarrierLossProbe, tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let probe = CarrierLossProbe::from_tcp_stream(&client).expect("probe over loopback");
        (probe, client, server)
    }

    /// A probe whose carrier is already gone. The FIN exchange is
    /// asynchronous, so poll until the socket leaves ESTABLISHED rather than
    /// sleeping a guessed interval.
    // Only called by the Linux-gated registry tests below; on a non-Linux
    // dev host those tests compile out and this helper goes unused.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) async fn dead_probe() -> CarrierLossProbe {
        let (probe, client, server) = live_pair().await;
        drop(server);
        drop(client);
        for _ in 0..50 {
            if !probe.sample().map(|s| s.alive).unwrap_or(false) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        probe
    }

    /// A live probe plus enough traffic pushed through the pair that
    /// `tcpi_segs_out` has certainly advanced, for tests that assert on
    /// observed volume. Both sockets come back with it: the caller must keep
    /// them bound for as long as the probe is expected to read a live carrier.
    // No test in this task calls it yet — reserved for Task 6's sampler
    // tests (see the module comment on `tests_support` above).
    #[allow(dead_code)]
    pub(crate) async fn live_probe_with_traffic()
    -> (CarrierLossProbe, tokio::net::TcpStream, tokio::net::TcpStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (probe, mut client, mut server) = live_pair().await;
        for _ in 0..16 {
            client.write_all(&[0u8; 1024]).await.unwrap();
        }
        let mut sink = vec![0u8; 16 * 1024];
        server.read_exact(&mut sink).await.unwrap();
        (probe, client, server)
    }
}

#[cfg(test)]
#[path = "tests/loss.rs"]
mod tests;
