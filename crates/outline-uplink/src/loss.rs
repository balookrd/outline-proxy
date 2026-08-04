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
pub(crate) const MAX_PROBES_PER_WIRE: usize = 8;

/// Consecutive sampling ticks with `Δsent == 0` before a probe is evicted as
/// stale, even though its carrier still reports itself alive.
///
/// Without this, a retained QUIC probe pins its connection alive forever:
/// `CarrierLossProbe::sample` reports `alive` from `close_reason().is_none()`,
/// and in quinn 0.11.9 the implicit close on drop only fires once every
/// handle's ref count reaches zero — the registry's own clone keeps it above
/// zero. A carrier this registry no longer sees new traffic from (the wire
/// was retired locally, or is a standby that stopped being dialed) never
/// naturally reaches zero handles on its own, so `alive` would stay `true`
/// and the entry would sit in the registry until pushed out by
/// [`MAX_PROBES_PER_WIRE`] — which never happens on an uplink that has
/// stopped dialing.
///
/// Three ticks: short enough that the zombie is evicted (releasing the
/// `quinn::Connection` clone / duplicated TCP fd, letting the carrier close
/// normally) well inside the client's own 28–35 s QUIC `max_idle_timeout`,
/// long enough that an ordinary lull between requests on a carrier still in
/// active use is never mistaken for abandonment.
pub(crate) const MAX_IDLE_TICKS: u32 = 3;

/// Smoothed loss ratio for one wire, plus the volume it was derived from.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LossEwma {
    ratio: Option<f64>,
    observed_packets: u64,
}

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
    /// look catastrophically lossy. Returns whether the window qualified and
    /// moved the ratio — callers that need to know whether *this* window was
    /// fresh evidence (as opposed to a silently-discarded one leaving a
    /// frozen ratio in place) use the return value.
    pub(crate) fn record_window(
        &mut self,
        sent: u64,
        lost: u64,
        min_packets: u64,
        alpha: f64,
    ) -> bool {
        if sent < min_packets.max(1) {
            return false;
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
        true
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

    /// Clear the verdict back to "not measured". Called when a wire loses
    /// its last registered carrier: without this, a loss ratio measured
    /// while the wire carried traffic would survive indefinitely — read by
    /// selection as a permanent penalty on precisely the standby an
    /// operator would want to fail over *to*. An absent verdict must mean
    /// "not measured", never "measured and clean" or a stale reading from
    /// traffic that no longer exists.
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }
}

/// One wire's traffic during a single sampling window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LossWindow {
    pub(crate) transport: TransportKind,
    pub(crate) wire: u8,
    pub(crate) sent: u64,
    pub(crate) lost: u64,
}

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
    /// Consecutive ticks (after the baseline reading) whose `Δsent` was `0`.
    /// Reset to `0` the moment a tick sees real traffic; reaching
    /// [`MAX_IDLE_TICKS`] evicts the entry — see that constant for why.
    idle_ticks: u32,
}

/// Result of one sampling pass over a registry.
pub(crate) struct LossCollection {
    /// Aggregated per-(transport, wire) windows from carriers that produced
    /// traffic this tick.
    pub(crate) windows: Vec<LossWindow>,
    /// Every (transport, wire) that held at least one registry entry before
    /// this tick and holds none after it (evicted for death or for
    /// staleness). The caller resets that wire's `LossEwma` — see
    /// [`LossEwma::reset`] — so its verdict reads as "not measured" instead
    /// of the last ratio a carrier that no longer exists left behind.
    pub(crate) emptied_wires: Vec<(TransportKind, u8)>,
}

/// Live probes for one uplink, keyed by (transport, wire).
#[derive(Default)]
pub(crate) struct CarrierLossRegistry {
    entries: Vec<ProbeEntry>,
}

impl CarrierLossRegistry {
    /// Only called by the Linux-gated registry tests (the registry needs
    /// `TCP_INFO`, Linux-only). `#[cfg(test)]` rather than a bare
    /// `pub(crate) fn` because it has no production caller at all — without
    /// it, the plain (non-test) `lib` target has zero callers on *every*
    /// platform, Linux included, and a platform-scoped `allow` alone cannot
    /// fix that (a `cfg_attr` only conditions the lint, not whether the item
    /// exists). With `#[cfg(test)]` the method compiles only into the test
    /// build, where the Linux-gated callers below satisfy it on Linux; on a
    /// non-Linux dev host those tests compile out and this accessor goes
    /// unused in that build the same way `dead_probe` in `tests_support`
    /// does, so it keeps the same platform-scoped `allow`.
    #[cfg(test)]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
            idle_ticks: 0,
        });
    }

    /// Sample every live probe, difference against the previous reading, and
    /// return one aggregated window per (transport, wire). Dead, unreadable
    /// or [stale](MAX_IDLE_TICKS) carriers are evicted here — that eviction
    /// is what closes their duplicated descriptors (TCP) or releases the
    /// `quinn::Connection` clone so quinn can close the carrier normally
    /// (QUIC). A (transport, wire) that had at least one entry before this
    /// call and has none after is reported in
    /// [`LossCollection::emptied_wires`].
    pub(crate) fn collect_windows(&mut self) -> LossCollection {
        let wires_before: std::collections::HashSet<(TransportKind, u8)> =
            self.entries.iter().map(|e| (e.transport, e.wire)).collect();

        let mut windows: Vec<LossWindow> = Vec::new();
        self.entries.retain_mut(|entry| {
            let Some(sample) = entry.probe.sample() else {
                return false;
            };
            if let Some((prev_sent, prev_lost)) = entry.last {
                // Counters are cumulative and monotonic within one connection;
                // `saturating_sub` is belt-and-braces against `tcpi_segs_out`
                // wrapping (it is a kernel `u32`, so it wraps at ~4 billion
                // segments). A wrap costs one dropped window — the delta
                // reads as 0 and the tick is skipped — which is the correct
                // behaviour: a negative or huge delta would corrupt the ratio
                // far worse than losing one window's resolution does.
                let sent = sample.sent.saturating_sub(prev_sent);
                let lost = sample.lost.saturating_sub(prev_lost);
                if sent > 0 {
                    entry.idle_ticks = 0;
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
                } else {
                    // A window below `loss_sample_min_packets` is a different
                    // thing from `Δsent == 0`: the former still means the
                    // carrier is in use, just too lightly to trust a ratio
                    // from; only the latter means nothing is using this
                    // carrier at all, which is what staleness eviction tracks.
                    entry.idle_ticks += 1;
                }
            }
            entry.last = Some((sample.sent, sample.lost));
            sample.alive && entry.idle_ticks < MAX_IDLE_TICKS
        });

        let emptied_wires = wires_before
            .into_iter()
            .filter(|wire| !self.entries.iter().any(|e| (e.transport, e.wire) == *wire))
            .collect();
        LossCollection { windows, emptied_wires }
    }
}

// `target_os = "linux"` rather than the `#[cfg_attr(..., allow(dead_code))]`
// pattern used elsewhere in this file: every helper here calls
// `CarrierLossProbe::from_tcp_stream`, which is `Some` only on Linux (see
// `carrier_loss.rs`) — on any other platform `live_pair`'s `.expect(...)`
// would be reachable only via a `None` that can never actually occur
// (`CarrierLossProbe` has no variants to construct there at all), which
// `rustc` resolves by treating the read of `server: TcpStream` and
// `probe: CarrierLossProbe` right before it as dead — an `unused_variables`
// warning under `-D warnings` on a plain, non-workspace `cargo check
// -p outline-uplink` on a non-Linux host, where feature unification does not
// pull in `outline-transport`'s QUIC variant either. Gating the whole module
// out on non-Linux removes the code these warnings would otherwise fire on,
// rather than silencing them after the fact.
#[cfg(all(test, target_os = "linux"))]
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
