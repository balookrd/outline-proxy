use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use crate::config::{LoadBalancingConfig, ProbeConfig, UplinkConfig};

use super::super::types::UplinkManager;

impl UplinkManager {
    /// Test-only constructor that supplies a fresh throwaway
    /// [`DnsCache`](outline_transport::DnsCache) so existing tests do not need
    /// to build one at every call site.
    pub fn new_for_test(
        group_name: impl Into<String>,
        uplinks: Vec<UplinkConfig>,
        probe: ProbeConfig,
        load_balancing: LoadBalancingConfig,
    ) -> Result<Self> {
        Self::new(
            group_name,
            uplinks,
            probe,
            load_balancing,
            Arc::new(outline_transport::DnsCache::default()),
        )
    }

    /// Test helper: run one warm-standby maintenance pass (validate + refill)
    /// for `(index, transport)` synchronously, so a test can fill the pool
    /// without waiting for the background sweep. Exposed to out-of-crate tests
    /// (`test-helpers`) because the ingress crates own the code that *takes*
    /// from the pool, and pinning "this acquisition came from the pool" needs
    /// a filled pool on this side of the boundary.
    #[doc(hidden)]
    pub async fn test_maintain_pool(&self, index: usize, transport: crate::types::TransportKind) {
        self.maintain_pool(index, transport).await;
    }

    /// Test helper: directly set TCP health / latency for uplink `index`.
    #[doc(hidden)]
    pub async fn test_set_tcp_health(&self, index: usize, healthy: bool, rtt_ms: u64) {
        self.inner.with_status_mut(index, |status| {
            status.tcp.healthy = Some(healthy);
            status.tcp.latency = Some(Duration::from_millis(rtt_ms));
            status.tcp.rtt_ewma = crate::rtt::RttEwma::measured(
                Duration::from_millis(rtt_ms),
                tokio::time::Instant::now(),
            );
        });
    }

    /// Test helper: directly set UDP health / latency for uplink `index`.
    #[doc(hidden)]
    pub async fn test_set_udp_health(&self, index: usize, healthy: bool, rtt_ms: u64) {
        self.inner.with_status_mut(index, |status| {
            status.udp.healthy = Some(healthy);
            status.udp.latency = Some(Duration::from_millis(rtt_ms));
            status.udp.rtt_ewma = crate::rtt::RttEwma::measured(
                Duration::from_millis(rtt_ms),
                tokio::time::Instant::now(),
            );
        });
    }

    /// Test helper: read tcp_healthy for uplink `index`.
    #[doc(hidden)]
    pub async fn test_tcp_healthy(&self, index: usize) -> Option<bool> {
        self.inner.read_status(index).tcp.healthy
    }

    /// Test helper: stamp the "a probe cycle completed just now" marker that
    /// [`Self::has_recent_liveness_evidence`] reads. `test_set_*_health`
    /// deliberately does not touch it, so a test can build the state a
    /// half-stuck daemon is in — health flagged healthy, nothing refreshing it.
    #[doc(hidden)]
    pub async fn test_mark_checked_now(&self, index: usize) {
        self.inner.with_status_mut(index, |status| {
            status.last_checked = Some(tokio::time::Instant::now());
        });
    }

    /// Test helper: stamp "real traffic just moved on this transport", the
    /// other evidence [`Self::has_recent_liveness_evidence`] accepts.
    #[doc(hidden)]
    pub async fn test_mark_active_now(&self, index: usize, transport: crate::TransportKind) {
        self.inner.with_status_mut(index, |status| {
            let now = tokio::time::Instant::now();
            match transport {
                crate::TransportKind::Tcp => status.tcp.last_active = Some(now),
                crate::TransportKind::Udp => status.udp.last_active = Some(now),
            }
        });
    }

    /// Test helper: whether uplink `index` is administratively disabled
    /// (operator on/off), i.e. the value the snapshot exposes as
    /// `admin_disabled`.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn test_admin_disabled(&self, index: usize) -> bool {
        !self.inner.admin_enabled(index)
    }

    /// Test helper: snapshot of full UplinkStatus for uplink `index`.
    /// Visibility is `pub(crate)` because `UplinkStatus` itself is
    /// crate-private; the helper is only consumed by inline tests in
    /// this crate. `allow(dead_code)` because it isn't called in the
    /// non-test lib build (test_helpers.rs is included via cfg-gated
    /// `#[path]` for both `cfg(test)` and `feature = "test-helpers"`,
    /// and the latter activates without Rust knowing the inline tests
    /// will pick up the helpers).
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn read_status_for_test(
        &self,
        index: usize,
    ) -> crate::manager::status::UplinkStatus {
        self.inner.read_status(index)
    }

    /// Test helper: feed a synthetic [`ProbeOutcome`] through the same path
    /// the scheduler uses, so probe-driven side effects (health flip,
    /// streak counters, mode-downgrade window, early active-wire failback)
    /// run without spinning up real probe targets. `pub(crate)` for the
    /// same reason as `read_status_for_test` — `ProbeOutcome` is
    /// crate-private, the helper is only used by inline tests.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn test_apply_probe_outcome_for_test(
        &self,
        index: usize,
        outcome: crate::manager::probe::outcome::ProbeOutcome,
    ) {
        // The real scheduler walks `process_probe_ok` with the per-uplink
        // effective TCP/UDP modes; for tests we read them off the uplink
        // config directly (no async-friendly accessor here, so block).
        let uplink = self.uplinks()[index].clone();
        let effective_tcp = uplink.tcp_dial_mode();
        let effective_udp = uplink.udp_dial_mode();
        let mut h3_tcp_recovery = Vec::new();
        let mut h3_udp_recovery = Vec::new();
        let _ = self.process_probe_ok(
            index,
            &uplink,
            outcome,
            effective_tcp,
            effective_udp,
            &mut h3_tcp_recovery,
            &mut h3_udp_recovery,
        );
    }

    /// Feed a synthetic probe error through `process_probe_err`. Mirrors
    /// `test_apply_probe_outcome_for_test` for the failure side: lets
    /// inline tests exercise the failure-path bookkeeping (active-wire
    /// advance on probe machinery error, consecutive_failures streak,
    /// cooldown / penalty) without standing up real probe targets.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn test_apply_probe_err_for_test(&self, index: usize, error: anyhow::Error) {
        let uplink = self.uplinks()[index].clone();
        let effective_tcp = uplink.tcp_dial_mode();
        let effective_udp = uplink.udp_dial_mode();
        self.process_probe_err(index, &uplink, error, effective_tcp, effective_udp);
    }

    /// Test helper: pre-stage `(active_wire, last_any_wire_success)` into
    /// the "sticky on a fallback that is verifiably alive" state, which is
    /// the precondition gate for `should_skip_primary_probe_escalation`.
    /// Inline tests use it to drive a primary-probe failure into the gate
    /// without needing to first synthesise a separate fallback-wire-probe
    /// success. `consecutive_failures` is reset to zero so the test starts
    /// from a clean streak.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn test_seed_active_fallback_with_recent_success(
        &self,
        index: usize,
        transport: crate::types::TransportKind,
        active_wire: u8,
        success_at: tokio::time::Instant,
    ) {
        self.inner.with_status_mut(index, |status| {
            let per = match transport {
                crate::types::TransportKind::Tcp => &mut status.tcp,
                crate::types::TransportKind::Udp => &mut status.udp,
            };
            per.active_wire = active_wire;
            per.last_any_wire_success = Some(success_at);
            per.consecutive_failures = 0;
        });
    }

    /// Test helper: accumulate `count` liveness penalties on `wire` for
    /// `(index, transport)`, the same effect a failed dial has. Lets the
    /// weighted-selection tests stage a wire as "frequently disconnecting"
    /// without driving the full active-wire / shuffle state machine.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn test_add_wire_penalty(
        &self,
        index: usize,
        transport: crate::types::TransportKind,
        wire: u8,
        count: usize,
    ) {
        let now = tokio::time::Instant::now();
        let lb = self.inner.load_balancing.clone();
        self.inner.with_status_mut(index, |status| {
            let per = match transport {
                crate::types::TransportKind::Tcp => &mut status.tcp,
                crate::types::TransportKind::Udp => &mut status.udp,
            };
            for _ in 0..count {
                crate::penalty::add_penalty(per.wire_penalty_slot_mut(wire), now, &lb);
            }
        });
    }

    /// Test helper: add `secs` of decaying uplink-level failure penalty on
    /// `(index, transport)` — the same `PerTransportStatus::penalty` field
    /// `penalty_weight` reads for weighted re-selection (`manager::reselect`).
    /// Distinct from [`Self::test_add_wire_penalty`], which accrues penalty on
    /// a per-*wire* slot (`wire_penalty`) consumed by wire-level dial-order /
    /// active-wire rerolls; this one is the uplink-level penalty consulted
    /// when weighing whole uplinks against each other.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn test_add_uplink_penalty(
        &self,
        index: usize,
        transport: crate::types::TransportKind,
        secs: u64,
    ) {
        let now = tokio::time::Instant::now();
        self.inner.with_status_mut(index, |status| {
            let ts = match transport {
                crate::types::TransportKind::Tcp => &mut status.tcp,
                crate::types::TransportKind::Udp => &mut status.udp,
            };
            ts.penalty.value_secs = secs as f64;
            ts.penalty.updated_at = Some(now);
        });
    }

    /// Test helper: directly set the sticky `active_wire` index for
    /// `(index, transport)` without going through the dial / probe state
    /// machine.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn test_set_active_wire(
        &self,
        index: usize,
        transport: crate::types::TransportKind,
        wire: u8,
    ) {
        self.inner.with_status_mut(index, |status| {
            match transport {
                crate::types::TransportKind::Tcp => status.tcp.active_wire = wire,
                crate::types::TransportKind::Udp => status.udp.active_wire = wire,
            };
        });
    }

    /// Test helper: directly seed the primary mode-downgrade window for
    /// `(index, transport)` with `cap` and a fresh deadline. Lets tests
    /// pre-stage the system into "previously degraded" state without
    /// driving a sequence of synthetic probe failures to converge there.
    /// Counters (`consecutive_failures` / `consecutive_successes`) are
    /// reset to zero so the test starts from a clean streak.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn test_seed_mode_downgrade_for_test(
        &self,
        index: usize,
        transport: crate::types::TransportKind,
        cap: crate::config::TransportMode,
    ) {
        let now = tokio::time::Instant::now();
        let until = now + self.inner.load_balancing.mode_downgrade_duration;
        self.inner.with_status_mut(index, |status| {
            let per = match transport {
                crate::types::TransportKind::Tcp => &mut status.tcp,
                crate::types::TransportKind::Udp => &mut status.udp,
            };
            per.descent.seed_window(until, cap);
            per.consecutive_failures = 0;
            per.consecutive_successes = 0;
        });
    }

    /// Like [`Self::test_seed_mode_downgrade_for_test`] but back-dates the
    /// continuous-degradation episode by `degraded_for`, so tests can stage
    /// an uplink that has been running below its configured carrier long
    /// enough to cross the `carrier_degraded_failover` threshold.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn test_seed_mode_downgrade_with_episode_for_test(
        &self,
        index: usize,
        transport: crate::types::TransportKind,
        cap: crate::config::TransportMode,
        degraded_for: Duration,
    ) {
        let now = tokio::time::Instant::now();
        let until = now + self.inner.load_balancing.mode_downgrade_duration;
        let started_at = now.checked_sub(degraded_for).unwrap_or(now);
        self.inner.with_status_mut(index, |status| {
            let per = match transport {
                crate::types::TransportKind::Tcp => &mut status.tcp,
                crate::types::TransportKind::Udp => &mut status.udp,
            };
            per.descent.seed_window_with_episode(until, cap, started_at);
            per.consecutive_failures = 0;
        });
    }

    /// Test helper: an [`UplinkCandidate`](crate::types::UplinkCandidate) for
    /// uplink `index`, built directly off the manager's configured uplinks —
    /// no probe / selection machinery involved. Used by dial-path tests that
    /// only need a candidate handle to call a dial method on.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) async fn tcp_candidates_for_test(
        &self,
        index: usize,
    ) -> crate::types::UplinkCandidate {
        crate::types::UplinkCandidate {
            index,
            uplink: self.uplinks()[index].clone(),
        }
    }

    /// Test helper: number of times [`Self::record_wire_outcome`] has been
    /// invoked for `(index, transport, wire)`, regardless of success or
    /// failure. The narrowest seam that lets `dial_over_wires` tests confirm
    /// a `WireAttempt::NotApplicable` wire really never reached
    /// `record_wire_outcome` — no other field distinguishes "never called"
    /// from "called and happened to leave everything unchanged".
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn wire_outcome_count_for_test(
        &self,
        index: usize,
        transport: crate::types::TransportKind,
        wire: u8,
    ) -> u32 {
        self.inner
            .read_status(index)
            .of(transport)
            .wire_outcome_calls
            .get(&wire)
            .copied()
            .unwrap_or(0)
    }

    /// Test helper: the set of wires currently holding a registered carrier
    /// loss probe for `(index, transport)`. See
    /// [`crate::loss::CarrierLossRegistry::registered_wires_for_test`].
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn registered_loss_probe_wires_for_test(
        &self,
        index: usize,
        transport: crate::types::TransportKind,
    ) -> std::collections::HashSet<u8> {
        self.inner.carrier_loss[index]
            .lock()
            .registered_wires_for_test(transport)
    }

    /// Test helper: a single connected-but-never-dialed stream, standalone
    /// rather than seeded into a pool — for tests that hand a stream
    /// straight to a push-path helper (e.g. `StandbyCtx::try_pool_dialed_stream`)
    /// instead of staging pool state through `fill_pool_for_test`.
    ///
    /// A genuine loopback TCP socket wrapped as an `Http1` `TransportStream`
    /// (mirrors the pattern in
    /// `taking_a_carrier_from_the_warm_pool_registers_its_loss_probe`): the
    /// take path peeks the socket for liveness before handing it out, so a
    /// fabricated stream would be discarded as stale before a test ever
    /// observes the behaviour under test. The accepted server-side socket is
    /// kept open for the life of the process (leaked into a pending task)
    /// rather than dropped at the end of this function — dropping it would
    /// close the TCP connection, so the client side the caller actually gets
    /// would observe closure and fail the same liveness peek.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) async fn dialed_stream_for_test() -> outline_transport::TransportStream {
        use tokio_tungstenite::tungstenite::protocol::Role;
        use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let _server = server;
            std::future::pending::<()>().await
        });
        let ws =
            WebSocketStream::from_raw_socket(MaybeTlsStream::Plain(client), Role::Client, None)
                .await;
        outline_transport::TransportStream::new_http1(ws)
    }

    /// Test helper: make `(index, transport)`'s warm-standby pool prewarm
    /// `wire` and seed it with `count` connected-but-never-dialed carriers on
    /// that wire. Lets pool-wire tests stage "the pool currently holds
    /// carriers dialed on wire W" without driving a real refill through the
    /// network. `count = 0` is a legitimate call: it claims the wire on an
    /// otherwise-untouched (or already-drained) pool without seeding any
    /// carriers, mirroring the drain-and-claim `try_take_alive` performs on a
    /// wire mismatch.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) async fn fill_pool_for_test(
        &self,
        index: usize,
        transport: crate::types::TransportKind,
        wire: u8,
        count: usize,
    ) {
        let mut streams = Vec::with_capacity(count);
        for _ in 0..count {
            streams.push(Self::dialed_stream_for_test().await);
        }
        let pool = self.inner.standby_pools[index].wire_pool(transport);
        let mut guard = pool.lock().await;
        guard.claim_wire(wire);
        for stream in streams {
            guard.stage_carrier_for_test(wire, stream);
        }
    }

    /// Test helper: seed `count` carriers tagged with `carrier_wire` into
    /// `(index, transport)`'s pool **without** touching the wire the pool
    /// says it prewarms.
    ///
    /// This stages the one state no production path can produce any more: a
    /// carrier from one wire sitting in a pool that claims to serve another.
    /// That is exactly what the old drain-then-restamp gap left behind — a
    /// refill dial for the outgoing wire, parked on the pool lock, pushed
    /// into the drained-but-not-yet-restamped pool — and it is the state the
    /// take path has to refuse.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) async fn stage_foreign_carriers_for_test(
        &self,
        index: usize,
        transport: crate::types::TransportKind,
        carrier_wire: u8,
        count: usize,
    ) {
        let mut streams = Vec::with_capacity(count);
        for _ in 0..count {
            streams.push(Self::dialed_stream_for_test().await);
        }
        let pool = self.inner.standby_pools[index].wire_pool(transport);
        let mut guard = pool.lock().await;
        for stream in streams {
            guard.stage_carrier_for_test(carrier_wire, stream);
        }
    }

    /// Test helper: the wire `(index, transport)`'s warm-standby pool
    /// currently prewarms.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) async fn pool_wire_for_test(
        &self,
        index: usize,
        transport: crate::types::TransportKind,
    ) -> u8 {
        self.inner.standby_pools[index]
            .wire_pool(transport)
            .lock()
            .await
            .wire()
    }

    /// Test helper: how many refill tasks have been spawned through
    /// `(index, transport)`'s [`RefillGate`](crate::manager::standby_pool::RefillGate)
    /// for the life of the manager. Lets tests confirm a code path schedules
    /// a background refill (`spawn_refill`) without needing the spawned task
    /// to actually complete a dial — the gate's claim counter observes the
    /// scheduling itself.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn refill_spawned_count_for_test(
        &self,
        index: usize,
        transport: crate::types::TransportKind,
    ) -> u64 {
        self.inner.standby_pools[index].refill_gate(transport).spawned()
    }

    /// Test helper: current length of `(index, transport)`'s warm-standby
    /// pool, via the same `len_hint()` `/metrics` scrapes read.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn pool_len_for_test(
        &self,
        index: usize,
        transport: crate::types::TransportKind,
    ) -> usize {
        self.inner.standby_pools[index].wire_pool(transport).len_hint()
    }
}
