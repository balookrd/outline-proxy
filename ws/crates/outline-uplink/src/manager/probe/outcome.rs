use std::time::Duration;

use tokio::time::Instant;
use tracing::{debug, warn};

use crate::config::{LoadBalancingConfig, UplinkTransport, WsTransportMode};

use super::super::super::types::{
    PerTransportStatus, ProbeOutcome, Uplink, UplinkManager,
};
use super::super::super::utils::{add_penalty, update_rtt_ewma};

fn record_transport_failure(
    status: &mut PerTransportStatus,
    now: Instant,
    min_failures: u32,
    load_balancing: &LoadBalancingConfig,
) {
    status.consecutive_successes = 0;
    status.consecutive_failures = status.consecutive_failures.saturating_add(1);
    if status.consecutive_failures >= min_failures {
        status.healthy = Some(false);
        add_penalty(&mut status.penalty, now, load_balancing);
    }
}

fn record_transport_success(status: &mut PerTransportStatus) {
    status.consecutive_failures = 0;
    status.consecutive_successes = status.consecutive_successes.saturating_add(1);
    status.healthy = Some(true);
    // Only clear runtime-failure cooldown when the probe confirms the transport is
    // healthy. Clearing unconditionally would make a recently-failed uplink
    // immediately eligible again, causing oscillation under load.
    status.cooldown_until = None;
}

fn apply_h3_downgrade_if_h3(
    status: &mut PerTransportStatus,
    uplink_transport: UplinkTransport,
    uplink_ws_mode: WsTransportMode,
    now: Instant,
    h3_downgrade_duration: Duration,
) {
    if uplink_transport == UplinkTransport::Ws && uplink_ws_mode == WsTransportMode::H3 {
        status.h3_downgrade_until = Some(now + h3_downgrade_duration);
    }
}

fn needs_h3_recovery(
    status: &PerTransportStatus,
    effective_mode: WsTransportMode,
    uplink_transport: UplinkTransport,
    uplink_ws_mode: WsTransportMode,
    now: Instant,
) -> bool {
    effective_mode == WsTransportMode::H2
        && uplink_transport == UplinkTransport::Ws
        && uplink_ws_mode == WsTransportMode::H3
        && status.h3_downgrade_until.is_some_and(|t| t > now)
}

impl UplinkManager {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn process_probe_ok(
        &self,
        index: usize,
        uplink: &Uplink,
        result: ProbeOutcome,
        effective_tcp_mode: WsTransportMode,
        effective_udp_mode: WsTransportMode,
        h3_tcp_recovery: &mut Vec<(usize, Uplink)>,
        h3_udp_recovery: &mut Vec<(usize, Uplink)>,
    ) -> (bool, bool) {
        let now = Instant::now();
        let min_failures = self.inner.probe.min_failures as u32;
        let rtt_ewma_alpha = self.inner.load_balancing.rtt_ewma_alpha;
        let h3_downgrade_duration = self.inner.load_balancing.h3_downgrade_duration;
        let load_balancing = self.inner.load_balancing.clone();
        // Read current h3_downgrade_until values before mutating so
        // we can emit warn! without holding the write lock.
        let (prev_tcp_h3, prev_udp_h3) = {
            let s = self.inner.read_status(index);
            (s.tcp.h3_downgrade_until, s.udp.h3_downgrade_until)
        };
        // Emit warn! for H3 downgrades before acquiring the write lock.
        if !result.tcp_ok
            && uplink.transport == UplinkTransport::Ws
            && uplink.tcp_ws_mode == WsTransportMode::H3
            && prev_tcp_h3.is_none_or(|t| t < now)
        {
            warn!(
                uplink = %uplink.name,
                downgrade_secs = h3_downgrade_duration.as_secs(),
                "H3 TCP probe failed, downgrading to H2 for next probe cycle"
            );
        }
        if result.udp_applicable
            && !result.udp_ok
            && uplink.transport == UplinkTransport::Ws
            && uplink.udp_ws_mode == WsTransportMode::H3
            && prev_udp_h3.is_none_or(|t| t < now)
        {
            warn!(
                uplink = %uplink.name,
                downgrade_secs = h3_downgrade_duration.as_secs(),
                "H3 UDP probe failed, downgrading to H2 for next probe cycle"
            );
        }
        let mut needs_h3_tcp_recovery = false;
        let mut needs_h3_udp_recovery = false;
        self.inner.with_status_mut(index, |status| {
            status.last_checked = Some(now);
            status.tcp.latency = result.tcp_latency;
            status.udp.latency = result.udp_latency;
            update_rtt_ewma(&mut status.tcp.rtt_ewma, result.tcp_latency, rtt_ewma_alpha);
            update_rtt_ewma(&mut status.udp.rtt_ewma, result.udp_latency, rtt_ewma_alpha);
            if !result.tcp_ok {
                record_transport_failure(&mut status.tcp, now, min_failures, &load_balancing);
                // If this uplink is configured for H3 and the TCP probe
                // failed, downgrade to H2 for the next probe cycle.  Without
                // this, intermittent H3 probe failures cause probe-driven
                // flapping in active-passive / global scope: the probe
                // alternates pass (H3) / fail (H3) → switch to backup /
                // switch back to primary on every cycle.  With H2 downgrade,
                // recovery probing uses H2 which is stable, and H3 is only
                // retried after the downgrade timer expires.
                apply_h3_downgrade_if_h3(
                    &mut status.tcp,
                    uplink.transport,
                    uplink.tcp_ws_mode,
                    now,
                    h3_downgrade_duration,
                );
            } else {
                record_transport_success(&mut status.tcp);
                // Do NOT clear h3_tcp_downgrade_until here.  The probe uses the
                // effective (possibly downgraded) WS mode, so a successful probe
                // only confirms H2 connectivity during a downgrade window — it does
                // not prove that H3 is healthy again.  Instead, schedule an H3
                // recovery re-probe below to confirm H3 liveness explicitly.
                needs_h3_tcp_recovery = needs_h3_recovery(
                    &status.tcp,
                    effective_tcp_mode,
                    uplink.transport,
                    uplink.tcp_ws_mode,
                    now,
                );
            }
            if result.udp_applicable {
                if !result.udp_ok {
                    record_transport_failure(&mut status.udp, now, min_failures, &load_balancing);
                    // Mirror of the TCP H3 downgrade above for UDP.
                    apply_h3_downgrade_if_h3(
                        &mut status.udp,
                        uplink.transport,
                        uplink.udp_ws_mode,
                        now,
                        h3_downgrade_duration,
                    );
                } else {
                    record_transport_success(&mut status.udp);
                    // Schedule UDP H3 recovery re-probe — mirror of the TCP
                    // path.  Successful H2 probe doesn't prove H3 is back, so
                    // verify it explicitly below.
                    needs_h3_udp_recovery = needs_h3_recovery(
                        &status.udp,
                        effective_udp_mode,
                        uplink.transport,
                        uplink.udp_ws_mode,
                        now,
                    );
                }
            }
            if result.tcp_ok && (!result.udp_applicable || result.udp_ok) {
                status.last_error = None;
            }
        });
        if needs_h3_tcp_recovery {
            h3_tcp_recovery.push((index, uplink.clone()));
        }
        if needs_h3_udp_recovery {
            h3_udp_recovery.push((index, uplink.clone()));
        }
        let (tcp_rtt_ewma_ms, udp_rtt_ewma_ms) = {
            let s = self.inner.read_status(index);
            (
                s.tcp.rtt_ewma.map(|v| v.as_millis() as u64).unwrap_or_default(),
                s.udp.rtt_ewma.map(|v| v.as_millis() as u64).unwrap_or_default(),
            )
        };
        debug!(
            uplink = %uplink.name,
            tcp_healthy = result.tcp_ok,
            udp_healthy = result.udp_ok,
            tcp_latency_ms = result.tcp_latency.map(|v| v.as_millis() as u64).unwrap_or_default(),
            udp_latency_ms = result.udp_latency.map(|v| v.as_millis() as u64).unwrap_or_default(),
            tcp_rtt_ewma_ms,
            udp_rtt_ewma_ms,
            "uplink probe succeeded"
        );
        let refill_tcp = result.tcp_ok;
        // When UDP is not configured for this uplink, leave the standby pool
        // alone (don't clear it, don't refill it).
        let refill_udp = result.udp_applicable && result.udp_ok;
        (refill_tcp, refill_udp)
    }

    pub(super) fn process_probe_err(
        &self,
        index: usize,
        uplink: &Uplink,
        error: anyhow::Error,
    ) {
        let now = Instant::now();
        let min_failures = self.inner.probe.min_failures as u32;
        let h3_downgrade_duration = self.inner.load_balancing.h3_downgrade_duration;
        let load_balancing = self.inner.load_balancing.clone();
        // Read h3_downgrade_until before mutating for warn! emission.
        let (prev_tcp_h3, prev_udp_h3) = {
            let s = self.inner.read_status(index);
            (s.tcp.h3_downgrade_until, s.udp.h3_downgrade_until)
        };
        // Emit warn! before acquiring write lock.
        if uplink.transport == UplinkTransport::Ws
            && uplink.tcp_ws_mode == WsTransportMode::H3
            && prev_tcp_h3.is_none_or(|t| t < now)
        {
            warn!(
                uplink = %uplink.name,
                error = %format!("{error:#}"),
                downgrade_secs = h3_downgrade_duration.as_secs(),
                "H3 probe connection failed, downgrading TCP to H2"
            );
        }
        if uplink.supports_udp()
            && uplink.transport == UplinkTransport::Ws
            && uplink.udp_ws_mode == WsTransportMode::H3
            && prev_udp_h3.is_none_or(|t| t < now)
        {
            warn!(
                uplink = %uplink.name,
                error = %format!("{error:#}"),
                downgrade_secs = h3_downgrade_duration.as_secs(),
                "H3 probe connection failed, downgrading UDP to H2"
            );
        }
        let error_text = format!("{error:#}");
        self.inner.with_status_mut(index, |status| {
            status.last_checked = Some(now);
            record_transport_failure(&mut status.tcp, now, min_failures, &load_balancing);
            // Only penalise UDP when it is actually configured.  The probe Err
            // path is usually a TCP connect failure; penalising UDP here when
            // there is no udp_ws_url would permanently mark UDP unhealthy for
            // TCP-only uplinks.
            if uplink.supports_udp() {
                record_transport_failure(&mut status.udp, now, min_failures, &load_balancing);
            }
            // Probe connection itself failed (ws connect / timeout).  Same H3
            // downgrade logic as the tcp_ok=false case above.
            apply_h3_downgrade_if_h3(
                &mut status.tcp,
                uplink.transport,
                uplink.tcp_ws_mode,
                now,
                h3_downgrade_duration,
            );
            // Same for UDP — when the uplink supports UDP and is on H3, a
            // probe-level failure also forces UDP H2 fallback so the failover
            // loop on a broken H3 server doesn't spin.
            if uplink.supports_udp() {
                apply_h3_downgrade_if_h3(
                    &mut status.udp,
                    uplink.transport,
                    uplink.udp_ws_mode,
                    now,
                    h3_downgrade_duration,
                );
            }
            status.last_error = Some(error_text.clone());
        });
        warn!(uplink = %uplink.name, error = %format!("{error:#}"), "uplink probe failed");
    }
}
