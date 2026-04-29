use tokio::time::Instant;
use tracing::{debug, warn};

use crate::config::{LoadBalancingConfig, UplinkTransport, TransportMode};

use super::super::super::penalty::{add_penalty, update_rtt_ewma};
use super::super::super::types::{
    PerTransportStatus, ProbeOutcome, TransportKind, Uplink, UplinkManager,
};
use super::super::mode_downgrade::ModeDowngradeTrigger;

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
    // Probe confirms the data path works again: drop any data-plane failure
    // streak so a fresh burst is required before another health flip.
    status.consecutive_runtime_failures = 0;
    // Only clear runtime-failure cooldown when the probe confirms the transport is
    // healthy. Clearing unconditionally would make a recently-failed uplink
    // immediately eligible again, causing oscillation under load.
    status.cooldown_until = None;
}

fn needs_h3_recovery(
    status: &PerTransportStatus,
    effective_mode: TransportMode,
    uplink_transport: UplinkTransport,
    uplink_ws_mode: TransportMode,
    now: Instant,
) -> bool {
    effective_mode == TransportMode::WsH2
        && uplink_transport == UplinkTransport::Ws
        && uplink_ws_mode == TransportMode::WsH3
        && status.mode_downgrade_until.is_some_and(|t| t > now)
}

impl UplinkManager {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn process_probe_ok(
        &self,
        index: usize,
        uplink: &Uplink,
        result: ProbeOutcome,
        effective_tcp_mode: TransportMode,
        effective_udp_mode: TransportMode,
        h3_tcp_recovery: &mut Vec<(usize, Uplink)>,
        h3_udp_recovery: &mut Vec<(usize, Uplink)>,
    ) -> (bool, bool) {
        let now = Instant::now();
        let min_failures = self.inner.probe.min_failures as u32;
        let rtt_ewma_alpha = self.inner.load_balancing.rtt_ewma_alpha;
        let load_balancing = self.inner.load_balancing.clone();
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
        // Route transport-level probe failures through the unified H3 downgrade
        // helper (no-op for non-WS / non-H3 uplinks).  This prevents flapping:
        // without downgrade, intermittent H3 probe failures alternate pass/fail
        // and churn active-passive selection every cycle; with H2 downgrade, the
        // next probe uses the stable H2 path and H3 is only retried after the
        // window expires or a recovery re-probe confirms liveness.
        if !result.tcp_ok {
            self.extend_mode_downgrade(
                index,
                TransportKind::Tcp,
                ModeDowngradeTrigger::ProbeTransportFailure,
            );
        }
        if result.udp_applicable && !result.udp_ok {
            self.extend_mode_downgrade(
                index,
                TransportKind::Udp,
                ModeDowngradeTrigger::ProbeTransportFailure,
            );
        }
        // The probe layer reports a "silent" downgrade when it succeeded but
        // the underlying dial was clamped/fallen-back below the requested
        // mode (host-level `ws_mode_cache` or inline H3→H2/H1 retry inside
        // `connect_websocket_with_resume`). Without this, `tcp_ok=true`
        // would mask the fact that H3 is unreachable, leaving
        // `effective_*_ws_mode` stuck on H3 forever while every actual probe
        // and user dial silently rides H2.
        if let Some(requested) = result.tcp_downgraded_from {
            self.extend_mode_downgrade(
                index,
                TransportKind::Tcp,
                ModeDowngradeTrigger::SilentTransportFallback(requested),
            );
        }
        if let Some(requested) = result.udp_downgraded_from {
            self.extend_mode_downgrade(
                index,
                TransportKind::Udp,
                ModeDowngradeTrigger::SilentTransportFallback(requested),
            );
        }
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

    pub(super) fn process_probe_err(&self, index: usize, uplink: &Uplink, error: anyhow::Error) {
        let now = Instant::now();
        let min_failures = self.inner.probe.min_failures as u32;
        let load_balancing = self.inner.load_balancing.clone();
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
            status.last_error = Some(error_text.clone());
        });
        // Probe-level failure (ws connect / timeout).  Same H3 downgrade logic
        // as the tcp_ok=false case above; helper is a no-op for non-WS/non-H3.
        self.extend_mode_downgrade(
            index,
            TransportKind::Tcp,
            ModeDowngradeTrigger::ProbeConnectFailure(&error),
        );
        if uplink.supports_udp() {
            self.extend_mode_downgrade(
                index,
                TransportKind::Udp,
                ModeDowngradeTrigger::ProbeConnectFailure(&error),
            );
        }
        warn!(uplink = %uplink.name, error = %format!("{error:#}"), "uplink probe failed");
    }
}
