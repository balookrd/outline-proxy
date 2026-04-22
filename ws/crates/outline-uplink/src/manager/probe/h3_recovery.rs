use std::sync::Arc;

use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::config::WsTransportMode;

use super::super::super::types::{TransportKind, Uplink, UplinkManager};
use super::scheduler::run_probe_attempt_with_timeout;

impl UplinkManager {
    pub(super) async fn run_h3_recovery_probes(
        &self,
        needed: Vec<(usize, Uplink)>,
        which: TransportKind,
    ) {
        if needed.is_empty() {
            return;
        }
        let mut recovery_tasks = tokio::task::JoinSet::new();
        for (index, uplink) in needed {
            let probe = self.inner.probe.clone();
            let dial_limit = Arc::clone(&self.inner.probe_dial_limit);
            let execution_limit = Arc::clone(&self.inner.probe_execution_limit);
            let group_name = self.inner.group_name.clone();
            let dns_cache = Arc::clone(&self.inner.dns_cache);
            recovery_tasks.spawn(async move {
                let _permit = execution_limit
                    .acquire_owned()
                    .await
                    .expect("probe execution semaphore closed");
                // Run probe with H3 for the transport we're recovering, and
                // keep the other transport at its native mode (it doesn't
                // affect the recovery decision but avoids penalising it).
                let (eff_tcp, eff_udp) = match which {
                    TransportKind::Tcp => (WsTransportMode::H3, uplink.udp_ws_mode),
                    TransportKind::Udp => (uplink.tcp_ws_mode, WsTransportMode::H3),
                };
                let outcome = run_probe_attempt_with_timeout(
                    Arc::clone(&dns_cache),
                    group_name,
                    uplink.clone(),
                    probe,
                    dial_limit,
                    eff_tcp,
                    eff_udp,
                )
                .await;
                (index, uplink, outcome)
            });
        }
        while let Some(joined) = recovery_tasks.join_next().await {
            let (index, uplink, outcome) = match joined {
                Ok(value) => value,
                Err(error) => {
                    warn!(error = %error, kind = ?which, "H3 recovery probe task failed");
                    continue;
                },
            };
            let now = Instant::now();
            let h3_downgrade_duration = self.inner.load_balancing.h3_downgrade_duration;
            let recovered = match which {
                TransportKind::Tcp => matches!(&outcome, Ok(r) if r.tcp_ok),
                TransportKind::Udp => matches!(&outcome, Ok(r) if r.udp_applicable && r.udp_ok),
            };
            if recovered {
                info!(
                    uplink = %uplink.name,
                    kind = ?which,
                    "H3 recovery confirmed by re-probe, clearing downgrade window early"
                );
                self.inner.with_status_mut(index, |status| match which {
                    TransportKind::Tcp => status.tcp.h3_downgrade_until = None,
                    TransportKind::Udp => status.udp.h3_downgrade_until = None,
                });
            } else {
                let new_until = now + h3_downgrade_duration;
                let current = {
                    let s = self.inner.read_status(index);
                    match which {
                        TransportKind::Tcp => s.tcp.h3_downgrade_until,
                        TransportKind::Udp => s.udp.h3_downgrade_until,
                    }
                };
                if current.is_none_or(|t| t < new_until) {
                    debug!(
                        uplink = %uplink.name,
                        kind = ?which,
                        downgrade_secs = h3_downgrade_duration.as_secs(),
                        "H3 still unreachable after recovery probe, extending downgrade window"
                    );
                    self.inner.with_status_mut(index, |status| match which {
                        TransportKind::Tcp => status.tcp.h3_downgrade_until = Some(new_until),
                        TransportKind::Udp => status.udp.h3_downgrade_until = Some(new_until),
                    });
                }
            }
        }
    }
}
