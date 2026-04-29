use std::sync::Arc;

use tracing::{info, warn};

use crate::config::TransportMode;

use super::super::super::types::{TransportKind, Uplink, UplinkManager};
use super::super::mode_downgrade::ModeDowngradeTrigger;
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
                    TransportKind::Tcp => (TransportMode::WsH3, uplink.udp_ws_mode),
                    TransportKind::Udp => (uplink.tcp_ws_mode, TransportMode::WsH3),
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
                self.clear_mode_downgrade(index, which);
            } else {
                self.extend_mode_downgrade(index, which, ModeDowngradeTrigger::RecoveryReprobeFail);
            }
        }
    }
}
