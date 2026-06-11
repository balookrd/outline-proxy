use std::sync::Arc;

use tracing::{info, warn};

use super::super::super::types::{TransportKind, Uplink, UplinkManager};
use super::super::mode_downgrade::ModeDowngradeTrigger;
use super::scheduler::run_probe_attempt_with_timeout;

impl UplinkManager {
    /// Run an explicit re-probe at the **configured** carrier of each
    /// uplink in `needed` to decide whether the active mode-downgrade
    /// window can be cleared early. The regular probe runs at the
    /// *effective* (capped) carrier, so its success only confirms the
    /// fallback rank; this pass tests the rank operators originally
    /// asked for and lets the cap drop as soon as it answers.
    ///
    /// Symmetric across both families:
    /// * WS uplinks configured at `WsH3` test `WsH3`.
    /// * VLESS uplinks configured at `XhttpH3` test `XhttpH3`; configured
    ///   at `XhttpH2` test `XhttpH2`.
    ///
    /// On success the recovery is recorded via
    /// [`UplinkManager::note_recovery_probe_success`], which only
    /// clears the cap when the per-transport recovery streak reaches
    /// [`UplinkManager::RECOVERY_SUCCESS_STREAK_THRESHOLD`] (currently
    /// 2). A single recovery success on a flaky configured carrier
    /// (handshake passes, data plane fails immediately after) is
    /// treated as tentative; the cap stays installed until a second
    /// consecutive recovery success confirms.
    ///
    /// On failure the cap is extended with
    /// [`ModeDowngradeTrigger::RecoveryReprobeFail`] so the per-cycle
    /// "still can't reach configured carrier" event is captured
    /// without re-stepping the cap further down (the existing
    /// monotonic-descent rule keeps the deepest prior cap), and the
    /// recovery streak is reset.
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
                // Recovery dials the **configured** carrier on both
                // sides — `WsH3` for WS uplinks configured at H3,
                // `XhttpH3` / `XhttpH2` for VLESS uplinks configured
                // at the matching XHTTP rank. We only inspect the
                // outcome for the side that's actually recovering
                // (`tcp_ok` for TCP, `udp_ok` for UDP) so the other
                // side's result is cosmetic.
                let eff_tcp = uplink.tcp_dial_mode();
                let eff_udp = uplink.udp_dial_mode();
                // Recovery deliberately bypasses both warm slots: the
                // cached pipes (if any) were dialled at the capped
                // mode, but recovery probes need to test the un-capped
                // configured carrier. Passing `None`/`None` forces a
                // fresh dial.
                let outcome = run_probe_attempt_with_timeout(
                    Arc::clone(&dns_cache),
                    group_name,
                    uplink.clone(),
                    probe,
                    dial_limit,
                    eff_tcp,
                    eff_udp,
                    None,
                    None,
                )
                .await;
                (index, uplink, outcome)
            });
        }
        while let Some(joined) = recovery_tasks.join_next().await {
            let (index, uplink, outcome) = match joined {
                Ok(value) => value,
                Err(error) => {
                    warn!(error = %error, kind = ?which, "carrier recovery probe task failed");
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
                    "carrier recovery probe succeeded; consulting streak gate"
                );
                self.note_recovery_probe_success(index, which);
            } else {
                self.extend_mode_downgrade(index, which, ModeDowngradeTrigger::RecoveryReprobeFail);
            }
        }
    }
}
