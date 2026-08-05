use std::sync::Arc;

use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use tracing::{debug, info};

use outline_metrics as metrics;
use outline_transport::{UdpResumeStore, UdpSessionTransport};
use outline_uplink::{
    TransportKind, UplinkCandidate, UplinkManager, UplinkTransport, WireAttempt, WireSpec,
};
use socks5_proto::TargetAddr;

#[derive(Clone)]
pub(super) struct ActiveUdpTransport {
    pub(super) index: usize,
    pub(super) uplink_name: Arc<str>,
    pub(super) transport: Arc<UdpSessionTransport>,
    /// Pre-resolved `up`-direction datagram + byte counters for this uplink's
    /// `(group, uplink)` series. Resolved once here (on select / failover) so
    /// the per-datagram send path skips the label hashing `add_udp_datagram` /
    /// `add_bytes` would pay on every packet.
    pub(super) up_counters: metrics::UdpFlowCounters,
}

/// Acquire a UDP transport for `candidate`, falling back to each configured
/// `[[outline.uplinks.fallbacks]]` entry on the same uplink when the primary
/// dial fails, via the shared [`UplinkManager::dial_over_wires`] loop.
/// `allow_fallbacks: true` unconditionally — SOCKS has walked its full wire
/// chain for as long as the chain has existed, unlike the TUN ingress whose
/// wire support is new enough to need `tun_wire_dial` gating.
///
/// `report_runtime_failure` is only called by the outer loop and only when
/// every wire on this uplink (primary + all fallbacks) has failed.
async fn acquire_udp_with_fallbacks(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    resume_store: &UdpResumeStore,
) -> Result<UdpSessionTransport> {
    let (transport, wire) = uplinks
        .dial_over_wires(candidate, TransportKind::Udp, true, |wire| async move {
            // Skip a fallback wire that has no UDP transport configured — not
            // a failure, it never ran a dial. The primary is always allowed
            // to attempt (its UDP shape is governed by the primary
            // supports_udp filter at the candidate level).
            if wire != 0 {
                let spec = WireSpec::of(&candidate.uplink, wire).ok_or_else(|| {
                    anyhow!("uplink {} has no wire {wire}", candidate.uplink.name)
                })?;
                if !spec.supports_udp() {
                    debug!(
                        uplink = %candidate.uplink.name,
                        wire,
                        "skipping wire with no UDP path configured",
                    );
                    return Ok(WireAttempt::NotApplicable);
                }
                // Resume-lookup metric, SS-fallback wires only — mirrors what
                // the hand-rolled fallback dial recorded before this loop
                // existed. `acquire_udp_on_wire` performs the same lookup
                // (and the store-back) internally as part of the dial; this
                // is a side-effect-free peek purely for the counter.
                if spec.transport == UplinkTransport::Ss {
                    let resume_key = uplinks.resume_cache_key_for(&candidate.uplink.name, "udp");
                    let hit = resume_store.ss().get(&resume_key).is_some();
                    metrics::record_resume_lookup(
                        "udp",
                        if uplinks.shared_resume() { "group" } else { "uplink" },
                        if hit { "hit" } else { "miss" },
                    );
                }
            }
            let source = if wire == 0 { "socks_udp" } else { "socks_udp_fb" };
            uplinks
                .acquire_udp_on_wire(candidate, wire, source, resume_store)
                .await
                .map(WireAttempt::Built)
        })
        .await?;

    // The success log lives in `dial_over_wires` — one line for both ingresses
    // rather than one there and one here. Only the metric is ours.
    if wire != 0 {
        outline_metrics::record_uplink_selected(
            "udp",
            uplinks.group_name(),
            &candidate.uplink.name,
        );
    }
    Ok(transport)
}

pub(super) async fn select_udp_transport(
    uplinks: &UplinkManager,
    target: Option<&TargetAddr>,
    client: Option<&str>,
    resume_store: &UdpResumeStore,
) -> Result<ActiveUdpTransport> {
    let mut last_error = None;
    let strict_transport = uplinks.strict_active_uplink_for(TransportKind::Udp);
    let mut candidates = uplinks.udp_candidates_for(target, client).await;
    if strict_transport {
        candidates.truncate(1);
    }
    for candidate in candidates {
        match acquire_udp_with_fallbacks(uplinks, &candidate, resume_store).await {
            Ok(transport) => {
                uplinks
                    .confirm_selected_uplink_for(
                        TransportKind::Udp,
                        target,
                        client,
                        candidate.index,
                    )
                    .await;
                // Install the carrier control-signal handler so a server
                // downstream-throttle notice on this UDP carrier penalises the
                // uplink and migrates traffic away. No-op unless the client
                // opted in; ignored by every non-padded datagram transport.
                let transport =
                    transport.with_throttle_handle(outline_uplink::dial::throttle_handle(
                        uplinks,
                        candidate.index,
                        TransportKind::Udp,
                    ));
                return Ok(ActiveUdpTransport {
                    index: candidate.index,
                    uplink_name: Arc::from(candidate.uplink.name.as_str()),
                    up_counters: metrics::udp_flow_counters(
                        "up",
                        uplinks.group_name(),
                        candidate.uplink.name.as_str(),
                    ),
                    transport: Arc::new(transport),
                });
            },
            Err(error) => {
                uplinks
                    .report_runtime_failure(candidate.index, TransportKind::Udp, &error)
                    .await;
                last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
            },
        }
    }

    Err(anyhow!(
        "all UDP uplinks failed: {}",
        last_error.unwrap_or_else(|| "no UDP-capable uplinks available".to_string())
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn failover_udp_transport(
    uplinks: &UplinkManager,
    active_transport: &ArcSwap<ActiveUdpTransport>,
    target: Option<&TargetAddr>,
    client: Option<&str>,
    failed_index: usize,
    error: anyhow::Error,
    resume_store: &UdpResumeStore,
) -> Result<ActiveUdpTransport> {
    let failed_uplink_name = {
        let active = active_transport.load();
        if active.index != failed_index {
            return Ok((**active).clone());
        }
        active.uplink_name.clone()
    };
    uplinks
        .report_runtime_failure(failed_index, TransportKind::Udp, &error)
        .await;
    let replacement = select_udp_transport(uplinks, target, client, resume_store).await?;
    if let Some(previous_transport) =
        replace_active_udp_transport_if_current(active_transport, failed_index, replacement.clone())
    {
        info!(
            failed_index,
            failed_uplink = %failed_uplink_name,
            new_uplink = %replacement.uplink_name,
            error = %format!("{error:#}"),
            "runtime UDP failover activated"
        );
        metrics::record_failover(
            "udp",
            uplinks.group_name(),
            &failed_uplink_name,
            &replacement.uplink_name,
        );
        metrics::record_uplink_selected("udp", uplinks.group_name(), &replacement.uplink_name);
        close_udp_transport(previous_transport, "failover").await;
        return Ok(replacement);
    }
    Ok((**active_transport.load()).clone())
}

pub(super) async fn reconcile_global_udp_transport(
    uplinks: &UplinkManager,
    active_transport: &ArcSwap<ActiveUdpTransport>,
    target: Option<&TargetAddr>,
    resume_store: &UdpResumeStore,
) -> Result<()> {
    if !uplinks.strict_active_uplink_for(TransportKind::Udp) {
        return Ok(());
    }

    let selected = active_transport.load().index;
    // Fast path: compare against the lock-free snapshot the manager publishes on
    // every active-uplink mutation. This runs per datagram in strict scopes, and
    // the datagram that finds a switch is the rare one — taking the manager's
    // async RwLock on every packet just to learn "still the same uplink" is what
    // this pre-check exists to avoid. The authoritative read below still gates
    // the actual switch, so a snapshot that has not been published yet only
    // delays reconciliation to the next datagram (or to the downlink task, which
    // is woken by the very same watch channel).
    let snapshot_active = uplinks
        .active_uplinks_snapshot()
        .udp_for(uplinks.strict_global_active_uplink());
    if snapshot_active == Some(selected) || snapshot_active.is_none() {
        return Ok(());
    }

    let current_active = uplinks.active_uplink_index_for_transport(TransportKind::Udp).await;
    if current_active == Some(selected) || current_active.is_none() {
        return Ok(());
    }

    let (replaced_uplink_name, previous_transport) = {
        let active = active_transport.load();
        if active.index != selected {
            return Ok(());
        }
        (active.uplink_name.clone(), Arc::clone(&active.transport))
    };

    // Retire the old carrier BEFORE dialling the new one, when — and only when —
    // this switch is one we mean to carry the session across.
    //
    // The server parks a datagram session only once its stream has closed
    // (`docs/SESSION-RESUMPTION.md` § Park sequence). Dialling first, as this
    // did, looked the association's id up against a still-live session, got
    // `miss-unknown`, and was handed a fresh upstream on a fresh source port —
    // so every strict repoint silently lost NAT continuity no matter how the
    // resume was configured. The park-before-resume barrier covers the rest of
    // the race once the close has started.
    //
    // On a drain the ordering is left alone: there is no resume to protect, and
    // closing first would hand the association a window with no carrier at all
    // if the replacement dial then failed.
    let migrating = uplinks
        .active_uplinks_snapshot()
        .intent
        .migrates_live_flows(uplinks.shared_resume());
    if migrating {
        close_udp_transport(Arc::clone(&previous_transport), "global_switch_retire").await;
    }

    // Reconcile only runs in strict (active_passive) scopes — it early-returns
    // above otherwise — so the per-client key is never relevant here.
    let replacement = select_udp_transport(uplinks, target, None, resume_store).await?;
    if let Some(previous_transport) =
        replace_active_udp_transport_if_current(active_transport, selected, replacement.clone())
    {
        metrics::record_failover(
            "udp",
            uplinks.group_name(),
            &replaced_uplink_name,
            &replacement.uplink_name,
        );
        metrics::record_uplink_selected("udp", uplinks.group_name(), &replacement.uplink_name);
        // Already closed above on a migrating switch; `close` is idempotent, so
        // this is a no-op there rather than a second teardown.
        close_udp_transport(previous_transport, "global_switch").await;
    }
    Ok(())
}

/// Atomically swap in `replacement` iff the current snapshot still has
/// `expected_index`. Returns the previous transport handle on success so the
/// caller can close it; returns `None` if some other task already replaced the
/// active transport (the freshly built `replacement` is dropped — its reader
/// will be torn down via the transport's own Drop / close path).
pub(super) fn replace_active_udp_transport_if_current(
    active_transport: &ArcSwap<ActiveUdpTransport>,
    expected_index: usize,
    replacement: ActiveUdpTransport,
) -> Option<Arc<UdpSessionTransport>> {
    let current = active_transport.load_full();
    if current.index != expected_index {
        return None;
    }
    let new_arc = Arc::new(replacement);
    let prev = active_transport.compare_and_swap(&current, Arc::clone(&new_arc));
    if Arc::ptr_eq(&prev, &current) {
        Some(Arc::clone(&current.transport))
    } else {
        None
    }
}

pub(super) async fn close_active_udp_transport(
    active_transport: &ArcSwap<ActiveUdpTransport>,
    reason: &'static str,
) {
    let transport = Arc::clone(&active_transport.load().transport);
    close_udp_transport(transport, reason).await;
}

async fn close_udp_transport(transport: Arc<UdpSessionTransport>, reason: &'static str) {
    if let Err(error) = transport.close().await {
        debug!(
            reason,
            error = %format!("{error:#}"),
            "failed to close SOCKS5 UDP transport"
        );
    }
}

#[cfg(test)]
#[path = "tests/transport.rs"]
mod tests;
