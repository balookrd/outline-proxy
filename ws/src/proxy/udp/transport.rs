use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
use tracing::{debug, info, warn};

use outline_metrics as metrics;
use socks5_proto::TargetAddr;
use outline_transport::{
    UdpSessionTransport, UdpWsTransport, connect_shadowsocks_udp_with_source,
    connect_websocket_with_source,
};
use outline_uplink::{
    FallbackTransport, TransportKind, UplinkCandidate, UplinkManager, UplinkTransport,
};

#[derive(Clone)]
pub(super) struct ActiveUdpTransport {
    pub(super) index: usize,
    pub(super) uplink_name: Arc<str>,
    pub(super) transport: Arc<UdpSessionTransport>,
}

/// Acquire a UDP transport for `candidate`, falling back to each configured
/// `[[outline.uplinks.fallbacks]]` entry on the same uplink when the primary
/// dial fails. Mirrors the TCP fallback path: `report_runtime_failure` is
/// only called by the outer loop and only when every wire on this uplink
/// (primary + all fallbacks) has failed.
///
/// VLESS as a *fallback* is not yet supported on UDP — the QUIC-mux factory
/// in `acquire_udp_standby_or_connect` is keyed on the parent's uplink
/// index/state, and reusing that machinery for a fallback wire requires
/// Phase-2 active-wire plumbing. A VLESS fallback entry surfaces a clear
/// error here in this iteration; SS and WS UDP fallbacks work today.
async fn acquire_udp_with_fallbacks(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
) -> Result<UdpSessionTransport> {
    let primary_err = match uplinks.acquire_udp_standby_or_connect(candidate, "socks_udp").await {
        Ok(transport) => return Ok(transport),
        Err(error) => {
            if candidate.uplink.fallbacks.is_empty() {
                return Err(error);
            }
            error
        },
    };

    warn!(
        uplink = %candidate.uplink.name,
        primary_transport = %candidate.uplink.transport,
        fallbacks = candidate.uplink.fallbacks.len(),
        error = %format!("{primary_err:#}"),
        "UDP primary dial failed; trying configured fallbacks on same uplink",
    );

    let mut last_err = primary_err;
    for (idx, fallback) in candidate.uplink.fallbacks.iter().enumerate() {
        if !fallback.supports_udp() {
            // Skip fallbacks whose configured wire-shape doesn't expose a UDP
            // path (e.g. WS fallback without `udp_ws_url`). Not an error per
            // se — UDP-only sessions just don't see this wire.
            continue;
        }
        match dial_udp_fallback(uplinks, candidate, fallback).await {
            Ok(transport) => {
                outline_metrics::record_uplink_selected(
                    "udp",
                    uplinks.group_name(),
                    &candidate.uplink.name,
                );
                debug!(
                    uplink = %candidate.uplink.name,
                    fallback_index = idx,
                    fallback_transport = %fallback.transport,
                    "UDP fallback dial succeeded",
                );
                return Ok(transport);
            },
            Err(error) => {
                warn!(
                    uplink = %candidate.uplink.name,
                    fallback_index = idx,
                    fallback_transport = %fallback.transport,
                    error = %format!("{error:#}"),
                    "UDP fallback dial failed",
                );
                last_err = error.context(format!(
                    "uplink {} fallback[{idx}] (transport={}) failed",
                    candidate.uplink.name, fallback.transport,
                ));
            },
        }
    }
    Err(last_err.context(format!(
        "uplink {}: primary and all UDP-capable fallback(s) failed",
        candidate.uplink.name,
    )))
}

async fn dial_udp_fallback(
    uplinks: &UplinkManager,
    parent: &UplinkCandidate,
    fallback: &FallbackTransport,
) -> Result<UdpSessionTransport> {
    let cache = uplinks.dns_cache();
    let source = "socks_udp_fb";

    match fallback.transport {
        UplinkTransport::Shadowsocks => {
            let addr = fallback.udp_addr.as_ref().ok_or_else(|| {
                anyhow!(
                    "uplink {} fallback (transport=shadowsocks) missing udp_addr",
                    parent.uplink.name,
                )
            })?;
            let socket = connect_shadowsocks_udp_with_source(
                cache,
                addr,
                fallback.fwmark,
                fallback.ipv6_first,
                source,
            )
            .await
            .with_context(|| format!("fallback udp dial to {addr} failed"))?;
            UdpWsTransport::from_socket(socket, fallback.cipher, &fallback.password, source)
                .map(UdpSessionTransport::Ss)
        },
        UplinkTransport::Ws => {
            let url = fallback.udp_ws_url.as_ref().ok_or_else(|| {
                anyhow!(
                    "uplink {} fallback (transport=ws) missing udp_ws_url",
                    parent.uplink.name,
                )
            })?;
            let mode = fallback.udp_dial_mode();
            let ws = connect_websocket_with_source(
                cache,
                url,
                mode,
                fallback.fwmark,
                fallback.ipv6_first,
                source,
            )
            .await
            .with_context(|| format!("fallback ws dial to {url} failed"))?;
            let keepalive = uplinks.load_balancing().udp_ws_keepalive_interval;
            UdpWsTransport::from_websocket(ws, fallback.cipher, &fallback.password, source, keepalive)
                .map(UdpSessionTransport::Ss)
        },
        UplinkTransport::Vless => {
            // Phase 2: VLESS UDP fallback needs the QUIC mux + WS fallback
            // factory machinery from `acquire_udp_standby_or_connect`, which
            // currently keys all per-uplink hooks on `candidate.index`. Wiring
            // those hooks for a fallback wire requires the active-wire state
            // landed in Phase 2.
            bail!(
                "uplink {}: VLESS-as-fallback on UDP is not supported yet (use SS or WS for the UDP fallback)",
                parent.uplink.name,
            )
        },
    }
}

pub(super) async fn select_udp_transport(
    uplinks: &UplinkManager,
    target: Option<&TargetAddr>,
) -> Result<ActiveUdpTransport> {
    let mut last_error = None;
    let strict_transport = uplinks.strict_active_uplink_for(TransportKind::Udp);
    let mut candidates = uplinks.udp_candidates(target).await;
    if strict_transport {
        candidates.truncate(1);
    }
    for candidate in candidates {
        match acquire_udp_with_fallbacks(uplinks, &candidate).await {
            Ok(transport) => {
                uplinks
                    .confirm_selected_uplink(TransportKind::Udp, target, candidate.index)
                    .await;
                return Ok(ActiveUdpTransport {
                    index: candidate.index,
                    uplink_name: Arc::from(candidate.uplink.name.as_str()),
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

pub(super) async fn failover_udp_transport(
    uplinks: &UplinkManager,
    active_transport: &ArcSwap<ActiveUdpTransport>,
    target: Option<&TargetAddr>,
    failed_index: usize,
    error: anyhow::Error,
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
    let replacement = select_udp_transport(uplinks, target).await?;
    if let Some(previous_transport) = replace_active_udp_transport_if_current(
        active_transport,
        failed_index,
        replacement.clone(),
    ) {
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
        metrics::record_uplink_selected(
            "udp",
            uplinks.group_name(),
            &replacement.uplink_name,
        );
        close_udp_transport(previous_transport, "failover").await;
        return Ok(replacement);
    }
    Ok((**active_transport.load()).clone())
}

pub(super) async fn reconcile_global_udp_transport(
    uplinks: &UplinkManager,
    active_transport: &ArcSwap<ActiveUdpTransport>,
    target: Option<&TargetAddr>,
) -> Result<()> {
    if !uplinks.strict_active_uplink_for(TransportKind::Udp) {
        return Ok(());
    }

    let current_active = uplinks.active_uplink_index_for_transport(TransportKind::Udp).await;
    let selected = active_transport.load().index;
    if current_active == Some(selected) || current_active.is_none() {
        return Ok(());
    }

    let replaced_uplink_name = {
        let active = active_transport.load();
        if active.index != selected {
            return Ok(());
        }
        active.uplink_name.clone()
    };
    let replacement = select_udp_transport(uplinks, target).await?;
    if let Some(previous_transport) = replace_active_udp_transport_if_current(
        active_transport,
        selected,
        replacement.clone(),
    ) {
        metrics::record_failover(
            "udp",
            uplinks.group_name(),
            &replaced_uplink_name,
            &replacement.uplink_name,
        );
        metrics::record_uplink_selected(
            "udp",
            uplinks.group_name(),
            &replacement.uplink_name,
        );
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
