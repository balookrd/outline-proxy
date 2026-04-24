use std::sync::Arc;

use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use tracing::{debug, info};

use outline_metrics as metrics;
use socks5_proto::TargetAddr;
use outline_transport::UdpSessionTransport;
use outline_uplink::{TransportKind, UplinkManager};

#[derive(Clone)]
pub(super) struct ActiveUdpTransport {
    pub(super) index: usize,
    pub(super) uplink_name: Arc<str>,
    pub(super) transport: Arc<UdpSessionTransport>,
}

pub(super) async fn select_udp_transport(
    uplinks: &UplinkManager,
    target: Option<&TargetAddr>,
) -> Result<ActiveUdpTransport> {
    let mut last_error = None;
    let strict_transport = uplinks.strict_active_uplink_for(TransportKind::Udp);
    let candidates = uplinks.udp_candidates(target).await;
    let iter = if strict_transport {
        candidates.into_iter().take(1).collect::<Vec<_>>()
    } else {
        candidates
    };
    for candidate in iter {
        match uplinks.acquire_udp_standby_or_connect(&candidate, "socks_udp").await {
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
mod tests {
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use tokio::net::UdpSocket;

    use outline_transport::{UdpSessionTransport, UdpWsTransport};
    use shadowsocks_crypto::CipherKind;

    use super::*;

    #[tokio::test]
    async fn replacing_active_udp_transport_closes_previous_reader() {
        let old_transport = Arc::new(UdpSessionTransport::Ss(
            UdpWsTransport::from_socket(
                UdpSocket::bind(("127.0.0.1", 0)).await.unwrap(),
                CipherKind::Chacha20IetfPoly1305,
                "password",
                "test_old",
            )
            .unwrap(),
        ));
        let new_transport = Arc::new(UdpSessionTransport::Ss(
            UdpWsTransport::from_socket(
                UdpSocket::bind(("127.0.0.1", 0)).await.unwrap(),
                CipherKind::Chacha20IetfPoly1305,
                "password",
                "test_new",
            )
            .unwrap(),
        ));
        let active_transport = ArcSwap::from_pointee(ActiveUdpTransport {
            index: 1,
            uplink_name: Arc::from("old"),
            transport: Arc::clone(&old_transport),
        });

        let reader_transport = Arc::clone(&old_transport);
        let read_task = tokio::spawn(async move { reader_transport.read_packet().await });

        let previous_transport = replace_active_udp_transport_if_current(
            &active_transport,
            1,
            ActiveUdpTransport {
                index: 2,
                uplink_name: Arc::from("new"),
                transport: Arc::clone(&new_transport),
            },
        )
        .expect("active transport should be replaced");
        close_udp_transport(previous_transport, "test_replace").await;

        let error = tokio::time::timeout(Duration::from_secs(1), async {
            read_task.await.unwrap().unwrap_err()
        })
        .await
        .unwrap();
        assert!(format!("{error:#}").contains("udp transport closed"));
        assert_eq!(active_transport.load().index, 2);
    }
}
