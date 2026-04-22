mod attribution;
mod failover_step;
mod first_chunk;
mod phase1;
mod phase2;
mod replay;
mod retry;

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use tokio::net::TcpStream;
use tracing::{debug, info};

use outline_metrics as metrics;
use socks5_proto::{
    SOCKS_STATUS_NOT_ALLOWED, SOCKS_STATUS_SUCCESS, TargetAddr, send_reply, socket_addr_to_target,
};

use outline_uplink::TransportKind;

use super::super::Route;
use super::direct::relay_tcp_direct;
use super::failover::{ActiveTcpUplink, connect_tcp_uplink};
use crate::proxy::TcpTimeouts;

use phase1::try_uplinks;
use phase2::run_relay;
use replay::ReplayBufState;

pub async fn serve_tcp_connect(
    mut client: TcpStream,
    dispatch: Route,
    target: TargetAddr,
    dns_cache: Arc<outline_transport::DnsCache>,
    timeouts: TcpTimeouts,
) -> Result<()> {
    let uplinks = match dispatch {
        Route::Direct { fwmark } => {
            info!(target = %target, "TCP route: direct connection");
            return relay_tcp_direct(client, target, fwmark, &dns_cache, timeouts).await;
        }
        Route::Drop => {
            info!(target = %target, "TCP route: policy drop");
            return reject_tcp_connection(client, &target).await;
        }
        Route::Group { name, manager } => {
            debug!(target = %target, group = %name, "TCP route: dispatching via group");
            manager
        }
    };

    let session = metrics::track_session("tcp");
    let result = async {
        // ── Initial uplink selection ─────────────────────────────────────────
        let mut last_error = None;
        let mut selected = None;
        let strict_transport = uplinks.strict_active_uplink_for(TransportKind::Tcp);
        let chunk0_attempt_timeout = uplinks.load_balancing().tcp_chunk0_failover_timeout;
        let mut tried_indexes = HashSet::new();
        loop {
            let candidates = uplinks.tcp_candidates(&target).await;
            let iter = if strict_transport {
                candidates.into_iter().take(1).collect::<Vec<_>>()
            } else {
                candidates
            };
            if iter.is_empty() {
                break;
            }
            let mut progressed = false;
            for candidate in iter {
                if strict_transport && !tried_indexes.insert(candidate.index) {
                    continue;
                }
                progressed = true;
                match connect_tcp_uplink(&uplinks, &candidate, &target).await {
                    Ok(connected) => {
                        selected = Some((candidate, connected));
                        break;
                    }
                    Err(error) => {
                        uplinks
                            .report_runtime_failure(candidate.index, TransportKind::Tcp, &error)
                            .await;
                        last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
                    }
                }
            }
            if selected.is_some() || !strict_transport || !progressed {
                break;
            }
        }

        let (candidate, connected) = selected.ok_or_else(|| {
            anyhow!(
                "all TCP uplinks failed: {}",
                last_error.unwrap_or_else(|| "no uplinks available".to_string())
            )
        })?;
        let mut active = ActiveTcpUplink::new(candidate.clone(), connected);
        uplinks
            .confirm_selected_uplink(TransportKind::Tcp, Some(&target), active.index)
            .await;
        metrics::record_uplink_selected("tcp", uplinks.group_name(), &active.name);
        info!(
            uplink = %active.name,
            weight = candidate.uplink.weight,
            target = %target,
            "selected TCP uplink"
        );

        let bound_addr = socket_addr_to_target(client.local_addr()?);
        send_reply(&mut client, SOCKS_STATUS_SUCCESS, &bound_addr).await?;

        let (mut client_read, mut client_write) = client.into_split();
        let mut replay = ReplayBufState::new();

        // ── Phase 1: chunk-0 failover ────────────────────────────────────────
        let first_chunk = match try_uplinks(
            &uplinks,
            &mut active,
            &target,
            strict_transport,
            &mut tried_indexes,
            chunk0_attempt_timeout,
            &timeouts,
            &mut client_read,
            &mut client_write,
            &mut replay,
        )
        .await?
        {
            Some(chunk) => chunk,
            None => return Ok(()),
        };

        // Phase-1 replay buffer is no longer needed; release memory before
        // the long-lived phase-2 tasks take over.
        drop(replay);

        // ── Phase 2: bidirectional relay ─────────────────────────────────────
        let target_label: Arc<str> = Arc::from(target.to_string());
        run_relay(
            uplinks,
            active,
            target_label,
            first_chunk,
            client_read,
            client_write,
            &timeouts,
        )
        .await
    }
    .await;

    session.finish(result.is_ok());
    result
}

/// Send a SOCKS5 reply with REP=0x02 (connection not allowed by ruleset) and
/// close the client connection. Used when a matched route has `via = "drop"`.
async fn reject_tcp_connection(mut client: TcpStream, target: &TargetAddr) -> Result<()> {
    let bound_addr = socket_addr_to_target(client.local_addr()?);
    send_reply(&mut client, SOCKS_STATUS_NOT_ALLOWED, &bound_addr).await?;
    debug!(target = %target, "TCP route: drop reply sent");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// `reject_tcp_connection` must send a SOCKS5 REP=0x02 (not allowed) reply and
    /// return `Ok(())` without forwarding any data.
    #[tokio::test]
    async fn reject_tcp_connection_sends_not_allowed_reply() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect_fut = tokio::net::TcpStream::connect(addr);
        let accept_fut = listener.accept();
        let (connect_res, accept_res) = tokio::join!(connect_fut, accept_fut);
        let mut client_side = connect_res.unwrap();
        let (server_side, _) = accept_res.unwrap();

        let target = TargetAddr::IpV4("1.2.3.4".parse().unwrap(), 80);
        reject_tcp_connection(server_side, &target).await.unwrap();

        // SOCKS5 reply: VER REP RSV ATYP(IPv4) ADDR(4) PORT(2) = 10 bytes
        let mut reply = [0u8; 10];
        client_side.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 5, "VER must be 5");
        assert_eq!(reply[1], SOCKS_STATUS_NOT_ALLOWED, "REP must be 0x02 (not allowed)");
        assert_eq!(reply[2], 0, "RSV must be 0");
        assert_eq!(reply[3], 1, "ATYP must be 1 (IPv4)");
    }
}
