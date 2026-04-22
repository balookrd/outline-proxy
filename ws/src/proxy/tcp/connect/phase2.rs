use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tracing::debug;

use outline_metrics as metrics;
use outline_transport::TcpWriter;
use shadowsocks_crypto::SHADOWSOCKS_MAX_PAYLOAD;

use outline_uplink::{TransportKind, UplinkManager};

use super::super::failover::ActiveTcpUplink;
use super::super::session::{IdleGuard, UplinkOutcome, drive_tcp_session_tasks};
use crate::client_io::ClientIo;
use crate::proxy::TcpTimeouts;

enum UplinkIo {
    ClientRead(usize),
    KeepaliveSent,
}

async fn read_client_or_keepalive<R: AsyncRead + Unpin>(
    client_read: &mut R,
    buf: &mut [u8],
    keepalive_interval: Option<Duration>,
    writer: &mut TcpWriter,
) -> Result<UplinkIo> {
    if let Some(interval) = keepalive_interval {
        tokio::select! {
            result = client_read.read(buf) => {
                Ok(UplinkIo::ClientRead(result.map_err(ClientIo::ReadFailed)?))
            }
            _ = tokio::time::sleep(interval) => {
                writer
                    .send_keepalive()
                    .await
                    .context("upstream TCP keepalive failed")?;
                Ok(UplinkIo::KeepaliveSent)
            }
        }
    } else {
        Ok(UplinkIo::ClientRead(client_read.read(buf).await.map_err(ClientIo::ReadFailed)?))
    }
}

/// Drives the long-lived bidirectional relay between the SOCKS client and the
/// pinned upstream after phase 1 has completed successfully.
///
/// Spawns an uplink task (client→upstream) and a downlink task
/// (upstream→client), wires them through an idle watcher, and reports any
/// mid-stream transport failures back to the uplink manager so that broken
/// transports trigger the H3→H2 downgrade and flush stale standby connections
/// promptly.
pub(super) async fn run_relay(
    uplinks: UplinkManager,
    active: ActiveTcpUplink,
    target_label: Arc<str>,
    first_chunk: Vec<u8>,
    mut client_read: OwnedReadHalf,
    mut client_write: OwnedWriteHalf,
    timeouts: &TcpTimeouts,
) -> Result<()> {
    // Once phase 1 completed and we received the first upstream bytes, this
    // SOCKS TCP session is pinned to the uplink that completed setup.
    // Strict active-uplink reselection only affects new sessions and
    // chunk-0 failover; established TCP tunnels are not migrated
    // transparently and should only end on a real transport error.
    let active_index = active.index;
    let active_name = active.name;
    let mut writer = active.writer;
    let mut reader = active.reader;

    // Idle-watcher activity channel: each data task signals a token after
    // every successful non-keepalive payload transfer.  Keepalive frames
    // deliberately do NOT signal activity — they only prove the local
    // WebSocket writer task is alive, not that the upstream server is
    // still reading, so counting them would defeat the watcher.
    let (activity_tx, activity_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let activity_for_uplink = activity_tx.clone();
    let activity_for_downlink = activity_tx.clone();
    // Drop the original handle so the channel closes naturally once both
    // data tasks finish and drop their clones.
    drop(activity_tx);

    let name_for_uplink_task = Arc::clone(&active_name);
    let manager_for_uplink_task = uplinks.clone();
    let keepalive_interval = uplinks.load_balancing().tcp_active_keepalive_interval;
    let uplink = async move {
        let mut buf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];
        let mut chunks_sent: u64 = 0;
        loop {
            // When a keepalive interval is set, race the client read against
            // a sleep timer.  If the timer fires first we send a Shadowsocks
            // keepalive frame (no-op for SS1, 0-length encrypted chunk for
            // SS2022) and loop immediately with a fresh timer.  This defeats
            // upstream proxy / NAT idle-timeout disconnections that otherwise
            // kill long-lived sessions (SSH, etc.) after ~25–30 s of silence,
            // but they must NOT reset `socks_upstream_idle`: only real payload
            // bytes count as session activity.
            let read = match read_client_or_keepalive(
                &mut client_read,
                &mut buf,
                keepalive_interval,
                &mut writer,
            )
            .await?
            {
                UplinkIo::ClientRead(read) => read,
                UplinkIo::KeepaliveSent => continue,
            };
            if read == 0 {
                // Client-side EOF.  Signal the upstream that we will not
                // send any more data (for WebSocket transport this emits a
                // Close frame; for a direct socket this half-closes the TCP
                // write side) and exit the uplink task.  The downlink task
                // is *not* aborted here: the server may still have in-flight
                // bytes to deliver — e.g. an SSH server sending its final
                // response after the client-side TUN/SOCKS5 layer half-
                // closed the flow — and tearing the upstream down eagerly
                // would truncate them and kill long-lived sessions the
                // moment the TUN hits its own idle timeout.  The downlink
                // will finish naturally once the server echoes our close.
                debug!(
                    uplink = %name_for_uplink_task,
                    transport_supports_tcp_half_close = writer.supports_half_close(),
                    "client closed SOCKS TCP session; initiating upstream half-close and awaiting downlink"
                );
                writer.close().await?;
                break;
            }
            metrics::add_bytes(
                "tcp",
                "client_to_upstream",
                manager_for_uplink_task.group_name(),
                &name_for_uplink_task,
                read,
            );
            writer.send_chunk(&buf[..read]).await?;
            let _ = activity_for_uplink.send(());
            chunks_sent += 1;
            if chunks_sent == 1 {
                debug!(uplink = %name_for_uplink_task, "first chunk sent to upstream");
            }
            manager_for_uplink_task
                .report_active_traffic(active_index, TransportKind::Tcp)
                .await;
        }
        Ok::<UplinkOutcome, anyhow::Error>(UplinkOutcome::Finished)
    };

    let name_for_downlink_task = Arc::clone(&active_name);
    let manager_for_downlink_task = uplinks.clone();
    let downlink = async move {
        metrics::add_bytes(
            "tcp",
            "upstream_to_client",
            manager_for_downlink_task.group_name(),
            &name_for_downlink_task,
            first_chunk.len(),
        );
        client_write
            .write_all(&first_chunk)
            .await
            .map_err(ClientIo::WriteFailed)?;
        let _ = activity_for_downlink.send(());
        manager_for_downlink_task
            .report_active_traffic(active_index, TransportKind::Tcp)
            .await;

        let mut chunks_forwarded: u64 = 1;
        loop {
            let chunk = match reader.read_chunk().await {
                Ok(chunk) => chunk,
                Err(_err) if reader.closed_cleanly() => {
                    if chunks_forwarded == 0 {
                        debug!(
                            uplink = %name_for_downlink_task,
                            "upstream closed before sending any data"
                        );
                    }
                    break;
                },
                Err(err) => return Err(err),
            };
            if chunk.is_empty() {
                // An empty decrypted payload is not valid in Shadowsocks;
                // treat it as EOF rather than busy-looping without any await.
                break;
            }
            chunks_forwarded += 1;
            metrics::add_bytes(
                "tcp",
                "upstream_to_client",
                manager_for_downlink_task.group_name(),
                &name_for_downlink_task,
                chunk.len(),
            );
            client_write.write_all(&chunk).await.map_err(ClientIo::WriteFailed)?;
            let _ = activity_for_downlink.send(());
            manager_for_downlink_task
                .report_active_traffic(active_index, TransportKind::Tcp)
                .await;
        }
        client_write.shutdown().await.context("client shutdown failed")?;
        Ok::<(), anyhow::Error>(())
    };

    // Preserve client half-close semantics (client EOF while still waiting
    // for the response), but do not keep the upstream transport alive after
    // the server side has already closed cleanly.
    let result = drive_tcp_session_tasks(
        uplink,
        downlink,
        Some(IdleGuard::new(activity_rx, timeouts.socks_upstream_idle)),
        target_label,
        timeouts.post_client_eof_downstream,
    )
    .await;

    // Report mid-stream upstream transport failures so that broken transports
    // (e.g. H3 APPLICATION_CLOSE received after session establishment) trigger
    // the H3→H2 downgrade and flush stale warm-standby connections
    // immediately, rather than waiting for the next connection attempt to fail.
    // Client-side disconnects and intentional uplink switches are excluded.
    if let Err(ref err) = result {
        if crate::disconnect::is_upstream_runtime_failure(err) {
            uplinks
                .report_runtime_failure(active_index, TransportKind::Tcp, err)
                .await;
        } else if crate::disconnect::is_ws_closed(err) {
            // The upstream server closed the WebSocket connection
            // mid-stream (server-initiated close, not a client
            // disconnect).  We do not set a full runtime-failure
            // cooldown to avoid penalising the uplink for normal
            // per-connection lifetime limits, but we clear the
            // activity timestamp so the probe is not skipped on the
            // next cycle — this lets the probe detect a downed server
            // promptly rather than waiting for probe.interval of silence.
            uplinks.report_upstream_close(active_index, TransportKind::Tcp).await;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use outline_transport::{
        ServerAddr, TcpReader, TcpShadowsocksReader, TcpShadowsocksWriter, UpstreamTransportGuard,
    };
    use outline_uplink::{
        CipherKind, LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, TargetAddr,
        UplinkCandidate, UplinkConfig, UplinkTransport, WsProbeConfig, WsTransportMode,
    };
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    use crate::proxy::tcp::failover::TcpUplinkSource;

    fn probe_disabled() -> ProbeConfig {
        ProbeConfig {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            max_concurrent: 1,
            max_dials: 1,
            min_failures: 1,
            attempts: 1,
            ws: WsProbeConfig { enabled: false },
            http: None,
            dns: None,
            tcp: None,
        }
    }

    fn lb(keepalive_interval: Duration) -> LoadBalancingConfig {
        LoadBalancingConfig {
            mode: LoadBalancingMode::ActiveActive,
            routing_scope: RoutingScope::PerFlow,
            sticky_ttl: Duration::from_secs(300),
            hysteresis: Duration::from_millis(50),
            failure_cooldown: Duration::from_secs(10),
            tcp_chunk0_failover_timeout: Duration::from_secs(10),
            warm_standby_tcp: 0,
            warm_standby_udp: 0,
            rtt_ewma_alpha: 0.25,
            failure_penalty: Duration::from_millis(500),
            failure_penalty_max: Duration::from_secs(30),
            failure_penalty_halflife: Duration::from_secs(60),
            h3_downgrade_duration: Duration::from_secs(60),
            udp_ws_keepalive_interval: None,
            tcp_ws_standby_keepalive_interval: None,
            tcp_active_keepalive_interval: Some(keepalive_interval),
            auto_failback: false,
        }
    }

    fn make_uplink(name: &str, addr: SocketAddr) -> UplinkConfig {
        UplinkConfig {
            name: name.to_string(),
            transport: UplinkTransport::Shadowsocks,
            tcp_ws_url: None,
            tcp_ws_mode: WsTransportMode::Http1,
            udp_ws_url: None,
            udp_ws_mode: WsTransportMode::Http1,
            tcp_addr: Some(addr.to_string().parse::<ServerAddr>().unwrap()),
            udp_addr: None,
            cipher: CipherKind::Chacha20IetfPoly1305,
            password: "secret".to_string(),
            weight: 1.0,
            fwmark: None,
            ipv6_first: false,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn run_relay_keepalive_does_not_extend_idle_timeout() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (_stream, _) = upstream_listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });

        let uplink = make_uplink("primary", upstream_addr);
        let manager = UplinkManager::new_for_test(
            "test",
            vec![uplink.clone()],
            probe_disabled(),
            lb(Duration::from_millis(20)),
        )
        .unwrap();

        let stream = TcpStream::connect(upstream_addr).await.unwrap();
        let (reader_half, writer_half) = stream.into_split();
        let master_key = uplink.cipher.derive_master_key(&uplink.password).unwrap();
        let lifetime = UpstreamTransportGuard::new("test", "tcp");
        let mut writer = TcpShadowsocksWriter::connect_socket(
            writer_half,
            uplink.cipher,
            &master_key,
            Arc::clone(&lifetime),
        )
        .unwrap();
        let reader =
            TcpShadowsocksReader::new_socket(reader_half, uplink.cipher, &master_key, lifetime)
                .with_request_salt(writer.request_salt());
        writer
            .send_chunk(&TargetAddr::IpV4(Ipv4Addr::LOCALHOST, 443).to_wire_bytes().unwrap())
            .await
            .unwrap();
        let active = ActiveTcpUplink {
            index: 0,
            name: Arc::from(uplink.name.as_str()),
            candidate: UplinkCandidate { index: 0, uplink: uplink.into() },
            writer: TcpWriter::Socket(writer),
            reader: TcpReader::Socket(reader),
            source: TcpUplinkSource::DirectSocket,
        };

        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let (connect_res, accept_res) =
            tokio::join!(TcpStream::connect(client_addr), client_listener.accept());
        let mut client_side = connect_res.unwrap();
        let (server_side, _) = accept_res.unwrap();
        let (client_read, client_write) = server_side.into_split();

        let timeouts = TcpTimeouts {
            post_client_eof_downstream: Duration::from_secs(30),
            upstream_response: Duration::from_secs(15),
            socks_upstream_idle: Duration::from_millis(50),
            direct_idle: Duration::from_secs(120),
        };
        let relay_task = tokio::spawn(async move {
            run_relay(
                manager,
                active,
                Arc::from("test"),
                b"OK".to_vec(),
                client_read,
                client_write,
                &timeouts,
            )
            .await
        });

        let mut first_chunk = [0u8; 2];
        client_side.read_exact(&mut first_chunk).await.unwrap();
        assert_eq!(&first_chunk, b"OK");

        tokio::time::advance(timeouts.socks_upstream_idle + Duration::from_millis(10)).await;
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }

        assert!(
            relay_task.is_finished(),
            "relay should exit once socks_upstream_idle elapses without payload"
        );
        let result = relay_task.await.unwrap();
        assert!(result.is_ok(), "idle timeout should close the session cleanly");

        upstream_task.abort();
        let _ = upstream_task.await;
    }
}
