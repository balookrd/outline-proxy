//! Tests for the UDP flow-reader's stop classification.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::anyhow;
use outline_transport::WsClosed;
use shadowsocks_crypto::CryptoError;
use socks5_proto::TargetAddr;

use super::{ReaderStop, is_clean_ws_close};
use crate::udp::UdpFlowKey;
use crate::wire::IpVersion;

#[test]
fn bare_ws_closed_is_clean() {
    let err = anyhow::Error::from(WsClosed);
    assert!(
        is_clean_ws_close(&err),
        "a bare WsClosed marker must classify as a clean close, not a runtime failure",
    );
}

#[test]
fn ws_closed_under_context_is_clean() {
    // The reader propagates the read error up through `?`, which can layer
    // additional context on top of the typed marker. The chain walk must still
    // find `WsClosed` underneath — otherwise a routine close would be charged
    // as a data-plane failure the moment any context is added.
    let err = anyhow::Error::from(WsClosed).context("reading UDP downlink packet");
    assert!(
        is_clean_ws_close(&err),
        "WsClosed beneath a context layer must still classify as a clean close",
    );
}

#[test]
fn dirty_read_error_is_not_clean() {
    // A real transport error (e.g. the 1013 "front alive, back dead" close)
    // carries no WsClosed marker and MUST still escalate as a runtime failure.
    let err = anyhow!("websocket read failed: IO error: Invalid close code: 1013");
    assert!(
        !is_clean_ws_close(&err),
        "a genuine read error must NOT be suppressed as a clean close",
    );
}

#[test]
fn h3_no_error_reader_stop_classifies_as_clean_close() {
    let err = anyhow!(
        "websocket read failed: IO error: I/O error: Connection error: Remote error: ApplicationClose: H3_NO_ERROR"
    );
    let stop = ReaderStop::classify(&err);
    assert!(
        matches!(stop, ReaderStop::CleanClose),
        "an H3_NO_ERROR close must classify as clean close, got {stop:?}",
    );
    assert!(!stop.escalates_to_carrier());
    assert_eq!(stop.close_reason(), "closed");
}

#[test]
fn corrupt_datagram_stops_the_flow_without_charging_the_carrier() {
    // A payload the AEAD could not open says nothing about the carrier that
    // delivered it. The flow still goes away (its SS2022 replay state is now
    // out of step), but it must be closed as a payload error — escalating it
    // caps xhttp_h3 → xhttp_h2 for the whole uplink over a single datagram.
    let err = anyhow::Error::new(CryptoError::DecryptFailed { cipher: "aes-256-gcm" })
        .context("failed to read UDP downlink packet");
    let stop = ReaderStop::classify(&err);
    assert!(
        matches!(stop, ReaderStop::PayloadIntegrity("decrypt_failed")),
        "an AEAD open failure must classify as a payload error, got {stop:?}",
    );
    assert!(
        !stop.escalates_to_carrier(),
        "a payload error must not reach the uplink manager"
    );
    assert_eq!(stop.close_reason(), "payload_error");
}

#[test]
fn carrier_read_failure_still_escalates() {
    let err = anyhow!("websocket read failed: IO error: Invalid close code: 1013");
    let stop = ReaderStop::classify(&err);
    assert!(
        matches!(stop, ReaderStop::CarrierFailure),
        "a dirty read error must still classify as a carrier failure, got {stop:?}",
    );
    assert!(
        stop.escalates_to_carrier(),
        "a carrier failure must still reach the uplink manager"
    );
    assert_eq!(stop.close_reason(), "read_error");
}

#[test]
fn clean_ws_close_neither_escalates_nor_counts_as_payload_corruption() {
    let stop = ReaderStop::classify(&anyhow::Error::from(WsClosed));
    assert!(
        matches!(stop, ReaderStop::CleanClose),
        "a Close frame is routine lifecycle, got {stop:?}",
    );
    assert!(!stop.escalates_to_carrier());
    assert_eq!(stop.close_reason(), "closed");
}

#[test]
fn udp_response_sources_from_client_dialled_addr_across_family_mismatch() {
    // Regression: with QUIC/UDP destination override the exit can resolve the
    // sniffed domain to a *different family* than the client's flow. The exit
    // then tags its response with that (here IPv6) address. The reader must
    // still build the client reply from the IPv4 address the client dialled —
    // not bail with "unexpected response address family" and tear the flow down
    // (which killed QUIC video once IPv6 was disabled and everything fell to v4).
    let exit_v6 = TargetAddr::IpV6(Ipv6Addr::new(0x2a00, 0x1450, 0, 0, 0, 0, 0, 0x200e), 443);
    let mut payload = exit_v6.to_wire_bytes().unwrap();
    payload.extend_from_slice(b"VIDEO");

    let key = UdpFlowKey {
        version: IpVersion::V4,
        local_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        local_port: 50000,
        remote_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 1, 14)),
        remote_port: 443,
    };

    // Building straight from the exit's IPv6 address on an IPv4 flow is exactly
    // the bail the old reader hit.
    assert!(
        super::super::wire::build_response_packet(
            key.version,
            &exit_v6,
            key.local_ip,
            key.local_port,
            b"VIDEO",
        )
        .is_err(),
        "echoing the exit's mismatched-family address must fail to build",
    );

    // The fix sources the reply from the client-dialled IPv4 address, so the
    // packet builds and carries the payload regardless of the exit's family.
    let pkt = super::build_client_response_packet(&key, &payload).unwrap();
    assert_eq!(pkt[0] >> 4, 4, "must be an IPv4 packet (client's family)");
    assert!(pkt.ends_with(b"VIDEO"), "payload must follow the rewritten header");
}

struct TempTunCapture {
    path: std::path::PathBuf,
}

impl TempTunCapture {
    fn new() -> (crate::SharedTunWriter, Self) {
        let path =
            std::env::temp_dir().join(format!("outline-tun-udp-uso-{}.bin", rand::random::<u64>()));
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        (crate::SharedTunWriter::new(file), Self { path })
    }
}

impl Drop for TempTunCapture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn ss2022_server_packet(
    cipher: outline_uplink::CipherKind,
    master_key: &[u8],
    server_session_id: u64,
    packet_id: u64,
    client_session_id: u64,
    target_wire: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut plaintext = Vec::new();
    outline_wire::ss2022::write_udp_response_body(
        &mut plaintext,
        now,
        &client_session_id.to_be_bytes(),
        target_wire,
        payload,
    );
    let separate_header = outline_wire::ss2022::encode_udp_separate_header(
        &server_session_id.to_be_bytes(),
        packet_id,
    );
    let nonce = outline_wire::ss2022::udp_nonce_from_separate_header(&separate_header);
    let subkey =
        shadowsocks_crypto::derive_subkey(cipher, master_key, &separate_header[..8]).unwrap();
    let encrypted_header =
        shadowsocks_crypto::encrypt_udp_separate_header(cipher, master_key, &separate_header)
            .unwrap();

    let mut packet = Vec::new();
    packet.extend_from_slice(&encrypted_header);
    shadowsocks_crypto::encrypt_into(
        cipher,
        &subkey[..cipher.key_len()],
        &nonce,
        &plaintext,
        &mut packet,
    )
    .unwrap();
    packet
}

fn ss2022_test_uplink_manager(udp_ws_url: url::Url) -> outline_uplink::UplinkManager {
    use outline_uplink::{
        CipherKind, LoadBalancingConfig, LoadBalancingMode, OverflowPolicy, ProbeConfig,
        RoutingScope, TransportMode, UplinkConfig, UplinkManager, UplinkTransport,
        VlessUdpMuxLimits, WsProbeConfig,
    };
    use std::time::Duration;

    let uplink = UplinkConfig {
        name: "ss2022-uso".to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: None,
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(udp_ws_url),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        cipher: CipherKind::Aes256Gcm2022,
        password: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=".to_string(),
        weight: 1.0,
        fwmark: None,
        dscp: None,
        disable_udp_gso: false,
        ipv6_first: false,
        ipv4_only: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: Vec::new(),
        shuffle_wires: false,
        carrier_downgrade: true,
        padding: None,
        shuffle_timer: None,
    };
    let probe = ProbeConfig {
        interval: Duration::from_secs(30),
        timeout: Duration::from_secs(5),
        max_concurrent: 2,
        max_dials: 1,
        min_failures: 1,
        attempts: 1,
        skip_when_active: true,
        liveness_interval: Duration::from_secs(300),
        endpoint_check: false,
        endpoint_check_timeout: Duration::from_millis(2000),
        ws: WsProbeConfig { enabled: false },
        http: None,
        dns: None,
        tcp: None,
        tls: None,
    };
    let lb = LoadBalancingConfig {
        mode: LoadBalancingMode::ActiveActive,
        routing_scope: RoutingScope::PerFlow,
        shared_resume: false,
        sticky_ttl: Duration::from_secs(300),
        hysteresis: Duration::from_millis(50),
        failure_cooldown: Duration::from_secs(10),
        tcp_chunk0_failover_timeout: Duration::from_secs(10),
        warm_standby_tcp: 0,
        warm_standby_udp: 0,
        rtt_ewma_alpha: 0.3,
        rtt_ewma_halflife: Duration::from_secs(300),
        loss_latency_penalty_k: 0.0,
        loss_latency_inflation_max: 4.0,
        loss_sample_interval: Duration::from_secs(30),
        loss_sample_min_packets: 50,
        loss_ewma_alpha: 0.2,
        failure_penalty: Duration::from_millis(500),
        failure_penalty_max: Duration::from_secs(30),
        failure_penalty_halflife: Duration::from_secs(60),
        mode_downgrade_duration: Duration::from_secs(60),
        carrier_degraded_failover: None,
        loss_failover_ratio: 0.0,
        loss_failover_duration: None,
        runtime_failure_window: Duration::from_secs(60),
        chunk0_failure_window: Duration::from_secs(300),
        global_udp_strict_health: false,
        udp_ws_keepalive_interval: None,
        tcp_ws_keepalive_interval: None,
        tcp_ws_standby_keepalive_interval: None,
        tcp_active_keepalive_interval: None,
        warm_probe_keepalive_interval: None,
        auto_failback: false,
        health_weighted_selection: false,
        tun_wire_dial: false,
        health_weight_floor: 0.05,
        vless_udp_mux_limits: VlessUdpMuxLimits::default(),
        tcp_mid_session_retry_buffer_bytes: 256 * 1024,
        tcp_mid_session_retry_budget: 1,
        tcp_mid_session_retry_overflow_policy: OverflowPolicy::Soft,
        tcp_mid_session_retry_consume_timeout: Duration::from_secs(5),
        tcp_symmetric_replay_enabled: true,
        tcp_symmetric_replay_max_bytes: 1_048_576,
        tun_suppress_icmp_reply_when_down: false,
        tun_icmp_liveness_window: None,
        bypass_when_down: false,
        reselect_at: Vec::new(),
        reselect_interval: None,
        reselect_sync: false,
    };
    UplinkManager::new_for_test("test", vec![uplink], probe, lb).unwrap()
}

/// Regression: under `udp_gso = true`, USO coalescing in `spawn_flow_reader`
/// must drain queued SS2022 bursts via `try_read_packet` without cancelling
/// reads mid-decrypt under concurrent uplink sends (`send_packet`), delivering
/// every coalesced segment and any mismatched trailing datagram cleanly.
#[tokio::test]
async fn uso_coalescing_drains_ss2022_burst_with_concurrent_uplink_sends_without_loss() {
    use futures_util::{SinkExt, StreamExt};
    use outline_routing::{RouteTarget, RoutingTable, RoutingTableConfig, SharedRoutingTable};
    use outline_uplink::{CipherKind, UplinkRegistry};
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_tungstenite::{accept_async, tungstenite::Message};

    const BURST_COUNT: usize = 64;
    const SEG_SIZE: usize = 1200;
    const TAIL_SIZE: usize = 400;
    const TAIL_MARKER: &[u8] = b"USO_TAIL_400";
    const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
    const CLIENT_PORT: u16 = 51000;
    const REMOTE_PORT: u16 = 443;

    let cipher = CipherKind::Aes256Gcm2022;
    let master_key = cipher
        .derive_master_key("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")
        .unwrap();

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let ws_addr = listener.local_addr().unwrap();
    let ws_url = url::Url::parse(&format!("ws://{ws_addr}/udp")).unwrap();

    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    let (done_tx, done_rx) = oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let ws = accept_async(stream).await.unwrap();
        let (mut sink, mut read) = ws.split();

        let first = loop {
            match read.next().await.unwrap().unwrap() {
                Message::Binary(bytes) => break bytes,
                _ => continue,
            }
        };
        let enc_hdr: [u8; 16] = first[..16].try_into().unwrap();
        let sep_hdr =
            shadowsocks_crypto::decrypt_udp_separate_header(cipher, &master_key, &enc_hdr).unwrap();
        let client_session_id = u64::from_be_bytes(sep_hdr[..8].try_into().unwrap());
        let _ = ready_tx.send(());

        // Drain the concurrent uplink sends and verify every SS2022 header decrypts.
        let uplink_key = master_key.clone();
        let uplink_count = Arc::new(AtomicUsize::new(1));
        let drain_count = Arc::clone(&uplink_count);
        let uplink_drain = tokio::spawn(async move {
            while let Some(msg) = read.next().await {
                if let Ok(Message::Binary(bytes)) = msg {
                    let hdr: [u8; 16] = bytes[..16].try_into().unwrap();
                    let sep =
                        shadowsocks_crypto::decrypt_udp_separate_header(cipher, &uplink_key, &hdr)
                            .unwrap();
                    assert_eq!(u64::from_be_bytes(sep[..8].try_into().unwrap()), client_session_id);
                    drain_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        let target_wire = TargetAddr::IpV4(REMOTE_IP, REMOTE_PORT).to_wire_bytes().unwrap();
        let server_session_id = 0xfeed_beef_cafe_0001u64;
        for seq in 0..BURST_COUNT {
            let mut payload = vec![0xABu8; SEG_SIZE];
            payload[..4].copy_from_slice(&(seq as u32).to_be_bytes());
            let pkt = ss2022_server_packet(
                cipher,
                &master_key,
                server_session_id,
                seq as u64,
                client_session_id,
                &target_wire,
                &payload,
            );
            sink.feed(Message::Binary(pkt.into())).await.unwrap();
        }
        let mut tail_payload = vec![0xCDu8; TAIL_SIZE];
        tail_payload[..TAIL_MARKER.len()].copy_from_slice(TAIL_MARKER);
        let tail_pkt = ss2022_server_packet(
            cipher,
            &master_key,
            server_session_id,
            BURST_COUNT as u64,
            client_session_id,
            &target_wire,
            &tail_payload,
        );
        sink.feed(Message::Binary(tail_pkt.into())).await.unwrap();
        sink.flush().await.unwrap();

        let _ = done_rx.await;
        uplink_drain.abort();
        drop(sink);
        uplink_count.load(Ordering::Relaxed)
    });

    let (writer, capture) = TempTunCapture::new();
    let manager = ss2022_test_uplink_manager(ws_url);
    let table = SharedRoutingTable::new(
        RoutingTable::compile(&RoutingTableConfig {
            rules: Vec::new(),
            default_target: RouteTarget::Group("test".into()),
            default_fallback: None,
        })
        .await
        .unwrap(),
    );
    let routing = crate::TunRouting::new(
        UplinkRegistry::from_single_manager(manager),
        Some(table),
        None,
        None,
        false,
    );
    let engine = crate::udp::TunUdpEngine::new(
        writer,
        routing,
        128,
        0,
        Duration::from_secs(60),
        false,
        false,
        false,
        crate::empty_sniff_override(),
        crate::empty_sniff_override(),
        true,
    );

    let send_uplink = |seq: u32| {
        let engine = engine.clone();
        async move {
            let mut body = vec![0x55u8; 32];
            body[..4].copy_from_slice(&seq.to_be_bytes());
            let ip_pkt = crate::udp::build_ipv4_udp_packet(
                CLIENT_IP,
                REMOTE_IP,
                CLIENT_PORT,
                REMOTE_PORT,
                &body,
            )
            .unwrap();
            let parsed = crate::udp::parse_udp_packet(&ip_pkt).unwrap();
            engine.handle_packet(parsed).await.unwrap();
        }
    };

    // Establish the flow with packet 0 and wait until the server captured client_session_id.
    send_uplink(0).await;
    tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .expect("timed out waiting for first uplink packet")
        .unwrap();

    // Blast concurrent uplink sends while the server pushes the 64x1200 + 400 burst.
    for seq in 1..BURST_COUNT as u32 {
        send_uplink(seq).await;
        if seq % 8 == 0 {
            tokio::task::yield_now().await;
        }
    }

    let mut offset = 0usize;
    let mut received_seqs = BTreeSet::new();
    let mut saw_tail = false;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let data = tokio::fs::read(&capture.path).await.unwrap_or_default();
        while let Some(rem) = data.get(offset..) {
            if rem.len() < 4 {
                break;
            }
            assert_eq!(rem[0] >> 4, 4, "expected IPv4 packet in TUN capture");
            let total_len = usize::from(u16::from_be_bytes([rem[2], rem[3]]));
            assert!(total_len >= 28, "invalid IPv4 UDP packet length {total_len}");
            if rem.len() < total_len {
                break;
            }
            let pkt = &rem[..total_len];
            let ihl = usize::from(pkt[0] & 0x0f) * 4;
            let udp_len = usize::from(u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]));
            assert_eq!(ihl + udp_len, total_len);
            let payload = &pkt[ihl + 8..total_len];

            if payload.len() == TAIL_SIZE {
                assert!(!saw_tail, "duplicate trailing 400-byte datagram");
                assert!(payload.starts_with(TAIL_MARKER), "trailing datagram marker mismatch",);
                saw_tail = true;
            } else {
                assert_eq!(
                    payload.len() % SEG_SIZE,
                    0,
                    "unexpected datagram length {} in TUN capture",
                    payload.len(),
                );
                let (chunks, remainder) = payload.as_chunks::<SEG_SIZE>();
                assert!(remainder.is_empty(), "expected whole {SEG_SIZE}-byte segments");
                for chunk in chunks {
                    let seq = u32::from_be_bytes(chunk[..4].try_into().unwrap());
                    assert!(received_seqs.insert(seq), "duplicate downlink segment seq {seq}",);
                }
            }
            offset += total_len;
        }

        if received_seqs.len() == BURST_COUNT && saw_tail {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for full downlink burst: got {}/{BURST_COUNT} seqs, saw_tail={saw_tail}",
            received_seqs.len(),
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(
        received_seqs.iter().copied().collect::<Vec<_>>(),
        (0..BURST_COUNT as u32).collect::<Vec<_>>(),
        "every segment seq 0..{BURST_COUNT} must arrive once without loss",
    );
    assert!(saw_tail, "mismatched trailing datagram must arrive via carried_over");

    let _ = done_tx.send(());
    drop(engine);
    let uplink_received = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("timed out waiting for server task shutdown")
        .unwrap();
    assert!(
        uplink_received >= 1,
        "expected server to receive uplink datagrams, got {uplink_received}",
    );
}
