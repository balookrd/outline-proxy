use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use outline_uplink::{LoadBalancingConfig, ProbeConfig, UplinkConfig, WsProbeConfig};
use outline_transport::{
    WsTransportStream, TcpShadowsocksReader, TcpShadowsocksWriter, UpstreamTransportGuard,
};
use crate::SharedTunWriter;
use crate::wire::IpVersion;
use shadowsocks_crypto::CipherKind;
use socks5_proto::TargetAddr;
use outline_uplink::UplinkTransport;
use outline_transport::WsTransportMode;
use outline_uplink::UplinkManager;
use futures_util::StreamExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::{MaybeTlsStream, accept_async};
use url::Url;

use super::super::state_machine::TcpFlowStatus;
use super::super::tests::{
    build_client_packet, build_client_packet_with_options, test_tun_tcp_config,
};
use super::super::wire::{IPV6_HEADER_LEN, parse_tcp_packet};
use super::super::{
    TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_SYN, TCP_TIME_WAIT_TIMEOUT, TcpFlowKey,
};

#[tokio::test]
async fn tun_tcp_reassembles_out_of_order_client_segments_end_to_end() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40000;
    let remote_port = 80;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            100,
            0,
            4096,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();

    let syn_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(syn_ack.flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
    assert_eq!(syn_ack.acknowledgement_number, 101);
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);

    let target = upstream.expect_target().await;
    let (target, consumed) = TargetAddr::from_wire_bytes(&target).unwrap();
    assert_eq!(target, TargetAddr::IpV4(remote_ip, remote_port));
    assert_eq!(consumed, target.to_wire_bytes().unwrap().len());

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            101,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            104,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            b"DEF",
        ))
        .await
        .unwrap();
    let gap_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(gap_ack.acknowledgement_number, 101);
    assert!(upstream.try_recv_chunk().await.is_none());

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            101,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            b"ABC",
        ))
        .await
        .unwrap();
    let full_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(full_ack.acknowledgement_number, 107);
    assert_eq!(upstream.recv_chunk().await, b"ABCDEF");
}

#[tokio::test]
async fn tun_tcp_honors_client_window_and_retransmits_unacked_server_data() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40001;
    let remote_port = 443;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1000,
            0,
            4,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1001,
            server_next_seq,
            4,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    upstream.send_chunk(b"ABCDEFGH").await;
    let first_data = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(first_data.payload, b"ABCD"[..]);
    assert_eq!(first_data.sequence_number, server_next_seq);

    for _ in 0..3 {
        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1001,
                server_next_seq,
                4,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();
    }

    let retransmitted = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(retransmitted.payload, b"ABCD"[..]);
    assert_eq!(retransmitted.sequence_number, server_next_seq);

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1001,
            server_next_seq.wrapping_add(4),
            4,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    let second_data = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(second_data.payload, b"EFGH"[..]);
    assert_eq!(second_data.sequence_number, server_next_seq.wrapping_add(4));
}

#[tokio::test]
async fn tun_tcp_sends_zero_window_probe_and_resumes_after_window_reopens() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40002;
    let remote_port = 80;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            100,
            0,
            0,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            101,
            server_next_seq,
            0,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    upstream.send_chunk(b"AB").await;
    let probe = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(probe.payload, b"A"[..]);
    assert_eq!(probe.sequence_number, server_next_seq);

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            101,
            server_next_seq,
            2,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    let data = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(data.payload, b"AB"[..]);
    assert_eq!(data.sequence_number, server_next_seq);
}

#[tokio::test]
async fn tun_tcp_defers_fin_until_buffered_server_data_is_acked() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40003;
    let remote_port = 80;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            500,
            0,
            2,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            501,
            server_next_seq,
            2,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    upstream.send_chunk(b"ABCD").await;
    let first_data = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(first_data.payload, b"AB"[..]);

    upstream.close().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            501,
            server_next_seq.wrapping_add(2),
            2,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    let second_data = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(second_data.payload, b"CD"[..]);

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            501,
            server_next_seq.wrapping_add(4),
            2,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    let fin = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(fin.flags, TCP_FLAG_FIN | TCP_FLAG_ACK);
    assert!(fin.payload.is_empty());
}

#[tokio::test]
async fn tun_tcp_timeout_retransmit_is_driven_by_flow_timer() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40004;
    let remote_port = 443;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1000,
            0,
            4096,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1001,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    upstream.send_chunk(b"AB").await;
    let first_data = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(first_data.payload, b"AB"[..]);

    let key = TcpFlowKey {
        version: IpVersion::V4,
        client_ip: client_ip.into(),
        client_port,
        remote_ip: remote_ip.into(),
        remote_port,
    };
    let flow = engine
        .inner
        .flows
        .get(&key)
        .map(|v| Arc::clone(v.value()))
        .expect("flow must exist");
    {
        let mut state = flow.lock().await;
        state.retransmission_timeout = Duration::from_millis(200);
        super::super::maintenance::sync_flow_metrics_and_wake(&mut state);
    }

    let retransmitted = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(retransmitted.sequence_number, first_data.sequence_number);
    assert_eq!(retransmitted.payload, b"AB"[..]);
}

#[tokio::test]
async fn tun_tcp_invalid_high_ack_triggers_challenge_ack() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40007;
    let remote_port = 443;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1000,
            0,
            4096,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1001,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1001,
            server_next_seq.wrapping_add(100),
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    let ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(ack.flags, TCP_FLAG_ACK);
    assert_eq!(ack.acknowledgement_number, 1001);
}

#[tokio::test]
async fn tun_tcp_invalid_rst_in_window_is_challenge_acked() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40008;
    let remote_port = 443;
    let key = TcpFlowKey {
        version: IpVersion::V4,
        client_ip: client_ip.into(),
        client_port,
        remote_ip: remote_ip.into(),
        remote_port,
    };

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1000,
            0,
            4096,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1001,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1002,
            server_next_seq,
            4096,
            TCP_FLAG_RST,
            &[],
        ))
        .await
        .unwrap();

    let ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(ack.flags, TCP_FLAG_ACK);
    assert_eq!(ack.acknowledgement_number, 1001);
    assert!(engine.inner.flows.contains_key(&key));
}

#[tokio::test]
async fn tun_tcp_unexpected_syn_in_established_flow_is_challenge_acked() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40009;
    let remote_port = 443;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1000,
            0,
            4096,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1001,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1001,
            server_next_seq,
            4096,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();

    let ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(ack.flags, TCP_FLAG_ACK);
    assert_eq!(ack.acknowledgement_number, 1001);
}

#[tokio::test]
async fn tun_tcp_paws_rejects_stale_timestamp_segment() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40010;
    let remote_port = 443;

    engine
        .handle_packet(&build_client_packet_with_options(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1000,
            0,
            4096,
            TCP_FLAG_SYN,
            &[8, 10, 0, 0, 0, 20, 0, 0, 0, 0, 1, 1],
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet(&build_client_packet_with_options(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1001,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &[8, 10, 0, 0, 0, 21, 0, 0, 0, 20, 1, 1],
            &[],
        ))
        .await
        .unwrap();

    engine
        .handle_packet(&build_client_packet_with_options(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1001,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &[8, 10, 0, 0, 0, 19, 0, 0, 0, 20, 1, 1],
            b"bad",
        ))
        .await
        .unwrap();

    let ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(ack.flags, TCP_FLAG_ACK);
    assert_eq!(ack.acknowledgement_number, 1001);
    assert!(upstream.try_recv_chunk().await.is_none());
}

#[tokio::test]
async fn tun_tcp_respects_peer_mss_for_server_segments() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40011;
    let remote_port = 443;

    engine
        .handle_packet(&build_client_packet_with_options(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1000,
            0,
            4096,
            TCP_FLAG_SYN,
            &[2, 4, 0x02, 0x58],
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1001,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    upstream.send_chunk(&vec![b'X'; 1000]).await;
    let data = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(data.payload.len(), 600);
}

#[tokio::test]
async fn tun_tcp_client_fin_transitions_through_last_ack() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40005;
    let remote_port = 80;

    let key = TcpFlowKey {
        version: IpVersion::V4,
        client_ip: client_ip.into(),
        client_port,
        remote_ip: remote_ip.into(),
        remote_port,
    };

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            500,
            0,
            4096,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            501,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            501,
            server_next_seq,
            4096,
            TCP_FLAG_ACK | TCP_FLAG_FIN,
            &[],
        ))
        .await
        .unwrap();
    let fin_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(fin_ack.flags, TCP_FLAG_ACK);
    assert_eq!(fin_ack.acknowledgement_number, 502);
    let flow = engine
        .inner
        .flows
        .get(&key)
        .map(|v| Arc::clone(v.value()))
        .expect("flow must remain after client FIN");
    assert!(matches!(
        flow.lock().await.status,
        TcpFlowStatus::CloseWait | TcpFlowStatus::LastAck
    ));

    upstream.close().await;
    let server_fin = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(server_fin.flags, TCP_FLAG_FIN | TCP_FLAG_ACK);
    let flow = engine
        .inner
        .flows
        .get(&key)
        .map(|v| Arc::clone(v.value()))
        .expect("flow must remain in LAST_ACK");
    assert_eq!(flow.lock().await.status, TcpFlowStatus::LastAck);

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            502,
            server_next_seq.wrapping_add(1),
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!engine.inner.flows.contains_key(&key));
}

#[tokio::test]
async fn tun_tcp_server_fin_transitions_through_time_wait() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40006;
    let remote_port = 80;

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            700,
            0,
            4096,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    let time_wait_key = TcpFlowKey {
        version: IpVersion::V4,
        client_ip: client_ip.into(),
        client_port,
        remote_ip: remote_ip.into(),
        remote_port,
    };

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            701,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    upstream.close().await;
    let server_fin = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(server_fin.flags, TCP_FLAG_FIN | TCP_FLAG_ACK);

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            701,
            server_next_seq.wrapping_add(1),
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();
    let flow = engine
        .inner
        .flows
        .get(&time_wait_key)
        .map(|v| Arc::clone(v.value()))
        .expect("flow must remain in FIN_WAIT_2");
    assert_eq!(flow.lock().await.status, TcpFlowStatus::FinWait2);

    engine
        .handle_packet(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            701,
            server_next_seq.wrapping_add(1),
            4096,
            TCP_FLAG_ACK | TCP_FLAG_FIN,
            &[],
        ))
        .await
        .unwrap();
    let final_ack = parse_tcp_packet(&capture.next_packet().await).unwrap();
    assert_eq!(final_ack.flags, TCP_FLAG_ACK);
    assert_eq!(final_ack.acknowledgement_number, 702);

    let flow = engine
        .inner
        .flows
        .get(&time_wait_key)
        .map(|v| Arc::clone(v.value()))
        .expect("flow must stay alive in TIME_WAIT");
    {
        let mut state = flow.lock().await;
        assert_eq!(state.status, TcpFlowStatus::TimeWait);
        state.timestamps.status_since = Instant::now() - TCP_TIME_WAIT_TIMEOUT - Duration::from_millis(1);
        // Force an immediate wake even though the newly-computed deadline
        // is in the past — scheduler's "earlier-only" push gate would
        // otherwise no-op on a later deadline.
        state.next_scheduled_deadline = None;
        super::super::maintenance::sync_flow_metrics_and_wake(&mut state);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!engine.inner.flows.contains_key(&time_wait_key));
}
#[tokio::test]
async fn new_flow_is_removed_when_synack_write_fails() {
    let path = std::env::temp_dir()
        .join(format!("outline-ws-rust-tun-write-fail-{}.bin", rand::random::<u64>()));
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .unwrap();
    let writer = SharedTunWriter::new(
        std::fs::OpenOptions::new().read(true).open(&path).unwrap(),
    );
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(
            build_test_manager(Url::parse("ws://127.0.0.1:9/tcp").unwrap()).await,
        ),
        128,
        Duration::from_secs(60),
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let error = engine
        .handle_packet(&build_client_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            40010,
            443,
            100,
            0,
            4096,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap_err();

    let error_text = format!("{error:#}");
    assert!(
        error_text.contains("failed to write packet to TUN")
            || error_text.contains("failed to flush TUN packet"),
        "{error_text}"
    );
    assert!(engine.inner.flows.is_empty());
    assert!(engine.inner.pending_connects.lock().await.is_empty());

    let _ = std::fs::remove_file(path);
}
pub(in crate::tcp) async fn build_test_manager(tcp_ws_url: Url) -> UplinkManager {
    UplinkManager::new_for_test(
        "test",
        vec![UplinkConfig {
            name: "test".to_string(),
            transport: UplinkTransport::Ws,
            tcp_ws_url: Some(tcp_ws_url),
            tcp_ws_mode: WsTransportMode::Http1,
            udp_ws_url: None,
            udp_ws_mode: WsTransportMode::Http1,
            tcp_addr: None,
            udp_addr: None,
            cipher: CipherKind::Chacha20IetfPoly1305,
            password: "Secret0".to_string(),
            weight: 1.0,
            fwmark: None,
            ipv6_first: false,
        }],
        ProbeConfig {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            max_concurrent: 2,
            max_dials: 1,
            min_failures: 1,
            attempts: 1,
            ws: WsProbeConfig { enabled: false },
            http: None,
            dns: None,
            tcp: None,
        },
        LoadBalancingConfig {
            mode: outline_uplink::LoadBalancingMode::ActiveActive,
            routing_scope: outline_uplink::RoutingScope::PerFlow,
            sticky_ttl: Duration::from_secs(300),
            hysteresis: Duration::from_millis(50),
            failure_cooldown: Duration::from_secs(10),
            tcp_chunk0_failover_timeout: Duration::from_secs(10),
            warm_standby_tcp: 0,
            warm_standby_udp: 0,
            rtt_ewma_alpha: 0.3,
            failure_penalty: Duration::from_millis(500),
            failure_penalty_max: Duration::from_secs(30),
            failure_penalty_halflife: Duration::from_secs(60),
            h3_downgrade_duration: Duration::from_secs(60),
            udp_ws_keepalive_interval: None,
            tcp_ws_standby_keepalive_interval: None,
            tcp_active_keepalive_interval: None,
            auto_failback: false,
        },
    )
    .unwrap()
}
struct TunCapture {
    path: PathBuf,
    offset: usize,
}

impl TunCapture {
    async fn new() -> (SharedTunWriter, Self) {
        let path = std::env::temp_dir()
            .join(format!("outline-ws-rust-tun-capture-{}.bin", rand::random::<u64>()));
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let writer = SharedTunWriter::new(file);
        (writer, Self { path, offset: 0 })
    }

    async fn next_packet(&mut self) -> Vec<u8> {
        for _ in 0..100 {
            let data = tokio::fs::read(&self.path).await.unwrap_or_default();
            if data.len() > self.offset {
                let remaining = &data[self.offset..];
                if let Some(packet_len) = packet_length(remaining) {
                    if remaining.len() >= packet_len {
                        let packet = remaining[..packet_len].to_vec();
                        self.offset += packet_len;
                        return packet;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for captured TUN packet");
    }
}

impl Drop for TunCapture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn packet_length(data: &[u8]) -> Option<usize> {
    match data.first().map(|byte| byte >> 4)? {
        4 if data.len() >= 4 => Some(u16::from_be_bytes([data[2], data[3]]) as usize),
        6 if data.len() >= 6 => {
            Some(IPV6_HEADER_LEN + u16::from_be_bytes([data[4], data[5]]) as usize)
        },
        _ => None,
    }
}
struct TestTcpUpstream {
    addr: SocketAddr,
    target_rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    chunk_rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    send_tx: mpsc::UnboundedSender<Vec<u8>>,
    _accepted: Arc<AtomicUsize>,
}

impl TestTcpUpstream {
    async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_task = Arc::clone(&accepted);
        let (target_tx, target_rx) = mpsc::unbounded_channel();
        let (chunk_tx, chunk_rx) = mpsc::unbounded_channel();
        let (send_tx, send_rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accepted_task.fetch_add(1, Ordering::SeqCst);
            let _ = handle_test_tcp_upstream(stream, target_tx, chunk_tx, send_rx).await;
        });

        Self {
            addr,
            target_rx: Mutex::new(target_rx),
            chunk_rx: Mutex::new(chunk_rx),
            send_tx,
            _accepted: accepted,
        }
    }

    fn url(&self) -> Url {
        Url::parse(&format!("ws://{}/tcp", self.addr)).unwrap()
    }

    async fn expect_target(&self) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(2), async {
            self.target_rx.lock().await.recv().await
        })
        .await
        .unwrap()
        .unwrap()
    }

    async fn recv_chunk(&self) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(2), async {
            self.chunk_rx.lock().await.recv().await
        })
        .await
        .unwrap()
        .unwrap()
    }

    async fn try_recv_chunk(&self) -> Option<Vec<u8>> {
        tokio::time::timeout(Duration::from_millis(100), async {
            self.chunk_rx.lock().await.recv().await
        })
        .await
        .ok()
        .flatten()
    }

    async fn send_chunk(&self, data: &[u8]) {
        self.send_tx.send(data.to_vec()).unwrap();
    }

    async fn close(&self) {
        let _ = self.send_tx.send(Vec::new());
    }
}

async fn handle_test_tcp_upstream(
    stream: TcpStream,
    target_tx: mpsc::UnboundedSender<Vec<u8>>,
    chunk_tx: mpsc::UnboundedSender<Vec<u8>>,
    mut send_rx: mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws = accept_async(MaybeTlsStream::Plain(stream)).await?;
    let ws = WsTransportStream::new_http1(ws);
    let (sink, stream) = ws.split();
    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher.derive_master_key("Secret0").unwrap();
    let lifetime = UpstreamTransportGuard::new("test", "tcp");
    let (mut writer, ctrl_tx) =
        TcpShadowsocksWriter::connect(sink, cipher, &master_key, Arc::clone(&lifetime)).await?;
    let request_salt = writer.request_salt();
    let mut reader = TcpShadowsocksReader::new(stream, cipher, &master_key, lifetime, ctrl_tx)
        .with_request_salt(request_salt);

    target_tx.send(reader.read_chunk().await?).unwrap();

    loop {
        tokio::select! {
            inbound = reader.read_chunk() => {
                match inbound {
                    Ok(chunk) => {
                        chunk_tx.send(chunk).unwrap();
                    }
                    Err(_) => break,
                }
            }
            outbound = send_rx.recv() => {
                match outbound {
                    Some(chunk) if chunk.is_empty() => break,
                    Some(chunk) => writer.send_chunk(&chunk).await?,
                    None => break,
                }
            }
        }
    }

    Ok(())
}
