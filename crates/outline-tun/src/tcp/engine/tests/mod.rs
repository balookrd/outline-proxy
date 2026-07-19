use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use crate::SharedTunWriter;
use crate::wire::IpVersion;
use futures_util::StreamExt;
use outline_transport::TransportMode;
use outline_transport::{
    TcpShadowsocksReader, TcpShadowsocksWriter, TransportStream, UpstreamTransportGuard,
};
use outline_uplink::UplinkManager;
use outline_uplink::UplinkTransport;
use outline_uplink::{LoadBalancingConfig, ProbeConfig, UplinkConfig, WsProbeConfig};
use shadowsocks_crypto::CipherKind;
use socks5_proto::TargetAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::{MaybeTlsStream, accept_async};
use url::Url;

mod dial_admission;
mod direct_backpressure;
mod global_budget;
mod migrate;
mod resume;
mod window_autotune;

use super::super::state_machine::TcpFlowStatus;
use super::super::tests::{
    build_client_packet, build_client_packet_with_options, test_tun_tcp_config,
};
use super::super::wire::{IPV6_HEADER_LEN, parse_tcp_packet_unverified};
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
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40000;
    let remote_port = 80;

    engine
        .handle_packet_unverified(&build_client_packet(
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

    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(syn_ack.flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
    assert_eq!(syn_ack.acknowledgement_number, 101);
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);

    let target = upstream.expect_target().await;
    let (target, consumed) = TargetAddr::from_wire_bytes(&target).unwrap();
    assert_eq!(target, TargetAddr::IpV4(remote_ip, remote_port));
    assert_eq!(consumed, target.to_wire_bytes().unwrap().len());

    engine
        .handle_packet_unverified(&build_client_packet(
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
        .handle_packet_unverified(&build_client_packet(
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
    let gap_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(gap_ack.acknowledgement_number, 101);
    assert!(upstream.try_recv_chunk().await.is_none());

    engine
        .handle_packet_unverified(&build_client_packet(
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
    let full_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(full_ack.acknowledgement_number, 107);
    assert_eq!(upstream.recv_chunk().await, b"ABCDEF");
}

/// Build a minimal TLS ClientHello record carrying a single `server_name`
/// (host_name) extension, used to drive the connection-sniffing path.
fn tls_client_hello_with_sni(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut sni_ext = Vec::new();
    let entry_len = 1 + 2 + name.len();
    sni_ext.extend_from_slice(&(entry_len as u16).to_be_bytes());
    sni_ext.push(0x00);
    sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(name);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&[0x11; 32]);
    hello.push(0x00);
    hello.extend_from_slice(&2u16.to_be_bytes());
    hello.extend_from_slice(&[0x13, 0x01]);
    hello.push(0x01);
    hello.push(0x00);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut handshake = vec![0x01];
    let l = hello.len();
    handshake.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    handshake.extend_from_slice(&hello);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[tokio::test]
async fn tun_tcp_sniffs_tls_sni_and_overrides_target_with_domain() {
    // Connection sniffing (default on): a TLS ClientHello arriving as the
    // first client segment must rewrite the dialled destination from the
    // literal IP into the SNI domain, so the exit node resolves it. The same
    // ClientHello bytes are still forwarded upstream verbatim.
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40044;
    let remote_port = 443;

    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            300,
            0,
            4096,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(syn_ack.flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);

    // Deliver the ClientHello as the first client segment *before* draining the
    // target, so the connect task sniffs it instead of timing out to the IP.
    let hello = tls_client_hello_with_sni("example.com");
    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            301,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &hello,
        ))
        .await
        .unwrap();

    let target = upstream.expect_target().await;
    let (target, _) = TargetAddr::from_wire_bytes(&target).unwrap();
    assert_eq!(target, TargetAddr::Domain("example.com".to_string(), remote_port));

    // The ClientHello itself is still forwarded upstream unchanged.
    assert_eq!(upstream.recv_chunk().await, hello);
}

/// Drive SYN → SYN-ACK → ACK and return the server's next sequence number.
async fn open_flow(
    engine: &super::TunTcpEngine,
    capture: &mut TunCapture,
    client_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    client_port: u16,
    remote_port: u16,
    client_isn: u32,
) -> u32 {
    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            client_isn,
            0,
            4096,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(syn_ack.flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
    syn_ack.sequence_number.wrapping_add(1)
}

#[tokio::test]
async fn tun_tcp_sniffs_http_host_and_overrides_target_with_domain() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let (client_port, remote_port) = (40046, 80);
    let server_next_seq =
        open_flow(&engine, &mut capture, client_ip, remote_ip, client_port, remote_port, 400).await;

    let request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            401,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            request,
        ))
        .await
        .unwrap();

    let target = upstream.expect_target().await;
    let (target, _) = TargetAddr::from_wire_bytes(&target).unwrap();
    assert_eq!(target, TargetAddr::Domain("example.com".to_string(), remote_port));
    assert_eq!(upstream.recv_chunk().await, request);
}

#[tokio::test]
async fn tun_tcp_non_sniffable_first_chunk_dials_by_ip() {
    // A first segment that is neither TLS nor HTTP is not sniffable: the connect
    // task gives up immediately (no timeout wait) and dials the literal IP.
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let (client_port, remote_port) = (40048, 22);
    let server_next_seq =
        open_flow(&engine, &mut capture, client_ip, remote_ip, client_port, remote_port, 500).await;

    let blob = b"\x00\x01\x02\x03 binary protocol, not TLS or HTTP";
    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            501,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            blob,
        ))
        .await
        .unwrap();

    let target = upstream.expect_target().await;
    let (target, _) = TargetAddr::from_wire_bytes(&target).unwrap();
    assert_eq!(target, TargetAddr::IpV4(remote_ip, remote_port));
    assert_eq!(upstream.recv_chunk().await, blob);
}

#[tokio::test]
async fn tun_tcp_sniffed_excluded_host_dials_by_ip() {
    // Sniffing is on and the ClientHello carries an SNI, but the host is in the
    // override-exclude list → the flow keeps the literal IP (the client's own
    // resolution), not the domain.
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let config = crate::config::TunTcpConfig {
        sniff_override_exclude: vec!["example.com".into()].into(),
        ..test_tun_tcp_config()
    };
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        false,
        config,
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let (client_port, remote_port) = (40052, 443);
    let server_next_seq =
        open_flow(&engine, &mut capture, client_ip, remote_ip, client_port, remote_port, 700).await;

    let hello = tls_client_hello_with_sni("example.com");
    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            701,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &hello,
        ))
        .await
        .unwrap();

    let target = upstream.expect_target().await;
    let (target, _) = TargetAddr::from_wire_bytes(&target).unwrap();
    assert_eq!(target, TargetAddr::IpV4(remote_ip, remote_port));
}

#[tokio::test]
async fn tun_tcp_sniffing_disabled_dials_by_ip() {
    // With sniffing off the connect happens on SYN (no wait for client data),
    // so even a TLS ClientHello leaves over the tunnel addressed to the IP.
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let config = crate::config::TunTcpConfig { sniffing: false, ..test_tun_tcp_config() };
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        false,
        config,
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let (client_port, remote_port) = (40050, 443);
    let _ =
        open_flow(&engine, &mut capture, client_ip, remote_ip, client_port, remote_port, 600).await;

    // No client data sent: the IP target is dialled immediately on SYN.
    let target = upstream.expect_target().await;
    let (target, _) = TargetAddr::from_wire_bytes(&target).unwrap();
    assert_eq!(target, TargetAddr::IpV4(remote_ip, remote_port));
}

#[tokio::test]
async fn tun_tcp_route_by_sni_reroutes_by_sniffed_domain() {
    // With route_by_sni on, the sniffed TLS SNI re-resolves the route before the
    // dial: a ClientHello for a domain a [[route]] rule sends to `drop` tears the
    // flow down with a RST — even though its literal IP (8.8.8.8) would otherwise
    // tunnel via the default group. Proves the SNI, not just the IP, drives
    // uplink/direct/drop selection on the TCP path.
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let table = std::sync::Arc::new(
        outline_routing::RoutingTable::compile(&outline_routing::RoutingTableConfig {
            rules: vec![outline_routing::RouteRule {
                inline_prefixes: Vec::new(),
                files: Vec::new(),
                inline_domains: vec!["example.com".to_string()],
                domain_files: Vec::new(),
                file_poll: Duration::from_secs(60),
                target: outline_routing::RouteTarget::Drop,
                fallback: None,
                invert: false,
            }],
            default_target: outline_routing::RouteTarget::Group("test".into()),
            default_fallback: None,
        })
        .await
        .unwrap(),
    );
    let registry = outline_uplink::UplinkRegistry::from_single_manager(manager);
    let dispatch = crate::TunRouting::new(registry, Some(table), None, false);
    let config = crate::config::TunTcpConfig { route_by_sni: true, ..test_tun_tcp_config() };
    let engine = super::TunTcpEngine::new(
        writer,
        dispatch,
        128,
        Duration::from_secs(60),
        false,
        config,
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let (client_port, remote_port) = (40077, 443);
    let server_next_seq =
        open_flow(&engine, &mut capture, client_ip, remote_ip, client_port, remote_port, 700).await;

    // Deliver the ClientHello whose SNI matches the `drop` rule.
    let hello = tls_client_hello_with_sni("example.com");
    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            701,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &hello,
        ))
        .await
        .unwrap();

    // The flow is reset. Drain any interim data-ACK for the ClientHello, then
    // assert a RST arrives — and that nothing was ever dialled upstream.
    let mut saw_rst = false;
    for _ in 0..5 {
        let parsed = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
        if parsed.flags & TCP_FLAG_RST != 0 {
            saw_rst = true;
            break;
        }
    }
    assert!(saw_rst, "expected a RST after the SNI routed the flow to drop");
    assert!(
        upstream.try_target().await.is_none(),
        "flow must not have tunneled: the SNI routed it to drop"
    );
}

#[tokio::test]
async fn tun_tcp_pump_delivers_sequential_client_chunks_in_order() {
    // After decoupling the read-loop from upstream sends, client payload is
    // buffered into `pending_client_data` and drained by the per-flow pump.
    // Verify that several separately-delivered in-order segments still reach
    // the upstream in order across distinct pump wake/drain cycles (not just
    // the single drain exercised by the reassembly test above).
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40020;
    let remote_port = 80;

    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            200,
            0,
            4096,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            201,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            201,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            b"ABC",
        ))
        .await
        .unwrap();
    assert_eq!(upstream.recv_chunk().await, b"ABC");

    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            204,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            b"DEF",
        ))
        .await
        .unwrap();
    assert_eq!(upstream.recv_chunk().await, b"DEF");
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
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40001;
    let remote_port = 443;

    engine
        .handle_packet_unverified(&build_client_packet(
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
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet_unverified(&build_client_packet(
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
    let first_data = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(first_data.payload, b"ABCD"[..]);
    assert_eq!(first_data.sequence_number, server_next_seq);

    for _ in 0..3 {
        engine
            .handle_packet_unverified(&build_client_packet(
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

    let retransmitted = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(retransmitted.payload, b"ABCD"[..]);
    assert_eq!(retransmitted.sequence_number, server_next_seq);

    engine
        .handle_packet_unverified(&build_client_packet(
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

    let second_data = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
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
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40002;
    let remote_port = 80;

    engine
        .handle_packet_unverified(&build_client_packet(
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
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet_unverified(&build_client_packet(
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
    let probe = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(probe.payload, b"A"[..]);
    assert_eq!(probe.sequence_number, server_next_seq);

    engine
        .handle_packet_unverified(&build_client_packet(
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

    let data = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
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
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40003;
    let remote_port = 80;

    engine
        .handle_packet_unverified(&build_client_packet(
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
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet_unverified(&build_client_packet(
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
    let first_data = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(first_data.payload, b"AB"[..]);

    upstream.close().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    engine
        .handle_packet_unverified(&build_client_packet(
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

    let second_data = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(second_data.payload, b"CD"[..]);

    engine
        .handle_packet_unverified(&build_client_packet(
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

    let fin = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
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
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40004;
    let remote_port = 443;

    engine
        .handle_packet_unverified(&build_client_packet(
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
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet_unverified(&build_client_packet(
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
    let first_data = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
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
        super::super::maintenance::commit_flow_changes(&mut state, &engine.inner.tcp);
    }

    let retransmitted = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(retransmitted.sequence_number, first_data.sequence_number);
    assert_eq!(retransmitted.payload, b"AB"[..]);
}

/// Regression: a partial ACK that clears the *oldest* unacked segment moves the
/// retransmission deadline out to the next segment's (later) `last_sent`.
/// `reschedule_flow` does not push a heap entry for a later deadline, so the
/// maintenance loop must still process the earlier (now-stale) entry and re-arm
/// the flow — otherwise the flow falls off the scheduler and the surviving
/// segment is never RTO-retransmitted. This is the split-TCP failure that left
/// Kinopoisk's ~4 KB TLS init hung (its tail segments dropped on the last mile,
/// never resent) until the TV reported "no internet".
#[tokio::test]
async fn tun_tcp_retransmits_after_partial_ack_moves_deadline_later() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40044;
    let remote_port = 443;

    engine
        .handle_packet_unverified(&build_client_packet(
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
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet_unverified(&build_client_packet(
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

    // Three separate downlink segments so there is an oldest to clear and a
    // still-unacked tail whose deadline lands later.
    upstream.send_chunk(b"AAAA").await;
    let seg1 = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    upstream.send_chunk(b"BBBB").await;
    let seg2 = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    upstream.send_chunk(b"CCCC").await;
    let seg3 = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(seg1.payload, b"AAAA"[..]);
    assert_eq!(seg2.payload, b"BBBB"[..]);
    assert_eq!(seg3.payload, b"CCCC"[..]);

    // First partial ACK clears seg1 (and, via its RTT sample, drops RTO to the
    // 200 ms floor) — the deadline moves *earlier* here, so it is pushed.
    let ack_seg1 = seg1.sequence_number.wrapping_add(seg1.payload.len() as u32);
    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1001,
            ack_seg1,
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    // Second partial ACK clears seg2, moving the deadline out to seg3's later
    // `last_sent`. `reschedule_flow` will NOT push a heap entry for it; only the
    // maintenance loop's re-plan of the earlier stale entry re-arms it.
    let ack_seg2 = seg2.sequence_number.wrapping_add(seg2.payload.len() as u32);
    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            1001,
            ack_seg2,
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    // seg3 must still be RTO-retransmitted. Before the scheduler fix the flow
    // fell off the scheduler here and this `next_packet` would never arrive.
    let retransmitted = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(retransmitted.sequence_number, seg3.sequence_number);
    assert_eq!(retransmitted.payload, b"CCCC"[..]);
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
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40007;
    let remote_port = 443;

    engine
        .handle_packet_unverified(&build_client_packet(
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
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet_unverified(&build_client_packet(
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
        .handle_packet_unverified(&build_client_packet(
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

    let ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
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
        false,
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
        .handle_packet_unverified(&build_client_packet(
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
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet_unverified(&build_client_packet(
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
        .handle_packet_unverified(&build_client_packet(
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

    let ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(ack.flags, TCP_FLAG_ACK);
    assert_eq!(ack.acknowledgement_number, 1001);
    assert!(engine.inner.flows.contains_key(&key));
}

#[tokio::test]
async fn tun_tcp_flow_limit_uses_activity_eviction_index() {
    let manager = build_test_manager("ws://127.0.0.1:1/".parse().unwrap()).await;
    let (writer, _capture) = TunCapture::new().await;
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager.clone()),
        2,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );
    let now = Instant::now();
    let first_key = test_flow_key(40010);
    let second_key = test_flow_key(40011);
    let third_key = test_flow_key(40012);

    engine
        .insert_flow(
            first_key.clone(),
            Arc::new(Mutex::new(eviction_test_flow_state(
                &engine,
                &manager,
                first_key.clone(),
                1,
                now,
            ))),
        )
        .await
        .unwrap();
    engine
        .insert_flow(
            second_key.clone(),
            Arc::new(Mutex::new(eviction_test_flow_state(
                &engine,
                &manager,
                second_key.clone(),
                2,
                now + Duration::from_millis(1),
            ))),
        )
        .await
        .unwrap();

    // Activity on the first flow moves it off the eviction head. The bump has to
    // clear `TCP_EVICTION_INDEX_QUANTUM`: a sub-quantum advance deliberately
    // leaves the index untouched so the packet path never takes the eviction lock.
    let first_flow = engine.lookup_flow(&first_key).await.unwrap();
    {
        let mut state = first_flow.lock().await;
        state.timestamps.last_seen = now + Duration::from_secs(2);
        engine.record_flow_activity(&mut state);
    }

    engine
        .insert_flow(
            third_key.clone(),
            Arc::new(Mutex::new(eviction_test_flow_state(
                &engine,
                &manager,
                third_key.clone(),
                3,
                now + Duration::from_millis(3),
            ))),
        )
        .await
        .unwrap();

    assert!(engine.inner.flows.contains_key(&first_key));
    assert!(!engine.inner.flows.contains_key(&second_key));
    assert!(engine.inner.flows.contains_key(&third_key));
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
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40009;
    let remote_port = 443;

    engine
        .handle_packet_unverified(&build_client_packet(
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
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet_unverified(&build_client_packet(
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
        .handle_packet_unverified(&build_client_packet(
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

    let ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
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
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40010;
    let remote_port = 443;

    engine
        .handle_packet_unverified(&build_client_packet_with_options(
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
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet_unverified(&build_client_packet_with_options(
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
        .handle_packet_unverified(&build_client_packet_with_options(
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

    let ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
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
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40011;
    let remote_port = 443;

    engine
        .handle_packet_unverified(&build_client_packet_with_options(
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
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet_unverified(&build_client_packet(
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
    let data = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
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
        false,
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
        .handle_packet_unverified(&build_client_packet(
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
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    let _ = upstream.expect_target().await;

    engine
        .handle_packet_unverified(&build_client_packet(
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
        .handle_packet_unverified(&build_client_packet(
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
    let fin_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
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
    let server_fin = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(server_fin.flags, TCP_FLAG_FIN | TCP_FLAG_ACK);
    let flow = engine
        .inner
        .flows
        .get(&key)
        .map(|v| Arc::clone(v.value()))
        .expect("flow must remain in LAST_ACK");
    assert_eq!(flow.lock().await.status, TcpFlowStatus::LastAck);

    engine
        .handle_packet_unverified(&build_client_packet(
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
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let client_port = 40006;
    let remote_port = 80;

    engine
        .handle_packet_unverified(&build_client_packet(
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
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
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
        .handle_packet_unverified(&build_client_packet(
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
    let server_fin = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(server_fin.flags, TCP_FLAG_FIN | TCP_FLAG_ACK);

    engine
        .handle_packet_unverified(&build_client_packet(
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
        .handle_packet_unverified(&build_client_packet(
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
    let final_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
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
        state.timestamps.status_since =
            Instant::now() - TCP_TIME_WAIT_TIMEOUT - Duration::from_millis(1);
        // Force an immediate wake even though the newly-computed deadline
        // is in the past — scheduler's "earlier-only" push gate would
        // otherwise no-op on a later deadline.
        state.next_scheduled_deadline = None;
        super::super::maintenance::commit_flow_changes(&mut state, &engine.inner.tcp);
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
    let writer = SharedTunWriter::new(std::fs::OpenOptions::new().read(true).open(&path).unwrap());
    let engine = super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(
            build_test_manager(Url::parse("ws://127.0.0.1:9/tcp").unwrap()).await,
        ),
        128,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let error = engine
        .handle_packet_unverified(&build_client_packet(
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

fn test_flow_key(client_port: u16) -> TcpFlowKey {
    TcpFlowKey {
        version: IpVersion::V4,
        client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        client_port,
        remote_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        remote_port: 443,
    }
}

fn eviction_test_flow_state(
    engine: &super::TunTcpEngine,
    manager: &UplinkManager,
    key: TcpFlowKey,
    id: u64,
    last_seen: Instant,
) -> super::super::state_machine::TcpFlowState {
    let (close_signal, _close_rx) = tokio::sync::watch::channel(false);
    super::super::state_machine::TcpFlowState {
        id,
        gso_enabled: false,
        key,
        routing: super::super::state_machine::FlowRouting {
            uplink_index: 0,
            uplink_name: Arc::from("test"),
            group_name: Arc::from(manager.group_name()),
            manager: manager.clone(),
            route: crate::TunRoute::Group {
                name: Arc::from("test"),
                manager: manager.clone(),
            },
            target: TargetAddr::IpV4(Ipv4Addr::new(8, 8, 8, 8), 443),
            upstream_carrier: None,
        },
        resume: super::super::state_machine::FlowResume::disarmed(),
        signals: super::super::state_machine::FlowControlSignals {
            close_signal,
            upstream_pump: Arc::new(tokio::sync::Notify::new()),
            carrier_migration: Arc::new(tokio::sync::Notify::new()),
            server_drain: Arc::new(tokio::sync::Notify::new()),
            scheduler: Arc::clone(&engine.inner.scheduler),
            idle_timeout: engine.inner.idle_timeout,
        },
        status: TcpFlowStatus::Established,
        rcv_nxt: 100,
        client_window_scale: 0,
        client_sack_permitted: false,
        client_max_segment_size: None,
        timestamps_enabled: false,
        recent_client_timestamp: None,
        server_timestamp_offset: 0,
        client_window: 4096,
        client_window_end: 5096,
        client_window_update_seq: 100,
        client_window_update_ack: 1000,
        server_seq: 1000,
        last_client_ack: 1000,
        duplicate_ack_count: 0,
        fast_recovery_end: None,
        recovery_epoch: 0,
        receive_window_capacity: 262_144,
        smoothed_rtt: None,
        rttvar: super::super::TCP_INITIAL_RTO / 2,
        retransmission_timeout: super::super::TCP_INITIAL_RTO,
        bbr: super::super::state_machine::BbrState::new(last_seen, 0),
        pending_server_data: VecDeque::new(),
        pending_server_bytes_total: 0,
        pending_budget_global: None,
        backlog_limit_exceeded_since: None,
        last_ack_progress_at: last_seen,
        pending_client_data: VecDeque::new(),
        unacked_server_segments: VecDeque::new(),
        sack_scoreboard: Vec::new(),
        pipe_bytes: 0,
        pipe_segments: 0,
        first_tx_mstamp: Instant::now(),
        earliest_unsacked_sent: None,
        unacked_reordered: false,
        pending_client_segments: VecDeque::new(),
        server_fin_pending: false,
        zero_window_probe_backoff: super::super::TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL,
        next_zero_window_probe_at: None,
        unacked_in_order_segments: 0,
        delayed_ack_deadline: None,
        keepalive_probes_sent: 0,
        last_keepalive_probe_at: None,
        reported: super::super::state_machine::ReportedFlowMetrics::default(),
        flow_gauges: None,
        timestamps: super::super::state_machine::FlowTimestamps {
            created_at: last_seen,
            status_since: last_seen,
            last_seen,
        },
        eviction_indexed_at: last_seen,
        next_scheduled_deadline: None,
    }
}

pub(in crate::tcp) async fn build_test_manager(tcp_ws_url: Url) -> UplinkManager {
    build_test_manager_with_urls(Some(tcp_ws_url), None).await
}

/// Build a single-uplink test manager, setting whichever of the TCP / UDP WS
/// dial URLs the caller supplies. Shared with the UDP-engine sniffing tests.
pub(crate) async fn build_test_manager_with_urls(
    tcp_ws_url: Option<Url>,
    udp_ws_url: Option<Url>,
) -> UplinkManager {
    UplinkManager::new_for_test(
        "test",
        vec![UplinkConfig {
            name: "test".to_string(),
            transport: UplinkTransport::Ss,
            tcp_ws_url,
            tcp_xhttp_url: None,
            tcp_mode: TransportMode::WsH1,
            udp_ws_url,
            udp_xhttp_url: None,
            udp_mode: TransportMode::WsH1,
            vless_ws_url: None,
            vless_xhttp_url: None,
            vless_mode: TransportMode::WsH1,
            ss_ws_url: None,
            ss_xhttp_url: None,
            ss_mode: None,
            cipher: CipherKind::Chacha20IetfPoly1305,
            password: "Secret0".to_string(),
            weight: 1.0,
            fwmark: None,
            ipv6_first: false,
            vless_id: None,
            fingerprint_profile: None,
            fallbacks: Vec::new(),
            shuffle_wires: false,
            carrier_downgrade: true,
            padding: None,
            shuffle_timer: None,
        }],
        ProbeConfig {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            max_concurrent: 2,
            max_dials: 1,
            min_failures: 1,
            attempts: 1,
            skip_when_active: true,
            liveness_interval: std::time::Duration::from_secs(300),
            ws: WsProbeConfig { enabled: false },
            http: None,
            dns: None,
            tcp: None,
            tls: None,
        },
        LoadBalancingConfig {
            mode: outline_uplink::LoadBalancingMode::ActiveActive,
            routing_scope: outline_uplink::RoutingScope::PerFlow,
            shared_resume: false,
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
            mode_downgrade_duration: Duration::from_secs(60),
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
            health_weight_floor: 0.05,
            vless_udp_mux_limits: outline_uplink::VlessUdpMuxLimits::default(),
            tcp_mid_session_retry_buffer_bytes: 256 * 1024,
            tcp_mid_session_retry_budget: 1,
            tcp_mid_session_retry_overflow_policy: outline_uplink::OverflowPolicy::Soft,
            tcp_mid_session_retry_consume_timeout: Duration::from_secs(5),
            tcp_symmetric_replay_enabled: true,
            tcp_symmetric_replay_max_bytes: 1_048_576,
            tun_suppress_icmp_reply_when_down: false,
            bypass_when_down: false,
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
                if let Some(packet_len) = packet_length(remaining)
                    && remaining.len() >= packet_len
                {
                    let packet = remaining[..packet_len].to_vec();
                    self.offset += packet_len;
                    return packet;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for captured TUN packet");
    }

    /// Non-blocking counterpart of [`TunCapture::next_packet`]: hands back the
    /// next fully-written packet if one is already in the capture, `None`
    /// otherwise. Lets a test assert on the *absence* of a packet (say, an RST)
    /// without waiting out a timeout it would then have to interpret.
    async fn try_next_packet(&mut self) -> Option<Vec<u8>> {
        let data = tokio::fs::read(&self.path).await.unwrap_or_default();
        let remaining = data.get(self.offset..)?;
        let packet_len = packet_length(remaining)?;
        if remaining.len() < packet_len {
            return None;
        }
        self.offset += packet_len;
        Some(remaining[..packet_len].to_vec())
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

    /// Non-blocking: the dialled target if the upstream was already reached,
    /// `None` otherwise. Lets a test assert a flow never tunneled.
    async fn try_target(&self) -> Option<Vec<u8>> {
        self.target_rx.lock().await.try_recv().ok()
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
    let ws = TransportStream::new_http1(ws);
    let (sink, stream) = ws.split();
    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher.derive_master_key("Secret0").unwrap();
    let lifetime = UpstreamTransportGuard::new("test", "tcp");
    let (mut writer, ctrl_tx) =
        TcpShadowsocksWriter::connect(sink, cipher, &master_key, Arc::clone(&lifetime)).await?;
    let request_salt = writer.request_salt();
    let mut reader = TcpShadowsocksReader::new(stream, cipher, &master_key, lifetime, ctrl_tx)
        .with_request_salt(request_salt);

    target_tx.send(reader.read_chunk().await?.to_vec()).unwrap();

    loop {
        tokio::select! {
            inbound = reader.read_chunk() => {
                match inbound {
                    Ok(chunk) => {
                        chunk_tx.send(chunk.to_vec()).unwrap();
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
