//! End-to-end QUIC connection-sniffing tests for the UDP engine: drive a real
//! QUIC Initial datagram through `handle_packet` and assert the destination
//! the upstream receives (encoded in the SS-UDP frame) was rewritten to the
//! sniffed SNI domain — or left as the literal IP when it should be.

use std::net::Ipv4Addr;
use std::time::Duration;

use futures_util::StreamExt;
use shadowsocks_crypto::{CipherKind, decrypt_udp_packet};
use socks5_proto::TargetAddr;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use crate::SharedTunWriter;
use crate::quic_sniff::test_vectors::{build_initial, client_hello};
use crate::tcp::engine::tests::build_test_manager_with_urls;
use crate::udp::TunUdpEngine;

const QUIC_V1: u32 = 0x0000_0001;
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const REMOTE_PORT: u16 = 443;

/// A WS upstream that decrypts each inbound SS-UDP frame and reports the
/// encoded destination target + payload, mirroring what the server resolves.
struct TestUdpUpstream {
    url: Url,
    decoded_rx: Mutex<mpsc::UnboundedReceiver<(TargetAddr, Vec<u8>)>>,
}

impl TestUdpUpstream {
    async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let ws = accept_async(stream).await.unwrap();
            let (_sink, mut read) = ws.split();
            let cipher = CipherKind::Chacha20IetfPoly1305;
            let master_key = cipher.derive_master_key("Secret0").unwrap();
            while let Some(Ok(message)) = read.next().await {
                if let Message::Binary(bytes) = message
                    && let Ok(plain) = decrypt_udp_packet(cipher, &master_key, &bytes[..])
                    && let Ok((target, consumed)) = TargetAddr::from_wire_bytes(&plain)
                {
                    let payload = plain[consumed..].to_vec();
                    let _ = tx.send((target, payload));
                }
            }
        });
        Self {
            url: Url::parse(&format!("ws://{addr}/udp")).unwrap(),
            decoded_rx: Mutex::new(rx),
        }
    }

    async fn expect_decoded(&self) -> (TargetAddr, Vec<u8>) {
        tokio::time::timeout(Duration::from_secs(3), async {
            self.decoded_rx.lock().await.recv().await
        })
        .await
        .expect("timed out waiting for upstream UDP datagram")
        .expect("upstream channel closed")
    }
}

fn test_tun_writer() -> SharedTunWriter {
    let path =
        std::env::temp_dir().join(format!("outline-tun-udp-sniff-{}.bin", rand::random::<u64>()));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    SharedTunWriter::new(file)
}

async fn build_engine(upstream_url: Url, sniff_quic: bool) -> TunUdpEngine {
    let manager = build_test_manager_with_urls(None, Some(upstream_url)).await;
    TunUdpEngine::new(
        test_tun_writer(),
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        false,
        sniff_quic,
        Vec::new().into(),
    )
}

async fn send_client_datagram(engine: &TunUdpEngine, client_port: u16, payload: &[u8]) {
    let bytes =
        crate::udp::build_ipv4_udp_packet(CLIENT_IP, REMOTE_IP, client_port, REMOTE_PORT, payload)
            .unwrap();
    let parsed = crate::udp::parse_udp_packet(&bytes).unwrap();
    engine.handle_packet(parsed).await.unwrap();
}

fn quic_initial(sni: &str) -> Vec<u8> {
    let dcid = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];
    build_initial(QUIC_V1, &dcid, &client_hello(sni))
}

#[tokio::test]
async fn tun_udp_sniffs_quic_initial_and_overrides_target_with_domain() {
    let upstream = TestUdpUpstream::start().await;
    let engine = build_engine(upstream.url.clone(), true).await;

    let initial = quic_initial("example.com");
    send_client_datagram(&engine, 40000, &initial).await;

    let (target, payload) = upstream.expect_decoded().await;
    assert_eq!(target, TargetAddr::Domain("example.com".to_string(), REMOTE_PORT));
    // The Initial itself is forwarded upstream unchanged.
    assert_eq!(payload, initial);
}

#[tokio::test]
async fn tun_udp_override_persists_across_subsequent_datagrams() {
    let upstream = TestUdpUpstream::start().await;
    let engine = build_engine(upstream.url.clone(), true).await;

    // First datagram: the QUIC Initial pins the flow to the domain.
    send_client_datagram(&engine, 40010, &quic_initial("cdn.example.org")).await;
    let (first, _) = upstream.expect_decoded().await;
    assert_eq!(first, TargetAddr::Domain("cdn.example.org".to_string(), REMOTE_PORT));

    // Second datagram on the same flow is not a QUIC Initial, yet it must still
    // be framed for the overridden domain (per-flow override persistence).
    send_client_datagram(&engine, 40010, b"\x00\x01\x02\x03 later datagram").await;
    let (second, _) = upstream.expect_decoded().await;
    assert_eq!(second, TargetAddr::Domain("cdn.example.org".to_string(), REMOTE_PORT));
}

#[tokio::test]
async fn tun_udp_non_quic_first_datagram_keeps_ip_target() {
    let upstream = TestUdpUpstream::start().await;
    let engine = build_engine(upstream.url.clone(), true).await;

    // A plain (non-QUIC) datagram is not sniffable: the IP target stands.
    send_client_datagram(&engine, 40020, b"not a quic initial").await;

    let (target, _) = upstream.expect_decoded().await;
    assert_eq!(target, TargetAddr::IpV4(REMOTE_IP, REMOTE_PORT));
}

#[tokio::test]
async fn tun_udp_quic_excluded_host_keeps_ip_target() {
    let upstream = TestUdpUpstream::start().await;
    let manager = build_test_manager_with_urls(None, Some(upstream.url.clone())).await;
    let exclude: std::sync::Arc<[Box<str>]> = vec!["example.com".into()].into();
    let engine = TunUdpEngine::new(
        test_tun_writer(),
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        false,
        true,
        exclude,
    );

    // Sniffing is on, but example.com is excluded → keep the literal IP.
    send_client_datagram(&engine, 40040, &quic_initial("example.com")).await;
    let (target, _) = upstream.expect_decoded().await;
    assert_eq!(target, TargetAddr::IpV4(REMOTE_IP, REMOTE_PORT));
}

#[tokio::test]
async fn tun_udp_sniffing_disabled_keeps_ip_target() {
    let upstream = TestUdpUpstream::start().await;
    let engine = build_engine(upstream.url.clone(), false).await;

    // Even a real QUIC Initial is dialled by IP when sniff_quic is off.
    send_client_datagram(&engine, 40030, &quic_initial("example.com")).await;

    let (target, _) = upstream.expect_decoded().await;
    assert_eq!(target, TargetAddr::IpV4(REMOTE_IP, REMOTE_PORT));
}
