#[path = "support/proxy_test_utils.rs"]
mod proxy_test_utils;

use std::fs;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::Duration;

use outline_ws_rust::crypto::{decrypt_udp_packet, encrypt_udp_packet};
use outline_ws_rust::types::{CipherKind, TargetAddr};

#[test]
fn udp_single_packet_can_receive_five_replies_over_local_direct_shadowsocks()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = proxy_test_utils::test_lock().lock().unwrap();

    let cipher = CipherKind::Chacha20IetfPoly1305;
    let password = "Secret0";
    let upstream = FanoutUdpServer::start(cipher, password)?;

    let temp = proxy_test_utils::TestDir::new()?;
    let proxy_port = proxy_test_utils::reserve_tcp_port()?;
    let config_path = temp.path().join("proxy.toml");
    fs::write(
        &config_path,
        format!(
            r#"
transport = "shadowsocks"
tcp_addr = "{upstream_addr}"
udp_addr = "{upstream_addr}"
method = "chacha20-ietf-poly1305"
password = "{password}"

[socks5]
listen = "127.0.0.1:{proxy_port}"
"#,
            upstream_addr = upstream.addr(),
        ),
    )?;

    let log_path = temp.path().join("proxy.log");
    let mut proxy = proxy_test_utils::ProxyProcess::start(&config_path, &log_path)?;
    proxy.wait_ready(proxy_port, Duration::from_secs(15))?;

    let (_control, relay_addr) =
        proxy_test_utils::socks5_udp_associate(proxy_port).map_err(|err| {
            format!(
                "SOCKS5 UDP ASSOCIATE failed: {err}\nproxy logs:\n{}",
                proxy
                    .logs()
                    .unwrap_or_else(|_| "<proxy logs unavailable>".into())
            )
        })?;

    let client = UdpSocket::bind(("127.0.0.1", 0))?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    client.set_write_timeout(Some(Duration::from_secs(5)))?;

    let target_host = "203.0.113.7";
    let target_port = 5300;
    let request_payload = b"fanout-check";
    let packet = proxy_test_utils::build_udp_packet(target_host, target_port, request_payload)?;
    client.send_to(&packet, relay_addr)?;

    let observed = upstream.wait_for_request()?;
    assert_eq!(
        observed.target,
        TargetAddr::IpV4(target_host.parse()?, target_port)
    );
    assert_eq!(observed.payload, request_payload);

    let mut replies = Vec::new();
    let mut buf = [0u8; 4096];
    for _ in 0..5 {
        let (len, _) = client.recv_from(&mut buf).map_err(|err| {
            format!(
                "failed to receive fanout UDP response: {err}\nproxy logs:\n{}",
                proxy
                    .logs()
                    .unwrap_or_else(|_| "<proxy logs unavailable>".into())
            )
        })?;
        let response = proxy_test_utils::parse_udp_packet(&buf[..len])?;
        assert_eq!(response.host, target_host);
        assert_eq!(response.port, target_port);
        replies.push(String::from_utf8(response.payload)?);
    }
    assert_eq!(
        replies,
        vec![
            "reply-0".to_string(),
            "reply-1".to_string(),
            "reply-2".to_string(),
            "reply-3".to_string(),
            "reply-4".to_string(),
        ]
    );

    proxy.stop()?;
    upstream.stop()?;
    Ok(())
}

struct FanoutRequest {
    target: TargetAddr,
    payload: Vec<u8>,
}

struct FanoutUdpServer {
    addr: SocketAddr,
    request_rx: Receiver<FanoutRequest>,
    shutdown_tx: SyncSender<()>,
    thread: Option<thread::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>>,
}

impl FanoutUdpServer {
    fn start(cipher: CipherKind, password: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(("127.0.0.1", 0))?;
        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
        socket.set_write_timeout(Some(Duration::from_secs(10)))?;
        let addr = socket.local_addr()?;
        let password = password.to_string();
        let (request_tx, request_rx) = mpsc::sync_channel(1);
        let (shutdown_tx, shutdown_rx) = mpsc::sync_channel(1);
        let thread = thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let master_key = cipher.derive_master_key(&password)?;
                let mut buf = [0u8; 65_535];
                let (len, peer) = socket.recv_from(&mut buf)?;
                let decrypted = decrypt_udp_packet(cipher, &master_key, &buf[..len])?;
                let (target, consumed) = TargetAddr::from_wire_bytes(&decrypted)?;
                let payload = decrypted[consumed..].to_vec();
                request_tx.send(FanoutRequest {
                    target: target.clone(),
                    payload,
                })?;

                for index in 0..5 {
                    let mut response = target.to_wire_bytes()?;
                    response.extend_from_slice(format!("reply-{index}").as_bytes());
                    let packet = encrypt_udp_packet(cipher, &master_key, &response)?;
                    socket.send_to(&packet, peer)?;
                }

                let _ = shutdown_rx.recv_timeout(Duration::from_secs(5));
                Ok(())
            },
        );
        Ok(Self {
            addr,
            request_rx,
            shutdown_tx,
            thread: Some(thread),
        })
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn wait_for_request(&self) -> Result<FanoutRequest, Box<dyn std::error::Error>> {
        self.request_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|err| format!("timed out waiting for upstream UDP request: {err}").into())
    }

    fn stop(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.shutdown_tx.send(());
        if let Some(thread) = self.thread.take() {
            match thread.join() {
                Ok(result) => result.map_err(|err| err as Box<dyn std::error::Error>)?,
                Err(_) => return Err("fanout UDP server thread panicked".into()),
            }
        }
        Ok(())
    }
}
