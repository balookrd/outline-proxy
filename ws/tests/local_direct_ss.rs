#[path = "support/proxy_test_utils.rs"]
mod proxy_test_utils;

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::Duration;

use outline_ws_rust::crypto::{
    SHADOWSOCKS_TAG_LEN, decrypt, decrypt_udp_packet, derive_subkey, encrypt, encrypt_udp_packet,
    increment_nonce,
};
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
                proxy.logs().unwrap_or_else(|_| "<proxy logs unavailable>".into())
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
    assert_eq!(observed.target, TargetAddr::IpV4(target_host.parse()?, target_port));
    assert_eq!(observed.payload, request_payload);

    let mut replies = Vec::new();
    let mut buf = [0u8; 4096];
    for _ in 0..5 {
        let (len, _) = client.recv_from(&mut buf).map_err(|err| {
            format!(
                "failed to receive fanout UDP response: {err}\nproxy logs:\n{}",
                proxy.logs().unwrap_or_else(|_| "<proxy logs unavailable>".into())
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

#[test]
fn tcp_half_closed_client_still_receives_response_over_local_direct_shadowsocks()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = proxy_test_utils::test_lock().lock().unwrap();

    let cipher = CipherKind::Chacha20IetfPoly1305;
    let password = "Secret0";
    let upstream = HalfCloseAwareTcpServer::start(cipher, password, 5)?;

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

    for index in 0..5 {
        let mut stream =
            proxy_test_utils::socks5_connect(proxy_port, "example.com", 80).map_err(|err| {
                format!(
                    "SOCKS5 CONNECT failed on iteration {index}: {err}\nproxy logs:\n{}",
                    proxy.logs().unwrap_or_else(|_| "<proxy logs unavailable>".into())
                )
            })?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        let request =
            format!("GET /{index} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes())?;
        stream.shutdown(Shutdown::Write)?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).map_err(|err| {
            format!(
                "failed to read tunneled response on iteration {index}: {err}\nproxy logs:\n{}",
                proxy.logs().unwrap_or_else(|_| "<proxy logs unavailable>".into())
            )
        })?;
        let text = String::from_utf8(response)?;
        assert!(text.contains("200 OK"), "unexpected HTTP response on iteration {index}: {text}");
        assert!(
            text.ends_with(&format!("response-{index}")),
            "unexpected HTTP body on iteration {index}: {text}"
        );
    }

    proxy.stop()?;
    upstream.stop()?;
    Ok(())
}

struct FanoutRequest {
    target: TargetAddr,
    payload: Vec<u8>,
}

struct HalfCloseAwareTcpServer {
    addr: SocketAddr,
    shutdown_tx: SyncSender<()>,
    thread: Option<thread::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>>,
}

impl HalfCloseAwareTcpServer {
    fn start(
        cipher: CipherKind,
        password: &str,
        expected_connections: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(false)?;
        let addr = listener.local_addr()?;
        let password = password.to_string();
        let (shutdown_tx, shutdown_rx) = mpsc::sync_channel(1);
        let thread = thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let master_key = cipher.derive_master_key(&password)?;
                for index in 0..expected_connections {
                    let (mut stream, _) = listener.accept()?;
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

                    let mut inbound = TcpSsStream::accept(&mut stream, cipher, &master_key)?;
                    let target = match inbound.read_chunk(&mut stream) {
                        Ok(target) => target,
                        Err(TcpSsReadError::CleanEof) => {
                            return Err("upstream closed before target header".into());
                        },
                        Err(TcpSsReadError::Io(err)) => return Err(err.into()),
                        Err(TcpSsReadError::Crypto(err)) => return Err(err.into()),
                    };
                    let (target, consumed) = TargetAddr::from_wire_bytes(&target)?;
                    assert_eq!(consumed, target.to_wire_bytes()?.len());

                    let mut request = Vec::new();
                    loop {
                        match inbound.read_chunk(&mut stream) {
                            Ok(chunk) => request.extend_from_slice(&chunk),
                            Err(TcpSsReadError::CleanEof) => break,
                            Err(TcpSsReadError::Io(err)) => return Err(err.into()),
                            Err(TcpSsReadError::Crypto(err)) => return Err(err.into()),
                        }
                    }

                    let request_text = String::from_utf8(request)?;
                    assert!(
                        request_text.starts_with(&format!("GET /{index} HTTP/1.1\r\n")),
                        "unexpected request on iteration {index}: {request_text}"
                    );

                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nresponse-{index}"
                    );
                    let mut outbound = TcpSsStream::new(cipher, &master_key)?;
                    outbound.write_chunk(&mut stream, response.as_bytes())?;
                    stream.shutdown(Shutdown::Write)?;
                }

                let _ = shutdown_rx.recv_timeout(Duration::from_secs(1));
                Ok(())
            },
        );
        Ok(Self { addr, shutdown_tx, thread: Some(thread) })
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn stop(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.shutdown_tx.send(());
        if let Some(thread) = self.thread.take() {
            match thread.join() {
                Ok(result) => result.map_err(|err| err as Box<dyn std::error::Error>)?,
                Err(_) => return Err("half-close TCP server thread panicked".into()),
            }
        }
        Ok(())
    }
}

struct TcpSsStream {
    cipher: CipherKind,
    key: Vec<u8>,
    nonce: [u8; 12],
    pending_salt: Option<Vec<u8>>,
}

enum TcpSsReadError {
    CleanEof,
    Io(std::io::Error),
    Crypto(anyhow::Error),
}

impl TcpSsStream {
    fn accept(
        stream: &mut TcpStream,
        cipher: CipherKind,
        master_key: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut salt = vec![0u8; cipher.salt_len()];
        stream.read_exact(&mut salt)?;
        Ok(Self {
            cipher,
            key: derive_subkey(cipher, master_key, &salt)?,
            nonce: [0u8; 12],
            pending_salt: None,
        })
    }

    fn new(
        cipher: CipherKind,
        master_key: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let salt = vec![7u8; cipher.salt_len()];
        Ok(Self {
            cipher,
            key: derive_subkey(cipher, master_key, &salt)?,
            nonce: [0u8; 12],
            pending_salt: Some(salt),
        })
    }

    fn read_chunk(&mut self, stream: &mut TcpStream) -> Result<Vec<u8>, TcpSsReadError> {
        let encrypted_len = self.read_exact(stream, 2 + SHADOWSOCKS_TAG_LEN)?;
        let len = decrypt(self.cipher, &self.key, &self.nonce, &encrypted_len)
            .map_err(TcpSsReadError::Crypto)?;
        increment_nonce(&mut self.nonce);
        let payload_len = u16::from_be_bytes([len[0], len[1]]) as usize;
        let encrypted_payload = self.read_exact(stream, payload_len + SHADOWSOCKS_TAG_LEN)?;
        let payload = decrypt(self.cipher, &self.key, &self.nonce, &encrypted_payload)
            .map_err(TcpSsReadError::Crypto)?;
        increment_nonce(&mut self.nonce);
        Ok(payload)
    }

    fn write_chunk(
        &mut self,
        stream: &mut TcpStream,
        payload: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let len = (payload.len() as u16).to_be_bytes();
        let encrypted_len = encrypt(self.cipher, &self.key, &self.nonce, &len)?;
        increment_nonce(&mut self.nonce);
        let encrypted_payload = encrypt(self.cipher, &self.key, &self.nonce, payload)?;
        increment_nonce(&mut self.nonce);

        if let Some(salt) = self.pending_salt.take() {
            stream.write_all(&salt)?;
        }
        stream.write_all(&encrypted_len)?;
        stream.write_all(&encrypted_payload)?;
        Ok(())
    }

    fn read_exact(&self, stream: &mut TcpStream, len: usize) -> Result<Vec<u8>, TcpSsReadError> {
        let mut buf = vec![0u8; len];
        match stream.read_exact(&mut buf) {
            Ok(()) => Ok(buf),
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                Err(TcpSsReadError::CleanEof)
            },
            Err(err) => Err(TcpSsReadError::Io(err)),
        }
    }
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
        let thread =
            thread::spawn(move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let master_key = cipher.derive_master_key(&password)?;
                let mut buf = [0u8; 65_535];
                let (len, peer) = socket.recv_from(&mut buf)?;
                let decrypted = decrypt_udp_packet(cipher, &master_key, &buf[..len])?;
                let (target, consumed) = TargetAddr::from_wire_bytes(&decrypted)?;
                let payload = decrypted[consumed..].to_vec();
                request_tx.send(FanoutRequest { target: target.clone(), payload })?;

                for index in 0..5 {
                    let mut response = target.to_wire_bytes()?;
                    response.extend_from_slice(format!("reply-{index}").as_bytes());
                    let packet = encrypt_udp_packet(cipher, &master_key, &response)?;
                    socket.send_to(&packet, peer)?;
                }

                let _ = shutdown_rx.recv_timeout(Duration::from_secs(5));
                Ok(())
            });
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
