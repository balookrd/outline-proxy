#![allow(dead_code)]

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn run_tcp_connect_test(
    run_env: &str,
    label: &str,
    mode: &str,
    env_prefix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _guard = test_lock().lock().unwrap();
    if env::var(run_env).ok().as_deref() != Some("1") {
        eprintln!("skipping real {label} integration test; set {run_env}=1 to enable");
        return Ok(());
    }

    let tcp_ws_url = required_env("OUTLINE_TCP_WS_URL")?;
    let udp_ws_url = env::var("OUTLINE_UDP_WS_URL").ok();
    let password = required_env("SHADOWSOCKS_PASSWORD")?;
    let method =
        env::var("SHADOWSOCKS_METHOD").unwrap_or_else(|_| "chacha20-ietf-poly1305".to_string());
    let target_host =
        env::var(format!("{env_prefix}_TEST_TARGET_HOST")).unwrap_or_else(|_| "example.com".into());
    let target_port: u16 = env::var(format!("{env_prefix}_TEST_TARGET_PORT"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(80);

    let temp = TestDir::new()?;
    let proxy_port = reserve_tcp_port()?;
    let config_path = temp.path().join("proxy.toml");

    let mut config = format!(
        r#"
[socks5]
listen = "127.0.0.1:{proxy_port}"

[outline]
tcp_ws_url = "{tcp_ws_url}"
tcp_mode = "{mode}"
method = "{method}"
password = "{password}"
"#
    );
    if let Some(udp_ws_url) = udp_ws_url {
        config.push_str(&format!(
            r#"
udp_ws_url = "{udp_ws_url}"
udp_mode = "{mode}"
"#
        ));
    }
    fs::write(&config_path, config)?;

    let log_path = temp.path().join("proxy.log");
    let mut proxy = ProxyProcess::start(&config_path, &log_path)?;
    proxy.wait_ready(proxy_port, Duration::from_secs(15))?;

    let mut stream = socks5_connect(proxy_port, &target_host, target_port).map_err(|err| {
        format!(
            "SOCKS5 CONNECT failed: {err}\nproxy logs:\n{}",
            proxy.logs().unwrap_or_else(|_| "<proxy logs unavailable>".into())
        )
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let request = format!("GET / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;

    let mut response = [0u8; 512];
    let n = stream.read(&mut response).map_err(|err| {
        format!(
            "failed to read tunneled response: {err}\nproxy logs:\n{}",
            proxy.logs().unwrap_or_else(|_| "<proxy logs unavailable>".into())
        )
    })?;
    let text = String::from_utf8_lossy(&response[..n]);
    assert!(
        text.starts_with("HTTP/1.1 ") || text.starts_with("HTTP/1.0 "),
        "unexpected HTTP response over tunnel: {text}"
    );

    proxy.stop()?;
    Ok(())
}

pub fn run_udp_associate_test(
    run_env: &str,
    label: &str,
    mode: &str,
    env_prefix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _guard = test_lock().lock().unwrap();
    if env::var(run_env).ok().as_deref() != Some("1") {
        eprintln!("skipping real {label} integration test; set {run_env}=1 to enable");
        return Ok(());
    }

    let tcp_ws_url = required_env("OUTLINE_TCP_WS_URL")?;
    let udp_ws_url = required_env("OUTLINE_UDP_WS_URL")?;
    let password = required_env("SHADOWSOCKS_PASSWORD")?;
    let method =
        env::var("SHADOWSOCKS_METHOD").unwrap_or_else(|_| "chacha20-ietf-poly1305".to_string());
    let dns_server =
        env::var(format!("{env_prefix}_TEST_DNS_SERVER")).unwrap_or_else(|_| "1.1.1.1".into());
    let dns_port: u16 = env::var(format!("{env_prefix}_TEST_DNS_PORT"))
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(53);
    let dns_name =
        env::var(format!("{env_prefix}_TEST_DNS_NAME")).unwrap_or_else(|_| "example.com".into());

    let temp = TestDir::new()?;
    let proxy_port = reserve_tcp_port()?;
    let config_path = temp.path().join("proxy.toml");

    let config = format!(
        r#"
[socks5]
listen = "127.0.0.1:{proxy_port}"

[outline]
tcp_ws_url = "{tcp_ws_url}"
tcp_mode = "{mode}"
udp_ws_url = "{udp_ws_url}"
udp_mode = "{mode}"
method = "{method}"
password = "{password}"
"#
    );
    fs::write(&config_path, config)?;

    let log_path = temp.path().join("proxy.log");
    let mut proxy = ProxyProcess::start(&config_path, &log_path)?;
    proxy.wait_ready(proxy_port, Duration::from_secs(15))?;

    let (_control, relay_addr) = socks5_udp_associate(proxy_port).map_err(|err| {
        format!(
            "SOCKS5 UDP ASSOCIATE failed: {err}\nproxy logs:\n{}",
            proxy.logs().unwrap_or_else(|_| "<proxy logs unavailable>".into())
        )
    })?;

    let client = UdpSocket::bind(("127.0.0.1", 0))?;
    client.set_read_timeout(Some(Duration::from_secs(10)))?;
    client.set_write_timeout(Some(Duration::from_secs(10)))?;

    let dns_query = build_dns_query(&dns_name)?;
    let packet = build_udp_packet(&dns_server, dns_port, &dns_query)?;
    client.send_to(&packet, relay_addr)?;

    let mut buf = [0u8; 4096];
    let (n, _) = client.recv_from(&mut buf).map_err(|err| {
        format!(
            "failed to receive UDP response: {err}\nproxy logs:\n{}",
            proxy.logs().unwrap_or_else(|_| "<proxy logs unavailable>".into())
        )
    })?;

    let response = parse_udp_packet(&buf[..n])?;
    assert_eq!(response.host, dns_server);
    assert_eq!(response.port, dns_port);
    assert!(response.payload.len() >= 12, "DNS response too short");
    assert_eq!(&response.payload[..2], &dns_query[..2], "DNS transaction id mismatch");
    assert!(response.payload[3] & 0x0f == 0, "DNS response code is non-zero");

    proxy.stop()?;
    Ok(())
}

pub fn required_env(key: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(key).map_err(|_| format!("missing required env var: {key}").into())
}

pub fn test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub struct ProxyProcess {
    child: Child,
    log_path: PathBuf,
}

impl ProxyProcess {
    pub fn start(config_path: &Path, log_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let binary = env!("CARGO_BIN_EXE_outline-ws-rust");
        let stdout = fs::OpenOptions::new().create(true).append(true).open(log_path)?;
        let stderr = fs::OpenOptions::new().create(true).append(true).open(log_path)?;
        let child = Command::new(binary)
            .arg("--config")
            .arg(config_path)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?;
        Ok(Self { child, log_path: log_path.to_path_buf() })
    }

    pub fn wait_ready(
        &mut self,
        port: u16,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Ok(());
            }
            if self.child.try_wait()?.is_some() {
                return Err(format!("proxy exited early:\n{}", self.logs()?).into());
            }
            thread::sleep(Duration::from_millis(200));
        }
        Err(
            format!("timed out waiting for proxy on port {}.\nlogs:\n{}", port, self.logs()?)
                .into(),
        )
    }

    pub fn logs(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(fs::read_to_string(&self.log_path).unwrap_or_default())
    }

    pub fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
            let _ = self.child.wait()?;
        }
        Ok(())
    }
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub fn socks5_connect(
    proxy_port: u16,
    host: &str,
    port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut method_reply = [0u8; 2];
    stream.read_exact(&mut method_reply)?;
    if method_reply != [0x05, 0x00] {
        return Err(format!("unexpected socks method reply: {method_reply:?}").into());
    }

    let host_len: u8 = host.len().try_into()?;
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host_len];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request)?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(format!("unexpected socks reply header: {head:?}").into());
    }

    match head[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest)?;
        },
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut rest)?;
        },
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest)?;
        },
        atyp => return Err(format!("unsupported socks reply atyp: {atyp}").into()),
    }

    Ok(stream)
}

pub fn socks5_udp_associate(
    proxy_port: u16,
) -> Result<(TcpStream, std::net::SocketAddr), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut method_reply = [0u8; 2];
    stream.read_exact(&mut method_reply)?;
    if method_reply != [0x05, 0x00] {
        return Err(format!("unexpected socks method reply: {method_reply:?}").into());
    }

    stream.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
    let relay_addr = read_socks_bound_addr(&mut stream)?;
    Ok((stream, relay_addr))
}

fn read_socks_bound_addr(
    stream: &mut TcpStream,
) -> Result<std::net::SocketAddr, Box<dyn std::error::Error>> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(format!("unexpected socks reply header: {head:?}").into());
    }

    let addr = match head[3] {
        0x01 => {
            let mut raw = [0u8; 6];
            stream.read_exact(&mut raw)?;
            std::net::SocketAddr::from((
                [raw[0], raw[1], raw[2], raw[3]],
                u16::from_be_bytes([raw[4], raw[5]]),
            ))
        },
        0x04 => {
            let mut raw = [0u8; 18];
            stream.read_exact(&mut raw)?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&raw[..16]);
            std::net::SocketAddr::from((ip, u16::from_be_bytes([raw[16], raw[17]])))
        },
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut rest)?;
            return Err("domain socks bound address is not supported in test".into());
        },
        atyp => return Err(format!("unsupported socks reply atyp: {atyp}").into()),
    };
    Ok(addr)
}

pub fn build_udp_packet(
    host: &str,
    port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = vec![0x00, 0x00, 0x00];
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ip) => {
                out.push(0x01);
                out.extend_from_slice(&ip.octets());
            },
            IpAddr::V6(ip) => {
                out.push(0x04);
                out.extend_from_slice(&ip.octets());
            },
        }
    } else {
        let host_len: u8 = host.len().try_into()?;
        out.push(0x03);
        out.push(host_len);
        out.extend_from_slice(host.as_bytes());
    }
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub struct UdpDomainPacket {
    pub host: String,
    pub port: u16,
    pub payload: Vec<u8>,
}

pub fn parse_udp_packet(packet: &[u8]) -> Result<UdpDomainPacket, Box<dyn std::error::Error>> {
    if packet.len() < 7 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return Err("invalid SOCKS5 UDP packet".into());
    }
    match packet[3] {
        0x01 => parse_udp_ipv4_packet(packet),
        0x03 => parse_udp_domain_packet(packet),
        0x04 => parse_udp_ipv6_packet(packet),
        atyp => Err(format!("unexpected UDP address type: {atyp}").into()),
    }
}

fn parse_udp_ipv4_packet(packet: &[u8]) -> Result<UdpDomainPacket, Box<dyn std::error::Error>> {
    if packet.len() < 10 {
        return Err("short SOCKS5 UDP IPv4 packet".into());
    }
    let ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
    let port = u16::from_be_bytes([packet[8], packet[9]]);
    Ok(UdpDomainPacket {
        host: ip.to_string(),
        port,
        payload: packet[10..].to_vec(),
    })
}

fn parse_udp_domain_packet(packet: &[u8]) -> Result<UdpDomainPacket, Box<dyn std::error::Error>> {
    let host_len = packet[4] as usize;
    let host_end = 5 + host_len;
    if packet.len() < host_end + 2 {
        return Err("short SOCKS5 UDP domain packet".into());
    }

    Ok(UdpDomainPacket {
        host: String::from_utf8(packet[5..host_end].to_vec())?,
        port: u16::from_be_bytes([packet[host_end], packet[host_end + 1]]),
        payload: packet[host_end + 2..].to_vec(),
    })
}

fn parse_udp_ipv6_packet(packet: &[u8]) -> Result<UdpDomainPacket, Box<dyn std::error::Error>> {
    if packet.len() < 22 {
        return Err("short SOCKS5 UDP IPv6 packet".into());
    }
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&packet[4..20]);
    let ip = Ipv6Addr::from(raw);
    let port = u16::from_be_bytes([packet[20], packet[21]]);
    Ok(UdpDomainPacket {
        host: ip.to_string(),
        port,
        payload: packet[22..].to_vec(),
    })
}

pub fn build_dns_query(name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    for label in name.split('.') {
        let len: u8 = label.len().try_into()?;
        out.push(len);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0x00);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    Ok(out)
}

pub fn reserve_tcp_port() -> Result<u16, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

pub struct TestDir {
    path: PathBuf,
}

impl TestDir {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let path = env::temp_dir().join(format!("outline-ws-rust-{}", unique_suffix()));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    nanos.to_string()
}
