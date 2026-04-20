#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use anyhow::{Context, Result};
use socket2::{Domain, Protocol as SocketProtocol, Socket, TcpKeepalive, Type};
use std::mem::ManuallyDrop;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::net::TcpStream;

static UDP_RECV_BUF_BYTES: OnceLock<usize> = OnceLock::new();
static UDP_SEND_BUF_BYTES: OnceLock<usize> = OnceLock::new();

/// Initialise UDP socket buffer overrides from config. When set, every UDP
/// socket created by `bind_udp_socket` will request the given buffer sizes
/// from the kernel via `SO_RCVBUF` / `SO_SNDBUF`. The kernel may silently
/// cap the value to `/proc/sys/net/core/rmem_max` (Linux). `None` leaves
/// the kernel default unchanged.
pub fn init_udp_socket_bufs(recv: Option<usize>, send: Option<usize>) {
    if let Some(v) = recv {
        UDP_RECV_BUF_BYTES.get_or_init(|| v);
    }
    if let Some(v) = send {
        UDP_SEND_BUF_BYTES.get_or_init(|| v);
    }
}

pub async fn connect_tcp_socket(addr: SocketAddr, fwmark: Option<u32>) -> Result<TcpStream> {
    // For connections without fwmark use tokio's async connector so we never
    // block a Tokio worker thread waiting for the TCP handshake to complete.
    if fwmark.is_none() {
        let stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("failed to connect TCP socket to {addr}"))?;
        configure_tcp_stream_low_latency(&stream, addr)?;
        return Ok(stream);
    }
    connect_tcp_socket_with_fwmark(addr, fwmark).await
}

/// fwmark variant: needs SO_MARK set on the raw socket before connect, which
/// requires socket2.  Only supported on Linux; on other platforms apply_fwmark
/// returns Err before we reach the connect logic.
#[cfg(target_os = "linux")]
async fn connect_tcp_socket_with_fwmark(
    addr: SocketAddr,
    fwmark: Option<u32>,
) -> Result<TcpStream> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(SocketProtocol::TCP))
        .context("failed to create TCP socket")?;
    apply_fwmark(&socket, fwmark)?;
    // Set non-blocking BEFORE connect so that the handshake is driven by tokio
    // instead of blocking the current thread.
    socket
        .set_nonblocking(true)
        .context("failed to set TCP socket nonblocking")?;
    // Non-blocking connect: returns EINPROGRESS while the handshake is in flight.
    match socket.connect(&addr.into()) {
        Ok(()) => {},
        Err(e)
            if e.raw_os_error() == Some(libc::EINPROGRESS)
                || e.kind() == std::io::ErrorKind::WouldBlock =>
        {
            // Connection in progress; writable() below will signal completion.
        },
        Err(e) => return Err(e).with_context(|| format!("failed to connect TCP socket to {addr}")),
    }
    let stream =
        TcpStream::from_std(socket.into()).context("failed to adopt TCP socket into tokio")?;
    // Yield to the runtime until the OS signals that the socket is writable,
    // which means the three-way handshake completed (or failed).
    stream
        .writable()
        .await
        .with_context(|| format!("failed waiting for TCP connect to {addr}"))?;
    // Retrieve the actual connect result via getsockopt(SO_ERROR).
    if let Some(err) = stream.take_error().context("failed to retrieve TCP socket error")? {
        return Err(err).with_context(|| format!("TCP connection to {addr} failed"));
    }
    configure_tcp_stream_low_latency(&stream, addr)?;
    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
async fn connect_tcp_socket_with_fwmark(
    _addr: SocketAddr,
    _fwmark: Option<u32>,
) -> Result<TcpStream> {
    bail!("fwmark is only supported on Linux")
}

pub fn bind_udp_socket(
    bind_addr: SocketAddr,
    fwmark: Option<u32>,
) -> Result<std::net::UdpSocket> {
    let socket =
        Socket::new(Domain::for_address(bind_addr), Type::DGRAM, Some(SocketProtocol::UDP))
            .context("failed to create UDP socket")?;
    if bind_addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    apply_fwmark(&socket, fwmark)?;
    if let Some(&size) = UDP_RECV_BUF_BYTES.get() {
        let _ = socket.set_recv_buffer_size(size);
    }
    if let Some(&size) = UDP_SEND_BUF_BYTES.get() {
        let _ = socket.set_send_buffer_size(size);
    }
    socket
        .set_nonblocking(true)
        .context("failed to set UDP socket nonblocking")?;
    socket
        .bind(&bind_addr.into())
        .with_context(|| format!("failed to bind UDP socket on {bind_addr}"))?;
    Ok(socket.into())
}

fn configure_tcp_stream_low_latency(stream: &TcpStream, addr: SocketAddr) -> Result<()> {
    stream
        .set_nodelay(true)
        .with_context(|| format!("failed to enable TCP_NODELAY for {addr}"))?;
    // Keep idle connections alive through NAT/middlebox timeouts that would
    // otherwise silently drop the TCP flow (common with SOCKS5-QUIC bridging
    // and router-level conntrack like hev-socks5-tunnel).  Tight budget —
    // first probe at 30 s, then every 10 s × 3 retries — means a dead uplink
    // is detected within ~60 s and gets surfaced as a write error so the
    // session can fail over instead of hanging on an H2/H3 shared connection.
    apply_tcp_keepalive(stream, addr, 30, 10, 3)
}

/// Configure an inbound SOCKS5 client socket (the one we accepted from
/// e.g. a TUN → SOCKS5 layer like sing-box / clash / mihomo).  These
/// layers frequently apply aggressive per-connection idle timeouts
/// (observed at 20 s with perfect clustering in the field), tearing
/// down long-lived TCP tunnels (SSH, long-polling HTTPS, etc.) the
/// moment no application bytes flow.  Enable TCP_NODELAY for
/// interactive latency and a short TCP keepalive so the kernel emits
/// zero-payload probes every ~10 s — conntrack in the TUN layer sees
/// these as packet activity and does not declare the flow idle.
pub fn configure_inbound_tcp_stream(stream: &TcpStream, peer: SocketAddr) -> Result<()> {
    stream
        .set_nodelay(true)
        .with_context(|| format!("failed to enable TCP_NODELAY on inbound socket from {peer}"))?;
    apply_tcp_keepalive(stream, peer, 10, 5, 6)
}

fn apply_tcp_keepalive(
    stream: &TcpStream,
    addr: SocketAddr,
    idle_secs: u64,
    interval_secs: u64,
    #[allow(unused_variables)] retries: u32,
) -> Result<()> {
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(idle_secs))
        .with_interval(Duration::from_secs(interval_secs));
    #[cfg(target_os = "linux")]
    let keepalive = keepalive.with_retries(retries);
    // SAFETY: `ManuallyDrop` prevents socket2 from closing the fd, which
    // remains owned by `stream` throughout.
    let raw_socket = ManuallyDrop::new(unsafe { Socket::from_raw_fd(stream.as_raw_fd()) });
    raw_socket
        .set_tcp_keepalive(&keepalive)
        .with_context(|| format!("failed to enable TCP keepalive for {addr}"))
}

fn apply_fwmark(socket: &Socket, fwmark: Option<u32>) -> Result<()> {
    let Some(mark) = fwmark else {
        return Ok(());
    };
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        let value = mark as libc::c_uint;
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to apply SO_MARK={mark}"));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _mark = mark;
        let _ = socket;
        bail!("fwmark is only supported on Linux")
    }
}

pub(crate) fn bind_addr_for(server_addr: SocketAddr) -> SocketAddr {
    match server_addr.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}
