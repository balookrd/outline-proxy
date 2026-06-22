//! Pure-OS socket helpers shared across outline crates.
//!
//! This crate owns low-level plumbing that is protocol-agnostic: TCP connect
//! with fwmark/keepalive, UDP bind with buffer sizing, inbound-socket
//! tuning, and the [`dns_cache`] resolution cache. It has no knowledge of
//! Shadowsocks, WebSocket, or any transport protocol — callers layer their
//! own context (e.g. `TransportOperation`) on top of the returned
//! `anyhow::Error`.

pub mod dns_cache;
pub mod ip_alias;

pub use ip_alias::{IpAliasError, IpAliasTable};

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

/// Whether outbound IPv6 sockets should pin a stable public source address
/// (RFC 5014 `IPV6_PREFER_SRC_PUBLIC`) instead of letting the OS pick a
/// rotating privacy-extension *temporary* address (RFC 4941). Defaults to
/// `true` when unset, but is auto-disabled when the host is rotating
/// (see [`ipv6_rotation_active`]).
static PREFER_PUBLIC_IPV6_SRC: OnceLock<bool> = OnceLock::new();

/// Cached system-wide IPv6 privacy-extension rotation state.
#[cfg(target_os = "linux")]
static IPV6_ROTATION_ACTIVE: OnceLock<bool> = OnceLock::new();

/// Configure whether outbound IPv6 sockets prefer a stable public source
/// address over privacy-extension temporary addresses. Set once at startup.
///
/// Direct-route connections bind no explicit source, so the kernel runs RFC
/// 6724 source selection and — with privacy extensions enabled on the host —
/// picks the current *temporary* address. When that address rotates and its
/// `valid_lft` expires the kernel removes it, tearing down every direct
/// connection that used it (observed as Yandex Maps tiles / long direct
/// flows breaking every couple of minutes). Requesting `IPV6_PREFER_SRC_PUBLIC`
/// makes the kernel pick the stable SLAAC/public address instead, which is
/// refreshed by RAs and does not rotate. Best-effort: ignored by kernels
/// that don't support the option, and a no-op on non-Linux.
pub fn init_prefer_public_ipv6_src(enabled: bool) {
    let _ = PREFER_PUBLIC_IPV6_SRC.set(enabled);
}

/// Whether IPv6 privacy-extension rotation is enabled system-wide
/// (`net.ipv6.conf.{all,default}.use_tempaddr >= 1`). Read once and cached:
/// the sysctl is set at boot and we never want this to vary per connect.
/// When rotation is on the host deliberately spreads outbound traffic across
/// temporary source addresses, so pinning a stable public source would defeat
/// it — `prefer_public_ipv6_src_enabled` backs off in that case.
#[cfg(target_os = "linux")]
fn ipv6_rotation_active() -> bool {
    *IPV6_ROTATION_ACTIVE.get_or_init(|| {
        ["all", "default"].iter().any(|scope| {
            std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{scope}/use_tempaddr"))
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
                .is_some_and(|v| v >= 1)
        })
    })
}

/// Effective stable-source preference: the configured switch (default `true`)
/// AND the host is not rotating temporary addresses. Auto-disabling under
/// rotation keeps the operator's `use_tempaddr` intent intact.
#[cfg(target_os = "linux")]
fn prefer_public_ipv6_src_enabled() -> bool {
    *PREFER_PUBLIC_IPV6_SRC.get().unwrap_or(&true) && !ipv6_rotation_active()
}

/// Best-effort `setsockopt(IPV6_ADDR_PREFERENCES, IPV6_PREFER_SRC_PUBLIC)` on
/// an IPv6 socket: prefer a stable public source over rotating
/// privacy-extension temporary addresses. No-op when the preference is off
/// (config opt-out or host rotation active) or on non-Linux. Errors are
/// ignored — an unsupported kernel just falls back to default selection.
/// Shared by the client direct path and the server outbound path.
#[cfg(target_os = "linux")]
pub fn apply_prefer_public_ipv6_src<T: AsRawFd>(socket: &T) {
    if !prefer_public_ipv6_src_enabled() {
        return;
    }
    let value: libc::c_int = libc::IPV6_PREFER_SRC_PUBLIC;
    // SAFETY: `socket` owns a valid IPv6 fd for the duration of this call;
    // `value` outlives the syscall and its size matches a `c_int` option.
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_ADDR_PREFERENCES,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        );
    }
}

#[cfg(not(target_os = "linux"))]
pub fn apply_prefer_public_ipv6_src<T>(_socket: &T) {}

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
    // The raw socket2 path is required whenever we must touch the socket
    // before connect: to set SO_MARK (fwmark) or to request a stable public
    // IPv6 source (IPV6_PREFER_SRC_PUBLIC). Otherwise use tokio's async
    // connector so we never block a Tokio worker thread on the handshake.
    if fwmark.is_none() && !prefer_public_raw_needed(addr) {
        let stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("failed to connect TCP socket to {addr}"))?;
        configure_tcp_stream_low_latency(&stream, addr)?;
        return Ok(stream);
    }
    connect_tcp_socket_raw(addr, fwmark).await
}

/// Whether the IPv6 stable-source preference forces the raw socket2 path.
/// Linux-only: on other platforms the option is a no-op, so a plain
/// fwmark-less connect keeps using tokio's fast path.
#[cfg(target_os = "linux")]
fn prefer_public_raw_needed(addr: SocketAddr) -> bool {
    addr.is_ipv6() && prefer_public_ipv6_src_enabled()
}

#[cfg(not(target_os = "linux"))]
fn prefer_public_raw_needed(_addr: SocketAddr) -> bool {
    false
}

/// Raw socket2 path: lets us touch the socket before connect to set SO_MARK
/// (fwmark) and/or request a stable public IPv6 source
/// (`IPV6_PREFER_SRC_PUBLIC`). `fwmark` is Linux-only; the stable-IPv6
/// preference is best-effort and applied only to IPv6 sockets.
#[cfg(target_os = "linux")]
async fn connect_tcp_socket_raw(addr: SocketAddr, fwmark: Option<u32>) -> Result<TcpStream> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(SocketProtocol::TCP))
        .context("failed to create TCP socket")?;
    apply_fwmark(&socket, fwmark)?;
    if addr.is_ipv6() {
        apply_prefer_public_ipv6_src(&socket);
    }
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
        Err(e) => {
            return Err(e).with_context(|| format!("failed to connect TCP socket to {addr}"));
        },
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
async fn connect_tcp_socket_raw(_addr: SocketAddr, _fwmark: Option<u32>) -> Result<TcpStream> {
    bail!("fwmark is only supported on Linux")
}

pub fn bind_udp_socket(bind_addr: SocketAddr, fwmark: Option<u32>) -> Result<std::net::UdpSocket> {
    let socket =
        Socket::new(Domain::for_address(bind_addr), Type::DGRAM, Some(SocketProtocol::UDP))
            .context("failed to create UDP socket")?;
    if bind_addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
        // Same rationale as the TCP path: when binding the unspecified IPv6
        // address the kernel picks the source at send time — prefer the
        // stable public address over a rotating privacy-extension temporary.
        apply_prefer_public_ipv6_src(&socket);
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

pub fn bind_addr_for(server_addr: SocketAddr) -> SocketAddr {
    match server_addr.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
