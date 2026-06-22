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

// ── Direct-route IPv6 prefix rotation ────────────────────────────────────────

/// Interface whose current global /64 seeds random source addresses for
/// direct-route IPv6 sockets. `None`/unset → feature off (kernel default
/// source + stable-public preference). Set once at startup from config.
static DIRECT_V6_PREFIX_IFACE: OnceLock<Option<String>> = OnceLock::new();

/// Configure the interface used to derive a rotating /64 source prefix for
/// direct-route IPv6 dials. The client mirror of the server's
/// `outbound_ipv6_prefix_interface`: each direct IPv6 connect/bind picks a
/// random address from the interface's current global /64 (re-read per connect
/// from `/proc/net/if_inet6`, so it follows a dynamic upstream prefix). The
/// whole /64 must be routed back to the host (NDP proxy / ndppd), since the
/// random addresses are not configured on the interface.
pub fn init_direct_ipv6_prefix_iface(iface: Option<String>) {
    let _ = DIRECT_V6_PREFIX_IFACE.set(iface);
}

/// A random source address from the configured direct /64, or `None` when the
/// feature is off, the target is not IPv6, or the interface has no usable
/// global address right now.
#[cfg(target_os = "linux")]
fn direct_source_for(addr: SocketAddr) -> Option<Ipv6Addr> {
    if !addr.is_ipv6() {
        return None;
    }
    let iface = DIRECT_V6_PREFIX_IFACE.get().and_then(|o| o.as_deref())?;
    let net = current_interface_prefix64(iface)?;
    Some(random_addr_in_prefix64(net))
}

/// The current global /64 (network address) on `iface`: the first live
/// global-unicast address in `/proc/net/if_inet6`, masked to /64. Skips
/// deprecated / tentative / dadfailed addresses so a rotating temporary that
/// is about to be removed never seeds the prefix.
#[cfg(target_os = "linux")]
fn current_interface_prefix64(iface: &str) -> Option<Ipv6Addr> {
    // IFA_F_TENTATIVE | IFA_F_DEPRECATED | IFA_F_DADFAILED
    const SKIP_FLAGS: u32 = 0x40 | 0x20 | 0x08;
    let content = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    for line in content.lines() {
        // Columns: <32-hex addr> <ifindex> <prefixlen> <scope> <flags> <dev>.
        let mut cols = line.split_whitespace();
        let (Some(addr_hex), Some(_idx), Some(_plen), Some(scope_hex), Some(flags_hex), Some(dev)) =
            (cols.next(), cols.next(), cols.next(), cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        if dev != iface || addr_hex.len() != 32 {
            continue;
        }
        if u32::from_str_radix(scope_hex, 16).unwrap_or(u32::MAX) != 0 {
            continue; // scope 0 == global
        }
        if u32::from_str_radix(flags_hex, 16).unwrap_or(0) & SKIP_FLAGS != 0 {
            continue;
        }
        let mut bytes = [0_u8; 16];
        let parsed = (0..16).try_for_each(|i| {
            u8::from_str_radix(&addr_hex[i * 2..i * 2 + 2], 16).map(|b| bytes[i] = b)
        });
        if parsed.is_err() {
            continue;
        }
        if (u16::from(bytes[0]) << 8 | u16::from(bytes[1])) & 0xe000 != 0x2000 {
            continue; // global unicast 2000::/3
        }
        bytes[8..].fill(0); // mask to the /64 network
        return Some(Ipv6Addr::from(bytes));
    }
    None
}

/// `net` (a /64 network) with 64 cryptographically-random host bits.
#[cfg(target_os = "linux")]
fn random_addr_in_prefix64(net: Ipv6Addr) -> Ipv6Addr {
    use rand::RngCore;
    let mut bytes = net.octets();
    let mut host = [0_u8; 8];
    rand::rng().fill_bytes(&mut host);
    bytes[8..].copy_from_slice(&host);
    Ipv6Addr::from(bytes)
}

/// Best-effort `setsockopt(IPV6_FREEBIND)` so a source address not configured
/// on any interface (the random /64 addresses) can be bound. Linux-only.
#[cfg(target_os = "linux")]
fn set_ipv6_freebind(socket: &Socket) -> std::io::Result<()> {
    let on: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_FREEBIND,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_ipv6_freebind<T>(_socket: &T) -> std::io::Result<()> {
    Ok(())
}

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
    connect_tcp_socket_raw(addr, fwmark, None).await
}

/// Direct-route TCP connect that honours the rotating /64 source prefix
/// (configured via [`init_direct_ipv6_prefix_iface`]). Binds a random source
/// from the interface's current /64 for IPv6 targets; falls back to the normal
/// connect (kernel source + stable-public preference) when the feature is off,
/// the target is IPv4, or the interface has no usable prefix. Use this only for
/// direct dials — uplink dials keep [`connect_tcp_socket`] so they are never
/// source-bound onto the local prefix.
pub async fn connect_tcp_socket_direct(addr: SocketAddr, fwmark: Option<u32>) -> Result<TcpStream> {
    #[cfg(target_os = "linux")]
    if let Some(src) = direct_source_for(addr) {
        return connect_tcp_socket_raw(addr, fwmark, Some(src)).await;
    }
    connect_tcp_socket(addr, fwmark).await
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
async fn connect_tcp_socket_raw(
    addr: SocketAddr,
    fwmark: Option<u32>,
    bind_source: Option<Ipv6Addr>,
) -> Result<TcpStream> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(SocketProtocol::TCP))
        .context("failed to create TCP socket")?;
    apply_fwmark(&socket, fwmark)?;
    if addr.is_ipv6() {
        match bind_source {
            // Direct rotating /64 source: bind a random (non-configured)
            // address; freebind lets us bind it and ndppd answers its NDP.
            Some(src) => {
                set_ipv6_freebind(&socket)?;
                socket
                    .bind(&SocketAddr::from((src, 0)).into())
                    .with_context(|| format!("failed to bind direct IPv6 source {src}"))?;
            },
            None => apply_prefer_public_ipv6_src(&socket),
        }
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
async fn connect_tcp_socket_raw(
    _addr: SocketAddr,
    _fwmark: Option<u32>,
    _bind_source: Option<Ipv6Addr>,
) -> Result<TcpStream> {
    bail!("fwmark is only supported on Linux")
}

pub fn bind_udp_socket(bind_addr: SocketAddr, fwmark: Option<u32>) -> Result<std::net::UdpSocket> {
    let socket =
        Socket::new(Domain::for_address(bind_addr), Type::DGRAM, Some(SocketProtocol::UDP))
            .context("failed to create UDP socket")?;
    if bind_addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
        if bind_addr.ip().is_unspecified() {
            // Wildcard bind: the kernel picks the source at send time — prefer
            // the stable public address over a rotating privacy-extension one.
            apply_prefer_public_ipv6_src(&socket);
        } else {
            // A specific (possibly non-local, e.g. a rotating /64) source needs
            // freebind so the bind succeeds; ndppd answers its NDP.
            let _ = set_ipv6_freebind(&socket);
        }
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

/// Direct-route UDP bind honouring the rotating /64 source prefix
/// (configured via [`init_direct_ipv6_prefix_iface`]). When the feature is on
/// and `bind_addr` is an unspecified IPv6 wildcard, bind a random /64 source
/// (freebind) so datagrams leave with a rotating source. Otherwise identical
/// to [`bind_udp_socket`]. Use this only for direct dials.
pub fn bind_udp_socket_direct(
    bind_addr: SocketAddr,
    fwmark: Option<u32>,
) -> Result<std::net::UdpSocket> {
    #[cfg(target_os = "linux")]
    if bind_addr.is_ipv6()
        && bind_addr.ip().is_unspecified()
        && let Some(src) = direct_source_for(bind_addr)
    {
        return bind_udp_socket(SocketAddr::new(IpAddr::V6(src), bind_addr.port()), fwmark);
    }
    bind_udp_socket(bind_addr, fwmark)
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
