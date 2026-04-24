use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

use crate::outbound::{OutboundIpv6, set_ipv6_freebind};

/// Create the NAT upstream UDP socket. When `outbound_ipv6` is configured and
/// the target is IPv6, the socket is bound to a random address from the pool
/// (with `IPV6_FREEBIND` to allow non-local bind); otherwise it falls back to
/// the kernel default wildcard bind, matching legacy behaviour. Interface
/// mode may return no usable address (e.g. interface not up yet) — in that
/// case we also fall back to the wildcard bind rather than fail the datagram.
pub(crate) fn bind_nat_udp_socket(
    target: SocketAddr,
    outbound_ipv6: Option<&OutboundIpv6>,
) -> Result<UdpSocket> {
    use socket2::{Domain, SockAddr, Socket, Type};

    let source = if target.is_ipv6() {
        match outbound_ipv6 {
            Some(src) => {
                let picked = src
                    .random_addr()
                    .context("failed to generate random outbound IPv6 address")?;
                if picked.is_none() {
                    tracing::debug!(
                        %target,
                        source = %src,
                        "outbound IPv6 pool is empty; NAT UDP socket falling back to wildcard bind",
                    );
                }
                picked
            },
            None => None,
        }
    } else {
        None
    };

    if source.is_none() {
        let bind_addr: SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let std_socket = std::net::UdpSocket::bind(bind_addr)
            .with_context(|| format!("failed to bind NAT UDP socket on {bind_addr}"))?;
        std_socket
            .set_nonblocking(true)
            .context("failed to set NAT UDP socket nonblocking")?;
        return UdpSocket::from_std(std_socket).context("failed to register NAT UDP socket");
    }

    // IPv6 with random source.
    let source = source.expect("checked above");
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(socket2::Protocol::UDP))
        .context("failed to create NAT UDP socket")?;
    set_ipv6_freebind(&socket).context("failed to set IPV6_FREEBIND on NAT UDP socket")?;
    let bind_addr = SocketAddr::V6(std::net::SocketAddrV6::new(source, 0, 0, 0));
    socket
        .bind(&SockAddr::from(bind_addr))
        .with_context(|| format!("failed to bind NAT UDP socket {bind_addr}"))?;
    socket
        .set_nonblocking(true)
        .context("failed to set NAT UDP socket nonblocking")?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).context("failed to register NAT UDP socket")
}
