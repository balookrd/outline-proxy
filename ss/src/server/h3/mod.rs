use std::{collections::BTreeSet, sync::Arc};

use anyhow::{Context, Result, anyhow};
use sockudo_ws::{
    Config as H3WebSocketConfig, Http3 as H3Transport, WebSocketServer as H3WebSocketServer,
};
use tokio::{sync::Semaphore, time::Duration};
use tracing::{debug, warn};

use crate::{
    config::{Config, H3Alpn, TuningProfile},
    crypto::UserKey,
    protocol::vless::VlessUser,
};

use super::{
    bootstrap::load_h3_tls_config,
    constants::{
        H3_MAX_CONCURRENT_CONNECTIONS, H3_MAX_CONCURRENT_STREAMS, H3_MAX_UDP_PAYLOAD_SIZE,
        H3_QUIC_IDLE_TIMEOUT_SECS, H3_QUIC_PING_INTERVAL_SECS,
    },
    state::{AuthPolicy, RoutesSnapshot, Services},
    transport::{
        RawQuicSsCtx, RawQuicVlessRouteCtx, UdpServerCtx, VlessWsServerCtx, WsTcpServerCtx,
        is_normal_h3_shutdown,
    },
};

mod http;
mod raw_ss;
mod raw_vless;

pub(in crate::server) async fn build_h3_server(
    config: &Config,
) -> Result<H3WebSocketServer<H3Transport>> {
    let listen = config
        .effective_h3_listen()
        .ok_or_else(|| anyhow!("h3 server requested without tls configuration"))?;
    let profile = &config.tuning;
    let tls_config = load_h3_tls_config(config)?;
    let ws_config = build_h3_ws_config(profile);
    let server_config = build_h3_quinn_server_config(tls_config, profile)?;
    let socket = bind_h3_udp_socket(listen, profile)?;
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config
        .max_udp_payload_size(H3_MAX_UDP_PAYLOAD_SIZE)
        .context("invalid H3 max UDP payload size")?;
    let endpoint = quinn::Endpoint::new(
        endpoint_config,
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("failed to create HTTP/3 QUIC endpoint")?;
    Ok(H3WebSocketServer::<H3Transport>::from_endpoint(endpoint, ws_config))
}

fn build_h3_ws_config(profile: &TuningProfile) -> H3WebSocketConfig {
    H3WebSocketConfig::builder()
        .idle_timeout(H3_QUIC_IDLE_TIMEOUT_SECS as u32)
        .ping_interval(H3_QUIC_PING_INTERVAL_SECS as u32)
        .max_backpressure(profile.h3_max_backpressure_bytes)
        .write_buffer_size(profile.h3_write_buffer_bytes)
        .http3_idle_timeout(H3_QUIC_IDLE_TIMEOUT_SECS * 1_000)
        .http3_stream_window_size(profile.h3_stream_window_bytes)
        .http3_enable_connect_protocol(true)
        .http3_max_udp_payload_size(H3_MAX_UDP_PAYLOAD_SIZE)
        .build()
}

fn build_h3_quinn_server_config(
    tls_config: rustls::ServerConfig,
    profile: &TuningProfile,
) -> Result<quinn::ServerConfig> {
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|_| anyhow!("invalid HTTP/3 TLS config"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    server_config.transport_config(Arc::new(build_h3_transport_config(profile)?));
    Ok(server_config)
}

fn build_h3_transport_config(profile: &TuningProfile) -> Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(
            profile.h3_max_concurrent_bidi_streams,
        ))
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(profile.h3_max_concurrent_uni_streams))
        .max_idle_timeout(Some(
            Duration::from_secs(H3_QUIC_IDLE_TIMEOUT_SECS)
                .try_into()
                .context("invalid HTTP/3 idle timeout")?,
        ))
        // Send QUIC PING frames from the server side so that NAT mappings and
        // stateful firewalls stay alive even when only the server is sending
        // data.  Without this, a one-directional idle on the client→server path
        // can expire a NAT mapping and the server's own idle timer fires after
        // H3_QUIC_IDLE_TIMEOUT_SECS, killing all multiplexed WebSocket sessions.
        .keep_alive_interval(Some(Duration::from_secs(H3_QUIC_PING_INTERVAL_SECS)))
        .stream_receive_window(quinn::VarInt::from_u32(
            u32::try_from(profile.h3_stream_window_bytes)
                .expect("h3_stream_window_bytes exceeds u32"),
        ))
        .receive_window(quinn::VarInt::from_u32(
            u32::try_from(profile.h3_connection_window_bytes)
                .expect("h3_connection_window_bytes exceeds u32"),
        ))
        .send_window(profile.h3_connection_window_bytes)
        .datagram_receive_buffer_size(Some(profile.h3_connection_window_bytes as usize))
        .datagram_send_buffer_size(profile.h3_connection_window_bytes as usize);
    // Endpoint also serves raw-QUIC ALPNs (vless / ss) which carry
    // application UDP datagrams as QUIC datagrams (RFC 9221). The
    // default initial_mtu of 1200 caps the server→client datagram
    // payload at ~1170 B for the first few RTTs of every connection
    // while DPLPMTUD probes upward — long enough to drop real UDP
    // traffic (DNS, video) on a 1500-Ethernet link. Bump the floor
    // to 1400 (safe whenever the path supports standard 1500 MTU)
    // and let MTU discovery target 1452 from there. The matching
    // client config in outline-ws-rust uses identical values.
    transport.initial_mtu(1400);
    let mut mtu = quinn::MtuDiscoveryConfig::default();
    mtu.upper_bound(1452);
    transport.mtu_discovery_config(Some(mtu));
    Ok(transport)
}

fn bind_h3_udp_socket(
    listen: std::net::SocketAddr,
    profile: &TuningProfile,
) -> Result<std::net::UdpSocket> {
    let domain = if listen.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .context("failed to create HTTP/3 UDP socket")?;
    socket
        .set_recv_buffer_size(profile.h3_udp_socket_buffer_bytes)
        .context("failed to set HTTP/3 UDP receive buffer")?;
    if let Ok(actual) = socket.recv_buffer_size()
        && actual < profile.h3_udp_socket_buffer_bytes
    {
        tracing::warn!(
            requested = profile.h3_udp_socket_buffer_bytes,
            actual,
            "HTTP/3 UDP receive buffer capped by OS — increase net.core.rmem_max (Linux) \
             or kern.ipc.maxsockbuf (macOS) to reduce packet drops"
        );
    }
    socket
        .set_send_buffer_size(profile.h3_udp_socket_buffer_bytes)
        .context("failed to set HTTP/3 UDP send buffer")?;
    if let Ok(actual) = socket.send_buffer_size()
        && actual < profile.h3_udp_socket_buffer_bytes
    {
        tracing::warn!(
            requested = profile.h3_udp_socket_buffer_bytes,
            actual,
            "HTTP/3 UDP send buffer capped by OS — increase net.core.wmem_max (Linux) \
             or kern.ipc.maxsockbuf (macOS) to reduce packet drops"
        );
    }
    socket
        .bind(&socket2::SockAddr::from(listen))
        .with_context(|| format!("failed to bind HTTP/3 UDP socket {listen}"))?;
    let socket: std::net::UdpSocket = socket.into();
    socket
        .set_nonblocking(true)
        .context("failed to set HTTP/3 UDP socket nonblocking mode")?;
    Ok(socket)
}

struct H3ConnectionCtx {
    routes: RoutesSnapshot,
    auth: Arc<AuthPolicy>,
    tcp_paths: Arc<BTreeSet<String>>,
    udp_paths: Arc<BTreeSet<String>>,
    vless_paths: Arc<BTreeSet<String>>,
    ws_config: H3WebSocketConfig,
    tcp_server: Arc<WsTcpServerCtx>,
    udp_server: Arc<UdpServerCtx>,
    vless_server: Arc<VlessWsServerCtx>,
    stream_semaphore: Arc<Semaphore>,
    alpn: Arc<[H3Alpn]>,
    raw_vless_route: Arc<RawQuicVlessRouteCtx>,
    raw_ss_ctx: Arc<RawQuicSsCtx>,
}

fn negotiated_alpn(connection: &quinn::Connection) -> Option<H3Alpn> {
    let data = connection.handshake_data()?;
    let handshake = data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?;
    let bytes = handshake.protocol?;
    H3Alpn::parse(std::str::from_utf8(&bytes).ok()?)
}

pub(in crate::server) async fn serve_h3_server(
    server: H3WebSocketServer<H3Transport>,
    routes: RoutesSnapshot,
    services: Arc<Services>,
    auth: Arc<AuthPolicy>,
    alpn: Arc<[H3Alpn]>,
    raw_vless_users: Arc<[VlessUser]>,
    raw_vless_candidates: Arc<[Arc<str>]>,
    raw_ss_users: Arc<[UserKey]>,
    mut shutdown: super::shutdown::ShutdownSignal,
) -> Result<()> {
    let initial = routes.load();
    let tcp_paths: Arc<BTreeSet<String>> =
        Arc::new(initial.tcp.keys().cloned().collect::<BTreeSet<_>>());
    let udp_paths: Arc<BTreeSet<String>> =
        Arc::new(initial.udp.keys().cloned().collect::<BTreeSet<_>>());
    let vless_paths: Arc<BTreeSet<String>> =
        Arc::new(initial.vless.keys().cloned().collect::<BTreeSet<_>>());
    drop(initial);
    let (endpoint, ws_config) = server.into_parts();
    let tcp_server = Arc::clone(&services.tcp_server);
    let udp_server = Arc::clone(&services.udp_server);
    let vless_server = Arc::clone(&services.vless_server);

    let connection_semaphore = Arc::new(Semaphore::new(H3_MAX_CONCURRENT_CONNECTIONS));
    let stream_semaphore = Arc::new(Semaphore::new(H3_MAX_CONCURRENT_STREAMS));

    let raw_vless_route = Arc::new(RawQuicVlessRouteCtx {
        users: raw_vless_users,
        candidate_users: raw_vless_candidates,
    });
    let raw_ss_ctx = Arc::new(RawQuicSsCtx {
        users: raw_ss_users,
        services: Arc::clone(&services),
    });

    loop {
        // Acquire a connection permit before accepting so that at most
        // H3_MAX_CONCURRENT_CONNECTIONS connection handlers exist at once.
        // New QUIC handshakes queue inside the endpoint (and are eventually
        // dropped by QUIC's own anti-amplification limits) rather than
        // spawning unbounded tasks.
        let connection_permit = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                debug!("HTTP/3 endpoint stopping on shutdown signal");
                endpoint.close(quinn::VarInt::from_u32(0), b"server shutting down");
                break;
            }
            permit = connection_semaphore.clone().acquire_owned() => {
                permit.expect("H3 connection semaphore unexpectedly closed")
            }
        };

        let incoming = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                debug!("HTTP/3 endpoint stopping on shutdown signal");
                // Stop accepting new connections and politely close existing
                // ones. `close` is synchronous; the runtime eventually
                // reclaims the QUIC state.
                endpoint.close(quinn::VarInt::from_u32(0), b"server shutting down");
                break;
            }
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => break,
            },
        };
        let ctx = Arc::new(H3ConnectionCtx {
            routes: Arc::clone(&routes),
            auth: Arc::clone(&auth),
            tcp_paths: Arc::clone(&tcp_paths),
            udp_paths: Arc::clone(&udp_paths),
            vless_paths: Arc::clone(&vless_paths),
            ws_config: ws_config.clone(),
            tcp_server: Arc::clone(&tcp_server),
            udp_server: Arc::clone(&udp_server),
            vless_server: Arc::clone(&vless_server),
            stream_semaphore: Arc::clone(&stream_semaphore),
            alpn: Arc::clone(&alpn),
            raw_vless_route: Arc::clone(&raw_vless_route),
            raw_ss_ctx: Arc::clone(&raw_ss_ctx),
        });

        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            if let Err(error) = handle_quic_connection(incoming, ctx).await
                && !is_normal_h3_shutdown(&error)
            {
                warn!(?error, "QUIC connection terminated with error");
            }
        });
    }

    Ok(())
}

async fn handle_quic_connection(
    incoming: quinn::Incoming,
    ctx: Arc<H3ConnectionCtx>,
) -> Result<()> {
    let connection = incoming
        .await
        .context("failed to accept incoming QUIC connection")?;
    let alpn = negotiated_alpn(&connection);
    match alpn {
        Some(H3Alpn::H3) if ctx.alpn.contains(&H3Alpn::H3) => {
            http::handle_h3_connection(connection, ctx).await
        },
        Some(H3Alpn::Vless) if ctx.alpn.contains(&H3Alpn::Vless) => {
            raw_vless::handle_raw_vless_connection(connection, ctx).await
        },
        Some(H3Alpn::Ss) if ctx.alpn.contains(&H3Alpn::Ss) => {
            raw_ss::handle_raw_ss_connection(connection, ctx).await
        },
        other => {
            warn!(?other, "rejecting QUIC connection with unsupported or disabled ALPN");
            connection.close(quinn::VarInt::from_u32(2), b"unsupported alpn");
            Ok(())
        },
    }
}
