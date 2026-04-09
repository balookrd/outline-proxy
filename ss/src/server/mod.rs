use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    fs,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use bytes::Bytes;

use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    extract::{
        OriginalUri, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{Method, StatusCode, Version},
    response::IntoResponse,
    routing::any,
    serve::ListenerExt,
};
use futures_util::{FutureExt, SinkExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as HyperBuilder,
    service::TowerToHyperService,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sockudo_ws::{
    Config as H3WebSocketConfig, ExtendedConnectRequest as H3ExtendedConnectRequest,
    Http3 as H3Transport, Message as H3Message, Stream as H3Stream,
    WebSocketServer as H3WebSocketServer, WebSocketStream as H3WebSocketStream,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket, lookup_host},
    sync::{Semaphore, mpsc},
    task::JoinSet,
    time::{Duration, timeout},
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::{
    config::Config,
    crypto::{
        AeadStreamDecryptor, AeadStreamEncryptor, CryptoError, MAX_CHUNK_SIZE, UserKey,
        decrypt_udp_packet, decrypt_udp_packet_with_hint, diagnose_stream_handshake,
        diagnose_udp_packet,
    },
    fwmark::apply_fwmark_if_needed,
    metrics::{DisconnectReason, Metrics, Protocol, TcpUpstreamGuard, Transport},
    nat::{NatKey, NatTable, UdpResponseSender},
    protocol::{TargetAddr, parse_target_addr},
};

mod bootstrap;
mod connect;
mod shadowsocks;
mod transport;

use self::{
    bootstrap::{
        build_app, build_h3_server, build_metrics_app, ensure_rustls_provider_installed,
        serve_h3_server, serve_metrics_listener, serve_tcp_listener,
    },
    connect::connect_tcp_target,
    shadowsocks::{serve_ss_tcp_listener, serve_ss_udp_socket},
    transport::{
        is_benign_ws_disconnect, tcp_websocket_upgrade, udp_websocket_upgrade,
    },
};

const H2_KEEPALIVE_INTERVAL_SECS: u64 = 20;
const H2_KEEPALIVE_TIMEOUT_SECS: u64 = 20;
const H2_STREAM_WINDOW_BYTES: u32 = 16 * 1024 * 1024; // 16 MB
const H2_CONNECTION_WINDOW_BYTES: u32 = 64 * 1024 * 1024; // 64 MB
const H2_MAX_SEND_BUF_SIZE: usize = 16 * 1024 * 1024; // 16 MB
const H3_QUIC_IDLE_TIMEOUT_SECS: u64 = 120;
const H3_QUIC_PING_INTERVAL_SECS: u64 = 10;
// Flow control windows: larger values allow higher throughput at high RTT.
// Stream window must be <= connection window.
const H3_STREAM_WINDOW_BYTES: u64 = 16 * 1024 * 1024; // 16 MB (was 8 MB)
const H3_CONNECTION_WINDOW_BYTES: u64 = 64 * 1024 * 1024; // 64 MB (was 32 MB)
const H3_MAX_CONCURRENT_BIDI_STREAMS: u32 = 4_096;
const H3_MAX_CONCURRENT_UNI_STREAMS: u32 = 1_024;
// Larger write buffer reduces per-packet overhead by batching more data per send.
const H3_WRITE_BUFFER_BYTES: usize = 512 * 1024; // 512 KB (was 256 KB)
// Higher backpressure threshold avoids dropping connections for transiently slow clients.
const H3_MAX_BACKPRESSURE_BYTES: usize = 16 * 1024 * 1024; // 16 MB (was 8 MB)
// Larger OS UDP socket buffers are the primary defense against packet drops under burst load.
// Increase net.core.rmem_max / kern.ipc.maxsockbuf on the host if the OS silently caps this.
const H3_UDP_SOCKET_BUFFER_BYTES: usize = 32 * 1024 * 1024; // 32 MB (was 8 MB)
const H3_MAX_UDP_PAYLOAD_SIZE: u16 = 1_350;
const TCP_CONNECT_TIMEOUT_SECS: u64 = 10;
const SS_TCP_HANDSHAKE_TIMEOUT_SECS: u64 = 30;
const TCP_HAPPY_EYEBALLS_DELAY_MS: u64 = 250;
const UDP_MAX_CONCURRENT_RELAY_TASKS: usize = 256;
const SS_MAX_CONCURRENT_TCP_CONNECTIONS: usize = 4_096;
const UDP_DNS_CACHE_TTL_SECS: u64 = 30;
const MAX_UDP_PAYLOAD_SIZE: usize = 65_507;
const UDP_CACHED_USER_INDEX_EMPTY: usize = usize::MAX;

#[derive(Clone)]
struct AppState {
    tcp_routes: Arc<BTreeMap<String, TransportRoute>>,
    udp_routes: Arc<BTreeMap<String, TransportRoute>>,
    metrics: Arc<Metrics>,
    nat_table: Arc<NatTable>,
    udp_dns_cache: Arc<UdpDnsCache>,
    prefer_ipv4_upstream: bool,
}

#[derive(Clone)]
struct TransportRoute {
    users: Arc<[UserKey]>,
    candidate_users: Arc<[String]>,
}

#[derive(Clone, Copy, Debug)]
struct UdpDnsCacheEntry {
    resolved: SocketAddr,
    expires_at: std::time::Instant,
}

// Outer key: (port, prefer_ipv4_upstream) — cheap to construct without allocation.
// Inner key: host String — supports &str lookup via String: Borrow<str>.
struct UdpDnsCache {
    entries: RwLock<HashMap<(u16, bool), HashMap<String, UdpDnsCacheEntry>>>,
    ttl: Duration,
}

impl UdpDnsCache {
    fn new(ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
        })
    }

    fn lookup(&self, host: &str, port: u16, prefer_ipv4_upstream: bool) -> Option<SocketAddr> {
        let now = std::time::Instant::now();
        {
            let entries = self.entries.read().expect("udp dns cache poisoned");
            if let Some(entry) = entries
                .get(&(port, prefer_ipv4_upstream))
                .and_then(|inner| inner.get(host))
                .copied()
            {
                if entry.expires_at > now {
                    return Some(entry.resolved);
                }
            } else {
                return None;
            }
        }
        // Entry exists but is expired — acquire write lock to evict it.
        let mut entries = self.entries.write().expect("udp dns cache poisoned");
        if let Some(inner) = entries.get_mut(&(port, prefer_ipv4_upstream)) {
            if inner.get(host).is_some_and(|e| e.expires_at <= now) {
                inner.remove(host);
            }
        }
        None
    }

    fn store(&self, host: &str, port: u16, prefer_ipv4_upstream: bool, resolved: SocketAddr) {
        let entry = UdpDnsCacheEntry {
            resolved,
            expires_at: std::time::Instant::now() + self.ttl,
        };
        self.entries
            .write()
            .expect("udp dns cache poisoned")
            .entry((port, prefer_ipv4_upstream))
            .or_default()
            .insert(host.to_owned(), entry);
    }
}

pub async fn run(config: Config) -> Result<()> {
    ensure_rustls_provider_installed();
    let config = Arc::new(config);
    let metrics = Metrics::new(config.as_ref());
    metrics.start_process_memory_sampler();
    let users = build_users(&config)?;
    let tcp_routes = Arc::new(build_transport_route_map(users.as_ref(), Transport::Tcp));
    let udp_routes = Arc::new(build_transport_route_map(users.as_ref(), Transport::Udp));
    let nat_table = NatTable::new(Duration::from_secs(config.udp_nat_idle_timeout_secs));
    let udp_dns_cache = UdpDnsCache::new(Duration::from_secs(UDP_DNS_CACHE_TTL_SECS));
    let app = build_app(
        tcp_routes.clone(),
        udp_routes.clone(),
        metrics.clone(),
        Arc::clone(&nat_table),
        Arc::clone(&udp_dns_cache),
        config.prefer_ipv4_upstream,
    );
    let listener = if let Some(listen) = config.listen {
        Some(
            TcpListener::bind(listen)
                .await
                .with_context(|| format!("failed to bind {}", listen))?,
        )
    } else {
        None
    };
    let ss_tcp_listener =
        if let Some(ss_listen) = config.ss_listen {
            Some(TcpListener::bind(ss_listen).await.with_context(|| {
                format!("failed to bind shadowsocks tcp listener {}", ss_listen)
            })?)
        } else {
            None
        };
    let ss_udp_socket = if let Some(ss_listen) = config.ss_listen {
        Some(Arc::new(UdpSocket::bind(ss_listen).await.with_context(
            || format!("failed to bind shadowsocks udp socket {}", ss_listen),
        )?))
    } else {
        None
    };
    let metrics_listener = if config.metrics_enabled() {
        let metrics_listen = config.metrics_listen.expect("metrics listen must exist");
        Some(
            TcpListener::bind(metrics_listen)
                .await
                .with_context(|| format!("failed to bind metrics listener {}", metrics_listen))?,
        )
    } else {
        None
    };
    let h3_server = if config.h3_enabled() {
        Some(build_h3_server(config.as_ref()).await?)
    } else {
        None
    };

    // Periodic NAT entry eviction.
    {
        let nat_table_cleanup = Arc::clone(&nat_table);
        let metrics_cleanup = Arc::clone(&metrics);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                nat_table_cleanup.evict_idle(&metrics_cleanup).await;
            }
        });
    }

    let tcp_paths = tcp_routes.keys().cloned().collect::<BTreeSet<_>>();
    let udp_paths = udp_routes.keys().cloned().collect::<BTreeSet<_>>();
    let user_routes = describe_user_routes(users.as_ref());
    info!(
        listen = ?config.listen,
        ss_listen = ?config.ss_listen,
        tcp_tls = config.tcp_tls_enabled(),
        h3_listen = ?config.effective_h3_listen(),
        metrics_listen = ?config.metrics_listen,
        metrics_path = %config.metrics_path,
        default_tcp_ws_path = %config.ws_path_tcp,
        default_udp_ws_path = %config.ws_path_udp,
        tcp_ws_paths = ?tcp_paths,
        udp_ws_paths = ?udp_paths,
        user_routes = ?user_routes,
        method = ?config.method,
        users = users.len(),
        udp_nat_idle_timeout_secs = config.udp_nat_idle_timeout_secs,
        prefer_ipv4_upstream = config.prefer_ipv4_upstream,
        "websocket shadowsocks server listening",
    );

    let mut tasks = JoinSet::new();
    if let Some(listener) = listener {
        let config = Arc::clone(&config);
        tasks.spawn(async move { serve_tcp_listener(listener, app, config).await });
    }
    if let Some(h3_server) = h3_server {
        let tcp_routes = tcp_routes.clone();
        let udp_routes = udp_routes.clone();
        let metrics = metrics.clone();
        let nat_table = Arc::clone(&nat_table);
        let udp_dns_cache = Arc::clone(&udp_dns_cache);
        let prefer_ipv4_upstream = config.prefer_ipv4_upstream;
        tasks.spawn(async move {
            serve_h3_server(
                h3_server,
                tcp_routes,
                udp_routes,
                metrics,
                nat_table,
                udp_dns_cache,
                prefer_ipv4_upstream,
            )
            .await
        });
    }
    if let Some(metrics_listener) = metrics_listener {
        let metrics_app = build_metrics_app(metrics.clone(), config.metrics_path.clone());
        tasks.spawn(async move { serve_metrics_listener(metrics_listener, metrics_app).await });
    }
    if let Some(listener) = ss_tcp_listener {
        let users = users.clone();
        let metrics = metrics.clone();
        let prefer_ipv4_upstream = config.prefer_ipv4_upstream;
        tasks.spawn(async move {
            serve_ss_tcp_listener(listener, users, metrics, prefer_ipv4_upstream).await
        });
    }
    if let Some(socket) = ss_udp_socket {
        let users = users.clone();
        let metrics = metrics.clone();
        let nat_table = Arc::clone(&nat_table);
        let udp_dns_cache = Arc::clone(&udp_dns_cache);
        let prefer_ipv4_upstream = config.prefer_ipv4_upstream;
        tasks.spawn(async move {
            serve_ss_udp_socket(
                socket,
                users,
                metrics,
                nat_table,
                udp_dns_cache,
                prefer_ipv4_upstream,
            )
            .await
        });
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(?error, "server task exited with error"),
            Err(join_error) => warn!(?join_error, "server task panicked"),
        }
    }
    Ok(())
}

fn protocol_from_http_version(version: Version) -> Protocol {
    match version {
        Version::HTTP_2 => Protocol::Http2,
        _ => Protocol::Http1,
    }
}

fn empty_transport_route() -> TransportRoute {
    TransportRoute {
        users: Arc::from(Vec::<UserKey>::new().into_boxed_slice()),
        candidate_users: Arc::from(Vec::<String>::new().into_boxed_slice()),
    }
}

fn build_transport_route_map(
    users: &[UserKey],
    transport: Transport,
) -> BTreeMap<String, TransportRoute> {
    let mut grouped = BTreeMap::<String, Vec<UserKey>>::new();
    for user in users {
        let path = match transport {
            Transport::Tcp => user.ws_path_tcp(),
            Transport::Udp => user.ws_path_udp(),
        };
        grouped
            .entry(path.to_owned())
            .or_default()
            .push(user.clone());
    }

    grouped
        .into_iter()
        .map(|(path, path_users)| {
            let candidate_users = path_users
                .iter()
                .map(|user| format!("{}:{}", user.id(), user.cipher().as_str()))
                .collect::<Vec<_>>();
            (
                path,
                TransportRoute {
                    users: Arc::from(path_users.into_boxed_slice()),
                    candidate_users: Arc::from(candidate_users.into_boxed_slice()),
                },
            )
        })
        .collect()
}

fn describe_user_routes(users: &[UserKey]) -> Vec<String> {
    users
        .iter()
        .map(|user| {
            format!(
                "{}:{} tcp={} udp={}",
                user.id(),
                user.cipher().as_str(),
                user.ws_path_tcp(),
                user.ws_path_udp()
            )
        })
        .collect()
}

fn build_users(config: &Config) -> Result<Arc<[UserKey]>> {
    Ok(Arc::from(
        config
            .user_entries()?
            .into_iter()
            .map(|entry| {
                let method = entry.effective_method(config.method);
                let ws_path_tcp = entry.effective_ws_path_tcp(&config.ws_path_tcp).to_owned();
                let ws_path_udp = entry.effective_ws_path_udp(&config.ws_path_udp).to_owned();
                UserKey::new(
                    entry.id,
                    &entry.password,
                    entry.fwmark,
                    method,
                    ws_path_tcp,
                    ws_path_udp,
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice(),
    ))
}


#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::Arc,
    };

    use anyhow::Result;
    use axum::http::{Method, Request, StatusCode, Version, header};
    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use h3::ext::Protocol as H3Protocol;
    use http_body_util::Empty;
    use hyper::ext::Protocol;
    use hyper_util::{
        client::legacy::Client,
        rt::{TokioExecutor, TokioIo},
    };
    use quinn::Endpoint;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use sockudo_ws::{
        Config as H3WsConfig, Http3 as H3Transport, Message as H3Message, Role as H3Role,
        Stream as H3Stream, WebSocketServer as H3WebSocketServer,
        WebSocketStream as H3WebSocketStream,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
    };
    use tokio_tungstenite::{
        WebSocketStream, connect_async,
        tungstenite::{Message as WsMessage, protocol},
    };

    use super::{
        UdpDnsCache, build_app, build_transport_route_map, build_users, connect_tcp_target,
        serve_h3_server, serve_ss_tcp_listener, serve_ss_udp_socket,
    };
    use super::bootstrap::serve_listener;
    use super::connect::{connect_tcp_addrs, order_tcp_connect_addrs};
    use crate::config::{CipherKind, Config, UserEntry};
    use crate::crypto::{
        AeadStreamDecryptor, AeadStreamEncryptor, decrypt_udp_packet, encrypt_udp_packet,
    };
    use crate::metrics::{Metrics, Transport};
    use crate::nat::NatTable;
    use crate::protocol::TargetAddr;

    #[tokio::test]
    async fn tcp_ipv6_loopback_smoke() -> Result<()> {
        let listener = match TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await {
            Ok(listener) => listener,
            Err(error) if ipv6_unavailable(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let addr = listener.local_addr()?;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut buf = [0_u8; 4];
            stream.read_exact(&mut buf).await?;
            stream.write_all(b"pong").await?;
            Result::<_, anyhow::Error>::Ok(buf)
        });

        let target = TargetAddr::Socket(SocketAddr::from((Ipv6Addr::LOCALHOST, addr.port())));
        let mut client = connect_tcp_target(&target, None, false).await?;
        client.write_all(b"ping").await?;

        let mut reply = [0_u8; 4];
        client.read_exact(&mut reply).await?;

        assert_eq!(&reply, b"pong");
        assert_eq!(server.await??, *b"ping");
        Ok(())
    }

    #[test]
    fn tcp_connect_order_interleaves_ipv4_and_ipv6() {
        let ordered = order_tcp_connect_addrs(
            vec![
                SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
                SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 2], 443)),
                SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 443)),
                SocketAddr::from((Ipv4Addr::new(203, 0, 113, 11), 443)),
                SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
            ],
            false,
        );

        assert_eq!(
            ordered,
            vec![
                SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
                SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 443)),
                SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 2], 443)),
                SocketAddr::from((Ipv4Addr::new(203, 0, 113, 11), 443)),
            ]
        );
    }

    #[test]
    fn udp_dns_cache_returns_fresh_entries_and_expires() {
        let cache = UdpDnsCache::new(std::time::Duration::from_millis(5));
        let resolved = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));

        cache.store("dns.google", 53, false, resolved);
        assert_eq!(cache.lookup("dns.google", 53, false), Some(resolved));

        std::thread::sleep(std::time::Duration::from_millis(10));
        assert_eq!(cache.lookup("dns.google", 53, false), None);
    }

    #[tokio::test]
    async fn tcp_connect_tries_next_resolved_address() -> Result<()> {
        let blocked_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let blocked_addr = blocked_listener.local_addr()?;
        drop(blocked_listener);

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut buf = [0_u8; 4];
            stream.read_exact(&mut buf).await?;
            stream.write_all(b"pong").await?;
            Result::<_, anyhow::Error>::Ok(buf)
        });

        let mut client = connect_tcp_addrs(&[blocked_addr, addr], None).await?;
        client.write_all(b"ping").await?;

        let mut reply = [0_u8; 4];
        client.read_exact(&mut reply).await?;

        assert_eq!(&reply, b"pong");
        assert_eq!(server.await??, *b"ping");
        Ok(())
    }

    #[tokio::test]
    async fn udp_ipv6_loopback_smoke() -> Result<()> {
        let echo = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await {
            Ok(s) => s,
            Err(error) if ipv6_unavailable(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let echo_addr = echo.local_addr()?;
        let server = tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            let (read, peer) = echo.recv_from(&mut buf).await?;
            echo.send_to(&buf[..read], peer).await?;
            Result::<_, anyhow::Error>::Ok(buf[..read].to_vec())
        });

        // Send a datagram to the echo server and wait for the reply.
        let client = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await?;
        client.send_to(b"ping", echo_addr).await?;
        let mut buf = [0_u8; 64];
        let (read, source) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await??;

        assert_eq!(source.ip(), Ipv6Addr::LOCALHOST);
        assert_eq!(&buf[..read], b"ping");
        assert_eq!(server.await??, b"ping");
        Ok(())
    }

    #[tokio::test]
    async fn websocket_rfc8441_http2_connect_smoke() -> Result<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;

        let config = sample_config(addr);
        let users = build_users(&config)?;
        let nat_table = NatTable::new(std::time::Duration::from_secs(300));
        let udp_dns_cache = UdpDnsCache::new(std::time::Duration::from_secs(30));
        let app = build_app(
            Arc::new(build_transport_route_map(users.as_ref(), Transport::Tcp)),
            Arc::new(build_transport_route_map(users.as_ref(), Transport::Udp)),
            Metrics::new(&config),
            nat_table,
            udp_dns_cache,
            false,
        );
        let server = tokio::spawn(async move { serve_listener(listener, app).await });

        let client = Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build_http::<Empty<Bytes>>();

        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("http://{addr}/tcp"))
            .version(Version::HTTP_2)
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .extension(Protocol::from_static("websocket"))
            .body(Empty::<Bytes>::new())?;

        let mut response = client.request(req).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), Version::HTTP_2);

        let upgraded = hyper::upgrade::on(&mut response).await?;
        let upgraded = TokioIo::new(upgraded);
        let mut socket =
            WebSocketStream::from_raw_socket(upgraded, protocol::Role::Client, None).await;
        socket.close(None).await?;

        server.abort();
        let _ = server.await;
        Ok(())
    }

    #[tokio::test]
    async fn websocket_rfc8441_http2_udp_relay_smoke() -> Result<()> {
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let upstream_addr = upstream.local_addr()?;
        let upstream_task = tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            let (read, peer) = upstream.recv_from(&mut buf).await?;
            upstream.send_to(&buf[..read], peer).await?;
            Result::<_, anyhow::Error>::Ok(buf[..read].to_vec())
        });

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;

        let config = sample_config(addr);
        let users = build_users(&config)?;
        let user = users[0].clone();
        let nat_table = NatTable::new(std::time::Duration::from_secs(300));
        let udp_dns_cache = UdpDnsCache::new(std::time::Duration::from_secs(30));
        let app = build_app(
            Arc::new(build_transport_route_map(users.as_ref(), Transport::Tcp)),
            Arc::new(build_transport_route_map(users.as_ref(), Transport::Udp)),
            Metrics::new(&config),
            nat_table,
            udp_dns_cache,
            false,
        );
        let server = tokio::spawn(async move { serve_listener(listener, app).await });

        let client = Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build_http::<Empty<Bytes>>();

        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("http://{addr}/udp"))
            .version(Version::HTTP_2)
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .extension(Protocol::from_static("websocket"))
            .body(Empty::<Bytes>::new())?;

        let mut response = client.request(req).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), Version::HTTP_2);

        let upgraded = hyper::upgrade::on(&mut response).await?;
        let upgraded = TokioIo::new(upgraded);
        let mut socket =
            WebSocketStream::from_raw_socket(upgraded, protocol::Role::Client, None).await;

        let mut plaintext = TargetAddr::Socket(upstream_addr).encode()?;
        plaintext.extend_from_slice(b"ping");
        let ciphertext = encrypt_udp_packet(&user, &plaintext)?;
        socket.send(WsMessage::Binary(ciphertext.into())).await?;

        let reply = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next()).await?;
        let Some(Ok(WsMessage::Binary(encrypted_reply))) = reply else {
            anyhow::bail!("expected binary websocket reply, got {reply:?}");
        };

        let packet = decrypt_udp_packet(std::slice::from_ref(&user), &encrypted_reply)?;
        let (target, consumed) = crate::protocol::parse_target_addr(&packet.payload)?
            .ok_or_else(|| anyhow::anyhow!("missing target in udp response"))?;
        assert_eq!(target, TargetAddr::Socket(upstream_addr));
        assert_eq!(&packet.payload[consumed..], b"ping");
        assert_eq!(upstream_task.await??, b"ping");

        socket.close(None).await?;
        server.abort();
        let _ = server.await;
        Ok(())
    }

    #[tokio::test]
    async fn websocket_tcp_path_isolates_users_by_route() -> Result<()> {
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let upstream_addr = upstream.local_addr()?;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let listen_addr = listener.local_addr()?;
        let config = sample_config_with_users(
            listen_addr,
            vec![
                UserEntry {
                    id: "alice".into(),
                    password: "secret-a".into(),
                    fwmark: None,
                    method: None,
                    ws_path_tcp: Some("/alice-tcp".into()),
                    ws_path_udp: Some("/alice-udp".into()),
                },
                UserEntry {
                    id: "bob".into(),
                    password: "secret-b".into(),
                    fwmark: None,
                    method: None,
                    ws_path_tcp: Some("/bob-tcp".into()),
                    ws_path_udp: Some("/bob-udp".into()),
                },
            ],
        );
        let users = build_users(&config)?;
        let nat_table = NatTable::new(std::time::Duration::from_secs(300));
        let udp_dns_cache = UdpDnsCache::new(std::time::Duration::from_secs(30));
        let app = build_app(
            Arc::new(build_transport_route_map(users.as_ref(), Transport::Tcp)),
            Arc::new(build_transport_route_map(users.as_ref(), Transport::Udp)),
            Metrics::new(&config),
            nat_table,
            udp_dns_cache,
            false,
        );
        let server = tokio::spawn(async move { serve_listener(listener, app).await });

        let bob = users
            .iter()
            .find(|user| user.id() == "bob")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing bob user"))?;
        let (mut socket, _) = connect_async(format!("ws://{listen_addr}/alice-tcp")).await?;
        let mut request = TargetAddr::Socket(upstream_addr).encode()?;
        request.extend_from_slice(b"ping");
        let mut encryptor = AeadStreamEncryptor::new(&bob, None)?;
        let ciphertext = encryptor.encrypt_chunk(&request)?;
        socket.send(WsMessage::Binary(ciphertext.into())).await?;

        let client_outcome =
            tokio::time::timeout(std::time::Duration::from_secs(1), socket.next()).await;
        assert!(
            matches!(
                client_outcome,
                Ok(Some(Ok(WsMessage::Close(_)))) | Ok(Some(Err(_))) | Ok(None)
            ),
            "unexpected websocket outcome: {client_outcome:?}"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), upstream.accept())
                .await
                .is_err(),
            "bob key on alice path must not reach upstream"
        );

        server.abort();
        let _ = server.await;
        Ok(())
    }

    #[tokio::test]
    async fn plain_shadowsocks_tcp_relay_smoke() -> Result<()> {
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let upstream_addr = upstream.local_addr()?;
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await?;
            let mut buf = [0_u8; 16];
            stream.read_exact(&mut buf[..4]).await?;
            stream.write_all(b"pong").await?;
            Result::<_, anyhow::Error>::Ok(buf[..4].to_vec())
        });

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let listen_addr = listener.local_addr()?;
        let config = sample_config(listen_addr);
        let users = build_users(&config)?;
        let user = users[0].clone();
        let metrics = Metrics::new(&config);
        let server =
            tokio::spawn(
                async move { serve_ss_tcp_listener(listener, users, metrics, false).await },
            );

        let mut client = TcpStream::connect(listen_addr).await?;
        let mut request = TargetAddr::Socket(upstream_addr).encode()?;
        request.extend_from_slice(b"ping");
        let mut encryptor = AeadStreamEncryptor::new(&user, None)?;
        let ciphertext = encryptor.encrypt_chunk(&request)?;
        client.write_all(&ciphertext).await?;

        let mut encrypted_reply = [0_u8; 256];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read(&mut encrypted_reply),
        )
        .await??;
        assert!(read > 0);

        let mut decryptor = AeadStreamDecryptor::new(Arc::from(vec![user].into_boxed_slice()));
        let mut plaintext = Vec::new();
        decryptor.push(&encrypted_reply[..read]);
        decryptor.pull_plaintext(&mut plaintext)?;
        assert_eq!(plaintext, b"pong");
        assert_eq!(upstream_task.await??, b"ping");

        server.abort();
        let _ = server.await;
        Ok(())
    }

    #[tokio::test]
    async fn websocket_rfc9220_http3_connect_smoke() -> Result<()> {
        let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let (tls_config, cert_der) = test_h3_server_tls()?;
        let server =
            H3WebSocketServer::<H3Transport>::bind(server_addr, tls_config, H3WsConfig::default())
                .await?;
        let addr = server.local_addr()?;

        let config = sample_config(addr);
        let users = build_users(&config)?;
        let tcp_routes = Arc::new(build_transport_route_map(users.as_ref(), Transport::Tcp));
        let udp_routes = Arc::new(build_transport_route_map(users.as_ref(), Transport::Udp));
        let metrics = Metrics::new(&config);
        let nat_table = NatTable::new(std::time::Duration::from_secs(300));
        let udp_dns_cache = UdpDnsCache::new(std::time::Duration::from_secs(30));
        let server = tokio::spawn(async move {
            serve_h3_server(
                server,
                tcp_routes,
                udp_routes,
                metrics,
                nat_table,
                udp_dns_cache,
                false,
            )
            .await
        });

        let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        endpoint.set_default_client_config(test_h3_client_config(cert_der)?);

        let connection = endpoint.connect(addr, "localhost")?.await?;
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(connection)).await?;
        let driver =
            tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://localhost:{}/tcp", addr.port()))
            .version(Version::HTTP_3)
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .extension(H3Protocol::WEBSOCKET)
            .body(())?;

        let stream = send_request.send_request(request).await?;
        let mut stream = stream;
        let response = stream.recv_response().await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), Version::HTTP_3);

        let h3_stream = H3Stream::<H3Transport>::from_h3_client(stream);
        let mut socket =
            H3WebSocketStream::from_raw(h3_stream, H3Role::Client, H3WsConfig::default());
        socket.send(H3Message::Close(None)).await?;

        driver.abort();
        server.abort();
        let _ = driver.await;
        let _ = server.await;
        Ok(())
    }

    #[tokio::test]
    async fn plain_shadowsocks_udp_relay_smoke() -> Result<()> {
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let upstream_addr = upstream.local_addr()?;
        let upstream_task = tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            let (read, peer) = upstream.recv_from(&mut buf).await?;
            upstream.send_to(&buf[..read], peer).await?;
            Result::<_, anyhow::Error>::Ok(buf[..read].to_vec())
        });

        let listener = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
        let listen_addr = listener.local_addr()?;
        let config = sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 3000)));
        let users = build_users(&config)?;
        let user = users[0].clone();
        let metrics = Metrics::new(&config);
        let nat_table = NatTable::new(std::time::Duration::from_secs(300));
        let udp_dns_cache = UdpDnsCache::new(std::time::Duration::from_secs(30));
        let server = tokio::spawn(async move {
            serve_ss_udp_socket(listener, users, metrics, nat_table, udp_dns_cache, false).await
        });

        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut plaintext = TargetAddr::Socket(upstream_addr).encode()?;
        plaintext.extend_from_slice(b"ping");
        let ciphertext = encrypt_udp_packet(&user, &plaintext)?;
        client.send_to(&ciphertext, listen_addr).await?;

        let mut encrypted_reply = [0_u8; 256];
        let (read, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut encrypted_reply),
        )
        .await??;

        let packet = decrypt_udp_packet(std::slice::from_ref(&user), &encrypted_reply[..read])?;
        let (target, consumed) = crate::protocol::parse_target_addr(&packet.payload)?
            .ok_or_else(|| anyhow::anyhow!("missing target in udp response"))?;
        assert_eq!(target, TargetAddr::Socket(upstream_addr));
        assert_eq!(&packet.payload[consumed..], b"ping");
        assert_eq!(upstream_task.await??, b"ping");

        server.abort();
        let _ = server.await;
        Ok(())
    }

    #[tokio::test]
    async fn plain_shadowsocks_udp_reuses_nat_entry_after_client_reconnect() -> Result<()> {
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let upstream_addr = upstream.local_addr()?;
        let upstream_task = tokio::spawn(async move {
            let mut peers = Vec::new();
            let mut buf = [0_u8; 64];
            for expected in [b"ping-1".as_slice(), b"ping-2".as_slice()] {
                let (read, peer) = upstream.recv_from(&mut buf).await?;
                peers.push(peer);
                assert_eq!(&buf[..read], expected);
                let reply = if expected == b"ping-1" {
                    b"pong-1".as_slice()
                } else {
                    b"pong-2".as_slice()
                };
                upstream.send_to(reply, peer).await?;
            }
            Result::<_, anyhow::Error>::Ok(peers)
        });

        let listener = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
        let listen_addr = listener.local_addr()?;
        let config = sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 3000)));
        let users = build_users(&config)?;
        let user = users[0].clone();
        let metrics = Metrics::new(&config);
        let nat_table = NatTable::new(std::time::Duration::from_secs(300));
        let udp_dns_cache = UdpDnsCache::new(std::time::Duration::from_secs(30));
        let server = tokio::spawn(async move {
            serve_ss_udp_socket(listener, users, metrics, nat_table, udp_dns_cache, false).await
        });

        let client1 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        send_encrypted_udp_request(&client1, listen_addr, upstream_addr, b"ping-1", &user).await?;
        let response1 = recv_decrypted_udp_response(&client1, &user).await?;
        assert_eq!(response1, b"pong-1");
        drop(client1);

        let client2 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        send_encrypted_udp_request(&client2, listen_addr, upstream_addr, b"ping-2", &user).await?;
        let response2 = recv_decrypted_udp_response(&client2, &user).await?;
        assert_eq!(response2, b"pong-2");

        let peers = upstream_task.await??;
        assert_eq!(peers.len(), 2);
        assert_eq!(
            peers[0], peers[1],
            "NAT socket source port should stay stable across reconnect"
        );

        server.abort();
        let _ = server.await;
        Ok(())
    }

    fn ipv6_unavailable(error: &std::io::Error) -> bool {
        matches!(
            error.kind(),
            std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
        )
    }

    fn sample_config(listen: SocketAddr) -> Config {
        sample_config_with_users(
            listen,
            vec![UserEntry {
                id: "bob".into(),
                password: "secret-b".into(),
                fwmark: None,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
            }],
        )
    }

    fn sample_config_with_users(listen: SocketAddr, users: Vec<UserEntry>) -> Config {
        Config {
            listen: Some(listen),
            ss_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            metrics_listen: None,
            metrics_path: "/metrics".into(),
            prefer_ipv4_upstream: false,
            client_active_ttl_secs: 300,
            udp_nat_idle_timeout_secs: 300,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            public_host: None,
            public_scheme: "ws".into(),
            access_key_url_base: None,
            access_key_file_extension: ".yaml".into(),
            print_access_keys: false,
            write_access_keys_dir: None,
            password: None,
            fwmark: None,
            users,
            method: CipherKind::Chacha20IetfPoly1305,
        }
    }

    async fn send_encrypted_udp_request(
        client: &UdpSocket,
        listen_addr: SocketAddr,
        target: SocketAddr,
        payload: &[u8],
        user: &crate::crypto::UserKey,
    ) -> Result<()> {
        let mut plaintext = TargetAddr::Socket(target).encode()?;
        plaintext.extend_from_slice(payload);
        let ciphertext = encrypt_udp_packet(user, &plaintext)?;
        client.send_to(&ciphertext, listen_addr).await?;
        Ok(())
    }

    async fn recv_decrypted_udp_response(
        client: &UdpSocket,
        user: &crate::crypto::UserKey,
    ) -> Result<Vec<u8>> {
        let mut encrypted_reply = [0_u8; 65_535];
        let (read, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut encrypted_reply),
        )
        .await??;

        let packet = decrypt_udp_packet(std::slice::from_ref(user), &encrypted_reply[..read])?;
        let (_, consumed) = crate::protocol::parse_target_addr(&packet.payload)?
            .ok_or_else(|| anyhow::anyhow!("missing target in udp response"))?;
        Ok(packet.payload[consumed..].to_vec())
    }

    fn test_h3_server_tls() -> Result<(rustls::ServerConfig, CertificateDer<'static>)> {
        super::ensure_rustls_provider_installed();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key)?;
        tls_config.alpn_protocols = vec![b"h3".to_vec()];
        Ok((tls_config, cert_der))
    }

    fn test_h3_client_config(cert_der: CertificateDer<'static>) -> Result<quinn::ClientConfig> {
        super::ensure_rustls_provider_installed();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der)?;

        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(Arc::new(roots))
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"h3".to_vec()];

        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|error| anyhow::anyhow!(error))?;
        Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
    }
}
