use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::{AppConfig, RouteTarget};
use crate::crypto::SHADOWSOCKS_MAX_PAYLOAD;
use crate::metrics;
use crate::socks5::{
    SOCKS_STATUS_SUCCESS, UdpFragmentReassembler, build_udp_packet, parse_udp_request,
    read_udp_tcp_packet, send_reply,
};
use crate::transport::{UdpWsTransport, is_dropped_oversized_udp_error};
use crate::types::{TargetAddr, socket_addr_to_target};
use crate::uplink::{TransportKind, UplinkManager, UplinkRegistry};

/// Per-packet routing decision for UDP.
///
/// `Tunnel` carries the resolved group name — the uplink loop then routes the
/// datagram through that group's transport (lazily opened on first use).
#[derive(Clone, Debug)]
enum UdpPacketRoute {
    Direct,
    Drop,
    Tunnel(String),
}

/// Per-association cache of route decisions keyed by destination target.
///
/// The routing table's [`version`](crate::routing::RoutingTable::version) is
/// captured alongside each entry; when the watcher reloads a rule's CIDR
/// file it bumps the version and the next lookup for an affected target
/// falls through to a fresh resolve.
type UdpRouteCache = HashMap<TargetAddr, (UdpPacketRoute, u64)>;

async fn resolve_udp_packet_route(
    cache: &mut UdpRouteCache,
    config: &AppConfig,
    registry: &UplinkRegistry,
    target: &TargetAddr,
) -> UdpPacketRoute {
    let default_group = registry.default_group_name().to_string();
    let Some(table) = config.routing_table.as_ref() else {
        return UdpPacketRoute::Tunnel(default_group);
    };
    let current_version = table.version();
    if let Some((route, entry_version)) = cache.get(target)
        && *entry_version == current_version {
            return route.clone();
        }
    // Tag the cached entry with the version captured *before* CIDR reads,
    // not the post-resolve version — otherwise a reload that races with
    // resolution would leave a stale decision tagged with the bumped
    // version and never invalidate. See `RoutingTable::resolve_versioned`.
    let (decision, resolve_version) = table.resolve_versioned(target).await;
    let route = classify_decision(registry, decision.primary, decision.fallback).await;
    cache.insert(target.clone(), (route.clone(), resolve_version));
    route
}

async fn classify_decision(
    registry: &UplinkRegistry,
    primary: RouteTarget,
    fallback: Option<RouteTarget>,
) -> UdpPacketRoute {
    let as_route = |target: RouteTarget| match target {
        RouteTarget::Direct => UdpPacketRoute::Direct,
        RouteTarget::Drop => UdpPacketRoute::Drop,
        RouteTarget::Group(name) => UdpPacketRoute::Tunnel(name),
    };
    // Fallback applies when the primary is a group whose UDP pool has no
    // healthy uplinks at resolve time; Direct/Drop primaries are terminal.
    if let RouteTarget::Group(ref name) = primary {
        let manager = registry.group_by_name(name);
        if manager.is_none() {
            // Unknown group — routing table referenced a group that was not
            // found in the registry. Honour the declared fallback before
            // falling back to the default (a declared fallback is an
            // explicit escape hatch the user wrote; using it first is safer
            // than silently substituting the default).
            if let Some(fb) = fallback {
                warn!(
                    group = %name,
                    fallback = ?fb,
                    "UDP route: unknown group, using declared fallback"
                );
                return as_route(fb);
            }
            warn!(
                group = %name,
                default = registry.default_group_name(),
                "UDP route: unknown group and no fallback; dispatching to default"
            );
            return UdpPacketRoute::Tunnel(registry.default_group_name().to_string());
        }
        let manager = manager.unwrap();
        if manager.has_any_healthy(TransportKind::Udp).await {
            return as_route(primary);
        }
        if let Some(fb) = fallback {
            debug!(primary = %name, fallback = ?fb, "UDP route: primary group unhealthy, using fallback");
            return as_route(fb);
        }
    }
    as_route(primary)
}

/// Returns `true` when a per-association direct UDP socket must be pre-allocated.
///
/// We allocate eagerly whenever a routing table is active because any rule may
/// resolve to `Direct` at packet time. Inspecting every rule's target up-front
/// would couple this to routing internals and still require a fallback for
/// dynamically reloaded rules; a single socket bind is cheap by comparison.
fn routing_table_active(config: &AppConfig) -> bool {
    config.routing_table.is_some()
}

/// Per-association state for one uplink group actively carrying UDP traffic.
///
/// Each `Tunnel(group)` resolution lazily opens a [`GroupUdpContext`] the
/// first time a packet targets that group. The context owns the
/// [`ActiveUdpTransport`] (so each group reconciles / fails over within its
/// own manager) and hands out `Arc<UdpWsTransport>` clones to the send path.
#[derive(Clone)]
struct GroupUdpContext {
    manager: UplinkManager,
    active: Arc<Mutex<ActiveUdpTransport>>,
}

/// A response datagram emitted by some group's downlink task, waiting to be
/// written to the SOCKS5 client. Allows multiple per-group read tasks to
/// share a single writer half without fighting for a mutex.
struct UdpResponse {
    target: TargetAddr,
    payload: Vec<u8>,
    group_name: String,
    uplink_name: String,
}

/// Per-association map of group-name → per-group UDP context, plus the
/// downlink tasks spawned for each active group. Owned exclusively by one
/// UDP associate session; not shared with other associations or the global
/// [`UplinkRegistry`].
struct AssocGroupMap {
    map: Mutex<HashMap<String, GroupUdpContext>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl AssocGroupMap {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            map: Mutex::new(HashMap::new()),
            tasks: Mutex::new(Vec::new()),
        })
    }

    /// Close every group's active transport; abort spawned downlink tasks.
    /// Called once on association shutdown.
    async fn shutdown(&self, reason: &'static str) {
        for task in self.tasks.lock().await.drain(..) {
            task.abort();
        }
        let map = std::mem::take(&mut *self.map.lock().await);
        for (_, ctx) in map {
            close_active_udp_transport(&ctx.active, reason).await;
        }
    }
}

/// Get-or-create the group context for `group_name`.
///
/// First caller spawns a dedicated downlink task that reads from the group's
/// transport and pushes responses into `responses`. All subsequent callers
/// reuse the cached context.
async fn resolve_group_context(
    registry_groups: &Arc<AssocGroupMap>,
    registry: &UplinkRegistry,
    group_name: &str,
    responses: &mpsc::Sender<UdpResponse>,
) -> Result<GroupUdpContext> {
    {
        let map = registry_groups.map.lock().await;
        if let Some(ctx) = map.get(group_name) {
            return Ok(ctx.clone());
        }
    }
    let manager = registry
        .group_by_name(group_name)
        .ok_or_else(|| anyhow!("uplink group \"{group_name}\" is not configured"))?
        .clone();
    let initial = select_udp_transport(&manager, None).await?;
    let active = Arc::new(Mutex::new(initial));
    let ctx = GroupUdpContext { manager: manager.clone(), active: Arc::clone(&active) };

    let mut map = registry_groups.map.lock().await;
    if let Some(existing) = map.get(group_name) {
        // Lost the race to another concurrent caller for the same group.
        // Clone what we need, release the lock first, then close the
        // duplicate transport — closing is async and must not hold the lock.
        let existing = existing.clone();
        drop(map);
        close_active_udp_transport(&active, "duplicate_group_context").await;
        return Ok(existing);
    }
    map.insert(group_name.to_string(), ctx.clone());
    drop(map);

    let task_ctx = ctx.clone();
    let task_responses = responses.clone();
    let group_label = group_name.to_string();
    let task = tokio::spawn(async move {
        if let Err(error) = run_group_downlink(task_ctx, task_responses).await {
            debug!(
                group = %group_label,
                error = %format!("{error:#}"),
                "UDP group downlink task exited"
            );
        }
    });
    registry_groups.tasks.lock().await.push(task);
    Ok(ctx)
}

/// Per-group downlink: reads upstream datagrams from one group's active
/// transport and pushes parsed responses into the shared channel.
async fn run_group_downlink(
    ctx: GroupUdpContext,
    responses: mpsc::Sender<UdpResponse>,
) -> Result<()> {
    loop {
        reconcile_global_udp_transport(&ctx.manager, &ctx.active, None).await?;
        let (index, name, transport) = {
            let a = ctx.active.lock().await;
            (a.index, a.uplink_name.clone(), Arc::clone(&a.transport))
        };
        let payload = match transport.read_packet().await {
            Ok(payload) => payload,
            Err(error) => {
                let replacement =
                    failover_udp_transport(&ctx.manager, &ctx.active, None, index, error).await?;
                let payload = replacement.transport.read_packet().await?;
                let (target, consumed) = TargetAddr::from_wire_bytes(&payload)?;
                if responses
                    .send(UdpResponse {
                        target,
                        payload: payload[consumed..].to_vec(),
                        group_name: ctx.manager.group_name().to_string(),
                        uplink_name: replacement.uplink_name,
                    })
                    .await
                    .is_err()
                {
                    return Ok(());
                }
                continue;
            },
        };
        let (target, consumed) = TargetAddr::from_wire_bytes(&payload)?;
        if responses
            .send(UdpResponse {
                target,
                payload: payload[consumed..].to_vec(),
                group_name: ctx.manager.group_name().to_string(),
                uplink_name: name,
            })
            .await
            .is_err()
        {
            return Ok(());
        }
    }
}

#[derive(Clone)]
pub(super) struct ActiveUdpTransport {
    pub(super) index: usize,
    pub(super) uplink_name: String,
    pub(super) uplink_weight: f64,
    pub(super) transport: Arc<UdpWsTransport>,
}

const MAX_CLIENT_UDP_PACKET_SIZE: usize = SHADOWSOCKS_MAX_PAYLOAD;
const MAX_UDP_RELAY_PACKET_SIZE: usize = 65_507;

fn udp_metric_payload_len(target: &TargetAddr, payload_len: usize) -> Result<usize> {
    Ok(target.to_wire_bytes()?.len().saturating_add(payload_len))
}

pub(super) async fn handle_udp_associate(
    mut client: TcpStream,
    config: Arc<AppConfig>,
    registry: UplinkRegistry,
    _client_hint: TargetAddr,
) -> Result<()> {
    let session = metrics::track_session("udp");
    let result = async {
        let bind_ip = client.local_addr()?.ip();
        let udp_socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .with_context(|| format!("failed to bind UDP relay on {}", bind_ip))?;
        let udp_socket = Arc::new(udp_socket);
        let relay_addr = udp_socket.local_addr().context("failed to read UDP relay address")?;

        // Optional socket for direct UDP packets with fwmark to prevent
        // loopback through TUN when all traffic is captured.
        let direct_socket = if routing_table_active(&config) {
            let std_sock = crate::transport::bind_udp_socket(
                SocketAddr::new(bind_ip, 0),
                config.direct_fwmark,
            )
            .with_context(|| format!("failed to bind direct UDP socket on {}", bind_ip))?;
            Some(Arc::new(UdpSocket::from_std(std_sock)?))
        } else {
            None
        };

        let client_udp_addr = Arc::new(Mutex::new(None::<SocketAddr>));
        let groups = AssocGroupMap::new();
        let (responses_tx, mut responses_rx) = mpsc::channel::<UdpResponse>(64);

        send_reply(&mut client, SOCKS_STATUS_SUCCESS, &socket_addr_to_target(relay_addr)).await?;

        let client_udp_addr_uplink = Arc::clone(&client_udp_addr);
        let socket_uplink = Arc::clone(&udp_socket);
        let groups_uplink = Arc::clone(&groups);
        let registry_uplink = registry.clone();
        let direct_socket_uplink = direct_socket.clone();
        let config_uplink = Arc::clone(&config);
        let responses_tx_uplink = responses_tx.clone();
        let uplink = async move {
            let mut buf = vec![0u8; 65_535];
            let mut reassembler = UdpFragmentReassembler::default();
            let mut route_cache: UdpRouteCache = HashMap::new();
            loop {
                let (len, addr) = socket_uplink
                    .recv_from(&mut buf)
                    .await
                    .context("UDP relay receive failed")?;
                *client_udp_addr_uplink.lock().await = Some(addr);

                let packet = parse_udp_request(&buf[..len])?;
                let Some(packet) = reassembler.push_fragment(packet)? else {
                    continue;
                };

                let group_name = match resolve_udp_packet_route(
                    &mut route_cache,
                    &config_uplink,
                    &registry_uplink,
                    &packet.target,
                )
                .await
                {
                    UdpPacketRoute::Drop => {
                        debug!(target = %packet.target, "UDP route: policy drop");
                        continue;
                    },
                    UdpPacketRoute::Direct => {
                        send_udp_direct(&direct_socket_uplink, &packet.target, &packet.payload)
                            .await?;
                        continue;
                    },
                    UdpPacketRoute::Tunnel(name) => name,
                };

                let mut payload = packet.target.to_wire_bytes()?;
                payload.extend_from_slice(&packet.payload);
                if payload.len() > MAX_CLIENT_UDP_PACKET_SIZE {
                    warn!(
                        %addr,
                        target = %packet.target,
                        payload_len = payload.len(),
                        limit = MAX_CLIENT_UDP_PACKET_SIZE,
                        "dropping oversized incoming UDP packet"
                    );
                    metrics::record_dropped_oversized_udp_packet("incoming");
                    continue;
                }

                let ctx = resolve_group_context(
                    &groups_uplink,
                    &registry_uplink,
                    &group_name,
                    &responses_tx_uplink,
                )
                .await?;
                send_tunneled_udp(&ctx, Some(&packet.target), &payload).await?;
            }
        };

        let client_udp_addr_writer = Arc::clone(&client_udp_addr);
        let socket_writer = Arc::clone(&udp_socket);
        let writer = async move {
            while let Some(response) = responses_rx.recv().await {
                let client_addr = client_udp_addr_writer.lock().await.ok_or_else(|| {
                    anyhow!("received UDP response before client sent any packet")
                })?;
                let packet = build_udp_packet(&response.target, &response.payload)?;
                if packet.len() > MAX_UDP_RELAY_PACKET_SIZE {
                    warn!(
                        %client_addr,
                        target = %response.target,
                        packet_len = packet.len(),
                        limit = MAX_UDP_RELAY_PACKET_SIZE,
                        "dropping oversized outgoing UDP response"
                    );
                    metrics::record_dropped_oversized_udp_packet("outgoing");
                    continue;
                }
                metrics::add_udp_datagram(
                    "upstream_to_client",
                    &response.group_name,
                    &response.uplink_name,
                );
                metrics::add_bytes(
                    "udp",
                    "upstream_to_client",
                    &response.group_name,
                    &response.uplink_name,
                    response.payload.len(),
                );
                socket_writer
                    .send_to(&packet, client_addr)
                    .await
                    .context("UDP relay send failed")?;
            }
            Ok::<(), anyhow::Error>(())
        };

        let control = async move {
            let mut buf = [0u8; 1];
            loop {
                let read = client
                    .read(&mut buf)
                    .await
                    .context("control connection read failed")?;
                if read == 0 {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        };

        // Receive responses from directly-contacted servers and forward to the client.
        let client_udp_addr_direct = Arc::clone(&client_udp_addr);
        let socket_direct = Arc::clone(&udp_socket);
        let direct_downlink = async move {
            let Some(sock) = direct_socket else {
                std::future::pending::<()>().await;
                unreachable!()
            };
            let mut buf = vec![0u8; MAX_UDP_RELAY_PACKET_SIZE];
            loop {
                let (len, src_addr) =
                    sock.recv_from(&mut buf).await.context("direct UDP recv failed")?;
                let client_addr = client_udp_addr_direct.lock().await.ok_or_else(|| {
                    anyhow!("received direct UDP response before client sent any packet")
                })?;
                let target = socket_addr_to_target(src_addr);
                let metric_payload_len = udp_metric_payload_len(&target, len)?;
                let packet = build_udp_packet(&target, &buf[..len])?;
                if packet.len() > MAX_UDP_RELAY_PACKET_SIZE {
                    warn!(
                        %client_addr,
                        target = %target,
                        packet_len = packet.len(),
                        limit = MAX_UDP_RELAY_PACKET_SIZE,
                        "dropping oversized direct UDP response"
                    );
                    metrics::record_dropped_oversized_udp_packet("outgoing");
                    continue;
                }
                socket_direct
                    .send_to(&packet, client_addr)
                    .await
                    .context("direct UDP relay send failed")?;
                metrics::add_udp_datagram(
                    "upstream_to_client",
                    metrics::DIRECT_GROUP_LABEL,
                    metrics::DIRECT_UPLINK_LABEL,
                );
                metrics::add_bytes(
                    "udp",
                    "upstream_to_client",
                    metrics::DIRECT_GROUP_LABEL,
                    metrics::DIRECT_UPLINK_LABEL,
                    metric_payload_len,
                );
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };

        let session_result = tokio::select! {
            result = uplink => result,
            result = writer => result,
            result = control => result,
            result = direct_downlink => result,
        };
        groups.shutdown("session_end").await;
        session_result
    }
    .await;
    session.finish(result.is_ok());
    result
}

/// Forward a datagram to a directly-contacted server via the direct socket.
/// Domain targets are resolved through the shared DNS cache, mirroring the
/// TCP direct path so SOCKS5 UDP ASSOCIATE clients that send `ATYP=03` can
/// use policy-direct routing.
async fn send_udp_direct(
    direct_socket: &Option<Arc<UdpSocket>>,
    target: &TargetAddr,
    payload: &[u8],
) -> Result<()> {
    let Some(sock) = direct_socket else {
        warn!(target = %target, "UDP direct route requested but direct socket not allocated; dropping");
        return Ok(());
    };
    let metric_payload_len = udp_metric_payload_len(target, payload.len())?;
    let target_addr = match target {
        TargetAddr::IpV4(ip, port) => SocketAddr::new(std::net::IpAddr::V4(*ip), *port),
        TargetAddr::IpV6(ip, port) => SocketAddr::new(std::net::IpAddr::V6(*ip), *port),
        TargetAddr::Domain(host, port) => {
            let resolved = crate::transport::resolve_host_with_preference(
                host,
                *port,
                "UDP direct resolve",
                false,
            )
            .await
            .with_context(|| format!("UDP direct: failed to resolve {target}"))?;
            match resolved.into_iter().next() {
                Some(addr) => addr,
                None => {
                    warn!(target = %target, "UDP direct: DNS returned no addresses; dropping");
                    return Ok(());
                },
            }
        },
    };
    sock.send_to(payload, target_addr)
        .await
        .context("direct UDP send failed")?;
    metrics::add_udp_datagram(
        "client_to_upstream",
        metrics::DIRECT_GROUP_LABEL,
        metrics::DIRECT_UPLINK_LABEL,
    );
    metrics::add_bytes(
        "udp",
        "client_to_upstream",
        metrics::DIRECT_GROUP_LABEL,
        metrics::DIRECT_UPLINK_LABEL,
        metric_payload_len,
    );
    Ok(())
}

/// Send a pre-wrapped payload through a group's active transport, with
/// reconciliation + runtime failover mirroring the pre-refactor uplink loop.
async fn send_tunneled_udp(
    ctx: &GroupUdpContext,
    target: Option<&TargetAddr>,
    payload: &[u8],
) -> Result<()> {
    reconcile_global_udp_transport(&ctx.manager, &ctx.active, target).await?;
    let (transport, uplink_name, active_index) = {
        let active = ctx.active.lock().await;
        (Arc::clone(&active.transport), active.uplink_name.clone(), active.index)
    };
    let group = ctx.manager.group_name();
    if let Err(error) = transport.send_packet(payload).await {
        if is_dropped_oversized_udp_error(&error) {
            return Ok(());
        }
        let replacement =
            failover_udp_transport(&ctx.manager, &ctx.active, target, active_index, error).await?;
        if let Err(error) = replacement.transport.send_packet(payload).await {
            if is_dropped_oversized_udp_error(&error) {
                return Ok(());
            }
            return Err(error);
        }
        metrics::add_udp_datagram("client_to_upstream", group, &replacement.uplink_name);
        metrics::add_bytes(
            "udp",
            "client_to_upstream",
            group,
            &replacement.uplink_name,
            payload.len(),
        );
        ctx.manager.report_active_traffic(replacement.index, TransportKind::Udp).await;
    } else {
        metrics::add_udp_datagram("client_to_upstream", group, &uplink_name);
        metrics::add_bytes("udp", "client_to_upstream", group, &uplink_name, payload.len());
        ctx.manager.report_active_traffic(active_index, TransportKind::Udp).await;
    }
    Ok(())
}

pub(super) async fn handle_udp_in_tcp(
    mut client: TcpStream,
    config: Arc<AppConfig>,
    registry: UplinkRegistry,
    client_hint: TargetAddr,
) -> Result<()> {
    let session = metrics::track_session("udp");
    let result = async {
        let bind_ip = client.local_addr()?.ip();
        let direct_socket = if routing_table_active(&config) {
            let std_sock = crate::transport::bind_udp_socket(
                SocketAddr::new(bind_ip, 0),
                config.direct_fwmark,
            )
            .with_context(|| format!("failed to bind direct UDP socket on {}", bind_ip))?;
            Some(Arc::new(UdpSocket::from_std(std_sock)?))
        } else {
            None
        };

        send_reply(&mut client, SOCKS_STATUS_SUCCESS, &client_hint).await?;

        let (mut client_read, mut client_write) = client.into_split();

        let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(64);

        let tcp_writer = async move {
            while let Some(frame) = write_rx.recv().await {
                client_write
                    .write_all(&frame)
                    .await
                    .context("UDP-in-TCP client write failed")?;
            }
            Ok::<(), anyhow::Error>(())
        };

        let groups = AssocGroupMap::new();
        let (responses_tx, mut responses_rx) = mpsc::channel::<UdpResponse>(64);

        let groups_uplink = Arc::clone(&groups);
        let registry_uplink = registry.clone();
        let direct_socket_uplink = direct_socket.clone();
        let config_uplink = Arc::clone(&config);
        let responses_tx_uplink = responses_tx.clone();
        let uplink = async move {
            let mut route_cache: UdpRouteCache = HashMap::new();
            loop {
                let Some(packet) = read_udp_tcp_packet(&mut client_read).await? else {
                    break;
                };

                let group_name = match resolve_udp_packet_route(
                    &mut route_cache,
                    &config_uplink,
                    &registry_uplink,
                    &packet.target,
                )
                .await
                {
                    UdpPacketRoute::Drop => {
                        debug!(target = %packet.target, "UDP-in-TCP route: policy drop");
                        continue;
                    },
                    UdpPacketRoute::Direct => {
                        send_udp_direct(&direct_socket_uplink, &packet.target, &packet.payload)
                            .await?;
                        continue;
                    },
                    UdpPacketRoute::Tunnel(name) => name,
                };

                let mut payload = packet.target.to_wire_bytes()?;
                payload.extend_from_slice(&packet.payload);
                if payload.len() > MAX_CLIENT_UDP_PACKET_SIZE {
                    warn!(
                        target = %packet.target,
                        payload_len = payload.len(),
                        limit = MAX_CLIENT_UDP_PACKET_SIZE,
                        "dropping oversized incoming UDP-in-TCP packet"
                    );
                    metrics::record_dropped_oversized_udp_packet("incoming");
                    continue;
                }

                let ctx = resolve_group_context(
                    &groups_uplink,
                    &registry_uplink,
                    &group_name,
                    &responses_tx_uplink,
                )
                .await?;
                send_tunneled_udp(&ctx, Some(&packet.target), &payload).await?;
            }
            Ok::<(), anyhow::Error>(())
        };

        let write_tx_writer = write_tx.clone();
        let writer = async move {
            while let Some(response) = responses_rx.recv().await {
                write_udp_tcp_response(
                    &write_tx_writer,
                    &response.target,
                    &response.payload,
                    "upstream UDP-in-TCP response",
                )
                .await?;
                metrics::add_udp_datagram(
                    "upstream_to_client",
                    &response.group_name,
                    &response.uplink_name,
                );
                metrics::add_bytes(
                    "udp",
                    "upstream_to_client",
                    &response.group_name,
                    &response.uplink_name,
                    response.payload.len(),
                );
            }
            Ok::<(), anyhow::Error>(())
        };

        let write_tx_direct = write_tx.clone();
        let direct_downlink = async move {
            let Some(sock) = direct_socket else {
                std::future::pending::<()>().await;
                unreachable!()
            };
            let mut buf = vec![0u8; MAX_UDP_RELAY_PACKET_SIZE];
            loop {
                let (len, src_addr) =
                    sock.recv_from(&mut buf).await.context("direct UDP recv failed")?;
                let target = socket_addr_to_target(src_addr);
                let metric_payload_len = udp_metric_payload_len(&target, len)?;
                write_udp_tcp_response(
                    &write_tx_direct,
                    &target,
                    &buf[..len],
                    "direct UDP-in-TCP response",
                )
                .await?;
                metrics::add_udp_datagram(
                    "upstream_to_client",
                    metrics::DIRECT_GROUP_LABEL,
                    metrics::DIRECT_UPLINK_LABEL,
                );
                metrics::add_bytes(
                    "udp",
                    "upstream_to_client",
                    metrics::DIRECT_GROUP_LABEL,
                    metrics::DIRECT_UPLINK_LABEL,
                    metric_payload_len,
                );
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };

        let session_result = tokio::select! {
            result = uplink => result,
            result = writer => result,
            result = direct_downlink => result,
            result = tcp_writer => result,
        };
        groups.shutdown("session_end").await;
        session_result
    }
    .await;
    session.finish(result.is_ok());
    result
}

pub(super) async fn select_udp_transport(
    uplinks: &UplinkManager,
    target: Option<&TargetAddr>,
) -> Result<ActiveUdpTransport> {
    let mut last_error = None;
    let strict_transport = uplinks.strict_active_uplink_for(TransportKind::Udp);
    let candidates = uplinks.udp_candidates(target).await;
    let iter = if strict_transport {
        candidates.into_iter().take(1).collect::<Vec<_>>()
    } else {
        candidates
    };
    for candidate in iter {
        match uplinks.acquire_udp_standby_or_connect(&candidate, "socks_udp").await {
            Ok(transport) => {
                uplinks
                    .confirm_selected_uplink(TransportKind::Udp, target, candidate.index)
                    .await;
                return Ok(ActiveUdpTransport {
                    index: candidate.index,
                    uplink_name: candidate.uplink.name.clone(),
                    uplink_weight: candidate.uplink.weight,
                    transport: Arc::new(transport),
                });
            },
            Err(error) => {
                uplinks
                    .report_runtime_failure(candidate.index, TransportKind::Udp, &error)
                    .await;
                last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
            },
        }
    }

    Err(anyhow!(
        "all UDP uplinks failed: {}",
        last_error.unwrap_or_else(|| "no UDP-capable uplinks available".to_string())
    ))
}

async fn failover_udp_transport(
    uplinks: &UplinkManager,
    active_transport: &Arc<Mutex<ActiveUdpTransport>>,
    target: Option<&TargetAddr>,
    failed_index: usize,
    error: anyhow::Error,
) -> Result<ActiveUdpTransport> {
    let failed_uplink_name = {
        let active = active_transport.lock().await;
        if active.index != failed_index {
            return Ok(active.clone());
        }
        active.uplink_name.clone()
    };
    uplinks
        .report_runtime_failure(failed_index, TransportKind::Udp, &error)
        .await;
    let replacement = select_udp_transport(uplinks, target).await?;
    if let Some(previous_transport) = replace_active_udp_transport_if_current(
        active_transport,
        failed_index,
        ActiveUdpTransport {
            index: replacement.index,
            uplink_name: replacement.uplink_name.clone(),
            uplink_weight: replacement.uplink_weight,
            transport: Arc::clone(&replacement.transport),
        },
    )
    .await
    {
        info!(
            failed_index,
            failed_uplink = %failed_uplink_name,
            new_uplink = %replacement.uplink_name,
            error = %format!("{error:#}"),
            "runtime UDP failover activated"
        );
        metrics::record_failover(
            "udp",
            uplinks.group_name(),
            &failed_uplink_name,
            &replacement.uplink_name,
        );
        metrics::record_uplink_selected(
            "udp",
            uplinks.group_name(),
            &replacement.uplink_name,
        );
        close_udp_transport(previous_transport, "failover").await;
        return Ok(replacement);
    }
    Ok(active_transport.lock().await.clone())
}

async fn reconcile_global_udp_transport(
    uplinks: &UplinkManager,
    active_transport: &Arc<Mutex<ActiveUdpTransport>>,
    target: Option<&TargetAddr>,
) -> Result<()> {
    if !uplinks.strict_active_uplink_for(TransportKind::Udp) {
        return Ok(());
    }

    let current_active = uplinks.active_uplink_index_for_transport(TransportKind::Udp).await;
    let selected = active_transport.lock().await.index;
    if current_active == Some(selected) || current_active.is_none() {
        return Ok(());
    }

    let replaced_uplink_name = {
        let active = active_transport.lock().await;
        if active.index != selected {
            return Ok(());
        }
        active.uplink_name.clone()
    };
    let replacement = select_udp_transport(uplinks, target).await?;
    if let Some(previous_transport) = replace_active_udp_transport_if_current(
        active_transport,
        selected,
        ActiveUdpTransport {
            index: replacement.index,
            uplink_name: replacement.uplink_name.clone(),
            uplink_weight: replacement.uplink_weight,
            transport: Arc::clone(&replacement.transport),
        },
    )
    .await
    {
        metrics::record_failover(
            "udp",
            uplinks.group_name(),
            &replaced_uplink_name,
            &replacement.uplink_name,
        );
        metrics::record_uplink_selected(
            "udp",
            uplinks.group_name(),
            &replacement.uplink_name,
        );
        close_udp_transport(previous_transport, "global_switch").await;
    }
    Ok(())
}

async fn replace_active_udp_transport_if_current(
    active_transport: &Arc<Mutex<ActiveUdpTransport>>,
    expected_index: usize,
    replacement: ActiveUdpTransport,
) -> Option<Arc<UdpWsTransport>> {
    let mut active = active_transport.lock().await;
    if active.index != expected_index {
        return None;
    }
    let previous_transport = Arc::clone(&active.transport);
    *active = replacement;
    Some(previous_transport)
}

async fn close_active_udp_transport(
    active_transport: &Arc<Mutex<ActiveUdpTransport>>,
    reason: &'static str,
) {
    let transport = {
        let active = active_transport.lock().await;
        Arc::clone(&active.transport)
    };
    close_udp_transport(transport, reason).await;
}

async fn close_udp_transport(transport: Arc<UdpWsTransport>, reason: &'static str) {
    if let Err(error) = transport.close().await {
        debug!(
            reason,
            error = %format!("{error:#}"),
            "failed to close SOCKS5 UDP transport"
        );
    }
}

async fn write_udp_tcp_response(
    write_tx: &mpsc::Sender<Vec<u8>>,
    target: &TargetAddr,
    payload: &[u8],
    context: &'static str,
) -> Result<()> {
    let addr_wire = target.to_wire_bytes()?;
    let header_len = 3 + addr_wire.len();
    if header_len > usize::from(u8::MAX) || payload.len() > usize::from(u16::MAX) {
        warn!(
            target = %target,
            payload_len = payload.len(),
            context,
            "dropping oversized outgoing UDP-in-TCP response"
        );
        metrics::record_dropped_oversized_udp_packet("outgoing");
        return Ok(());
    }

    let data_len = payload.len() as u16;
    let header_len = header_len as u8;

    let mut frame = Vec::with_capacity(2 + 1 + addr_wire.len() + payload.len());
    frame.extend_from_slice(&data_len.to_be_bytes());
    frame.push(header_len);
    frame.extend_from_slice(&addr_wire);
    frame.extend_from_slice(payload);

    write_tx
        .send(frame)
        .await
        .with_context(|| format!("failed to write {context}: TCP writer task exited"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::net::UdpSocket;

    use super::*;
    use crate::types::CipherKind;

    #[tokio::test]
    async fn replacing_active_udp_transport_closes_previous_reader() {
        let old_transport = Arc::new(
            UdpWsTransport::from_socket(
                UdpSocket::bind(("127.0.0.1", 0)).await.unwrap(),
                CipherKind::Chacha20IetfPoly1305,
                "password",
                "test_old",
            )
            .unwrap(),
        );
        let new_transport = Arc::new(
            UdpWsTransport::from_socket(
                UdpSocket::bind(("127.0.0.1", 0)).await.unwrap(),
                CipherKind::Chacha20IetfPoly1305,
                "password",
                "test_new",
            )
            .unwrap(),
        );
        let active_transport = Arc::new(Mutex::new(ActiveUdpTransport {
            index: 1,
            uplink_name: "old".to_string(),
            uplink_weight: 1.0,
            transport: Arc::clone(&old_transport),
        }));

        let reader_transport = Arc::clone(&old_transport);
        let read_task = tokio::spawn(async move { reader_transport.read_packet().await });

        let previous_transport = replace_active_udp_transport_if_current(
            &active_transport,
            1,
            ActiveUdpTransport {
                index: 2,
                uplink_name: "new".to_string(),
                uplink_weight: 1.0,
                transport: Arc::clone(&new_transport),
            },
        )
        .await
        .expect("active transport should be replaced");
        close_udp_transport(previous_transport, "test_replace").await;

        let error = tokio::time::timeout(Duration::from_secs(1), async {
            read_task.await.unwrap().unwrap_err()
        })
        .await
        .unwrap();
        assert!(format!("{error:#}").contains("udp transport closed"));
        assert_eq!(active_transport.lock().await.index, 2);
    }

    // ── classify_decision ─────────────────────────────────────────────────────

    /// When the routing table references a group name that is not in the
    /// registry, `classify_decision` must fall back to the registry's default
    /// group rather than panicking or returning an error.  This is consistent
    /// with the TCP dispatch path (`resolve_single_target`).
    #[tokio::test]
    async fn classify_decision_unknown_group_falls_back_to_default() {
        use std::time::Duration;
        use url::Url;

        use crate::config::{
            LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, UplinkConfig,
            WsProbeConfig,
        };
        use crate::types::{UplinkTransport, WsTransportMode};
        use crate::uplink::{UplinkManager, UplinkRegistry};

        let uplink = UplinkConfig {
            name: "default-uplink".to_string(),
            transport: UplinkTransport::Websocket,
            tcp_ws_url: Some(Url::parse("wss://127.0.0.1:1/tcp").unwrap()),
            tcp_ws_mode: WsTransportMode::Http1,
            udp_ws_url: None,
            udp_ws_mode: WsTransportMode::Http1,
            tcp_addr: None,
            udp_addr: None,
            cipher: crate::types::CipherKind::Chacha20IetfPoly1305,
            password: "s3cr3t_password".to_string(),
            weight: 1.0,
            fwmark: None,
            ipv6_first: false,
        };
        let probe = ProbeConfig {
            interval: Duration::from_secs(120),
            timeout: Duration::from_secs(10),
            max_concurrent: 4,
            max_dials: 2,
            min_failures: 3,
            attempts: 1,
            ws: WsProbeConfig { enabled: false },
            http: None,
            dns: None,
            tcp: None,
        };
        let lb = LoadBalancingConfig {
            mode: LoadBalancingMode::ActiveActive,
            routing_scope: RoutingScope::PerFlow,
            sticky_ttl: Duration::from_secs(300),
            hysteresis: Duration::from_millis(50),
            failure_cooldown: Duration::from_secs(10),
            tcp_chunk0_failover_timeout: Duration::from_secs(10),
            warm_standby_tcp: 0,
            warm_standby_udp: 0,
            rtt_ewma_alpha: 0.25,
            failure_penalty: Duration::from_millis(500),
            failure_penalty_max: Duration::from_secs(30),
            failure_penalty_halflife: Duration::from_secs(60),
            h3_downgrade_duration: Duration::from_secs(60),
            udp_ws_keepalive_interval: None,
            tcp_ws_standby_keepalive_interval: None,
            tcp_active_keepalive_interval: None,
            auto_failback: false,
        };

        let manager = UplinkManager::new("my-default", vec![uplink], probe, lb).unwrap();
        let registry = UplinkRegistry::from_single_manager(manager);

        // The routing table resolved to group "nonexistent" which is not in the registry.
        let route = classify_decision(
            &registry,
            crate::config::RouteTarget::Group("nonexistent".into()),
            None,
        )
        .await;

        // Must fall back to the registry's default group name.
        match route {
            UdpPacketRoute::Tunnel(name) => {
                assert_eq!(name, registry.default_group_name(), "must fall back to default group")
            }
            other => panic!("expected Tunnel(default), got {other:?}"),
        }
    }
}
