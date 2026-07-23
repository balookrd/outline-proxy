use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use tokio::sync::{Mutex, RwLock, mpsc};
use tracing::debug;

use std::net::SocketAddr;

use anyhow::Context;
use tokio::net::UdpSocket;
use tracing::{info, warn};

use super::lifecycle::CloseWork;
use super::sni_cache::{SNI_ROUTE_CACHE_CAP, SNI_ROUTE_CACHE_TTL, SniRouteCache};
use super::types::{
    DirectFlowTable, DirectUdpFlowState, FlowTable, UdpFlowKey, bump_last_seen_if_current,
};
use super::wire::{IpVersion, ParsedUdpPacket, build_ipv4_udp_packet, build_ipv6_udp_packet};
use crate::atomic_counter::CounterU64;
use crate::icmp::{
    IPV4_MIN_PATH_MTU, IPV6_MIN_PATH_MTU, build_icmpv4_frag_needed, build_icmpv6_packet_too_big,
};
use crate::{SharedTunWriter, TunRoute, TunRouting};
use outline_metrics as metrics;
use outline_transport::{AbortOnDrop, OversizedUdpDatagram};
use socks5_proto::TargetAddr;

/// Upper bound for a single received UDP datagram (max UDP payload is 65 507
/// bytes; the extra slack keeps the ceiling at the IPv4 total-length limit).
/// Used to size the direct reader's receive buffer.
const MAX_UDP_DATAGRAM: usize = 65_535;

#[derive(Clone)]
pub struct TunUdpEngine {
    pub(super) inner: Arc<TunUdpEngineInner>,
}

pub(super) struct TunUdpEngineInner {
    pub(super) writer: SharedTunWriter,
    /// Dispatch resolves a flow's destination to a group manager at
    /// creation time; engine code that needs a "default" (cleanup loops,
    /// strict checks without flow context) reads `dispatch.default_group()`.
    pub(super) dispatch: TunRouting,
    pub(super) flows: FlowTable,
    /// Direct-routed flows: per-flow UDP socket + reader task.
    pub(super) direct_flows: DirectFlowTable,
    pub(super) next_flow_id: CounterU64,
    pub(super) max_flows: usize,
    pub(super) idle_timeout: Duration,
    /// Async cleanup pool: flows removed from the table are sent here so
    /// `transport.close()` runs off the hot path without holding any map lock.
    pub(super) close_tx: mpsc::UnboundedSender<CloseWork>,
    /// When `false` (default), the PMTUD path refuses to advertise a path
    /// MTU below the QUIC v1 Initial-datagram minimum (1200 v4 / 1280 v6,
    /// RFC 9000 §14.1) — sending such a PTB would tell compliant QUIC
    /// stacks the destination cannot carry QUIC and silently evict them
    /// onto TCP. Operators running pure VoWiFi / IKEv2 concentrators
    /// with no QUIC clients to protect can set
    /// [`TunConfig::pmtud_emit_below_quic_initial`](crate::TunConfig)
    /// to `true` to restore the unconditional PTB emission and surface
    /// explicit PMTUD signals on every sub-1200/1280 drop.
    pub(super) pmtud_emit_below_quic_initial: bool,
    /// QUIC connection sniffing for the UDP path. See
    /// [`TunConfig::sniff_quic`](crate::TunConfig).
    pub(super) sniff_quic: bool,
    /// Route a new flow by its sniffed QUIC SNI (domain rules first, then the
    /// literal IP) instead of by IP alone. See
    /// [`TunConfig::route_by_sni`](crate::TunConfig). Implies `sniff_quic`
    /// (enforced at config load).
    pub(super) route_by_sni: bool,
    /// Domain suffixes excluded from QUIC sniff destination-override. See
    /// [`TunConfig::sniff_override_exclude`](crate::TunConfig).
    pub(super) sniff_override_exclude: std::sync::Arc<[Box<str>]>,
    /// Domain sniffed per `(client, destination)` pair, consulted when a new
    /// flow's first datagram carries no ClientHello — see [`SniRouteCache`].
    /// `None` unless `route_by_sni` is on, so the feature-off path allocates
    /// nothing and never takes the lock.
    pub(super) sni_route_cache: Option<parking_lot::Mutex<SniRouteCache>>,
    /// `TUN_F_USO` accepted at attach — coalesce equal-sized downlink UDP
    /// datagrams of one flow into a `GSO_UDP_L4` super-segment on write. See
    /// [`TunConfig::uso`](crate::TunConfig).
    pub(super) udp_gso: bool,
    /// Admission gate for upstream dials (`[tun] max_concurrent_upstream_dials`),
    /// shared with the TCP engine — see `TunTcpEngineInner::dial_admission`.
    /// The uplink task keeps buffering the client's datagrams (handshake
    /// preface) while it queues for a permit. Unset = no limit.
    pub(super) dial_admission: std::sync::OnceLock<Arc<tokio::sync::Semaphore>>,
}

impl TunUdpEngine {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        writer: SharedTunWriter,
        dispatch: TunRouting,
        max_flows: usize,
        idle_timeout: Duration,
        pmtud_emit_below_quic_initial: bool,
        sniff_quic: bool,
        route_by_sni: bool,
        sniff_override_exclude: std::sync::Arc<[Box<str>]>,
        udp_gso: bool,
    ) -> Self {
        let (close_tx, close_rx) = mpsc::unbounded_channel();
        let engine = Self {
            inner: Arc::new(TunUdpEngineInner {
                writer,
                dispatch,
                flows: Arc::new(RwLock::new(HashMap::new())),
                direct_flows: Arc::new(RwLock::new(HashMap::new())),
                next_flow_id: CounterU64::new(1),
                max_flows,
                idle_timeout,
                close_tx,
                pmtud_emit_below_quic_initial,
                sniff_quic,
                route_by_sni,
                sniff_override_exclude,
                sni_route_cache: route_by_sni.then(|| {
                    parking_lot::Mutex::new(SniRouteCache::new(
                        SNI_ROUTE_CACHE_CAP,
                        SNI_ROUTE_CACHE_TTL,
                    ))
                }),
                udp_gso,
                dial_admission: std::sync::OnceLock::new(),
            }),
        };
        engine.spawn_cleanup_loop();
        engine.spawn_cleanup_pool(close_rx);
        engine
    }

    /// Install the process-wide upstream-dial admission semaphore (shared with
    /// the TCP engine). Called once at engine wiring, before any traffic;
    /// never called when the limit is disabled.
    pub(crate) fn set_dial_admission(&self, semaphore: Arc<tokio::sync::Semaphore>) {
        let _ = self.inner.dial_admission.set(semaphore);
    }

    pub(crate) async fn handle_packet(&self, packet: ParsedUdpPacket) -> Result<()> {
        let remote_target = super::ip_to_target(packet.destination_ip, packet.destination_port);
        let key = UdpFlowKey {
            version: packet.version,
            local_ip: packet.source_ip,
            local_port: packet.source_port,
            remote_ip: packet.destination_ip,
            remote_port: packet.destination_port,
        };

        // Check if this is an existing direct flow first. Clone the Arc
        // under a short read-lock, then operate on the per-flow Mutex so
        // concurrent packets on other flows are not serialised.
        let direct_flow = {
            let guard = self.inner.direct_flows.read().await;
            guard.get(&key).map(Arc::clone)
        };
        if let Some(flow_handle) = direct_flow {
            let mut flow = flow_handle.lock().await;
            flow.last_seen = Instant::now();
            let target_addr = SocketAddr::new(key.remote_ip, key.remote_port);
            // `send_to().await` runs under the per-flow Mutex only — other
            // direct flows remain unblocked while the kernel completes the
            // send. Ordering of datagrams within this flow is preserved.
            flow.socket
                .send_to(&packet.payload, target_addr)
                .await
                .context("direct UDP send failed")?;
            metrics::direct_udp_counters("up").record(packet.payload.len());
            return Ok(());
        }

        // Existing tunnelled flow: hand the raw datagram to its outbound queue
        // and return immediately. The per-flow uplink task drains the queue and
        // awaits the carrier send on its own task, so carrier back-pressure
        // never reaches this shared read-loop — the decoupling point that stops
        // a slow/parked carrier from head-of-line-blocking every other flow.
        // Strict-active migration is handled by the uplink task and the
        // downlink reader, not on this hot path.
        if let Some(handle) = self.inner.flows.read().await.get(&key).map(Arc::clone) {
            let outbound_tx = {
                let mut flow = handle.lock().await;
                flow.last_seen = Instant::now();
                flow.outbound_tx.clone()
            };
            super::lifecycle::queue_client_datagram(&outbound_tx, Bytes::from(packet.payload));
            return Ok(());
        }

        // New flow. When SNI-routing is on we sniff the QUIC Initial up-front
        // so the recovered domain can steer the route (domain rules first, IP
        // fallback); that same sniff result also drives destination-override
        // framing, so a flow is sniffed at most once. A datagram with no
        // ClientHello falls back to the domain remembered for this
        // `(client, destination)` pair, which keeps a QUIC connection whose
        // flow was torn down mid-session on its original route. When off we
        // keep the legacy order: route purely by IP, and sniff only inside the
        // Group arm for framing — so a flow that resolves to Direct/Drop never
        // pays the QUIC-decrypt cost.
        let presniffed: Option<Option<TargetAddr>> = if self.inner.route_by_sni {
            Some(self.sniffed_or_remembered_domain(&key, &packet.payload))
        } else {
            None
        };
        let route = match presniffed.as_ref() {
            Some(override_target) => {
                let sni_host = override_target.as_ref().and_then(|t| match t {
                    TargetAddr::Domain(host, _) => Some(host.as_str()),
                    _ => None,
                });
                self.inner.dispatch.resolve_udp_sni(sni_host, &remote_target).await
            },
            None => self.inner.dispatch.resolve_udp(&remote_target).await,
        };
        match route {
            TunRoute::Direct { fwmark } => {
                self.handle_direct_packet(key, &remote_target, &packet, fwmark).await
            },
            TunRoute::Drop { reason } => {
                debug!(target = %remote_target, reason, "TUN UDP route: dropping flow");
                Ok(())
            },
            TunRoute::Group { manager, .. } => {
                // Connection sniffing for destination-override framing: pin the
                // flow to the sniffed domain so the exit resolves it. Reuse the
                // up-front sniff when SNI-routing already ran it; otherwise sniff
                // now (legacy path). Then register the flow and hand off to its
                // uplink task, which dials the carrier off this read-loop
                // (buffering datagrams meanwhile) instead of dialling inline.
                let override_target = match presniffed {
                    Some(sniffed) => sniffed,
                    None => self.sniff_quic_override(&packet.payload, key.remote_port),
                };
                self.spawn_tunnel_flow(key, &manager, override_target, Bytes::from(packet.payload))
                    .await;
                Ok(())
            },
        }
    }

    /// Destination domain for a new SNI-routed flow: the SNI carried by this
    /// datagram's QUIC Initial, or — when there is none to sniff — the domain
    /// remembered for the same `(client, destination)` pair.
    ///
    /// Only a QUIC Initial carries a ClientHello, so a flow torn down while
    /// its connection is still live (idle eviction, carrier read error,
    /// `max_flows` eviction) is recreated from a Short Header and has nothing
    /// to sniff. Resolving that by literal IP would hand a live QUIC
    /// connection to a different exit — or drop it — mid-session, because the
    /// domain rule that picked the original route no longer applies. The
    /// recalled domain drives both the route and the destination-override
    /// framing, exactly as the original sniff did.
    ///
    /// Only called with `route_by_sni` on; the memory is bounded and
    /// invalidated by routing-table version (see [`SniRouteCache`]).
    fn sniffed_or_remembered_domain(&self, key: &UdpFlowKey, payload: &[u8]) -> Option<TargetAddr> {
        let table_version = self.inner.dispatch.routing_version();
        let now = Instant::now();
        let cache = self.inner.sni_route_cache.as_ref();
        match self.sniff_quic_override(payload, key.remote_port) {
            Some(TargetAddr::Domain(host, port)) => {
                if let Some(cache) = cache {
                    cache.lock().remember(key, &host, table_version, now);
                }
                Some(TargetAddr::Domain(host, port))
            },
            // `sniff_quic_override` only ever yields a domain; anything else
            // is passed through untouched rather than assumed unreachable.
            Some(other) => Some(other),
            None => {
                let host = cache?.lock().recall(key, table_version, now)?;
                metrics::record_tun_udp_sniff("recalled");
                debug!(
                    host = %host,
                    port = key.remote_port,
                    "TUN UDP sniff: reusing domain remembered for this client/destination pair"
                );
                Some(TargetAddr::Domain(host.to_string(), key.remote_port))
            },
        }
    }

    /// Connection sniffing for the UDP path: if QUIC sniffing is enabled and
    /// `payload` is a QUIC Initial whose ClientHello carries an SNI, return a
    /// `TargetAddr::Domain` for `remote_port`. Returns `None` otherwise — most
    /// first datagrams (DNS, STUN, plain UDP) are not QUIC Initials, so only
    /// successful overrides are counted to keep the metric low-cardinality.
    fn sniff_quic_override(&self, payload: &[u8], remote_port: u16) -> Option<TargetAddr> {
        if !self.inner.sniff_quic {
            return None;
        }
        match crate::quic_sniff::sniff_quic_sni(payload) {
            crate::sniff::SniffOutcome::Found(host) => {
                if crate::sniff::host_is_excluded(&host, &self.inner.sniff_override_exclude) {
                    metrics::record_tun_udp_sniff("excluded");
                    debug!(host, "TUN UDP sniff: QUIC host excluded from override, framing by IP");
                    return None;
                }
                metrics::record_tun_udp_sniff("override");
                debug!(
                    host,
                    port = remote_port,
                    "TUN UDP sniff: QUIC destination overridden to domain"
                );
                Some(TargetAddr::Domain(host, remote_port))
            },
            crate::sniff::SniffOutcome::Incomplete | crate::sniff::SniffOutcome::NotMatched => None,
        }
    }

    /// Send an ICMP "Fragmentation Needed" (IPv4) or ICMPv6 "Packet Too
    /// Big" reply to the sender of a UDP datagram that was just dropped by
    /// the transport for being too large. Without this the client has no
    /// way to learn the effective tunnel MTU and keeps retransmitting the
    /// same oversize payload (real-world breakage: VoWiFi IKE_AUTH with
    /// certificates over a raw-QUIC uplink).
    ///
    /// Throttled per-flow to one PTB every [`Self::PTB_THROTTLE`] — RFC
    /// 4443 §2.4(f) makes this mandatory for ICMPv6 and RFC 1812 §4.3.2.8
    /// strongly recommends it for IPv4. Bursts of oversize sends (e.g.
    /// IKE retransmits) thus produce one PTB per second per flow, which is
    /// enough for the sender's PMTUD logic to react.
    ///
    /// Suppressed entirely when the transport's reported limit sits below
    /// QUIC v1's minimum Initial-datagram floor (1200 v4 / 1280 v6, RFC
    /// 9000 §14.1). A PTB advertising a path MTU below that floor tells
    /// well-behaved QUIC clients that the destination cannot carry QUIC at
    /// all; they comply by disabling QUIC for the destination and falling
    /// back to TCP — the opposite of what an operator carrying real QUIC
    /// traffic (YouTube, Google services, …) wants. The PMTUD machinery
    /// stays useful for legitimate path-MTU drops higher up (VoWiFi
    /// IKE_AUTH with certificates, GRE / IPsec encapsulation overhead,
    /// ~1300–1450 byte budgets); only the sub-QUIC-floor range is muted.
    ///
    /// The suppression is operator-overridable via
    /// [`TunConfig::pmtud_emit_below_quic_initial`](crate::TunConfig);
    /// setting it to `true` restores the unconditional PTB emission for
    /// deployments that prefer explicit PMTUD signalling on every
    /// sub-1200/1280 drop (e.g. pure VoWiFi / IKE concentrators with no
    /// QUIC traffic to protect).
    ///
    /// Best-effort: any failure (writer error, malformed parsed packet) is
    /// logged at `debug!` and swallowed — the drop is already classified
    /// by the caller, the metric is already incremented at the transport
    /// boundary, and we must not turn an oversize drop into a hard error.
    pub(super) async fn emit_pmtud_after_oversize_drop(
        &self,
        key: &UdpFlowKey,
        error: &anyhow::Error,
    ) {
        let limit = error
            .chain()
            .find_map(|e| e.downcast_ref::<OversizedUdpDatagram>().map(|o| o.limit));
        if !should_emit_ptb_for_limit(limit, key.version, self.inner.pmtud_emit_below_quic_initial)
        {
            return;
        }
        if !self.claim_ptb_emission_slot(key).await {
            return;
        }
        if let Err(err) = self.write_pmtud_packet(key, limit).await {
            debug!(
                error = %format!("{err:#}"),
                "failed to emit ICMP PTB after TUN UDP oversize drop"
            );
        }
    }

    /// Minimum interval between PTBs synthesised for the same flow. Aligned
    /// with the Linux `net.ipv4.icmp_ratelimit` default (1000 ms).
    const PTB_THROTTLE: Duration = Duration::from_secs(1);

    /// Returns `true` if the caller is allowed to synthesise a PTB for the
    /// flow at `key` right now, and atomically records the new emission
    /// timestamp on the flow. Returns `false` if the previous PTB was sent
    /// within [`Self::PTB_THROTTLE`], or if the flow no longer exists.
    ///
    /// Returning `false` on a missing flow is deliberate: with no flow
    /// state we have no place to keep the throttle, and a flow that just
    /// disappeared from the table is racing against the cleanup path
    /// anyway — letting the PTB go unthrottled there would defeat the
    /// rate-limit during teardown bursts.
    async fn claim_ptb_emission_slot(&self, key: &UdpFlowKey) -> bool {
        let handle = self.inner.flows.read().await.get(key).map(Arc::clone);
        let Some(handle) = handle else {
            return false;
        };
        let mut flow = handle.lock().await;
        let now = Instant::now();
        if !should_emit_ptb_now(flow.last_ptb_sent, now, Self::PTB_THROTTLE) {
            return false;
        }
        flow.last_ptb_sent = Some(now);
        true
    }

    async fn write_pmtud_packet(&self, key: &UdpFlowKey, limit: Option<usize>) -> Result<()> {
        // The offending datagram's 5-tuple lives entirely in the flow key
        // (local = client source, remote = destination), so the PTB is rebuilt
        // from the key — the pump no longer holds the parsed packet.
        let icmp = match (key.version, key.local_ip, key.remote_ip) {
            (IpVersion::V4, std::net::IpAddr::V4(client_ip), std::net::IpAddr::V4(remote_ip)) => {
                // Re-synthesise just the IP+UDP header of the offending
                // packet (no payload bytes are needed for socket matching:
                // RFC 1812 only requires the 8-byte UDP header).
                let original = build_ipv4_udp_packet(
                    client_ip,
                    remote_ip,
                    key.local_port,
                    key.remote_port,
                    &[],
                )?;
                let mtu = limit
                    .map(|l| u16::try_from(l).unwrap_or(u16::MAX))
                    .unwrap_or(IPV4_MIN_PATH_MTU);
                build_icmpv4_frag_needed(mtu, &original)?
            },
            (IpVersion::V6, std::net::IpAddr::V6(client_ip), std::net::IpAddr::V6(remote_ip)) => {
                let original = build_ipv6_udp_packet(
                    client_ip,
                    remote_ip,
                    key.local_port,
                    key.remote_port,
                    &[],
                )?;
                let mtu = limit
                    .map(|l| u32::try_from(l).unwrap_or(u32::MAX))
                    .unwrap_or(IPV6_MIN_PATH_MTU as u32);
                build_icmpv6_packet_too_big(mtu, &original)?
            },
            _ => return Ok(()),
        };
        self.inner.writer.write_packet(&icmp).await
    }

    /// Handle a packet that resolved to `via = "direct"`: open (or reuse) a
    /// plain UDP socket, send the datagram, and spawn a response reader that
    /// writes synthetic IP+UDP packets back into the TUN device.
    async fn handle_direct_packet(
        &self,
        key: UdpFlowKey,
        remote_target: &TargetAddr,
        packet: &ParsedUdpPacket,
        fwmark: Option<u32>,
    ) -> Result<()> {
        let target_addr = SocketAddr::new(key.remote_ip, key.remote_port);
        let bind_addr = match key.remote_ip {
            std::net::IpAddr::V4(_) => {
                SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
            },
            std::net::IpAddr::V6(_) => {
                SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
            },
        };
        let std_sock =
            outline_net::bind_udp_socket_direct(bind_addr, fwmark).with_context(|| {
                format!("failed to bind direct UDP socket for TUN flow to {remote_target}")
            })?;
        let sock = Arc::new(UdpSocket::from_std(std_sock)?);
        sock.send_to(&packet.payload, target_addr)
            .await
            .context("direct TUN UDP send failed")?;

        let flow_id = self
            .inner
            .next_flow_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = Instant::now();

        // Spawn a reader task that receives responses on this socket and writes
        // them as synthetic IP+UDP packets back into the TUN device.
        let reader_sock = Arc::clone(&sock);
        let writer = self.inner.writer.clone();
        let reader_key = key.clone();
        let direct_flows = Arc::clone(&self.inner.direct_flows);
        // Direct flows carry constant `(direct, direct)` labels; resolve the
        // downlink datagram+byte counters once for the reader's lifetime.
        let down_counters = metrics::direct_udp_counters("down");
        let reader = AbortOnDrop::new(tokio::spawn(async move {
            loop {
                // Park on readiness without holding a receive buffer, so an
                // idle direct flow costs no per-flow datagram buffer. The
                // buffer is allocated only once a datagram is actually ready
                // and released before the next park — steady-state memory then
                // tracks in-flight datagrams rather than the number of open
                // flows. `try_recv_buf_from` fills the spare capacity without
                // zeroing it first, avoiding a 64 KiB memset per datagram.
                if reader_sock.readable().await.is_err() {
                    break;
                }
                let mut buf = Vec::with_capacity(MAX_UDP_DATAGRAM);
                let (len, src_addr) = match reader_sock.try_recv_buf_from(&mut buf) {
                    Ok(v) => v,
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                };
                let src_target = socks5_proto::socket_addr_to_target(src_addr);
                let response_packet = match super::wire::build_response_packet(
                    reader_key.version,
                    &src_target,
                    reader_key.local_ip,
                    reader_key.local_port,
                    &buf[..len],
                ) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                down_counters.record(len);
                if writer.write_packet(&response_packet).await.is_err() {
                    break;
                }
                metrics::record_tun_packet(
                    "down",
                    super::ip_family_from_version(reader_key.version),
                    "accepted",
                );
                // Update last_seen on the flow. Read-lock to clone the Arc,
                // then per-flow Mutex — does not block other flows' I/O.
                bump_last_seen_if_current(&direct_flows, &reader_key, flow_id).await;
            }
        }));

        let state = Arc::new(Mutex::new(DirectUdpFlowState {
            id: flow_id,
            socket: sock,
            _reader: reader,
            created_at: now,
            last_seen: now,
        }));
        // Bound the direct flow table the same way `create_flow` bounds the
        // tunnelled `flows` table: on overflow, evict the least-recently-seen
        // flow so a UDP storm to direct-routed destinations cannot grow the
        // table (and its per-flow sockets and reader tasks) without limit.
        let mut evicted_flow = None;
        {
            let mut guard = self.inner.direct_flows.write().await;
            if guard.len() >= self.inner.max_flows
                && let Some(evicted_key) = super::lifecycle::oldest_flow_key(&guard).await
                && let Some(evicted) = guard.remove(&evicted_key)
            {
                {
                    let snapshot = evicted.lock().await;
                    warn!(
                        evicted_flow_id = snapshot.id,
                        max_flows = self.inner.max_flows,
                        "evicted oldest direct TUN UDP flow due to flow table limit"
                    );
                }
                evicted_flow = Some(evicted);
            }
            guard.insert(key, state);
        }
        if let Some(flow) = evicted_flow {
            self.enqueue_close_direct(flow, "evicted");
        }

        metrics::direct_udp_counters("up").record(packet.payload.len());
        metrics::record_tun_flow_created(metrics::DIRECT_GROUP_LABEL, metrics::DIRECT_UPLINK_LABEL);
        info!(
            flow_id,
            target = %remote_target,
            "created direct TUN UDP flow"
        );
        Ok(())
    }
}

/// Decide whether a PTB may be emitted at `now`, given the previous emission
/// timestamp (`None` ⇒ this is the first PTB for the flow) and the configured
/// throttle interval. Extracted so the rate-limit policy can be unit-tested
/// independently of the async flow-table machinery.
pub(crate) fn should_emit_ptb_now(
    previous: Option<Instant>,
    now: Instant,
    throttle: Duration,
) -> bool {
    match previous {
        None => true,
        Some(prev) => now.saturating_duration_since(prev) >= throttle,
    }
}

/// Smallest UDP-payload size a QUIC v1 endpoint is willing to use for an
/// Initial datagram (RFC 9000 §14.1). A PTB that advertises a path MTU
/// below this floor signals "the path cannot carry QUIC" to a compliant
/// stack — yielding the QUIC-disabled TCP fallback we want to avoid.
const QUIC_MIN_INITIAL_PAYLOAD_V4: usize = 1200;
/// IPv6 endpoints follow the IPv6 minimum link MTU (RFC 9000 §14.1
/// references RFC 8200): 1280 bytes for the IP packet as a whole.
const QUIC_MIN_INITIAL_PAYLOAD_V6: usize = 1280;

/// Decide whether a PTB may be synthesised for an oversize-dropped UDP flow
/// given the transport's reported size `limit`, the flow's IP version, and
/// the operator's `emit_below_quic_initial` preference.
///
/// With `emit_below_quic_initial = false` (the default, mirroring
/// [`TunConfig::pmtud_emit_below_quic_initial`](crate::TunConfig)) the
/// function returns `false` for limits below the QUIC v1
/// Initial-datagram minimum for that family — a PTB advertising
/// sub-minimum MTU would push compliant QUIC clients off UDP onto TCP,
/// the opposite of what an operator carrying real QUIC traffic wants.
///
/// With `emit_below_quic_initial = true` the suppression is disabled
/// and every drop with a known limit becomes eligible for a PTB — the
/// pre-suppression behaviour, suitable for VoWiFi / IKE-only
/// deployments that have no QUIC clients to protect.
///
/// `limit == None` is permissive regardless of the flag: without an
/// explicit transport budget we cannot prove the minimum is violated,
/// and suppressing all PTBs in that case would hide legitimate PMTUD
/// signals on transports that do not surface a size.
pub(crate) fn should_emit_ptb_for_limit(
    limit: Option<usize>,
    version: IpVersion,
    emit_below_quic_initial: bool,
) -> bool {
    let Some(limit) = limit else {
        return true;
    };
    if emit_below_quic_initial {
        return true;
    }
    let minimum = match version {
        IpVersion::V4 => QUIC_MIN_INITIAL_PAYLOAD_V4,
        IpVersion::V6 => QUIC_MIN_INITIAL_PAYLOAD_V6,
    };
    limit >= minimum
}
