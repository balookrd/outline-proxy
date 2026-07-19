use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, watch};
use tokio::time::{Instant, timeout};
use tracing::{debug, info, warn};

use outline_metrics as metrics;
use outline_transport::TcpWriter;
use socks5_proto::TargetAddr;

use super::super::super::super::TcpFlowKey;
use super::super::super::super::maintenance::commit_flow_changes;
use super::super::super::super::state_machine::{
    FlowResume, TcpFlowState, TcpFlowStatus, UpstreamCarrier, UpstreamWriter, clear_flow_metrics,
    client_fin_seen,
};
use super::super::super::connect::{ConnectedTunTcpUplink, select_tcp_candidate_and_connect};
use super::super::super::{TunTcpEngine, close_upstream_writer, target_socket_addr};
use crate::sniff::{SNIFF_PEEK_CAP, SniffOutcome, sniff_host};

/// Bounded negative cache of direct-connect destinations that recently failed
/// to connect. A destination present (within TTL) is not dialed again — the
/// flow is reset immediately instead of parking a task on the full connect
/// timeout. This isolates an unreachable origin the client keeps re-dialing
/// (e.g. a censored host) so a reconnect storm cannot pile up connect tasks and
/// starve the engine. Pure logic (no clock of its own) so it is unit-testable.
pub(in crate::tcp) struct ConnectFailureCache {
    failures: HashMap<SocketAddr, std::time::Instant>,
    ttl: Duration,
    cap: usize,
}

impl ConnectFailureCache {
    pub(in crate::tcp) fn new(ttl: Duration, cap: usize) -> Self {
        Self { failures: HashMap::new(), ttl, cap }
    }

    /// Whether `addr` failed to connect within the TTL as of `now`.
    pub(in crate::tcp) fn recently_failed(
        &self,
        addr: &SocketAddr,
        now: std::time::Instant,
    ) -> bool {
        self.failures
            .get(addr)
            .is_some_and(|&at| now.duration_since(at) < self.ttl)
    }

    /// Record a connect failure for `addr`. Sweeps expired entries when the cap
    /// is hit and drops the record if still full (bounded resource).
    pub(in crate::tcp) fn record_failure(&mut self, addr: SocketAddr, now: std::time::Instant) {
        if self.failures.len() >= self.cap {
            self.failures.retain(|_, &mut at| now.duration_since(at) < self.ttl);
        }
        if self.failures.len() < self.cap {
            self.failures.insert(addr, now);
        }
    }

    /// Clear `addr` after a successful connect, so a recovered origin is dialed
    /// normally again.
    pub(in crate::tcp) fn clear(&mut self, addr: &SocketAddr) {
        self.failures.remove(addr);
    }
}

/// Outcome of the upstream-dial admission gate
/// (`[tun] max_concurrent_upstream_dials`).
enum DialAdmission {
    /// No limit configured — dial immediately.
    Unlimited,
    /// A permit was granted; hold it for the duration of the dial. The permit
    /// is never read, only held — dropping the variant releases it.
    Admitted {
        _permit: tokio::sync::OwnedSemaphorePermit,
    },
    /// The flow closed while queued; abandon the connect.
    FlowClosed,
}

/// Ordered direct-dial candidate list: locally re-resolved addresses first,
/// then the client's literal IP as a fallback (deduplicated). The literal is
/// what direct-by-IP would have dialled, so it rescues a flow whose SNI
/// re-resolve returned nothing or only unreachable addresses.
fn build_direct_dial_candidates(
    resolved: &[SocketAddr],
    literal: Option<SocketAddr>,
) -> Vec<SocketAddr> {
    let mut candidates: Vec<SocketAddr> = resolved.to_vec();
    if let Some(lit) = literal
        && !candidates.contains(&lit)
    {
        candidates.push(lit);
    }
    candidates
}

impl TunTcpEngine {
    /// Take a place in the process-wide upstream-dial admission gate.
    ///
    /// Returns immediately when no limit is configured or a permit is free;
    /// otherwise parks until one frees up (FIFO), watching `close_rx` so a
    /// flow torn down while queued abandons the connect instead of dialling
    /// for a corpse. The permit covers the *dial only* — callers drop it as
    /// soon as the connect resolves, success or failure. The connect timeout
    /// is armed after admission, so a queue wait cannot eat into it.
    async fn acquire_dial_admission(&self, close_rx: &mut watch::Receiver<bool>) -> DialAdmission {
        let Some(semaphore) = self.inner.dial_admission.get() else {
            return DialAdmission::Unlimited;
        };
        if let Ok(permit) = Arc::clone(semaphore).try_acquire_owned() {
            return DialAdmission::Admitted { _permit: permit };
        }
        metrics::record_tun_tcp_async_connect("dial_queued");
        let acquire = Arc::clone(semaphore).acquire_owned();
        tokio::pin!(acquire);
        loop {
            tokio::select! {
                _ = close_rx.changed() => {
                    if *close_rx.borrow() {
                        return DialAdmission::FlowClosed;
                    }
                }
                permit = &mut acquire => {
                    let permit = permit.expect("dial admission semaphore is never closed");
                    // A teardown and a freed permit can become ready in the
                    // same instant, and `select!` may pick this branch first —
                    // re-check the close signal so a flow torn down while
                    // queued is never dialled (the permit drops right here,
                    // back to the pool).
                    if *close_rx.borrow() {
                        return DialAdmission::FlowClosed;
                    }
                    return DialAdmission::Admitted { _permit: permit };
                }
            }
        }
    }

    pub(in crate::tcp::engine) fn spawn_upstream_connect(
        &self,
        key: TcpFlowKey,
        target: TargetAddr,
        flow_id: u64,
        flow: Arc<Mutex<TcpFlowState>>,
        mut close_rx: watch::Receiver<bool>,
        ip_family: &'static str,
    ) {
        let engine = self.clone();
        tokio::spawn(async move {
            struct AsyncConnectActiveGuard;
            impl Drop for AsyncConnectActiveGuard {
                fn drop(&mut self) {
                    metrics::add_tun_tcp_async_connects_active(-1);
                }
            }

            metrics::add_tun_tcp_async_connects_active(1);
            metrics::record_tun_tcp_async_connect("started");
            let _active_guard = AsyncConnectActiveGuard;

            // Use the flow's bound manager and route — set by handle_new_flow
            // from the literal IP. SNI routing (below) may re-resolve them.
            let (mut manager, mut route) = {
                let state = flow.lock().await;
                (state.routing.manager.clone(), state.routing.route.clone())
            };

            // SNI-based routing (the TCP counterpart of the UDP two-pass). When
            // `route_by_sni` is on, peek the client's first bytes up-front and
            // re-resolve the route by the recovered TLS SNI / HTTP Host — domain
            // rules first, literal-IP fallback — *before* committing to
            // direct-vs-tunnel or dialling. The SYN-ACK went out on the IP route
            // already (the handshake is terminated locally), but the upstream
            // group is still open here, so the SNI can still steer it. The same
            // sniff is threaded into the branch below via `presniffed`, so the
            // flow is peeked only once; with the flag off nothing here runs and
            // the legacy per-branch sniff + IP route are unchanged.
            let presniffed: Option<TargetAddr> = if engine.inner.tcp.route_by_sni
                && engine.inner.tcp.sniffing
            {
                let sniffed =
                    match engine.sniff_and_override_target(&flow, target.clone(), &mut close_rx).await
                    {
                        Some(t) => t,
                        None => {
                            metrics::record_tun_tcp_async_connect("cancelled");
                            debug!(flow_id, "TUN TCP flow closed during SNI-routing sniff");
                            return;
                        },
                    };
                let sni_host = match &sniffed {
                    TargetAddr::Domain(host, _) => Some(host.as_str()),
                    _ => None,
                };
                let new_route = engine
                    .inner
                    .dispatch
                    .resolve_sni(sni_host, &target, outline_uplink::TransportKind::Tcp)
                    .await;
                match &new_route {
                    crate::TunRoute::Drop { reason } => {
                        debug!(flow_id, remote = %target, reason, "SNI route: dropping flow");
                        engine.abort_flow_with_rst(&key, "sni_policy_drop").await;
                        return;
                    },
                    crate::TunRoute::Group { manager: m, .. } => manager = m.clone(),
                    // Direct uses a dummy manager (default group), matching
                    // handle_new_flow — the direct branch skips the uplink pipeline.
                    crate::TunRoute::Direct { .. } => {
                        manager = engine.inner.dispatch.default_group().clone()
                    },
                }
                route = new_route.clone();
                // Publish the re-resolved route so metrics, the pump's group
                // label, and any carrier-migration re-dial see the group the SNI
                // selected — mirroring handle_new_flow's initial commit.
                {
                    let mut state = flow.lock().await;
                    state.routing.manager = manager.clone();
                    state.routing.route = new_route.clone();
                    state.routing.group_name = Arc::from(manager.group_name());
                }
                Some(sniffed)
            } else {
                None
            };

            let is_direct = matches!(route, crate::TunRoute::Direct { .. });

            if is_direct {
                // Direct: plain TcpStream, no Shadowsocks framing.
                let fwmark = match route {
                    crate::TunRoute::Direct { fwmark } => fwmark,
                    _ => None,
                };
                // Preserve the literal IP the client dialled. The TUN ingress
                // always carries a literal IP; SNI re-resolve below may replace
                // the target with a domain whose locally-resolved address is
                // *different* (a geo-CDN can resolve to an unreachable region or
                // AZ from this node). We keep the literal as a dial fallback so a
                // bad re-resolve never black-holes a flow that direct-by-IP would
                // have reached — the failure mode that left Kinopoisk's AWS init
                // endpoints hanging while the client could reach them by IP.
                let literal_addr = target_socket_addr(&target);

                // SNI bypass: when enabled, peek the first client bytes and, if
                // they carry a TLS SNI / HTTP Host, re-resolve that domain
                // through this node's own resolver and dial the IP *it* returns
                // — not the (possibly dead / foreign-resolved) literal IP the
                // client dialled. `sniff_and_override_target` reuses the peek +
                // exclude-list logic and hands back a `Domain` target for a
                // sniffed, non-excluded host; everything else stays the literal
                // IP. Off by default, so direct keeps the zero-latency IP dial.
                let target = if let Some(t) = presniffed.as_ref() {
                    // route_by_sni already sniffed this flow. A direct flow only
                    // local-re-resolves the sniffed domain when
                    // `sniff_direct_reresolve` is on; otherwise it keeps dialling
                    // the literal IP (the sniffed domain still steered the route
                    // to direct above — this only governs the dial address).
                    if engine.inner.tcp.sniff_direct_reresolve { t.clone() } else { target }
                } else if engine.inner.tcp.sniffing && engine.inner.tcp.sniff_direct_reresolve {
                    match engine.sniff_and_override_target(&flow, target, &mut close_rx).await {
                        Some(target) => target,
                        None => {
                            metrics::record_tun_tcp_async_connect("cancelled");
                            debug!(flow_id, "direct TUN TCP flow closed during sniffing");
                            return;
                        },
                    }
                } else {
                    target
                };

                // Build the dial-candidate list: re-resolved addresses first
                // (when SNI bypass produced a domain), then the literal IP as a
                // fallback. A plain IP target has no re-resolved set, so it just
                // dials the literal.
                let resolved: Vec<SocketAddr> = match &target {
                    TargetAddr::Domain(host, port) => {
                        match outline_transport::resolve_host_with_preference(
                            engine.dns_cache(),
                            host,
                            *port,
                            "tun_direct_sni",
                            false,
                        )
                        .await
                        {
                            Ok(addrs) => {
                                if let Some(first) = addrs.first() {
                                    debug!(flow_id, host, resolved = %first, "direct TUN TCP: SNI re-resolved via local resolver");
                                }
                                addrs.iter().copied().collect()
                            },
                            other => {
                                debug!(flow_id, host, error = ?other.err(), "direct TUN TCP: local SNI re-resolve failed, falling back to literal IP");
                                Vec::new()
                            },
                        }
                    },
                    _ => Vec::new(),
                };
                let candidates = build_direct_dial_candidates(&resolved, literal_addr);
                if candidates.is_empty() {
                    metrics::record_tun_tcp_async_connect("failed");
                    warn!(flow_id, remote = %target, "direct TUN TCP: no dial candidates");
                    engine.abort_flow_with_rst(&key, "connect_failed").await;
                    return;
                }

                // Dial candidates in order, falling through on connect error or
                // timeout. With more than one candidate, cap each attempt so the
                // fallback to the literal IP is fast when a re-resolved address
                // black-holes (a dead SYN otherwise eats the full connect
                // timeout before the literal is even tried).
                let per_try = if candidates.len() > 1 {
                    engine.inner.tcp.connect_timeout.min(Duration::from_secs(3))
                } else {
                    engine.inner.tcp.connect_timeout
                };
                let dial_admission = match engine.acquire_dial_admission(&mut close_rx).await {
                    DialAdmission::FlowClosed => {
                        metrics::record_tun_tcp_async_connect("cancelled");
                        debug!(
                            flow_id,
                            "direct TUN TCP flow closed while queued for dial admission"
                        );
                        return;
                    },
                    admitted => admitted,
                };
                let mut stream = None;
                let mut last_outcome = "failed";
                for addr in &candidates {
                    // Fail-fast: a destination that failed to connect within the
                    // TTL is not re-dialed — skip it instead of parking this task
                    // on the full connect timeout. This is what stops a reconnect
                    // storm to a blackholed origin from piling up connect tasks.
                    if engine
                        .inner
                        .connect_failures
                        .lock()
                        .await
                        .recently_failed(addr, std::time::Instant::now())
                    {
                        last_outcome = "recent_failure";
                        continue;
                    }
                    match timeout(per_try, outline_net::connect_tcp_socket_direct(*addr, fwmark))
                        .await
                    {
                        Ok(Ok(s)) => {
                            engine.inner.connect_failures.lock().await.clear(addr);
                            stream = Some(s);
                            break;
                        },
                        Ok(Err(error)) => {
                            engine
                                .inner
                                .connect_failures
                                .lock()
                                .await
                                .record_failure(*addr, std::time::Instant::now());
                            last_outcome = "failed";
                            debug!(flow_id, remote = %addr, error = %format!("{error:#}"), "direct TUN TCP: candidate connect failed");
                        },
                        Err(_) => {
                            engine
                                .inner
                                .connect_failures
                                .lock()
                                .await
                                .record_failure(*addr, std::time::Instant::now());
                            last_outcome = "timeout";
                            debug!(flow_id, remote = %addr, "direct TUN TCP: candidate connect timed out");
                        },
                    }
                }
                let stream = match stream {
                    Some(stream) => stream,
                    None => {
                        metrics::record_tun_tcp_async_connect(last_outcome);
                        warn!(flow_id, remote = %target, outcome = last_outcome, "failed to establish direct TUN TCP connection to any candidate");
                        let reason = match last_outcome {
                            "timeout" => "connect_timeout",
                            "recent_failure" => "connect_recent_failure",
                            _ => "connect_failed",
                        };
                        engine.abort_flow_with_rst(&key, reason).await;
                        return;
                    },
                };
                drop(dial_admission);
                let (read_half, write_half) = stream.into_split();
                let upstream_carrier =
                    Arc::new(Mutex::new(UpstreamCarrier::new(UpstreamWriter::Direct(write_half))));
                let (group_name, uplink_name, notify) = {
                    let mut state = flow.lock().await;
                    if matches!(state.status, TcpFlowStatus::Closed) {
                        metrics::record_tun_tcp_async_connect("discarded_closed_flow");
                        return;
                    }
                    clear_flow_metrics(&mut state);
                    state.routing.uplink_name = Arc::from("direct");
                    state.routing.target = target.clone();
                    state.routing.upstream_carrier = Some(Arc::clone(&upstream_carrier));
                    // `state.resume` stays disarmed: a direct flow owns a plain
                    // socket to the origin, so there is no carrier to migrate off
                    // and no server-parked upstream to re-attach. Paying for a
                    // replay ring here would be pure copy cost.
                    let notify = state.signals.upstream_pump.clone();
                    commit_flow_changes(&mut state, &engine.inner.tcp);
                    let group_name = state.routing.group_name.clone();
                    let uplink_name = state.routing.uplink_name.clone();
                    (group_name, uplink_name, notify)
                };
                metrics::record_tun_tcp_async_connect("connected");
                // Reader drains upstream→TUN; pump drains TUN→upstream
                // (including any data/FIN buffered before connect completed),
                // so the shared read-loop never blocks on this flow's send.
                engine.spawn_direct_upstream_reader(
                    key.clone(),
                    flow.clone(),
                    read_half,
                    close_rx.clone(),
                );
                engine.spawn_upstream_pump(
                    key.clone(),
                    flow.clone(),
                    upstream_carrier,
                    manager.clone(),
                    usize::MAX,
                    group_name,
                    uplink_name,
                    notify,
                    close_rx,
                );
                metrics::record_uplink_selected(
                    "tcp",
                    metrics::DIRECT_GROUP_LABEL,
                    metrics::DIRECT_UPLINK_LABEL,
                );
                info!(flow_id, remote = %target, "created direct TUN TCP flow");
                return;
            }

            // Tunneled path (existing).
            //
            // Connection sniffing (Xray destOverride): before selecting an
            // uplink, peek the first client bytes and, if they carry a TLS
            // ClientHello SNI or an HTTP Host, rewrite the literal-IP target
            // into a domain so the request leaves over VLESS/SS as a *domain*
            // and the exit node resolves it. Sniffable flows resolve almost
            // instantly (the TUN stack terminated the handshake locally, so
            // the client already sent its preface); the bounded wait only
            // affects server-speaks-first protocols, which fall back to
            // dialling by IP. Cancellation during the wait aborts the connect.
            let target = if let Some(t) = presniffed.as_ref() {
                // route_by_sni already sniffed this flow up-front; reuse the
                // recovered domain as the exit-facing target (no second peek).
                t.clone()
            } else if engine.inner.tcp.sniffing {
                match engine.sniff_and_override_target(&flow, target, &mut close_rx).await {
                    Some(target) => target,
                    None => {
                        metrics::record_tun_tcp_async_connect("cancelled");
                        debug!(flow_id, "TUN TCP flow closed during sniffing");
                        return;
                    },
                }
            } else {
                target
            };

            // Per-client affinity key: the LAN client's source IP. Consulted
            // only under routing_scope = "per_client"; ignored otherwise.
            let client_id = key.client_ip.to_string();
            let dial_admission = match engine.acquire_dial_admission(&mut close_rx).await {
                DialAdmission::FlowClosed => {
                    metrics::record_tun_tcp_async_connect("cancelled");
                    debug!(flow_id, remote = %target, "TUN TCP flow closed while queued for dial admission");
                    return;
                },
                admitted => admitted,
            };
            let connected = tokio::select! {
                _ = close_rx.changed() => {
                    if *close_rx.borrow() {
                        metrics::record_tun_tcp_async_connect("cancelled");
                        debug!(flow_id, remote = %target, "cancelled pending async TUN TCP upstream connect");
                        return;
                    }
                    metrics::record_tun_tcp_async_connect("cancelled");
                    return;
                }
                result = timeout(
                    engine.inner.tcp.connect_timeout,
                    select_tcp_candidate_and_connect(&manager, &target, Some(&client_id)),
                ) => result,
            };

            let ConnectedTunTcpUplink {
                candidate,
                writer: upstream_writer,
                reader: upstream_reader,
                session_id,
            } = match connected {
                Ok(Ok(connected)) => connected,
                Ok(Err(error)) => {
                    metrics::record_tun_tcp_async_connect("failed");
                    warn!(flow_id, remote = %target, error = %format!("{error:#}"), "failed to establish async TUN TCP upstream");
                    engine.abort_flow_with_rst(&key, "connect_failed").await;
                    return;
                },
                Err(_) => {
                    metrics::record_tun_tcp_async_connect("timeout");
                    warn!(flow_id, remote = %target, timeout_secs = engine.inner.tcp.connect_timeout.as_secs(), "timed out establishing async TUN TCP upstream");
                    engine.abort_flow_with_rst(&key, "connect_timeout").await;
                    return;
                },
            };
            drop(dial_admission);

            let upstream_carrier =
                Arc::new(Mutex::new(UpstreamCarrier::new(match upstream_writer {
                    TcpWriter::Ws(w) => UpstreamWriter::TunneledWs(w),
                    TcpWriter::Socket(w) => UpstreamWriter::TunneledSocket(w),
                    TcpWriter::Vless(w) => UpstreamWriter::TunneledVless(w),
                })));
            let (group_name, uplink_name, notify) = {
                let mut state = flow.lock().await;
                if matches!(state.status, TcpFlowStatus::Closed) {
                    metrics::record_tun_tcp_async_connect("discarded_closed_flow");
                    drop(state);
                    close_upstream_writer(Some(Arc::clone(&upstream_carrier))).await;
                    return;
                }
                clear_flow_metrics(&mut state);
                state.routing.uplink_index = candidate.index;
                state.routing.uplink_name = Arc::from(candidate.uplink.name.as_str());
                // The destination as actually dialled — connection sniffing may
                // have turned the client's literal IP into a domain. A carrier
                // migration re-dials this same target.
                state.routing.target = target.clone();
                state.routing.upstream_carrier = Some(Arc::clone(&upstream_carrier));
                // Arm the flow's resume accounting with the Session ID this flow
                // was just issued: from here the pump mirrors every uplink chunk
                // into the flow's replay ring and the reader counts every
                // downstream payload byte, so a carrier migration has the exact
                // tail (and offset) it needs to close both byte gaps.
                state.resume = FlowResume::armed(session_id);
                let notify = state.signals.upstream_pump.clone();
                commit_flow_changes(&mut state, &engine.inner.tcp);
                let group_name = state.routing.group_name.clone();
                let uplink_name = state.routing.uplink_name.clone();
                (group_name, uplink_name, notify)
            };
            metrics::record_tun_tcp_async_connect("connected");

            // Reader drains upstream→TUN; pump drains TUN→upstream (including
            // data/FIN buffered before connect completed), so the shared
            // read-loop never blocks on this flow's upstream back-pressure.
            engine.spawn_upstream_reader(
                key.clone(),
                flow.clone(),
                upstream_reader,
                close_rx.clone(),
            );
            engine.spawn_upstream_pump(
                key.clone(),
                flow.clone(),
                upstream_carrier,
                manager.clone(),
                candidate.index,
                group_name,
                uplink_name,
                notify,
                close_rx,
            );

            metrics::record_uplink_selected("tcp", manager.group_name(), &candidate.uplink.name);
            info!(
                flow_id,
                uplink = %candidate.uplink.name,
                remote = %target,
                ip_family,
                "created TUN TCP flow"
            );
        });
    }

    /// Peek the buffered client prefix and, if it carries a recoverable
    /// destination host (TLS SNI / HTTP Host), return a domain target;
    /// otherwise return the original IP target. Returns `None` if the flow is
    /// torn down (or the connect cancelled) while waiting for the preface.
    ///
    /// The buffer is only peeked, never consumed — the same bytes are later
    /// pumped upstream verbatim, so the server still receives the exact
    /// ClientHello / request the client sent.
    pub(in crate::tcp::engine) async fn sniff_and_override_target(
        &self,
        flow: &Arc<Mutex<TcpFlowState>>,
        target: TargetAddr,
        close_rx: &mut watch::Receiver<bool>,
    ) -> Option<TargetAddr> {
        let notify = {
            let state = flow.lock().await;
            state.signals.upstream_pump.clone()
        };
        let deadline = Instant::now() + self.inner.tcp.sniff_timeout;
        loop {
            let (peeked, client_done) = {
                let state = flow.lock().await;
                if matches!(state.status, TcpFlowStatus::Closed) {
                    return None;
                }
                let mut buf = Vec::new();
                for chunk in &state.pending_client_data {
                    if buf.len() >= SNIFF_PEEK_CAP {
                        break;
                    }
                    let take = (SNIFF_PEEK_CAP - buf.len()).min(chunk.len());
                    buf.extend_from_slice(&chunk[..take]);
                }
                (buf, client_fin_seen(state.status))
            };

            match sniff_host(&peeked) {
                SniffOutcome::Found(host) => {
                    if crate::sniff::host_is_excluded(&host, &self.inner.tcp.sniff_override_exclude)
                    {
                        metrics::record_tun_tcp_sniff("excluded");
                        debug!(host, original = %target, "TUN TCP sniff: host excluded from override, dialing by IP");
                        return Some(target);
                    }
                    let port = target_port(&target);
                    metrics::record_tun_tcp_sniff("override");
                    debug!(host, port, original = %target, "TUN TCP sniff: destination overridden to domain");
                    return Some(TargetAddr::Domain(host, port));
                },
                SniffOutcome::NotMatched => {
                    metrics::record_tun_tcp_sniff("miss");
                    return Some(target);
                },
                SniffOutcome::Incomplete => {
                    if client_done || peeked.len() >= SNIFF_PEEK_CAP {
                        // No more bytes will help (client half-closed, or we
                        // have all we are willing to buffer): dial by IP.
                        metrics::record_tun_tcp_sniff("miss");
                        return Some(target);
                    }
                    tokio::select! {
                        changed = close_rx.changed() => {
                            // A send means the flow was closed; treat any other
                            // outcome (sender dropped) as a teardown too.
                            if changed.is_err() || *close_rx.borrow() {
                                return None;
                            }
                        }
                        _ = notify.notified() => {}
                        _ = tokio::time::sleep_until(deadline) => {
                            metrics::record_tun_tcp_sniff("timeout");
                            return Some(target);
                        }
                    }
                },
            }
        }
    }
}

fn target_port(target: &TargetAddr) -> u16 {
    match target {
        TargetAddr::IpV4(_, port) | TargetAddr::IpV6(_, port) | TargetAddr::Domain(_, port) => {
            *port
        },
    }
}

#[cfg(test)]
#[path = "tests/connect.rs"]
mod tests;
