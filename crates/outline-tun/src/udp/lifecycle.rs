use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::udp::AllUdpUplinksFailed;
use anyhow::Result;
use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tokio::time::sleep;
use tracing::{debug, warn};

use outline_metrics as metrics;
use outline_transport::{
    AbortOnDrop, UdpSessionTransport, WsClosed, is_dropped_oversized_udp_error,
};
use outline_uplink::{TransportKind, UplinkCandidate, UplinkManager};
use socks5_proto::TargetAddr;

use super::types::{
    DirectUdpFlowState, FlowStamp, UDP_OUTBOUND_QUEUE_CAP, UDP_PENDING_DIAL_BUFFER_CAP,
    bump_last_seen_if_current, drain_idle_flows, flow_is_current,
};
use futures_util::FutureExt as _;

use super::wire::{
    GSO_MAX_UDP_SUPER_PAYLOAD, UDP_GSO_MIN_DATAGRAM, UDP_MAX_SEGMENTS, build_gso_udp_packet,
    build_response_packet,
};
use super::{
    TUN_FLOW_CLEANUP_INTERVAL, TunUdpEngine, UdpFlowKey, UdpFlowState, ip_family_from_version,
    ip_to_target,
};

pub(super) enum CloseWork {
    Tunnel {
        flow: Arc<Mutex<UdpFlowState>>,
        reason: &'static str,
    },
    Direct {
        flow: Arc<Mutex<DirectUdpFlowState>>,
        reason: &'static str,
    },
}

impl TunUdpEngine {
    pub(super) fn spawn_cleanup_loop(&self) {
        let engine = self.clone();
        tokio::spawn(async move {
            loop {
                sleep(TUN_FLOW_CLEANUP_INTERVAL).await;
                engine.cleanup_idle_flows().await;
            }
        });
    }

    /// Spawn the async cleanup pool. Flows removed from the flow table are
    /// sent to this pool so that `transport.close()` (async, potentially
    /// slow) runs without holding any map lock and without blocking the
    /// calling task. Each close request is dispatched to its own spawned
    /// task for full concurrency.
    pub(super) fn spawn_cleanup_pool(&self, mut rx: mpsc::UnboundedReceiver<CloseWork>) {
        tokio::spawn(async move {
            while let Some(work) = rx.recv().await {
                match work {
                    CloseWork::Tunnel { flow, reason } => {
                        tokio::spawn(close_udp_flow(flow, reason));
                    },
                    CloseWork::Direct { flow, reason } => {
                        tokio::spawn(async move {
                            // The reader task is wrapped in `AbortOnDrop`,
                            // so simply releasing the last reference
                            // tears it down — `flow._reader` aborts via
                            // its `Drop` impl when this `Arc` is dropped
                            // and no other task can reach it (we hold
                            // the only outstanding `Arc` after the map
                            // removed its entry).
                            let (created_at, _alive_until_end) = {
                                let guard = flow.lock().await;
                                (guard.created_at, ())
                            };
                            metrics::record_tun_flow_closed(
                                metrics::DIRECT_GROUP_LABEL,
                                metrics::DIRECT_UPLINK_LABEL,
                                reason,
                                Instant::now().saturating_duration_since(created_at),
                            );
                            drop(flow);
                        });
                    },
                }
            }
        });
    }

    pub(super) fn enqueue_close(&self, flow: Arc<Mutex<UdpFlowState>>, reason: &'static str) {
        let _ = self.inner.close_tx.send(CloseWork::Tunnel { flow, reason });
    }

    pub(super) fn enqueue_close_direct(
        &self,
        flow: Arc<Mutex<DirectUdpFlowState>>,
        reason: &'static str,
    ) {
        let _ = self.inner.close_tx.send(CloseWork::Direct { flow, reason });
    }

    /// Register a new tunnelled UDP flow **without** blocking the caller (the
    /// shared TUN read-loop) on the carrier dial. A pending flow record — with
    /// its outbound queue — is inserted immediately and a per-flow uplink task
    /// is spawned to dial the carrier, spawn the downlink reader, and drain the
    /// queue. `first_payload` is buffered onto the queue and shipped once the
    /// dial completes. This is the UDP mirror of the TCP path's async
    /// `spawn_upstream_connect`: neither connect nor send ever runs inline in
    /// the read-loop, so a slow/parked carrier can no longer head-of-line-block
    /// the whole TUN.
    pub(super) async fn spawn_tunnel_flow(
        &self,
        key: UdpFlowKey,
        manager: &UplinkManager,
        remote_target_override: Option<TargetAddr>,
        first_payload: Bytes,
    ) {
        let now = Instant::now();
        let flow_id = self
            .inner
            .next_flow_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut evicted_flow = None;
        let outbound_tx = {
            let mut guard = self.inner.flows.write().await;
            if let Some(existing) = guard.get(&key).map(Arc::clone) {
                // Raced with an existing flow for the same 5-tuple: keep it and
                // feed the datagram to its queue instead of replacing it.
                drop(guard);
                let mut existing = existing.lock().await;
                existing.last_seen = now;
                existing.outbound_tx.clone()
            } else {
                if guard.len() >= self.inner.max_flows {
                    match oldest_flow_key(&guard).await {
                        Some(evicted_key) => {
                            if let Some(evicted) = guard.remove(&evicted_key) {
                                {
                                    let snapshot = evicted.lock().await;
                                    warn!(
                                        evicted_flow_id = snapshot.id,
                                        evicted_uplink = %snapshot.uplink_name,
                                        max_flows = self.inner.max_flows,
                                        "evicted oldest TUN UDP flow due to flow table limit"
                                    );
                                }
                                evicted_flow = Some(evicted);
                            }
                        },
                        None => {
                            warn!("TUN UDP flow table limit reached and no flow could be evicted");
                            return;
                        },
                    }
                }
                let (outbound_tx, outbound_rx) = mpsc::channel::<Bytes>(UDP_OUTBOUND_QUEUE_CAP);
                let uplink_task = self.spawn_udp_uplink(
                    key.clone(),
                    flow_id,
                    manager.clone(),
                    remote_target_override.clone(),
                    outbound_rx,
                );
                let state = UdpFlowState {
                    id: flow_id,
                    uplink_index: usize::MAX,
                    uplink_name: Arc::from("connecting"),
                    group_name: Arc::from(manager.group_name()),
                    created_at: now,
                    last_seen: now,
                    last_ptb_sent: None,
                    outbound_tx: outbound_tx.clone(),
                    _uplink_task: Some(uplink_task),
                };
                guard.insert(key.clone(), Arc::new(Mutex::new(state)));
                outbound_tx
            }
        };

        if let Some(flow) = evicted_flow {
            self.enqueue_close(flow, "evicted");
        }

        // Buffer the first datagram; the uplink task ships it after it dials.
        queue_client_datagram(&outbound_tx, first_payload);
    }

    /// Per-flow uplink task: the sole owner of a tunnelled UDP flow's carrier.
    /// Dials the uplink off the read-loop, publishes the resolved uplink onto
    /// the flow record, spawns the downlink reader, then drains the outbound
    /// queue into carrier sends — awaiting each send on this task so carrier
    /// back-pressure parks here, never the read-loop. Reconnects (once) on a
    /// send error and tears the flow down if the (re)dial fails.
    fn spawn_udp_uplink(
        &self,
        key: UdpFlowKey,
        flow_id: u64,
        manager: UplinkManager,
        remote_target_override: Option<TargetAddr>,
        mut outbound_rx: mpsc::Receiver<Bytes>,
    ) -> AbortOnDrop {
        let engine = self.clone();
        AbortOnDrop::new(tokio::spawn(async move {
            let remote_target = ip_to_target(key.remote_ip, key.remote_port);
            // Per-client affinity key: the LAN client's source IP. Consulted
            // only under routing_scope = "per_client"; ignored otherwise.
            let client_id = key.local_ip.to_string();

            // Drain the outbound queue into a local buffer while the carrier
            // dial is in flight. Nothing can send until we are connected, so the
            // bounded outbound channel would otherwise fill during a slow dial
            // (seconds under DPI) and start dropping datagrams — losing exactly
            // the QUIC-handshake Initials / PTO retransmits the client sends
            // before it gets a reply, stalling the handshake onto TCP. Draining
            // here keeps the channel empty so the read-loop's `try_send` never
            // hits a full queue during the handshake window.
            let mut pending_datagrams: Vec<Bytes> = Vec::new();
            let connected = {
                let connect_fut =
                    select_candidate_and_connect(&manager, &remote_target, Some(&client_id));
                tokio::pin!(connect_fut);
                loop {
                    tokio::select! {
                        biased;
                        result = &mut connect_fut => break result,
                        maybe = outbound_rx.recv() => match maybe {
                            Some(raw) => {
                                if pending_datagrams.len() < UDP_PENDING_DIAL_BUFFER_CAP {
                                    pending_datagrams.push(raw);
                                } else {
                                    metrics::record_tun_udp_forward_error("pending_dial_buffer_full");
                                }
                            },
                            // The flow record (and its sender) was removed while
                            // dialling — idle eviction or a migration. Abandon.
                            None => return,
                        },
                    }
                }
            };
            let (candidate, transport) = match connected {
                Ok(connected) => connected,
                Err(error) => {
                    warn!(flow_id, error = %format!("{error:#}"), "failed to establish TUN UDP uplink");
                    engine.close_flow_if_current(&key, flow_id, "connect_failed").await;
                    return;
                },
            };
            manager
                .confirm_selected_uplink_for(
                    TransportKind::Udp,
                    Some(&remote_target),
                    Some(&client_id),
                    candidate.index,
                )
                .await;

            let mut transport = Arc::new(transport);
            let mut uplink_index = candidate.index;
            let mut uplink_name: Arc<str> = Arc::from(candidate.uplink.name.as_str());

            // Publish the resolved uplink onto the pending flow record. If the
            // flow was already torn down (idle eviction / migration during the
            // dial), stop — the transport drops here and its carrier closes.
            if !engine
                .bind_flow_uplink(&key, flow_id, uplink_index, &uplink_name)
                .await
            {
                return;
            }
            metrics::record_uplink_selected("udp", manager.group_name(), &uplink_name);
            metrics::record_tun_flow_created(manager.group_name(), &uplink_name);
            debug!(
                flow_id,
                group = %manager.group_name(),
                uplink = %uplink_name,
                local = %format!("{}:{}", key.local_ip, key.local_port),
                remote = %format!("{}:{}", key.remote_ip, key.remote_port),
                "created TUN UDP flow"
            );

            // Downlink reader (upstream→client). Reassigned on reconnect so the
            // previous carrier's reader — and the transport `Arc` it holds —
            // drop and close.
            let mut _reader = engine.spawn_flow_reader(
                key.clone(),
                flow_id,
                Arc::clone(&transport),
                uplink_index,
                manager.clone(),
            );

            // Drain the outbound queue. `recv` yields `None` when the flow
            // record (holding the sender) is removed — the flow's teardown
            // signal — at which point the reader and transport drop here.
            // Flush the datagrams buffered during the dial (the client's
            // handshake preface) in order first, then resume the live drain.
            let mut pending = pending_datagrams.into_iter();
            loop {
                let raw = match pending.next() {
                    Some(raw) => raw,
                    None => match outbound_rx.recv().await {
                        Some(raw) => raw,
                        None => break,
                    },
                };
                // Follow a strict-active repoint: tear down so the client's
                // traffic re-homes onto the newly active uplink.
                if super::should_migrate_flow(&manager, uplink_index).await {
                    engine.close_flow_if_current(&key, flow_id, "global_switch").await;
                    return;
                }
                let effective_target = remote_target_override.as_ref().unwrap_or(&remote_target);
                let payload = match super::build_udp_payload(effective_target, &raw) {
                    Ok(payload) => payload,
                    Err(_) => continue,
                };
                match transport.send_packet(&payload).await {
                    Ok(()) => super::record_udp_xfer(
                        "up",
                        manager.group_name(),
                        &uplink_name,
                        payload.len(),
                    ),
                    Err(error) if is_dropped_oversized_udp_error(&error) => {
                        engine.emit_pmtud_after_oversize_drop(&key, &error).await;
                    },
                    Err(error) => {
                        // Reconnect off the read-loop (was
                        // `recreate_flow_after_send_error`): report the failure,
                        // re-dial, respawn the reader, and retry once.
                        report_udp_runtime_failure(&manager, uplink_index, &error).await;
                        match select_candidate_and_connect(
                            &manager,
                            &remote_target,
                            Some(&client_id),
                        )
                        .await
                        {
                            Ok((cand, new_transport)) => {
                                metrics::record_failover(
                                    "udp",
                                    manager.group_name(),
                                    &uplink_name,
                                    cand.uplink.name.as_str(),
                                );
                                transport = Arc::new(new_transport);
                                uplink_index = cand.index;
                                uplink_name = Arc::from(cand.uplink.name.as_str());
                                if !engine
                                    .bind_flow_uplink(&key, flow_id, uplink_index, &uplink_name)
                                    .await
                                {
                                    return;
                                }
                                _reader = engine.spawn_flow_reader(
                                    key.clone(),
                                    flow_id,
                                    Arc::clone(&transport),
                                    uplink_index,
                                    manager.clone(),
                                );
                                if let Err(retry_error) = transport.send_packet(&payload).await {
                                    warn!(flow_id, error = %format!("{retry_error:#}"), "TUN UDP resend after reconnect failed");
                                } else {
                                    super::record_udp_xfer(
                                        "up",
                                        manager.group_name(),
                                        &uplink_name,
                                        payload.len(),
                                    );
                                }
                            },
                            Err(error) => {
                                warn!(flow_id, error = %format!("{error:#}"), "TUN UDP uplink reconnect failed");
                                engine.close_flow_if_current(&key, flow_id, "send_error").await;
                                return;
                            },
                        }
                    },
                }
                // Keep an actively-sending flow from being idle-reaped.
                bump_last_seen_if_current(&engine.inner.flows, &key, flow_id).await;
            }
        }))
    }

    /// Publish a freshly-dialled uplink (`index`, `name`) onto the flow record,
    /// replacing the `usize::MAX` / `"connecting"` placeholders. Returns `false`
    /// if the flow at `key` is gone or was replaced (a newer generation now
    /// owns the slot), signalling the uplink task to stop.
    async fn bind_flow_uplink(
        &self,
        key: &UdpFlowKey,
        flow_id: u64,
        uplink_index: usize,
        uplink_name: &Arc<str>,
    ) -> bool {
        let handle = self.inner.flows.read().await.get(key).map(Arc::clone);
        let Some(handle) = handle else {
            return false;
        };
        let mut flow = handle.lock().await;
        if flow.id != flow_id {
            return false;
        }
        flow.uplink_index = uplink_index;
        flow.uplink_name = Arc::clone(uplink_name);
        true
    }

    fn spawn_flow_reader(
        &self,
        key: UdpFlowKey,
        flow_id: u64,
        transport: Arc<UdpSessionTransport>,
        uplink_index: usize,
        manager: UplinkManager,
    ) -> AbortOnDrop {
        let engine = self.clone();
        AbortOnDrop::new(tokio::spawn(async move {
            let result = async {
                let mut carried_over: Option<Bytes> = None;
                loop {
                    if super::should_migrate_flow(&manager, uplink_index).await {
                        engine.close_flow_if_current(&key, flow_id, "global_switch").await;
                        return Ok(());
                    }
                    // First datagram of a potential batch: the one carried over
                    // from the previous iteration (a size change ended that
                    // batch) or a fresh blocking read.
                    let first_raw = match carried_over.take() {
                        Some(raw) => raw,
                        None => transport.read_packet().await?,
                    };
                    let first_payload = extract_udp_payload(&first_raw)?;
                    let datagram_size = first_payload.len();

                    // With USO, coalesce equal-sized datagrams of THIS flow (its
                    // 4-tuple is fixed by `key`, so all reply to the same
                    // destination) into one GSO_UDP_L4 super-segment. `now_or_never`
                    // drains only datagrams already queued — no added latency, and
                    // `read_packet` is left un-polled otherwise. A different-sized
                    // datagram ends the batch and is carried over (zero-loss); the
                    // kernel requires every segment but the last to be equal-sized.
                    let mut batch: Vec<Bytes> = vec![first_payload];
                    let mut total_payload = datagram_size;
                    if engine.inner.udp_gso && datagram_size >= UDP_GSO_MIN_DATAGRAM {
                        while batch.len() < UDP_MAX_SEGMENTS
                            && total_payload + datagram_size <= GSO_MAX_UDP_SUPER_PAYLOAD
                        {
                            match transport.read_packet().now_or_never() {
                                Some(Ok(next_raw)) => {
                                    let next_payload = extract_udp_payload(&next_raw)?;
                                    if next_payload.len() == datagram_size {
                                        total_payload += next_payload.len();
                                        batch.push(next_payload);
                                    } else {
                                        carried_over = Some(next_raw);
                                        break;
                                    }
                                },
                                Some(Err(error)) => return Err(error),
                                None => break,
                            }
                        }
                    }

                    let uplink_name: Arc<str> = {
                        let handle = engine.inner.flows.read().await.get(&key).map(Arc::clone);
                        match handle {
                            Some(h) => {
                                let flow = h.lock().await;
                                if flow.id == flow_id {
                                    flow.uplink_name.clone()
                                } else {
                                    Arc::from("unknown")
                                }
                            },
                            None => Arc::from("unknown"),
                        }
                    };
                    super::record_udp_xfer(
                        "down",
                        manager.group_name(),
                        &uplink_name,
                        total_payload,
                    );

                    let batch_len = batch.len();
                    if batch_len > 1 {
                        // Assemble the super-segment straight from the batch's
                        // `Bytes` — the builder copies each datagram into the
                        // packet's payload region, so the old `coalesced` Vec
                        // (a full super-segment allocation + memcpy per USO
                        // write) is gone.
                        let (packet, vnet) = build_gso_udp_packet(
                            key.version,
                            key.remote_ip,
                            key.local_ip,
                            key.remote_port,
                            key.local_port,
                            datagram_size as u16,
                            &batch,
                        )?;
                        engine.inner.writer.write_gso_segment(&packet, vnet).await?;
                        metrics::record_tun_packet(
                            "down",
                            ip_family_from_version(key.version),
                            "uso_supersegment",
                        );
                    } else {
                        let packet = build_client_response_packet(&key, &first_raw)?;
                        engine.inner.writer.write_packet(&packet).await?;
                    }
                    // Per-datagram `accepted` parity with the non-USO path.
                    for _ in 0..batch_len {
                        metrics::record_tun_packet(
                            "down",
                            ip_family_from_version(key.version),
                            "accepted",
                        );
                    }
                    bump_last_seen_if_current(&engine.inner.flows, &key, flow_id).await;
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            }
            .await;
            // A clean WebSocket close (Close frame / EOF from the peer, surfaced
            // as `WsClosed`) is NOT a data-path failure. UDP associations are
            // ephemeral and the server closing the mux carrier — e.g. on its own
            // idle timeout — is normal lifecycle, not an outage. Treat it like
            // the TCP downlink does (`closed_cleanly()` → stop without error):
            // do not stamp a runtime-failure cooldown, which would otherwise
            // flap the UDP health indicator on every routine close. A *dirty*
            // read error still escalates exactly as before. The flow is closed
            // as "closed" either way and re-created on the next packet.
            let clean_close = result.as_ref().err().is_some_and(is_clean_ws_close);
            let close_reason = if result.is_ok() || clean_close {
                "closed"
            } else {
                "read_error"
            };

            if let Err(ref error) = result
                && !clean_close
                && flow_is_current(&engine.inner.flows, &key, flow_id).await
            {
                report_udp_runtime_failure(&manager, uplink_index, error).await;
                metrics::record_tun_packet("down", ip_family_from_version(key.version), "error");
                warn!(
                    flow_id,
                    error = %format!("{error:#}"),
                    "TUN UDP flow reader stopped"
                );
            }
            engine.close_flow_if_current(&key, flow_id, close_reason).await;
        }))
    }

    pub(super) async fn close_flow_if_current(
        &self,
        key: &UdpFlowKey,
        flow_id: u64,
        reason: &'static str,
    ) {
        // Two-stage: first check (read-lock + per-flow lock) without
        // mutating the map, then take the write-lock only if removal is
        // actually warranted. Avoids acquiring the map write-lock on every
        // call from reader tasks that lost the race.
        if !flow_is_current(&self.inner.flows, key, flow_id).await {
            return;
        }
        let removed = {
            let mut guard = self.inner.flows.write().await;
            // Re-check under write-lock: another racer may have replaced this
            // flow between our read-lock drop and write-lock acquire.
            if let Some(handle) = guard.get(key).map(Arc::clone) {
                let same = handle.lock().await.id == flow_id;
                if same { guard.remove(key) } else { None }
            } else {
                None
            }
        };

        if let Some(flow) = removed {
            self.enqueue_close(flow, reason);
        }
    }

    async fn cleanup_idle_flows(&self) {
        let now = Instant::now();
        let idle_timeout = self.inner.idle_timeout;

        for flow in drain_idle_flows(&self.inner.flows, idle_timeout, now).await {
            self.enqueue_close(flow, "idle_timeout");
        }
        for flow in drain_idle_flows(&self.inner.direct_flows, idle_timeout, now).await {
            self.enqueue_close_direct(flow, "idle_timeout");
        }
    }
}

/// Enqueue a raw client datagram onto a flow's outbound queue without ever
/// blocking. Called from the shared TUN read-loop; on a full queue (carrier
/// back-pressured or still dialling) or a closed queue (flow torn down) the
/// datagram is dropped and counted — the connectionless-correct response, and
/// what keeps the read-loop free of carrier back-pressure.
pub(super) fn queue_client_datagram(tx: &mpsc::Sender<Bytes>, payload: Bytes) {
    match tx.try_send(payload) {
        Ok(()) => {},
        Err(mpsc::error::TrySendError::Full(_)) => {
            metrics::record_tun_udp_forward_error("outbound_queue_full");
        },
        Err(mpsc::error::TrySendError::Closed(_)) => {
            metrics::record_tun_udp_forward_error("outbound_queue_closed");
        },
    }
}

/// Whether a UDP flow-reader error is a *clean* WebSocket close (Close frame /
/// EOF from the peer) rather than a data-path failure.
///
/// UDP associations are ephemeral: the server closing the mux carrier — e.g. on
/// its own idle timeout — is normal lifecycle, not an outage. Charging it as a
/// runtime failure stamps a cooldown and flaps the UDP health indicator on every
/// routine close. The TCP downlink already distinguishes this via
/// `closed_cleanly()`; this mirrors that on the connectionless path by matching
/// the typed [`WsClosed`] marker anywhere in the error chain (the documented
/// detection path, robust to added context layers). A *dirty* read error
/// returns `false` and escalates as before.
fn is_clean_ws_close(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.downcast_ref::<WsClosed>().is_some())
}

async fn report_udp_runtime_failure(
    manager: &UplinkManager,
    uplink_index: usize,
    error: &anyhow::Error,
) {
    manager
        .report_runtime_failure(uplink_index, TransportKind::Udp, error)
        .await;
}

async fn select_candidate_and_connect(
    manager: &UplinkManager,
    remote_target: &TargetAddr,
    client: Option<&str>,
) -> Result<(UplinkCandidate, UdpSessionTransport)> {
    let mut last_error = None;
    let strict_transport = manager.strict_active_uplink_for(TransportKind::Udp);
    let candidates = manager.udp_candidates_for(Some(remote_target), client).await;
    let iter = if strict_transport {
        candidates.into_iter().take(1).collect::<Vec<_>>()
    } else {
        candidates
    };
    for candidate in iter {
        match manager.acquire_udp_standby_or_connect(&candidate, "tun_udp").await {
            Ok(transport) => {
                // Install the carrier control-signal handler so a server
                // downstream-throttle notice on this UDP carrier penalises the
                // uplink and migrates traffic away. No-op unless the client
                // opted in; ignored by every non-padded datagram transport.
                let transport =
                    transport.with_throttle_handle(outline_uplink::dial::throttle_handle(
                        manager,
                        candidate.index,
                        TransportKind::Udp,
                    ));
                return Ok((candidate, transport));
            },
            Err(error) => {
                report_udp_runtime_failure(manager, candidate.index, &error).await;
                last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
            },
        }
    }
    Err(anyhow::Error::from(AllUdpUplinksFailed).context(format!(
        "all UDP uplinks failed for TUN flow: {}",
        last_error.unwrap_or_else(|| "no UDP-capable uplinks available".to_string())
    )))
}

/// Pick the least-recently-seen flow key in a table. Generic over the flow
/// state (via [`FlowStamp`]) so both the tunnelled (`flows`) and direct
/// (`direct_flows`) tables share one eviction-selection routine.
pub(super) async fn oldest_flow_key<K, F>(flows: &HashMap<K, Arc<Mutex<F>>>) -> Option<K>
where
    K: Clone,
    F: FlowStamp,
{
    let mut oldest: Option<(K, Instant)> = None;
    for (key, handle) in flows {
        let last_seen = handle.lock().await.last_seen();
        match &oldest {
            Some((_, t)) if last_seen >= *t => continue,
            _ => oldest = Some((key.clone(), last_seen)),
        }
    }
    oldest.map(|(k, _)| k)
}

pub(crate) async fn close_udp_flow(flow: Arc<Mutex<UdpFlowState>>, reason: &'static str) {
    // Record the close, then drop the flow state. The carrier is owned by the
    // flow's uplink task (`_uplink_task`, an `AbortOnDrop`); dropping the state
    // aborts that task, which releases the transport `Arc` it (and the downlink
    // reader) captured, so the upstream UDP socket / TCP / QUIC connection
    // closes promptly on drop — no explicit `transport.close()` is needed
    // (mirrors the TCP path, where teardown is likewise drop-driven).
    let (group, uplink, created_at) = {
        let guard = flow.lock().await;
        (guard.group_name.clone(), guard.uplink_name.clone(), guard.created_at)
    };
    metrics::record_tun_flow_closed(
        &group,
        &uplink,
        reason,
        Instant::now().saturating_duration_since(created_at),
    );
    drop(flow);
}

/// Build the TUN packet that delivers an exit's UDP response back to the
/// client. The wire prefix only tells us how many header bytes to skip; we
/// always source the reply from the address the client actually dialled
/// (`key.remote_*`), never the address the exit resolved/returned. With
/// QUIC/UDP destination override the exit may resolve the sniffed domain to a
/// different family (e.g. IPv6 for an IPv4 client) — echoing the exit's address
/// produced an unbuildable family-mismatched packet (`unexpected response
/// address family`, which tore down the whole flow and broke QUIC video) and
/// would have spoofed a source the client never contacted.
pub(super) fn build_client_response_packet(key: &UdpFlowKey, payload: &[u8]) -> Result<Vec<u8>> {
    let (_exit_src, consumed) = TargetAddr::from_wire_bytes(payload)?;
    let remote_target = ip_to_target(key.remote_ip, key.remote_port);
    build_response_packet(
        key.version,
        &remote_target,
        key.local_ip,
        key.local_port,
        &payload[consumed..],
    )
}

/// Strip the exit's `TargetAddr` wire prefix from a downlink datagram, leaving
/// just the UDP payload — the bytes coalesced into a USO super-segment. Mirror
/// of the skip in [`build_client_response_packet`]; a zero-copy `Bytes` slice.
fn extract_udp_payload(raw: &Bytes) -> Result<Bytes> {
    let (_exit_src, consumed) = TargetAddr::from_wire_bytes(raw)?;
    Ok(raw.slice(consumed..))
}

#[cfg(test)]
#[path = "tests/lifecycle.rs"]
mod tests;
