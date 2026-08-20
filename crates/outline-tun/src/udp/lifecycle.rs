use std::sync::Arc;
use std::time::Instant;

use crate::udp::AllUdpUplinksFailed;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tokio::time::sleep;
use tracing::{debug, warn};

use outline_metrics as metrics;
use outline_transport::{
    AbortOnDrop, UdpSessionTransport, WsClosed, is_dropped_oversized_udp_error,
    payload_integrity_cause,
};
use outline_uplink::{TransportKind, UplinkCandidate, UplinkManager, WireAttempt};
use socks5_proto::TargetAddr;

use super::eviction::{evict_oldest_flow, record_flow_activity};
use super::types::{
    DirectUdpFlowState, UDP_OUTBOUND_QUEUE_CAP, UDP_PENDING_DIAL_BUFFER_CAP,
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

/// Everything [`TunUdpEngine::migrate_udp_flow`] needs to move a live flow onto
/// another uplink. The `&mut` fields are the uplink task's own carrier state:
/// the migration replaces them in place so the drain loop carries straight on
/// with the new carrier.
struct MigrateUdpFlow<'a> {
    key: &'a UdpFlowKey,
    flow_id: u64,
    /// Uplink the group repointed to. The redial goes *there* — unlike a TCP
    /// carrier-death migration, which redials the flow's own uplink because that
    /// is where the parked upstream is. Here the id carries its home shard, so a
    /// `shared_resume` mesh edge relays the resumed carrier back to the home.
    target: usize,
    manager: &'a UplinkManager,
    resume_store: &'a outline_transport::UdpResumeStore,
    transport: &'a mut Arc<UdpSessionTransport>,
    reader: &'a mut Option<AbortOnDrop>,
    uplink_index: &'a mut usize,
    uplink_name: &'a mut Arc<str>,
}

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

/// Placeholder `uplink_name` a flow carries between insertion into the table and
/// the moment its dial resolves. It is not a real uplink, so it never owns a
/// `tun_flows_active` entry — `bind_flow_uplink` relies on that when deciding
/// whether a rename is a migration or just the first bind.
pub(super) const UPLINK_CONNECTING: &str = "connecting";

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
                            // The flow's reader and sender tasks are both
                            // wrapped in `AbortOnDrop`, so simply releasing
                            // the last reference tears them down — they abort
                            // via their `Drop` impls when this `Arc` is
                            // dropped and no other task can reach it (we hold
                            // the only outstanding `Arc` after the map
                            // removed its entry), releasing the socket they
                            // share.
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
                record_flow_activity(&self.inner.eviction_index, &key, &mut *existing);
                existing.outbound_tx.clone()
            } else {
                // Each of these flows owns a carrier, and a carrier is ~28× a
                // direct flow in RSS, so they are bounded tighter than the
                // shared `max_flows` prices them. The budget is shared with the
                // TCP engine: `max_carrier_flows` means "how many carriers may
                // live at once", and counting each protocol separately let the
                // two paths together reach roughly twice the configured cap.
                let carrier_slot = match self.inner.carrier_slots.get() {
                    Some(slots) => match slots.try_acquire() {
                        Some(slot) => Some(slot),
                        None => {
                            // Victim selection is a single O(log n) index pop: no
                            // scan of the table and no other flow's lock is taken,
                            // so the write-lock this read-loop holds is released in
                            // constant time instead of after one await per live flow.
                            match evict_oldest_flow(&mut guard, &self.inner.eviction_index) {
                                Some((_, evicted)) => {
                                    evicted_flow = Some(evicted);
                                    // The victim's slot comes back only once the
                                    // background closer drops its state, so take
                                    // the place we just paid for directly.
                                    Some(slots.acquire_evicted())
                                },
                                None => {
                                    warn!(
                                        "TUN UDP flow table limit reached and no flow could be evicted"
                                    );
                                    return;
                                },
                            }
                        },
                    },
                    None => None,
                };
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
                    uplink_name: Arc::from(UPLINK_CONNECTING),
                    group_name: Arc::from(manager.group_name()),
                    created_at: now,
                    last_seen: now,
                    eviction_indexed_at: now,
                    last_ptb_sent: None,
                    outbound_tx: outbound_tx.clone(),
                    _uplink_task: Some(uplink_task),
                    _carrier_slot: carrier_slot,
                };
                guard.insert(key.clone(), Arc::new(Mutex::new(state)));
                self.inner.eviction_index.upsert(key.clone(), flow_id, now);
                outbound_tx
            }
        };

        if let Some(flow) = evicted_flow {
            // Logged off the write-lock: the victim's own lock can be held by
            // its carrier send for as long as the network takes, and the
            // read-loop must not wait on that with the table locked.
            {
                let snapshot = flow.lock().await;
                let (carriers_in_use, carrier_limit) = self
                    .inner
                    .carrier_slots
                    .get()
                    .map(|slots| (slots.in_use(), slots.cap()))
                    .unwrap_or((0, 0));
                warn!(
                    evicted_flow_id = snapshot.id,
                    evicted_uplink = %snapshot.uplink_name,
                    // The budget is shared with the TCP engine, so `in_use` can
                    // exceed this path's own flow count — that is the point.
                    carriers_in_use,
                    carrier_limit,
                    max_flows = self.inner.max_flows,
                    max_carrier_flows = self.inner.max_carrier_flows,
                    "evicted oldest TUN UDP flow: the carrier budget is full"
                );
            }
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
            // This flow's own resume slot. The process-wide SS-UDP cache holds
            // ONE id per resume scope, which is sound only where one carrier
            // exists per scope — and TUN dials one carrier per *flow*. Sharing
            // it made a fresh flow present the id the previously-closed flow
            // parked: on a hit the server re-points that flow's NAT entries at
            // this carrier, and `build_client_response_packet` then re-sources
            // its peer's datagrams from *this* flow's remote. A private slot
            // keeps the id with the flow that was issued it, which is also what
            // makes a soft-switch redial able to re-attach anything at all.
            let resume_store = outline_transport::UdpResumeStore::private();
            // Woken by every active-uplink change so an idle flow follows a
            // switch too, instead of sitting on the old uplink until its next
            // client datagram — which for a long-lived quiet flow may be never.
            let mut active_rx = manager.subscribe_active_uplinks();

            // Drain the outbound queue into a local buffer while the carrier
            // dial is in flight. Nothing can send until we are connected, so the
            // bounded outbound channel would otherwise fill during a slow dial
            // (seconds under DPI) and start dropping datagrams — losing exactly
            // the QUIC-handshake Initials / PTO retransmits the client sends
            // before it gets a reply, stalling the handshake onto TCP. Draining
            // here keeps the channel empty so the read-loop's `try_send` never
            // hits a full queue during the handshake window.
            let mut pending_datagrams: Vec<Bytes> = Vec::new();
            // Admission gate (`[tun] max_concurrent_upstream_dials`, shared
            // with the TCP engine): a UDP flow burst dials one carrier per
            // flow, so excess dials queue here for a permit — while still
            // buffering the client's datagrams (the QUIC-handshake preface)
            // exactly like the dial phase below, so nothing is lost to a full
            // outbound channel during the wait.
            let dial_admission = match engine.inner.dial_admission.get() {
                None => None,
                Some(semaphore) => match Arc::clone(semaphore).try_acquire_owned() {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        debug!(
                            flow_id,
                            "TUN UDP dial queued: concurrent upstream-dial cap reached"
                        );
                        let acquire = Arc::clone(semaphore).acquire_owned();
                        tokio::pin!(acquire);
                        loop {
                            tokio::select! {
                                biased;
                                permit = &mut acquire => {
                                    break Some(permit.expect(
                                        "dial admission semaphore is never closed",
                                    ));
                                },
                                maybe = outbound_rx.recv() => match maybe {
                                    Some(raw) => {
                                        if pending_datagrams.len() < UDP_PENDING_DIAL_BUFFER_CAP {
                                            pending_datagrams.push(raw);
                                        } else {
                                            metrics::record_tun_udp_forward_error(
                                                "pending_dial_buffer_full",
                                            );
                                        }
                                    },
                                    // The flow record (and its sender) was
                                    // removed while queued — abandon without
                                    // ever taking a permit.
                                    None => return,
                                },
                            }
                        }
                    },
                },
            };
            let connected = {
                let connect_fut = select_candidate_and_connect(
                    &manager,
                    &remote_target,
                    Some(&client_id),
                    &resume_store,
                );
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
            // The permit covers the dial only — never the flow's lifetime.
            drop(dial_admission);
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
            let mut reader = Some(engine.spawn_flow_reader(
                key.clone(),
                flow_id,
                Arc::clone(&transport),
                uplink_index,
                manager.clone(),
            ));

            // Uplink datagram+byte counters, cached across the drain. The group
            // is fixed for the flow; a mid-flow failover swaps `uplink_name` for
            // a fresh `Arc` (below), which re-resolves the handle onto the new
            // uplink's series via `FailoverCounter`'s `Arc::ptr_eq` check.
            let group_label: Arc<str> = Arc::from(manager.group_name());
            let mut up_counters = metrics::FailoverCounter::new();

            // Drain the outbound queue. `recv` yields `None` when the flow
            // record (holding the sender) is removed — the flow's teardown
            // signal — at which point the reader and transport drop here.
            // Flush the datagrams buffered during the dial (the client's
            // handshake preface) in order first, then resume the live drain.
            let mut pending = pending_datagrams.into_iter();
            loop {
                // Follow a strict-active repoint. Checked before the wait below,
                // not after it, so a flow with nothing to send still acts on the
                // switch.
                match super::udp_active_uplink_verdict(&manager, uplink_index) {
                    super::UdpActiveUplinkVerdict::Stay => {},
                    super::UdpActiveUplinkVerdict::Abort => {
                        engine.close_flow_if_current(&key, flow_id, "global_switch").await;
                        return;
                    },
                    super::UdpActiveUplinkVerdict::Migrate { target } => {
                        match engine
                            .migrate_udp_flow(MigrateUdpFlow {
                                key: &key,
                                flow_id,
                                target,
                                manager: &manager,
                                resume_store: &resume_store,
                                transport: &mut transport,
                                reader: &mut reader,
                                uplink_index: &mut uplink_index,
                                uplink_name: &mut uplink_name,
                            })
                            .await
                        {
                            true => continue,
                            // The redial failed: fall through to the teardown a
                            // switch would have given anyway.
                            false => {
                                engine.close_flow_if_current(&key, flow_id, "global_switch").await;
                                return;
                            },
                        }
                    },
                }
                let raw = match pending.next() {
                    Some(raw) => raw,
                    None => tokio::select! {
                        biased;
                        // A repoint: go round and let the verdict decide.
                        _ = active_rx.changed() => continue,
                        maybe = outbound_rx.recv() => match maybe {
                            Some(raw) => raw,
                            None => break,
                        },
                    },
                };
                let effective_target = remote_target_override.as_ref().unwrap_or(&remote_target);
                let payload = match super::build_udp_payload(effective_target, &raw) {
                    Ok(payload) => payload,
                    Err(_) => continue,
                };
                match transport.send_packet(&payload).await {
                    Ok(()) => up_counters
                        .get(&group_label, &uplink_name, |group, uplink| {
                            metrics::udp_flow_counters("up", group, uplink)
                        })
                        .record(payload.len()),
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
                            &resume_store,
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
                                reader = Some(engine.spawn_flow_reader(
                                    key.clone(),
                                    flow_id,
                                    Arc::clone(&transport),
                                    uplink_index,
                                    manager.clone(),
                                ));
                                if let Err(retry_error) = transport.send_packet(&payload).await {
                                    warn!(flow_id, error = %format!("{retry_error:#}"), "TUN UDP resend after reconnect failed");
                                } else {
                                    // `uplink_name` was just swapped to the
                                    // replacement's `Arc`, so this re-resolves
                                    // onto the new uplink's series.
                                    up_counters
                                        .get(&group_label, &uplink_name, |group, uplink| {
                                            metrics::udp_flow_counters("up", group, uplink)
                                        })
                                        .record(payload.len());
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
                bump_last_seen_if_current(
                    &engine.inner.flows,
                    &engine.inner.eviction_index,
                    &key,
                    flow_id,
                )
                .await;
            }
        }))
    }

    /// Publish a freshly-dialled uplink (`index`, `name`) onto the flow record,
    /// replacing the `usize::MAX` / `"connecting"` placeholders. Returns `false`
    /// if the flow at `key` is gone or was replaced (a newer generation now
    /// owns the slot), signalling the uplink task to stop.
    /// Carry a live TUN UDP flow over to the uplink the group just repointed to,
    /// instead of tearing it down. Returns `false` when the redial failed and
    /// the caller must fall through to the teardown.
    ///
    /// # What "migrating" means here — and what it does not
    ///
    /// Not byte-continuity. A parked UDP session keeps **no** back-buffer of
    /// upstream-bound packets (`server/resumption/parked.rs`): the kernel
    /// receive buffer fills and overflow drops, because UDP is loss-tolerant by
    /// design. What resume preserves is the *session*: for SS-UDP the server
    /// re-points the parked NAT entries at the new carrier, for VLESS-UDP it
    /// re-attaches the pinned `UdpSocket` — either way the exit keeps the same
    /// source port, so the peer's own NAT binding, its path validation and any
    /// per-address state survive the switch. That is the whole prize, and it is
    /// why there is no confirmed-hit rule like the TCP path's: a UDP resume miss
    /// costs a new source port, not a spliced byte stream, so it is never worse
    /// than the teardown this replaces.
    ///
    /// # Ordering
    ///
    /// The reader dies first, then the carrier, and only then does the redial go
    /// out. Both halves of that are load-bearing:
    ///
    /// - The **reader** must go first because it tears the flow down on *any*
    ///   read failure — including the one that closing the carrier is about to
    ///   cause. Left running, it would remove the flow record from under this
    ///   task and the migration would have nothing to carry over.
    /// - The **carrier** must be closed before the redial because the server
    ///   parks a session only once its stream has closed. A redial that arrived
    ///   first would look this flow's id up against a still-live session, get
    ///   `miss-unknown`, and be handed a fresh upstream — a guaranteed miss.
    ///   Same rule the TCP soft switch follows.
    async fn migrate_udp_flow(&self, args: MigrateUdpFlow<'_>) -> bool {
        let MigrateUdpFlow {
            key,
            flow_id,
            target,
            manager,
            resume_store,
            transport,
            reader,
            uplink_index,
            uplink_name,
        } = args;
        let group_label: Arc<str> = Arc::from(manager.group_name());
        let Some(candidate) = manager
            .uplinks()
            .get(target)
            .map(|uplink| UplinkCandidate { index: target, uplink: uplink.clone() })
        else {
            // The pointer named an index this group does not have. Nothing to
            // dial; the caller tears the flow down as a switch always did.
            metrics::record_tun_udp_event(&group_label, uplink_name, "soft_switch_target_invalid");
            return false;
        };

        // Retire, in this order. See the ordering note above.
        *reader = None;
        if let Err(error) = transport.close().await {
            debug!(
                flow_id,
                error = %format!("{error:#}"),
                "closing the old TUN UDP carrier before a soft-switch redial failed"
            );
        }

        // Did this flow ever hold an id of its own? A carrier the server issued
        // nothing for (resumption off server-side) still migrates — the flow
        // survives the switch, it just comes back on a fresh source port — but
        // "migrated" and "migrated blind" must not share a counter, or a fleet
        // with resumption misconfigured would look like a fleet with working
        // session continuity.
        let carried_an_id = resume_store.holds_any_id().unwrap_or(false);

        // Redial the *target uplink's* current active wire, not always its
        // primary: a soft-switch redial that ignored a repointed-away-from-
        // primary wire would migrate the flow off the carrier that uplink is
        // actually serving traffic on. Not "the flow's own wire" — a flow keeps
        // no wire memory, so this follows whatever the uplink's state machine
        // points at at redial time.
        //
        // But only when the gate is on. `tun_wire_dial` exists so this binary
        // can be deployed to the fleet inert — gate off must behave exactly
        // like today's wire-0-only redial, byte for byte, so operators can
        // flip the flag on one node at a time. `active_wire` is NOT
        // provably 0 on a gate-off node: the fallback-wire prober
        // (`manager/probe/wire.rs`), `rotate_active_wire`'s shuffle timer,
        // and the SOCKS ingress's UDP dial loop (which always allows
        // fallbacks, gate or no gate) can all advance it independently of
        // this ingress's own gate. Reading it unconditionally would let a
        // gate-off TUN redial land on a different carrier than the one it
        // would have dialed before this feature existed. Do not "simplify"
        // this back to an unconditional read — that is precisely the bug
        // this comment exists to prevent.
        //
        // One wire, no cascade: this resolves a single wire and dials it
        // directly rather than walking `dial_over_wires`, so no sibling wire is
        // tried and no `record_wire_outcome` is filed. A failed redial tears the
        // flow down exactly as a hard switch would (the arm below), which is the
        // pre-wire behaviour. Gate-on consequence: an active wire with no UDP
        // path is dialed and fails here rather than being skipped as
        // `NotApplicable` the way the fresh path skips it.
        let wire = if manager.load_balancing().tun_wire_dial {
            manager.active_wire(candidate.index, TransportKind::Udp)
        } else {
            0
        };
        let connected = manager
            .acquire_udp_on_wire(&candidate, wire, "tun_udp", resume_store)
            .await;
        let fresh = match connected {
            Ok(fresh) => fresh,
            Err(error) => {
                report_udp_runtime_failure(manager, target, &error).await;
                warn!(
                    flow_id,
                    error = %format!("{error:#}"),
                    "TUN UDP soft-switch redial failed; tearing the flow down as a hard switch would"
                );
                metrics::record_tun_udp_event(
                    &group_label,
                    uplink_name,
                    "soft_switch_migration_failed",
                );
                return false;
            },
        };
        let fresh = fresh.with_throttle_handle(outline_uplink::dial::throttle_handle(
            manager,
            target,
            TransportKind::Udp,
        ));

        *transport = Arc::new(fresh);
        *uplink_index = target;
        *uplink_name = Arc::from(candidate.uplink.name.as_str());
        // Re-label the flow onto the new uplink, or the verdict above would see
        // it as stranded on the very next datagram and undo the migration.
        if !self.bind_flow_uplink(key, flow_id, *uplink_index, uplink_name).await {
            // The flow was replaced or evicted while the redial was in flight;
            // the caller's teardown is a no-op against the newer generation.
            return false;
        }
        *reader = Some(self.spawn_flow_reader(
            key.clone(),
            flow_id,
            Arc::clone(transport),
            *uplink_index,
            manager.clone(),
        ));
        metrics::record_uplink_selected("udp", manager.group_name(), uplink_name);
        metrics::record_tun_udp_event(
            &group_label,
            uplink_name,
            if carried_an_id {
                "soft_switch_migrated"
            } else {
                "soft_switch_migrated_no_resume_id"
            },
        );
        debug!(
            flow_id,
            uplink = %uplink_name,
            carried_an_id,
            "TUN UDP flow followed a strict-active repoint instead of being torn down"
        );
        true
    }

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
        // Carry the flow's `tun_flows_active` entry over with it. The gauge is
        // keyed by `(group, uplink)`: the `+1` was booked when the flow was
        // created and the `-1` is booked, on close, against whatever uplink it
        // is on by then. A migration that only renamed the flow therefore
        // stranded the `+1` on the uplink it left and took the `-1` from the one
        // it arrived at, so both series drifted by one per migration and the
        // destination went negative — production showed `nuxt2 = +177` against
        // `sebek = -177`, and a 14-day minimum of -491 on another node. Direct
        // flows were never affected because they never migrate.
        //
        // Skipped for the first bind, which merely replaces the `"connecting"`
        // placeholder: `record_tun_flow_created` has not run yet at that point,
        // so there is no `+1` to move and booking one here would push
        // `uplink="connecting"` negative instead.
        if flow.uplink_name.as_ref() != UPLINK_CONNECTING
            && flow.uplink_name.as_ref() != uplink_name.as_ref()
        {
            metrics::move_tun_flow_active(&flow.group_name, &flow.uplink_name, uplink_name);
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
            // Downlink datagram+byte counters, cached across reads. The group is
            // fixed for the flow; `uplink_name` (re-read from the flow record
            // each iteration) swaps to a fresh `Arc` on failover, re-resolving
            // the handle onto the new series via `FailoverCounter`.
            let group_label: Arc<str> = Arc::from(manager.group_name());
            let mut down_counters = metrics::FailoverCounter::new();
            let result = async {
                let mut carried_over: Option<Bytes> = None;
                loop {
                    // Only the teardown verdict is the reader's to act on. A
                    // migration replaces the carrier this task is reading, so it
                    // belongs to the uplink task that owns it — which retires
                    // this reader before it touches the carrier at all.
                    if matches!(
                        super::udp_active_uplink_verdict(&manager, uplink_index),
                        super::UdpActiveUplinkVerdict::Abort
                    ) {
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
                    down_counters
                        .get(&group_label, &uplink_name, |group, uplink| {
                            metrics::udp_flow_counters("down", group, uplink)
                        })
                        .record(total_payload);

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
                    bump_last_seen_if_current(
                        &engine.inner.flows,
                        &engine.inner.eviction_index,
                        &key,
                        flow_id,
                    )
                    .await;
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            }
            .await;
            // Why the reader stopped decides what the uplink is charged for:
            // only a carrier fault may escalate (see [`ReaderStop`]). The flow
            // itself goes away in every case and is re-created on the next
            // packet; only the close reason and the uplink-level accounting
            // differ.
            let stop = result.as_ref().err().map(ReaderStop::classify);
            let close_reason = stop.as_ref().map_or("closed", ReaderStop::close_reason);

            if let Err(ref error) = result
                && let Some(ref stop) = stop
                && !matches!(stop, ReaderStop::CleanClose)
                && flow_is_current(&engine.inner.flows, &key, flow_id).await
            {
                if stop.escalates_to_carrier() {
                    report_udp_runtime_failure(&manager, uplink_index, error).await;
                    metrics::record_tun_packet(
                        "down",
                        ip_family_from_version(key.version),
                        "error",
                    );
                    warn!(
                        flow_id,
                        error = %format!("{error:#}"),
                        "TUN UDP flow reader stopped"
                    );
                } else if let ReaderStop::PayloadIntegrity(cause) = stop {
                    manager.report_payload_integrity_failure(
                        uplink_index,
                        TransportKind::Udp,
                        cause,
                        error,
                    );
                    metrics::record_tun_packet(
                        "down",
                        ip_family_from_version(key.version),
                        "payload_error",
                    );
                    debug!(
                        flow_id,
                        cause,
                        error = %format!("{error:#}"),
                        "TUN UDP flow reader stopped on a corrupt datagram"
                    );
                }
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
                if same {
                    // Unindex before the map removal so no eviction can pick a
                    // key that is no longer in the table.
                    self.inner.eviction_index.remove(key, flow_id);
                    guard.remove(key)
                } else {
                    None
                }
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

        // Each reaped flow also leaves the eviction index — a stale entry is
        // both a leaked key and a wasted eviction attempt later on. The removal
        // is generation-checked, so a key already re-created by a fresh flow
        // keeps the new generation's entry.
        for (key, flow) in drain_idle_flows(&self.inner.flows, idle_timeout, now).await {
            let flow_id = flow.lock().await.id;
            self.inner.eviction_index.remove(&key, flow_id);
            self.enqueue_close(flow, "idle_timeout");
        }
        for (key, flow) in drain_idle_flows(&self.inner.direct_flows, idle_timeout, now).await {
            let flow_id = flow.lock().await.id;
            self.inner.direct_eviction_index.remove(&key, flow_id);
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

/// Why a UDP flow reader stopped — and, with it, what the uplink is charged
/// for. The flow is torn down in all three cases; only the accounting differs.
#[derive(Debug)]
pub(super) enum ReaderStop {
    /// A clean WebSocket close (Close frame / EOF from the peer, surfaced as
    /// [`WsClosed`]). UDP associations are ephemeral and the server closing
    /// the mux carrier — e.g. on its own idle timeout — is normal lifecycle,
    /// not an outage. Mirrors the TCP downlink's `closed_cleanly()`.
    CleanClose,
    /// The carrier delivered bytes that could not be turned back into a
    /// datagram: an AEAD open failure, a truncated packet, or an SS2022
    /// replay/reorder rejection. Carries the low-cardinality cause label.
    ///
    /// This is *not* a carrier fault, and reporting it as one is the bug this
    /// variant exists to prevent: it capped `xhttp_h3 → xhttp_h2` per
    /// occurrence, so a ~0.1 % corrupt-datagram rate held one production
    /// uplink in UDP-over-TCP 69.6 % of the time. The flow is still recreated
    /// (its SS2022 replay state is out of step after the rejection); the
    /// uplink just does not pay for it.
    PayloadIntegrity(&'static str),
    /// A dirty transport error — read failure, timeout, reset, frame-send
    /// error. The one shape that says something about the carrier, and the
    /// only one that escalates.
    CarrierFailure,
}

impl ReaderStop {
    pub(super) fn classify(error: &anyhow::Error) -> Self {
        if is_clean_ws_close(error) {
            return Self::CleanClose;
        }
        match payload_integrity_cause(error) {
            Some(cause) => Self::PayloadIntegrity(cause),
            None => Self::CarrierFailure,
        }
    }

    /// Whether this stop may be reported as a runtime uplink failure
    /// (cooldown, penalty, failure streak, carrier descent).
    pub(super) fn escalates_to_carrier(&self) -> bool {
        matches!(self, Self::CarrierFailure)
    }

    /// The flow-close reason recorded on `tun_flows_closed_total`.
    pub(super) fn close_reason(&self) -> &'static str {
        match self {
            Self::CleanClose => "closed",
            Self::PayloadIntegrity(_) => "payload_error",
            Self::CarrierFailure => "read_error",
        }
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
    resume_store: &outline_transport::UdpResumeStore,
) -> Result<(UplinkCandidate, UdpSessionTransport)> {
    let mut last_error = None;
    let strict_transport = manager.strict_active_uplink_for(TransportKind::Udp);
    let candidates = manager.udp_candidates_for(Some(remote_target), client).await;
    let iter = if strict_transport {
        candidates.into_iter().take(1).collect::<Vec<_>>()
    } else {
        candidates
    };
    let wires_enabled = manager.load_balancing().tun_wire_dial;
    for candidate in iter {
        let candidate_ref = &candidate;
        let dialed = manager
            .dial_over_wires(candidate_ref, TransportKind::Udp, wires_enabled, |wire| async move {
                let spec =
                    outline_uplink::WireSpec::of(&candidate_ref.uplink, wire).ok_or_else(|| {
                        anyhow!("uplink {} has no wire {wire}", candidate_ref.uplink.name)
                    })?;
                // A wire with no UDP path is not a failure of that wire — it
                // was never dialable on this plane. Skipping without an
                // outcome keeps it out of the wire state machine entirely.
                //
                // Gated on `wires_enabled`, not on `wire == 0`: with the gate
                // off, `dial_over_wires` only ever asks for wire 0, and that
                // call must reach `acquire_udp_on_wire` exactly as it did
                // before this loop existed — including its "no udp dial URL
                // configured" failure and the `warm_standby_acquire` counter
                // tick that comes with it. Skipping it here instead would
                // swap that failure for `dial_over_wires`'s own "no wires
                // configured" text, changing a production metric label and
                // dropping a counter on a gate-off node — the very inertness
                // this flag promises not to break. With the gate on, the
                // skip must still apply to a UDP-less *primary* (not just
                // fallback wires): that is what lets a TCP-only-primary,
                // UDP-fallback uplink (`supports_udp_any()`) reach its UDP
                // wire at all.
                if wires_enabled && !spec.supports_udp() {
                    return Ok(WireAttempt::NotApplicable);
                }
                manager
                    .acquire_udp_on_wire(candidate_ref, wire, "tun_udp", resume_store)
                    .await
                    .map(WireAttempt::Built)
            })
            .await;
        match dialed {
            Ok((transport, _wire)) => {
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
