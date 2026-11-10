//! Plaintext Shadowsocks-UDP splice, and the response sender that routes a
//! relayed session's NAT replies back over the mesh.

use super::*;

/// The identity every NAT key of a relayed SS-UDP session is built from, taken
/// from the park and cross-checked against the user the edge attested.
///
/// This is the whole of the ownership rule. A relayed datagram supplies exactly
/// one thing — its target — and the home supplies the rest from here, so a
/// session can reattach the entries it parked, create entries for targets it has
/// not met before (both under its own `scope`), and reach an entry belonging to
/// another session or user by no path at all: a foreign entry lives under a
/// different key, which this session can never construct.
#[derive(Clone)]
pub(super) struct RelayedUdpIdentity {
    pub(super) user_id: Arc<str>,
    pub(super) fwmark: Option<u32>,
    pub(super) scope: Option<crate::server::nat::NatScope>,
}

impl RelayedUdpIdentity {
    /// Derives the identity from a park, and returns the parked keys that belong
    /// to it.
    ///
    /// The template comes from the first key the attested `user` owns; every
    /// other key must match it exactly or it is dropped rather than reattached.
    /// `take_for_resume` has already matched the park's *owner* against the same
    /// attestation, so a disagreement here means the key set itself straddles
    /// identities — impossible from this build's park path, and precisely the
    /// case where reattaching would hand a session a socket that is not its own.
    ///
    /// `None` when no key names the attested user (including an empty key set,
    /// which the park path never produces): there is no identity to serve under,
    /// and inventing one — an unmarked `fwmark`, say — would route the session's
    /// traffic outside the policy route its user is configured for.
    pub(super) fn from_park(
        parked: &ParkedSsUdpStream,
        user: &str,
    ) -> Option<(Self, Vec<NatKey>, usize)> {
        let template = parked.nat_keys.iter().find(|key| key.user_id.as_ref() == user)?;
        let identity = Self {
            user_id: Arc::clone(&template.user_id),
            fwmark: template.fwmark,
            scope: template.scope,
        };
        let owned: Vec<NatKey> = parked
            .nat_keys
            .iter()
            .filter(|key| identity.owns(key))
            .cloned()
            .collect();
        let foreign = parked.nat_keys.len() - owned.len();
        Some((identity, owned, foreign))
    }

    /// Whether `key` is one this session may address.
    pub(super) fn owns(&self, key: &NatKey) -> bool {
        key.user_id == self.user_id && key.fwmark == self.fwmark && key.scope == self.scope
    }
}

/// Downlink sender for a v5 relayed SS-UDP session.
///
/// Every NAT entry the session owns holds a clone; each upstream response
/// arrives here already SOCKS5-wrapped and *unsealed* (the entry's
/// [`UdpResponseCoding::Plaintext`] attachment) and goes onto a bounded channel
/// the splice's downlink pump frames onto the mesh stream.
///
/// No carrier padding and no throttle monitor, unlike the direct SS-UDP sender:
/// with the client's crypto terminated on the edge, the carrier the client
/// actually reads is the edge's, so padding and last-mile throttle detection
/// belong there and applying them here would pad bytes the client never sees in
/// that form.
pub(super) struct RelayedUdpSender {
    pub(super) tx: mpsc::Sender<Bytes>,
}

impl ResponseSender for RelayedUdpSender {
    fn send_bytes(&self, data: Bytes) -> futures_util::future::BoxFuture<'_, bool> {
        Box::pin(async move { self.tx.send(data).await.is_ok() })
    }

    fn protocol(&self) -> Protocol {
        // The mesh is QUIC; the client-facing protocol is the edge's business.
        Protocol::Http3
    }

    fn app_protocol(&self) -> AppProtocol {
        AppProtocol::Shadowsocks
    }
}

/// Path label for a relayed session's logs and per-path bookkeeping (SS-UDP NAT
/// entries, VLESS-mux sub-connections). The v5 home resolves no route — the
/// request path is a local matter of the edge — so one stable, low-cardinality
/// label stands in for it.
pub(super) const RELAYED_PATH: &str = "mesh";

/// Splices a relayed plaintext SS-UDP session onto the NAT entries it parked.
///
/// Not a byte splice like [`splice_plaintext_tcp`]: a parked SS-UDP session owns
/// no socket of its own, only a set of NAT keys, and the entries behind them are
/// addressed per datagram by the target that rides inside each one. So the two
/// pumps here are a *router*, not a copy loop:
///
/// * **Uplink** — one mesh datagram is one SOCKS5-wrapped packet. It is routed
///   through [`relay_socks5_datagram`], the same entry point the direct SS-UDP
///   path reaches after decrypting; the identity it is keyed under comes from
///   [`RelayedUdpIdentity`], never from the datagram.
/// * **Downlink** — every NAT entry the session owns holds a
///   [`RelayedUdpSender`]; the pump drains that channel and frames each response
///   back onto the mesh.
///
/// Datagram boundaries are the point (an SS-UDP packet is atomic, and two
/// coalescing into one decrypt is the production incident this migration
/// started from), so both directions use the mesh's own length framing —
/// [`read_datagram`] / [`write_datagram`] — rather than any byte splice. The
/// halves are held
/// directly instead of behind that carrier only because the close-intent
/// handling below needs `reset`/`finish`/`stopped` on the raw stream.
///
/// Bounded on every axis a peer could push: at most
/// [`UDP_MAX_CONCURRENT_RELAY_TASKS`] in-flight datagrams per relay (plus the
/// process-wide relay semaphore), one bounded downlink channel, a read that
/// caps each datagram at the framing's own maximum, and `cluster.relay_budget`
/// on every mesh write.
///
/// Continuity mirrors the TCP splice where it applies and is deliberately silent
/// where it does not: an `ack_prefix` OPEN still gets its
/// [`UpstreamAckFrame`] — the prologue is present exactly when the flag is set,
/// on both framings — but reports `0`, because a datagram session has no uplink
/// byte offset to be short of. `symmetric_replay` likewise has nothing to
/// replay: UDP is lossy by contract and no ring is kept.
///
/// Per-user byte accounting is deliberately absent, as in
/// [`splice_plaintext_tcp`]: it belongs to the node that terminates the client
/// session, which here is the edge. The `UdpResponseCoding::Plaintext`
/// attachment is what carries that decision down into
/// [`relay_socks5_datagram`] and the NAT reader; this splice counts the same
/// traffic on its `role="home"` mesh counters instead.
pub(super) async fn splice_plaintext_udp(
    stream: MeshStream,
    parked: ParkedSsUdpStream,
    header: &OpenHeader,
    session_id: SessionId,
    user: &str,
    cluster: &ClusterCtx,
    services: &Services,
) -> Result<()> {
    let MeshStream { mut send, mut recv } = stream;
    let registry = &services.orphan_registry;
    let server = Arc::clone(&services.udp_server);

    let Some((identity, owned_keys, foreign_keys)) = RelayedUdpIdentity::from_park(&parked, user)
    else {
        cluster.metrics.record_mesh_relay_rejected("park_identity");
        // Not a `miss`: a park *was* found under this id and taken, and it is
        // gone now — this arm cannot hand back keys it has no identity to route
        // under. See the `unusable` outcome's HELP text.
        cluster.metrics.record_mesh_relay_outcome("unusable", CLOSE_NONE);
        warn!(
            user,
            "refusing a relayed SS-UDP resume: no parked NAT key belongs to the attested user",
        );
        refuse_relay(MeshStream { send, recv }, CloseReason::Abort);
        return Ok(());
    };
    if foreign_keys > 0 {
        // Not fatal — the session keeps the keys that are its own — but nothing
        // in this build parks a mixed-identity key set, so it is worth saying.
        warn!(
            user,
            foreign_keys,
            "dropping parked SS-UDP NAT keys that do not belong to the resuming session",
        );
    }

    let stream_id = next_ss_udp_stream_id();
    let (tx, mut downlink_rx) = mpsc::channel::<Bytes>(server.ws_data_channel_capacity);
    let response_sender = UdpResponseSender::new(Arc::new(RelayedUdpSender { tx }));

    // Reattach: re-point every surviving parked entry at this carrier, under the
    // plaintext coding — the entry keeps its socket, and therefore its source
    // port and any upstream state pinned to it, across the node switch.
    let nat_keys = Arc::new(parking_lot::Mutex::new(StreamNatKeys::new()));
    let reattached = reattach_parked_nat_keys(
        &server.nat_table,
        owned_keys,
        &response_sender,
        &UdpResponseCoding::Plaintext,
        stream_id,
    );
    debug!(
        user,
        reattached = reattached.len(),
        "relayed ss-udp session reattached its parked NAT entries",
    );
    nat_keys.lock().adopt(reattached);

    // Uplink continuity, for symmetry with the byte-stream splice: the frame is
    // present exactly when the OPEN asked for it. Zero is the truthful answer —
    // a datagram session acknowledges no byte offset.
    if header.ack_prefix {
        let frame = UpstreamAckFrame { upstream_acked: 0 };
        if let Err(error) = send.write_all(&frame.encode()).await {
            cluster.metrics.record_mesh_relay_outcome("hit", CLOSE_NONE);
            // Detach the entries from this dead carrier and put them straight
            // back into the registry, exactly as the teardown path below does.
            // Not a datagram has moved, so every entry still holds the socket —
            // and the source port — it was parked with; releasing them without
            // re-parking would leave them ageing out with no responder attached
            // and cost the client its continuity for a mesh fault it had no part
            // in. `end.reparks` is not consulted because there is no close to
            // read an intent from: the client never said it was done.
            let detached = release_relayed_udp(&server, stream_id, &nat_keys);
            if registry.enabled() && !detached.is_empty() {
                registry.park(
                    session_id,
                    Parked::SsUdpStream(ParkedSsUdpStream {
                        nat_keys: detached,
                        owner: identity.user_id,
                    }),
                );
            }
            return Err(
                anyhow::Error::new(error).context("sending the upstream-ack frame over the mesh")
            );
        }
    }

    let up_bytes = cluster.metrics.mesh_bytes_counter("home", "up", "udp");
    let up_datagrams = cluster.metrics.mesh_datagrams_counter("home", "up");
    let down_bytes = cluster.metrics.mesh_bytes_counter("home", "down", "udp");
    let down_datagrams = cluster.metrics.mesh_datagrams_counter("home", "down");
    let budget = cluster.relay_budget;
    let stop_downlink = Notify::new();

    let SpliceOutcome { end, stream_finished, observed_intent } = {
        let recv = &mut recv;
        let send = &mut send;
        let stop = &stop_downlink;
        let server = &server;
        let identity = &identity;
        let nat_keys = &nat_keys;
        let response_sender = &response_sender;

        // Uplink: mesh → NAT. Datagrams are relayed concurrently, as the direct
        // path relays them, so one slow DNS resolution does not stall the
        // session behind it — bounded by the same per-carrier and process-wide
        // caps.
        let uplink = async move {
            let mut in_flight: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
            let mut buf = Vec::new();
            loop {
                // The read is pinned for the whole wait and only ever *polled*
                // by the inner select, never dropped by it. `read_datagram` is
                // not cancel-safe — it consumes a 4-byte length prefix and then
                // the body, so dropping it part-way leaves the stream mid-
                // datagram and every later read is mis-framed. Draining
                // `in_flight` concurrently is still required (a
                // `FuturesUnordered` advances only while polled, so an
                // otherwise idle session would stall its own DNS and sends
                // until the next datagram arrived), and this is how the two
                // coexist.
                let read = {
                    let read = read_datagram(recv, &mut buf);
                    tokio::pin!(read);
                    loop {
                        tokio::select! {
                            Some(()) = in_flight.next(), if !in_flight.is_empty() => {},
                            result = &mut read => break result,
                        }
                    }
                };
                let len = match read.context("relayed uplink datagram read from the mesh") {
                    // The edge finished the stream: the client carrier is gone.
                    // The NAT entries are deliberately left alone — the caller
                    // re-parks them for the next carrier.
                    Ok(None) => break,
                    Ok(Some(len)) => len,
                    Err(error) => {
                        // Drain what is already in flight before returning, so a
                        // datagram the home accepted still reaches its target
                        // rather than being dropped mid-send.
                        while in_flight.next().await.is_some() {}
                        return Err(SpliceFault::mesh(error));
                    },
                };
                up_bytes.increment(len as u64);
                up_datagrams.increment(1);
                if in_flight.len() >= UDP_MAX_CONCURRENT_RELAY_TASKS {
                    server.metrics.record_udp_relay_drop(
                        Transport::Udp,
                        Protocol::Http3,
                        AppProtocol::Shadowsocks,
                        "concurrency_limit",
                    );
                    warn!("relayed udp concurrent relay limit reached, dropping datagram");
                    continue;
                }
                let global_permit = match server
                    .relay_semaphore
                    .as_ref()
                    .map(|sem| Arc::clone(sem).try_acquire_owned())
                {
                    Some(Ok(permit)) => Some(permit),
                    Some(Err(_)) => {
                        server.metrics.record_udp_relay_drop(
                            Transport::Udp,
                            Protocol::Http3,
                            AppProtocol::Shadowsocks,
                            "global_concurrency_limit",
                        );
                        warn!("global udp concurrent relay limit reached, dropping datagram");
                        continue;
                    },
                    None => None,
                };
                let datagram = std::mem::take(&mut buf);
                let server = Arc::clone(server);
                let identity = identity.clone();
                let nat_keys = Arc::clone(nat_keys);
                let response_sender = response_sender.clone();
                in_flight.push(
                    async move {
                        let ctx = UdpDatagramCtx {
                            user_id: identity.user_id,
                            fwmark: identity.fwmark,
                            scope: identity.scope,
                            stream_id,
                            coding: UdpResponseCoding::Plaintext,
                            nat_keys: &nat_keys,
                            protocol: Protocol::Http3,
                            path: RELAYED_PATH,
                            started_at: std::time::Instant::now(),
                        };
                        if let Err(error) =
                            relay_socks5_datagram(&server, &ctx, &datagram, response_sender).await
                        {
                            warn!(?error, "relayed udp datagram failed");
                        }
                        drop(global_permit);
                    }
                    .boxed(),
                );
            }
            while in_flight.next().await.is_some() {}
            Ok(())
        };

        // Downlink: NAT responses → mesh, one datagram per frame. The ONLY
        // writer to the mesh stream.
        let downlink = async move {
            loop {
                let response = tokio::select! {
                    // Biased so a pending stop wins over one more response: the
                    // uplink has ended, and a response written into a stream the
                    // caller is about to close is worth nothing. Both branches
                    // are cancel-safe.
                    biased;
                    () = stop.notified() => return Ok(DownlinkEnd::Stopped),
                    // Never `None`: this scope holds `response_sender`, and with
                    // it a live sender clone, for the whole splice.
                    Some(response) = downlink_rx.recv() => response,
                    else => return Ok(DownlinkEnd::Stopped),
                };
                let len = response.len();
                match tokio::time::timeout(budget, write_datagram(send, &response)).await {
                    Ok(Ok(())) => {},
                    Ok(Err(error)) => {
                        // A `ClientDone` stop lands here as a write failure, the
                        // same signal the byte-stream splice reads: the client
                        // is finished, so the uplink must go on draining to its
                        // FIN while the downlink stands down.
                        if let Some(quinn::WriteError::Stopped(code)) =
                            error.downcast_ref::<quinn::WriteError>()
                            && CloseIntent::from_code(code.into_inner()) == CloseIntent::ClientDone
                        {
                            return Ok(DownlinkEnd::ClientDone);
                        }
                        return Err(SpliceFault::mesh(
                            error.context("relayed downlink datagram write to the mesh"),
                        ));
                    },
                    Err(_elapsed) => {
                        return Err(SpliceFault::stalled_mesh(anyhow::anyhow!(
                            "relayed downlink stalled past the health budget"
                        )));
                    },
                }
                down_bytes.increment(len as u64);
                down_datagrams.increment(1);
            }
        };

        tokio::pin!(uplink, downlink);
        let mut downlink_ended: Option<Result<DownlinkEnd, SpliceFault>> = None;
        loop {
            tokio::select! {
                result = &mut uplink => {
                    let downlink_end = match downlink_ended {
                        Some(ended) => ended,
                        None => {
                            stop.notify_one();
                            downlink.as_mut().await
                        },
                    };
                    break splice_end(result, downlink_end);
                },
                result = &mut downlink, if downlink_ended.is_none() => match result {
                    Ok(ended) => downlink_ended = Some(Ok(ended)),
                    Err(fault) => break SpliceOutcome {
                        end: fault.into_end(),
                        stream_finished: false,
                        observed_intent: CloseIntent::CarrierEnded,
                    },
                },
            }
        }
    };

    let intent = resolve_close_intent(&end, observed_intent, &send);
    cluster
        .metrics
        .record_mesh_relay_outcome("hit", intent.metric_label());

    match end.stream_close(stream_finished, intent) {
        StreamClose::Reset(reason) => {
            let _ = send.reset(VarInt::from_u32(reason.code()));
        },
        StreamClose::Finish => {
            let _ = send.finish();
        },
    }

    // Release the response sender from every entry we still own, exactly as the
    // direct path does at teardown: the entry holds a clone of it, and with it a
    // clone of the downlink channel, so leaving it in place would keep feeding a
    // carrier that is gone until the entry idle-expires.
    let detached = release_relayed_udp(&server, stream_id, &nat_keys);

    // Re-park unless the client said it was done. `SpliceEnd::reparks` also
    // gates on an upstream health verdict that a datagram session cannot fail:
    // the NAT entries are owned by the table, not by this carrier, and a mesh
    // fault leaves them untouched and worth handing to the next carrier.
    if end.reparks(intent) && registry.enabled() && !detached.is_empty() {
        debug!(
            user,
            keys = detached.len(),
            "re-parking a relayed ss-udp session after the mesh carrier ended",
        );
        registry.park(
            session_id,
            Parked::SsUdpStream(ParkedSsUdpStream {
                nat_keys: detached,
                owner: identity.user_id,
            }),
        );
    } else {
        // Nothing parked: the entries keep ageing on their own idle timer with
        // no responder attached, which is what an SS-UDP session without a
        // client has always done.
        debug!(user, ?intent, "not re-parking a relayed ss-udp session");
    }

    match end {
        SpliceEnd::Graceful { .. } => Ok(()),
        SpliceEnd::Faulted { error, .. } => Err(error),
    }
}

/// Detaches a relayed SS-UDP session's response sender from every NAT entry it
/// still owns, and hands back the keys that were still its own.
pub(super) fn release_relayed_udp(
    server: &UdpServerCtx,
    stream_id: u64,
    nat_keys: &parking_lot::Mutex<StreamNatKeys>,
) -> Vec<NatKey> {
    let keys = nat_keys.lock().take();
    detach_stream_nat_keys(&server.nat_table, stream_id, keys)
}
