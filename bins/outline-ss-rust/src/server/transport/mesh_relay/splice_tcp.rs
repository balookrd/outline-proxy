//! Plaintext TCP splice between a relayed stream and a parked upstream.

use super::*;

/// Splices a relayed plaintext stream onto a parked TCP upstream.
///
/// Simpler than the direct relay it stands in for: no decryptor, no encryptor,
/// no route context — just the unacked replay suffix followed by a bidirectional
/// pump. The edge holds the client's crypto and this node holds the socket.
/// The ring already holds **plaintext** keyed by plaintext offsets, so the
/// suffix goes out as-is and the edge seals it under its own client key.
///
/// Health budget: `cluster.relay_budget` bounds a single write in each
/// direction, so a peer (or an upstream) that stops draining tears the relay
/// down instead of pinning the parked socket forever. It measures progress, not
/// RTT — an idle relay blocks on a read, never on a write, and a socket that
/// keeps taking bytes keeps renewing the budget.
///
/// Both pumps borrow their halves rather than consuming them, so whichever side
/// ends first this function gets the halves back. That is what makes the three
/// obligations below possible:
///
/// * **Failures never look graceful.** Every error arm resets the mesh stream
///   ([`CloseReason::Budget`] for a stalled write, [`CloseReason::Abort`]
///   otherwise) before returning. Dropping the send half instead would `finish`
///   it, and the edge would read a stalled home or a broken upstream as a clean
///   upstream close — sealing a truncated response to its client as complete.
///   The one exception is a stream the downlink already finished on upstream
///   EOF: quinn accepts a reset after a finish and drops the still-unacked tail,
///   so resetting there would turn a *complete* response into an abort.
/// * **The session is re-parked — unless the client is done with it.** When the
///   carrier ends while the upstream is healthy, the upstream halves go back
///   into the registry under the same id, mirroring the direct path's
///   `try_park_on_drop`. Without it a v5 session would survive exactly one
///   carrier switch. The exception is a [`CloseIntent::ClientDone`] close: that
///   client is not coming back, so the upstream is half-closed instead of
///   parked (see [`SpliceEnd::reparks`]), and the mesh half — which that client
///   already stopped — is closed with an explicit [`CloseReason::Fin`] rather
///   than left to quinn's drop, which would echo the [`CloseIntent`] code back
///   as a reset code (see [`SpliceEnd::stream_close`]). A failure in the
///   *prologue* — the ack frame or the replay suffix — re-parks too, and
///   unconditionally: nothing has been read from or written to the upstream, so
///   there is no close to read an intent from and the bundle goes back exactly
///   as it came. All four splices agree on this.
/// * **The hand-off loses no bytes.** Because the session is re-parked, a pump
///   dropped mid-operation would silently punch a hole in the client's stream.
///   The downlink is therefore stopped cooperatively at a read boundary (as the
///   direct path's `relay_cancel` does) instead of being cancelled inside a
///   write, and the uplink accounts for every byte the socket took as it takes
///   them, so `upstream_bytes_acked` is exact at any cancellation point.
pub(super) async fn splice_plaintext_tcp(
    stream: MeshStream,
    parked: ParkedTcp,
    header: &OpenHeader,
    session_id: SessionId,
    cluster: &ClusterCtx,
    registry: &OrphanRegistry,
) -> Result<()> {
    let MeshStream { mut send, mut recv } = stream;

    let up_bytes = cluster.metrics.mesh_bytes_counter("home", "up", "tcp");
    let down_bytes = cluster.metrics.mesh_bytes_counter("home", "down", "tcp");
    let budget = cluster.relay_budget;

    // The prologue runs against `parked` whole, before it is taken apart, so a
    // write that fails here can hand the bundle straight back: neither socket
    // half has been touched, and the ring is only read (`replay_from` takes
    // `&self` and consumes nothing), so the session is worth exactly as much to
    // the next carrier as it was a moment ago. Discarding it instead would cost
    // the client its continuity for a mesh fault the session had no part in —
    // the same reasoning the VLESS-mux splice states at its own ack frame.
    // Nothing is written to the upstream before this point either, so the edge
    // is free to re-open the relay and get the same bytes again.
    let bundle_intact = |parked: ParkedTcp| {
        // A `hit` however it ends — the park *was* taken — but it ended before
        // either pump ran, so there is no close to label it with.
        cluster.metrics.record_mesh_relay_outcome("hit", CLOSE_NONE);
        if registry.enabled() {
            registry.park(session_id, Parked::Tcp(parked));
        }
    };

    // Uplink continuity: how far the upstream socket actually got before this
    // carrier. The home may have consumed uplink bytes off a dying mesh carrier
    // that the socket never took, so without this the resuming edge would either
    // skip them (a hole in the request body at the target) or resend from zero.
    // First on the wire, ahead of the replay suffix and of any fresh byte —
    // the same order the direct path emits its v1 frame before the v2 "ORDR" one.
    if header.ack_prefix {
        let frame = UpstreamAckFrame {
            upstream_acked: parked.upstream_bytes_acked.load(Ordering::Relaxed),
        };
        if let Err(error) = send.write_all(&frame.encode()).await {
            bundle_intact(parked);
            return Err(
                anyhow::Error::new(error).context("sending the upstream-ack frame over the mesh")
            );
        }
    }

    // Byte-continuity: everything the session emitted past the offset the client
    // acknowledged goes out first, ahead of any fresh upstream byte, so the
    // client's stream has no gap and no duplicate across the carrier switch.
    let replay = match (header.symmetric_replay, &parked.downlink_ring) {
        (true, Some(ring)) => Some(ring.lock().replay_from(header.client_down_acked)),
        _ => None,
    };
    if let Some(outcome) = replay {
        match outcome {
            ReplayOutcome::Available(bytes) if !bytes.is_empty() => {
                if let Err(error) = send.write_all(&bytes).await {
                    // The suffix is still in the ring — `replay_from` only read
                    // it — and the edge never delivered these bytes to a client,
                    // so the next carrier replays the same suffix from the same
                    // offset.
                    bundle_intact(parked);
                    return Err(anyhow::Error::new(error)
                        .context("replaying the downlink suffix over the mesh"));
                }
                down_bytes.increment(bytes.len() as u64);
            },
            // Nothing outstanding: the client observed everything sent.
            ReplayOutcome::Available(_) => {},
            // Eviction rolled past the requested offset, or the client claims
            // more than was ever sent. Continuity is lost for the gap; the
            // session still runs from here.
            //
            // TODO: the v5 OPEN ack carries no flag for this, so unlike the
            // direct path (which sets REPLAY_TRUNCATED in its "ORDR" frame) the
            // home cannot yet tell the edge to fail the client fast, as
            // `docs/SESSION-RESUMPTION.md` requires. Until that protocol field
            // exists the condition is at least observable on the counter the
            // direct path feeds, under its own `path="mesh"` label.
            other => {
                // `replay_from` only ever answers `Truncated` or `OffsetAhead`
                // here — a park with no ring never produced a `replay` at all
                // (the `match` above returns `None` for it), so this arm cannot
                // see the `no_ring` case the direct paths report.
                let reason = match other {
                    ReplayOutcome::OffsetAhead => "client_ahead",
                    _ => "evicted",
                };
                cluster
                    .metrics
                    .record_orphan_downlink_replay_truncated("tcp", reason, "mesh");
                debug!(
                    ?other,
                    target = %parked.target_display,
                    "no replayable downlink suffix for a relayed resume; the client is not yet \
                     told about the gap",
                );
            },
        }
    }

    // Past the prologue: nothing below can hand the bundle back whole, so it is
    // taken apart here. Every field is kept — the plaintext splice itself needs
    // only the socket halves and the ring, but a re-park has to hand the whole
    // bundle back to the registry with the same field semantics the direct path
    // parks with. The user is already authenticated (by the edge, attested in
    // the USER frame) and the owner check is done, so the identity does no work
    // *here* — `owner` still keys the park, and `protocol` rides along as the
    // diagnostic label of whichever protocol first minted this session.
    let ParkedTcp {
        mut upstream_writer,
        mut upstream_reader,
        target_display,
        owner,
        protocol,
        // Per-user byte accounting stays with the node that terminates the
        // client session, i.e. the edge; the home counts this traffic on its
        // `role="home"` mesh counters below.
        user_counters,
        upstream_guard,
        upstream_bytes_acked,
        downlink_ring,
    } = parked;

    // Cooperative stop for the downlink pump, mirroring `relay_cancel` on the
    // direct path (`super::tcp`). `select!` drops the losing future wherever it
    // happens to be, and for the downlink that means discarding bytes already
    // read out of the upstream socket. Those bytes survive only if a v2 ring
    // exists and the next resume negotiates one — and `downlink_buffer_bytes`
    // defaults to 0 — so with the session re-parked below, the next carrier
    // would resume a stream with a silent hole. Stopping at a read boundary
    // instead loses nothing: unread bytes stay in the socket, which is exactly
    // what the park hands on.
    let stop_downlink = Notify::new();

    let SpliceOutcome { end, stream_finished, observed_intent } = {
        // Reborrows, so the pumps own references and the halves come back to
        // this scope when the pumps drop.
        let recv = &mut recv;
        let send = &mut send;
        let writer = &mut upstream_writer;
        let reader = &mut upstream_reader;
        let acked = &upstream_bytes_acked;
        let ring = &downlink_ring;
        let stop = &stop_downlink;

        // Uplink: mesh → parked upstream. The ONLY writer to the upstream socket.
        let uplink = async move {
            loop {
                let chunk = match recv
                    .read_chunk(MESH_HOME_SPLICE_CHUNK, true)
                    .await
                    .context("relayed uplink read from the mesh")
                {
                    Ok(Some(chunk)) => chunk,
                    // The edge finished the stream: the client carrier is gone.
                    // The upstream is deliberately left open — the caller
                    // re-parks it for the next carrier, and a half-close would
                    // make that park useless. The non-park path shuts it down.
                    Ok(None) => return Ok(()),
                    Err(error) => return Err(SpliceFault::mesh(error)),
                };
                write_uplink_chunk(writer, &chunk.bytes, budget, &up_bytes, acked).await?;
            }
        };

        // Downlink: parked upstream → mesh. The ONLY writer to the mesh stream.
        // One buffer for the relay's lifetime, bounded by MESH_HOME_SPLICE_CHUNK.
        let downlink = async move {
            let mut buf = vec![0u8; MESH_HOME_SPLICE_CHUNK];
            loop {
                let len = tokio::select! {
                    // Biased: once the uplink has ended, every further chunk is
                    // one more thing to hand over, so a pending stop wins over
                    // more upstream data. Both branches are cancel-safe — a
                    // dropped `Notified` hands its notification back, and a
                    // cancelled `read` consumes nothing from the socket.
                    biased;
                    () = stop.notified() => return Ok(DownlinkEnd::Stopped),
                    read = reader.read(&mut buf) => match read
                        .context("relayed downlink read from the upstream")
                    {
                        Ok(len) => len,
                        Err(error) => return Err(SpliceFault::upstream(error)),
                    },
                };
                if len == 0 {
                    // Upstream EOF — the one case where a graceful FIN is the
                    // truth, so the edge can seal a complete response. From here
                    // on the stream must never be reset.
                    let _ = send.finish();
                    return Ok(DownlinkEnd::UpstreamEof);
                }
                // Capture plaintext into the ring before it leaves the home,
                // exactly as the direct relay does — so a later park under this
                // id can still replay the suffix from a consistent offset.
                if let Some(ring) = ring {
                    ring.lock().push(&buf[..len]);
                }
                match tokio::time::timeout(budget, send.write_all(&buf[..len])).await {
                    Ok(Ok(())) => {},
                    // The edge stopping this half with `ClientDone` is a
                    // deliberate end, not a fault: it wants no more downlink and
                    // the uplink must go on draining to its FIN so the target
                    // sees the whole request body. Any other stop code (a bare
                    // carrier drop sends `0`) stays a fault, which re-parks and
                    // lets the next carrier replay from the acked offset.
                    Ok(Err(quinn::WriteError::Stopped(code)))
                        if CloseIntent::from_code(code.into_inner()) == CloseIntent::ClientDone =>
                    {
                        return Ok(DownlinkEnd::ClientDone);
                    },
                    Ok(Err(error)) => {
                        return Err(SpliceFault::mesh(
                            anyhow::Error::new(error).context("relayed downlink write to the mesh"),
                        ));
                    },
                    Err(_elapsed) => {
                        return Err(SpliceFault::stalled_mesh(anyhow::anyhow!(
                            "relayed downlink stalled past the health budget"
                        )));
                    },
                }
                down_bytes.increment(len as u64);
            }
        };

        tokio::pin!(uplink, downlink);
        let mut downlink_ended: Option<Result<DownlinkEnd, SpliceFault>> = None;
        loop {
            tokio::select! {
                result = &mut uplink => {
                    let downlink_end = match downlink_ended {
                        Some(ended) => ended,
                        // The uplink is done, so ask the downlink to stop at its
                        // next read boundary and wait for it rather than
                        // dropping it mid-write. Bounded: its one blocking
                        // operation, the mesh write, is bounded by `budget`.
                        None => {
                            stop.notify_one();
                            downlink.as_mut().await
                        },
                    };
                    break splice_end(result, downlink_end);
                },
                result = &mut downlink, if downlink_ended.is_none() => match result {
                    // The upstream is done, but the edge may still be uploading
                    // a request body, so the uplink keeps running until it ends
                    // too — the same shape the previous join had.
                    Ok(ended) => downlink_ended = Some(Ok(ended)),
                    // The downlink failed, so the whole relay is over: the
                    // uplink is dropped here, and only the byte accounting above
                    // makes that safe. A `ClientDone` is not a failure, so this
                    // arm never carries one.
                    Err(fault) => break SpliceOutcome {
                        end: fault.into_end(),
                        stream_finished: false,
                        observed_intent: CloseIntent::CarrierEnded,
                    },
                },
            }
        }
    };

    // Why the edge ended: "the client is done" and "the carrier ended" want
    // opposite things from the parked upstream. Mostly already known from the
    // downlink pump; otherwise read off the still-open send half before it is
    // closed.
    let intent = resolve_close_intent(&end, observed_intent, &send);
    let reparks = end.reparks(intent);
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

    let error = match end {
        SpliceEnd::Graceful { .. } => None,
        SpliceEnd::Faulted { error, .. } => Some(error),
    };

    if reparks && registry.enabled() {
        // Mirror of the direct path's `transport::tcp::try_park_on_drop`: the
        // client side went away while the upstream is healthy, so the whole
        // bundle goes back under the same id for the next carrier to resume.
        //
        // No `reserve_park` is taken (the direct path needs one only because it
        // awaits a reader harvest between deciding to park and committing): here
        // both halves are already in hand and `park` commits synchronously, so
        // there is no window for a racing resume to miss.
        debug!(
            user = %owner,
            target = %target_display,
            "re-parking a relayed tcp upstream after the mesh carrier ended",
        );
        registry.park(
            session_id,
            Parked::Tcp(ParkedTcp {
                upstream_writer,
                upstream_reader,
                target_display,
                owner,
                protocol,
                user_counters,
                upstream_guard,
                upstream_bytes_acked,
                downlink_ring,
            }),
        );
    } else {
        // Nothing worth parking (the upstream EOF'd or failed, the client said
        // it was done, or resumption is off): half-close so the target sees the
        // end of the request body — a half-close-then-read protocol hangs
        // without it. The upstream guard drops with this scope, releasing the
        // gauge, and both socket halves drop with it.
        debug!(
            user = %owner,
            target = %target_display,
            ?intent,
            "closing a relayed tcp upstream instead of re-parking it",
        );
        let _ = upstream_writer.shutdown().await;
        drop(upstream_reader);
        linger_until_delivered(upstream_writer.as_ref(), budget).await;
    }

    match error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
