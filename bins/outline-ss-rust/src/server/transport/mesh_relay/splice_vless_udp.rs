//! Plaintext VLESS-UDP splice.

use super::*;

/// Splices a relayed plaintext VLESS-UDP session onto the single connected
/// `UdpSocket` it parked.
///
/// The simplest of the three splices, because a single-target VLESS-UDP session
/// *is* one socket: no NAT table, no per-datagram target, no identity to derive.
/// Every mesh datagram goes to the socket's connected peer and every datagram the
/// socket receives comes back — which is also why the edge sends bare payloads
/// and no target address, unlike the SS-UDP splice beside it.
///
/// Boundaries are the whole point, on both hops. The client frames each datagram
/// with VLESS's own `u16` length prefix, the edge de-frames it and writes one
/// mesh datagram per packet ([`write_datagram`]), and this splice does one
/// `send` per datagram. A byte splice anywhere along that chain would let two
/// datagrams coalesce into one `send` and arrive at the target as a single
/// corrupt packet.
///
/// Per-user accounting is deliberately absent, as in the two splices above: it
/// belongs to the node that terminates the client session, which is the edge.
/// The park's `user_counters` ride through untouched so a later *direct* resume
/// on this node keeps counting where it left off.
///
/// Continuity matches the SS-UDP splice: an `ack_prefix` OPEN gets its
/// [`UpstreamAckFrame`] — present exactly when the flag is set, on every framing
/// — reporting `0`, because a datagram session acknowledges no uplink byte
/// offset. `symmetric_replay` has nothing to replay: UDP is lossy by contract and
/// no ring is kept.
///
/// Bounded: one pooled receive buffer per datagram (returned before the next
/// park), a read that caps each mesh datagram at the framing's own maximum, and
/// `cluster.relay_budget` on every mesh write.
pub(super) async fn splice_plaintext_vless_udp(
    stream: MeshStream,
    parked: ParkedVlessUdpSingle,
    header: &OpenHeader,
    session_id: SessionId,
    cluster: &ClusterCtx,
    registry: &OrphanRegistry,
) -> Result<()> {
    let MeshStream { mut send, mut recv } = stream;

    // Uplink continuity, for symmetry with the other splices: the frame is
    // present exactly when the OPEN asked for it, and zero is the truthful
    // answer — a datagram session acknowledges no byte offset.
    //
    // Written before the bundle is taken apart so a failure can hand it back
    // whole: not a datagram has crossed either way, so the socket — and with it
    // the source port the target has been talking to — is worth as much to the
    // next carrier as it was a moment ago. Dropping it here would close it, and
    // a mesh fault the session had no part in would cost it that port.
    if header.ack_prefix {
        let frame = UpstreamAckFrame { upstream_acked: 0 };
        if let Err(error) = send.write_all(&frame.encode()).await {
            cluster.metrics.record_mesh_relay_outcome("hit", CLOSE_NONE);
            if registry.enabled() {
                registry.park(session_id, Parked::VlessUdpSingle(parked));
            }
            return Err(
                anyhow::Error::new(error).context("sending the upstream-ack frame over the mesh")
            );
        }
    }

    // Every field is kept: the splice needs only the socket, but a re-park has
    // to hand the whole bundle back with the same field semantics the direct
    // path parks with. `udp_client_buffer` is the *client*-side reassembly
    // buffer, which on a relayed session lives on the edge — it travels through
    // untouched so a later direct resume finds it where it left it.
    let ParkedVlessUdpSingle {
        socket,
        target_display,
        owner,
        user,
        user_counters,
        udp_client_buffer,
    } = parked;

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
        let socket = socket.as_ref();

        // Uplink: mesh → the parked socket, one datagram per frame. Serial
        // rather than fanned out: the socket is connected, so there is no DNS
        // and no bind to overlap, and `send` on a connected socket does not
        // block long enough to want concurrency.
        let uplink = async move {
            let mut buf = Vec::new();
            loop {
                let len = match read_datagram(recv, &mut buf)
                    .await
                    .context("relayed uplink datagram read from the mesh")
                {
                    // The edge finished the stream: the client carrier is gone.
                    // The socket is deliberately left open — the caller re-parks
                    // it for the next carrier.
                    Ok(None) => return Ok(()),
                    Ok(Some(len)) => len,
                    Err(error) => return Err(SpliceFault::mesh(error)),
                };
                up_bytes.increment(len as u64);
                up_datagrams.increment(1);
                match socket.send(&buf[..len]).await {
                    Ok(sent) if sent == len => {},
                    // A short send is a datagram the target will never see whole;
                    // the socket itself is still usable, so the session goes on.
                    Ok(sent) => {
                        warn!(sent, expected = len, "relayed vless udp short send");
                    },
                    Err(error) => {
                        return Err(SpliceFault::upstream(
                            anyhow::Error::new(error)
                                .context("relayed uplink send on the parked vless udp socket"),
                        ));
                    },
                }
            }
        };

        // Downlink: the parked socket → mesh, one datagram per frame. The ONLY
        // writer to the mesh stream.
        let downlink = async move {
            loop {
                tokio::select! {
                    // Biased so a pending stop wins over one more datagram: the
                    // uplink has ended, and a response written into a stream the
                    // caller is about to close is worth nothing. Both branches
                    // are cancel-safe — a dropped `Notified` hands its
                    // notification back, and `readable` consumes nothing.
                    biased;
                    () = stop.notified() => return Ok(DownlinkEnd::Stopped),
                    ready = socket.readable() => if let Err(error) = ready {
                        return Err(SpliceFault::upstream(
                            anyhow::Error::new(error)
                                .context("awaiting the parked vless udp socket"),
                        ));
                    },
                }
                // Allocate from the pool only once a datagram is ready, so an
                // idle relay holds no per-session receive buffer and the buffer
                // is back in the pool before the next park.
                let mut buffer = UdpRecvBuf::take();
                let len = match socket.try_recv(&mut buffer) {
                    Ok(len) => len,
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => {
                        return Err(SpliceFault::upstream(
                            anyhow::Error::new(error)
                                .context("relayed downlink read from the parked vless udp socket"),
                        ));
                    },
                };
                // A zero-length datagram is dropped rather than relayed, which is
                // exactly what the direct VLESS-UDP reader does with it
                // (`vless_udp::relay_vless_udp_upstream_to_client`). Forwarding it
                // would hand a relayed client an empty VLESS frame that a direct
                // client on the same session never sees — the two paths serve the
                // same socket and must look the same from the client's side.
                if len == 0 {
                    continue;
                }
                match tokio::time::timeout(budget, write_datagram(send, &buffer[..len])).await {
                    Ok(Ok(())) => {},
                    Ok(Err(error)) => {
                        // A `ClientDone` stop lands here as a write failure, the
                        // same signal the other splices read: the client is
                        // finished, so the uplink goes on draining to its FIN
                        // while the downlink stands down.
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

    // Re-park unless the client said it was done or the socket itself failed —
    // the same rule the byte-stream splice applies, and the reason a VLESS-UDP
    // session survives more than one carrier switch. A socket that is gone is
    // worth nothing to the next carrier; dropping it here closes it.
    if end.reparks(intent) && registry.enabled() {
        debug!(
            user = %owner,
            target = %target_display,
            "re-parking a relayed vless udp socket after the mesh carrier ended",
        );
        registry.park(
            session_id,
            Parked::VlessUdpSingle(ParkedVlessUdpSingle {
                socket,
                target_display,
                owner,
                user,
                user_counters,
                udp_client_buffer,
            }),
        );
    } else {
        debug!(
            user = %owner,
            target = %target_display,
            ?intent,
            "closing a relayed vless udp socket instead of re-parking it",
        );
    }

    match end {
        SpliceEnd::Graceful { .. } => Ok(()),
        SpliceEnd::Faulted { error, .. } => Err(error),
    }
}
