//! Home side: accept relayed sessions from edge peers and route each onto
//! the park it resumes.

use super::*;

/// Accepts relayed connections from edge peers until the endpoint closes or the
/// server shuts down. One task per peer connection; one task per relayed
/// session on it.
pub(in crate::server) async fn run_mesh_listener(
    cluster: Arc<ClusterCtx>,
    services: Arc<Services>,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    loop {
        tokio::select! {
            accepted = cluster.endpoint.accept() => {
                match accepted {
                    Some(Ok(conn)) => {
                        let cluster = Arc::clone(&cluster);
                        let services = Arc::clone(&services);
                        tokio::spawn(handle_mesh_connection(conn, cluster, services));
                    },
                    Some(Err(error)) => debug!(?error, "mesh peer connection failed"),
                    None => break, // endpoint closed
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }
    Ok(())
}

/// Serves every relay stream a peer opens on `conn` until it closes.
pub(super) async fn handle_mesh_connection(
    conn: quinn::Connection,
    cluster: Arc<ClusterCtx>,
    services: Arc<Services>,
) {
    // Ends only when the peer closes the connection. A stream that fails on its
    // way in is dropped on its own: the connection is still carrying every relay
    // already accepted on it.
    loop {
        let (header, stream) = match accept_relay(&conn).await {
            Ok(accepted) => accepted,
            Err(AcceptRelayError::Connection(error)) => {
                debug!(?error, "mesh peer connection ended");
                break;
            },
            Err(AcceptRelayError::Stream(error)) => {
                debug!(?error, "dropping an unusable mesh relay stream");
                continue;
            },
        };
        // Bounded resources: one permit per served relay, held for its lifetime.
        // Refusing beyond the cap keeps a degraded peer — one opening streams in
        // a loop — from growing this home's task/socket footprint without bound.
        // A refused edge fails fast and serves its client locally instead.
        let Ok(permit) = Arc::clone(&cluster.relay_permits).try_acquire_owned() else {
            cluster.metrics.record_mesh_relay_rejected("capacity");
            warn!("mesh relayed-session cap reached; refusing a relay stream");
            refuse_relay(stream, CloseReason::Capacity);
            continue;
        };
        let cluster = Arc::clone(&cluster);
        let services = Arc::clone(&services);
        tokio::spawn(async move {
            // Releases the slot when the relay ends, on every path.
            let _permit = permit;
            // One wire version, so no dispatch: `accept_relay` has already
            // refused anything this build cannot parse — including a straggler's
            // retired v4 OPEN — before the stream got here.
            if let Err(error) = serve_relayed(header, stream, &cluster, &services).await {
                debug!(?error, "relayed session ended with error");
            }
        });
    }
}

/// Refuses one relay stream, resetting both halves with `reason` so the edge
/// learns of the refusal on its next read or write instead of waiting out its
/// health budget.
pub(super) fn refuse_relay(stream: MeshStream, reason: CloseReason) {
    let MeshStream { mut send, mut recv } = stream;
    let code = VarInt::from_u32(reason.code());
    let _ = send.reset(code);
    let _ = recv.stop(code);
}

/// Upper bound on how long the home waits for the second-phase USER frame after
/// acking a v5 OPEN.
///
/// The accept loop's relay permit is held for the whole wait, so an acked peer
/// that then withholds the frame would otherwise pin a slot until the QUIC idle
/// timeout — minutes, and one slot per stream it opens. Deliberately the same
/// order as the registry's own `RESERVATION_WAIT` (5 s), which bounds the
/// neighbouring phase-2 `take_for_resume`. On expiry the stream is refused like
/// any other malformed setup.
pub(super) const USER_FRAME_WAIT: Duration = Duration::from_secs(5);

/// Reads the second-phase USER frame off a v5 relay stream.
///
/// Bounded by construction: one length byte, then at most [`MAX_USER_LEN`]
/// bytes. A peer can never drive an unbounded read or allocation here, however
/// large a length it claims — the length is checked before the body is read.
pub(super) async fn read_user_frame(recv: &mut RecvStream) -> Result<UserFrame> {
    let mut len = [0u8; 1];
    recv.read_exact(&mut len)
        .await
        .context("reading the mesh USER frame length")?;
    let claimed = len[0] as usize;
    if claimed > MAX_USER_LEN {
        bail!("mesh USER frame user name too long: {claimed}");
    }
    let mut frame = vec![0u8; 1 + claimed];
    frame[0] = len[0];
    recv.read_exact(&mut frame[1..])
        .await
        .context("reading the mesh USER frame")?;
    UserFrame::parse(&frame)
}

/// A park whose shape agrees with the one the relay was acked for — every shape
/// the v5 home splices. Narrowing [`Parked`] to it right after phase 2 keeps the
/// shape agreement in one `match` instead of one late check per splice.
pub(super) enum SplicableParked {
    Tcp(ParkedTcp),
    SsUdp(ParkedSsUdpStream),
    VlessUdp(ParkedVlessUdpSingle),
    VlessMux(ParkedVlessMux),
}

/// The wire spelling of a park shape, for the ack that tells an edge what this
/// home is holding.
pub(super) fn mesh_shape(shape: ParkShape) -> MeshShape {
    match shape {
        ParkShape::Stream => MeshShape::Stream,
        ParkShape::Datagram => MeshShape::Datagram,
        ParkShape::VlessUdpSingle => MeshShape::VlessUdpSingle,
        ParkShape::VlessMux => MeshShape::VlessMux,
    }
}

/// The shape question this OPEN is asking, or `None` for a combination no edge
/// produces.
///
/// A Shadowsocks OPEN names its splice exactly: SS-TCP and SS-UDP arrive on
/// different paths, so the framing *is* the shape. A VLESS OPEN names nothing —
/// one path multiplexes TCP, UDP and mux and the OPEN precedes the client's
/// first frame — so it asks for any VLESS shape and is told which one this home
/// holds. A VLESS OPEN with datagram framing is the combination that cannot
/// arise: an edge picks the framing before it knows the command, so it always
/// picks `Tcp`.
pub(super) fn park_query(header: &OpenHeader) -> Option<ParkQuery> {
    match (header.framing, header.protocol) {
        (MeshFraming::Tcp, MeshProtocol::Ss) => Some(ParkQuery::Exact(ParkShape::Stream)),
        (MeshFraming::Udp, MeshProtocol::Ss) => Some(ParkQuery::Exact(ParkShape::Datagram)),
        (MeshFraming::Tcp, MeshProtocol::Vless) => Some(ParkQuery::AnyVless),
        (MeshFraming::Udp, MeshProtocol::Vless) => None,
    }
}

/// Serves one relayed session: the two-phase resume hand-off.
///
/// The edge already terminated the client's crypto, so the home is a pure
/// session owner. There is no route lookup (the request path is a local matter
/// of the edge), no decryptor and no encryptor: the mesh carries application
/// plaintext inside the QUIC/TLS tunnel the peers already authenticated to each
/// other with. The retired v4 path that re-ran the whole accept path against a
/// still-encrypted carrier is gone with the wire version that carried it.
///
/// The two phases exist because the edge must decide what to echo in its `101`
/// before it can read the client's first encrypted frame, so it cannot name the
/// user in OPEN. Phase 1 therefore answers the narrower question "is there a
/// park under this id?" and phase 2 does the owner check `take_for_resume` has
/// always done, one round trip later. A refusal in phase 1 reaches the edge
/// *before* the client carrier is upgraded, which is what keeps a failed relay
/// from becoming a black hole.
pub(super) async fn serve_relayed(
    header: OpenHeader,
    mut stream: MeshStream,
    cluster: &ClusterCtx,
    services: &Services,
) -> Result<()> {
    let session_id = SessionId::from_bytes(header.session_id);
    let registry = &services.orphan_registry;
    let Some(query) = park_query(&header) else {
        // A datagram-framed VLESS OPEN: no edge builds one, because the framing
        // is chosen before the command is known. Refuse rather than guess which
        // of the three VLESS shapes was meant.
        cluster.metrics.record_mesh_relay_rejected("bad_setup");
        cluster.metrics.record_mesh_relay_outcome("error", CLOSE_NONE);
        warn!("refusing a relay whose OPEN framing and protocol cannot name a park shape");
        refuse_relay(stream, CloseReason::Abort);
        return Ok(());
    };

    // Phase 1: does a park exist under this id, and is it a shape a splice on
    // this node can serve? The user is not known yet, so the owner check is
    // deliberately deferred; an in-flight park counts as present (see
    // `OrphanRegistry::probe_park`).
    //
    // The shape half of the question is load-bearing, not defensive: phase 2
    // below *consumes* the park before the shape match can reject it, so
    // admitting a mismatched park here would destroy it and leave the client
    // resuming an id that is admitted and destroyed on every attempt.
    //
    // Both refusals look identical on the wire — the edge serves its client a
    // fresh local session either way — and both are ordinary, so neither is a
    // warning. They are counted apart because they mean different things to an
    // operator: `no_session` is a park that expired or never existed, while
    // `park_shape` is a park that no splice reachable from this OPEN carries —
    // an SS-UDP park under a VLESS resume id, or the reverse — which no amount
    // of config will change.
    let shape = match registry.probe_park(session_id, query) {
        ParkProbe::Splicable(Some(shape)) => shape,
        // A park still landing has no shape to report yet. Answer the one the
        // OPEN committed to, and `Stream` when it committed to none — what the
        // ack meant on every build before it could carry a shape at all. The
        // cost is bounded to that window: a VLESS command that disagrees with
        // the answer releases the relay without consuming anything.
        ParkProbe::Splicable(None) => match query {
            ParkQuery::Exact(shape) => shape,
            ParkQuery::AnyVless => ParkShape::Stream,
        },
        ParkProbe::Missing => {
            cluster.metrics.record_mesh_relay_rejected("no_session");
            cluster.metrics.record_mesh_relay_outcome("miss", CLOSE_NONE);
            debug!("no parked session for a relayed resume id; refusing the relay");
            refuse_relay(stream, CloseReason::NoSession);
            return Ok(());
        },
        ParkProbe::OtherShape => {
            cluster.metrics.record_mesh_relay_rejected("park_shape");
            cluster.metrics.record_mesh_relay_outcome("miss", CLOSE_NONE);
            debug!(
                "the parked session under a relayed resume id is not a shape this relay's OPEN \
                 could ever splice; refusing the relay without consuming it",
            );
            refuse_relay(stream, CloseReason::NoSession);
            return Ok(());
        },
    };
    // Admitted so far. The ack releases the edge to upgrade its client carrier
    // and echo continuity, and is the first downlink byte of the stream. It also
    // carries `shape` when the OPEN could not name one — the answer a VLESS edge
    // needs before it can tell, from the command it is about to read, whether
    // this park is one it can use at all.
    if let Err(error) =
        write_open_ack(&mut stream.send, header.committed_shape(), mesh_shape(shape)).await
    {
        // The mesh stream broke during setup, before any park was consulted:
        // neither a hit nor a miss, but still one relay that entered this
        // handler — counted so the outcome series reconciles against the
        // streams actually served.
        cluster.metrics.record_mesh_relay_outcome("error", CLOSE_NONE);
        return Err(error);
    }

    // Phase 2: the user the edge authenticated, then the owner check. Bounded by
    // [`USER_FRAME_WAIT`]: an acked peer that never sends the frame would
    // otherwise hold its relay permit for the QUIC idle timeout.
    let user = match tokio::time::timeout(USER_FRAME_WAIT, read_user_frame(&mut stream.recv)).await
    {
        Ok(Ok(user)) => user,
        Ok(Err(error)) => {
            cluster.metrics.record_mesh_relay_rejected("bad_setup");
            cluster.metrics.record_mesh_relay_outcome("error", CLOSE_NONE);
            debug!(?error, "refusing a v5 relay whose USER frame is unusable");
            refuse_relay(stream, CloseReason::Abort);
            return Ok(());
        },
        Err(_elapsed) => {
            cluster.metrics.record_mesh_relay_rejected("bad_setup");
            cluster.metrics.record_mesh_relay_outcome("error", CLOSE_NONE);
            // "Sent", not "delivered": nothing came back on this arm, so whether
            // the edge ever read the ack is exactly what is unknown — and the
            // refusal below resets the stream, which drops the ack byte if it
            // was still unacked. Either way the edge degrades to a fresh local
            // session, which is what both a reset and a silent home mean to it.
            warn!(
                wait_secs = USER_FRAME_WAIT.as_secs(),
                "refusing a v5 relay: the ack was sent but no USER frame followed",
            );
            refuse_relay(stream, CloseReason::Abort);
            return Ok(());
        },
    };
    // The shape was *advertised* in phase 1, not proven: the park could have
    // expired and been replaced between the two phases, and a peer is free to
    // ignore what it was told. Re-ask before `take_for_resume`, which is the
    // last moment a mismatch can be refused without destroying the park — the
    // invariant the whole two-phase shape hand-off exists to keep.
    //
    // The two ways it can fail are counted apart, exactly as in phase 1 and for
    // the same reason: a park that expired in the window between the phases is
    // an ordinary `no_session`, and only a park that is *there* under a
    // different shape is a `park_shape`. Folding the two together would make an
    // expiry read to an operator as a shape disagreement.
    match registry.probe_park(session_id, ParkQuery::Exact(shape)) {
        ParkProbe::Splicable(_) => {},
        ParkProbe::Missing => {
            cluster.metrics.record_mesh_relay_rejected("no_session");
            cluster.metrics.record_mesh_relay_outcome("miss", CLOSE_NONE);
            debug!(
                "the park under a relayed resume id is gone between the ack and the USER frame; \
                 refusing the relay",
            );
            refuse_relay(stream, CloseReason::NoSession);
            return Ok(());
        },
        ParkProbe::OtherShape => {
            cluster.metrics.record_mesh_relay_rejected("park_shape");
            cluster.metrics.record_mesh_relay_outcome("miss", CLOSE_NONE);
            debug!(
                shape = mesh_shape(shape).label(),
                "the park under a relayed resume id no longer has the shape this relay was acked \
                 for; refusing the relay without consuming it",
            );
            refuse_relay(stream, CloseReason::NoSession);
            return Ok(());
        },
    }
    let parked = match registry.take_for_resume(session_id, &user.user).await {
        ResumeOutcome::Hit(parked) => parked,
        ResumeOutcome::Miss(miss) => {
            let reason = match miss {
                // A park exists but under a different owner. Worth a warning —
                // and the user name is an identifier, not a secret — but the
                // message stops at what is observed, because the causes are not
                // all config: besides a genuine security event and a cluster
                // whose nodes disagree on what a name means, an SS-TCP park is
                // keyed on the *base* user id (`transport::tcp` parks with
                // `user.id_arc()`) while both the direct resume and this
                // attestation use the effective accounting label, so a user with
                // `[users.aliases]` connecting from a matching subnet mismatches
                // here with nothing wrong in the config at all. That is a
                // pre-existing bug in the park key, not something an operator
                // can fix by editing names, so this log must not send them after
                // one.
                ResumeMiss::OwnerMismatch => {
                    warn!(
                        user = %user.user,
                        "relayed resume rejected: the parked session is owned by a different user \
                         name than the edge attested",
                    );
                    "unknown_user"
                },
                // The park expired or was evicted between phase 1 and phase 2.
                _ => "no_session",
            };
            cluster.metrics.record_mesh_relay_rejected(reason);
            cluster.metrics.record_mesh_relay_outcome("miss", CLOSE_NONE);
            refuse_relay(stream, CloseReason::NoSession);
            return Ok(());
        },
    };
    let parked = match (shape, parked) {
        (ParkShape::Stream, Parked::Tcp(parked)) => SplicableParked::Tcp(parked),
        (ParkShape::Datagram, Parked::SsUdpStream(parked)) => SplicableParked::SsUdp(parked),
        (ParkShape::VlessUdpSingle, Parked::VlessUdpSingle(parked)) => {
            SplicableParked::VlessUdp(parked)
        },
        (ParkShape::VlessMux, Parked::VlessMux(parked)) => SplicableParked::VlessMux(parked),
        // The shape this relay was acked for disagrees with what is actually
        // parked under the id. Both probes reject a committed park of the wrong
        // shape, so what is left here is the reservation window — a park that
        // was still landing when phase 1 looked and committed as some other
        // shape by now — or a forged peer.
        //
        // The park is already consumed by the time it can be inspected, so it
        // goes straight back into the registry under the same id: this session
        // cannot be served on *this* relay, but nothing about it is damaged, and
        // a carrier that asks for the right shape can still have it. Re-parking
        // is exact here because the whole `Parked` value is in hand and
        // `OrphanRegistry::park` re-derives the owner from it. Without this the
        // reservation window cost the client its continuity for good — the one
        // way a v5 relay could destroy a park it never spliced.
        (shape, parked) => {
            cluster.metrics.record_mesh_relay_rejected("framing_mismatch");
            cluster.metrics.record_mesh_relay_outcome("miss", CLOSE_NONE);
            warn!(
                acked_shape = mesh_shape(shape).label(),
                parked_kind = parked.kind(),
                "the relayed park shape does not match the parked session kind; aborting the relay \
                 and putting the park back",
            );
            if registry.enabled() {
                registry.park(session_id, parked);
            }
            refuse_relay(stream, CloseReason::Abort);
            return Ok(());
        },
    };
    let parked = match parked {
        SplicableParked::Tcp(parked) => parked,
        SplicableParked::VlessMux(parked) => {
            // A VLESS-mux park is VLESS by construction — only the mux command
            // mints one — and unlike a byte-stream park it cannot cross to an SS
            // carrier however sure we are of the account: the bundle is a map of
            // sub-connections keyed by mux stream id plus a half-decoded mux
            // frame, and SS-over-WS has no multiplex to express any of it.
            // Unreachable through `park_query`, which never hands an SS OPEN
            // this shape, but the splice is the place that would be wrong. The
            // bundle is untouched here, so it goes back whole.
            if header.protocol != MeshProtocol::Vless {
                cluster.metrics.record_mesh_relay_rejected("protocol_mismatch");
                cluster.metrics.record_mesh_relay_outcome("miss", CLOSE_NONE);
                warn!(
                    relayed = header.protocol.label(),
                    "refusing a relayed VLESS-mux resume claimed under another proxy protocol",
                );
                if registry.enabled() {
                    registry.park(session_id, Parked::VlessMux(parked));
                }
                refuse_relay(stream, CloseReason::Abort);
                return Ok(());
            }
            let _relay_active = cluster.metrics.open_mesh_relay();
            return splice_plaintext_vless_mux(
                stream, parked, &header, session_id, cluster, services,
            )
            .await;
        },
        SplicableParked::VlessUdp(parked) => {
            // A VLESS-UDP park is VLESS by construction — nothing else mints one
            // — and it cannot cross either: one connected socket plus a
            // half-decoded 2-byte-length-prefixed frame, against an SS-UDP
            // carrier that is many-target and frames every datagram under its
            // own header. Unreachable through `park_query`, which never hands an
            // SS OPEN this shape, but the splice is the place that would be
            // wrong.
            if header.protocol != MeshProtocol::Vless {
                cluster.metrics.record_mesh_relay_rejected("protocol_mismatch");
                cluster.metrics.record_mesh_relay_outcome("miss", CLOSE_NONE);
                warn!(
                    relayed = header.protocol.label(),
                    "refusing a relayed VLESS-UDP resume claimed under another proxy protocol",
                );
                refuse_relay(stream, CloseReason::Abort);
                return Ok(());
            }
            let _relay_active = cluster.metrics.open_mesh_relay();
            return splice_plaintext_vless_udp(
                stream, parked, &header, session_id, cluster, registry,
            )
            .await;
        },
        SplicableParked::SsUdp(parked) => {
            // An SS-UDP park is Shadowsocks by construction — there is no other
            // way to mint one — and, like the two arms above, it holds framing
            // state a VLESS carrier cannot take over: a set of NAT keys whose
            // responder slots are re-pointed under SS coding, against a
            // single-target VLESS-UDP session. Only the byte-stream splice
            // below crosses protocols.
            if header.protocol != MeshProtocol::Ss {
                cluster.metrics.record_mesh_relay_rejected("protocol_mismatch");
                cluster.metrics.record_mesh_relay_outcome("miss", CLOSE_NONE);
                warn!(
                    relayed = header.protocol.label(),
                    "refusing a relayed SS-UDP resume claimed under another proxy protocol",
                );
                refuse_relay(stream, CloseReason::Abort);
                return Ok(());
            }
            let _relay_active = cluster.metrics.open_mesh_relay();
            return splice_plaintext_udp(
                stream, parked, &header, session_id, &user.user, cluster, services,
            )
            .await;
        },
    };
    // A byte-stream park crosses the proxy-protocol boundary freely, exactly as
    // the two direct paths let it (`transport::tcp` and `transport::vless::tcp`):
    // the mesh body is plaintext, the replay ring is filled ahead of encryption,
    // and everything else in the bundle is a socket half or a counter. The owner
    // check above is what binds the id to an account, and one account is reached
    // over both protocols by construction — a single `[[users]]` entry carries
    // both `password` and `vless_id`. A client rerolling its active wire between
    // an SS and a VLESS one (`shuffle_wires`) lands here on every reroll, which
    // is precisely when the session is worth keeping.
    //
    // The datagram and mux arms above still refuse: those parks hold framing
    // state the other protocol cannot express, not merely a label.
    //
    // Counted on the home, which owns the park — the same node whose
    // `orphan_resume_hit_total` this crossing is a subset of.
    if parked.protocol.label() != header.protocol.label() {
        cluster
            .metrics
            .record_orphan_resume_cross_protocol(parked.protocol.label(), header.protocol.label());
    }
    // The `hit` itself is recorded by the splice on its way out, where the
    // close intent that labels it is finally known; `outline_ss_mesh_relay_active`
    // is what counts the relay while it runs.
    // Count this relay as active for its whole lifetime; the guard drops on
    // return, including every early bail inside the splice.
    let _relay_active = cluster.metrics.open_mesh_relay();
    splice_plaintext_tcp(stream, parked, &header, session_id, cluster, registry).await
}
