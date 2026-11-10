//! Edge side of the mesh relay: open a relay towards the home that owns a
//! session and present it to the accept path as an upstream.

use super::*;

/// The deadline for an OPEN ack: [`OPEN_ACK_WAIT`], never longer than the
/// relay's own progress budget.
pub(super) fn open_ack_wait(relay_budget: Duration) -> Duration {
    relay_budget.min(OPEN_ACK_WAIT)
}

/// Opens a v5 mesh relay to the home for an edge-routed carrier: asks whether a
/// park exists under the client's resume id, and waits for the answer *before*
/// the client carrier is upgraded.
///
/// This is phase 1 of the two-phase OPEN. It carries no user — the edge cannot
/// know one until it has read the client's first encrypted frame, which it
/// cannot do until it has decided what to echo in the `101`. The home therefore
/// answers the narrower question "is there a park under this id?", and the owner
/// check follows one phase later, when the edge sends the USER frame
/// ([`super::upstream_source::MeshUpstreamSetup::attach`]).
///
/// `protocol` is the one thing about the client's crypto the header still
/// carries, and only because the home cannot otherwise apply the cross-protocol
/// rule both direct resume paths enforce: a park authenticated under SS is never
/// handed to a VLESS carrier, or the other way round. Unlike the user, the edge
/// knows it before it reads a single client byte.
///
/// `None` means serve the client locally: the home is unreachable, or it holds
/// no park under this id — an ordinary outcome now that fresh sessions are never
/// created over the mesh. The caller then becomes the home for a fresh session.
///
/// A [`MeshShape`] rides back with the relay: the shape of the park the home
/// actually holds. An SS carrier already knew it (its OPEN named it), but a VLESS
/// one could not — see `cluster::mesh::frame` — and this is where it finds out,
/// early enough to decide between splicing and releasing the relay once the
/// client's command arrives.
pub(in crate::server) async fn open_edge_relay(
    cluster: &ClusterCtx,
    shard: ShardId,
    advert: &EdgeResumeAdvert,
    framing: MeshFraming,
    protocol: MeshProtocol,
    peer_addr: SocketAddr,
) -> Option<(PooledRelay, MeshShape)> {
    let header = OpenHeader {
        framing,
        protocol,
        session_id: *advert.session_id.as_bytes(),
        resume_capable: advert.resume_capable,
        ack_prefix: advert.ack_prefix,
        symmetric_replay: advert.symmetric_replay,
        client_down_acked: advert.down_acked,
        peer_addr: Some(peer_addr),
    };
    let mut pooled = match cluster.pool.open_relay(shard, &header).await {
        Ok(pooled) => pooled,
        Err(error) => {
            cluster.metrics.record_mesh_relay_opened("fail");
            debug!(
                ?error,
                shard = shard.get(),
                "mesh relay open failed; serving a fresh local session",
            );
            return None;
        },
    };
    let shape = match pooled.await_ack(open_ack_wait(cluster.relay_budget)).await {
        Ok(shape) => shape,
        Err(error) => {
            cluster.metrics.record_mesh_relay_opened("refused");
            // Not a warning: with edge-terminated crypto a refusal is the
            // expected answer whenever the home holds no park — every fresh
            // session, and every session whose park has expired. The edge simply
            // serves it.
            debug!(
                ?error,
                shard = shard.get(),
                "home holds no session for this resume id; serving a fresh local session",
            );
            return None;
        },
    };
    cluster.metrics.record_mesh_relay_opened("ok");
    Some((pooled, shape))
}

/// Everything an edge needs to serve a client whose upstream it just took over
/// the mesh: the relay itself, and the response echo that tells the client its
/// session continued.
pub(in crate::server) struct EdgeUpstream {
    /// The upstream the relay must be run with.
    pub(in crate::server) source: UpstreamSource,
    /// Resume state for a relayed session: nothing is resumed *here* and
    /// nothing is parked *here*, but the Ack-Prefix capability still rides
    /// through, because the edge re-emits the home's acked offset to the client.
    pub(in crate::server) resume: ResumeContext,
    /// Headers to apply to the upgrade response.
    pub(in crate::server) echo: ResumeResponseEcho,
}

/// Builds the edge-side pieces of a v5 relayed byte-stream session — SS or
/// VLESS — from an accepted relay.
///
/// Two deliberate choices are encoded here.
///
/// *The session id echoed is the one the client presented*, because the home
/// parks under exactly that id — that is what makes the session survive a node
/// switch at all.
///
/// *The v2 Symmetric Downlink Replay capability is never confirmed*, even when
/// the client advertised it (and the OPEN forwarded that advertisement, so the
/// home does replay the unacked suffix). The home's suffix arrives as
/// undelimited plaintext at the head of the mesh body, and the edge has no way
/// to tell where it ends — so it cannot wrap it in the framed "ORDR" reply a v2
/// client expects, and claiming v2 would make the client misread those bytes as
/// a frame header. Left unconfirmed, the same bytes are exactly what the client
/// is missing, in order, and it consumes them as ordinary stream continuation.
/// Continuity is preserved; only the explicit truncation signal is not.
///
/// `shape` must be the one the home acked. It decides how the body is framed and
/// which transport label the relay's `role="edge"` counters are published under,
/// and it is what makes this one constructor serve the datagram edges (SS-UDP,
/// VLESS-UDP) as well as the byte-stream ones — the resume story is identical on
/// all of them, which is the point.
pub(in crate::server) fn edge_upstream(
    pooled: PooledRelay,
    shape: MeshShape,
    advert: &EdgeResumeAdvert,
    cluster: &ClusterCtx,
    metrics: &Arc<Metrics>,
    registry: &OrphanRegistry,
) -> EdgeUpstream {
    // Same gate `ResumeContext::from_request_headers` applies: with resumption
    // off this node emits no control frames, so it must not claim otherwise.
    let ack_prefix = advert.ack_prefix && registry.enabled();
    EdgeUpstream {
        source: UpstreamSource::Mesh(MeshUpstreamSetup::new(
            pooled,
            advert.ack_prefix,
            cluster.relay_budget,
            shape,
            metrics,
        )),
        resume: ResumeContext {
            // The home owns both halves of resumption for this session: it holds
            // the park and it re-parks on teardown. A `None` here is also the
            // second guard against this edge parking a socket it does not own.
            requested_resume: None,
            issued_session_id: None,
            ack_prefix_requested: ack_prefix,
            symmetric_replay_requested: false,
            client_acked_offset: 0,
        },
        echo: ResumeResponseEcho {
            session_id: Some(advert.session_id),
            ack_prefix,
            symmetric_replay: false,
        },
    }
}

/// The session id a byte-stream edge records and echoes for this carrier.
///
/// `Some(edge)` — the home admitted the relay — yields the id the client
/// presented, because the home parks the upstream under exactly that id; that is
/// what makes the session survive a node switch.
///
/// `None` — not clustered, an own-shard id, or a home that refused — yields the
/// **locally minted** id instead. This node has just become the session's home,
/// so echoing the foreign id back would send the client's next reconnect
/// straight to the home that already refused it, be refused again, and be served
/// locally again: a session that can never resume. The id the client is told
/// must be the id something is actually parked under.
///
/// Every byte-stream entry point resolves its echoed id through here — SS and
/// VLESS alike, over the axum WS upgrade, the h3 extended-CONNECT upgrade (both
/// via [`edge_echo`]) and the XHTTP handlers — so the invariant cannot hold on
/// one carrier and lapse on another.
pub(in crate::server) fn edge_session_id(
    edge: Option<&EdgeUpstream>,
    local: &ResumeContext,
) -> Option<SessionId> {
    match edge {
        Some(edge) => edge.echo.session_id,
        None => local.issued_session_id,
    }
}

/// The full response echo for a byte-stream edge: the relay's own echo when the
/// home admitted it, the local negotiation otherwise.
///
/// The relayed echo is deliberately *not* the local one with a different id: it
/// also withholds the v2 Symmetric Downlink Replay confirmation, which a relayed
/// session cannot honour (see [`edge_upstream`]).
pub(in crate::server) fn edge_echo(
    edge: Option<&EdgeUpstream>,
    local: &ResumeContext,
) -> ResumeResponseEcho {
    match edge {
        Some(edge) => edge.echo,
        None => local.response_echo(),
    }
}

/// The response echo a **datagram** edge answers with: the session id
/// [`edge_session_id`] resolved, and nothing else.
///
/// The v1/v2 capability confirmations are stream features that no SS-UDP path
/// has ever echoed — direct or relayed — so the only thing a relay changes here
/// is *which* id goes back, and that is exactly the thing that must come from
/// the mesh rather than from the request: the id the client is told is the id
/// the home parks under. Every SS-UDP entry point (the axum WS upgrade, the h3
/// extended CONNECT and the XHTTP handlers) resolves its echo through here, so
/// the rule cannot hold on one carrier and lapse on another.
pub(in crate::server) fn edge_udp_echo(
    edge: Option<&EdgeUpstream>,
    local: &ResumeContext,
) -> ResumeResponseEcho {
    ResumeResponseEcho {
        session_id: edge_session_id(edge, local),
        ..Default::default()
    }
}
