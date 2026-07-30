//! Home-side mesh relay: accept relayed sessions from edge peers and splice
//! them onto the parked upstreams this node owns.
//!
//! A relayed session arrives as a QUIC stream carrying an [`OpenHeader`] plus
//! application **plaintext**: the edge terminated the client's crypto, so the
//! home is a pure session owner. [`serve_relayed`] resolves the park behind the
//! relayed resume id and splices onto it directly — no route table, no
//! decryptor, no accept path. There is exactly one wire version; a peer sending
//! anything else is refused by `accept_relay` before it reaches here.
//!
//! Resume: the header's session id is both the requested resume id and the
//! issued id — the home parks under the id the client already holds (there is
//! no HTTP response over the mesh to echo a fresh one). See `docs/CLUSTER.md`.
//!
//! Two signals keep a resumed session whole; the cluster mesh `frame` module
//! documents the layout of both. The home opens a resumed splice with an
//! [`UpstreamAckFrame`] saying how far its upstream socket actually got, and the
//! edge closes one with a [`CloseIntent`] saying whether to expect the client
//! back.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use metrics::Counter;
use outline_wire::cluster::ShardId;
use quinn::{RecvStream, SendStream, VarInt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, warn};

use crate::metrics::{AppProtocol, Metrics, Protocol, Transport};
use crate::server::cluster::ClusterCtx;
use crate::server::cluster::mesh::{
    AcceptRelayError, CloseIntent, CloseReason, MAX_USER_LEN, MeshFraming, MeshProtocol, MeshShape,
    MeshStream, OpenHeader, PooledRelay, UpstreamAckFrame, UserFrame, accept_relay, read_datagram,
    write_datagram, write_open_ack,
};
use crate::server::nat::{NatKey, ResponseSender, UdpResponseCoding, UdpResponseSender};
use crate::server::resumption::downlink_ring::ReplayOutcome;
use crate::server::resumption::{
    OrphanRegistry, ParkProbe, ParkQuery, ParkShape, Parked, ParkedSsUdpStream, ParkedTcp,
    ParkedVlessMux, ParkedVlessUdpSingle, ResumeMiss, ResumeOutcome, SessionId, TcpProtocolContext,
};
use crate::server::shutdown::ShutdownSignal;
use crate::server::state::Services;

use super::super::constants::UDP_MAX_CONCURRENT_RELAY_TASKS;
use super::super::scratch::UdpRecvBuf;
use super::resume_headers::{EdgeResumeAdvert, ResumeContext, ResumeResponseEcho};
use super::udp::{
    StreamNatKeys, UdpDatagramCtx, UdpServerCtx, detach_stream_nat_keys, next_ss_udp_stream_id,
    reattach_parked_nat_keys, relay_socks5_datagram,
};
use super::upstream_source::{MeshUpstreamSetup, UpstreamSource};
use super::vless_mux::{self, MuxAccounting, MuxRouteCtx, MuxServerCtx};

/// Read granularity of the home's plaintext splice, in both directions. Also
/// the size of the single upstream read buffer the splice allocates once per
/// relay — the explicit bound on that buffer.
const MESH_HOME_SPLICE_CHUNK: usize = 64 * 1024;

/// `close` label for a relay outcome that never reached a close: every `miss`
/// and `error`, plus a `hit` whose resume prologue failed before either pump
/// ran. The two closes that *did* happen are named by
/// [`CloseIntent::metric_label`].
const CLOSE_NONE: &str = "none";

/// Ceiling on how long an OPEN ack is waited for, whatever the relay's
/// progress budget is.
///
/// The wait sits in front of the client's `101`, so every foreign-shard
/// reconnect pays it — and a home that is reachable but wedged answers no OPEN
/// at all. Reusing `relay_budget` there would stall each such upgrade for the
/// full progress budget (30 s on some fleet nodes) before falling back to a
/// local session, turning one sick home into a fleet-wide upgrade stall. A setup
/// round trip is a *latency* question, unlike the budget's *progress* one, so it
/// gets its own, much shorter deadline. Still generous next to any real
/// cross-region mesh RTT, and a node whose budget is deliberately tighter keeps
/// its own value (the wait is the smaller of the two).
const OPEN_ACK_WAIT: Duration = Duration::from_secs(3);

/// The deadline for an OPEN ack: [`OPEN_ACK_WAIT`], never longer than the
/// relay's own progress budget.
fn open_ack_wait(relay_budget: Duration) -> Duration {
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
async fn handle_mesh_connection(
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
fn refuse_relay(stream: MeshStream, reason: CloseReason) {
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
const USER_FRAME_WAIT: Duration = Duration::from_secs(5);

/// Reads the second-phase USER frame off a v5 relay stream.
///
/// Bounded by construction: one length byte, then at most [`MAX_USER_LEN`]
/// bytes. A peer can never drive an unbounded read or allocation here, however
/// large a length it claims — the length is checked before the body is read.
async fn read_user_frame(recv: &mut RecvStream) -> Result<UserFrame> {
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

/// Whether a parked TCP session may be spliced onto a relay the edge opened for
/// `relayed`. The mesh carries plaintext, so nothing about the body depends on
/// this — only the invariant that a session stays inside the protocol it was
/// authenticated under.
fn protocol_matches(relayed: MeshProtocol, parked: &TcpProtocolContext) -> bool {
    matches!(
        (relayed, parked),
        (MeshProtocol::Ss, TcpProtocolContext::Ss(_))
            | (MeshProtocol::Vless, TcpProtocolContext::Vless)
    )
}

/// A park whose shape agrees with the one the relay was acked for — every shape
/// the v5 home splices. Narrowing [`Parked`] to it right after phase 2 keeps the
/// shape agreement in one `match` instead of one late check per splice.
enum SplicableParked {
    Tcp(ParkedTcp),
    SsUdp(ParkedSsUdpStream),
    VlessUdp(ParkedVlessUdpSingle),
    VlessMux(ParkedVlessMux),
}

/// The wire spelling of a park shape, for the ack that tells an edge what this
/// home is holding.
fn mesh_shape(shape: ParkShape) -> MeshShape {
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
fn park_query(header: &OpenHeader) -> Option<ParkQuery> {
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
async fn serve_relayed(
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
                // A park exists but under a different owner. Either a genuine
                // security event or the shared-user-namespace invariant broken
                // by config — worth a warning either way, and the user name is
                // an identifier, not a secret.
                ResumeMiss::OwnerMismatch => {
                    warn!(
                        user = %user.user,
                        "relayed resume rejected: the parked session belongs to another user — \
                         check that user names denote the same person on every cluster node",
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
            // mints one — so an SS relay claiming it is the same cross-protocol
            // confusion the arms below refuse. Unreachable through `park_query`,
            // which never hands an SS OPEN this shape, but the splice is the
            // place that would be wrong. The bundle is untouched here, so it
            // goes back whole.
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
            // — so an SS relay claiming it is the same cross-protocol confusion
            // the two arms below refuse. Unreachable through `park_query`, which
            // never hands an SS OPEN this shape, but the splice is the place
            // that would be wrong.
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
            // way to mint one — so a relay claiming VLESS over it is the same
            // cross-protocol confusion the byte-stream arm refuses below.
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
    // Cross-protocol resume, refused exactly as the two direct paths refuse it
    // (`transport::tcp` and `transport::vless::tcp`): an SS-authenticated carrier
    // never reattaches to a park minted under VLESS, or the other way round. The
    // owner check above already binds an id to one user identity, so reaching
    // here means SS and VLESS users share an identifier across the cluster — a
    // configuration error worth surfacing rather than silently splicing a
    // session onto the wrong protocol's carrier.
    //
    // Checked here, after the park is taken, for the same reason the direct
    // paths check it there: the protocol is a property of the *park*, and asking
    // in phase 1 would only narrow the window, not close it (a reservation
    // carries no protocol either). Unlike a UDP- or mux-shaped park — routine
    // now that VLESS multiplexes three shapes onto one id — this is not
    // something a healthy cluster produces, so it does not earn the phase-1
    // lookup that `park_shape` does.
    if !protocol_matches(header.protocol, &parked.protocol_context) {
        cluster.metrics.record_mesh_relay_rejected("protocol_mismatch");
        cluster.metrics.record_mesh_relay_outcome("miss", CLOSE_NONE);
        warn!(
            relayed = header.protocol.label(),
            parked_kind = parked.protocol_context.label(),
            "refusing a relayed resume across proxy protocols — check that user names denote the \
             same person, and the same protocol, on every cluster node",
        );
        refuse_relay(stream, CloseReason::Abort);
        return Ok(());
    }
    // The `hit` itself is recorded by the splice on its way out, where the
    // close intent that labels it is finally known; `outline_ss_mesh_relay_active`
    // is what counts the relay while it runs.
    // Count this relay as active for its whole lifetime; the guard drops on
    // return, including every early bail inside the splice.
    let _relay_active = cluster.metrics.open_mesh_relay();
    splice_plaintext_tcp(stream, parked, &header, session_id, cluster, registry).await
}

/// A failed half of a v5 splice: what the edge must see, and whether the parked
/// upstream survived it.
struct SpliceFault {
    /// Reset code sent on the mesh stream before the splice returns — unless the
    /// downlink pump already finished the stream on upstream EOF, in which case
    /// the caller suppresses it. Without the reset quinn's `Drop for SendStream`
    /// finishes the stream, so the edge would read a stalled home or a broken
    /// upstream as a clean close and seal a truncated response to its client.
    reset: CloseReason,
    /// Whether the parked upstream is still healthy — i.e. whether the session
    /// is worth re-parking for a later carrier.
    upstream_healthy: bool,
    error: anyhow::Error,
}

impl SpliceFault {
    /// The mesh peer failed (read or write): the upstream is untouched, so the
    /// session is re-parked exactly as if the client had simply gone away.
    fn mesh(error: anyhow::Error) -> Self {
        Self {
            reset: CloseReason::Abort,
            upstream_healthy: true,
            error,
        }
    }

    /// The upstream socket failed: a later resume would reattach to a dead
    /// socket, so nothing is parked.
    fn upstream(error: anyhow::Error) -> Self {
        Self {
            reset: CloseReason::Abort,
            upstream_healthy: false,
            error,
        }
    }

    /// An upstream write stalled past the health budget: the socket itself is
    /// not draining, so it is not worth handing to a later carrier.
    fn stalled_upstream(error: anyhow::Error) -> Self {
        Self {
            reset: CloseReason::Budget,
            upstream_healthy: false,
            error,
        }
    }

    /// A mesh write stalled past the health budget: the edge is wedged, but the
    /// parked upstream is fine and worth keeping for the next carrier. The edge
    /// sees [`CloseReason::Budget`] on both stall arms, mirroring what the edge
    /// pump signals to the home.
    fn stalled_mesh(error: anyhow::Error) -> Self {
        Self {
            reset: CloseReason::Budget,
            upstream_healthy: true,
            error,
        }
    }

    fn into_end(self) -> SpliceEnd {
        SpliceEnd::Faulted {
            reset: self.reset,
            upstream_healthy: self.upstream_healthy,
            error: self.error,
        }
    }
}

/// How a v5 splice ended, once both halves are back in the caller's hands.
///
/// One enum rather than a `reset: Option<_>` / `error: Option<_>` pair: a fault
/// always carries both and a graceful end carries neither, so the two mixed
/// combinations the pair could express were never reachable and are now
/// unrepresentable.
enum SpliceEnd {
    /// Neither half failed: the edge finished the mesh stream, or the upstream
    /// EOF'd, or both.
    Graceful { upstream_healthy: bool },
    /// One half failed. The edge is told with `reset` — unless the stream was
    /// already finished on upstream EOF — and the caller returns `error`.
    Faulted {
        reset: CloseReason,
        upstream_healthy: bool,
        error: anyhow::Error,
    },
}

/// What the home does to the mesh send half once a v5 splice ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamClose {
    /// Finish the stream. A no-op when the downlink pump already finished it.
    Finish,
    /// Reset it, so the edge cannot mistake a failed relay for a complete
    /// response.
    Reset(CloseReason),
}

impl SpliceEnd {
    /// How the mesh send half must be closed.
    ///
    /// `stream_finished` — the downlink pump finished the stream on upstream EOF
    /// — overrides everything below. quinn does not reject a reset after a
    /// finish: it drops whatever of the stream is still unacked and queues
    /// RESET_STREAM. Resetting there would hand the edge a **complete** response
    /// as an abort, the mirror image of the truncation the reset exists to
    /// prevent.
    ///
    /// A fault otherwise resets, so the edge cannot read a broken relay as a
    /// clean close.
    ///
    /// A graceful end resets too — with [`CloseReason::Fin`] — when the edge
    /// closed with [`CloseIntent::ClientDone`], because that intent rode a
    /// `STOP_SENDING` on this very half. `finish` on a stopped half is a silent
    /// no-op in quinn, leaving `Drop for SendStream` to reset the stream with
    /// the `STOP_SENDING` code it received: a `CloseIntent` code arriving where
    /// the edge reads a [`CloseReason`], which `CloseReason::from_code` would
    /// then read as `Abort`. An explicit `Fin` reset says the same thing in the
    /// vocabulary resets are parsed in, and drops nothing that was wanted — the
    /// only bytes it abandons are downlink bytes the edge has just asked not to
    /// receive.
    fn stream_close(&self, stream_finished: bool, intent: CloseIntent) -> StreamClose {
        if stream_finished {
            return StreamClose::Finish;
        }
        match self {
            SpliceEnd::Faulted { reset, .. } => StreamClose::Reset(*reset),
            SpliceEnd::Graceful { .. } => match intent {
                CloseIntent::ClientDone => StreamClose::Reset(CloseReason::Fin),
                CloseIntent::CarrierEnded => StreamClose::Finish,
            },
        }
    }

    /// Whether the upstream this splice held is still worth handing to a later
    /// carrier — the health verdict both halves agreed on.
    fn upstream_healthy(&self) -> bool {
        match self {
            SpliceEnd::Graceful { upstream_healthy }
            | SpliceEnd::Faulted { upstream_healthy, .. } => *upstream_healthy,
        }
    }

    /// Whether the session goes back into the registry once the splice ends.
    ///
    /// Two independent questions, and both must say yes. A broken or EOF'd
    /// upstream is never parked, as before. On top of that,
    /// [`CloseIntent::ClientDone`] never parks a *healthy* one either: the
    /// client that owns the session has finished with it, so the park would
    /// never be claimed — it would hold one of the user's `orphan_per_user_cap`
    /// slots until the TTL (where it can evict a park still wanted) while the
    /// target waits for a request-body FIN that never comes. The caller's
    /// non-park path half-closes the upstream, which is exactly what that
    /// client's target is owed.
    fn reparks(&self, intent: CloseIntent) -> bool {
        matches!(intent, CloseIntent::CarrierEnded) && self.upstream_healthy()
    }

    /// Marks the parked upstream unusable whatever else this end says. Used when
    /// the *other* half already found the socket EOF'd or broken: a resume would
    /// reattach to something with nothing left to read.
    fn deny_park(self) -> Self {
        match self {
            SpliceEnd::Graceful { .. } => SpliceEnd::Graceful { upstream_healthy: false },
            SpliceEnd::Faulted { reset, error, .. } => {
                SpliceEnd::Faulted { reset, upstream_healthy: false, error }
            },
        }
    }
}

/// Why the downlink pump stopped, when it stopped without failing.
enum DownlinkEnd {
    /// The upstream EOF'd. The pump finished the mesh stream on its way out, so
    /// the caller must never reset it afterwards.
    UpstreamEof,
    /// The uplink asked the pump to stop and it returned at a read boundary,
    /// with the upstream socket intact.
    Stopped,
    /// The edge stopped the downlink half with [`CloseIntent::ClientDone`],
    /// failing whatever write was in flight. Not a fault: the client is done, so
    /// downlink bytes it will never read are worth nothing, and the upstream
    /// socket is untouched. Distinct from [`DownlinkEnd::Stopped`] because it
    /// arrives *while the uplink is still running* — and the uplink must keep
    /// running, or the tail of the request body still buffered on the mesh would
    /// be dropped instead of reaching the target, which is the very hole the
    /// close intent exists to close.
    ClientDone,
}

/// Writes one relayed uplink chunk to the parked upstream, counting every byte
/// the socket takes *as it takes it*.
///
/// Incremental, rather than one `write_all` followed by a single `fetch_add` for
/// the whole chunk, because this future is dropped where it stands when the
/// downlink faults: `upstream_bytes_acked` must still name exactly the bytes the
/// socket received. A whole-chunk add records nothing for a cancelled partial
/// write, and a later ack-prefix replay from that counter would resend a prefix
/// the target already has.
///
/// `budget` bounds one write, not the chunk: a socket that keeps taking bytes
/// keeps renewing it, and only a socket that stops draining trips it.
async fn write_uplink_chunk<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    chunk: &[u8],
    budget: Duration,
    up_bytes: &Counter,
    acked: &AtomicU64,
) -> Result<(), SpliceFault> {
    let mut written = 0usize;
    while written < chunk.len() {
        match tokio::time::timeout(budget, writer.write(&chunk[written..])).await {
            // A socket that takes nothing is not going to take the rest either;
            // looping on it would spin.
            Ok(Ok(0)) => {
                return Err(SpliceFault::upstream(anyhow::anyhow!(
                    "relayed uplink write to the upstream accepted no bytes"
                )));
            },
            Ok(Ok(n)) => {
                written += n;
                up_bytes.increment(n as u64);
                // Keeps the Ack-Prefix counter monotonic across this reattach,
                // the same guarantee the direct relay gives.
                acked.fetch_add(n as u64, Ordering::Relaxed);
            },
            Ok(Err(error)) => {
                return Err(SpliceFault::upstream(
                    anyhow::Error::new(error).context("relayed uplink write to the upstream"),
                ));
            },
            Err(_elapsed) => {
                return Err(SpliceFault::stalled_upstream(anyhow::anyhow!(
                    "relayed uplink stalled past the health budget"
                )));
            },
        }
    }
    Ok(())
}

/// Everything the end-of-splice decisions need once both pumps are back in the
/// caller's hands.
struct SpliceOutcome {
    /// How the splice ended, and whether the upstream survived it.
    end: SpliceEnd,
    /// The downlink pump finished the mesh stream on upstream EOF, so the
    /// caller must never reset it afterwards.
    stream_finished: bool,
    /// The [`CloseIntent`] the pumps actually observed on the wire. Only a
    /// downlink write that failed with `STOP_SENDING(ClientDone)` proves the
    /// client is finished; anything else is [`CloseIntent::CarrierEnded`] until
    /// the stream itself says otherwise (see [`resolve_close_intent`]).
    observed_intent: CloseIntent,
}

/// Whether the end-of-splice decision still has to ask the stream for the close
/// intent, or whether the pumps have already settled it.
///
/// Answering "no" wherever possible is not an optimisation. quinn's
/// `SendStream::stopped()` inserts a per-stream `Arc<Notify>` into the
/// connection's `stopped` map the first time it polls `Pending`, and dropping
/// the future does not take it back out: the entry is reaped only by
/// `StreamEvent::Finished` (all data plus the FIN acked), `StreamEvent::Stopped`
/// or the connection dying. A **reset** stream produces none of those, so a poll
/// on a relay that is about to be reset would strand one entry for the whole
/// life of a pooled — and therefore long-lived — mesh connection, once per
/// faulted relay.
///
/// So the poll is confined to the single end where it is both needed and reaped:
///
/// * The pumps saw the intent already — nothing left to ask.
/// * The upstream is not healthy — [`SpliceEnd::reparks`] is `false` whatever
///   the intent says, and this is also the end where the downlink pump has
///   already finished the send half, which is the state
///   `SendStream::stopped()` must not be asked about.
/// * The splice faulted — the send half is about to be reset, so an entry
///   inserted here would never be reaped. Nothing is lost: a `ClientDone` that
///   lands on an in-flight downlink write is reported by the pump itself, and
///   one that lands on a *faulted* relay only costs a park that expires on its
///   TTL, which is exactly the documented fallback for a missing code.
///
/// What remains is the bare-FIN carrier switch with a healthy upstream — the
/// case the intent exists to distinguish — where the send half is finished, its
/// FIN is acked, and quinn reaps the entry.
fn needs_stopped_poll(end: &SpliceEnd, observed: CloseIntent) -> bool {
    observed == CloseIntent::CarrierEnded
        && matches!(end, SpliceEnd::Graceful { upstream_healthy: true })
}

/// Reads the [`CloseIntent`] the edge attached to a v5 stream, without waiting
/// for one to arrive.
///
/// The intent rides the `STOP_SENDING` the edge applies to this send half, which
/// it emits together with the FIN on the other half — so by the time the home
/// has seen the FIN, the code is already in quinn's stream state and a single
/// poll observes it. Polling instead of awaiting is deliberate: an edge that
/// merely switched carriers sends no `STOP_SENDING` at all, and awaiting one
/// would delay every re-park by however long the wait was, holding the session
/// out of the registry exactly while the next carrier is trying to resume it.
///
/// Missing the code (a lost or reordered packet) yields
/// [`CloseIntent::CarrierEnded`], the pre-v5 behaviour: the session is re-parked
/// and expires on its TTL. Nothing is lost that way — only reclaimed late.
///
/// Only [`resolve_close_intent`] may call this, and only where
/// [`needs_stopped_poll`] says so: the send half must still be open (quinn
/// reports a closed stream as un-stopped) and must be headed for a `finish`,
/// which is what reaps the map entry the poll leaves behind.
fn poll_close_intent(send: &SendStream) -> CloseIntent {
    let stopped = send.stopped();
    let mut stopped = std::pin::pin!(stopped);
    // A no-op waker is right here and nowhere else: this future is polled once
    // and dropped, so there is no later wakeup to deliver.
    let mut cx = TaskContext::from_waker(Waker::noop());
    match stopped.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(Some(code))) => CloseIntent::from_code(code.into_inner()),
        Poll::Ready(_) | Poll::Pending => CloseIntent::CarrierEnded,
    }
}

/// Why the edge ended, from whichever source can still know it.
///
/// The downlink pump observes a `ClientDone` directly whenever the intent lands
/// on an in-flight write — the same `STOP_SENDING`, seen as
/// `WriteError::Stopped`. One that lands while the downlink sits idle in its
/// upstream read leaves no trace there, and that one case is what the stream
/// poll is for.
fn resolve_close_intent(end: &SpliceEnd, observed: CloseIntent, send: &SendStream) -> CloseIntent {
    if needs_stopped_poll(end, observed) {
        poll_close_intent(send)
    } else {
        observed
    }
}

/// Merges the two halves' verdicts once both have ended.
///
/// The uplink decides what the edge sees — it is the half that ended first and
/// stopped the other — but the park decision is the AND of both: an upstream
/// that either half found EOF'd or broken must never be handed to a later
/// carrier.
fn splice_end(
    uplink: Result<(), SpliceFault>,
    downlink: Result<DownlinkEnd, SpliceFault>,
) -> SpliceOutcome {
    let stream_finished = matches!(downlink, Ok(DownlinkEnd::UpstreamEof));
    let observed_intent = match &downlink {
        Ok(DownlinkEnd::ClientDone) => CloseIntent::ClientDone,
        _ => CloseIntent::CarrierEnded,
    };
    let downlink_healthy = match &downlink {
        Ok(DownlinkEnd::Stopped | DownlinkEnd::ClientDone) => true,
        Ok(DownlinkEnd::UpstreamEof) => false,
        Err(fault) => fault.upstream_healthy,
    };
    let end = match uplink {
        Ok(()) => match downlink {
            Ok(_) => SpliceEnd::Graceful { upstream_healthy: true },
            // The uplink ended cleanly but the downlink failed on its way out;
            // the edge must still be told, so the fault wins.
            Err(fault) => fault.into_end(),
        },
        Err(fault) => fault.into_end(),
    };
    SpliceOutcome {
        end: if downlink_healthy { end } else { end.deny_park() },
        stream_finished,
        observed_intent,
    }
}

/// Splices a relayed plaintext stream onto a parked TCP upstream.
///
/// Simpler than the v4 path beside it: no decryptor, no encryptor, no route
/// context — just the unacked replay suffix followed by a bidirectional pump.
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
///   as a reset code (see [`SpliceEnd::stream_close`]).
/// * **The hand-off loses no bytes.** Because the session is re-parked, a pump
///   dropped mid-operation would silently punch a hole in the client's stream.
///   The downlink is therefore stopped cooperatively at a read boundary (as the
///   direct path's `relay_cancel` does) instead of being cancelled inside a
///   write, and the uplink accounts for every byte the socket took as it takes
///   them, so `upstream_bytes_acked` is exact at any cancellation point.
async fn splice_plaintext_tcp(
    stream: MeshStream,
    parked: ParkedTcp,
    header: &OpenHeader,
    session_id: SessionId,
    cluster: &ClusterCtx,
    registry: &OrphanRegistry,
) -> Result<()> {
    let MeshStream { mut send, mut recv } = stream;
    // Every field is kept: the plaintext splice itself needs only the socket
    // halves and the ring, but a re-park has to hand the whole bundle back to
    // the registry with the same field semantics the direct path parks with.
    // The user is already authenticated (by the edge, attested in the USER
    // frame) and the owner check is done, so neither the identity nor the SS
    // user key does any work *here* — `owner` still keys the park and
    // `protocol_context` still guards a later cross-protocol resume.
    let ParkedTcp {
        mut upstream_writer,
        mut upstream_reader,
        target_display,
        owner,
        protocol_context,
        // Per-user byte accounting stays with the node that terminates the
        // client session, i.e. the edge; the home counts this traffic on its
        // `role="home"` mesh counters below.
        user_counters,
        upstream_guard,
        upstream_bytes_acked,
        downlink_ring,
    } = parked;

    let up_bytes = cluster.metrics.mesh_bytes_counter("home", "up", "tcp");
    let down_bytes = cluster.metrics.mesh_bytes_counter("home", "down", "tcp");
    let budget = cluster.relay_budget;

    // Uplink continuity: how far the upstream socket actually got before this
    // carrier. The home may have consumed uplink bytes off a dying mesh carrier
    // that the socket never took, so without this the resuming edge would either
    // skip them (a hole in the request body at the target) or resend from zero.
    // First on the wire, ahead of the replay suffix and of any fresh byte —
    // the same order the direct path emits its v1 frame before the v2 "ORDR" one.
    if header.ack_prefix {
        let frame = UpstreamAckFrame {
            upstream_acked: upstream_bytes_acked.load(Ordering::Relaxed),
        };
        if let Err(error) = send.write_all(&frame.encode()).await {
            // The park was taken, so this stream is a `hit` however it ends —
            // but it ended before either pump ran, so there is no close to
            // label it with.
            cluster.metrics.record_mesh_relay_outcome("hit", CLOSE_NONE);
            return Err(
                anyhow::Error::new(error).context("sending the upstream-ack frame over the mesh")
            );
        }
    }

    // Byte-continuity: everything the session emitted past the offset the client
    // acknowledged goes out first, ahead of any fresh upstream byte, so the
    // client's stream has no gap and no duplicate across the carrier switch.
    if header.symmetric_replay
        && let Some(ring) = &downlink_ring
    {
        let outcome = ring.lock().replay_from(header.client_down_acked);
        match outcome {
            ReplayOutcome::Available(bytes) if !bytes.is_empty() => {
                if let Err(error) = send.write_all(&bytes).await {
                    // As above: a `hit` that never reached a close.
                    cluster.metrics.record_mesh_relay_outcome("hit", CLOSE_NONE);
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
            // exists the condition is at least observable on the same counter
            // the direct path feeds.
            other => {
                cluster.metrics.record_orphan_downlink_replay_truncated("tcp");
                debug!(
                    ?other,
                    target = %target_display,
                    "no replayable downlink suffix for a relayed resume; the client is not yet \
                     told about the gap",
                );
            },
        }
    }

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
                protocol_context,
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
    }

    match error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

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
struct RelayedUdpIdentity {
    user_id: Arc<str>,
    fwmark: Option<u32>,
    scope: Option<crate::server::nat::NatScope>,
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
    fn from_park(parked: &ParkedSsUdpStream, user: &str) -> Option<(Self, Vec<NatKey>, usize)> {
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
    fn owns(&self, key: &NatKey) -> bool {
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
/// No carrier padding and no throttle monitor, unlike the v4
/// `MeshUdpResponseSender` beside it: with the client's crypto terminated on the
/// edge, the carrier the client actually reads is the edge's, so padding and
/// last-mile throttle detection belong there and applying them here would pad
/// bytes the client never sees in that form.
struct RelayedUdpSender {
    tx: mpsc::Sender<Bytes>,
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
const RELAYED_PATH: &str = "mesh";

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
async fn splice_plaintext_udp(
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
        cluster.metrics.record_mesh_relay_outcome("miss", CLOSE_NONE);
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
            release_relayed_udp(&server, stream_id, &nat_keys);
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
async fn splice_plaintext_vless_udp(
    stream: MeshStream,
    parked: ParkedVlessUdpSingle,
    header: &OpenHeader,
    session_id: SessionId,
    cluster: &ClusterCtx,
    registry: &OrphanRegistry,
) -> Result<()> {
    let MeshStream { mut send, mut recv } = stream;
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

    // Uplink continuity, for symmetry with the other splices: the frame is
    // present exactly when the OPEN asked for it, and zero is the truthful
    // answer — a datagram session acknowledges no byte offset.
    if header.ack_prefix {
        let frame = UpstreamAckFrame { upstream_acked: 0 };
        if let Err(error) = send.write_all(&frame.encode()).await {
            cluster.metrics.record_mesh_relay_outcome("hit", CLOSE_NONE);
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

/// Splices a relayed plaintext VLESS-mux session onto the bundle of
/// sub-connections it parked.
///
/// # What crosses the mesh
///
/// The client's own **mux frame stream**, verbatim, as a transparent byte
/// stream. The edge terminates the client's carrier and the VLESS request
/// header, but it does not parse mux frames — so the body arriving here is
/// exactly what the client emitted, and this node is the mux endpoint. Nothing
/// needs a mesh-level delimiter: a mux frame carries its own length prefix, and
/// a UDP sub-connection's datagram boundary is the frame boundary (one `Keep`
/// frame is one datagram, target included), so the atomicity that
/// [`super::super::cluster::mesh::datagram`] framing exists to protect is
/// already on the wire. See the `cluster::mesh::frame` module doc for what was
/// rejected.
///
/// # How each sub-connection re-attaches
///
/// It does not move. [`vless_mux::attach_parked`] re-spawns one reader task per
/// parked sub-connection against this splice's downlink channel instead of a
/// WebSocket writer — a TCP sub-connection keeps its `OwnedWriteHalf` and gets
/// its `OwnedReadHalf` back, a UDP one keeps its `Arc<UdpSocket>` and its
/// `default_target` — so not one upstream socket is reopened and every source
/// port survives the node switch. The mux's half-decoded inbound frame rides
/// through in `MuxState::buffer`.
///
/// Sub-connections opened *inside* a relayed mux are therefore dialled from
/// **this** node, not the edge: the mux frame layer runs here, so `New` frames
/// reach `open_tcp_sub` / `open_udp_sub` with this node's DNS cache and outbound
/// settings, under the fwmark of the `VlessUser` the park carries. That is the
/// same rule every other relayed shape follows — the home owns the session's
/// upstreams — and the alternative would split one mux bundle across two nodes,
/// leaving nothing either of them could park.
///
/// # Whole or nothing
///
/// A mux park is one session, not a bag of sockets: `Parked::VlessMux` is a
/// single registry entry and the client addresses every sub-connection in it by
/// id. So the bundle is admitted whole or refused whole. The one precondition —
/// it still holds a sub-connection — is checked **before** `attach_parked`, and
/// a bundle that fails it is refused with nothing consumed from it;
/// `attach_parked` is total below that point, so no partial attach exists to
/// guard against.
///
/// # Accounting
///
/// Per-user bytes are counted on the edge, once, exactly as in the three
/// splices above — here through [`MuxAccounting::OnTheEdge`], which silences the
/// per-sub-connection counters the direct mux path uses. The park's
/// `user_counters` ride through untouched so a later *direct* resume on this
/// node keeps counting where it left off.
///
/// # Continuity
///
/// An `ack_prefix` OPEN gets its [`UpstreamAckFrame`] — present exactly when the
/// flag is set, on every shape — reporting `0`: a mux session has no single
/// uplink byte offset to be short of, its upstreams being many sockets behind a
/// frame layer. The edge emits no client-facing Ack-Prefix frame for a mux
/// either, matching the direct mux path, which has never emitted one.
/// `symmetric_replay` likewise has nothing to replay: no mux path keeps a
/// downlink ring.
///
/// Which is why a **downlink fault refuses the park** here, where the byte-stream
/// splice keeps it: with nothing to replay from, a bundle whose uplink was
/// cancelled mid-frame cannot be handed on as continuable. See the `deny_park` on
/// the downlink-fault arm below.
async fn splice_plaintext_vless_mux(
    stream: MeshStream,
    parked: ParkedVlessMux,
    header: &OpenHeader,
    session_id: SessionId,
    cluster: &ClusterCtx,
    services: &Services,
) -> Result<()> {
    let MeshStream { mut send, mut recv } = stream;
    let registry = &services.orphan_registry;
    let vless = &services.vless_server;
    let owner = Arc::clone(&parked.owner);

    // Whole or nothing, checked before anything is attached. An empty bundle is
    // the one state a park can reach that no splice can serve — `harvest_into_parked`
    // prunes sub-connections whose reader already exited — and it is worth
    // nothing to a later carrier either, so it is dropped rather than put back
    // (the direct park path refuses to create one for the same reason, see
    // `MuxState::is_parkable`).
    if parked.sub_conns.is_empty() {
        cluster.metrics.record_mesh_relay_rejected("park_incomplete");
        cluster.metrics.record_mesh_relay_outcome("miss", CLOSE_NONE);
        warn!(
            user = %owner,
            "refusing a relayed VLESS-mux resume: the parked bundle holds no sub-connection to \
             re-attach",
        );
        refuse_relay(MeshStream { send, recv }, CloseReason::Abort);
        return Ok(());
    }

    // Uplink continuity, for symmetry with the other splices: present exactly
    // when the OPEN asked for it, and zero is the truthful answer. The bundle is
    // still untouched if this fails, so it goes back whole.
    if header.ack_prefix {
        let frame = UpstreamAckFrame { upstream_acked: 0 };
        if let Err(error) = send.write_all(&frame.encode()).await {
            cluster.metrics.record_mesh_relay_outcome("hit", CLOSE_NONE);
            if registry.enabled() {
                registry.park(session_id, Parked::VlessMux(parked));
            }
            return Err(
                anyhow::Error::new(error).context("sending the upstream-ack frame over the mesh")
            );
        }
    }

    // The mux frame layer runs here, so it needs this node's outbound context —
    // the same one the direct VLESS path hands it. `Protocol::Http3` and the
    // `mesh` path label stand in for the client-facing carrier the home does not
    // have; neither reaches a per-user series, because this mux does not count.
    let mux_server = MuxServerCtx {
        dns_cache: Arc::clone(&vless.dns_cache),
        prefer_ipv4_upstream: vless.prefer_ipv4_upstream,
        outbound_ipv6: vless.outbound_ipv6.clone(),
        metrics: Arc::clone(&vless.metrics),
    };
    let mux_route = MuxRouteCtx {
        protocol: Protocol::Http3,
        path: Arc::from(RELAYED_PATH),
    };
    // Bounded, like every other downlink fan-in on this node: the sub-connection
    // readers block on a full channel instead of growing it.
    let (tx, mut downlink_rx) = mpsc::channel::<Bytes>(vless.ws_data_channel_capacity);
    let mut mux = vless_mux::attach_parked(
        parked,
        tx.clone(),
        std::convert::identity,
        &vless.metrics,
        Protocol::Http3,
        MuxAccounting::OnTheEdge,
    );

    let up_bytes = cluster.metrics.mesh_bytes_counter("home", "up", "tcp");
    let down_bytes = cluster.metrics.mesh_bytes_counter("home", "down", "tcp");
    let budget = cluster.relay_budget;
    let stop_downlink = Notify::new();

    let SpliceOutcome { end, stream_finished, observed_intent } = {
        let recv = &mut recv;
        let send = &mut send;
        let stop = &stop_downlink;
        let mux = &mut mux;
        let tx = &tx;
        let mux_server = &mux_server;
        let mux_route = &mux_route;
        let downlink_rx = &mut downlink_rx;

        // Uplink: mesh → the mux frame layer. Chunk boundaries are irrelevant —
        // `handle_client_bytes` buffers a partial frame and that buffer is what
        // a re-park hands on.
        let uplink = async move {
            loop {
                let chunk = match recv
                    .read_chunk(MESH_HOME_SPLICE_CHUNK, true)
                    .await
                    .context("relayed uplink read from the mesh")
                {
                    Ok(Some(chunk)) => chunk,
                    // The edge finished the stream: the client carrier is gone.
                    // Every sub-connection is deliberately left running — the
                    // caller harvests and re-parks the whole bundle.
                    Ok(None) => return Ok(()),
                    Err(error) => return Err(SpliceFault::mesh(error)),
                };
                up_bytes.increment(chunk.bytes.len() as u64);
                if let Err(error) = vless_mux::handle_client_bytes(
                    mux,
                    &chunk.bytes,
                    mux_server,
                    mux_route,
                    tx,
                    std::convert::identity,
                )
                .await
                {
                    // A malformed frame stream, or a downlink channel that is
                    // gone: the mux's frame buffer is desynchronised either way,
                    // so the bundle is not worth handing to a later carrier.
                    return Err(SpliceFault::upstream(
                        error.context("relaying vless mux frames from the mesh"),
                    ));
                }
            }
        };

        // Downlink: the sub-connections' frames → mesh. The ONLY writer to the
        // mesh stream. Frames go out whole, but need no mesh-level delimiter:
        // each already carries its own length prefix.
        let downlink = async move {
            loop {
                let frame = tokio::select! {
                    // Biased so a pending stop wins over one more frame: the
                    // uplink has ended, and a frame written into a stream the
                    // caller is about to close is worth nothing. Both branches
                    // are cancel-safe.
                    biased;
                    () = stop.notified() => return Ok(DownlinkEnd::Stopped),
                    // Never `None`: this scope's `tx` keeps a sender alive.
                    Some(frame) = downlink_rx.recv() => frame,
                    else => return Ok(DownlinkEnd::Stopped),
                };
                let len = frame.len();
                match tokio::time::timeout(budget, send.write_all(&frame)).await {
                    Ok(Ok(())) => {},
                    // A `ClientDone` stop lands here as a write failure, the same
                    // signal the other splices read: the client is finished, so
                    // the uplink goes on draining to its FIN while the downlink
                    // stands down.
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
                    // The uplink is done, so the downlink stops at a frame
                    // boundary and is awaited rather than dropped — and because
                    // the uplink has already returned, a fault it reports here
                    // cancels nothing and may still hand the bundle on.
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
                    // The downlink failed, so the whole relay is over and the
                    // uplink is dropped where it stands. `deny_park` is what
                    // makes that safe here — and it is deliberately **not** the
                    // trade `splice_plaintext_tcp` makes on the identical arm.
                    //
                    // That splice keeps its upstream across the very same
                    // cancellation because `write_uplink_chunk` credits
                    // `upstream_bytes_acked` byte by byte as the socket takes
                    // them, so the next carrier replays exactly the hole the
                    // cancellation left. A mux has none of that compensation:
                    // `upstream_acked` is `0` by construction, there is no
                    // downlink ring, and no client-facing Ack-Prefix frame is
                    // ever emitted. The cancelled uplink can be suspended inside
                    // a sub-connection's `write_all` — a partial application
                    // payload already handed to a TCP socket, its frame already
                    // removed from `MuxState::buffer` — or inside `open_tcp_sub`,
                    // losing a `New` frame so that sub-connection id would answer
                    // nothing for the rest of the session. Neither leaves a trace
                    // in the bundle that would be handed on.
                    //
                    // So a bundle whose uplink was cancelled at an unknown point
                    // is exactly as untrustworthy as the desynchronised frame
                    // buffer `SpliceFault::upstream` already refuses to park, and
                    // is refused the same way: the client re-establishes its mux
                    // instead of resuming one with a silent hole in it. Stopping
                    // the uplink cooperatively at a frame boundary — the shape
                    // the downlink uses — was the alternative, and it would have
                    // to wait on a sub-connection write that carries no budget
                    // while draining a downlink channel whose pump is already
                    // gone: a rare lost bundle traded for a relay that can hang.
                    Err(fault) => break SpliceOutcome {
                        end: fault.into_end().deny_park(),
                        stream_finished: false,
                        observed_intent: CloseIntent::CarrierEnded,
                    },
                },
            }
        }
    };

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

    if reparks && registry.enabled() {
        // Harvest and re-park the whole bundle, mirroring the direct path's
        // `try_park_vless_mux`, so a mux session survives more than one carrier
        // switch.
        //
        // The drain is load-bearing, not tidiness: `harvest_into_parked` awaits
        // each reader task after asking it to stop, and a reader blocked on a
        // full downlink channel only reaches its cancel arm once that send
        // completes. The direct path is safe because its WebSocket writer keeps
        // draining through the harvest; here the downlink pump has already
        // stopped, so the harvest has to drain the channel itself or deadlock.
        // The frames it discards are ones the carrier that is already gone would
        // never have carried.
        let parked = {
            let harvest = mux.harvest_into_parked(Arc::clone(&owner));
            tokio::pin!(harvest);
            loop {
                tokio::select! {
                    parked = &mut harvest => break parked,
                    _ = downlink_rx.recv() => {},
                }
            }
        };
        if parked.sub_conns.is_empty() {
            debug!(
                user = %owner,
                "not re-parking a relayed vless mux: no sub-connection survived the harvest",
            );
        } else {
            debug!(
                user = %owner,
                sub_conns = parked.sub_conns.len(),
                "re-parking a relayed vless mux after the mesh carrier ended",
            );
            registry.park(session_id, Parked::VlessMux(parked));
        }
    } else {
        // Nothing worth parking (the frame stream broke, the client said it was
        // done, or resumption is off): half-close every TCP sub-connection so its
        // target sees the end of the request body, and drop the rest.
        debug!(user = %owner, ?intent, "closing a relayed vless mux instead of re-parking it");
        mux.shutdown().await;
    }

    match end {
        SpliceEnd::Graceful { .. } => Ok(()),
        SpliceEnd::Faulted { error, .. } => Err(error),
    }
}

/// Detaches a relayed SS-UDP session's response sender from every NAT entry it
/// still owns, and hands back the keys that were still its own.
fn release_relayed_udp(
    server: &UdpServerCtx,
    stream_id: u64,
    nat_keys: &parking_lot::Mutex<StreamNatKeys>,
) -> Vec<NatKey> {
    let keys = nat_keys.lock().take();
    detach_stream_nat_keys(&server.nat_table, stream_id, keys)
}

#[cfg(test)]
#[path = "tests/mesh_relay.rs"]
mod tests;
