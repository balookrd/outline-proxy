//! Mesh stream framing.
//!
//! Each relayed session is one QUIC bidirectional stream. The stream opens with
//! a single [`OpenHeader`] — the metadata the home needs to find the park the
//! edge is resuming — after which application **plaintext** flows through in
//! both directions: the edge terminates the client's crypto, so the home never
//! decrypts anything and needs no request path (routing and padding are a local
//! matter of the edge). Only [`MeshFraming`] says how the body is delimited, and
//! [`MeshProtocol`] says which protocol's park may be spliced onto it; the user
//! arrives in a second-phase [`UserFrame`], and the park's [`MeshShape`] — which
//! a VLESS carrier cannot state in its OPEN — comes back in the home's ack.
//!
//! The body framing depends on [`MeshFraming`]: `Tcp` relays as a transparent
//! byte stream (chunk boundaries are irrelevant; the QUIC stream *is* the
//! channel, there is no per-chunk data frame), whereas `Udp` frames each
//! datagram as `u32 BE length | payload` because a UDP packet is atomic — an
//! SS-UDP one decrypts as garbage if it is coalesced or split, and a VLESS-UDP
//! one reaches the target as a corrupt packet — see [`super::datagram`]. The stream closes
//! with a QUIC `finish` (graceful) or `reset` whose error code is a
//! [`CloseReason`].
//!
//! # Stream layout
//!
//! A stream is a fixed setup sequence followed by the relayed body, and each
//! element sits at a position both peers can compute from what they have
//! already exchanged — there is no in-band framing over the body, so nothing
//! may be inserted once it starts:
//!
//! ```text
//! edge → home:  OPEN                            length-prefixed OpenHeader
//! home → edge:  ack(1)                          OPEN_ACK_ACCEPTED, or the
//!                                               park's MeshShape when the OPEN
//!                                               committed to none
//! edge → home:  USER                            UserFrame
//! home → edge:  UPSTREAM-ACK(8)                 iff OPEN set the ACK-PREFIX flag
//! home → edge:  [downlink replay suffix]        iff OPEN set SYMMETRIC-REPLAY
//! both ways:    body …                          plaintext, framed per MeshShape
//! ```
//!
//! # Who names the park shape, and when
//!
//! A relay must agree on the shape of the park it splices — a byte-stream
//! upstream, an SS-UDP NAT identity, a single-target VLESS-UDP socket — because
//! the shape is also the body framing, and because a home that consumed the
//! wrong shape has destroyed a session nobody can get back.
//!
//! For a Shadowsocks carrier the edge knows the answer before it speaks: SS-TCP
//! and SS-UDP arrive on different paths. The OPEN's [`MeshFraming`] says which,
//! and the home checks it against the park before it consumes anything.
//!
//! A **VLESS** carrier cannot: one path multiplexes `Tcp`, `Udp` and `Mux`, and
//! the command rides the client's *first frame* — which the edge may only read
//! after it has answered the upgrade, which it may only answer after the OPEN
//! has been acked. So every VLESS OPEN is byte-identical whatever the session
//! turns out to be, and the shape has to be settled later. Three ways were
//! weighed:
//!
//! * **Have the edge re-open** a second relay once it knows. Costs a mesh round
//!   trip in front of the first payload byte and a second relay slot on both
//!   nodes, for a question that is already answered on the home when the first
//!   OPEN lands.
//! * **Have the edge name the shape in phase 2**, alongside the [`UserFrame`].
//!   Costs nothing on the wire, but arrives too late to be *useful*: by then the
//!   edge has already upgraded its client and echoed the home's resume id, so a
//!   home that answers "wrong shape" leaves it with a client it can only fail —
//!   and a client that reconnects with the same id and fails again.
//! * **Have the home name the shape in its ack** — what this build does. The
//!   home knows the park's shape when it probes for it, one phase earlier than
//!   the edge can possibly know its own, and the ack byte is already on the wire
//!   at exactly that moment. So the ack answers the question the OPEN left open:
//!   it stays [`OPEN_ACK_ACCEPTED`] when the OPEN committed to a shape, and
//!   carries the park's [`MeshShape`] when it did not.
//!
//! The edge then decides everything locally. It reads the client's command, and
//! either the shape the home advertised is the one that command needs — so it
//! attests the user and splices — or it is not, so it releases the relay
//! *before* the USER frame that would make the home consume its park, and serves
//! the client locally (`transport::vless`'s `keep_mesh_upstream_for`). No round
//! trip, no failed session, and the park is still there for the carrier that can
//! use it.
//!
//! Two things pay for that. The ack is *optimistic* in one narrow window: a park
//! still landing (a reservation, see `OrphanRegistry::probe_park`) has no shape
//! to report, and the home answers [`MeshShape::Stream`] — the shape it would
//! have assumed before this field existed — so a VLESS-UDP resume arriving
//! inside that window is served locally instead. And the advertisement is not
//! *itself* the check: the home re-probes with the shape it advertised
//! immediately before `take_for_resume`, so a mismatch is still refused before
//! anything is consumed, whatever a peer does with the ack.
//!
//! # How a mux body crosses, and why it needs no framing of its own
//!
//! [`MeshShape::VlessMux`] took no wire change at all, which is the point of
//! recording *why* here rather than in the splice that implements it.
//!
//! A mux session is a bundle: one `Parked::VlessMux` holding a TCP or UDP
//! sub-connection per multiplexed id, each with its own upstream socket. Those
//! sockets cannot move, so a relayed mux is served by the node that owns them —
//! the home runs the mux frame layer, and the edge is a pure carrier. What
//! crosses the mesh is therefore the client's **own mux frame stream**,
//! verbatim: the edge terminates the client's carrier and the VLESS request
//! header, but never parses a mux frame.
//!
//! That is what makes [`MeshFraming::Tcp`] correct here, and it is not the same
//! argument as for a byte-stream park. It rests on the mux frames themselves:
//! every one carries a `u16` meta length and, when it has a payload, a `u16`
//! data length — so the stream is self-delimiting whatever the QUIC chunking
//! does — and a UDP sub-connection's **datagram boundary is a frame boundary**,
//! one `Keep` frame per packet with its own target. The atomicity the `Udp`
//! framing exists to protect is already on the wire, one layer up. Contrast
//! SS-UDP and single-target VLESS-UDP, where the edge *strips* the client's
//! framing and the mesh must supply one.
//!
//! Three alternatives were weighed and rejected:
//!
//! * **Length-frame each mux frame as a mesh datagram.** Would force the edge to
//!   parse mux frames purely to re-frame them — putting the mux parser on both
//!   nodes, with two chances to disagree — and spend four bytes per frame
//!   duplicating a length prefix already present.
//! * **Demultiplex on the edge: one mesh sub-stream (or a sub-connection-id
//!   field) per mux sub-connection.** This re-invents mux inside the mesh: an id
//!   space, an admission decision and a teardown rule per sub-connection, plus a
//!   wire addition — and buys nothing, because every socket it addresses is on
//!   the same home anyway.
//! * **Split the bundle: relay the sub-connections that fit an existing shape,
//!   dial the rest locally.** Rejected outright. The bundle is one registry
//!   entry, and half of it on each node is a session neither can ever park
//!   again.
//!
//! The bundle is therefore admitted whole or refused whole, and the check runs
//! before anything is consumed: `transport::mesh_relay`'s
//! `splice_plaintext_vless_mux` tests the one precondition (the bundle still
//! holds a sub-connection) ahead of `vless_mux::attach_parked`, which is total
//! over what it is given — every parked sub-connection already carries both
//! halves of its upstream, so none can fail to re-attach and no partial outcome
//! exists below that point.
//!
//! One consequence is worth stating plainly, because it is a scope decision and
//! not an accident: sub-connections opened *inside* a relayed mux are dialled
//! from the **home**, since that is where the frame layer runs. The rule that a
//! mux session a node establishes dials its own sub-connections is unchanged —
//! it is about a fresh mux, and this is about a park that already exists
//! elsewhere. Both say the same thing: sub-connections live wherever the mux
//! bundle lives, and never straddle two nodes.
//!
//! Version skew degrades the same way it always has, in both directions. A home
//! that predates the field answers [`OPEN_ACK_ACCEPTED`], which reads as
//! [`MeshShape::Stream`] — exactly what such a home splices. An edge that
//! predates it refuses any ack byte that is not `1`, so a home advertising a
//! non-stream park costs it the resume and nothing else.
//!
//! [`UpstreamAckFrame`] is the resume-continuity half of the protocol: it
//! tells the resuming edge how far the home's upstream socket actually got, so
//! the edge replays only the uplink the target never received. It is gated on
//! the ACK-PREFIX flag the edge itself set in the OPEN, so its presence is never
//! ambiguous, and it precedes the replay suffix for the same reason the direct
//! path emits its v1 frame before the v2 "ORDR" one. The gate is on the flag
//! alone, not on the framing: a [`MeshFraming::Udp`] relay sends the frame too
//! and reports `0`, because a datagram session acknowledges no uplink byte
//! offset — so the stream head parses identically on both framings.
//!
//! Teardown carries the other resume-continuity signal. The edge always ends its uplink
//! half with a QUIC FIN — a reset would drop still-unacked request-body bytes —
//! and says *why* by stopping the home's downlink half with a [`CloseIntent`]
//! code. FIN alone therefore keeps its old meaning ("the carrier ended, expect a
//! resume"), which is the safe default when no code arrives.
//!
//! The two frames are emitted together and the home reads the code once it has
//! seen the FIN, so an ordinary close delivers both in one flight. A
//! [`CloseIntent::ClientDone`] that lands while the home is mid-downlink-write
//! ends that half early; the home still drains the uplink to its FIN, so a
//! finished client's request body reaches the target whole.
//!
//! The edge owns the client's crypto, so the header carries only what the home
//! still has to decide on: the resume id, how the body is framed, which proxy
//! protocol the park must have been authenticated under, the resume capability
//! bits the client advertised and an optional client address hint. The
//! authenticated user is *not* here — the edge cannot know it before it answers
//! the client's upgrade — so it follows in the [`UserFrame`]. See
//! `docs/CLUSTER.md`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Result, bail};

/// Wire-format version of an [`OpenHeader`]. Bump on any layout change so a peer
/// on an older build fails cleanly instead of misparsing.
///
/// v5 is the only version this build speaks, and the only one it ever will
/// again: it is where client crypto moved to the edge. Its predecessors relayed
/// the client's *still-encrypted* bytes and made the home re-run its whole
/// accept path against them — v2 added the `SsXhttp` / `VlessXhttp` carrier
/// kinds, v3 the `SsUdpXhttp` one and v4 the [`OPEN_ACK_ACCEPTED`] setup
/// acknowledgement — so their header carried a request path and a carrier kind
/// that a plaintext relay has no use for. All of it is retired: [`parse`]
/// refuses any version byte other than `5`, which costs a straggler peer its
/// session continuity (the edge serves its client locally) and never
/// misinterprets its bytes.
///
/// [`parse`]: OpenHeader::parse
const OPEN_VERSION: u8 = 5;

/// The home's setup acknowledgement, sent as the first downlink byte of an
/// admitted relay stream and consumed by the edge before it splices the client
/// carrier. It answers the one question the edge cannot decide alone: whether
/// this home actually holds the park being resumed. A refusal is not a byte
/// value but a stream reset carrying a [`CloseReason`], so an edge waiting for
/// the ack learns of it immediately either way.
///
/// An OPEN that could not commit to a park shape — a VLESS carrier, whose
/// command the edge has not read yet — gets the park's [`MeshShape`] here
/// instead; see [`open_ack_byte`] and the module doc. The two never collide:
/// this value *is* [`MeshShape::Stream`]'s code, which is also the only shape a
/// peer predating the field could have meant.
pub(in crate::server) const OPEN_ACK_ACCEPTED: u8 = 1;

/// The shape of the park a relay stream splices onto, and with it the framing of
/// its body.
///
/// Distinct from [`MeshFraming`] — which is what the *edge* can commit to in its
/// OPEN — because a VLESS carrier commits to nothing there: one path carries
/// three commands and the edge reads none of them before the OPEN. The shape is
/// what the home actually holds, so the home is what names it (see the module
/// doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum MeshShape {
    /// A byte-stream upstream (`Parked::Tcp`), SS or VLESS alike.
    Stream,
    /// An SS-UDP session's NAT identity (`Parked::SsUdpStream`).
    Datagram,
    /// A single-target VLESS-UDP socket (`Parked::VlessUdpSingle`).
    VlessUdpSingle,
    /// A VLESS-mux bundle (`Parked::VlessMux`) — every TCP and UDP
    /// sub-connection multiplexed inside one mux session, spliced as one.
    VlessMux,
}

impl MeshShape {
    /// Wire code. `Stream` is deliberately [`OPEN_ACK_ACCEPTED`]: an ack byte
    /// from a peer predating this field means a byte-stream park, which is the
    /// only shape it could splice.
    fn to_u8(self) -> u8 {
        match self {
            MeshShape::Stream => OPEN_ACK_ACCEPTED,
            MeshShape::Datagram => 2,
            MeshShape::VlessUdpSingle => 3,
            MeshShape::VlessMux => 4,
        }
    }

    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            OPEN_ACK_ACCEPTED => MeshShape::Stream,
            2 => MeshShape::Datagram,
            3 => MeshShape::VlessUdpSingle,
            4 => MeshShape::VlessMux,
            other => bail!("unknown mesh park shape {other}"),
        })
    }

    /// How this shape's body is delimited.
    ///
    /// `Option` only because a future shape may again have no body; every shape
    /// this build splices has one.
    pub(in crate::server) fn framing(self) -> Option<MeshFraming> {
        match self {
            MeshShape::Stream => Some(MeshFraming::Tcp),
            // One datagram per length-delimited frame, for the same reason on
            // both: a UDP packet is atomic and must not be coalesced or split.
            MeshShape::Datagram | MeshShape::VlessUdpSingle => Some(MeshFraming::Udp),
            // A mux body is the client's own frame stream, forwarded verbatim,
            // and every mux frame is self-delimiting — including the datagram
            // ones. See the module doc's "How a mux body crosses".
            MeshShape::VlessMux => Some(MeshFraming::Tcp),
        }
    }

    /// Stable label for structured logs and metrics. Low cardinality by
    /// construction: one static string per variant.
    pub(in crate::server) fn label(self) -> &'static str {
        match self {
            MeshShape::Stream => "stream",
            MeshShape::Datagram => "datagram",
            MeshShape::VlessUdpSingle => "vless_udp",
            MeshShape::VlessMux => "vless_mux",
        }
    }
}

/// The ack byte a home sends for a park of shape `parked`, on a relay whose OPEN
/// committed to `committed` ([`OpenHeader::committed_shape`]).
///
/// A committed OPEN gets the plain [`OPEN_ACK_ACCEPTED`] — the shape was never in
/// question, and an edge predating the shape field must keep reading the byte it
/// expects. An OPEN that committed to nothing gets the shape itself, which is
/// the whole point of the field.
pub(in crate::server) fn open_ack_byte(committed: Option<MeshShape>, parked: MeshShape) -> u8 {
    match committed {
        Some(_) => OPEN_ACK_ACCEPTED,
        None => parked.to_u8(),
    }
}

/// Reads the home's ack byte on the edge, yielding the shape the relay is now
/// agreed on.
///
/// `committed` is what this edge's own OPEN committed to, so the two peers read
/// the same byte the same way without it having to be self-describing. A
/// committed OPEN accepts only [`OPEN_ACK_ACCEPTED`] and keeps its own shape; an
/// uncommitted one takes the home's word for it.
pub(in crate::server) fn parse_open_ack(
    byte: u8,
    committed: Option<MeshShape>,
) -> Result<MeshShape> {
    match committed {
        Some(shape) => {
            if byte != OPEN_ACK_ACCEPTED {
                bail!("unexpected mesh OPEN ack byte {byte}");
            }
            Ok(shape)
        },
        None => MeshShape::from_u8(byte),
    }
}

/// Upper bound on the user name carried in a [`UserFrame`]. Guards the parser
/// against an oversized allocation from a malformed peer; a single length byte
/// is enough because names are short identifiers.
///
/// `pub(crate)` rather than `pub(in crate::server)` because config validation
/// refuses a clustered `[[users]]` name that could never fit here (see
/// `Config::validate`) — the bound belongs to the wire, and a copied literal
/// there would drift the moment this one moved.
pub(crate) const MAX_USER_LEN: usize = 64;

/// Why a relayed stream was closed. Encoded as the QUIC stream reset error
/// code; a graceful end uses `finish` and maps to [`CloseReason::Fin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum CloseReason {
    /// Orderly end of stream (both sides done).
    Fin,
    /// Aborted (peer reset, upstream error).
    Abort,
    /// The edge tore the relay down on its health budget (stalled progress).
    Budget,
    /// The home refused the stream: it is already serving its cap of relayed
    /// sessions. Distinct from [`CloseReason::Abort`] so the edge can tell "this
    /// home is full" from a generic failure; a peer on an older build maps it to
    /// `Abort` through [`CloseReason::from_code`], which is the right fallback.
    Capacity,
    /// The home refused the stream: it holds no parked session under the
    /// relayed resume id, or the id's owner is not the user the edge
    /// authenticated. An ordinary outcome — parks expire and are evicted — so
    /// the edge simply serves its client a fresh local session. A peer on an
    /// older build maps it to `Abort`, which is the right fallback.
    NoSession,
}

impl CloseReason {
    /// The QUIC stream reset code for this reason.
    pub(in crate::server) fn code(self) -> u32 {
        match self {
            CloseReason::Fin => 0,
            CloseReason::Abort => 1,
            CloseReason::Budget => 2,
            CloseReason::Capacity => 3,
            CloseReason::NoSession => 5,
        }
    }

    /// Maps a received QUIC reset code back to a reason. Unknown codes are
    /// treated as [`CloseReason::Abort`] (a reset is a reset).
    ///
    /// Code `4` is deliberately unmapped: it was the retired `NoRoute` refusal a
    /// pre-v5 home sent when the relayed request path resolved to no configured
    /// users. No home performs that lookup any more, so a straggler still
    /// sending the code lands on `Abort`, which is the right reading — the edge
    /// serves its client locally either way.
    pub(in crate::server) fn from_code(code: u32) -> Self {
        match code {
            0 => CloseReason::Fin,
            2 => CloseReason::Budget,
            3 => CloseReason::Capacity,
            5 => CloseReason::NoSession,
            _ => CloseReason::Abort,
        }
    }
}

// Flag bits packed into the header's flag byte.
const FLAG_RESUME_CAPABLE: u8 = 0x01;
const FLAG_ACK_PREFIX: u8 = 0x02;
const FLAG_SYMMETRIC_REPLAY: u8 = 0x04;
const FLAG_HAS_PEER_ADDR: u8 = 0x08;
/// The edge terminated VLESS rather than Shadowsocks for this stream. A spare
/// bit rather than a new field, so a peer built before the flag existed —
/// necessarily an SS edge, since SS migrated to v5 first — still parses, and its
/// cleared bit reads as [`MeshProtocol::Ss`], which is what it is.
const FLAG_VLESS: u8 = 0x10;

/// Second-phase frame: the user the edge authenticated, sent after the home's
/// setup ack.
///
/// It is a separate frame rather than an OPEN field because the edge does not
/// know the user when it sends OPEN — it must decide what to echo in its `101`
/// before it can read the client's first encrypted frame. The home trusts this
/// attestation (a peer holding the mesh PSK is already a full cluster member)
/// and checks it against the park's owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) struct UserFrame {
    pub(in crate::server) user: String,
}

impl UserFrame {
    /// Layout: `user_len(1) | user`. One length byte suffices: names are bounded
    /// by [`MAX_USER_LEN`].
    pub(in crate::server) fn encode(&self) -> Vec<u8> {
        let user = self.user.as_bytes();
        let mut out = Vec::with_capacity(1 + user.len());
        out.push(user.len() as u8);
        out.extend_from_slice(user);
        out
    }

    /// Parses the frame. Rejects an empty name (it could never match a park
    /// owner), an over-long one, or invalid UTF-8.
    pub(in crate::server) fn parse(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        let len = r.u8()? as usize;
        if len == 0 {
            bail!("mesh USER frame carries an empty user name");
        }
        if len > MAX_USER_LEN {
            bail!("mesh USER frame user name too long: {len}");
        }
        let user = String::from_utf8(r.bytes(len)?.to_vec())
            .map_err(|_| anyhow::anyhow!("mesh USER frame user name is not valid UTF-8"))?;
        Ok(Self { user })
    }
}

/// How a relayed stream is framed. The edge owns the client crypto, so
/// WS-vs-XHTTP never reaches the home — only the framing does: TCP-shaped
/// carriers relay as a byte stream, UDP as length-delimited datagrams (see
/// [`super::datagram`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum MeshFraming {
    Tcp,
    Udp,
}

/// Which proxy protocol the edge terminated for a relayed stream.
///
/// The home never speaks it — the mesh carries application plaintext — and a
/// byte-stream park is served to a carrier of either protocol, so this does not
/// gate the splice. What it still decides is the *shape* question: paired with
/// [`MeshFraming`] it names which park shapes an OPEN can be asking for
/// (`mesh_relay::park_query`), because an SS carrier names one exactly while a
/// VLESS one multiplexes three onto a single path. It also labels the crossing
/// in logs and on `outline_ss_orphan_resume_cross_protocol_total`. The edge
/// knows it before it reads a client byte, unlike the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum MeshProtocol {
    Ss,
    Vless,
}

impl MeshProtocol {
    /// Stable label for structured logs and metrics. Matches
    /// `resumption::ParkedProtocol::label`, so an operator reads the same two
    /// words on both sides of a crossing.
    pub(in crate::server) fn label(self) -> &'static str {
        match self {
            MeshProtocol::Ss => "ss",
            MeshProtocol::Vless => "vless",
        }
    }
}

impl MeshFraming {
    fn to_u8(self) -> u8 {
        match self {
            MeshFraming::Tcp => 0,
            MeshFraming::Udp => 1,
        }
    }

    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => MeshFraming::Tcp,
            1 => MeshFraming::Udp,
            other => bail!("unknown mesh framing {other}"),
        })
    }
}

/// Metadata prefixing a relayed session stream: everything the home needs to
/// find the park the edge is resuming, and nothing about the client's crypto.
///
/// The authenticated user is deliberately absent — the edge cannot know it when
/// it sends OPEN (it must decide what to echo in its `101` before reading the
/// client's first encrypted frame), so it arrives in the second-phase
/// [`UserFrame`] after the home's ack. See `docs/CLUSTER.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) struct OpenHeader {
    /// The framing the edge can commit to before the client has said anything.
    ///
    /// On a Shadowsocks carrier that is also the body's framing — SS-TCP and
    /// SS-UDP arrive on different paths. On a VLESS carrier it is not: the edge
    /// must send OPEN before the first frame reveals whether the session is TCP,
    /// UDP or mux, so every VLESS OPEN says `Tcp` and the real shape comes back
    /// in the home's ack ([`open_ack_byte`]). Read
    /// [`OpenHeader::committed_shape`] rather than this field wherever the
    /// *shape* is what matters.
    pub(in crate::server) framing: MeshFraming,
    /// Which proxy protocol the edge terminated. Not used to decode anything —
    /// the body is plaintext either way — only to keep a park from being
    /// resumed across a protocol boundary, as both direct resume paths do.
    pub(in crate::server) protocol: MeshProtocol,
    /// The resume id the client presented (shard already routes to this home).
    pub(in crate::server) session_id: [u8; 16],
    /// Client advertised `X-Outline-Resume-Capable`.
    pub(in crate::server) resume_capable: bool,
    /// Client advertised the Ack-Prefix (v1) capability.
    pub(in crate::server) ack_prefix: bool,
    /// Client advertised Symmetric Downlink Replay (v2).
    pub(in crate::server) symmetric_replay: bool,
    /// Client-reported downstream-acked offset (v2), else 0.
    pub(in crate::server) client_down_acked: u64,
    /// Optional client address hint (for logging / routing scope).
    pub(in crate::server) peer_addr: Option<SocketAddr>,
}

impl OpenHeader {
    /// The park shape this OPEN commits to, or `None` when it defers to the
    /// home's ack.
    ///
    /// A Shadowsocks carrier commits: its framing names exactly one shape. A
    /// VLESS carrier cannot — one path multiplexes three commands and the OPEN
    /// precedes the first of them — so it defers, and the home answers with the
    /// shape it actually holds. See the module doc.
    pub(in crate::server) fn committed_shape(&self) -> Option<MeshShape> {
        match self.protocol {
            MeshProtocol::Ss => Some(match self.framing {
                MeshFraming::Tcp => MeshShape::Stream,
                MeshFraming::Udp => MeshShape::Datagram,
            }),
            MeshProtocol::Vless => None,
        }
    }

    /// Serializes the header. Layout (all integers big-endian):
    /// `version(1) | framing(1) | flags(1) | down_acked(8) | session_id(16) |
    ///  [peer_addr]`, where peer_addr (present iff the flag is set) is
    /// `family(1: 4|6) | addr(4|16) | port(2)`. The protocol rides
    /// [`FLAG_VLESS`] in the flag byte rather than taking a field of its own.
    pub(in crate::server) fn encode(&self) -> Vec<u8> {
        let mut flags = 0u8;
        if self.resume_capable {
            flags |= FLAG_RESUME_CAPABLE;
        }
        if self.ack_prefix {
            flags |= FLAG_ACK_PREFIX;
        }
        if self.symmetric_replay {
            flags |= FLAG_SYMMETRIC_REPLAY;
        }
        if self.peer_addr.is_some() {
            flags |= FLAG_HAS_PEER_ADDR;
        }
        if self.protocol == MeshProtocol::Vless {
            flags |= FLAG_VLESS;
        }

        let mut out = Vec::with_capacity(27 + 19);
        out.push(OPEN_VERSION);
        out.push(self.framing.to_u8());
        out.push(flags);
        out.extend_from_slice(&self.client_down_acked.to_be_bytes());
        out.extend_from_slice(&self.session_id);
        if let Some(addr) = self.peer_addr {
            match addr.ip() {
                IpAddr::V4(v4) => {
                    out.push(4);
                    out.extend_from_slice(&v4.octets());
                },
                IpAddr::V6(v6) => {
                    out.push(6);
                    out.extend_from_slice(&v6.octets());
                },
            }
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        out
    }

    /// Parses a header from the stream prefix. Rejects any version byte that is
    /// not [`OPEN_VERSION`] — including a retired v4 frame from a straggler
    /// peer, which is what makes a mixed cluster degrade to a lost resume
    /// instead of a misparsed stream.
    pub(in crate::server) fn parse(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        let version = r.u8()?;
        if version != OPEN_VERSION {
            bail!("unsupported mesh OPEN version {version}");
        }
        let framing = MeshFraming::from_u8(r.u8()?)?;
        let flags = r.u8()?;
        let client_down_acked = r.u64()?;
        let session_id = r.array16()?;
        let peer_addr = if flags & FLAG_HAS_PEER_ADDR != 0 {
            let ip = match r.u8()? {
                4 => IpAddr::V4(Ipv4Addr::from(r.array4()?)),
                6 => IpAddr::V6(Ipv6Addr::from(r.array16()?)),
                fam => bail!("unknown mesh OPEN address family {fam}"),
            };
            Some(SocketAddr::new(ip, r.u16()?))
        } else {
            None
        };
        Ok(Self {
            framing,
            // A cleared bit is Shadowsocks, which is also what a peer built
            // before the flag existed can only have been relaying.
            protocol: if flags & FLAG_VLESS != 0 {
                MeshProtocol::Vless
            } else {
                MeshProtocol::Ss
            },
            session_id,
            resume_capable: flags & FLAG_RESUME_CAPABLE != 0,
            ack_prefix: flags & FLAG_ACK_PREFIX != 0,
            symmetric_replay: flags & FLAG_SYMMETRIC_REPLAY != 0,
            client_down_acked,
            peer_addr,
        })
    }
}

/// Length of an [`UpstreamAckFrame`] on the wire. Fixed, so a peer reads it
/// with a single `read_exact` and can never be driven into an unbounded read.
pub(in crate::server) const UPSTREAM_ACK_FRAME_LEN: usize = 8;

/// Home→edge resume-continuity frame: how many uplink bytes the parked
/// upstream socket has actually taken over this session's whole life.
///
/// It answers the question a relayed resume cannot otherwise answer. The home may
/// have consumed uplink bytes off a dying mesh carrier that the upstream socket
/// never took; without this offset the resuming edge would either skip them (a
/// silent hole in the request body at the target) or resend from zero (a
/// duplicate). It is the mesh spelling of what the direct path sends its client as
/// the Ack-Prefix v1 control frame — same number, same meaning, same position at
/// the head of the resumed session — except that here the edge is the one that
/// owns the client's crypto and re-emits it downstream.
///
/// Sent immediately after the home has taken the park (so the number is final
/// for the previous carrier) and before any replayed or fresh downlink byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) struct UpstreamAckFrame {
    pub(in crate::server) upstream_acked: u64,
}

impl UpstreamAckFrame {
    /// Layout: `upstream_acked(8)`, big-endian. Positional rather than tagged —
    /// its presence and offset both follow from the OPEN both peers already
    /// exchanged, exactly as the one-byte [`OPEN_ACK_ACCEPTED`] does.
    pub(in crate::server) fn encode(&self) -> [u8; UPSTREAM_ACK_FRAME_LEN] {
        self.upstream_acked.to_be_bytes()
    }

    /// Parses the frame. Rejects a truncated buffer; every 8-byte value is a
    /// legal offset.
    pub(in crate::server) fn parse(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        Ok(Self { upstream_acked: r.u64()? })
    }
}

/// Why the edge ended its half of a relay stream — the distinction the home
/// needs to decide whether the session has a future.
///
/// Carried as the QUIC `STOP_SENDING` error code the edge applies to the home's
/// downlink half, alongside the FIN it sends on the uplink half either way. The
/// FIN is what keeps the request body intact (a `RESET_STREAM` would drop
/// still-unacked bytes), and it carries no code of its own — hence the
/// companion signal on the other half rather than an in-band trailer, which a
/// transparent byte stream has no way to delimit.
///
/// The codes live in their own `0x50xx` range, disjoint from every
/// [`CloseReason`], so a stray code is unambiguously one or the other. The two
/// are not interchangeable: a `CloseReason` travels as the `RESET_STREAM` code
/// on this stream, a `CloseIntent` only ever as the `STOP_SENDING` code applied
/// to it.
///
/// Keeping that true takes one deliberate step on the home, because QUIC's own
/// answer to a `STOP_SENDING` is a `RESET_STREAM` — and quinn's
/// `Drop for SendStream` builds it from the very code it received, which would
/// put a `CloseIntent` code exactly where a reader looks for a `CloseReason`.
/// The home therefore closes a stopped half itself, with
/// [`CloseReason::Fin`], rather than letting the drop do it; see
/// `transport::mesh_relay`'s `SpliceEnd::stream_close`.
///
/// One window escapes that step, and a reader must tolerate it: when the home
/// has already finished the stream on upstream EOF and a `STOP_SENDING` lands
/// afterwards — anywhere in the remaining uplink drain — quinn's drop still
/// resets with the received code, so a `CloseIntent` value can appear as a
/// `RESET_STREAM` code. RFC 9000 §3.5 permits exactly this (in "Data Sent" the
/// endpoint MAY defer the reset and SHOULD copy the `STOP_SENDING` code), and
/// it is harmless: the code travels only back to the peer that sent the
/// `STOP_SENDING`, which has already abandoned its receive half. Treat an
/// observed `0x50xx` reset code as this echo, not as a protocol violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum CloseIntent {
    /// The mesh carrier ended but the client has not: it is switching carriers
    /// and will resume this session. The home re-parks the upstream.
    CarrierEnded,
    /// The client is done for good. The home must half-close the upstream so the
    /// target sees the end of the request body, and must **not** re-park —
    /// a park nobody will claim holds one of the user's `orphan_per_user_cap`
    /// slots until its TTL, where it can evict a park that is still wanted.
    ClientDone,
}

const CLOSE_INTENT_CARRIER_ENDED: u32 = 0x5001;
const CLOSE_INTENT_CLIENT_DONE: u32 = 0x5002;

impl CloseIntent {
    /// The `STOP_SENDING` error code for this intent.
    pub(in crate::server) fn code(self) -> u32 {
        match self {
            CloseIntent::CarrierEnded => CLOSE_INTENT_CARRIER_ENDED,
            CloseIntent::ClientDone => CLOSE_INTENT_CLIENT_DONE,
        }
    }

    /// Maps a received `STOP_SENDING` code back to an intent. Takes a `u64`
    /// because that is what a QUIC `VarInt` holds, while our own codes fit a
    /// `u32`.
    ///
    /// Anything unrecognised is [`CloseIntent::CarrierEnded`] — deliberately the
    /// conservative reading, and the one an ordinary quinn `RecvStream` drop
    /// produces (code `0`). Guessing "client done" from an unknown code would
    /// tear down a session the client still wants; guessing "carrier ended"
    /// only costs a park that expires on its TTL, which is what every pre-v5
    /// build did with every close.
    pub(in crate::server) fn from_code(code: u64) -> Self {
        match u32::try_from(code) {
            Ok(CLOSE_INTENT_CLIENT_DONE) => CloseIntent::ClientDone,
            _ => CloseIntent::CarrierEnded,
        }
    }

    /// The `close` label this intent contributes to
    /// `outline_ss_mesh_relay_outcome_total`. Low cardinality by construction:
    /// one static string per variant, and there are two.
    pub(in crate::server) fn metric_label(self) -> &'static str {
        match self {
            CloseIntent::CarrierEnded => "carrier_ended",
            CloseIntent::ClientDone => "client_done",
        }
    }
}

/// Minimal big-endian byte reader with bounds checks.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|e| *e <= self.buf.len());
        match end {
            Some(end) => {
                let slice = &self.buf[self.pos..end];
                self.pos = end;
                Ok(slice)
            },
            // Shared by every frame this module parses — the OPEN header, the
            // USER frame and the upstream-ack frame — so the message names the
            // reader, not whichever frame happened to be first.
            None => bail!("truncated mesh frame"),
        }
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.bytes(2)?.try_into().expect("2 bytes")))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.bytes(8)?.try_into().expect("8 bytes")))
    }

    fn array4(&mut self) -> Result<[u8; 4]> {
        Ok(self.bytes(4)?.try_into().expect("4 bytes"))
    }

    fn array16(&mut self) -> Result<[u8; 16]> {
        Ok(self.bytes(16)?.try_into().expect("16 bytes"))
    }
}

#[cfg(test)]
#[path = "tests/frame.rs"]
mod tests;
