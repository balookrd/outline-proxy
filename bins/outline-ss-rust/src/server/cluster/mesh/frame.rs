//! Mesh stream framing.
//!
//! Each relayed session is one QUIC bidirectional stream. The stream opens
//! with a single [`OpenHeader`] — the metadata the home needs to admit the
//! relayed carrier into its normal accept path — after which the still-encrypted
//! application bytes flow through in both directions. The body framing depends
//! on the carrier kind: the TCP-shaped carriers (`SsTcp` / `VlessTcp` and their
//! `*Xhttp` variants) relay as a transparent byte stream (chunk boundaries are
//! irrelevant; the QUIC stream *is* the channel, there is no per-chunk data
//! frame), whereas `SsUdp` frames each datagram as `u32 BE length | payload`
//! because an SS-UDP packet is atomic and must not be coalesced or split — see
//! [`super::datagram`]. The stream closes with a QUIC `finish` (graceful) or
//! `reset` whose error code is a [`CloseReason`].
//!
//! Two header versions coexist while the fleet migrates: [`OpenHeader`] (v4,
//! described above and below) and [`OpenHeaderV5`], where the edge terminates
//! the client's crypto and the mesh carries plaintext. A v5 home needs no
//! request path (routing is a local matter of the edge) and never decodes the
//! body — only [`MeshFraming`] says how it is delimited, and [`MeshProtocol`]
//! says which protocol's park may be spliced onto it — and it learns the user
//! from a second-phase [`UserFrame`]. [`RelayOpen::parse`] routes a frame to the
//! matching parser by its leading version byte.
//!
//! # v5 stream layout
//!
//! A v5 stream is a fixed setup sequence followed by the relayed body, and each
//! element sits at a position both peers can compute from what they have
//! already exchanged — there is no in-band framing over the body, so nothing
//! may be inserted once it starts:
//!
//! ```text
//! edge → home:  OPEN(v5)                        length-prefixed OpenHeaderV5
//! home → edge:  ack(1)                          OPEN_ACK_ACCEPTED
//! edge → home:  USER                            UserFrame
//! home → edge:  UPSTREAM-ACK(8)                 iff OPEN set the ACK-PREFIX flag
//! home → edge:  [downlink replay suffix]        iff OPEN set SYMMETRIC-REPLAY
//! both ways:    body …                          plaintext, framed per MeshFraming
//! ```
//!
//! [`UpstreamAckFrame`] is the resume-continuity half of the v5 protocol: it
//! tells the resuming edge how far the home's upstream socket actually got, so
//! the edge replays only the uplink the target never received. It is gated on
//! the ACK-PREFIX flag the edge itself set in the OPEN, so its presence is never
//! ambiguous, and it precedes the replay suffix for the same reason the direct
//! path emits its v1 frame before the v2 "ORDR" one. The gate is on the flag
//! alone, not on the framing: a [`MeshFraming::Udp`] relay sends the frame too
//! and reports `0`, because a datagram session acknowledges no uplink byte
//! offset — so the stream head parses identically on both framings.
//!
//! Teardown carries the other v5-only signal. The edge always ends its uplink
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
//! The edge never decrypts, so the header carries only carrier metadata the
//! edge can see before the payload: the resume id, the carrier kind, the
//! resume capability bits the client advertised, the request path (for the
//! home's padding-scheme selection) and an optional client address hint. The
//! authenticated user is *not* here — the home authenticates it from the
//! relayed byte stream itself (SS salt / VLESS UUID), exactly as for a direct
//! carrier. See `docs/CLUSTER.md`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Result, bail};

/// Wire-format version of the [`OpenHeader`]. Bump on any layout change so a
/// peer on an older build fails cleanly instead of misparsing.
///
/// v2 added the `SsXhttp` / `VlessXhttp` carrier kinds.
/// v3 added the `SsUdpXhttp` carrier kind (SS-UDP over XHTTP).
/// v4 added the [`OPEN_ACK_ACCEPTED`] setup acknowledgement: the home now
/// prefixes the downlink with one ack byte, which an older edge would misread as
/// carrier payload — so the version gate is what keeps the two apart.
const OPEN_VERSION: u8 = 4;

/// The home's setup acknowledgement, sent as the first downlink byte of an
/// admitted relay stream (v4+) and consumed by the edge before it splices the
/// client carrier. It answers the one question the edge cannot decide alone:
/// whether this home can actually serve the relayed path and carrier. A refusal
/// is not a byte value but a stream reset carrying a [`CloseReason`], so an edge
/// waiting for the ack learns of it immediately either way.
pub(in crate::server) const OPEN_ACK_ACCEPTED: u8 = 1;

/// Upper bound on the request path length carried in an OPEN header. Guards the
/// parser against an oversized allocation from a malformed peer.
const MAX_PATH_LEN: usize = 512;

/// Upper bound on the user name carried in a [`UserFrame`]. Guards the parser
/// against an oversized allocation from a malformed peer; a single length byte
/// is enough because names are short identifiers.
pub(in crate::server) const MAX_USER_LEN: usize = 64;

/// Which carrier a relayed stream is, so the home dispatches it into the right
/// accept path. Combined-SS path-kind is already resolved into the Tcp/Udp
/// split here. The `*Xhttp` kinds differ from the WS kinds only in which route
/// table the home resolves the path against (`xhttp_ss` / `xhttp_vless` /
/// `xhttp_ss_udp` vs the WS `tcp` / `vless` / `udp` tables); the crypto is the
/// same. Body framing depends on the kind: the TCP-shaped carriers relay as a
/// byte stream, whereas `SsUdp` and `SsUdpXhttp` are datagram-framed (see
/// [`super::datagram`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum CarrierKind {
    SsTcp,
    SsUdp,
    VlessTcp,
    VlessUdp,
    SsXhttp,
    VlessXhttp,
    SsUdpXhttp,
}

impl CarrierKind {
    fn to_u8(self) -> u8 {
        match self {
            CarrierKind::SsTcp => 0,
            CarrierKind::SsUdp => 1,
            CarrierKind::VlessTcp => 2,
            CarrierKind::VlessUdp => 3,
            CarrierKind::SsXhttp => 4,
            CarrierKind::VlessXhttp => 5,
            CarrierKind::SsUdpXhttp => 6,
        }
    }

    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => CarrierKind::SsTcp,
            1 => CarrierKind::SsUdp,
            2 => CarrierKind::VlessTcp,
            3 => CarrierKind::VlessUdp,
            4 => CarrierKind::SsXhttp,
            5 => CarrierKind::VlessXhttp,
            6 => CarrierKind::SsUdpXhttp,
            other => bail!("unknown mesh carrier kind {other}"),
        })
    }
}

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
    /// The home refused the stream: the relayed path and carrier resolve to no
    /// configured users here, so it holds no key that could authenticate a
    /// single packet on it. Only reachable under an asymmetric cluster config
    /// (the homes and edges disagree on paths or users); the edge degrades to a
    /// fresh local session rather than relaying into a black hole. A peer on an
    /// older build maps it to `Abort`, which is the right fallback.
    NoRoute,
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
            CloseReason::NoRoute => 4,
            CloseReason::NoSession => 5,
        }
    }

    /// Maps a received QUIC reset code back to a reason. Unknown codes are
    /// treated as [`CloseReason::Abort`] (a reset is a reset).
    pub(in crate::server) fn from_code(code: u32) -> Self {
        match code {
            0 => CloseReason::Fin,
            2 => CloseReason::Budget,
            3 => CloseReason::Capacity,
            4 => CloseReason::NoRoute,
            5 => CloseReason::NoSession,
            _ => CloseReason::Abort,
        }
    }
}

/// Metadata prefixing a relayed session stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) struct OpenHeader {
    pub(in crate::server) carrier: CarrierKind,
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
    /// Request path the client used (WS/XHTTP), for the home's padding-scheme
    /// selection and routing. Bounded by [`MAX_PATH_LEN`].
    pub(in crate::server) path: String,
    /// Optional client address hint (for logging / routing scope).
    pub(in crate::server) peer_addr: Option<SocketAddr>,
}

// Flag bits packed into the header's flag byte.
const FLAG_RESUME_CAPABLE: u8 = 0x01;
const FLAG_ACK_PREFIX: u8 = 0x02;
const FLAG_SYMMETRIC_REPLAY: u8 = 0x04;
const FLAG_HAS_PEER_ADDR: u8 = 0x08;
/// v5 only: the edge terminated VLESS rather than Shadowsocks for this stream.
/// A spare bit rather than a new field, so a v5 peer built before the flag
/// existed — necessarily an SS edge, since SS migrated to v5 first — still
/// parses, and its cleared bit reads as [`MeshProtocol::Ss`], which is what it
/// is. Never set by [`OpenHeader`] (v4), which carries the protocol in its
/// [`CarrierKind`] byte instead.
const FLAG_VLESS: u8 = 0x10;

impl OpenHeader {
    /// Serializes the header. Layout (all integers big-endian):
    /// `version(1) | carrier(1) | flags(1) | down_acked(8) | session_id(16) |
    ///  path_len(2) | path | [peer_addr]`, where peer_addr (present iff the
    /// flag is set) is `family(1: 4|6) | addr(4|16) | port(2)`.
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

        let path = self.path.as_bytes();
        let mut out = Vec::with_capacity(29 + path.len() + 19);
        out.push(OPEN_VERSION);
        out.push(self.carrier.to_u8());
        out.push(flags);
        out.extend_from_slice(&self.client_down_acked.to_be_bytes());
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&(path.len() as u16).to_be_bytes());
        out.extend_from_slice(path);
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

    /// Parses a header from the stream prefix. Rejects an unknown version, an
    /// over-long path, or a truncated buffer.
    pub(in crate::server) fn parse(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        let version = r.u8()?;
        if version != OPEN_VERSION {
            bail!("unsupported mesh OPEN version {version}");
        }
        let carrier = CarrierKind::from_u8(r.u8()?)?;
        let flags = r.u8()?;
        let client_down_acked = r.u64()?;
        let session_id = r.array16()?;
        let path_len = r.u16()? as usize;
        if path_len > MAX_PATH_LEN {
            bail!("mesh OPEN path too long: {path_len}");
        }
        let path = String::from_utf8(r.bytes(path_len)?.to_vec())
            .map_err(|_| anyhow::anyhow!("mesh OPEN path is not valid UTF-8"))?;
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
            carrier,
            session_id,
            resume_capable: flags & FLAG_RESUME_CAPABLE != 0,
            ack_prefix: flags & FLAG_ACK_PREFIX != 0,
            symmetric_replay: flags & FLAG_SYMMETRIC_REPLAY != 0,
            client_down_acked,
            path,
            peer_addr,
        })
    }
}

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

/// Wire-format version of an [`OpenHeaderV5`]. Coexists with [`OPEN_VERSION`]
/// (v4) while the edges migrate: the home dispatches on the leading byte via
/// [`peek_open_version`], so a v4 edge and a v5 edge can both be served.
///
/// v5 is where client crypto moves to the edge. The home no longer decrypts
/// anything, so the header loses the request path (routing and padding become a
/// local matter of the edge) and the carrier byte narrows to the only
/// distinctions the home still needs — how the relayed body is framed, and
/// which protocol's park may be spliced onto it.
const OPEN_VERSION_V5: u8 = 5;

/// How a relayed v5 stream is framed. The edge owns the client crypto, so
/// WS-vs-XHTTP never reaches the home — only the framing does: TCP-shaped
/// carriers relay as a byte stream, UDP as length-delimited datagrams (see
/// [`super::datagram`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum MeshFraming {
    Tcp,
    Udp,
}

/// Which proxy protocol the edge terminated for a relayed v5 stream.
///
/// The home never speaks it — the mesh carries application plaintext — but the
/// park it is about to splice does: [`crate::server::resumption::ParkedTcp`]
/// keeps the protocol its session was authenticated under, and both direct
/// resume paths refuse to reattach across that boundary. The home needs the same
/// answer to apply the same rule, so the protocol travels in the OPEN (where the
/// edge already knows it, unlike the user).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum MeshProtocol {
    Ss,
    Vless,
}

impl MeshProtocol {
    /// Stable label for structured logs. Matches
    /// `resumption::TcpProtocolContext::label`, so an operator reads the same
    /// two words on both sides of the refusal.
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

/// Metadata prefixing a v5 relayed session stream: everything the home needs to
/// find the park the edge is resuming, and nothing about the client's crypto.
///
/// The authenticated user is deliberately absent — the edge cannot know it when
/// it sends OPEN (it must decide what to echo in its `101` before reading the
/// client's first encrypted frame), so it arrives in the second-phase
/// [`UserFrame`] after the home's ack. See `docs/CLUSTER.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) struct OpenHeaderV5 {
    /// How the relayed body is framed on this stream.
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

impl OpenHeaderV5 {
    /// Serializes the header. Layout (all integers big-endian):
    /// `version(1) | framing(1) | flags(1) | down_acked(8) | session_id(16) |
    ///  [peer_addr]`, where peer_addr (present iff the flag is set) is
    /// `family(1: 4|6) | addr(4|16) | port(2)`. Identical to v4 minus the
    /// length-prefixed path, so the flag bits and address encoding are shared;
    /// the protocol rides [`FLAG_VLESS`] in that same flag byte.
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
        out.push(OPEN_VERSION_V5);
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

    /// Parses a v5 header from the stream prefix. Rejects any version byte that
    /// is not `5` — including a v4 frame, which is what makes a mixed cluster
    /// degrade to a lost resume instead of a misparsed stream.
    pub(in crate::server) fn parse(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        let version = r.u8()?;
        if version != OPEN_VERSION_V5 {
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
            // A cleared bit is Shadowsocks, which is also what a v5 peer built
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

/// Length of an [`UpstreamAckFrame`] on the wire. Fixed, so a v5 peer reads it
/// with a single `read_exact` and can never be driven into an unbounded read.
pub(in crate::server) const UPSTREAM_ACK_FRAME_LEN: usize = 8;

/// Home→edge resume-continuity frame (v5 only): how many uplink bytes the parked
/// upstream socket has actually taken over this session's whole life.
///
/// It answers the question a v5→v5 resume cannot otherwise answer. The home may
/// have consumed uplink bytes off a dying mesh carrier that the upstream socket
/// never took; without this offset the resuming edge would either skip them (a
/// silent hole in the request body at the target) or resend from zero (a
/// duplicate). It is the v5 spelling of what the direct path sends its client as
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

/// Why the edge ended its half of a v5 relay stream — the distinction the home
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

/// Reads the version byte a mesh OPEN frame starts with, without consuming it,
/// so the accept loop can route the frame to the matching parser.
pub(in crate::server) fn peek_open_version(buf: &[u8]) -> Result<u8> {
    buf.first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("empty mesh OPEN frame"))
}

/// A parsed mesh OPEN frame, in whichever version the peer sent. The home
/// dispatches on this: v4 keeps the legacy still-encrypted relay path, v5 takes
/// the plaintext one. Both are served for as long as the fleet runs a mix.
pub(in crate::server) enum RelayOpen {
    V4(OpenHeader),
    V5(OpenHeaderV5),
}

impl RelayOpen {
    /// Parses a frame by its leading version byte. An unknown version is an
    /// error, exactly as an unparsable header has always been.
    pub(in crate::server) fn parse(buf: &[u8]) -> Result<Self> {
        match peek_open_version(buf)? {
            OPEN_VERSION => Ok(RelayOpen::V4(OpenHeader::parse(buf)?)),
            OPEN_VERSION_V5 => Ok(RelayOpen::V5(OpenHeaderV5::parse(buf)?)),
            other => bail!("unsupported mesh OPEN version {other}"),
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
            None => bail!("truncated mesh OPEN header"),
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
