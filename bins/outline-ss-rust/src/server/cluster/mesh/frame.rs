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
