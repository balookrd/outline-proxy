//! Mesh relay between cluster nodes: the edge that received a client hands a
//! foreign-shard session to the home that owns it, and the home splices the
//! relayed stream onto its parked upstream.
//!
//! A relayed session arrives as a QUIC stream carrying an [`OpenHeader`] plus
//! application **plaintext**: the edge terminated the client's crypto, so the
//! home is a pure session owner. `serve_relayed` resolves the park behind the
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
//!
//! Layout:
//!
//! - `edge` — the edge side: open a relay, present it as an upstream.
//! - `home` — the home side: accept a relayed stream, find its park.
//! - `close` — how a splice ended and the close intent each side derives.
//! - `splice_tcp`, `splice_udp`, `splice_vless_udp`, `splice_vless_mux` — one
//!   plaintext splice per protocol shape.

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
use outline_wire::padding::PaddingScheme;
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
    ParkedVlessMux, ParkedVlessUdpSingle, ResumeMiss, ResumeOutcome, SessionId,
};
use crate::server::shutdown::ShutdownSignal;
use crate::server::state::Services;

use super::super::constants::UDP_MAX_CONCURRENT_RELAY_TASKS;
use super::super::scratch::UdpRecvBuf;
use super::resume_headers::{EdgeResumeAdvert, ResumeContext, ResumeResponseEcho};
use super::tcp_linger::linger_until_delivered;
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

mod close;
mod edge;
mod home;
mod splice_tcp;
mod splice_udp;
mod splice_vless_mux;
mod splice_vless_udp;

// Every submodule is globbed into this one and starts with `use super::*`, so
// the split changes where code lives, not what it can name. Only `edge` and
// `home` hold items the rest of the server calls.
use self::close::*;
pub(in crate::server) use self::edge::*;
pub(in crate::server) use self::home::*;
use self::splice_tcp::*;
use self::splice_udp::*;
use self::splice_vless_mux::*;
use self::splice_vless_udp::*;

#[cfg(test)]
mod tests;
