//! Mesh relay between cluster nodes: the edge that received a client hands a
//! foreign-shard session to the home that owns it, and the home splices the
//! relayed stream onto its parked upstream.
//!
//! A relayed session arrives as a QUIC stream carrying an `OpenHeader` plus
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
//! `UpstreamAckFrame` saying how far its upstream socket actually got, and the
//! edge closes one with a `CloseIntent` saying whether to expect the client
//! back.
//!
//! Layout:
//!
//! - `edge` — the edge side: open a relay, present it as an upstream.
//! - `home` — the home side: accept a relayed stream, find its park.
//! - `close` — how a splice ended and the close intent each side derives.
//! - `splice_tcp`, `splice_udp`, `splice_vless_udp`, `splice_vless_mux` — one
//!   plaintext splice per protocol shape.

use std::time::Duration;

/// Read granularity of the home's plaintext splice, in both directions. Also
/// the size of the single upstream read buffer the splice allocates once per
/// relay — the explicit bound on that buffer.
const MESH_HOME_SPLICE_CHUNK: usize = 64 * 1024;

/// `close` label for a relay outcome that never reached a close: every `miss`
/// and `error`, plus a `hit` whose resume prologue failed before either pump
/// ran. The two closes that *did* happen are named by
/// `CloseIntent::metric_label`.
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

// What the rest of the server calls. Everything else stays inside this module:
// each submodule imports what it uses, from the crate and from its siblings.
pub(in crate::server) use self::edge::{
    EdgeUpstream, edge_echo, edge_session_id, edge_udp_echo, edge_upstream, open_edge_relay,
};
pub(in crate::server) use self::home::run_mesh_listener;

#[cfg(test)]
mod tests;
