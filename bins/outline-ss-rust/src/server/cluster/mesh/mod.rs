//! Mesh interconnect transport: QUIC between cluster members over PSK-derived
//! mutual TLS. An edge that does not own a session relays its already-decrypted
//! application plaintext to the home over this link.
//!
//! This module owns the wire types: TLS identity setup ([`tls`]), the stream
//! framing ([`frame`]), and the transport primitives ([`endpoint`],
//! [`peer_pool`], [`pump`]) that the accept/relay path wires the mesh into.
//! See `docs/CLUSTER.md`.

mod datagram;
mod endpoint;
mod frame;
mod peer_pool;
mod pump;
mod tls;

// Re-exported so the transport-side relay path can accept relayed streams and
// splice them onto the parks this node owns.
pub(in crate::server) use datagram::{read_datagram, write_datagram};
pub(in crate::server) use endpoint::{
    AcceptRelayError, MeshEndpoint, MeshStream, accept_relay, write_open_ack,
};
pub(in crate::server) use frame::{
    CloseIntent, CloseReason, MAX_USER_LEN, MeshFraming, MeshProtocol, MeshShape, OpenHeader,
    UPSTREAM_ACK_FRAME_LEN, UpstreamAckFrame, UserFrame,
};
// Setup-phase pieces the *reading* peer needs. The edge reads the ack through
// `PooledRelay::await_ack`, so outside this module only the test standing in for
// an edge names the byte itself — or, for an OPEN that committed to no shape,
// asks the parser which shape the byte names.
#[cfg(test)]
pub(in crate::server) use frame::{OPEN_ACK_ACCEPTED, parse_open_ack};
pub(in crate::server) use peer_pool::{MeshPeerPool, PooledRelay};
pub(in crate::server) use tls::MeshIdentity;
