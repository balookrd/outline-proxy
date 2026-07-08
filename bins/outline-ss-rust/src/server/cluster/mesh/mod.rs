//! Mesh interconnect transport: QUIC between cluster members over PSK-derived
//! mutual TLS. An edge that does not own a session relays its still-encrypted
//! application bytes to the home over this link.
//!
//! Phase 4a lands the TLS foundation ([`tls`]), 4b the stream framing
//! ([`frame`]) and 4c the transport primitives ([`endpoint`], [`peer_pool`],
//! [`pump`]). Wiring these into the accept/relay path is phase 5. See
//! `docs/CLUSTER.md`.

mod control;
mod datagram;
mod endpoint;
mod frame;
mod peer_pool;
mod pump;
mod throttle;
mod tls;

// Re-exported so the transport-side relay dispatch can accept relayed streams
// and wrap them (`MeshCarrier`) into the existing accept path.
//
// The home receiver (T2) consumes `ControlDatagram`/`parse_control_datagram`;
// `encode_throttle_hint` is the edge detector's (T3) sender and has no in-tree
// consumer yet, so keep the unused re-export allow (a phase gate).
#[allow(unused_imports)]
pub(in crate::server) use control::{
    ControlDatagram, encode_throttle_hint, parse_control_datagram,
};
pub(in crate::server) use datagram::{read_datagram, write_datagram};
pub(in crate::server) use endpoint::{MeshEndpoint, MeshStream, accept_relay};
pub(in crate::server) use frame::{CarrierKind, CloseReason, OpenHeader};
pub(in crate::server) use peer_pool::{MeshPeerPool, PooledRelay};
pub(in crate::server) use throttle::ThrottleRegistry;
pub(in crate::server) use tls::MeshIdentity;
