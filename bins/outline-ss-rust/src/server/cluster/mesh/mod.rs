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
// and wrap them (`MeshCarrier`) into the existing accept path. The home receiver
// consumes `ControlDatagram`/`parse_control_datagram` (T2); the edge detector
// sends via `encode_throttle_hint` (T3).
pub(in crate::server) use control::{
    ControlDatagram, encode_throttle_hint, parse_control_datagram,
};
pub(in crate::server) use datagram::{read_datagram, write_datagram};
pub(in crate::server) use endpoint::{
    AcceptRelayError, MeshEndpoint, MeshStream, accept_relay, write_open_ack,
};
pub(in crate::server) use frame::{
    CarrierKind, CloseIntent, CloseReason, MAX_USER_LEN, MeshFraming, MeshProtocol, OpenHeader,
    OpenHeaderV5, RelayOpen, UPSTREAM_ACK_FRAME_LEN, UpstreamAckFrame, UserFrame,
};
// Setup-phase constant the *reading* peer needs. The edge reads the ack through
// `PooledRelay::await_ack`, so outside this module only the test standing in for
// an edge names the byte itself.
#[cfg(test)]
pub(in crate::server) use frame::OPEN_ACK_ACCEPTED;
pub(in crate::server) use peer_pool::{MeshPeerPool, PooledRelay};
pub(in crate::server) use throttle::ThrottleRegistry;
pub(in crate::server) use tls::MeshIdentity;
