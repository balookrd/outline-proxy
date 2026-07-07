//! Mesh interconnect transport: QUIC between cluster members over PSK-derived
//! mutual TLS. An edge that does not own a session relays its still-encrypted
//! application bytes to the home over this link.
//!
//! Phase 4a lands the TLS foundation ([`tls`]), 4b the stream framing
//! ([`frame`]) and 4c the transport primitives ([`endpoint`], [`peer_pool`],
//! [`pump`]). Wiring these into the accept/relay path is phase 5. See
//! `docs/CLUSTER.md`.

mod endpoint;
mod frame;
mod peer_pool;
mod pump;
mod tls;

// Re-exported so the transport-side `MeshCarrier` (a `WsSocket` adapter) can
// wrap a relayed stream and feed it into the existing accept path.
pub(in crate::server) use endpoint::MeshStream;
