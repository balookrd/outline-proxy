//! Mesh interconnect transport: QUIC between cluster members over PSK-derived
//! mutual TLS. An edge that does not own a session relays its still-encrypted
//! application bytes to the home over this link.
//!
//! Phase 4a lands the TLS foundation ([`tls`]); the listener, peer pool,
//! framing and pump follow in later sub-phases. See `docs/CLUSTER.md`.

mod tls;
