//! QUIC endpoint / TLS plumbing for the HTTP/3 carrier.
//!
//! The raw-QUIC forward carriers (VLESS / Shadowsocks framed directly over
//! QUIC) have been removed; the only remaining consumer of this module is the
//! HTTP/3 carrier (`crate::h3`), which negotiates the [`ALPN_H3`] ALPN and
//! reuses the shared per-AF endpoint and client-config builder in
//! [`tls_config`].

#![cfg(feature = "quic")]

mod tls_config;

pub(crate) use tls_config::h3_quic_client_config;
pub use tls_config::init_quic_window_sizes;

/// ALPN identifier for HTTP/3 (used by the `crate::h3` module).
pub const ALPN_H3: &[u8] = b"h3";
