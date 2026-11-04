//! QUIC endpoint / TLS plumbing for the HTTP/3 carrier.
//!
//! The raw-QUIC forward carriers (VLESS / Shadowsocks framed directly over
//! QUIC) have been removed; the only remaining consumer of this module is the
//! HTTP/3 carrier (`crate::h3`), which negotiates the [`ALPN_H3`] ALPN and
//! takes its browser-shaped client and endpoint configs from [`tls_config`]
//! (each dial owns its endpoint).

#![cfg(feature = "quic")]

#[cfg(test)]
#[path = "tests/loopback.rs"]
mod loopback;
#[cfg(feature = "h3")]
pub(crate) mod pmtu_cache;
mod tls_config;
pub(crate) mod tls_profile;
mod tp_profile;
mod vendored;

#[cfg(feature = "h3")]
pub use pmtu_cache::init_pmtu_cache;
#[cfg(feature = "h3")]
pub(crate) use tls_config::h3_dial_offers_udp_datagrams;
#[cfg(test)]
pub(crate) use tls_config::h3_quic_client_config;
pub(crate) use tls_config::{
    h3_endpoint_config, h3_quic_client_config_with_first_probe, raise_h3_receive_window,
};
pub use tls_config::{
    init_quic_idle_timeout, init_quic_keepalive_interval, init_quic_udp_datagrams,
    init_quic_window_sizes,
};

/// ALPN identifier for HTTP/3 (used by the `crate::h3` module).
pub const ALPN_H3: &[u8] = b"h3";
