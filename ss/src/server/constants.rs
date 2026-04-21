//! Server tuning constants (HTTP/2, HTTP/3, TCP, UDP, shadowsocks).
//!
//! HTTP/2 and HTTP/3 resource limits live in [`crate::config::TuningProfile`],
//! driven by the `tuning_profile` preset with optional `[tuning]` overrides.

pub(super) const H2_KEEPALIVE_INTERVAL_SECS: u64 = 20;
pub(super) const H2_KEEPALIVE_TIMEOUT_SECS: u64 = 20;

pub(super) const H3_QUIC_IDLE_TIMEOUT_SECS: u64 = 120;
pub(super) const H3_QUIC_PING_INTERVAL_SECS: u64 = 10;
pub(super) const H3_MAX_UDP_PAYLOAD_SIZE: u16 = 1_350;

pub(super) const TCP_CONNECT_TIMEOUT_SECS: u64 = 5;
pub(super) const SS_TCP_HANDSHAKE_TIMEOUT_SECS: u64 = 30;
pub(super) const TCP_HAPPY_EYEBALLS_DELAY_MS: u64 = 250;

pub(super) const UDP_MAX_CONCURRENT_RELAY_TASKS: usize = 256;
pub(super) const SS_MAX_CONCURRENT_TCP_CONNECTIONS: usize = 4_096;
pub(super) const UDP_DNS_CACHE_TTL_SECS: u64 = 30;
// Keep expired entries around for this long so that stale-fallback can serve
// them if the upstream resolver temporarily fails.
pub(super) const DNS_CACHE_STALE_GRACE_SECS: u64 = 3_600;
// How often the background task sweeps entries that exceeded the stale grace.
pub(super) const DNS_CACHE_SWEEP_INTERVAL_SECS: u64 = 300;
pub(super) const MAX_UDP_PAYLOAD_SIZE: usize = 65_507;
pub(super) const UDP_CACHED_USER_INDEX_EMPTY: usize = usize::MAX;
