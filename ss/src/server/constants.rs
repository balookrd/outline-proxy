//! Server tuning constants (HTTP/2, HTTP/3, TCP, UDP, shadowsocks).
//!
//! HTTP/2 and HTTP/3 resource limits live in [`crate::config::TuningProfile`],
//! driven by the `tuning_profile` preset with optional `[tuning]` overrides.

pub(super) const H2_KEEPALIVE_INTERVAL_SECS: u64 = 20;
pub(super) const H2_KEEPALIVE_TIMEOUT_SECS: u64 = 20;

// Cap on concurrent active TLS connections (handshake + established). Matches
// the plain-TCP shadowsocks cap so a TLS listener cannot spawn unbounded tasks.
pub(super) const TLS_MAX_CONCURRENT_CONNECTIONS: usize = 4_096;
// How long the TLS listener waits for in-flight connections to finish after
// the shutdown signal fires before forcibly aborting remaining tasks.
pub(super) const TLS_GRACEFUL_SHUTDOWN_TIMEOUT_SECS: u64 = 30;

pub(super) const H3_QUIC_IDLE_TIMEOUT_SECS: u64 = 120;
pub(super) const H3_QUIC_PING_INTERVAL_SECS: u64 = 10;
pub(super) const H3_MAX_UDP_PAYLOAD_SIZE: u16 = 1_350;

pub(super) const TCP_CONNECT_TIMEOUT_SECS: u64 = 5;
pub(super) const SS_TCP_HANDSHAKE_TIMEOUT_SECS: u64 = 30;
// Interval at which the server sends WebSocket Ping frames to clients on active
// TCP relay sessions.  The client's WsReadTransport resets its WS_READ_IDLE_TIMEOUT
// on every received frame, including Ping.  Without these Pings the client times
// out (currently 300 s) when the remote target is slow to respond — e.g. during
// a long model-inference step on an SSE/streaming API.  60 s is well below the
// 300 s client timeout and low enough that even a Ping lost to transient packet
// loss is recovered before the timer fires.
pub(super) const WS_TCP_KEEPALIVE_PING_INTERVAL_SECS: u64 = 60;
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
