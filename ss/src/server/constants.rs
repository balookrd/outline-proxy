//! Server tuning constants (HTTP/2, HTTP/3, TCP, UDP, shadowsocks).

pub(super) const H2_KEEPALIVE_INTERVAL_SECS: u64 = 20;
pub(super) const H2_KEEPALIVE_TIMEOUT_SECS: u64 = 20;
pub(super) const H2_STREAM_WINDOW_BYTES: u32 = 16 * 1024 * 1024; // 16 MB
pub(super) const H2_CONNECTION_WINDOW_BYTES: u32 = 64 * 1024 * 1024; // 64 MB
pub(super) const H2_MAX_SEND_BUF_SIZE: usize = 16 * 1024 * 1024; // 16 MB

pub(super) const H3_QUIC_IDLE_TIMEOUT_SECS: u64 = 120;
pub(super) const H3_QUIC_PING_INTERVAL_SECS: u64 = 10;
// Flow control windows: larger values allow higher throughput at high RTT.
// Stream window must be <= connection window.
pub(super) const H3_STREAM_WINDOW_BYTES: u64 = 16 * 1024 * 1024; // 16 MB (was 8 MB)
pub(super) const H3_CONNECTION_WINDOW_BYTES: u64 = 64 * 1024 * 1024; // 64 MB (was 32 MB)
pub(super) const H3_MAX_CONCURRENT_BIDI_STREAMS: u32 = 4_096;
pub(super) const H3_MAX_CONCURRENT_UNI_STREAMS: u32 = 1_024;
// Larger write buffer reduces per-packet overhead by batching more data per send.
pub(super) const H3_WRITE_BUFFER_BYTES: usize = 512 * 1024; // 512 KB (was 256 KB)
// Higher backpressure threshold avoids dropping connections for transiently slow clients.
pub(super) const H3_MAX_BACKPRESSURE_BYTES: usize = 16 * 1024 * 1024; // 16 MB (was 8 MB)
// Larger OS UDP socket buffers are the primary defense against packet drops under burst load.
// Increase net.core.rmem_max / kern.ipc.maxsockbuf on the host if the OS silently caps this.
pub(super) const H3_UDP_SOCKET_BUFFER_BYTES: usize = 32 * 1024 * 1024; // 32 MB (was 8 MB)
pub(super) const H3_MAX_UDP_PAYLOAD_SIZE: u16 = 1_350;

pub(super) const TCP_CONNECT_TIMEOUT_SECS: u64 = 10;
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
