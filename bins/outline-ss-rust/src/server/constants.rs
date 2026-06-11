//! Server tuning constants (HTTP/2, HTTP/3, TCP, UDP, shadowsocks).
//!
//! HTTP/2 and HTTP/3 resource limits live in [`crate::config::TuningProfile`],
//! driven by the `tuning_profile` preset with optional `[tuning]` overrides.

pub(super) const H2_KEEPALIVE_INTERVAL_SECS: u64 = 20;
pub(super) const H2_KEEPALIVE_TIMEOUT_SECS: u64 = 20;

// Cap on concurrent active TLS connections (handshake + established). Matches
// the plain-TCP shadowsocks cap so a TLS listener cannot spawn unbounded tasks.
pub(super) const TLS_MAX_CONCURRENT_CONNECTIONS: usize = 4_096;
// How long an HTTP listener (plain TCP, TLS, metrics) waits for in-flight
// connections to finish after the shutdown signal fires before forcibly
// aborting them. Required because hyper's graceful shutdown keeps the
// per-connection task alive for the full lifetime of upgraded WebSocket
// streams; without this cap the process never exits on SIGTERM and systemd
// has to SIGKILL after the unit's TimeoutStopSec.
pub(super) const HTTP_GRACEFUL_SHUTDOWN_TIMEOUT_SECS: u64 = 10;

pub(super) const H3_QUIC_IDLE_TIMEOUT_SECS: u64 = 120;
pub(super) const H3_QUIC_PING_INTERVAL_SECS: u64 = 10;
pub(super) const H3_MAX_UDP_PAYLOAD_SIZE: u16 = 1_350;
// Cap on concurrent active HTTP/3 QUIC connections. Matches the TLS listener
// so an attacker cannot force unbounded per-connection task spawns by opening
// many QUIC handshakes in parallel.
pub(super) const H3_MAX_CONCURRENT_CONNECTIONS: usize = 4_096;
// Global cap on concurrent in-flight WebSocket streams across all HTTP/3
// connections.  Per-connection stream concurrency is already bounded by
// `tuning.h3_max_concurrent_bidi_streams`, but without a global limit the
// total fan-out is `connections * streams_per_connection`, which at the
// throughput profile would allow millions of spawned tasks.  Sized to give
// plenty of headroom for legitimate multiplexed traffic while keeping total
// fan-out bounded.
pub(super) const H3_MAX_CONCURRENT_STREAMS: usize = 65_536;

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
/// If no inbound WS frame (Pong, Binary, Ping or Close) is observed for
/// `WS_TCP_KEEPALIVE_PING_INTERVAL_SECS * WS_PONG_DEADLINE_MULTIPLIER`
/// seconds, the relay tears down the session. This catches silently-dead
/// clients (mobile in tunnel, NAT-rebind, ISP black-hole) much faster
/// than the underlying TCP/QUIC keepalive — the latter can take minutes
/// or never fire — preventing UDP-upstream sockets and 64 KiB reader
/// buffers from being held by half-dead sessions for the full transport
/// idle window. A multiplier of 3 means we tolerate two missed pongs
/// before declaring the peer gone.
pub(super) const WS_PONG_DEADLINE_MULTIPLIER: u32 = 3;
/// Cadence at which the per-session WebSocket writer task flushes any
/// control-frame responses its split reader has buffered — chiefly a
/// `Pong` queued in reply to a client keepalive `Ping`. On the H3 carrier
/// the vendored `sockudo-ws` split reader swallows the inbound Ping and
/// parks the Pong in an internal channel that is only drained when the
/// writer next runs `process_control_requests` (via `send`/`flush`). On a
/// quiet UDP datagram channel the writer would otherwise never run — no
/// downlink packets, and the SS-UDP relay sends no server-originated
/// Ping — so the Pong would sit unsent until the client's
/// `WS_READ_IDLE_TIMEOUT` (300 s on outline-ws-rust) trips and tears the
/// session down. Pumping a flush on this cadence delivers that Pong
/// WITHOUT writing a server-originated Ping: an unconditional Ping write
/// is unsafe on H3, where it races stream teardown on a `shuffle_timer`
/// reroll and escalates to a connection-level `H3_INTERNAL_ERROR` that
/// kills every multiplexed stream on the QUIC connection. 30 s is an
/// order of magnitude inside the 300 s client watchdog, so even several
/// dropped flushes leave a wide margin.
pub(super) const WS_CONTROL_FLUSH_INTERVAL_SECS: u64 = 30;
pub(super) const TCP_HAPPY_EYEBALLS_DELAY_MS: u64 = 250;

pub(super) const UDP_MAX_CONCURRENT_RELAY_TASKS: usize = 256;
pub(super) const SS_MAX_CONCURRENT_TCP_CONNECTIONS: usize = 4_096;
pub(super) const UDP_DNS_CACHE_TTL_SECS: u64 = 30;
// Keep expired entries around for this long so that stale-fallback can serve
// them if the upstream resolver temporarily fails.
pub(super) const DNS_CACHE_STALE_GRACE_SECS: u64 = 3_600;
// How often the background task sweeps entries that exceeded the stale grace.
pub(super) const DNS_CACHE_SWEEP_INTERVAL_SECS: u64 = 300;
// Theoretical upper bound of a UDP datagram including headers (2^16 − 1).
// Used to size the receive buffer where the kernel may hand us the full
// datagram before we trim to the header-less payload.
pub(super) const MAX_UDP_DATAGRAM_SIZE: usize = 65_535;
// RFC 768: max UDP payload over IPv4 = 65 535 − 20 (IP) − 8 (UDP).
pub(super) const MAX_UDP_PAYLOAD_SIZE: usize = 65_507;
pub(super) const UDP_CACHED_USER_INDEX_EMPTY: usize = usize::MAX;

// Bounded LRU mapping `peer_addr -> user_index`, queried before each TCP
// handshake to skip the O(N) AEAD-decryption probe when we already saw this
// peer authenticate against a known user. ~4k entries cover the active
// keep-alive set of a multi-tenant deployment without unbounded growth; a
// stale entry (cipher mismatch, user removed, list reorder) self-heals on the
// next successful scan because we record the freshly observed user index.
pub(super) const TCP_PEER_USER_CACHE_CAPACITY: usize = 4_096;

// Bounded mpsc capacity for the per-session WebSocket writer's control fan-in
// (Pong / Close frames). Data fan-in capacity is configurable per deployment
// via `tuning.ws_data_channel_capacity` — see `crate::config::TuningProfile`.
pub(super) const WS_CTRL_CHANNEL_CAPACITY: usize = 8;

// Period at which the background task sweeps idle NAT entries and stale
// replay-filter sessions.
pub(super) const NAT_EVICTION_INTERVAL_SECS: u64 = 60;

// How often the orphan-registry sweeper wakes to evict TTL-expired parked
// sessions. The TTL itself (per-kind) lives on the resumption config; this
// only bounds the lag between a deadline passing and the entry being
// reclaimed. Five seconds matches `docs/SESSION-RESUMPTION.md`.
pub(super) const ORPHAN_SWEEP_INTERVAL_SECS: u64 = 5;

// Period at which the XHTTP registry janitor evicts idle / closed
// sessions. Sessions whose `XhttpSession::touch` last ran more than
// `SESSION_IDLE_EVICTION` ago are dropped on the next tick. 30 s
// caps the leak window for a session that was created by the GET
// handler but whose relay never started (client disconnected before
// the first POST landed) — without this, dead sessions accumulate
// in the `XhttpRegistry` for the lifetime of the process.
pub(super) const XHTTP_EVICTION_INTERVAL_SECS: u64 = 30;

// How often the certificate watcher polls the configured TLS cert/key
// files for changes. On a detected change it rebuilds the affected
// listener's TLS config and installs it for new connections (established
// connections keep the cert they negotiated). Polling — rather than an
// inotify/kqueue watch — is deliberate: it is dependency-free and robust
// to the atomic rename / symlink swap that ACME clients (certbot, lego,
// acme.sh) perform on renewal, where a watch pinned to the original inode
// would silently stop firing. Certs rotate rarely (ACME renews weeks
// before expiry), so a 5-minute poll is plenty responsive while keeping
// the steady-state cost to a handful of small file reads every few
// minutes.
pub(super) const CERT_RELOAD_POLL_INTERVAL_SECS: u64 = 300;
