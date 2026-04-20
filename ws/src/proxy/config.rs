use std::sync::Arc;
use std::time::Duration;

use outline_transport::DnsCache;
use socks5_proto::Socks5AuthConfig;

use super::router::Router;

/// TCP session timeouts (previously compile-time constants).
///
/// `post_client_eof_downstream` — bound for the downstream side to flush and
/// send FIN after the client half-closes; otherwise stuck half-open sessions
/// pin two socket FDs forever.
///
/// `upstream_response` — chunk-0 response deadline per uplink when no
/// failover is available (strict or exhausted candidates).
///
/// `socks_upstream_idle` — kills a SOCKS-through-uplink session when BOTH
/// directions have been silent (no real payload) for this long. Keepalive
/// frames do NOT reset the timer.
///
/// `direct_idle` — same semantics but for direct (bypass-routed) sessions.
#[derive(Debug, Clone, Copy)]
pub struct TcpTimeouts {
    pub post_client_eof_downstream: Duration,
    pub upstream_response: Duration,
    pub socks_upstream_idle: Duration,
    pub direct_idle: Duration,
}

impl TcpTimeouts {
    pub const DEFAULT: Self = Self {
        post_client_eof_downstream: Duration::from_secs(30),
        upstream_response: Duration::from_secs(15),
        socks_upstream_idle: Duration::from_secs(300),
        direct_idle: Duration::from_secs(120),
    };
}

impl Default for TcpTimeouts {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Runtime configuration slice for the proxy layer.
///
/// Built from [`AppConfig`](crate::config::AppConfig) in `run_with_config`
/// after the two-phase init (dns_cache and router are fully resolved)
/// and frozen into an `Arc` that every accepted connection clones cheaply.
///
/// Proxy code depends only on this struct — not on the full `AppConfig` —
/// and routing is abstracted behind the [`Router`] trait, so the proxy
/// module can be extracted into its own crate later without dragging in
/// `outline-routing` or the configuration domain.
#[derive(Debug)]
pub struct ProxyConfig {
    pub socks5_auth: Option<Socks5AuthConfig>,
    /// DNS cache shared with transport resolve paths; always populated before
    /// the listener accepts connections.
    pub dns_cache: Arc<DnsCache>,
    /// Policy router; `None` when no `[[route]]` is declared
    /// (all traffic goes to the default group).
    pub router: Option<Arc<dyn Router>>,
    /// SO_MARK applied to outbound sockets for `via = "direct"` routes
    /// (Linux only). Prevents direct traffic from looping back through TUN.
    pub direct_fwmark: Option<u32>,
    /// TCP session timeouts applied to SOCKS CONNECT and direct sessions.
    pub tcp_timeouts: TcpTimeouts,
}
