use std::sync::Arc;

use outline_routing::RoutingTable;
use outline_transport::DnsCache;
use socks5_proto::Socks5AuthConfig;

/// Runtime configuration slice for the proxy layer.
///
/// Built from [`AppConfig`](crate::config::AppConfig) in `run_with_config`
/// after the two-phase init (dns_cache and routing_table are fully resolved)
/// and frozen into an `Arc` that every accepted connection clones cheaply.
///
/// Proxy code depends only on this struct — not on the full `AppConfig` —
/// so the proxy module can be extracted into its own crate later without
/// dragging in the entire configuration domain.
#[derive(Debug)]
pub struct ProxyConfig {
    pub socks5_auth: Option<Socks5AuthConfig>,
    /// DNS cache shared with transport resolve paths; always populated before
    /// the listener accepts connections.
    pub dns_cache: Arc<DnsCache>,
    /// Compiled routing table; `None` when no `[[route]]` is declared
    /// (all traffic goes to the default group).
    pub routing_table: Option<Arc<RoutingTable>>,
    /// SO_MARK applied to outbound sockets for `via = "direct"` routes
    /// (Linux only). Prevents direct traffic from looping back through TUN.
    pub direct_fwmark: Option<u32>,
}
