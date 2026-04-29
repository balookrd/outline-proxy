use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use url::Url;

use outline_transport::{ServerAddr, TransportMode};
use outline_uplink::UplinkTransport;
use shadowsocks_crypto::CipherKind;

#[derive(Debug, Clone, Parser)]
#[command(version, about = "SOCKS5 -> Outline over WebSocket proxy")]
pub struct Args {
    #[arg(long, env = "PROXY_CONFIG", default_value = "config.toml")]
    pub config: PathBuf,

    #[arg(long, env = "SOCKS5_LISTEN")]
    pub listen: Option<SocketAddr>,

    #[arg(long, env = "SOCKS5_USERNAME")]
    pub socks5_username: Option<String>,

    #[arg(long, env = "SOCKS5_PASSWORD")]
    pub socks5_password: Option<String>,

    #[arg(long, env = "OUTLINE_TCP_WS_URL")]
    pub tcp_ws_url: Option<Url>,

    #[arg(long, env = "OUTLINE_TRANSPORT")]
    pub transport: Option<UplinkTransport>,

    #[arg(long, env = "OUTLINE_TCP_WS_MODE", help = "http1, h2, or h3")]
    pub tcp_ws_mode: Option<TransportMode>,

    #[arg(long, env = "OUTLINE_UDP_WS_URL")]
    pub udp_ws_url: Option<Url>,

    #[arg(long, env = "OUTLINE_TCP_ADDR")]
    pub tcp_addr: Option<ServerAddr>,

    #[arg(long, env = "OUTLINE_UDP_ADDR")]
    pub udp_addr: Option<ServerAddr>,

    #[arg(long, env = "OUTLINE_UDP_WS_MODE", help = "http1, h2, or h3")]
    pub udp_ws_mode: Option<TransportMode>,

    /// VLESS-only: single WS URL serving both TCP and UDP. Required when
    /// `transport = "vless"` and `vless_mode` is a `ws_*` / `quic`
    /// variant. Mutually exclusive with `tcp_ws_url`/`udp_ws_url`.
    #[arg(long, env = "OUTLINE_VLESS_WS_URL")]
    pub vless_ws_url: Option<Url>,

    /// VLESS-only: base URL for XHTTP packet-up. Required when
    /// `vless_mode` is `xhttp_h2` / `xhttp_h3`. The session id is
    /// appended at dial time (single path segment).
    #[arg(long, env = "OUTLINE_VLESS_XHTTP_URL")]
    pub vless_xhttp_url: Option<Url>,

    /// VLESS-only: dial mode. One of ws_h1, ws_h2, ws_h3, quic,
    /// xhttp_h2, xhttp_h3.
    #[arg(long, env = "OUTLINE_VLESS_MODE", help = "ws_h1, ws_h2, ws_h3, quic, xhttp_h2, xhttp_h3")]
    pub vless_mode: Option<TransportMode>,

    #[arg(long, env = "SHADOWSOCKS_METHOD")]
    pub method: Option<CipherKind>,

    #[arg(long, env = "SHADOWSOCKS_PASSWORD")]
    pub password: Option<String>,

    #[arg(long, env = "OUTLINE_FWMARK")]
    pub fwmark: Option<u32>,

    #[arg(long, env = "OUTLINE_IPV6_FIRST")]
    pub ipv6_first: Option<bool>,

    #[arg(long, env = "METRICS_LISTEN")]
    pub metrics_listen: Option<SocketAddr>,

    /// Bind address for the control-plane HTTP listener. Required in
    /// combination with `--control-token`/`CONTROL_TOKEN`.
    #[arg(long, env = "CONTROL_LISTEN")]
    pub control_listen: Option<SocketAddr>,

    /// Bearer token required on every control-plane request. Must be set
    /// whenever the control listener is enabled.
    #[arg(long, env = "CONTROL_TOKEN")]
    pub control_token: Option<String>,

    #[cfg(feature = "tun")]
    #[arg(long, env = "TUN_PATH")]
    pub tun_path: Option<PathBuf>,

    #[cfg(feature = "tun")]
    #[arg(long, env = "TUN_NAME")]
    pub tun_name: Option<String>,

    #[cfg(feature = "tun")]
    #[arg(long, env = "TUN_MTU")]
    pub tun_mtu: Option<usize>,

    /// Number of tokio worker threads (default: number of CPU cores).
    /// Set to 1 on weak/single-core routers.
    #[arg(long, env = "WORKER_THREADS")]
    pub worker_threads: Option<usize>,

    /// Stack size per tokio worker thread in KiB (default: 2048 KiB = 2 MiB).
    /// Reduce to 512 on memory-constrained routers with multiple worker threads.
    /// Has no effect when worker_threads=1 (current_thread scheduler has no extra threads).
    #[arg(long, env = "THREAD_STACK_SIZE_KB")]
    pub thread_stack_size_kb: Option<usize>,

    /// Path for persisting active-uplink state across restarts.
    /// Overrides the default (config path with .state.toml extension) and
    /// the state_path key in the config file.
    #[arg(long, env = "STATE_PATH")]
    pub state_path: Option<PathBuf>,

    /// Migrate the config file in place from the legacy top-level uplink
    /// shape to the current `[outline]`-grouped shape, then exit. Intended to
    /// be run from a writable context when the service itself cannot persist
    /// the migration (e.g. `ProtectSystem=strict` with a read-only /etc).
    #[arg(long)]
    pub migrate_config: bool,
}
