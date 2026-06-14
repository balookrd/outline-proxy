#![allow(dead_code, unused_imports)]
//! Facade tying the e2e support modules together. Test files include only this
//! one module (`#[path = "support/failover_harness.rs"] mod harness;`); the
//! pieces are nested submodules here so they can reference each other (e.g.
//! `traffic` → `super::proxy_test_utils`).
//!
//! Provides the shared env-gate, a polling helper, and ephemeral-address
//! reservation on top of the existing `proxy_test_utils` primitives.

#[path = "proxy_test_utils.rs"]
pub mod proxy_test_utils;

#[path = "config_builder.rs"]
pub mod config_builder;
#[path = "control_client.rs"]
pub mod control_client;
#[path = "echo_upstream.rs"]
pub mod echo_upstream;
#[path = "fault_injection.rs"]
pub mod fault_injection;
#[path = "server_process.rs"]
pub mod server_process;
#[cfg(feature = "test-tls")]
#[path = "tls_fixture.rs"]
pub mod tls_fixture;
#[path = "traffic.rs"]
pub mod traffic;

pub use config_builder::{
    ClientConfig, Creds, GroupSpec, PATH_SS_TCP, PATH_SS_UDP, PATH_SS_XHTTP, PATH_VLESS_WS,
    PATH_VLESS_XHTTP, ProbeSpec, ServerConfig, TEST_METHOD, TEST_PASSWORD, TEST_VLESS_ID,
    UplinkSpec, Wire,
};
pub use control_client::{Metrics, Topology, get_topology, metrics_scrape};
pub use echo_upstream::EchoUpstream;
pub use fault_injection::{BlackholeListener, MidSessionBreaker, RejectingListener};
pub use proxy_test_utils::{ProxyProcess, TestDir, reserve_tcp_port};
pub use server_process::ServerProcess;
pub use traffic::{ContinuousEcho, socks5_echo_attempt, socks5_echo_roundtrip, socks5_udp_echo};

use std::fs;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

type BoxError = Box<dyn std::error::Error>;

/// Bearer token wired into both the client `[control]` section and the
/// harness's topology reads.
pub const CONTROL_TOKEN: &str = "e2e-control-token";

/// The group name every builder uses (single group → no `[[route]]` needed).
pub const GROUP: &str = "default";

/// True when `RUN_E2E_FAILOVER=1`. The tests are slow (subprocess spawns,
/// second-scale failover windows) and gated off by default, mirroring the
/// existing `real_server_h*` tests.
pub fn e2e_enabled() -> bool {
    std::env::var("RUN_E2E_FAILOVER").ok().as_deref() == Some("1")
}

pub fn skip_notice(name: &str) {
    eprintln!("skipping e2e test `{name}`; set RUN_E2E_FAILOVER=1 to enable");
}

/// Reserve an ephemeral loopback TCP address (bind :0 → record → drop). There
/// is a TOCTOU window, but `--test-threads=1` keeps it small; callers reserve
/// immediately before spawning the process that binds it.
pub fn reserve_addr() -> Result<SocketAddr, BoxError> {
    let port = reserve_tcp_port()?;
    Ok(SocketAddr::from(([127, 0, 0, 1], port)))
}

/// Reserve an ephemeral loopback UDP address (for the H3/QUIC listener).
pub fn reserve_udp_addr() -> Result<SocketAddr, BoxError> {
    let sock = UdpSocket::bind(("127.0.0.1", 0))?;
    let addr = sock.local_addr()?;
    drop(sock);
    Ok(SocketAddr::from(([127, 0, 0, 1], addr.port())))
}

/// Write `contents` to `dir/name` and return the path.
pub fn write_file(dir: &Path, name: &str, contents: &str) -> Result<PathBuf, BoxError> {
    let path = dir.join(name);
    fs::write(&path, contents)?;
    Ok(path)
}

/// Poll `pred` every 100 ms until it returns `true` or `timeout` elapses.
/// Returns whether the predicate was satisfied.
pub fn poll_until<F: FnMut() -> bool>(mut pred: F, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if pred() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Poll the client's topology until `pred(&Topology)` holds or `timeout`
/// elapses; returns the last fetched topology (so the caller can assert on it
/// either way and print it on failure).
pub fn poll_topology<F: Fn(&Topology) -> bool>(
    control: SocketAddr,
    token: &str,
    pred: F,
    timeout: Duration,
) -> Result<Topology, BoxError> {
    let deadline = Instant::now() + timeout;
    loop {
        let topo = get_topology(control, token)?;
        if pred(&topo) || Instant::now() >= deadline {
            return Ok(topo);
        }
        thread::sleep(Duration::from_millis(150));
    }
}
