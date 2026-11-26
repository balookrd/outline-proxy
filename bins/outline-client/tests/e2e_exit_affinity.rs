//! End-to-end test for fast L4 failover (< 5s) and cluster Exit Affinity
//! (`x-outline-home-affinity`) on real `outline-server` and `outline-client`
//! binaries.
//!
//! Gated behind `RUN_E2E_FAILOVER=1`.

#[path = "support/failover_harness.rs"]
mod harness;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use harness::*;
use tokio::net::TcpListener;
use tokio::runtime::{Builder, Runtime};

type BoxError = Box<dyn std::error::Error>;

const CLUSTER_PSK_B64: &str = "ZTJlLWV4aXQtYWZmaW5pdHktbWVzaC1wc2stMDE=";

/// Local TCP forwarder that can be cut so new client dials immediately hit
/// `ConnectionRefused` (`L4ConnectError` -> `EndpointUnreachable`) while the
/// backend server stays alive on its mesh port.
struct CuttableForwarder {
    addr: SocketAddr,
    cut: Arc<AtomicBool>,
    _rt: Runtime,
}

impl CuttableForwarder {
    fn start(target: SocketAddr) -> std::io::Result<Self> {
        let rt = Builder::new_multi_thread().worker_threads(1).enable_all().build()?;
        let cut = Arc::new(AtomicBool::new(false));
        let (listener, addr) = rt.block_on(async {
            let l = TcpListener::bind(("127.0.0.1", 0)).await?;
            let a = l.local_addr()?;
            std::io::Result::Ok((l, a))
        })?;
        let cut_flag = Arc::clone(&cut);
        rt.spawn(async move {
            loop {
                if cut_flag.load(Ordering::Acquire) {
                    drop(listener);
                    break;
                }
                let accept =
                    tokio::time::timeout(Duration::from_millis(50), listener.accept()).await;
                let Ok(Ok((mut client, _))) = accept else {
                    continue;
                };
                if cut_flag.load(Ordering::Acquire) {
                    drop(client);
                    drop(listener);
                    break;
                }
                tokio::spawn(async move {
                    if let Ok(mut server) = tokio::net::TcpStream::connect(target).await {
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                    }
                });
            }
        });
        Ok(Self { addr, cut, _rt: rt })
    }

    fn cut(&self) {
        self.cut.store(true, Ordering::Release);
        // Wake up the accept loop if it is parked and ensure listener drops.
        let _ = std::net::TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
    }
}

#[test]
fn fast_failover_preserves_exit_affinity_via_mesh_and_clears_on_manual_switch()
-> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("fast_failover_preserves_exit_affinity_via_mesh_and_clears_on_manual_switch");
        return Ok(());
    }

    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    let srv_a_addr = reserve_addr()?;
    let srv_a_mesh = reserve_udp_addr()?;
    let srv_a_metrics = reserve_addr()?;
    let srv_b_addr = reserve_addr()?;
    let srv_b_mesh = reserve_udp_addr()?;
    let srv_b_metrics = reserve_addr()?;

    let peers = vec![(1, srv_a_mesh), (2, srv_b_mesh)];
    let srv_a_cfg = ServerConfig::new(srv_a_addr)
        .all_paths()
        .with_session_resumption(65_536)
        .with_metrics(srv_a_metrics)
        .with_cluster(1, CLUSTER_PSK_B64, srv_a_mesh, peers.clone())
        .render();
    let srv_a_cfg_path = write_file(dir.path(), "server-a.toml", &srv_a_cfg)?;
    let mut server_a =
        ServerProcess::start(&srv_a_cfg_path, &dir.path().join("server-a.log"), srv_a_addr)?;
    server_a.wait_ready(Duration::from_secs(15))?;

    let srv_b_cfg = ServerConfig::new(srv_b_addr)
        .all_paths()
        .with_session_resumption(65_536)
        .with_metrics(srv_b_metrics)
        .with_cluster(2, CLUSTER_PSK_B64, srv_b_mesh, peers)
        .render();
    let srv_b_cfg_path = write_file(dir.path(), "server-b.toml", &srv_b_cfg)?;
    let mut server_b =
        ServerProcess::start(&srv_b_cfg_path, &dir.path().join("server-b.log"), srv_b_addr)?;
    server_b.wait_ready(Duration::from_secs(15))?;

    let fwd_a = CuttableForwarder::start(srv_a_addr)?;

    let mut up_a = UplinkSpec::new(
        "up-a",
        Wire::SsWs {
            tcp_url: format!("ws://{}{PATH_SS_TCP}", fwd_a.addr),
            udp_url: Some(format!("ws://{}{PATH_SS_UDP}", fwd_a.addr)),
            mode: "ws_h1".into(),
        },
        Creds::ss(),
    );
    up_a.weight = 1.0;
    let mut up_b = UplinkSpec::new(
        "up-b",
        Wire::SsWs {
            tcp_url: format!("ws://{srv_b_addr}{PATH_SS_TCP}"),
            udp_url: Some(format!("ws://{srv_b_addr}{PATH_SS_UDP}")),
            mode: "ws_h1".into(),
        },
        Creds::ss(),
    );
    up_b.weight = 0.5;

    let socks = reserve_addr()?;
    let control = reserve_addr()?;
    let client_metrics = reserve_addr()?;
    let client_cfg = ClientConfig::new(socks, &dir.path().join("c.state.toml"), ProbeSpec::fast())
        .with_control(control, CONTROL_TOKEN)
        .with_metrics(client_metrics)
        .group(
            GroupSpec::new("active_passive", "global")
                .with_shared_resume(true)
                .uplink(up_a)
                .uplink(up_b),
        )
        .render();
    let client_cfg_path = write_file(dir.path(), "client.toml", &client_cfg)?;
    let mut client = ProxyProcess::start(&client_cfg_path, &dir.path().join("client.log"))?;
    client
        .wait_ready(socks.port(), Duration::from_secs(15))
        .map_err(|e| format!("{e}\nclient log:\n{}", client.logs().unwrap_or_default()))?;

    // 1. Initial session goes through up-a (weight 1.0 > 0.5), pinning home shard 1.
    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"initial-home-a")?;
    let topo = poll_topology(
        control,
        CONTROL_TOKEN,
        |t| t.global_active_uplink(GROUP).as_deref() == Some("up-a"),
        Duration::from_secs(10),
    )?;
    assert_eq!(topo.global_active_uplink(GROUP).as_deref(), Some("up-a"));

    // 2. Cut direct client path to server-a (mesh to server-a stays alive).
    fwd_a.cut();
    let failover_start = Instant::now();
    let switched = poll_until(
        || {
            let _ = socks5_echo_attempt(socks.port(), echo.tcp_addr());
            get_topology(control, CONTROL_TOKEN)
                .map(|t| t.global_active_uplink(GROUP).as_deref() == Some("up-b"))
                .unwrap_or(false)
        },
        Duration::from_secs(5),
    );
    let failover_elapsed = failover_start.elapsed();
    assert!(
        switched,
        "failover from up-a to up-b did not complete within 5s (elapsed {failover_elapsed:?})\nclient log:\n{}",
        client.logs().unwrap_or_default()
    );

    // 3. Brand-new TCP session over up-b must egress from server-a via mesh.
    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"via-edge-b-to-home-a")?;

    let mesh_seen = poll_until(
        || {
            let b_ok = metrics_scrape(srv_b_metrics)
                .map(|m| m.sum("outline_ss_mesh_relay_opened_total", &[("outcome", "ok")]) >= 1.0)
                .unwrap_or(false);
            let a_ok = metrics_scrape(srv_a_metrics)
                .map(|m| {
                    m.sum(
                        "outline_ss_mesh_bytes_total",
                        &[("role", "home"), ("direction", "up"), ("transport", "tcp")],
                    ) > 0.0
                })
                .unwrap_or(false);
            b_ok && a_ok
        },
        Duration::from_secs(5),
    );
    assert!(
        mesh_seen,
        "new session after failover did not use exit affinity over mesh\nserver-b metrics:\n{}\nserver-a metrics:\n{}",
        metrics_scrape(srv_b_metrics)?.raw(),
        metrics_scrape(srv_a_metrics)?.raw(),
    );
    let mesh_opened_before_manual = metrics_scrape(srv_b_metrics)?
        .sum("outline_ss_mesh_relay_opened_total", &[("outcome", "ok")]);

    // 4. Manual switch clears home affinity; subsequent new session exits directly from server-b.
    post_activate(control, CONTROL_TOKEN, GROUP, "up-b", false)?;
    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"direct-from-b-after-manual")?;
    std::thread::sleep(Duration::from_millis(1200));
    let mesh_opened_after_manual = metrics_scrape(srv_b_metrics)?
        .sum("outline_ss_mesh_relay_opened_total", &[("outcome", "ok")]);
    assert_eq!(
        mesh_opened_after_manual, mesh_opened_before_manual,
        "manual switch must clear home affinity so subsequent sessions exit directly from server-b"
    );

    client.stop()?;
    server_a.kill()?;
    server_b.kill()?;
    Ok(())
}
