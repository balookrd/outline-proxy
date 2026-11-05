#![cfg(feature = "test-tls")]
//! The DNS probe reuses a warm UDP transport across cycles. On an uplink that
//! carries traffic the regular probe cycle is skipped and runs only every
//! `liveness_interval`, while the warm-slot keepalive stays off because the
//! configured probe interval is short. The server meanwhile reaps the idle
//! probe session at its pong deadline (3 × its keepalive tick, 180 s in
//! production), so the next liveness cycle finds the warm transport dead. That cycle must redial
//! instead of reporting a failed probe and capping the UDP carrier from H3 to
//! H2 — the fleet saw one such cap every ten minutes on each active uplink.
//!
//! The server's `test-hooks` build shortens its keepalive to
//! [`SERVER_KEEPALIVE_SECS`], so the reap takes seconds, not three minutes.
//!
//! Run with:
//! `RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls
//!  --test e2e_warm_probe_retry -- --test-threads=1`.

#[path = "support/failover_harness.rs"]
mod harness;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use harness::tls_fixture::TlsFixture;
use harness::*;

type BoxError = Box<dyn std::error::Error>;

/// Server keepalive tick for this test; the pong deadline is three of them.
const SERVER_KEEPALIVE_SECS: u64 = 5;

/// Longer than the server's idle reap (3 × [`SERVER_KEEPALIVE_SECS`] deadline,
/// checked on each keepalive tick).
const LIVENESS_SECS: u64 = 30;

/// DNS probe runs with the given `result` label (`success` / `error`).
fn dns_runs(metrics: SocketAddr, result: &str) -> Result<f64, BoxError> {
    Ok(metrics_scrape(metrics)?
        .sum("outline_ws_probe_runs_total", &[("probe", "dns"), ("result", result)]))
}

/// Poll until `cond` holds or `timeout` passes.
fn wait_for(
    timeout: Duration,
    mut cond: impl FnMut() -> Result<bool, BoxError>,
) -> Result<bool, BoxError> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond()? {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(500));
    }
    Ok(false)
}

#[test]
fn reaped_warm_udp_probe_transport_is_redialled_not_reported() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("reaped_warm_udp_probe_transport_is_redialled_not_reported");
        return Ok(());
    }
    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;
    let tls = TlsFixture::generate_into(dir.path())?;

    // One port number for the TLS/TCP listener and the H3/QUIC listener, as on
    // the fleet: the client reaches both (cert check, H2 fallback) by the URL.
    let addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(addr)
        .all_paths()
        .with_tls(&tls.leaf_pem, &tls.key_pem)
        .with_h3(addr, &["h3", "vless", "ss"])
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let keepalive = SERVER_KEEPALIVE_SECS.to_string();
    let mut server = ServerProcess::start_with_env(
        &server_cfg_path,
        &dir.path().join("server.log"),
        addr,
        &[("OUTLINE_SS_TEST_WS_KEEPALIVE_SECS", &keepalive)],
    )?;
    server.wait_ready(Duration::from_secs(15))?;

    // A 10 s interval keeps the warm-slot keepalive off (it only runs when the
    // interval exceeds its own 20 s period), exactly as on the fleet.
    let probe = ProbeSpec {
        enabled: true,
        interval_secs: 10,
        timeout_secs: 10,
        min_failures: 2,
        dns: None,
        liveness_interval_secs: None,
    }
    .with_dns(echo.udp_addr())
    .with_liveness_interval(LIVENESS_SECS);
    let wire = Wire::VlessXhttp {
        url: format!("https://127.0.0.1:{}{PATH_VLESS_XHTTP}", addr.port()),
        mode: "xhttp_h3".into(),
    };
    let socks = reserve_addr()?;
    let metrics = reserve_addr()?;
    let client_cfg = ClientConfig::new(socks, &dir.path().join("c.state.toml"), probe)
        .with_metrics(metrics)
        .group(GroupSpec::new("active_passive", "global").uplink(UplinkSpec::new(
            "up-a",
            wire,
            Creds::vless(),
        )))
        .render();
    let client_cfg_path = write_file(dir.path(), "client.toml", &client_cfg)?;
    let ca = tls.ca_der.to_string_lossy().to_string();
    let mut client = ProxyProcess::start_with_env(
        &client_cfg_path,
        &dir.path().join("client.log"),
        &[("OUTLINE_WS_TEST_TLS_CA_DER", &ca), ("RUST_LOG", "info,outline_uplink=debug")],
    )?;
    client.wait_ready(socks.port(), Duration::from_secs(15))?;

    // The startup cycle stashes its transport in the warm slot.
    let first = wait_for(Duration::from_secs(30), || Ok(dns_runs(metrics, "success")? >= 1.0))?;
    assert!(
        first,
        "the first DNS probe never succeeded:\n{}\nserver log:\n{}",
        client.logs()?,
        server.logs()?
    );
    let successes = dns_runs(metrics, "success")?;
    let errors = dns_runs(metrics, "error")?;

    // Live traffic makes the scheduler skip every cycle until the liveness one.
    let stop = Arc::new(AtomicBool::new(false));
    let traffic = {
        let stop = Arc::clone(&stop);
        let echo_addr = echo.tcp_addr();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = socks5_echo_attempt(socks.port(), echo_addr);
                thread::sleep(Duration::from_secs(2));
            }
        })
    };

    let next = wait_for(Duration::from_secs(LIVENESS_SECS + 40), || {
        Ok(dns_runs(metrics, "success")? + dns_runs(metrics, "error")? > successes + errors)
    });
    stop.store(true, Ordering::Relaxed);
    let _ = traffic.join();
    let next = next?;

    let logs = client.logs()?;
    let server_logs = server.logs()?;
    assert!(next, "the liveness probe cycle never ran:\n{logs}\nserver log:\n{server_logs}");
    assert!(
        logs.contains("skipping probe cycle"),
        "traffic never made the scheduler skip a cycle, so the test proved nothing:\n{logs}"
    );
    assert!(
        server_logs.contains("pong deadline exceeded"),
        "the server never reaped the idle probe session, so the test proved nothing:\n{server_logs}"
    );
    assert_eq!(
        dns_runs(metrics, "error")?,
        errors,
        "a reaped warm transport was reported as a failed DNS probe:\n{logs}"
    );
    assert!(
        !logs.contains("UDP probe failed"),
        "a reaped warm transport capped the UDP carrier:\n{logs}"
    );
    assert!(
        logs.contains("warm DNS probe transport failed, retrying with a fresh dial"),
        "the liveness cycle never retried past the reaped warm transport, so the test proved nothing:\n{logs}"
    );

    client.stop()?;
    server.kill()?;
    Ok(())
}
