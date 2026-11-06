#![cfg(feature = "test-tls")]
//! A failing probe stage must say why it failed. The DNS probe used to run
//! under an outer timeout that dropped it before it was recorded, so a probe
//! that never got an answer left no log line and no `result="error"` sample:
//! on the fleet a standby uplink was capped from H3 to H2 about once an hour
//! with nothing to show what had stalled.
//!
//! The probe here targets a UDP socket that never answers. Each cycle must
//! count as a DNS probe error, the first must log a warning naming the step
//! it stalled at, and the rest of the streak must not repeat the warning.
//!
//! Run with:
//! `RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls
//!  --test e2e_probe_failure_reason -- --test-threads=1`.

#[path = "support/failover_harness.rs"]
mod harness;

use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use harness::tls_fixture::TlsFixture;
use harness::*;

type BoxError = Box<dyn std::error::Error>;

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
fn an_unanswered_dns_probe_is_recorded_and_says_where_it_stalled() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("an_unanswered_dns_probe_is_recorded_and_says_where_it_stalled");
        return Ok(());
    }
    let dir = TestDir::new()?;
    let tls = TlsFixture::generate_into(dir.path())?;
    // Bound and kept open, so queries are delivered and silently ignored.
    let silent_dns = UdpSocket::bind("127.0.0.1:0")?;

    let addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(addr)
        .all_paths()
        .with_tls(&tls.leaf_pem, &tls.key_pem)
        .with_h3(addr, &["h3", "vless", "ss"])
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let mut server = ServerProcess::start(&server_cfg_path, &dir.path().join("server.log"), addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    let probe = ProbeSpec {
        enabled: true,
        interval_secs: 2,
        timeout_secs: 3,
        min_failures: 2,
        dns: None,
        liveness_interval_secs: None,
    }
    .with_dns(silent_dns.local_addr()?);
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
        &[("OUTLINE_WS_TEST_TLS_CA_DER", &ca), ("RUST_LOG", "info")],
    )?;
    client.wait_ready(socks.port(), Duration::from_secs(15))?;

    let streak = wait_for(Duration::from_secs(40), || Ok(dns_runs(metrics, "error")? >= 3.0))?;
    let logs = client.logs()?;
    assert!(
        streak,
        "unanswered DNS probes were not counted as errors:\n{logs}\nserver log:\n{}",
        server.logs()?
    );
    assert_eq!(dns_runs(metrics, "success")?, 0.0, "a probe got an answer from a silent target");

    let warnings: Vec<&str> = logs
        .lines()
        .filter(|line| line.contains("probe stage failed") && line.contains("\"dns\""))
        .collect();
    assert_eq!(
        warnings.len(),
        1,
        "a streak of DNS probe failures must warn exactly once:\n{logs}"
    );
    assert!(
        warnings[0].contains("at read"),
        "the warning does not say the probe stalled waiting for the answer:\n{logs}"
    );

    client.stop()?;
    server.kill()?;
    drop(silent_dns);
    Ok(())
}
