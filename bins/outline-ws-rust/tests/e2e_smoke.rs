//! E2e smoke test: stand up a real `outline-ss-rust` server + `outline-ws-rust`
//! client + local echo upstream, drive one SS-over-WS round-trip through SOCKS5,
//! and confirm the control/metrics planes are readable. No fault injection —
//! this validates the harness wiring that the failover tests build on.
//!
//! Gated behind `RUN_E2E_FAILOVER=1`; runs nothing in a plain `cargo test`.

#[path = "support/failover_harness.rs"]
mod harness;

use std::time::Duration;

use harness::*;

type BoxError = Box<dyn std::error::Error>;

#[test]
fn smoke_ss_ws_h1_roundtrip_and_control_planes() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("smoke_ss_ws_h1_roundtrip_and_control_planes");
        return Ok(());
    }

    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    // ── Server: one process serving every cleartext path ──
    let server_addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(server_addr).all_paths().render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let server_log = dir.path().join("server.log");
    let mut server = ServerProcess::start(&server_cfg_path, &server_log, server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    // ── Client: single group, one SS-over-WS-h1 uplink ──
    let socks = reserve_addr()?;
    let control = reserve_addr()?;
    let metrics = reserve_addr()?;
    let state_path = dir.path().join("client.state.toml");

    let uplink = UplinkSpec::new(
        "up-a",
        Wire::SsWs {
            tcp_url: format!("ws://{server_addr}{PATH_SS_TCP}"),
            udp_url: Some(format!("ws://{server_addr}{PATH_SS_UDP}")),
            mode: "ws_h1".into(),
        },
        Creds::ss(),
    );
    let client_cfg = ClientConfig::new(socks, &state_path, ProbeSpec::disabled())
        .with_control(control, CONTROL_TOKEN)
        .with_metrics(metrics)
        .group(GroupSpec::new("active_active", "per_flow").uplink(uplink))
        .render();
    let client_cfg_path = write_file(dir.path(), "client.toml", &client_cfg)?;
    let client_log = dir.path().join("client.log");
    let mut client = ProxyProcess::start(&client_cfg_path, &client_log)?;
    client
        .wait_ready(socks.port(), Duration::from_secs(15))
        .map_err(|e| format!("{e}\nclient log:\n{}", client.logs().unwrap_or_default()))?;

    // ── Traffic: SS-over-WS round-trip through the tunnel ──
    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"hello-outline-e2e").map_err(|e| {
        format!(
            "round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
            client.logs().unwrap_or_default(),
            server.logs().unwrap_or_default()
        )
    })?;
    assert!(echo.tcp_connections() >= 1, "server never reached the echo upstream");

    // ── Control plane: topology JSON is readable and shows our group/uplink ──
    let topo = get_topology(control, CONTROL_TOKEN)?;
    assert!(
        topo.tcp_active_wire(GROUP, "up-a").is_some(),
        "topology missing tcp_active_wire for up-a: {}",
        topo.raw()
    );

    // ── Metrics plane: scrape returns Prometheus text ──
    let m = metrics_scrape(metrics)?;
    assert!(m.raw().contains("outline_ws_rust"), "metrics scrape looked empty");

    client.stop()?;
    server.kill()?;
    Ok(())
}
