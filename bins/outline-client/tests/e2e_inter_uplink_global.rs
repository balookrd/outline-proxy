//! (C) Inter-uplink failover in `routing_scope = "global"` (`active_passive`).
//! Two uplinks, each on its own real server. Killing the active uplink's server
//! makes the probe flip it unhealthy; the next sessions re-select and the global
//! active uplink moves to the survivor — including across protocols (SS↔VLESS).
//! Confirmed via `global_active_uplink` in the control topology. Gated behind
//! `RUN_E2E_FAILOVER=1`.

#[path = "support/failover_harness.rs"]
mod harness;

use std::net::SocketAddr;
use std::time::Duration;

use harness::*;

type BoxError = Box<dyn std::error::Error>;

/// Two live servers, one uplink each. `up-a` (index 0) should start active;
/// after its server is killed the global active must move to `up-b`.
fn run_global_failover_case(
    mk_a: impl FnOnce(SocketAddr) -> (Wire, Creds),
    mk_b: impl FnOnce(SocketAddr) -> (Wire, Creds),
) -> Result<(), BoxError> {
    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    let a_addr = reserve_addr()?;
    let a_cfg = ServerConfig::new(a_addr).all_paths().render();
    let a_cfg_path = write_file(dir.path(), "server-a.toml", &a_cfg)?;
    let mut server_a = ServerProcess::start(&a_cfg_path, &dir.path().join("server-a.log"), a_addr)?;
    server_a.wait_ready(Duration::from_secs(15))?;

    let b_addr = reserve_addr()?;
    let b_cfg = ServerConfig::new(b_addr).all_paths().render();
    let b_cfg_path = write_file(dir.path(), "server-b.toml", &b_cfg)?;
    let mut server_b = ServerProcess::start(&b_cfg_path, &dir.path().join("server-b.log"), b_addr)?;
    server_b.wait_ready(Duration::from_secs(15))?;

    let (a_wire, a_creds) = mk_a(a_addr);
    let (b_wire, b_creds) = mk_b(b_addr);

    let socks = reserve_addr()?;
    let control = reserve_addr()?;
    let metrics = reserve_addr()?;
    let client_cfg = ClientConfig::new(socks, &dir.path().join("c.state.toml"), ProbeSpec::fast())
        .with_control(control, CONTROL_TOKEN)
        .with_metrics(metrics)
        .group(
            GroupSpec::new("active_passive", "global")
                .uplink(UplinkSpec::new("up-a", a_wire, a_creds))
                .uplink(UplinkSpec::new("up-b", b_wire, b_creds)),
        )
        .render();
    let client_cfg_path = write_file(dir.path(), "client.toml", &client_cfg)?;
    let mut client = ProxyProcess::start(&client_cfg_path, &dir.path().join("client.log"))?;
    client
        .wait_ready(socks.port(), Duration::from_secs(15))
        .map_err(|e| format!("{e}\nclient log:\n{}", client.logs().unwrap_or_default()))?;

    // Warm up + wait for the probe to settle on *some* global active. Which of
    // two equal-weight uplinks wins the initial selection is not fixed, so
    // discover it dynamically and kill that one's server.
    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"global-warmup").map_err(|e| {
        format!(
            "warmup round-trip failed: {e}\nclient log:\n{}",
            client.logs().unwrap_or_default()
        )
    })?;
    let topo = poll_topology(
        control,
        CONTROL_TOKEN,
        |t| t.global_active_uplink(GROUP).is_some(),
        Duration::from_secs(15),
    )?;
    let initial = topo
        .global_active_uplink(GROUP)
        .ok_or_else(|| format!("no global active uplink selected; topology:\n{}", topo.raw()))?;

    // Kill the active uplink's server; its probe flips unhealthy and new
    // sessions re-select onto the survivor.
    let survivor = match initial.as_str() {
        "up-a" => {
            server_a.kill()?;
            "up-b"
        },
        "up-b" => {
            server_b.kill()?;
            "up-a"
        },
        other => return Err(format!("unexpected initial active uplink: {other}").into()),
    };

    let switched = poll_until(
        || {
            // Drive a fresh session each tick so the lazy global re-selection runs.
            let _ = socks5_echo_attempt(socks.port(), echo.tcp_addr());
            get_topology(control, CONTROL_TOKEN)
                .map(|t| t.global_active_uplink(GROUP).as_deref() == Some(survivor))
                .unwrap_or(false)
        },
        Duration::from_secs(25),
    );
    let topo = get_topology(control, CONTROL_TOKEN)?;
    assert!(
        switched,
        "global active did not move from {initial} to {survivor} after killing its server; \
         topology:\n{}\nclient log:\n{}",
        topo.raw(),
        client.logs().unwrap_or_default()
    );

    // Traffic flows through the survivor.
    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"after-global-failover")?;

    client.stop()?;
    server_a.kill()?;
    server_b.kill()?;
    Ok(())
}

fn ss_ws(addr: SocketAddr) -> (Wire, Creds) {
    (
        Wire::SsWs {
            tcp_url: format!("ws://{addr}{PATH_SS_TCP}"),
            udp_url: None,
            mode: "ws_h1".into(),
        },
        Creds::ss(),
    )
}

fn vless_ws(addr: SocketAddr) -> (Wire, Creds) {
    (
        Wire::VlessWs {
            url: format!("ws://{addr}{PATH_VLESS_WS}"),
            mode: "ws_h1".into(),
        },
        Creds::vless(),
    )
}

#[test]
fn global_failover_ss_to_ss_kill_active() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("global_failover_ss_to_ss_kill_active");
        return Ok(());
    }
    run_global_failover_case(ss_ws, ss_ws)
}

#[test]
fn global_failover_ss_to_vless_kill_active() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("global_failover_ss_to_vless_kill_active");
        return Ok(());
    }
    run_global_failover_case(ss_ws, vless_ws)
}

#[test]
fn global_failover_vless_to_ss_kill_active() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("global_failover_vless_to_ss_kill_active");
        return Ok(());
    }
    run_global_failover_case(vless_ws, ss_ws)
}
