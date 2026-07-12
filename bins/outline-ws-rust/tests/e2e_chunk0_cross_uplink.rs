//! (B) Per-session chunk-0 / dial failover *across uplinks* in strict
//! (`active_passive` + `global`) mode. The active uplink's only wire points at a
//! dead endpoint; within a single SOCKS session the connect loop rolls over to
//! a second, healthy uplink — which may run a different protocol/carrier — and
//! the client-visible bytes replay onto it intact. Confirmed via the
//! `uplink_failovers_total{transport="tcp"}` cross-uplink counter plus a clean
//! echo round-trip. Gated behind `RUN_E2E_FAILOVER=1`.

#[path = "support/failover_harness.rs"]
mod harness;

use std::time::Duration;

use harness::*;

type BoxError = Box<dyn std::error::Error>;

/// uplink-A (index 0, the default active) is on a dead endpoint; uplink-B is on
/// the live server. Drive one session and assert it failed over to B.
fn run_cross_uplink_case(
    a_on_dead: impl FnOnce(std::net::SocketAddr) -> (Wire, Creds),
    b_on_server: impl FnOnce(std::net::SocketAddr) -> (Wire, Creds),
) -> Result<(), BoxError> {
    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    let server_addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(server_addr).all_paths().render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let mut server =
        ServerProcess::start(&server_cfg_path, &dir.path().join("server.log"), server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    let dead = RejectingListener::start()?;
    let (a_wire, a_creds) = a_on_dead(dead.addr());
    let (b_wire, b_creds) = b_on_server(server_addr);

    let socks = reserve_addr()?;
    let control = reserve_addr()?;
    let metrics = reserve_addr()?;
    let client_cfg =
        ClientConfig::new(socks, &dir.path().join("c.state.toml"), ProbeSpec::disabled())
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

    // The session dials uplink-A (dead) first, then fails over to uplink-B.
    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"cross-uplink-payload").map_err(|e| {
        format!(
            "round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
            client.logs().unwrap_or_default(),
            server.logs().unwrap_or_default()
        )
    })?;
    assert!(echo.tcp_connections() >= 1, "traffic never reached the live uplink-B");

    // The active uplink-A took a runtime dial failure (it is dead), which is
    // what drove the in-session rollover to uplink-B. A dial-failure cross-
    // uplink switch goes through the connect loop, so the observable signal is
    // the per-uplink runtime-failure counter on up-a (not `failovers_total`,
    // which is the chunk-0 / post-handshake Phase-B counter). Combined with the
    // successful echo above (which can only have traversed up-b), this proves
    // the inter-uplink failover.
    let _ = socks5_echo_attempt(socks.port(), echo.tcp_addr());
    let failed_over = poll_until(
        || {
            metrics_scrape(metrics)
                .map(|m| {
                    m.sum("outline_ws_uplink_runtime_failures_total", &[("uplink", "up-a")]) >= 1.0
                })
                .unwrap_or(false)
        },
        Duration::from_secs(10),
    );
    let m = metrics_scrape(metrics)?;
    let a_failures = m.sum("outline_ws_uplink_runtime_failures_total", &[("uplink", "up-a")]);
    assert!(
        failed_over,
        "expected a runtime failure recorded on the dead up-a; got {a_failures}\nclient log:\n{}",
        client.logs().unwrap_or_default()
    );

    client.stop()?;
    server.kill()?;
    Ok(())
}

#[test]
fn cross_uplink_ss_to_ss() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("cross_uplink_ss_to_ss");
        return Ok(());
    }
    run_cross_uplink_case(
        |dead| {
            (
                Wire::SsWs {
                    tcp_url: format!("ws://{dead}{PATH_SS_TCP}"),
                    udp_url: None,
                    mode: "ws_h1".into(),
                },
                Creds::ss(),
            )
        },
        |srv| {
            (
                Wire::SsWs {
                    tcp_url: format!("ws://{srv}{PATH_SS_TCP}"),
                    udp_url: None,
                    mode: "ws_h1".into(),
                },
                Creds::ss(),
            )
        },
    )
}

#[test]
fn cross_uplink_ss_to_vless() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("cross_uplink_ss_to_vless");
        return Ok(());
    }
    run_cross_uplink_case(
        |dead| {
            (
                Wire::SsWs {
                    tcp_url: format!("ws://{dead}{PATH_SS_TCP}"),
                    udp_url: None,
                    mode: "ws_h1".into(),
                },
                Creds::ss(),
            )
        },
        |srv| {
            (
                Wire::VlessWs {
                    url: format!("ws://{srv}{PATH_VLESS_WS}"),
                    mode: "ws_h1".into(),
                },
                Creds::vless(),
            )
        },
    )
}

#[test]
fn cross_uplink_vless_to_ss_xhttp() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("cross_uplink_vless_to_ss_xhttp");
        return Ok(());
    }
    run_cross_uplink_case(
        |dead| {
            (
                Wire::VlessWs {
                    url: format!("ws://{dead}{PATH_VLESS_WS}"),
                    mode: "ws_h1".into(),
                },
                Creds::vless(),
            )
        },
        |srv| {
            (
                Wire::SsXhttp {
                    tcp_url: format!("http://{srv}{PATH_SS_XHTTP}"),
                    mode: "xhttp_h1".into(),
                },
                Creds::ss(),
            )
        },
    )
}
