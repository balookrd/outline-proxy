//! (A) Seamless failover between *sub-uplinks* (wires = primary + fallbacks
//! within a single uplink). A broken primary wire (a `RejectingListener` that
//! resets the handshake) must roll over to a working fallback wire — including
//! across protocols (VLESS↔SS) and carriers (h2c→h1) — while traffic keeps
//! flowing. The switch is confirmed via `tcp_active_wire` advancing 0→1 in the
//! control topology, not just "traffic still worked".
//!
//! `active_passive` + `global` makes the transport strict so the in-session
//! wire failover path is active. Gated behind `RUN_E2E_FAILOVER=1`.

#[path = "support/failover_harness.rs"]
mod harness;

use std::time::Duration;

use harness::*;

type BoxError = Box<dyn std::error::Error>;

/// Build a one-uplink client whose primary wire points at a dead endpoint and
/// whose single fallback points at the live server, drive traffic, and assert
/// the active wire advances to the fallback while the echo round-trip succeeds.
fn run_wire_failover_case(
    primary_on_dead: impl FnOnce(std::net::SocketAddr) -> (Wire, Creds),
    fallback_on_server: impl FnOnce(std::net::SocketAddr) -> (Wire, Creds),
) -> Result<(), BoxError> {
    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    let server_addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(server_addr).all_paths().render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let mut server =
        ServerProcess::start(&server_cfg_path, &dir.path().join("server.log"), server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    // Broken primary wire: a listener that accepts then instantly resets.
    let dead = RejectingListener::start()?;
    let (primary_wire, primary_creds) = primary_on_dead(dead.addr());
    let (fallback_wire, fallback_creds) = fallback_on_server(server_addr);

    let uplink = UplinkSpec::new("up-a", primary_wire, primary_creds)
        .with_fallback(fallback_wire, fallback_creds);

    let socks = reserve_addr()?;
    let control = reserve_addr()?;
    let metrics = reserve_addr()?;
    let client_cfg =
        ClientConfig::new(socks, &dir.path().join("c.state.toml"), ProbeSpec::disabled())
            .with_control(control, CONTROL_TOKEN)
            .with_metrics(metrics)
            .group(GroupSpec::new("active_passive", "global").uplink(uplink))
            .render();
    let client_cfg_path = write_file(dir.path(), "client.toml", &client_cfg)?;
    let mut client = ProxyProcess::start(&client_cfg_path, &dir.path().join("client.log"))?;
    client
        .wait_ready(socks.port(), Duration::from_secs(15))
        .map_err(|e| format!("{e}\nclient log:\n{}", client.logs().unwrap_or_default()))?;

    // First round-trip rolls over to the fallback wire in-session and records
    // the dial failure on the primary, advancing the sticky active wire.
    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"wire-failover-payload").map_err(
        |e| {
            format!(
                "round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
                client.logs().unwrap_or_default(),
                server.logs().unwrap_or_default()
            )
        },
    )?;

    // A couple more sessions to make the advance deterministic, then confirm.
    let _ = socks5_echo_attempt(socks.port(), echo.tcp_addr());
    let topo = poll_topology(
        control,
        CONTROL_TOKEN,
        |t| t.tcp_active_wire(GROUP, "up-a") == Some(1),
        Duration::from_secs(10),
    )?;
    assert_eq!(
        topo.tcp_active_wire(GROUP, "up-a"),
        Some(1),
        "active wire did not advance to the fallback; topology:\n{}\nclient log:\n{}",
        topo.raw(),
        client.logs().unwrap_or_default()
    );

    // Traffic still flows on the fallback wire after the switch.
    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"after-switch")?;

    // Metric corroboration: the failover counter moved (any tcp-flavoured
    // failover label), and the active-wire gauge reads the fallback index.
    let m = metrics_scrape(metrics)?;
    let wire_idx = m.sum(
        "outline_ws_rust_uplink_active_wire_index",
        &[("uplink", "up-a"), ("transport", "tcp")],
    );
    assert!(wire_idx >= 1.0, "active_wire_index gauge expected >=1, got {wire_idx}");

    client.stop()?;
    server.kill()?;
    Ok(())
}

#[test]
fn wire_failover_ss_ws_h1_to_ss_ws_h1() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("wire_failover_ss_ws_h1_to_ss_ws_h1");
        return Ok(());
    }
    run_wire_failover_case(
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
fn wire_failover_cross_protocol_vless_ws_to_ss_xhttp() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("wire_failover_cross_protocol_vless_ws_to_ss_xhttp");
        return Ok(());
    }
    run_wire_failover_case(
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

#[test]
fn wire_failover_cross_protocol_ss_xhttp_to_vless_ws() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("wire_failover_cross_protocol_ss_xhttp_to_vless_ws");
        return Ok(());
    }
    run_wire_failover_case(
        |dead| {
            (
                Wire::SsXhttp {
                    tcp_url: format!("http://{dead}{PATH_SS_XHTTP}"),
                    mode: "xhttp_h1".into(),
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
fn wire_failover_same_protocol_carrier_h2c_to_h1() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("wire_failover_same_protocol_carrier_h2c_to_h1");
        return Ok(());
    }
    run_wire_failover_case(
        |dead| {
            (
                Wire::SsWs {
                    tcp_url: format!("ws://{dead}{PATH_SS_TCP}"),
                    udp_url: None,
                    mode: "ws_h2".into(),
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
fn wire_failover_no_advance_when_primary_healthy() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("wire_failover_no_advance_when_primary_healthy");
        return Ok(());
    }
    // Primary points at the live server; the fallback (on a dead endpoint) must
    // never be touched and the active wire must stay pinned at 0.
    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;
    let server_addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(server_addr).all_paths().render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let mut server =
        ServerProcess::start(&server_cfg_path, &dir.path().join("server.log"), server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    let dead = RejectingListener::start()?;
    let uplink = UplinkSpec::new(
        "up-a",
        Wire::SsWs {
            tcp_url: format!("ws://{server_addr}{PATH_SS_TCP}"),
            udp_url: None,
            mode: "ws_h1".into(),
        },
        Creds::ss(),
    )
    .with_fallback(
        Wire::SsWs {
            tcp_url: format!("ws://{}{PATH_SS_TCP}", dead.addr()),
            udp_url: None,
            mode: "ws_h1".into(),
        },
        Creds::ss(),
    );

    let socks = reserve_addr()?;
    let control = reserve_addr()?;
    let client_cfg =
        ClientConfig::new(socks, &dir.path().join("c.state.toml"), ProbeSpec::disabled())
            .with_control(control, CONTROL_TOKEN)
            .group(GroupSpec::new("active_passive", "global").uplink(uplink))
            .render();
    let client_cfg_path = write_file(dir.path(), "client.toml", &client_cfg)?;
    let mut client = ProxyProcess::start(&client_cfg_path, &dir.path().join("client.log"))?;
    client.wait_ready(socks.port(), Duration::from_secs(15))?;

    for _ in 0..3 {
        socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"healthy-primary")?;
    }
    let topo = get_topology(control, CONTROL_TOKEN)?;
    assert_eq!(
        topo.tcp_active_wire(GROUP, "up-a"),
        Some(0),
        "active wire must stay on the healthy primary; topology:\n{}",
        topo.raw()
    );

    client.stop()?;
    server.kill()?;
    Ok(())
}
