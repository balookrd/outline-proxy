//! (F) UDP sub-uplink wire failover. A single SS-over-WS uplink whose primary
//! UDP wire points at a dead endpoint must roll the UDP transport over to its
//! fallback UDP wire while a SOCKS5 UDP ASSOCIATE datagram round-trips intact.
//! Confirmed via `udp_active_wire` advancing 0→1 in the control topology. The
//! TCP wire stays healthy throughout, so this isolates the per-transport
//! (UDP-only) active-wire state machine. Gated behind `RUN_E2E_FAILOVER=1`.

#[path = "support/failover_harness.rs"]
mod harness;

use std::time::Duration;

use harness::*;

type BoxError = Box<dyn std::error::Error>;

#[test]
fn udp_wire_failover_ss_ws() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("udp_wire_failover_ss_ws");
        return Ok(());
    }

    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    let server_addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(server_addr).all_paths().render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let mut server =
        ServerProcess::start(&server_cfg_path, &dir.path().join("server.log"), server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    // Primary UDP wire is dead; the TCP wire and the fallback UDP wire are live.
    let dead = RejectingListener::start()?;
    let uplink = UplinkSpec::new(
        "up-a",
        Wire::SsWs {
            tcp_url: format!("ws://{server_addr}{PATH_SS_TCP}"),
            udp_url: Some(format!("ws://{}{PATH_SS_UDP}", dead.addr())),
            mode: "ws_h1".into(),
        },
        Creds::ss(),
    )
    .with_fallback(
        Wire::SsWs {
            tcp_url: format!("ws://{server_addr}{PATH_SS_TCP}"),
            udp_url: Some(format!("ws://{server_addr}{PATH_SS_UDP}")),
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
    client
        .wait_ready(socks.port(), Duration::from_secs(15))
        .map_err(|e| format!("{e}\nclient log:\n{}", client.logs().unwrap_or_default()))?;

    // Drive UDP through the tunnel; the primary UDP wire fails and the session
    // rolls over to the fallback UDP wire, which echoes our datagram.
    let payload = b"udp-failover-datagram";
    let echoed = socks5_udp_echo(socks.port(), echo.udp_addr(), payload).map_err(|e| {
        format!(
            "UDP echo failed: {e}\nclient log:\n{}\nserver log:\n{}",
            client.logs().unwrap_or_default(),
            server.logs().unwrap_or_default()
        )
    })?;
    assert_eq!(echoed, payload, "UDP datagram came back corrupted");

    // A second datagram makes the UDP active-wire advance deterministic.
    let _ = socks5_udp_echo(socks.port(), echo.udp_addr(), payload);
    let topo = poll_topology(
        control,
        CONTROL_TOKEN,
        |t| t.udp_active_wire(GROUP, "up-a") == Some(1),
        Duration::from_secs(10),
    )?;
    assert_eq!(
        topo.udp_active_wire(GROUP, "up-a"),
        Some(1),
        "UDP active wire did not advance to the fallback; topology:\n{}\nclient log:\n{}",
        topo.raw(),
        client.logs().unwrap_or_default()
    );

    client.stop()?;
    server.kill()?;
    Ok(())
}
