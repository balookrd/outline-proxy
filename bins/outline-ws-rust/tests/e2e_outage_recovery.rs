//! Recovery from a *total* outage when no probe is configured.
//!
//! This is the shape the generated Android profile ships (`ops/access-keys/
//! ws_toml.py` writes no `[probe]` section at all): every wire of every uplink
//! fails at once — the phone's active SIM changes, the old cellular network
//! disappears with it — and once connectivity is back the client has to climb
//! out on its own. With probe off, real traffic is the only health signal, so
//! the dial path is the only thing that can clear `healthy = Some(false)` and
//! the cooldown that `shuffle_wires` round exhaustion stamps.
//!
//! The outage is modelled as "the server stops answering, then answers again on
//! the same address": both halves of the trap are the same as on the phone —
//! every wire fails, the uplink is confirmed down, and nothing external pokes
//! the client afterwards.
//!
//! Gated behind `RUN_E2E_FAILOVER=1`.

#[path = "support/failover_harness.rs"]
mod harness;

use std::time::Duration;

use harness::*;

type BoxError = Box<dyn std::error::Error>;

/// Wire on `addr` carrying SS over plain WS, one per carrier mode so the
/// fallback chain looks like the generated profile's (primary + fallbacks).
fn ss_ws_wire(addr: std::net::SocketAddr, mode: &str) -> (Wire, Creds) {
    (
        Wire::SsWs {
            tcp_url: format!("ws://{addr}{PATH_SS_TCP}"),
            udp_url: None,
            mode: mode.into(),
        },
        Creds::ss(),
    )
}

#[test]
fn uplink_recovers_after_total_outage_without_probe() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("uplink_recovers_after_total_outage_without_probe");
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

    // One uplink, a primary plus two fallback wires, `shuffle_wires` on — the
    // generated Android profile's shape, so round exhaustion is reachable.
    let (primary, primary_creds) = ss_ws_wire(server_addr, "ws_h1");
    let (fb1, fb1_creds) = ss_ws_wire(server_addr, "ws_h1");
    let (fb2, fb2_creds) = ss_ws_wire(server_addr, "ws_h1");
    let mut uplink = UplinkSpec::new("up-a", primary, primary_creds)
        .with_fallback(fb1, fb1_creds)
        .with_fallback(fb2, fb2_creds);
    uplink.shuffle_wires = Some(true);

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

    // Baseline: the link works, so `healthy` is Some(true) and every wire has a
    // recorded success — the state the phone is in before the SIM switch.
    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"before-outage").map_err(|e| {
        format!(
            "baseline round-trip failed: {e}\nclient log:\n{}",
            client.logs().unwrap_or_default()
        )
    })?;

    // Outage: every wire now fails. A handful of sessions walks the whole
    // fallback chain and confirms the uplink down.
    server.kill()?;
    for _ in 0..6 {
        let _ = socks5_echo_attempt(socks.port(), echo.tcp_addr());
    }
    assert!(
        socks5_echo_attempt(socks.port(), echo.tcp_addr()).is_err(),
        "traffic still flowed with the server down; the outage did not take"
    );

    // Connectivity returns: same address, fresh server — as far as the client
    // is concerned the path is usable again and nothing told it so.
    let mut server =
        ServerProcess::start(&server_cfg_path, &dir.path().join("server2.log"), server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    // The client must climb out by itself, without a restart.
    let recovered = poll_until(
        || socks5_echo_attempt(socks.port(), echo.tcp_addr()).is_ok(),
        Duration::from_secs(90),
    );
    let topo = get_topology(control, CONTROL_TOKEN)
        .map(|t| t.raw().to_string())
        .unwrap_or_default();
    assert!(
        recovered,
        "uplink never recovered after connectivity returned (no probe configured)\n\
         topology:\n{topo}\nclient log:\n{}\nserver log:\n{}",
        client.logs().unwrap_or_default(),
        server.logs().unwrap_or_default()
    );

    client.stop()?;
    server.kill()?;
    Ok(())
}
