//! (A) Seamless failover between *sub-uplinks* (wires = primary + fallbacks
//! within a single uplink). A broken primary wire (a `RejectingListener` that
//! resets the handshake) must roll over to a working fallback wire — including
//! across protocols (VLESS↔SS) and carriers (h2c→h1) — while traffic keeps
//! flowing. The switch is confirmed via `tcp_active_wire` advancing 0→1 in the
//! control topology, not just "traffic still worked".
//!
//! `active_passive` + `global` makes the transport strict so the in-session
//! wire failover path is active. Gated behind `RUN_E2E_FAILOVER=1`.
//!
//! The last test in this file (`dead_primary_wire_does_not_flap_to_a_sibling_uplink`)
//! is the boundary case between this file and `e2e_chunk0_cross_uplink.rs` /
//! `e2e_inter_uplink_global.rs`: a wire-level failure that a fallback wire
//! absorbs must never surface as an *uplink*-level runtime failure, or it
//! would flap a two-uplink group off the wire-broken uplink and onto a
//! healthy sibling that never needed to be touched.

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
        "outline_ws_uplink_active_wire_index",
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

/// Task 11's end-to-end coverage: a dead primary carrier must keep a flow on
/// the *same* uplink (by rolling over to its own fallback wire) rather than
/// moving it to a sibling uplink, and doing so must not raise a runtime
/// failure on the parent uplink — that is the entire point of
/// `dial_over_wires` reporting per-wire outcomes to `record_wire_outcome`
/// instead of `report_runtime_failure` while any wire is still left to try
/// (see `crates/outline-uplink/src/manager/wire_dial.rs` module docs).
///
/// This exercises the SOCKS ingress, not TUN: the real subprocess e2e harness
/// this file belongs to (`tests/support/failover_harness.rs` +
/// `config_builder.rs`) has no `[tun]` support at all — `ClientConfig` only
/// ever renders a `[socks5]` listener, and driving a real TUN device would
/// need a network namespace / CAP_NET_ADMIN this harness does not set up. But
/// `dial_over_wires` and the active-wire state machine it drives are the same
/// code both ingresses call (Task 7 deleted the SOCKS ingress's own
/// duplicate), so proving the invariant here through a real client/server
/// subprocess pair proves it for the shared mechanism itself, not just for
/// SOCKS. The TUN-specific half — that `tun_wire_dial` actually reaches this
/// same loop from a TUN TCP packet — is covered separately, and already
/// passes, in
/// `crates/outline-tun/src/tcp/engine/tests/wire_fallback.rs::tun_tcp_falls_back_to_a_sibling_wire_before_leaving_the_uplink`.
///
/// Topology: `nuxt` (declared first, so it is the default active uplink with
/// no runtime history yet) has a dead primary wire and one live fallback wire
/// on `server_a`; `senko` has a healthy primary of its own on `server_b`. If
/// a regression ever turned "primary wire dead" into "uplink dead" (i.e. made
/// `dial_over_wires`'s per-wire failure escape as an uplink-level runtime
/// failure), the connect loop would cross over to `senko` instead of trying
/// `nuxt`'s fallback wire — exactly the failure mode `e2e_chunk0_cross_uplink.rs`
/// exercises deliberately for an uplink with *no* fallback wire.
#[test]
fn dead_primary_wire_does_not_flap_to_a_sibling_uplink() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("dead_primary_wire_does_not_flap_to_a_sibling_uplink");
        return Ok(());
    }

    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    let server_a_addr = reserve_addr()?;
    let server_a_cfg = ServerConfig::new(server_a_addr).all_paths().render();
    let server_a_cfg_path = write_file(dir.path(), "server-a.toml", &server_a_cfg)?;
    let mut server_a =
        ServerProcess::start(&server_a_cfg_path, &dir.path().join("server-a.log"), server_a_addr)?;
    server_a.wait_ready(Duration::from_secs(15))?;

    let server_b_addr = reserve_addr()?;
    let server_b_cfg = ServerConfig::new(server_b_addr).all_paths().render();
    let server_b_cfg_path = write_file(dir.path(), "server-b.toml", &server_b_cfg)?;
    let mut server_b =
        ServerProcess::start(&server_b_cfg_path, &dir.path().join("server-b.log"), server_b_addr)?;
    server_b.wait_ready(Duration::from_secs(15))?;

    // `nuxt`'s primary is a dead endpoint; its only fallback lands on
    // `server_a`. `senko`'s primary is live on its own server, `server_b`, and
    // has no fallback — it must never be dialed at all.
    let dead = RejectingListener::start()?;
    let nuxt = UplinkSpec::new(
        "nuxt",
        Wire::SsWs {
            tcp_url: format!("ws://{}{PATH_SS_TCP}", dead.addr()),
            udp_url: None,
            mode: "ws_h1".into(),
        },
        Creds::ss(),
    )
    .with_fallback(
        Wire::SsWs {
            tcp_url: format!("ws://{server_a_addr}{PATH_SS_TCP}"),
            udp_url: None,
            mode: "ws_h1".into(),
        },
        Creds::ss(),
    );
    let senko = UplinkSpec::new(
        "senko",
        Wire::SsWs {
            tcp_url: format!("ws://{server_b_addr}{PATH_SS_TCP}"),
            udp_url: None,
            mode: "ws_h1".into(),
        },
        Creds::ss(),
    );

    let socks = reserve_addr()?;
    let control = reserve_addr()?;
    let metrics = reserve_addr()?;
    let client_cfg =
        ClientConfig::new(socks, &dir.path().join("c.state.toml"), ProbeSpec::disabled())
            .with_control(control, CONTROL_TOKEN)
            .with_metrics(metrics)
            .group(GroupSpec::new("active_passive", "global").uplink(nuxt).uplink(senko))
            .render();
    let client_cfg_path = write_file(dir.path(), "client.toml", &client_cfg)?;
    let mut client = ProxyProcess::start(&client_cfg_path, &dir.path().join("client.log"))?;
    client
        .wait_ready(socks.port(), Duration::from_secs(15))
        .map_err(|e| format!("{e}\nclient log:\n{}", client.logs().unwrap_or_default()))?;

    // First round-trip: `nuxt`'s dead primary wire fails inside
    // `dial_over_wires`, its fallback wire succeeds, and the flow completes —
    // it must never have reached `senko`.
    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"dead-primary-payload").map_err(|e| {
        format!(
            "round-trip failed: {e}\nclient log:\n{}\nserver-a log:\n{}\nserver-b log:\n{}",
            client.logs().unwrap_or_default(),
            server_a.logs().unwrap_or_default(),
            server_b.logs().unwrap_or_default(),
        )
    })?;

    // A couple more sessions to make the wire advance deterministic, then
    // confirm both that the wire moved within `nuxt` and that `nuxt` (not
    // `senko`) is still the group's active TCP uplink.
    let _ = socks5_echo_attempt(socks.port(), echo.tcp_addr());
    let topo = poll_topology(
        control,
        CONTROL_TOKEN,
        |t| t.tcp_active_wire(GROUP, "nuxt") == Some(1),
        Duration::from_secs(10),
    )?;
    assert_eq!(
        topo.tcp_active_wire(GROUP, "nuxt"),
        Some(1),
        "active wire did not advance to nuxt's fallback; topology:\n{}\nclient log:\n{}",
        topo.raw(),
        client.logs().unwrap_or_default()
    );
    assert_eq!(
        topo.global_active_uplink(GROUP).as_deref(),
        Some("nuxt"),
        "a broken carrier costs one wire, not the server: the active uplink must stay nuxt; \
         topology:\n{}",
        topo.raw()
    );

    // Traffic still flows on nuxt's fallback wire after the switch.
    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"after-switch")?;

    // Metric corroboration, mirroring the reasoning in
    // `e2e_chunk0_cross_uplink.rs`: `dial_over_wires` only reports a wire
    // outcome (`record_wire_outcome`, feeding `tcp_active_wire` above) while a
    // fallback is left to try. It never calls `report_runtime_failure` for an
    // intermediate wire failure — only the caller does, and only once the
    // whole chain is exhausted. So `nuxt`'s dead primary must leave
    // `runtime_failures_total{uplink="nuxt"}` at zero, and `senko` — never
    // dialed at all — must have zero selections.
    let m = metrics_scrape(metrics)?;
    let nuxt_runtime_failures =
        m.sum("outline_ws_uplink_runtime_failures_total", &[("uplink", "nuxt")]);
    assert_eq!(
        nuxt_runtime_failures,
        0.0,
        "one broken wire must not flap the uplink out of the candidate set: \
         got {nuxt_runtime_failures} runtime failures on nuxt\n{}",
        m.raw()
    );
    let senko_selections = m.sum("outline_ws_uplink_selected_total", &[("uplink", "senko")]);
    assert_eq!(
        senko_selections,
        0.0,
        "senko must never have been dialed while nuxt still had a fallback wire\n{}",
        m.raw()
    );
    let nuxt_wire_idx = m.sum(
        "outline_ws_uplink_active_wire_index",
        &[("uplink", "nuxt"), ("transport", "tcp")],
    );
    assert!(
        nuxt_wire_idx >= 1.0,
        "active_wire_index gauge expected >=1, got {nuxt_wire_idx}"
    );

    client.stop()?;
    server_a.kill()?;
    server_b.kill()?;
    Ok(())
}
