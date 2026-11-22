//! (G) End-to-end SS-UDP soft switch across a 2-node mesh cluster with
//! `warm_standby_udp = 1`.
//!
//! Reproduces the live `gw-1` (`nuxt2 -> nuxt`) scenario on real `outline-server`
//! and `outline-client` binaries:
//! - Two clustered `outline-server` nodes (`shard_id` 1 and 2) connected over
//!   the QUIC mesh with `[session_resumption] enabled = true`.
//! - `outline-client` configured with `shared_resume = true` and
//!   `warm_standby_udp = 1` in `active_passive` / `global` mode.
//! - An active SOCKS5 UDP association sends a datagram over `up-a`, warming a
//!   standby socket on `up-b` in the background.
//! - An operator soft switch (`POST /control/activate {"soft": true}`) moves
//!   the group to `up-b`.
//! - A subsequent datagram on the same association must survive via mesh relay:
//!   `up-b`'s pre-warmed socket stays untouched (`warm_standby_acquire` for
//!   `up-b` stays 0), `server-b` (edge) opens a mesh relay, `server-a` (home)
//!   records `outline_ss_orphan_resume_hit_total{kind="ss_udp_stream"} >= 1`,
//!   mesh datagrams flow in both directions, and the echo upstream sees the
//!   exact same source `IP:port` before and after the switch.
//! - A subsequent brand-new UDP association on `up-b` (with no `SessionId`)
//!   still consumes `up-b`'s pre-warmed socket with 0-RTT.
//!
//! Gated behind `RUN_E2E_FAILOVER=1`.

#[path = "support/failover_harness.rs"]
mod harness;

use std::time::Duration;

use harness::*;

type BoxError = Box<dyn std::error::Error>;

const CLUSTER_PSK_B64: &str = "ZTJlLXVkcC1zb2Z0LXN3aXRjaC1tZXNoLXBzay0wMQ==";

#[test]
fn udp_soft_switch_ss_ws_with_warm_standby_preserves_source_port_via_mesh() -> Result<(), BoxError>
{
    if !e2e_enabled() {
        skip_notice("udp_soft_switch_ss_ws_with_warm_standby_preserves_source_port_via_mesh");
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

    let up_a = UplinkSpec::new(
        "up-a",
        Wire::SsWs {
            tcp_url: format!("ws://{srv_a_addr}{PATH_SS_TCP}"),
            udp_url: Some(format!("ws://{srv_a_addr}{PATH_SS_UDP}")),
            mode: "ws_h1".into(),
        },
        Creds::ss(),
    );
    let up_b = UplinkSpec::new(
        "up-b",
        Wire::SsWs {
            tcp_url: format!("ws://{srv_b_addr}{PATH_SS_TCP}"),
            udp_url: Some(format!("ws://{srv_b_addr}{PATH_SS_UDP}")),
            mode: "ws_h1".into(),
        },
        Creds::ss(),
    );

    let socks = reserve_addr()?;
    let control = reserve_addr()?;
    let client_metrics = reserve_addr()?;
    let client_cfg =
        ClientConfig::new(socks, &dir.path().join("c.state.toml"), ProbeSpec::disabled())
            .with_control(control, CONTROL_TOKEN)
            .with_metrics(client_metrics)
            .group(
                GroupSpec::new("active_passive", "global")
                    .with_shared_resume(true)
                    .with_warm_standby_udp(1)
                    .uplink(up_a)
                    .uplink(up_b),
            )
            .render();
    let client_cfg_path = write_file(dir.path(), "client.toml", &client_cfg)?;
    let mut client = ProxyProcess::start(&client_cfg_path, &dir.path().join("client.log"))?;
    client
        .wait_ready(socks.port(), Duration::from_secs(15))
        .map_err(|e| format!("{e}\nclient log:\n{}", client.logs().unwrap_or_default()))?;

    // Pin initial traffic on `up-a` and wait until `up-b`'s UDP warm-standby
    // pool has 1 pre-warmed socket ready.
    post_activate(control, CONTROL_TOKEN, GROUP, "up-a", false)?;
    let topo = poll_topology(
        control,
        CONTROL_TOKEN,
        |t| t.global_active_uplink(GROUP).as_deref() == Some("up-a"),
        Duration::from_secs(10),
    )?;
    assert_eq!(topo.global_active_uplink(GROUP).as_deref(), Some("up-a"));
    let warmed = poll_until(
        || {
            metrics_scrape(client_metrics)
                .map(|m| {
                    m.sum(
                        "outline_ws_uplink_standby_ready",
                        &[("group", GROUP), ("transport", "udp"), ("uplink", "up-b")],
                    ) >= 1.0
                })
                .unwrap_or(false)
        },
        Duration::from_secs(15),
    );
    assert!(
        warmed,
        "up-b UDP warm-standby pool did not warm up;\nmetrics:\n{}\nclient log:\n{}",
        metrics_scrape(client_metrics)
            .map(|m| m.raw().to_string())
            .unwrap_or_default(),
        client.logs().unwrap_or_default()
    );

    // Establish an active UDP association via `up-a` (`server-a` becomes home).
    let assoc = ContinuousUdpEcho::connect(socks.port(), echo.udp_addr())?;
    let reply1 = assoc.echo_datagram(b"before-soft-switch").map_err(|e| {
        format!(
            "initial UDP echo failed: {e}\nclient log:\n{}\nserver-a log:\n{}",
            client.logs().unwrap_or_default(),
            server_a.logs().unwrap_or_default()
        )
    })?;
    assert_eq!(reply1, b"before-soft-switch");

    let sources_before = echo.udp_sources();
    assert_eq!(sources_before.len(), 1, "expected 1 UDP datagram at echo upstream");
    let source_before = sources_before[0];

    assert_eq!(
        metrics_scrape(client_metrics)?.sum(
            "outline_ws_uplink_standby_ready",
            &[("group", GROUP), ("transport", "udp"), ("uplink", "up-b")],
        ),
        1.0,
    );

    // Perform soft switch `up-a -> up-b` while `warm_standby_udp = 1`.
    let activate_resp = post_activate(control, CONTROL_TOKEN, GROUP, "up-b", true)?;
    assert_eq!(
        activate_resp.get("soft").and_then(|v| v.as_bool()),
        Some(true),
        "soft switch must be applied on shared_resume cluster group: {activate_resp}",
    );

    let topo_after = poll_topology(
        control,
        CONTROL_TOKEN,
        |t| t.global_active_uplink(GROUP).as_deref() == Some("up-b"),
        Duration::from_secs(10),
    )?;
    assert_eq!(topo_after.global_active_uplink(GROUP).as_deref(), Some("up-b"));

    // Send a second datagram on the SAME association: must route through `up-b`
    // -> mesh -> `server-a` NAT socket, keeping the exact same exit `IP:port`.
    let reply2 = assoc.echo_datagram(b"after-soft-switch").map_err(|e| {
        format!(
            "post-soft-switch UDP echo failed: {e}\nclient log:\n{}\nserver-a log:\n{}\nserver-b log:\n{}",
            client.logs().unwrap_or_default(),
            server_a.logs().unwrap_or_default(),
            server_b.logs().unwrap_or_default()
        )
    })?;
    assert_eq!(reply2, b"after-soft-switch");

    let sources_after = echo.udp_sources();
    assert!(sources_after.len() >= 2, "expected at least 2 datagrams at echo upstream");
    assert!(
        sources_after.iter().all(|s| *s == source_before),
        "UDP exit source IP:port changed across soft switch! before={source_before}, all={sources_after:?}\nclient log:\n{}\nserver-a log:\n{}\nserver-b log:\n{}",
        client.logs().unwrap_or_default(),
        server_a.logs().unwrap_or_default(),
        server_b.logs().unwrap_or_default()
    );

    // Client metrics: wait past the 1 s metrics render cache TTL until the
    // scrape reflects the post-switch state (`up-b` active, `udp_associate >= 1`),
    // then confirm migration did NOT touch `up-b`'s warm-standby pool.
    let c_metrics_fresh = poll_until(
        || {
            metrics_scrape(client_metrics)
                .map(|m| {
                    m.sum(
                        "outline_ws_global_active_uplink_info",
                        &[("group", GROUP), ("uplink", "up-b")],
                    ) == 1.0
                        && m.sum("outline_ws_requests_total", &[("command", "udp_associate")])
                            >= 1.0
                })
                .unwrap_or(false)
        },
        Duration::from_secs(5),
    );
    let c_metrics = metrics_scrape(client_metrics)?;
    assert!(
        c_metrics_fresh,
        "client metrics did not refresh to post-switch state\nclient metrics:\n{}",
        c_metrics.raw()
    );
    assert_eq!(
        c_metrics.sum(
            "outline_ws_warm_standby_acquire_total",
            &[("transport", "udp"), ("uplink", "up-a"), ("outcome", "hit")],
        ),
        1.0,
        "initial association on up-a must have used up-a's warm-standby socket\nclient metrics:\n{}",
        c_metrics.raw()
    );
    assert_eq!(
        c_metrics.sum(
            "outline_ws_warm_standby_acquire_total",
            &[("transport", "udp"), ("uplink", "up-b"), ("outcome", "hit")],
        ),
        0.0,
        "soft switch must bypass up-b's warm-standby pool\nclient metrics:\n{}",
        c_metrics.raw()
    );
    assert_eq!(
        c_metrics.sum(
            "outline_ws_warm_standby_acquire_total",
            &[("transport", "udp"), ("uplink", "up-b"), ("outcome", "miss")],
        ),
        0.0,
        "soft switch bypassing the pool must not count a false miss\nclient metrics:\n{}",
        c_metrics.raw()
    );
    assert_eq!(
        c_metrics.sum(
            "outline_ws_uplink_standby_ready",
            &[("group", GROUP), ("transport", "udp"), ("uplink", "up-b")],
        ),
        1.0,
        "up-b's pre-warmed socket must still sit in the pool",
    );

    // Server-b (edge) metrics: mesh relay opened and datagrams relayed both ways.
    let b_metrics = metrics_scrape(srv_b_metrics)?;
    assert!(
        b_metrics.sum("outline_ss_mesh_relay_opened_total", &[("outcome", "ok")]) >= 1.0,
        "edge server-b did not open mesh relay\nserver-b metrics:\n{}\nserver-b log:\n{}",
        b_metrics.raw(),
        server_b.logs().unwrap_or_default()
    );
    assert!(
        b_metrics.sum("outline_ss_mesh_datagrams_total", &[("role", "edge"), ("direction", "up")],)
            >= 1.0,
        "edge server-b missing uplink mesh datagrams\n{}",
        b_metrics.raw()
    );
    assert!(
        b_metrics
            .sum("outline_ss_mesh_datagrams_total", &[("role", "edge"), ("direction", "down")],)
            >= 1.0,
        "edge server-b missing downlink mesh datagrams\n{}",
        b_metrics.raw()
    );

    // Server-a (home) metrics: orphan resume hit for `ss_udp_stream` and home mesh datagrams.
    let a_metrics = metrics_scrape(srv_a_metrics)?;
    assert!(
        a_metrics.sum("outline_ss_orphan_resume_hit_total", &[("kind", "ss_udp_stream")]) >= 1.0,
        "home server-a missing ss_udp_stream orphan resume hit\nserver-a metrics:\n{}\nserver-a log:\n{}",
        a_metrics.raw(),
        server_a.logs().unwrap_or_default()
    );
    assert!(
        a_metrics.sum("outline_ss_mesh_datagrams_total", &[("role", "home"), ("direction", "up")],)
            >= 1.0,
        "home server-a missing uplink mesh datagrams\n{}",
        a_metrics.raw()
    );
    assert!(
        a_metrics
            .sum("outline_ss_mesh_datagrams_total", &[("role", "home"), ("direction", "down")],)
            >= 1.0,
        "home server-a missing downlink mesh datagrams\n{}",
        a_metrics.raw()
    );

    // A fresh independent UDP flow (no SessionId) on `up-b` must still reuse
    // `up-b`'s untouched warm-standby socket (`outcome="hit" >= 1`).
    let fresh_reply = socks5_udp_echo(socks.port(), echo.udp_addr(), b"fresh-flow")?;
    assert_eq!(fresh_reply, b"fresh-flow");
    let fresh_hit = poll_until(
        || {
            metrics_scrape(client_metrics)
                .map(|m| {
                    m.sum(
                        "outline_ws_warm_standby_acquire_total",
                        &[("transport", "udp"), ("uplink", "up-b"), ("outcome", "hit")],
                    ) >= 1.0
                })
                .unwrap_or(false)
        },
        Duration::from_secs(5),
    );
    assert!(
        fresh_hit,
        "fresh UDP association on up-b must still consume the warm-standby socket\n{}",
        metrics_scrape(client_metrics)
            .map(|m| m.raw().to_string())
            .unwrap_or_default()
    );

    drop(assoc);
    client.stop()?;
    server_a.kill()?;
    server_b.kill()?;
    Ok(())
}
