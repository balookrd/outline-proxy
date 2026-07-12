//! (D) Mid-session Ack-Prefix resume handshake across real binaries. A
//! `MidSessionBreaker` splices the client to a live, resumption-capable server;
//! once data is flowing it severs the carrier — it feeds the client a corrupt
//! downlink frame (read as an upstream runtime failure, the mid-session-retry
//! trigger) and sends the server a WS Close so it parks the orphaned session.
//! The client then engages the Ack-Prefix mid-session retry and re-dials; the
//! server answers with a resume HIT, emitting the Ack-Prefix control frame.
//! This exercises the full cross-binary resume negotiation: capability
//! advertise → session-id issuance → park → resume request → resume hit.
//!
//! Scope: this asserts the resume *handshake*, not byte-exact tail replay.
//! Exact replay needs the client ring's absolute offset to equal the server's
//! `up_acked`; the client ring counts from the first pinned-relay byte while the
//! server counts from session start (including the chunk-0 bytes), so a splice-
//! reconstructed scenario is always off by the chunk-0 payload size. Byte-exact
//! replay is covered by the in-process unit test
//! `proxy::tcp::connect::tests::pinned_relay`. Gated behind `RUN_E2E_FAILOVER=1`.

#[path = "support/failover_harness.rs"]
mod harness;

use std::time::Duration;

use harness::*;

type BoxError = Box<dyn std::error::Error>;

fn run_mid_session_resume(
    primary: impl FnOnce(std::net::SocketAddr) -> (Wire, Creds),
) -> Result<(), BoxError> {
    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    // Resumption-capable server (v1 Ack-Prefix + v2 downlink replay buffer).
    let server_addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(server_addr)
        .all_paths()
        .with_session_resumption(65536)
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let mut server =
        ServerProcess::start(&server_cfg_path, &dir.path().join("server.log"), server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    // Breaker splices client → live server; its front address is the wire URL.
    let breaker = MidSessionBreaker::start(server_addr)?;
    let (wire, creds) = primary(breaker.front_addr());

    let socks = reserve_addr()?;
    let control = reserve_addr()?;
    let metrics = reserve_addr()?;
    let client_cfg =
        ClientConfig::new(socks, &dir.path().join("c.state.toml"), ProbeSpec::disabled())
            .with_control(control, CONTROL_TOKEN)
            .with_metrics(metrics)
            .group(
                GroupSpec::new("active_passive", "global")
                    .with_mid_session_retry(256 * 1024, 2)
                    .uplink(UplinkSpec::new("up-a", wire, creds)),
            )
            .render();
    let client_cfg_path = write_file(dir.path(), "client.toml", &client_cfg)?;
    let mut client = ProxyProcess::start(&client_cfg_path, &dir.path().join("client.log"))?;
    client
        .wait_ready(socks.port(), Duration::from_secs(15))
        .map_err(|e| format!("{e}\nclient log:\n{}", client.logs().unwrap_or_default()))?;

    // Open a long-lived session. The FIRST exchanged chunk traverses the
    // chunk-0 replay buffer (the pre-first-upstream-byte path), not the
    // mid-session ring — so it must complete before the ring starts capturing.
    let mut conn = ContinuousEcho::connect(socks.port(), echo.tcp_addr()).map_err(|e| {
        format!("connect failed: {e}\nclient log:\n{}", client.logs().unwrap_or_default())
    })?;
    conn.echo_chunk(b"warmup-clears-chunk0").map_err(|e| {
        format!(
            "warmup echo failed: {e}\nclient log:\n{}\nserver log:\n{}",
            client.logs().unwrap_or_default(),
            server.logs().unwrap_or_default()
        )
    })?;
    // This second chunk rides the pinned relay and is captured in the
    // mid-session ring buffer, so it can be replayed across the resume.
    conn.echo_chunk(b"chunk-one-before-cut").map_err(|e| {
        format!(
            "pre-cut echo failed: {e}\nclient log:\n{}\nserver log:\n{}",
            client.logs().unwrap_or_default(),
            server.logs().unwrap_or_default()
        )
    })?;
    assert!(breaker.splices_open() >= 1, "no live carrier through the breaker");

    // Sever the carrier mid-session; the live server keeps running so it can
    // accept the client's resume re-dial. Keep `conn` alive so the session is
    // active at cut time.
    breaker.cut();

    // The resume handshake must complete: (1) the client detects the upstream
    // runtime failure on the live session and engages the Ack-Prefix mid-session
    // retry (any outcome → the path was taken), (2) it re-dials (a second splice
    // opens), and (3) the server answers with a resume HIT — it finds the parked
    // session and emits the Ack-Prefix control frame ("resume hit" in its log).
    let resumed = poll_until(
        || {
            let client_retried = metrics_scrape(metrics)
                .map(|m| m.sum("outline_ws_uplink_mid_session_retries_total", &[]) >= 1.0)
                .unwrap_or(false);
            let server_resume_hit =
                server.logs().map(|l| l.contains("resume hit")).unwrap_or(false);
            client_retried && server_resume_hit && breaker.splices_total() >= 2
        },
        Duration::from_secs(15),
    );

    let retries = metrics_scrape(metrics)
        .map(|m| m.sum("outline_ws_uplink_mid_session_retries_total", &[]))
        .unwrap_or(0.0);
    let server_resume_hit = server.logs().map(|l| l.contains("resume hit")).unwrap_or(false);
    assert!(
        resumed,
        "mid-session Ack-Prefix resume handshake did not complete: \
         client mid_session_retries_total={retries}, server resume hit={server_resume_hit}, \
         splices_total={}\nclient log:\n{}\nserver log:\n{}",
        breaker.splices_total(),
        client.logs().unwrap_or_default(),
        server.logs().unwrap_or_default()
    );

    // Hold the session open until the assertions are done.
    drop(conn);
    client.stop()?;
    server.kill()?;
    Ok(())
}

#[test]
fn mid_session_resume_ss_ws_h1() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("mid_session_resume_ss_ws_h1");
        return Ok(());
    }
    run_mid_session_resume(|front| {
        (
            Wire::SsWs {
                tcp_url: format!("ws://{front}{PATH_SS_TCP}"),
                udp_url: None,
                mode: "ws_h1".into(),
            },
            Creds::ss(),
        )
    })
}
