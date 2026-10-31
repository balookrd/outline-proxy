#![cfg(feature = "test-tls")]
//! (E) TLS-bearing carriers and the QUIC family, end-to-end through the real
//! binaries. The client binary, built with `--features test-tls`, trusts the
//! harness CA via `OUTLINE_WS_TEST_TLS_CA_DER`, so it can dial a self-signed
//! server over `wss://` WebSocket-over-H2 (TLS on the TCP listener) and `wss://`
//! WebSocket-over-H3 (QUIC). Plus a TLS→cleartext sub-uplink failover, proving wires
//! of different security levels interoperate in one uplink.
//!
//! Run with: `cargo test -p outline-ws-rust --features test-tls
//!            --test e2e_tls_carriers -- --test-threads=1` and
//! `RUN_E2E_FAILOVER=1`.

#[path = "support/failover_harness.rs"]
mod harness;

use std::net::SocketAddr;
use std::time::Duration;

use harness::tls_fixture::TlsFixture;
use harness::*;

type BoxError = Box<dyn std::error::Error>;

/// Bring up a TLS + H3/QUIC server and a single-uplink client that trusts the
/// harness CA, then drive an echo round-trip over `make_wire`'s carrier.
/// `make_wire` receives `(tcp_tls_addr, h3_udp_addr)`.
fn run_tls_dial(
    make_wire: impl FnOnce(SocketAddr, SocketAddr) -> (Wire, Creds),
) -> Result<(), BoxError> {
    run_tls_dial_with(None, 1, make_wire)
}

/// [`run_tls_dial`] with an optional client `fingerprint_profile` strategy
/// and `roundtrips` echo round-trips (each a fresh SOCKS session).
fn run_tls_dial_with(
    fingerprint_profile: Option<&str>,
    roundtrips: usize,
    make_wire: impl FnOnce(SocketAddr, SocketAddr) -> (Wire, Creds),
) -> Result<(), BoxError> {
    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;
    let tls = TlsFixture::generate_into(dir.path())?;

    let tcp_addr = reserve_addr()?;
    let h3_addr = reserve_udp_addr()?;
    let server_cfg = ServerConfig::new(tcp_addr)
        .all_paths()
        .with_tls(&tls.leaf_pem, &tls.key_pem)
        .with_h3(h3_addr, &["h3", "vless", "ss"])
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let mut server =
        ServerProcess::start(&server_cfg_path, &dir.path().join("server.log"), tcp_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    let (wire, creds) = make_wire(tcp_addr, h3_addr);
    let socks = reserve_addr()?;
    let control = reserve_addr()?;
    let mut client_cfg =
        ClientConfig::new(socks, &dir.path().join("c.state.toml"), ProbeSpec::disabled())
            .with_control(control, CONTROL_TOKEN)
            .group(
                GroupSpec::new("active_passive", "global")
                    .uplink(UplinkSpec::new("up-a", wire, creds)),
            );
    if let Some(strategy) = fingerprint_profile {
        client_cfg = client_cfg.with_fingerprint_profile(strategy);
    }
    let client_cfg = client_cfg.render();
    let client_cfg_path = write_file(dir.path(), "client.toml", &client_cfg)?;
    let ca = tls.ca_der.to_string_lossy().to_string();
    let mut client = ProxyProcess::start_with_env(
        &client_cfg_path,
        &dir.path().join("client.log"),
        &[("OUTLINE_WS_TEST_TLS_CA_DER", &ca)],
    )?;
    client
        .wait_ready(socks.port(), Duration::from_secs(15))
        .map_err(|e| format!("{e}\nclient log:\n{}", client.logs().unwrap_or_default()))?;

    for _ in 0..roundtrips {
        socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"tls-carrier-payload").map_err(
            |e| {
                format!(
                    "round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
                    client.logs().unwrap_or_default(),
                    server.logs().unwrap_or_default()
                )
            },
        )?;
    }
    assert!(
        echo.tcp_connections() >= 1,
        "traffic never reached the upstream over the TLS carrier"
    );

    client.stop()?;
    server.kill()?;
    Ok(())
}

#[test]
fn tls_wss_h2_ss_dial_works() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("tls_wss_h2_ss_dial_works");
        return Ok(());
    }
    run_tls_dial(|tcp, _h3| {
        (
            Wire::SsWs {
                tcp_url: format!("wss://127.0.0.1:{}{PATH_SS_TCP}", tcp.port()),
                udp_url: None,
                mode: "ws_h2".into(),
            },
            Creds::ss(),
        )
    })
}

#[test]
fn tls_ws_h3_ss_dial_works() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("tls_ws_h3_ss_dial_works");
        return Ok(());
    }
    run_tls_dial(|_tcp, h3| {
        (
            Wire::SsWs {
                // WS-over-H3 rides QUIC on the H3 UDP port.
                tcp_url: format!("wss://127.0.0.1:{}{PATH_SS_TCP}", h3.port()),
                udp_url: None,
                mode: "ws_h3".into(),
            },
            Creds::ss(),
        )
    })
}

/// With browser profiles on (`fingerprint_profile = "random"`: a fresh
/// profile per dial), every carrier sends its browser-shaped request headers
/// to the real server — WebSocket upgrades offer `permessage-deflate` like
/// Chrome and Firefox, which the server must decline (the client implements
/// no extension and rejects a handshake that accepts one) — and data flows.
#[test]
fn tls_carriers_work_with_browser_profiles() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("tls_carriers_work_with_browser_profiles");
        return Ok(());
    }
    for mode in ["ws_h1", "ws_h2", "ws_h3", "xhttp_h1", "xhttp_h2", "xhttp_h3"] {
        run_tls_dial_with(Some("random"), 3, |tcp, h3| {
            let port = if mode.ends_with("h3") { h3.port() } else { tcp.port() };
            let wire = if mode.starts_with("ws") {
                Wire::SsWs {
                    tcp_url: format!("wss://127.0.0.1:{port}{PATH_SS_TCP}"),
                    udp_url: None,
                    mode: mode.into(),
                }
            } else {
                Wire::SsXhttp {
                    tcp_url: format!("https://127.0.0.1:{port}{PATH_SS_XHTTP}"),
                    mode: mode.into(),
                }
            };
            (wire, Creds::ss())
        })
        .map_err(|e| format!("{mode}: {e}"))?;
    }
    Ok(())
}

/// Primary wire is cleartext `ws://` WS-over-H1 pointed at a dead endpoint; the
/// fallback is `wss://` WS-over-H2 on the live TLS server. The active wire must
/// roll over from the cleartext primary to the TLS fallback — exercising the
/// `test-tls` CA trust on the fallback and proving wires of different security
/// levels interoperate within one uplink.
#[test]
fn tls_failover_cleartext_ws_to_wss_h2() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("tls_failover_cleartext_ws_to_wss_h2");
        return Ok(());
    }
    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;
    let tls = TlsFixture::generate_into(dir.path())?;

    let tcp_addr = reserve_addr()?;
    let h3_addr = reserve_udp_addr()?;
    let server_cfg = ServerConfig::new(tcp_addr)
        .all_paths()
        .with_tls(&tls.leaf_pem, &tls.key_pem)
        // A TLS-configured server auto-enables H3 and requires an explicit
        // h3_listen, even though this test only exercises the TCP TLS path.
        .with_h3(h3_addr, &["h3"])
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let mut server =
        ServerProcess::start(&server_cfg_path, &dir.path().join("server.log"), tcp_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    let dead = RejectingListener::start()?;
    let uplink = UplinkSpec::new(
        "up-a",
        Wire::SsWs {
            tcp_url: format!("ws://127.0.0.1:{}{PATH_SS_TCP}", dead.addr().port()),
            udp_url: None,
            mode: "ws_h1".into(),
        },
        Creds::ss(),
    )
    .with_fallback(
        Wire::SsWs {
            tcp_url: format!("wss://127.0.0.1:{}{PATH_SS_TCP}", tcp_addr.port()),
            udp_url: None,
            mode: "ws_h2".into(),
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
    let ca = tls.ca_der.to_string_lossy().to_string();
    let mut client = ProxyProcess::start_with_env(
        &client_cfg_path,
        &dir.path().join("client.log"),
        &[("OUTLINE_WS_TEST_TLS_CA_DER", &ca)],
    )?;
    client
        .wait_ready(socks.port(), Duration::from_secs(15))
        .map_err(|e| format!("{e}\nclient log:\n{}", client.logs().unwrap_or_default()))?;

    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"tls-to-cleartext").map_err(|e| {
        format!("round-trip failed: {e}\nclient log:\n{}", client.logs().unwrap_or_default())
    })?;
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
        "active wire did not roll over from the TLS primary to the cleartext fallback; \
         topology:\n{}\nclient log:\n{}",
        topo.raw(),
        client.logs().unwrap_or_default()
    );

    client.stop()?;
    server.kill()?;
    Ok(())
}
