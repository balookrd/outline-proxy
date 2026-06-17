//! E2e carrier-padding: stand up a real `outline-ss-rust` server + grouped
//! `outline-ws-rust` client with `[padding]` enabled on BOTH ends, drive an
//! echo round-trip through SOCKS5, and confirm the bytes survive end-to-end.
//!
//! This verifies the config-synchronised framing over the real WS / XHTTP
//! carriers — the client wraps each SS chunk in a padding frame, the server
//! strips it before the AEAD layer (and pads the downlink symmetrically). A
//! mis-wired encode/decode would corrupt the stream and the echo would fail.
//! The `cover` variant additionally proves idle cover frames are dropped
//! transparently and never corrupt real data.
//!
//! Gated behind `ln=1`; runs nothing in a plain `cargo test`.

#[path = "support/failover_harness.rs"]
mod harness;

use std::time::Duration;

use harness::*;

type BoxError = Box<dyn std::error::Error>;

#[test]
fn padding_ss_ws_h1_roundtrip_with_cover() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("padding_ss_ws_h1_roundtrip_with_cover");
        return Ok(());
    }

    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    // ── Server: pad the SS-over-WS TCP path, with idle cover on the downlink ──
    let server_addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(server_addr)
        .all_paths()
        .with_padding(&[PATH_SS_TCP], true)
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let server_log = dir.path().join("server.log");
    let mut server = ServerProcess::start(&server_cfg_path, &server_log, server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    // ── Client: padding on (global), one SS-over-WS-h1 uplink on the same path ──
    let socks = reserve_addr()?;
    let state_path = dir.path().join("client.state.toml");
    let uplink = UplinkSpec::new(
        "up-a",
        Wire::SsWs {
            tcp_url: format!("ws://{server_addr}{PATH_SS_TCP}"),
            udp_url: None,
            mode: "ws_h1".into(),
        },
        Creds::ss(),
    );
    let client_cfg = ClientConfig::new(socks, &state_path, ProbeSpec::disabled())
        .with_padding(true)
        .group(GroupSpec::new("active_active", "per_flow").uplink(uplink))
        .render();
    let client_cfg_path = write_file(dir.path(), "client.toml", &client_cfg)?;
    let client_log = dir.path().join("client.log");
    let mut client = ProxyProcess::start(&client_cfg_path, &client_log)?;
    client
        .wait_ready(socks.port(), Duration::from_secs(15))
        .map_err(|e| format!("{e}\nclient log:\n{}", client.logs().unwrap_or_default()))?;

    // A round-trip only succeeds if the padded uplink decodes server-side and
    // the padded downlink decodes client-side — i.e. the framing is symmetric.
    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"padded-ws-roundtrip").map_err(|e| {
        format!(
            "padded WS round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
            client.logs().unwrap_or_default(),
            server.logs().unwrap_or_default()
        )
    })?;
    assert!(echo.tcp_connections() >= 1, "server never reached the echo upstream");

    client.stop()?;
    server.kill()?;
    Ok(())
}

#[test]
fn padding_ss_xhttp_h1_roundtrip() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("padding_ss_xhttp_h1_roundtrip");
        return Ok(());
    }

    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    // ── Server: pad the SS-over-XHTTP path (rides the same relay as SS-WS) ──
    let server_addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(server_addr)
        .all_paths()
        .with_padding(&[PATH_SS_XHTTP], false)
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let server_log = dir.path().join("server.log");
    let mut server = ServerProcess::start(&server_cfg_path, &server_log, server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    // ── Client: padding on, one SS-over-XHTTP-h1 uplink on the padded path ──
    let socks = reserve_addr()?;
    let state_path = dir.path().join("client.state.toml");
    let uplink = UplinkSpec::new(
        "up-x",
        Wire::SsXhttp {
            tcp_url: format!("http://{server_addr}{PATH_SS_XHTTP}"),
            mode: "xhttp_h1".into(),
        },
        Creds::ss(),
    );
    let client_cfg = ClientConfig::new(socks, &state_path, ProbeSpec::disabled())
        .with_padding(false)
        .group(GroupSpec::new("active_active", "per_flow").uplink(uplink))
        .render();
    let client_cfg_path = write_file(dir.path(), "client.toml", &client_cfg)?;
    let client_log = dir.path().join("client.log");
    let mut client = ProxyProcess::start(&client_cfg_path, &client_log)?;
    client
        .wait_ready(socks.port(), Duration::from_secs(15))
        .map_err(|e| format!("{e}\nclient log:\n{}", client.logs().unwrap_or_default()))?;

    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"padded-xhttp-roundtrip").map_err(
        |e| {
            format!(
                "padded XHTTP round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
                client.logs().unwrap_or_default(),
                server.logs().unwrap_or_default()
            )
        },
    )?;
    assert!(echo.tcp_connections() >= 1, "server never reached the echo upstream");

    client.stop()?;
    server.kill()?;
    Ok(())
}

/// WS-over-H3 (QUIC) carries the padded frames over the same `WsWriteTransport`
/// / `run_tcp_relay::<H3Ws>` path as h1/h2 — the H3 stream just converts
/// sockudo↔tungstenite `Message`s, passing the `Binary` payload (padding and
/// all) through untouched. This proves it end-to-end on the real QUIC carrier,
/// including that idle cover frames (a `Binary`, never a Ping) do not perturb
/// the H3 stream. Requires the `test-tls` feature (H3 is QUIC, so TLS-bearing).
#[cfg(feature = "test-tls")]
#[test]
fn padding_ss_ws_h3_roundtrip_with_cover() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("padding_ss_ws_h3_roundtrip_with_cover");
        return Ok(());
    }

    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;
    let tls = harness::tls_fixture::TlsFixture::generate_into(dir.path())?;

    // ── Server: TLS + H3, padding the SS-over-WS path with idle cover ──
    let tcp_addr = reserve_addr()?;
    let h3_addr = reserve_udp_addr()?;
    let server_cfg = ServerConfig::new(tcp_addr)
        .all_paths()
        .with_tls(&tls.leaf_pem, &tls.key_pem)
        .with_h3(h3_addr, &["h3", "vless", "ss"])
        .with_padding(&[PATH_SS_TCP], true)
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let server_log = dir.path().join("server.log");
    let mut server = ServerProcess::start(&server_cfg_path, &server_log, tcp_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    // ── Client: padding on, single WS-over-H3 uplink on the QUIC port ──
    let socks = reserve_addr()?;
    let state_path = dir.path().join("client.state.toml");
    let uplink = UplinkSpec::new(
        "up-h3",
        Wire::SsWs {
            tcp_url: format!("wss://127.0.0.1:{}{PATH_SS_TCP}", h3_addr.port()),
            udp_url: None,
            mode: "ws_h3".into(),
        },
        Creds::ss(),
    );
    let client_cfg = ClientConfig::new(socks, &state_path, ProbeSpec::disabled())
        .with_padding(true)
        .group(GroupSpec::new("active_passive", "global").uplink(uplink))
        .render();
    let client_cfg_path = write_file(dir.path(), "client.toml", &client_cfg)?;
    let client_log = dir.path().join("client.log");
    let ca = tls.ca_der.to_string_lossy().to_string();
    let mut client = ProxyProcess::start_with_env(
        &client_cfg_path,
        &client_log,
        &[("OUTLINE_WS_TEST_TLS_CA_DER", &ca)],
    )?;
    client
        .wait_ready(socks.port(), Duration::from_secs(15))
        .map_err(|e| format!("{e}\nclient log:\n{}", client.logs().unwrap_or_default()))?;

    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"padded-ws-h3-roundtrip").map_err(
        |e| {
            format!(
                "padded WS-H3 round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
                client.logs().unwrap_or_default(),
                server.logs().unwrap_or_default()
            )
        },
    )?;
    assert!(echo.tcp_connections() >= 1, "server never reached the echo upstream over H3");

    client.stop()?;
    server.kill()?;
    Ok(())
}
