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

/// Per-uplink override: the global `[padding]` default is OFF
/// (`enabled = false`), but the uplink pins `padding = true`, so its dials are
/// padded anyway. Proves the override/fallback resolution end-to-end —
/// `effective_carrier_padding` reads the per-uplink task-local that
/// `dial_in_uplink_scope` sets, not the global default. The server pads the
/// matching path, so the round-trip survives ONLY if the override actually
/// turned padding on for this uplink (a plain dial would desync the decoder).
#[test]
fn padding_per_uplink_override_with_global_default_off() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("padding_per_uplink_override_with_global_default_off");
        return Ok(());
    }

    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    // ── Server: pad the SS-over-WS path ──
    let server_addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(server_addr)
        .all_paths()
        .with_padding(&[PATH_SS_TCP], false)
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let server_log = dir.path().join("server.log");
    let mut server = ServerProcess::start(&server_cfg_path, &server_log, server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    // ── Client: GLOBAL default OFF (scheme params still present), but the
    // uplink pins `padding = true`. Without a working override the dial would
    // be plain and the padded server would reject it. ──
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
    )
    .padding(true);
    let client_cfg = ClientConfig::new(socks, &state_path, ProbeSpec::disabled())
        .with_padding_default(false, false)
        .group(GroupSpec::new("active_active", "per_flow").uplink(uplink))
        .render();
    let client_cfg_path = write_file(dir.path(), "client.toml", &client_cfg)?;
    let client_log = dir.path().join("client.log");
    let mut client = ProxyProcess::start(&client_cfg_path, &client_log)?;
    client
        .wait_ready(socks.port(), Duration::from_secs(15))
        .map_err(|e| format!("{e}\nclient log:\n{}", client.logs().unwrap_or_default()))?;

    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"per-uplink-override-padding").map_err(
        |e| {
            format!(
                "per-uplink override round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
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

/// Per-uplink override on the VLESS-UDP path. Global default OFF, the VLESS
/// uplink pins `padding = true`. VLESS-UDP dials lazily inside the session mux
/// — outside the dial scope — so this exercises the mux `with_padding_override`
/// plumbing that captures the override on the dialer and re-applies it per
/// per-target dial. Without it the UDP datagram would be unframed and the
/// padded server would corrupt it.
#[test]
fn padding_vless_udp_per_uplink_override() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("padding_vless_udp_per_uplink_override");
        return Ok(());
    }

    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    let server_addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(server_addr)
        .all_paths()
        .with_padding(&[PATH_VLESS_WS], false)
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let server_log = dir.path().join("server.log");
    let mut server = ServerProcess::start(&server_cfg_path, &server_log, server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    let socks = reserve_addr()?;
    let state_path = dir.path().join("client.state.toml");
    let uplink = UplinkSpec::new(
        "up-v",
        Wire::VlessWs {
            url: format!("ws://{server_addr}{PATH_VLESS_WS}"),
            mode: "ws_h1".into(),
        },
        Creds::vless(),
    )
    .padding(true);
    let client_cfg = ClientConfig::new(socks, &state_path, ProbeSpec::disabled())
        .with_padding_default(false, false)
        .group(GroupSpec::new("active_active", "per_flow").uplink(uplink))
        .render();
    let client_cfg_path = write_file(dir.path(), "client.toml", &client_cfg)?;
    let client_log = dir.path().join("client.log");
    let mut client = ProxyProcess::start(&client_cfg_path, &client_log)?;
    client
        .wait_ready(socks.port(), Duration::from_secs(15))
        .map_err(|e| format!("{e}\nclient log:\n{}", client.logs().unwrap_or_default()))?;

    let payload = b"vless-udp-per-uplink-override";
    let echoed = socks5_udp_echo(socks.port(), echo.udp_addr(), payload).map_err(|e| {
        format!(
            "VLESS-UDP per-uplink override round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
            client.logs().unwrap_or_default(),
            server.logs().unwrap_or_default()
        )
    })?;
    assert_eq!(echoed, payload, "VLESS-UDP echo must survive padding under per-uplink override");

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

#[test]
fn padding_vless_ws_h1_roundtrip_with_cover() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("padding_vless_ws_h1_roundtrip_with_cover");
        return Ok(());
    }

    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    // ── Server: pad the VLESS-over-WS path, idle cover on the downlink ──
    let server_addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(server_addr)
        .all_paths()
        .with_padding(&[PATH_VLESS_WS], true)
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let server_log = dir.path().join("server.log");
    let mut server = ServerProcess::start(&server_cfg_path, &server_log, server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    // ── Client: padding on (global), one VLESS-over-WS-h1 uplink on that path ──
    let socks = reserve_addr()?;
    let state_path = dir.path().join("client.state.toml");
    let uplink = UplinkSpec::new(
        "up-v",
        Wire::VlessWs {
            url: format!("ws://{server_addr}{PATH_VLESS_WS}"),
            mode: "ws_h1".into(),
        },
        Creds::vless(),
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

    // A VLESS round-trip only succeeds if the padded uplink frames decode
    // server-side (before VLESS parsing) and the padded downlink decodes
    // client-side (in the WS frame source) — i.e. framing is symmetric.
    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"padded-vless-ws-roundtrip").map_err(
        |e| {
            format!(
                "padded VLESS-WS round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
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

/// VLESS-UDP-over-WS rides the datagram channel, padded per-datagram inside
/// `VlessUdpTransport` (the SS-UDP path stays plain). Because VLESS multiplexes
/// tcp/udp on one path, the server cannot tell the legs apart before reading
/// data — so the UDP leg MUST pad too, or a padded path would corrupt it. This
/// drives a UDP echo through SOCKS5 UDP ASSOCIATE on the same padded VLESS path.
#[test]
fn padding_vless_ws_h1_udp_roundtrip() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("padding_vless_ws_h1_udp_roundtrip");
        return Ok(());
    }

    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    let server_addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(server_addr)
        .all_paths()
        .with_padding(&[PATH_VLESS_WS], true)
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let server_log = dir.path().join("server.log");
    let mut server = ServerProcess::start(&server_cfg_path, &server_log, server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    let socks = reserve_addr()?;
    let state_path = dir.path().join("client.state.toml");
    let uplink = UplinkSpec::new(
        "up-v",
        Wire::VlessWs {
            url: format!("ws://{server_addr}{PATH_VLESS_WS}"),
            mode: "ws_h1".into(),
        },
        Creds::vless(),
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

    let payload = b"padded-vless-udp-roundtrip";
    let echoed = socks5_udp_echo(socks.port(), echo.udp_addr(), payload).map_err(|e| {
        format!(
            "padded VLESS-UDP round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
            client.logs().unwrap_or_default(),
            server.logs().unwrap_or_default()
        )
    })?;
    assert_eq!(echoed, payload, "VLESS-UDP echo payload must survive padding both ways");

    client.stop()?;
    server.kill()?;
    Ok(())
}

/// SS-UDP-over-WS, split paths. The TCP and UDP legs are *separate* paths, so
/// the operator lists BOTH in `[padding] paths`; the UDP leg now frames each
/// datagram (one frame per SS-AEAD packet) exactly like the TCP stream and
/// VLESS-UDP, closing the old "SS-UDP stays plain" asymmetry. Idle cover frames
/// on the UDP downlink (`cover = true`) must be dropped transparently by the
/// client's datagram decoder and never corrupt the echo. Drives a UDP echo
/// through SOCKS5 UDP ASSOCIATE on the padded SS-UDP path.
#[test]
fn padding_ss_udp_split_roundtrip_with_cover() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("padding_ss_udp_split_roundtrip_with_cover");
        return Ok(());
    }

    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    // ── Server: pad BOTH SS-over-WS split legs (tcp + udp), idle cover on ──
    let server_addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(server_addr)
        .all_paths()
        .with_padding(&[PATH_SS_TCP, PATH_SS_UDP], true)
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let server_log = dir.path().join("server.log");
    let mut server = ServerProcess::start(&server_cfg_path, &server_log, server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    // ── Client: padding on (global), one SS-over-WS-h1 uplink with a UDP leg ──
    let socks = reserve_addr()?;
    let state_path = dir.path().join("client.state.toml");
    let uplink = UplinkSpec::new(
        "up-su",
        Wire::SsWs {
            tcp_url: format!("ws://{server_addr}{PATH_SS_TCP}"),
            udp_url: Some(format!("ws://{server_addr}{PATH_SS_UDP}")),
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

    // The round-trip survives only if the client frames each uplink datagram,
    // the server decodes it before SS-UDP decrypt, frames the encrypted
    // downlink back, and the client decodes that — i.e. the per-datagram
    // framing is symmetric on the UDP leg.
    let payload = b"padded-ss-udp-split-roundtrip";
    let echoed = socks5_udp_echo(socks.port(), echo.udp_addr(), payload).map_err(|e| {
        format!(
            "padded SS-UDP split round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
            client.logs().unwrap_or_default(),
            server.logs().unwrap_or_default()
        )
    })?;
    assert_eq!(echoed, payload, "SS-UDP echo payload must survive padding both ways");

    client.stop()?;
    server.kill()?;
    Ok(())
}

/// Combined-SS: the TCP and UDP legs share ONE path ([`PATH_SS_WS_COMBINED`]),
/// split by a hidden token bit the server decodes at upgrade time. Padding the
/// combined base path pads BOTH legs uniformly — the UDP leg's `run_udp_relay`
/// resolves the same per-path scheme as the TCP leg's `run_tcp_relay`. Drives a
/// TCP echo AND a UDP echo over the one padded combined uplink; both must
/// survive, proving the combined UDP leg is no longer routed to an unpadded
/// relay.
#[test]
fn padding_ss_combined_roundtrip_both_legs() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("padding_ss_combined_roundtrip_both_legs");
        return Ok(());
    }

    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    // ── Server: a combined SS-over-WS base path, padded (both legs) ──
    let server_addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(server_addr)
        .all_paths()
        .with_combined_ss_ws_path()
        .with_padding(&[PATH_SS_WS_COMBINED], true)
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let server_log = dir.path().join("server.log");
    let mut server = ServerProcess::start(&server_cfg_path, &server_log, server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    // ── Client: padding on, ONE combined-SS uplink (single URL, both legs) ──
    let socks = reserve_addr()?;
    let state_path = dir.path().join("client.state.toml");
    let uplink = UplinkSpec::new(
        "up-sc",
        Wire::SsWsCombined {
            url: format!("ws://{server_addr}{PATH_SS_WS_COMBINED}"),
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

    // TCP leg: combined path, tcp bit in the token → padded run_tcp_relay.
    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"padded-combined-tcp").map_err(|e| {
        format!(
            "combined-SS TCP leg round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
            client.logs().unwrap_or_default(),
            server.logs().unwrap_or_default()
        )
    })?;

    // UDP leg: same combined path, udp bit in the token → padded run_udp_relay.
    let payload = b"padded-combined-udp";
    let echoed = socks5_udp_echo(socks.port(), echo.udp_addr(), payload).map_err(|e| {
        format!(
            "combined-SS UDP leg round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
            client.logs().unwrap_or_default(),
            server.logs().unwrap_or_default()
        )
    })?;
    assert_eq!(echoed, payload, "combined-SS UDP leg must survive padding both ways");
    assert!(echo.tcp_connections() >= 1, "server never reached the echo upstream over TCP");

    client.stop()?;
    server.kill()?;
    Ok(())
}

#[test]
fn padding_vless_xhttp_h1_roundtrip() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("padding_vless_xhttp_h1_roundtrip");
        return Ok(());
    }

    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;

    // ── Server: pad the VLESS-over-XHTTP path (rides run_vless_relay::<XhttpDuplex>) ──
    let server_addr = reserve_addr()?;
    let server_cfg = ServerConfig::new(server_addr)
        .all_paths()
        .with_padding(&[PATH_VLESS_XHTTP], false)
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let server_log = dir.path().join("server.log");
    let mut server = ServerProcess::start(&server_cfg_path, &server_log, server_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    // ── Client: padding on, one VLESS-over-XHTTP-h1 uplink on the padded path ──
    let socks = reserve_addr()?;
    let state_path = dir.path().join("client.state.toml");
    let uplink = UplinkSpec::new(
        "up-vx",
        Wire::VlessXhttp {
            url: format!("http://{server_addr}{PATH_VLESS_XHTTP}"),
            mode: "xhttp_h1".into(),
        },
        Creds::vless(),
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

    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"padded-vless-xhttp-roundtrip").map_err(
        |e| {
            format!(
                "padded VLESS-XHTTP round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
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

/// VLESS-over-H3: same QUIC carrier as the SS-H3 case, but through
/// `run_vless_relay::<H3Ws>`. Confirms the VLESS frame source/sink padding and
/// cover frames ride the real H3 stream untouched. Requires `test-tls`.
#[cfg(feature = "test-tls")]
#[test]
fn padding_vless_ws_h3_roundtrip_with_cover() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("padding_vless_ws_h3_roundtrip_with_cover");
        return Ok(());
    }

    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;
    let tls = harness::tls_fixture::TlsFixture::generate_into(dir.path())?;

    // ── Server: TLS + H3, padding the VLESS-over-WS path with idle cover ──
    let tcp_addr = reserve_addr()?;
    let h3_addr = reserve_udp_addr()?;
    let server_cfg = ServerConfig::new(tcp_addr)
        .all_paths()
        .with_tls(&tls.leaf_pem, &tls.key_pem)
        .with_h3(h3_addr, &["h3", "vless", "ss"])
        .with_padding(&[PATH_VLESS_WS], true)
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let server_log = dir.path().join("server.log");
    let mut server = ServerProcess::start(&server_cfg_path, &server_log, tcp_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    // ── Client: padding on, single VLESS-over-H3 uplink on the QUIC port ──
    let socks = reserve_addr()?;
    let state_path = dir.path().join("client.state.toml");
    let uplink = UplinkSpec::new(
        "up-vh3",
        Wire::VlessWs {
            url: format!("wss://127.0.0.1:{}{PATH_VLESS_WS}", h3_addr.port()),
            mode: "ws_h3".into(),
        },
        Creds::vless(),
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

    socks5_echo_roundtrip(socks.port(), echo.tcp_addr(), b"padded-vless-h3-roundtrip").map_err(
        |e| {
            format!(
                "padded VLESS-H3 round-trip failed: {e}\nclient log:\n{}\nserver log:\n{}",
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
