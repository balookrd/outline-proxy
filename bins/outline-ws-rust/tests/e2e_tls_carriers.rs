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

use harness::proxy_test_utils::{build_udp_packet, parse_udp_packet, socks5_udp_associate};
use harness::tls_fixture::TlsFixture;
use harness::*;
use outline_transport::fingerprint_profile::{Strategy, select_with_strategy};
use url::Url;

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

// ── UDP over HTTP/3 DATAGRAM ────────────────────────────────────────────────

/// Which browser family the client is pinned to for a datagram scenario.
#[derive(Clone, Copy)]
enum DatagramBrowser {
    /// Advertises `max_datagram_frame_size`: the client offers datagrams.
    Chromium,
    /// Advertises no `max_datagram_frame_size`: never offers datagrams.
    #[cfg(target_os = "macos")]
    Safari,
}

impl DatagramBrowser {
    fn matches(self, profile_name: &str) -> bool {
        match self {
            Self::Chromium => profile_name.starts_with("chrome-"),
            #[cfg(target_os = "macos")]
            Self::Safari => profile_name.starts_with("safari-"),
        }
    }
}

/// Reserve a UDP address whose port makes `per_host_stable` pick the wanted
/// browser. The client hashes `(host, port)` of the dial URL with the std
/// `DefaultHasher`, so the pick is a pure function of the port: the test calls
/// the same selector the binary uses and re-rolls the port until it lands on
/// the wanted family. Deterministic for a given build, no hook needed.
fn reserve_h3_addr_for(browser: DatagramBrowser) -> Result<SocketAddr, BoxError> {
    for _ in 0..500 {
        let addr = reserve_udp_addr()?;
        let url = Url::parse(&format!("https://127.0.0.1:{}/", addr.port()))?;
        let picked = select_with_strategy(&url, Strategy::PerHostStable)
            .ok_or("per_host_stable selected no profile")?;
        if browser.matches(picked.name) {
            return Ok(addr);
        }
    }
    Err("no UDP port hashed onto the wanted browser profile".into())
}

/// SOCKS5 UDP echo over `mode` (`ws_h3` / `xhttp_h3`) with the client pinned to
/// `browser`. Sends a burst on one association so the datagram path has time to
/// engage (the first packets can ride the stream while the response header is
/// still in flight), and returns the client's `outline_ws_udp_h3_datagrams_total`
/// sum.
fn run_udp_datagram_case(mode: &str, browser: DatagramBrowser) -> Result<f64, BoxError> {
    let dir = TestDir::new()?;
    let echo = EchoUpstream::start()?;
    let tls = TlsFixture::generate_into(dir.path())?;

    let tcp_addr = reserve_addr()?;
    let h3_addr = reserve_h3_addr_for(browser)?;
    let server_cfg = ServerConfig::new(tcp_addr)
        .all_paths()
        .with_combined_ss_xhttp_path()
        .with_tls(&tls.leaf_pem, &tls.key_pem)
        .with_h3(h3_addr, &["h3", "vless", "ss"])
        .render();
    let server_cfg_path = write_file(dir.path(), "server.toml", &server_cfg)?;
    let mut server =
        ServerProcess::start(&server_cfg_path, &dir.path().join("server.log"), tcp_addr)?;
    server.wait_ready(Duration::from_secs(15))?;

    let port = h3_addr.port();
    let wire = if mode.starts_with("ws") {
        Wire::SsWs {
            tcp_url: format!("wss://127.0.0.1:{port}{PATH_SS_TCP}"),
            udp_url: Some(format!("wss://127.0.0.1:{port}{PATH_SS_UDP}")),
            mode: mode.into(),
        }
    } else {
        Wire::SsXhttpCombined {
            url: format!("https://127.0.0.1:{port}{PATH_SS_XHTTP_COMBINED}"),
            mode: mode.into(),
        }
    };
    let socks = reserve_addr()?;
    let metrics = reserve_addr()?;
    let client_cfg =
        ClientConfig::new(socks, &dir.path().join("c.state.toml"), ProbeSpec::disabled())
            .with_metrics(metrics)
            .with_fingerprint_profile("per_host_stable")
            .group(GroupSpec::new("active_passive", "global").uplink(UplinkSpec::new(
                "up-a",
                wire,
                Creds::ss(),
            )))
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

    let fail = |what: String, client: &ProxyProcess, server: &ServerProcess| {
        format!(
            "{what}\nclient log:\n{}\nserver log:\n{}",
            client.logs().unwrap_or_default(),
            server.logs().unwrap_or_default()
        )
    };

    let (_control, relay_addr) = socks5_udp_associate(socks.port())?;
    let sock = std::net::UdpSocket::bind(("127.0.0.1", 0))?;
    sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    let target = echo.udp_addr();
    let host = target.ip().to_string();
    let mut buf = [0u8; 4096];
    for i in 0..20u8 {
        let payload = vec![i; 64 + usize::from(i)];
        sock.send_to(&build_udp_packet(&host, target.port(), &payload)?, relay_addr)?;
        let (n, _) = sock
            .recv_from(&mut buf)
            .map_err(|e| fail(format!("udp echo {i} ({mode}): {e}"), &client, &server))?;
        let parsed = parse_udp_packet(&buf[..n])?;
        if parsed.payload != payload {
            return Err(
                fail(format!("udp echo {i} ({mode}): payload mismatch"), &client, &server).into()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let total = metrics_scrape(metrics)?.sum("outline_ws_udp_h3_datagrams_total", &[]);
    client.stop()?;
    server.kill()?;
    Ok(total)
}

/// Chromium advertises `max_datagram_frame_size`, so SS-UDP over `ws_h3` and
/// `xhttp_h3` negotiates datagrams with the real server and the client counts
/// packets handed to QUIC as datagrams.
#[test]
fn tls_udp_h3_datagrams_chromium() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("tls_udp_h3_datagrams_chromium");
        return Ok(());
    }
    for mode in ["ws_h3", "xhttp_h3"] {
        let sent = run_udp_datagram_case(mode, DatagramBrowser::Chromium)?;
        assert!(sent > 0.0, "{mode}: echo worked but no packet travelled as an H3 datagram");
    }
    Ok(())
}

/// Safari advertises no `max_datagram_frame_size`: the client never offers
/// datagrams, so UDP stays on the stream (echo still works, counter is 0).
/// Safari is only in the macOS profile pool.
#[cfg(target_os = "macos")]
#[test]
fn tls_udp_h3_datagrams_safari_none() -> Result<(), BoxError> {
    if !e2e_enabled() {
        skip_notice("tls_udp_h3_datagrams_safari_none");
        return Ok(());
    }
    for mode in ["ws_h3", "xhttp_h3"] {
        let sent = run_udp_datagram_case(mode, DatagramBrowser::Safari)?;
        assert_eq!(sent, 0.0, "{mode}: Safari profile must never send H3 datagrams");
    }
    Ok(())
}
