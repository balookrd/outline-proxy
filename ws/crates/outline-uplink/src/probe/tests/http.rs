use std::time::Duration;

use super::*;
use crate::probe::tests::spawn_vless_loopback;

/// Regression for the "VLESS HTTP probe leaks SOCKS5 target_wire into
/// the upstream stream" bug: with `needs_socks5_target = false` the
/// fake VLESS server must see exactly the HTTP HEAD request — no atyp
/// / addr / port prefix. Equivalent to the live behavior on a VLESS
/// uplink (any transport mode), since target is already encoded in
/// the VLESS request header.
#[tokio::test]
async fn vless_http_probe_does_not_prefix_socks5_target() {
    let (mut writer, mut reader, server) =
        spawn_vless_loopback(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

    let dummy_target = TargetAddr::Domain("example.com".to_string(), 80).to_wire_bytes().unwrap();
    let bytes = BytesRecorder { group: "g", uplink: "u", transport: "tcp", probe: "http" };
    let result = exchange_http_probe(
        &mut writer,
        &mut reader,
        "example.com",
        80,
        "/",
        &dummy_target,
        false, // VLESS path
        &bytes,
    )
    .await
    .expect("exchange_http_probe failed");
    assert!(result.status_ok, "fake server returned 200; probe should report status_ok");

    // Drop the writer so the server task observes a clean EOF and the
    // capture future resolves.
    writer.close().await.unwrap();
    let capture = server.await.unwrap().unwrap();

    let app = String::from_utf8(capture.app_stream).unwrap();
    assert!(
        app.starts_with("HEAD / HTTP/1.1\r\n"),
        "VLESS app stream should start with the HEAD request — got: {app:?}"
    );
    assert!(
        !app.contains("\x02example.com"),
        "VLESS app stream must not contain a SOCKS5 atyp/host prefix — got: {app:?}"
    );
}

/// Symmetric positive control: with `needs_socks5_target = true` (the
/// pre-fix behavior, still correct for SS-AEAD uplinks) the captured
/// server-side stream MUST contain the SOCKS5 atyp prefix ahead of
/// the HTTP request. Pinning this guards against accidentally
/// flipping the default for SS uplinks.
#[tokio::test]
async fn ss_style_http_probe_prefixes_socks5_target() {
    let (mut writer, mut reader, server) =
        spawn_vless_loopback(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

    let target = TargetAddr::Domain("example.com".to_string(), 80);
    let target_wire = target.to_wire_bytes().unwrap();
    let bytes = BytesRecorder { group: "g", uplink: "u", transport: "tcp", probe: "http" };
    let _ = exchange_http_probe(
        &mut writer,
        &mut reader,
        "example.com",
        80,
        "/",
        &target_wire,
        true, // SS path
        &bytes,
    )
    .await
    .expect("exchange_http_probe failed");

    writer.close().await.unwrap();
    let capture = server.await.unwrap().unwrap();
    // With needs_socks5_target=true the captured app stream begins
    // with the SOCKS5 atyp/host/port wire form, not "HEAD".
    assert!(
        capture.app_stream.starts_with(&target_wire),
        "SS-style probe must prefix target_wire to the app stream"
    );
}

/// Red-path smoke test for the HTTPS handshake-only probe: when the
/// upstream server forwards the ClientHello but never produces a
/// `ServerHello` (the exact `chunk0_timeout` pattern observed in the
/// field), the handshake must block on the next read so the caller's
/// outer probe timeout can surface it as a probe failure. The fake
/// VLESS server here echoes only the response header (no application
/// bytes), so `read_chunk()` parks forever waiting for the next data
/// frame — equivalent to a silent upstream from the client's view.
///
/// We bound the wait with `tokio::time::timeout` so a regression that
/// makes `run_https_handshake_probe` return early on no-data fails the
/// test loudly instead of hanging forever.
#[tokio::test]
async fn https_probe_silent_upstream_blocks_handshake() {
    let (mut writer, mut reader, _server) = spawn_vless_loopback(b"");

    let target = TargetAddr::Domain("example.com".to_string(), 443);
    let target_wire = target.to_wire_bytes().unwrap();
    let bytes = BytesRecorder { group: "g", uplink: "u", transport: "tcp", probe: "https" };

    let result = tokio::time::timeout(
        Duration::from_millis(150),
        run_https_handshake_probe(
            &mut writer,
            &mut reader,
            "example.com",
            &target_wire,
            false, // VLESS path: target encoded in the request header, no SOCKS5 prefix
            &bytes,
        ),
    )
    .await;

    assert!(
        result.is_err(),
        "silent upstream must keep the TLS handshake parked until the caller's timeout fires"
    );
}
