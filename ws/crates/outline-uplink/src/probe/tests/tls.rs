use std::time::Duration;

use super::*;
use crate::probe::tests::spawn_vless_loopback;

/// Red-path smoke test for the TLS handshake-only probe: when the upstream
/// server forwards the ClientHello but never produces a `ServerHello` (the
/// exact `chunk0_timeout` pattern observed in the field), the handshake must
/// block on the next read so the caller's outer probe timeout can surface it
/// as a probe failure. The fake VLESS server here echoes only the response
/// header (no application bytes), so `read_chunk()` parks forever waiting
/// for the next data frame — equivalent to a silent upstream from the
/// client's view.
///
/// We bound the wait with `tokio::time::timeout` so a regression that makes
/// `drive_tls_handshake` return early on no-data fails the test loudly
/// instead of hanging forever.
#[tokio::test]
async fn tls_probe_silent_upstream_blocks_handshake() {
    let (mut writer, mut reader, _server) = spawn_vless_loopback(b"");

    let target = TargetAddr::Domain("example.com".to_string(), 443);
    let target_wire = target.to_wire_bytes().unwrap();
    let bytes = BytesRecorder { group: "g", uplink: "u", transport: "tcp", probe: "tls" };

    let result = tokio::time::timeout(
        Duration::from_millis(150),
        drive_tls_handshake(
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
