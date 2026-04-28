use super::*;
use crate::probe::tests::spawn_vless_loopback;

/// Regression for the "VLESS TCP-tunnel probe leaks SOCKS5 target_wire
/// into the upstream stream" bug AND the "VLESS request header is
/// never flushed for server-first targets" bug. With
/// `needs_socks5_target = false` the fake VLESS server must see an
/// empty app stream (just the request header, then EOF) — meaning
/// the empty `send_chunk(&[])` correctly flushed the header, and no
/// SOCKS5 prefix leaked in.
#[tokio::test]
async fn vless_tcp_tunnel_probe_flushes_header_without_socks5_prefix() {
    let (mut writer, mut reader, server) = spawn_vless_loopback(b"OK");

    let dummy_target =
        TargetAddr::Domain("example.com".to_string(), 25).to_wire_bytes().unwrap();
    let bytes = BytesRecorder { group: "g", uplink: "u", transport: "tcp", probe: "tcp" };
    let result = exchange_tcp_tunnel_probe(
        &mut writer,
        &mut reader,
        "u",
        "example.com",
        25,
        &dummy_target,
        false, // VLESS path
        &bytes,
    )
    .await
    .expect("exchange_tcp_tunnel_probe failed");
    assert!(result, "any byte from the target counts as success");

    writer.close().await.unwrap();
    let capture = server.await.unwrap().unwrap();
    assert!(
        capture.app_stream.is_empty(),
        "VLESS tcp-tunnel app stream must be empty (target carried in request header) — got: {:?}",
        capture.app_stream
    );
}
