use super::*;

use crate::ack_prefix::{FRAME_LEN_V1, MAGIC, VERSION_V1};
use crate::tcp_transport::{SocketTcpWriter, TcpShadowsocksWriter};
use shadowsocks_crypto::CipherKind;
use tokio::net::{TcpListener, TcpStream};

const PASSWORD: &str = "ack-prefix-reader-tests";

/// Builds a v1 control-frame plaintext payload carrying `up_acked`.
/// Mirrors the server-side serializer; kept inline so the tests stay
/// independent of any helper that may grow defaults the parser does
/// not actually require.
fn build_v1_frame(up_acked: u64) -> [u8; FRAME_LEN_V1] {
    let mut f = [0u8; FRAME_LEN_V1];
    f[..4].copy_from_slice(&MAGIC);
    f[4] = VERSION_V1;
    f[5] = 0;
    f[6..14].copy_from_slice(&up_acked.to_be_bytes());
    f
}

/// Sets up a real loopback TCP pair, splits both ends, and returns
/// a server-side SS writer plus a client-side SS reader (with no
/// `with_request_salt` — we always use the non-SS2022 cipher path
/// so the response-header step is skipped).
async fn ss_socket_pair() -> (SocketTcpWriter, SocketTcpReader) {
    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher.derive_master_key(PASSWORD).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
    let client_stream = TcpStream::connect(addr).await.unwrap();
    let server_stream = accept.await.unwrap();

    let (_server_read, server_write) = server_stream.into_split();
    let (client_read, _client_write) = client_stream.into_split();

    let lifetime_w = UpstreamTransportGuard::new("test", "tcp");
    let writer =
        TcpShadowsocksWriter::connect_socket(server_write, cipher, &master_key, lifetime_w)
            .unwrap();

    let lifetime_r = UpstreamTransportGuard::new("test", "tcp");
    let reader = TcpShadowsocksReader::new_socket(client_read, cipher, &master_key, lifetime_r);

    (writer, reader)
}

#[tokio::test]
async fn read_chunk_consumes_exact_14_byte_prefix_and_returns_next_payload() {
    let (mut writer, reader) = ss_socket_pair().await;
    let mut reader = reader.with_expect_ack_prefix(true);

    let prefix = build_v1_frame(987_654_321);
    let payload = b"hello-world".to_vec();

    let writer_task = tokio::spawn(async move {
        writer.send_chunk(&prefix).await.unwrap();
        writer.send_chunk(&payload).await.unwrap();
    });

    let chunk = reader.read_chunk().await.unwrap();
    assert_eq!(
        chunk, b"hello-world",
        "first chunk must be the next data frame, not the consumed prefix",
    );
    assert_eq!(
        reader.upstream_acked_offset(),
        Some(987_654_321),
        "up_acked must be parked on the reader after the prefix is consumed",
    );

    writer_task.await.unwrap();
}

#[tokio::test]
async fn read_chunk_returns_trailing_bytes_when_prefix_chunk_carries_extras() {
    // Server should normally emit the prefix as its own AEAD chunk, but
    // a future server (or a misconfigured one) might bundle data after
    // the 14 bytes. The reader must surface the trailing bytes as the
    // first data chunk so no upstream payload is dropped.
    let (mut writer, reader) = ss_socket_pair().await;
    let mut reader = reader.with_expect_ack_prefix(true);

    let mut bundled = build_v1_frame(42).to_vec();
    bundled.extend_from_slice(b"bonus-bytes");

    let writer_task = tokio::spawn(async move {
        writer.send_chunk(&bundled).await.unwrap();
    });

    let chunk = reader.read_chunk().await.unwrap();
    assert_eq!(chunk, b"bonus-bytes");
    assert_eq!(reader.upstream_acked_offset(), Some(42));

    writer_task.await.unwrap();
}

#[tokio::test]
async fn read_chunk_passthrough_when_expect_ack_prefix_is_false() {
    // A reader that did not negotiate the protocol must NEVER look at
    // payload bytes — even bytes that happen to start with "ORSM" are
    // upstream data and must be returned verbatim.
    let (mut writer, mut reader) = ss_socket_pair().await;
    let mut payload = Vec::new();
    payload.extend_from_slice(&MAGIC);
    payload.extend_from_slice(b"-but-not-actually-a-prefix");

    let writer_task = {
        let payload = payload.clone();
        tokio::spawn(async move {
            writer.send_chunk(&payload).await.unwrap();
        })
    };

    let chunk = reader.read_chunk().await.unwrap();
    assert_eq!(chunk, payload);
    assert_eq!(
        reader.upstream_acked_offset(),
        None,
        "no negotiation → accessor must always return None",
    );

    writer_task.await.unwrap();
}

#[tokio::test]
async fn read_chunk_drops_session_on_bad_magic() {
    let (mut writer, reader) = ss_socket_pair().await;
    let mut reader = reader.with_expect_ack_prefix(true);

    let mut bad = [0u8; FRAME_LEN_V1];
    bad[..4].copy_from_slice(b"NOPE");
    bad[4] = VERSION_V1;
    bad[6..14].copy_from_slice(&1u64.to_be_bytes());

    let writer_task = tokio::spawn(async move {
        writer.send_chunk(&bad).await.unwrap();
    });

    let err = reader.read_chunk().await.expect_err("bad magic must surface");
    let msg = format!("{err:#}");
    assert!(msg.contains("unexpected magic"), "expected magic error, got: {msg}",);
    assert!(
        reader.upstream_acked_offset().is_none(),
        "no offset should be parked on a failed parse",
    );

    writer_task.await.unwrap();
}

#[tokio::test]
async fn read_chunk_drops_session_on_unsupported_version() {
    let (mut writer, reader) = ss_socket_pair().await;
    let mut reader = reader.with_expect_ack_prefix(true);

    let mut bad = build_v1_frame(0);
    bad[4] = 0x99;

    let writer_task = tokio::spawn(async move {
        writer.send_chunk(&bad).await.unwrap();
    });

    let err = reader
        .read_chunk()
        .await
        .expect_err("unsupported version must surface");
    let msg = format!("{err:#}");
    assert!(msg.contains("unsupported version"), "expected version error, got: {msg}",);

    writer_task.await.unwrap();
}

#[tokio::test]
async fn read_chunk_drops_session_on_reserved_flags() {
    let (mut writer, reader) = ss_socket_pair().await;
    let mut reader = reader.with_expect_ack_prefix(true);

    let mut bad = build_v1_frame(7);
    bad[5] = 0x01;

    let writer_task = tokio::spawn(async move {
        writer.send_chunk(&bad).await.unwrap();
    });

    let err = reader.read_chunk().await.expect_err("reserved-flag bit must surface");
    let msg = format!("{err:#}");
    assert!(msg.contains("reserved flags"), "expected reserved-flags error, got: {msg}",);

    writer_task.await.unwrap();
}

#[tokio::test]
async fn read_chunk_drops_session_when_first_chunk_is_too_short() {
    // Server's emit always sends a full 14-byte AEAD chunk; receiving
    // a smaller chunk under expect_ack_prefix means something is wrong
    // and the spec says drop the session rather than try to "wait for
    // more bytes" (each AEAD chunk is atomic).
    let (mut writer, reader) = ss_socket_pair().await;
    let mut reader = reader.with_expect_ack_prefix(true);

    let writer_task = tokio::spawn(async move {
        writer.send_chunk(b"too-short").await.unwrap();
    });

    let err = reader
        .read_chunk()
        .await
        .expect_err("too-short prefix chunk must surface");
    let msg = format!("{err:#}");
    assert!(msg.contains("shorter than"), "expected too-short error, got: {msg}",);

    writer_task.await.unwrap();
}

#[tokio::test]
async fn upstream_acked_offset_is_none_until_first_read_completes() {
    let (_writer, reader) = ss_socket_pair().await;
    let reader = reader.with_expect_ack_prefix(true);
    assert_eq!(
        reader.upstream_acked_offset(),
        None,
        "before any read, the accessor must report None even when expect_ack_prefix is set",
    );
}

// ── consume_ack_prefix v1.1 fast path ─────────────────────────────────

#[tokio::test]
async fn consume_ack_prefix_returns_offset_without_blocking_for_data() {
    // The whole point of the v1.1 API: the orchestrator can surface
    // the offset BEFORE the relay loop reads any real data. The
    // server here sends only the prefix; consume_ack_prefix returns
    // the offset, then upstream_acked_offset() observes the same
    // value, and a subsequent read_chunk would block on the next
    // chunk (we abort the writer to confirm the consume call did
    // NOT block on data that was never sent).
    let (mut writer, reader) = ss_socket_pair().await;
    let mut reader = reader.with_expect_ack_prefix(true);
    let prefix = build_v1_frame(123_456);

    let writer_task = tokio::spawn(async move {
        writer.send_chunk(&prefix).await.unwrap();
        // Hold the writer open; without the consume_ack_prefix path,
        // a `read_chunk` here would hang waiting for the next chunk.
        std::future::pending::<()>().await;
    });

    let parsed = reader.consume_ack_prefix().await.unwrap();
    assert_eq!(parsed, Some(123_456));
    assert_eq!(reader.upstream_acked_offset(), Some(123_456));

    writer_task.abort();
}

#[tokio::test]
async fn consume_ack_prefix_stashes_extras_for_next_read_chunk() {
    let (mut writer, reader) = ss_socket_pair().await;
    let mut reader = reader.with_expect_ack_prefix(true);
    let mut bundled = build_v1_frame(7).to_vec();
    bundled.extend_from_slice(b"trailing-data");

    let writer_task = tokio::spawn(async move {
        writer.send_chunk(&bundled).await.unwrap();
    });

    assert_eq!(reader.consume_ack_prefix().await.unwrap(), Some(7));
    // Trailing bytes must surface on the very next read_chunk so no
    // upstream payload is silently dropped.
    let chunk = reader.read_chunk().await.unwrap();
    assert_eq!(chunk, b"trailing-data");

    writer_task.await.unwrap();
}

#[tokio::test]
async fn consume_ack_prefix_returns_none_when_protocol_not_negotiated() {
    let (_writer, mut reader) = ss_socket_pair().await;
    // Reader was NOT marked with `with_expect_ack_prefix(true)`, so
    // `consume_ack_prefix` must short-circuit without touching the
    // wire — proves the no-op call is safe to wire unconditionally
    // from the orchestrator regardless of negotiation outcome.
    assert_eq!(reader.consume_ack_prefix().await.unwrap(), None);
    assert_eq!(reader.upstream_acked_offset(), None);
}

#[tokio::test]
async fn consume_ack_prefix_is_idempotent_after_first_call() {
    let (mut writer, reader) = ss_socket_pair().await;
    let mut reader = reader.with_expect_ack_prefix(true);
    let writer_task = tokio::spawn(async move {
        writer.send_chunk(&build_v1_frame(99)).await.unwrap();
        std::future::pending::<()>().await;
    });

    assert_eq!(reader.consume_ack_prefix().await.unwrap(), Some(99));
    // Second call must NOT re-read; it returns the cached offset and
    // does not block on more bytes.
    assert_eq!(reader.consume_ack_prefix().await.unwrap(), Some(99));

    writer_task.abort();
}

#[tokio::test]
async fn consume_ack_prefix_with_timeout_surfaces_timeout_when_server_silent() {
    // Establish the cipher session (writer sends the salt as part of
    // its construction) but never push the prefix chunk. The reader
    // expects the prefix and must time out instead of hanging
    // forever — protects the orchestrator against a server that
    // negotiated the capability but forgot to emit.
    let (_writer, reader) = ss_socket_pair().await;
    let mut reader = reader.with_expect_ack_prefix(true);

    let err = reader
        .consume_ack_prefix_with_timeout(std::time::Duration::from_millis(100))
        .await
        .expect_err("silent server must surface as a timeout");
    let msg = format!("{err:#}");
    assert!(msg.contains("did not arrive within"), "expected timeout error, got: {msg}",);
}

#[tokio::test]
async fn consume_ack_prefix_drops_session_on_bad_magic() {
    let (mut writer, reader) = ss_socket_pair().await;
    let mut reader = reader.with_expect_ack_prefix(true);
    let mut bad = [0u8; FRAME_LEN_V1];
    bad[..4].copy_from_slice(b"NOPE");
    bad[4] = VERSION_V1;
    bad[6..14].copy_from_slice(&1u64.to_be_bytes());

    let writer_task = tokio::spawn(async move {
        writer.send_chunk(&bad).await.unwrap();
    });

    let err = reader
        .consume_ack_prefix()
        .await
        .expect_err("bad magic must surface from the v1.1 entry too");
    let msg = format!("{err:#}");
    assert!(msg.contains("unexpected magic"), "expected magic error, got: {msg}");

    writer_task.await.unwrap();
}
