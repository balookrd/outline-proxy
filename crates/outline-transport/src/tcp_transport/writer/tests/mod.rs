use super::*;

use crate::tcp_transport::{SocketTcpReader, TcpShadowsocksReader};
use shadowsocks_crypto::CipherKind;
use tokio::net::{TcpListener, TcpStream};

const PASSWORD: &str = "send-chunks-writer-tests";

/// Loopback TCP pair with a server-side SS writer and a client-side SS reader.
/// Uses a non-SS2022 cipher so the request-header / salt-echo dance is skipped
/// and the data path is exercised directly.
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

    let writer = TcpShadowsocksWriter::connect_socket(
        server_write,
        cipher,
        &master_key,
        UpstreamTransportGuard::new("test", "tcp"),
    )
    .unwrap();
    let reader = TcpShadowsocksReader::new_socket(
        client_read,
        cipher,
        &master_key,
        UpstreamTransportGuard::new("test", "tcp"),
    );
    (writer, reader)
}

/// Reads decrypted chunks until `total` bytes have been collected.
async fn read_exact_bytes(reader: &mut SocketTcpReader, total: usize) -> Vec<u8> {
    let mut collected = Vec::with_capacity(total);
    while collected.len() < total {
        let chunk = reader.read_chunk().await.unwrap();
        assert!(!chunk.is_empty(), "reader yielded an empty chunk before EOF");
        collected.extend_from_slice(&chunk);
    }
    collected
}

/// A batch of `Bytes` whose reassembly must equal their concatenation, across
/// chunk sizes that straddle AEAD-record and `FRAME_SOFT_CAP` boundaries: sub-byte,
/// sub-MSS, an over-`max` chunk (fast path + record straddle), and an interleaved
/// empty chunk (which must be skipped without corrupting the stream).
fn mixed_batch() -> Vec<Bytes> {
    let mut batch = Vec::new();
    batch.push(Bytes::from(vec![0xAB; 1])); // single byte
    batch.push(Bytes::new()); // empty — must be a no-op
    for i in 0..220u16 {
        // ~330 KiB of ~MSS chunks — exceeds FRAME_SOFT_CAP, forcing frame flushes.
        batch.push(Bytes::from(vec![i as u8; 1460]));
    }
    batch.push(Bytes::from(vec![0xCD; 150_000])); // > max (65535): fast path + straddle
    batch.push(Bytes::from(vec![0xEF; 777]));
    batch
}

#[tokio::test]
async fn send_chunks_reassembles_to_the_concatenation_of_the_batch() {
    let (mut writer, mut reader) = ss_socket_pair().await;
    let batch = mixed_batch();
    let expected: Vec<u8> = batch.iter().flat_map(|b| b.iter().copied()).collect();

    let sent = batch.clone();
    let writer_task = tokio::spawn(async move {
        writer.send_chunks(&sent).await.unwrap();
        // Keep the writer alive until the reader has drained everything.
        writer
    });

    let got = read_exact_bytes(&mut reader, expected.len()).await;
    assert_eq!(got, expected, "send_chunks must deliver the batch bytes in order");

    let _writer = writer_task.await.unwrap();
}

#[tokio::test]
async fn send_chunks_matches_a_single_send_chunk_over_the_concatenation() {
    // The vectored path must be wire-equivalent to concatenating first and calling
    // the scalar path: same plaintext out of the reader, regardless of buffering.
    let batch = mixed_batch();
    let concatenated: Vec<u8> = batch.iter().flat_map(|b| b.iter().copied()).collect();

    let (mut w_vec, mut r_vec) = ss_socket_pair().await;
    let (mut w_scalar, mut r_scalar) = ss_socket_pair().await;

    let sent = batch.clone();
    let vec_task = tokio::spawn(async move {
        w_vec.send_chunks(&sent).await.unwrap();
        w_vec
    });
    let scalar_payload = concatenated.clone();
    let scalar_task = tokio::spawn(async move {
        w_scalar.send_chunk(&scalar_payload).await.unwrap();
        w_scalar
    });

    let via_chunks = read_exact_bytes(&mut r_vec, concatenated.len()).await;
    let via_scalar = read_exact_bytes(&mut r_scalar, concatenated.len()).await;

    assert_eq!(via_chunks, concatenated);
    assert_eq!(via_chunks, via_scalar);

    let _ = vec_task.await.unwrap();
    let _ = scalar_task.await.unwrap();
}

// ── SS2022 header hold (`write_frame_held`) ─────────────────────────────────

use crate::tcp_transport::writer::transport::SS2022_HEADER_HOLD;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio_tungstenite::tungstenite::error::Error as WsError;

/// Sink that records every message handed to it, plus a `Close(None)` marker
/// when the writer task closes it.
struct RecordingSink(mpsc::UnboundedSender<Message>);

impl futures_util::Sink<Message> for RecordingSink {
    type Error = WsError;
    fn poll_ready(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Result<(), WsError>> {
        Poll::Ready(Ok(()))
    }
    fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), WsError> {
        let _ = self.0.send(item);
        Ok(())
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Result<(), WsError>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<Result<(), WsError>> {
        let _ = self.0.send(Message::Close(None));
        Poll::Ready(Ok(()))
    }
}

fn ws_transport() -> (WsWriteTransport, mpsc::Sender<Message>, mpsc::UnboundedReceiver<Message>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let (transport, ctrl_tx) = WsWriteTransport::spawn(RecordingSink(tx), false);
    (transport, ctrl_tx, rx)
}

fn binary(payload: &[u8]) -> Message {
    Message::Binary(payload.to_vec().into())
}

#[tokio::test(start_paused = true)]
async fn held_header_merges_with_the_next_data_frame_into_one_message() {
    let (mut t, _ctrl, mut rx) = ws_transport();
    t.write_frame_held(b"HEADER".to_vec()).await.unwrap();
    tokio::time::advance(Duration::from_millis(4)).await;
    t.write_frame(b"CLIENTHELLO".to_vec()).await.unwrap();
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::task::yield_now().await;

    assert_eq!(rx.try_recv().unwrap(), binary(b"HEADERCLIENTHELLO"));
    assert!(rx.try_recv().is_err(), "header and data must share ONE message");
}

#[tokio::test(start_paused = true)]
async fn held_header_goes_out_alone_after_the_hold_window() {
    let (mut t, _ctrl, mut rx) = ws_transport();
    t.write_frame_held(b"HEADER".to_vec()).await.unwrap();
    tokio::time::advance(SS2022_HEADER_HOLD / 2).await;
    tokio::task::yield_now().await;
    assert!(rx.try_recv().is_err(), "header must still be held inside the window");

    tokio::time::advance(SS2022_HEADER_HOLD).await;
    tokio::task::yield_now().await;
    assert_eq!(rx.try_recv().unwrap(), binary(b"HEADER"));
    assert!(rx.try_recv().is_err());

    // Later data is a normal standalone message.
    t.write_frame(b"LATE".to_vec()).await.unwrap();
    tokio::task::yield_now().await;
    assert_eq!(rx.try_recv().unwrap(), binary(b"LATE"));
}

#[tokio::test(start_paused = true)]
async fn held_header_is_flushed_before_the_writer_closes() {
    let (mut t, _ctrl, mut rx) = ws_transport();
    t.write_frame_held(b"HEADER".to_vec()).await.unwrap();
    t.close().await.unwrap();
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    assert_eq!(rx.try_recv().unwrap(), binary(b"HEADER"));
    assert_eq!(rx.try_recv().unwrap(), Message::Close(None));
}

#[tokio::test(start_paused = true)]
async fn held_header_is_flushed_before_a_control_message() {
    let (mut t, ctrl, mut rx) = ws_transport();
    t.write_frame_held(b"HEADER".to_vec()).await.unwrap();
    ctrl.send(Message::Pong(vec![1].into())).await.unwrap();
    tokio::task::yield_now().await;

    assert_eq!(rx.try_recv().unwrap(), binary(b"HEADER"));
    assert_eq!(rx.try_recv().unwrap(), Message::Pong(vec![1].into()));
}

#[tokio::test(start_paused = true)]
async fn socket_transport_default_held_write_is_immediate() {
    let (mut writer, mut reader) = ss_socket_pair().await;
    writer.send_chunk(b"plain").await.unwrap();
    assert_eq!(read_exact_bytes(&mut reader, 5).await, b"plain");
}

/// Collects Binary payloads up to the writer's `Close` marker.
async fn collect_until_close(rx: &mut mpsc::UnboundedReceiver<Message>) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(m) = rx.recv().await {
        match m {
            Message::Binary(b) => out.extend_from_slice(&b),
            Message::Close(_) => break,
            _ => {},
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn held_header_precedes_data_under_multithread_races() {
    for _ in 0..200 {
        let (mut t, _ctrl, mut rx) = ws_transport();
        t.write_frame_held(b"HEADER".to_vec()).await.unwrap();
        t.write_frame(b"DATA".to_vec()).await.unwrap();
        t.close().await.unwrap();
        assert_eq!(collect_until_close(&mut rx).await, b"HEADERDATA");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn held_header_survives_immediate_close_under_multithread_races() {
    for _ in 0..200 {
        let (mut t, _ctrl, mut rx) = ws_transport();
        t.write_frame_held(b"HEADER".to_vec()).await.unwrap();
        t.close().await.unwrap();
        assert_eq!(collect_until_close(&mut rx).await, b"HEADER");
    }
}

// ── Lead-in cover frequency on the shaped first write ───────────────────────

/// Splits one WS message into the `real_len` of each padding frame it holds.
fn frame_real_lens(msg: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= msg.len() {
        let real = u16::from_be_bytes([msg[i], msg[i + 1]]) as usize;
        let pad = u16::from_be_bytes([msg[i + 2], msg[i + 3]]) as usize;
        out.push(real);
        i += 4 + real + pad;
    }
    assert_eq!(i, msg.len(), "message must be a whole number of padding frames");
    out
}

/// Capture analysis found lead-in covers in far fewer sessions than the 1/2
/// draw predicts. On SS the held SS2022 header merges with the first queued
/// message, which is the first cover, so that cover shares a record with the
/// header and never shows up as a standalone pad-only message. The cover is
/// still emitted: it must be present in about half of the sessions.
#[tokio::test(start_paused = true)]
async fn lead_in_cover_rides_with_the_held_header_on_about_half_of_sessions() {
    crate::carrier_padding::init_carrier_padding(
        crate::carrier_padding::CarrierPadding {
            scheme: outline_wire::padding::PaddingScheme::new(0, 64),
            cover: false,
            cover_jitter_min_ms: 0,
            cover_jitter_max_ms: 0,
        },
        false,
    );
    let (mut with_cover, mut standalone_cover) = (0, 0);
    for _ in 0..200 {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut t = crate::carrier_padding::with_uplink_padding_override(true, async {
            let (t, _ctrl) = WsWriteTransport::spawn(RecordingSink(tx), true);
            t
        })
        .await;
        t.write_frame_held(vec![7u8; 120]).await.unwrap();
        t.write_frame(vec![9u8; 1964]).await.unwrap();
        tokio::time::advance(SS2022_HEADER_HOLD * 2).await;
        tokio::task::yield_now().await;
        t.close().await.unwrap();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let mut covers = 0;
        let mut data_bytes = 0;
        while let Ok(m) = rx.try_recv() {
            if let Message::Binary(b) = m {
                let lens = frame_real_lens(&b);
                if lens.iter().all(|&l| l == 0) {
                    standalone_cover += 1;
                }
                covers += lens.iter().filter(|&&l| l == 0).count();
                data_bytes += lens.iter().sum::<usize>();
            }
        }
        assert_eq!(data_bytes, 120 + 1964, "payload must survive shaping intact");
        if covers > 0 {
            with_cover += 1;
        }
    }
    assert!(
        (70..=130).contains(&with_cover),
        "sessions with a lead-in cover: {with_cover}/200"
    );
    eprintln!(
        "ss lead-in cover: {with_cover}/200 sessions, {standalone_cover} standalone cover messages"
    );
}

/// `shape = true` without padding (no per-uplink override in scope, global
/// default off): the first large write is cut into several plain `Binary`
/// messages, each within the client piece ceiling, that concatenate back to the
/// original bytes — no padding framing on the wire.
#[tokio::test(start_paused = true)]
async fn shaped_write_without_padding_splits_into_plain_messages() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (mut t, _ctrl) = WsWriteTransport::spawn(RecordingSink(tx), true);
    let frame: Vec<u8> = (0..1964u32).map(|i| i as u8).collect();
    t.write_frame(frame.clone()).await.unwrap();
    t.close().await.unwrap();
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    let mut pieces = Vec::new();
    while let Ok(m) = rx.try_recv() {
        if let Message::Binary(b) = m {
            pieces.push(b.to_vec());
        }
    }
    assert!(pieces.len() >= 2, "a 1964 B first write must be split: {}", pieces.len());
    assert!(
        pieces.iter().all(|p| (1..=850).contains(&p.len())),
        "piece sizes: {:?}",
        pieces.iter().map(Vec::len).collect::<Vec<_>>()
    );
    assert_eq!(pieces.concat(), frame, "plain pieces must concatenate to the write");
}
