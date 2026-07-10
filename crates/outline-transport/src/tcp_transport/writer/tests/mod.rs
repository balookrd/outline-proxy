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
