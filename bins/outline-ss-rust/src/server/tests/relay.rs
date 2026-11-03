//! Tests for the shared upstream→client relay loop in `server::relay`.
//!
//! These drive the real loop through [`relay_upstream_to_client`] with a
//! non-TCP [`UpstreamRead`] impl — a test that only exercised a fake sink
//! while still requiring a real `TcpStream` upstream would stay green even
//! if the generification in this module were never done.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex;

use crate::config::CipherKind;
use crate::crypto::{AeadStreamDecryptor, AeadStreamEncryptor, StreamResponseContext, UserKey};
use crate::metrics::{AppProtocol, Metrics, Protocol};
use crate::server::transport::upstream_source::MESH_UPSTREAM_CHUNK;

use super::super::relay::{UpstreamRead, UpstreamSink, relay_upstream_to_client};
use super::super::resumption::downlink_ring::{DownlinkRing, ReplayOutcome};
use super::sample_config;

/// Fixed user key shared by `test_encryptor` and `decrypt_all` so
/// ciphertext produced by one can be undone by the other — decryption
/// recovers the per-message session key from the salt embedded in the
/// ciphertext plus this shared master key, not from sharing the live
/// `AeadStreamEncryptor` object.
fn test_user_key() -> UserKey {
    UserKey::new(
        "relay-test-user",
        "relay-test-password",
        None,
        CipherKind::Chacha20IetfPoly1305,
        None,
    )
    .expect("valid test user key")
}

fn test_encryptor() -> AeadStreamEncryptor {
    AeadStreamEncryptor::new(&test_user_key(), None).expect("valid test encryptor")
}

fn test_metrics() -> Arc<Metrics> {
    Metrics::new(&sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 3000))))
}

/// Undoes `test_encryptor`'s stream, concatenating every decrypted chunk in
/// order.
fn decrypt_all(chunks: &[Bytes]) -> Vec<u8> {
    let mut decryptor = AeadStreamDecryptor::new(Arc::from(vec![test_user_key()]));
    for chunk in chunks {
        decryptor.feed_ciphertext(chunk);
    }
    let mut plaintext = Vec::new();
    decryptor
        .drain_plaintext(&mut plaintext)
        .expect("valid ciphertext stream");
    plaintext
}

/// Records every ciphertext chunk handed to [`UpstreamSink::send_ciphertext`]
/// in arrival order, standing in for a real transport sink in tests that only
/// care about what bytes the relay loop emits.
#[derive(Default, Clone)]
struct RecordingSink {
    chunks: Arc<std::sync::Mutex<Vec<Bytes>>>,
}

impl RecordingSink {
    fn recorded(&self) -> Arc<std::sync::Mutex<Vec<Bytes>>> {
        Arc::clone(&self.chunks)
    }
}

impl UpstreamSink for RecordingSink {
    async fn send_ciphertext(&mut self, ciphertext: Bytes) -> anyhow::Result<()> {
        self.chunks.lock().unwrap().push(ciphertext);
        Ok(())
    }

    async fn close(&mut self) {}
}

/// An upstream that is deliberately not a `TcpStream`: it hands out a scripted
/// sequence of chunks and then EOFs. Standing in for the mesh stream an edge
/// reads its plaintext from.
struct ScriptedUpstream {
    chunks: VecDeque<Vec<u8>>,
}

impl UpstreamRead for ScriptedUpstream {
    async fn readable(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn try_read_buf<B: bytes::BufMut>(&mut self, buf: &mut B) -> std::io::Result<usize> {
        // Like a socket (and the mesh upstream), hand over only what `buf`
        // has room for and keep the rest of the chunk for the next read.
        match self.chunks.pop_front() {
            Some(mut chunk) => {
                let n = chunk.len().min(buf.remaining_mut());
                let rest = chunk.split_off(n);
                buf.put_slice(&chunk);
                if !rest.is_empty() {
                    self.chunks.push_front(rest);
                }
                Ok(n)
            },
            None => Ok(0), // EOF
        }
    }
}

#[tokio::test]
async fn relay_pumps_a_non_tcp_upstream_through_to_the_sink() {
    let upstream = ScriptedUpstream {
        chunks: vec![b"alpha".to_vec(), b"beta".to_vec()].into(),
    };
    let sink = RecordingSink::default();
    let recorded = sink.recorded();
    let mut encryptor = test_encryptor();

    relay_upstream_to_client(
        upstream,
        sink,
        &mut encryptor,
        test_metrics(),
        Protocol::Http1,
        AppProtocol::Shadowsocks,
        Arc::from("beerloga"),
        None,
        None,
        None,
    )
    .await
    .expect("the relay completes when the upstream reaches EOF");

    assert_eq!(
        decrypt_all(&recorded.lock().unwrap()),
        b"alphabeta",
        "every upstream chunk must reach the client, in order"
    );
}

#[tokio::test]
async fn relay_captures_plaintext_into_the_ring_before_encrypting() {
    // The ring must hold plaintext: that is the property letting a *different*
    // node re-seal a replay under its own client key, which is what makes
    // cross-node continuity possible at all.
    let upstream = ScriptedUpstream { chunks: vec![b"ring-me".to_vec()].into() };
    let ring = Arc::new(Mutex::new(DownlinkRing::new(1024)));
    let mut encryptor = test_encryptor();

    relay_upstream_to_client(
        upstream,
        RecordingSink::default(),
        &mut encryptor,
        test_metrics(),
        Protocol::Http1,
        AppProtocol::Shadowsocks,
        Arc::from("beerloga"),
        None,
        Some(Arc::clone(&ring)),
        None,
    )
    .await
    .expect("the relay completes");

    let outcome = ring.lock().replay_from(0);
    let ReplayOutcome::Available(bytes) = outcome else {
        panic!("expected the whole plaintext to still be available, got {outcome:?}");
    };
    assert_eq!(bytes, b"ring-me", "the ring holds plaintext, not ciphertext");
}

/// An SS-2022 (AES) user. The chunk ceiling below is enforced only by the
/// SS-2022 encryptor: a legacy cipher splits an over-long chunk instead of
/// rejecting it, which is why the existing multi-megabyte ChaCha20 tests never
/// caught this.
fn ss2022_user_key() -> UserKey {
    UserKey::new(
        "relay-test-user",
        "MDEyMzQ1Njc4OWFiY2RlZg==",
        None,
        CipherKind::Aes128Gcm2022,
        None,
    )
    .expect("valid ss2022 test user key")
}

#[tokio::test]
async fn a_mesh_sized_chunk_survives_an_ss2022_relay() {
    // A cluster edge hands the relay one whole mesh chunk at a time — its
    // `try_read_buf` `put_slice`s the chunk in full rather than filling the
    // spare capacity the relay reserved, which is the bound that keeps a direct
    // TCP upstream inside `crypto::MAX_CHUNK_SIZE`. So the plaintext buffer
    // handed to `encrypt_chunk` is exactly `MESH_UPSTREAM_CHUNK` long, and one
    // byte over the ceiling fails the whole relay task on an SS-2022 cipher:
    // with the previous `64 * 1024` this call returns
    // `CryptoError::InvalidChunkSize(65536)`.
    let upstream = ScriptedUpstream {
        chunks: vec![vec![0x5a; MESH_UPSTREAM_CHUNK]].into(),
    };
    let sink = RecordingSink::default();
    let recorded = sink.recorded();
    let mut encryptor = AeadStreamEncryptor::new(
        &ss2022_user_key(),
        Some(StreamResponseContext::for_test(&[7_u8; 16])),
    )
    .expect("valid ss2022 test encryptor");

    relay_upstream_to_client(
        upstream,
        sink,
        &mut encryptor,
        test_metrics(),
        Protocol::Http1,
        AppProtocol::Shadowsocks,
        Arc::from("beerloga"),
        None,
        None,
        None,
    )
    .await
    .expect("a full mesh chunk must fit one SS-2022 chunk");

    assert_eq!(
        recorded.lock().unwrap().len(),
        1,
        "the chunk goes out whole; a split would mean the ceiling was hit",
    );
}

/// A recording sink that asks the relay for a plaintext cap, standing in for a
/// `ChannelSink` on an h2 carrier.
#[derive(Clone)]
struct CappedSink {
    inner: RecordingSink,
    cap: Option<usize>,
}

impl UpstreamSink for CappedSink {
    async fn send_ciphertext(&mut self, ciphertext: Bytes) -> anyhow::Result<()> {
        self.inner.send_ciphertext(ciphertext).await
    }

    async fn close(&mut self) {}

    fn plaintext_cap(&self) -> Option<usize> {
        self.cap
    }
}

/// Per-chunk AEAD framing of both SS flavours: sealed length (2 + tag 16) plus
/// the payload tag (16).
const SS_CHUNK_OVERHEAD: usize = 34;

async fn run_capped(
    chunks: Vec<Vec<u8>>,
    cap: Option<usize>,
    mut encryptor: AeadStreamEncryptor,
) -> Vec<Bytes> {
    let sink = CappedSink { inner: RecordingSink::default(), cap };
    let recorded = sink.inner.recorded();
    relay_upstream_to_client(
        ScriptedUpstream { chunks: chunks.into() },
        sink,
        &mut encryptor,
        test_metrics(),
        Protocol::Http2,
        AppProtocol::Shadowsocks,
        Arc::from("beerloga"),
        None,
        None,
        None,
    )
    .await
    .expect("the relay completes");
    recorded.lock().unwrap().clone()
}

#[tokio::test]
async fn a_capped_sink_gets_every_ciphertext_within_cap_plus_chunk_overhead() {
    // 65536 B in one read (the most a direct TCP read or a mesh chunk hands
    // over), then a small tail: every message, the salted first one included,
    // must stay within `cap + 34`, and the stream must still decrypt whole.
    let cap = 16_337;
    let data: Vec<u8> = (0..65_536u32).map(|i| (i % 251) as u8).collect();
    let chunks =
        run_capped(vec![data.clone(), b"tail".to_vec()], Some(cap), test_encryptor()).await;
    assert!(chunks.len() >= 5, "65536 B at a 16337 B cap is at least five messages");
    for (i, c) in chunks.iter().enumerate() {
        assert!(c.len() <= cap + SS_CHUNK_OVERHEAD, "message {i} is {} B", c.len());
    }
    let mut expected = data;
    expected.extend_from_slice(b"tail");
    assert_eq!(decrypt_all(&chunks), expected);
}

#[tokio::test]
async fn a_capped_ss2022_sink_fits_the_response_header_into_the_first_message() {
    // SS-2022 puts salt + the sealed response header in front of the first
    // chunk; the relay shortens that chunk so the first message stays in budget.
    let cap = 16_337;
    let encryptor = AeadStreamEncryptor::new(
        &ss2022_user_key(),
        Some(StreamResponseContext::for_test(&[7_u8; 16])),
    )
    .expect("valid ss2022 test encryptor");
    let chunks = run_capped(vec![vec![0x5a; MESH_UPSTREAM_CHUNK]], Some(cap), encryptor).await;
    assert!(chunks.len() >= 5);
    for (i, c) in chunks.iter().enumerate() {
        assert!(c.len() <= cap + SS_CHUNK_OVERHEAD, "message {i} is {} B", c.len());
    }
    let wire: usize = chunks.iter().map(Bytes::len).sum();
    let header = 16 + 1 + 8 + 16; // salt + type + timestamp + request salt
    assert_eq!(wire, MESH_UPSTREAM_CHUNK + header + chunks.len() * SS_CHUNK_OVERHEAD);
}

#[tokio::test]
async fn an_uncapped_sink_still_gets_one_message_per_read() {
    let data = vec![0x11; 40_000];
    let chunks = run_capped(vec![data.clone()], None, test_encryptor()).await;
    assert_eq!(chunks.len(), 1, "no cap: the whole read is one message");
    assert_eq!(decrypt_all(&chunks), data);
}

#[tokio::test]
async fn a_capped_sink_on_a_bulk_upstream_gets_no_small_middle_messages() {
    // Far more than one message is available at once. The bounded read makes
    // every message a full one: a small remainder piece ahead of the next full
    // message is what h2 coalesces into a write that spills a full TLS record
    // plus a small one. Only the very last message may be short.
    let cap = 16_337;
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let chunks = run_capped(vec![data.clone()], Some(cap), test_encryptor()).await;
    // First message: 16305 B of data behind the 32-byte legacy salt; then
    // 16337 B each: 1 + ceil((200000 - 16305) / 16337) = 13 messages.
    assert_eq!(chunks.len(), 13);
    let (last, middle) = chunks.split_last().expect("messages were sent");
    for (i, c) in middle.iter().enumerate() {
        assert_eq!(c.len(), cap + SS_CHUNK_OVERHEAD, "message {i} is not a full one");
    }
    assert!(last.len() <= cap + SS_CHUNK_OVERHEAD);
    assert_eq!(decrypt_all(&chunks), data);
}
