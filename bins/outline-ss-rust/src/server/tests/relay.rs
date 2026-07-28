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
use crate::crypto::{AeadStreamDecryptor, AeadStreamEncryptor, UserKey};
use crate::metrics::{AppProtocol, Metrics, Protocol};

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
        match self.chunks.pop_front() {
            Some(chunk) => {
                buf.put_slice(&chunk);
                Ok(chunk.len())
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
