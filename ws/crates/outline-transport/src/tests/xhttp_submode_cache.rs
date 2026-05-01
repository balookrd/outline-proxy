//! Unit tests for the per-host XHTTP submode cache.
//!
//! Sibling of `tests/xhttp_mode_cache.rs` — same shape, scoped to the
//! stream-one ↔ packet-up axis instead of the h-version axis. Each
//! test parses a unique URL so the process-global cache map cannot
//! bleed state across concurrent tests sharing a `host:port`.

use url::Url;

use crate::xhttp::XhttpSubmode;
use crate::xhttp_submode_cache::{effective_submode, gc, record_failure, record_success};

#[tokio::test]
async fn no_entry_passes_requested_submode_through_unchanged() {
    let url: Url = "https://no-entry-submode.test:443/xhttp".parse().unwrap();
    assert_eq!(
        effective_submode(&url, XhttpSubmode::StreamOne).await,
        XhttpSubmode::StreamOne,
    );
    assert_eq!(
        effective_submode(&url, XhttpSubmode::PacketUp).await,
        XhttpSubmode::PacketUp,
    );
}

#[tokio::test]
async fn record_failure_stream_one_clamps_subsequent_stream_one_to_packet_up() {
    let url: Url = "https://record-stream-fail.test:443/xhttp".parse().unwrap();
    record_failure(&url, XhttpSubmode::StreamOne).await;
    assert_eq!(
        effective_submode(&url, XhttpSubmode::StreamOne).await,
        XhttpSubmode::PacketUp,
        "stream-one failure must clamp the next stream-one dial to packet-up",
    );
    // PacketUp requests are not affected by the cache.
    assert_eq!(
        effective_submode(&url, XhttpSubmode::PacketUp).await,
        XhttpSubmode::PacketUp,
    );
}

#[tokio::test]
async fn record_failure_packet_up_is_noop() {
    // Recording a packet-up failure would be a logic error at the
    // call site (packet-up is the carrier we fall back *to*). Guard
    // against that by making the cache silently ignore it.
    let url: Url = "https://record-packet-fail.test:443/xhttp".parse().unwrap();
    record_failure(&url, XhttpSubmode::PacketUp).await;
    assert_eq!(
        effective_submode(&url, XhttpSubmode::StreamOne).await,
        XhttpSubmode::StreamOne,
        "a packet-up failure must not seed the stream-one block",
    );
}

#[tokio::test]
async fn record_success_clears_block() {
    let url: Url = "https://success-clears-submode.test:443/xhttp".parse().unwrap();
    record_failure(&url, XhttpSubmode::StreamOne).await;
    assert_eq!(
        effective_submode(&url, XhttpSubmode::StreamOne).await,
        XhttpSubmode::PacketUp,
    );
    record_success(&url, XhttpSubmode::StreamOne).await;
    assert_eq!(
        effective_submode(&url, XhttpSubmode::StreamOne).await,
        XhttpSubmode::StreamOne,
        "successful stream-one dial must drop the clamp",
    );
}

#[tokio::test]
async fn record_success_packet_up_does_not_clear_stream_one_block() {
    // A packet-up success proves nothing about stream-one viability,
    // so it must leave any active block in place. Without this, the
    // very fallback we rely on (stream-one fail → retry packet-up)
    // would clear the cap immediately and the next dial would burn
    // another stream-one handshake.
    let url: Url = "https://success-packet-keeps-block.test:443/xhttp".parse().unwrap();
    record_failure(&url, XhttpSubmode::StreamOne).await;
    record_success(&url, XhttpSubmode::PacketUp).await;
    assert_eq!(
        effective_submode(&url, XhttpSubmode::StreamOne).await,
        XhttpSubmode::PacketUp,
        "a packet-up success must leave the stream-one block intact",
    );
}

#[tokio::test]
async fn gc_is_safe_to_call_with_active_entries() {
    // The cache TTL defaults to 60 s, so a freshly-recorded entry is
    // guaranteed to be in the future when `gc` runs. Smoke-test that
    // gc does not panic and does not strip live entries.
    let url: Url = "https://gc-keeps-live-submode.test:443/xhttp".parse().unwrap();
    record_failure(&url, XhttpSubmode::StreamOne).await;
    gc().await;
    assert_eq!(
        effective_submode(&url, XhttpSubmode::StreamOne).await,
        XhttpSubmode::PacketUp,
        "gc must not evict entries that have not yet expired",
    );
}
