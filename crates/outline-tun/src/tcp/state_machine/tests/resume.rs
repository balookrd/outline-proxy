use outline_transport::SessionId;
use outline_transport::uplink_replay::PushError;

use super::*;

fn session_id(seed: u8) -> SessionId {
    SessionId::from_bytes([seed; 16])
}

#[test]
fn a_fresh_flow_is_not_resumable() {
    let resume = FlowResume::disarmed();
    assert!(!resume.is_resumable());
    assert!(resume.session_id.is_none());
    assert!(resume.replay().is_none());
    assert_eq!(resume.client_acked_offset(), 0);
}

#[test]
fn arming_records_the_flows_own_session_id_and_a_capped_ring() {
    let resume = FlowResume::armed(Some(session_id(0xab)));
    assert!(resume.is_resumable());
    assert_eq!(resume.session_id, Some(session_id(0xab)));
    let ring = resume.replay().expect("an armed flow holds a ring");
    assert_eq!(ring.capacity_bytes(), TUN_UPLINK_REPLAY_RING_BYTES);
    // The cap is a ceiling, not a preallocation: nothing is buffered until the
    // flow actually sends.
    assert_eq!(ring.buffered_bytes(), 0);
    assert_eq!(ring.total_sent(), 0);
}

#[test]
fn uplink_chunks_accumulate_in_send_order_and_track_total_sent() {
    let mut resume = FlowResume::armed(Some(session_id(1)));
    resume.record_uplink_chunk(b"GET / ").unwrap();
    resume.record_uplink_chunk(b"HTTP/1.1\r\n").unwrap();

    let ring = resume.replay().unwrap();
    assert_eq!(ring.total_sent(), 16);
    assert_eq!(ring.buffered_bytes(), 16);
    // Replay from the start hands back the exact byte stream the writer got.
    assert_eq!(ring.replay_from(0).unwrap(), b"GET / HTTP/1.1\r\n".to_vec());
    // …and from a mid-chunk offset, the suffix a server would still be missing.
    assert_eq!(ring.replay_from(6).unwrap(), b"HTTP/1.1\r\n".to_vec());
}

#[test]
fn an_oversized_chunk_downgrades_the_flow_instead_of_torn_replay() {
    let mut resume = FlowResume::armed_with_capacity(Some(session_id(2)), 8);
    resume.record_uplink_chunk(b"12345678").unwrap();
    assert!(resume.is_resumable());

    let error = resume
        .record_uplink_chunk(b"123456789")
        .expect_err("a chunk larger than the ring can never be replayed whole");
    assert!(matches!(
        error,
        PushError::OversizedSingleChunk { chunk_len: 9, capacity_bytes: 8 }
    ));

    // Downgraded, not poisoned: the ring is gone (so no later replay can skip a
    // hole), the id survives, and further recording is a silent no-op rather
    // than a repeated error the caller must keep handling.
    assert!(!resume.is_resumable());
    assert!(resume.replay().is_none());
    assert_eq!(resume.session_id, Some(session_id(2)));
    resume
        .record_uplink_chunk(b"more")
        .expect("recording on a downgraded flow is a no-op");
    assert!(!resume.is_resumable());
}

#[test]
fn downstream_payload_bytes_accumulate_even_after_a_downgrade() {
    let mut resume = FlowResume::armed_with_capacity(Some(session_id(3)), 8);
    resume.record_downlink_payload(100);
    resume.record_downlink_payload(23);
    assert_eq!(resume.client_acked_offset(), 123);

    resume.record_uplink_chunk(&[0u8; 64]).unwrap_err();
    assert!(!resume.is_resumable());

    // The counter is about bytes taken from the server, which is still true of a
    // flow that can no longer replay its uplink.
    resume.record_downlink_payload(7);
    assert_eq!(resume.client_acked_offset(), 130);
}

#[test]
fn each_flow_owns_its_session_id() {
    let first = FlowResume::armed(Some(session_id(0x11)));
    let second = FlowResume::armed(Some(session_id(0x22)));
    assert_ne!(first.session_id, second.session_id);

    // Rings are per-flow too: one flow's uplink never shows up in another's
    // replay tail (a shared ring would replay foreign bytes into this flow's
    // upstream on a resume hit).
    let mut first = first;
    first.record_uplink_chunk(b"first-flow").unwrap();
    assert_eq!(first.replay().unwrap().total_sent(), 10);
    assert_eq!(second.replay().unwrap().total_sent(), 0);
}
