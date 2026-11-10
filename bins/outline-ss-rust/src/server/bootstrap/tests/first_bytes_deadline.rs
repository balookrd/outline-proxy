use std::io::ErrorKind;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    time::{Duration, Instant},
};

use super::FirstBytesDeadline;

const DEADLINE: Duration = Duration::from_secs(60);

#[tokio::test(start_paused = true)]
async fn a_silent_peer_is_timed_out_at_the_deadline() {
    let (_peer, ours) = duplex(64);
    let mut stream = FirstBytesDeadline::new(ours, 24, DEADLINE);
    let start = Instant::now();
    let error = stream
        .read(&mut [0u8; 8])
        .await
        .expect_err("silent peer must time out");
    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert_eq!(Instant::now() - start, DEADLINE);
}

/// Bytes short of the requirement do not lift the deadline: a peer cannot buy
/// unlimited time by sending one byte.
#[tokio::test(start_paused = true)]
async fn a_partial_delivery_does_not_lift_the_deadline() {
    let (mut peer, ours) = duplex(64);
    let mut stream = FirstBytesDeadline::new(ours, 24, DEADLINE);
    peer.write_all(b"PRI * HTTP").await.unwrap();
    let mut buf = [0u8; 64];
    assert_eq!(stream.read(&mut buf).await.unwrap(), 10);
    let error = stream.read(&mut buf).await.expect_err("the rest never arrives");
    assert_eq!(error.kind(), ErrorKind::TimedOut);
}

#[tokio::test(start_paused = true)]
async fn the_deadline_is_lifted_once_the_bytes_arrive() {
    let (mut peer, ours) = duplex(64);
    let mut stream = FirstBytesDeadline::new(ours, 24, DEADLINE);
    peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
    let mut buf = [0u8; 64];
    assert_eq!(stream.read(&mut buf).await.unwrap(), 24);

    // Long past the deadline the stream is still an ordinary pending read.
    let late = tokio::time::timeout(DEADLINE * 10, stream.read(&mut buf)).await;
    assert!(late.is_err(), "read after the requirement was met must stay pending");
    peer.write_all(b"more").await.unwrap();
    assert_eq!(stream.read(&mut buf).await.unwrap(), 4);
}

#[tokio::test(start_paused = true)]
async fn zero_required_bytes_never_times_out() {
    let (_peer, ours) = duplex(64);
    let mut stream = FirstBytesDeadline::new(ours, 0, DEADLINE);
    let read = tokio::time::timeout(DEADLINE * 10, stream.read(&mut [0u8; 8])).await;
    assert!(read.is_err(), "a pass-through wrapper must not time out");
}

#[tokio::test(start_paused = true)]
async fn end_of_stream_is_reported_as_is() {
    let (peer, ours) = duplex(64);
    drop(peer);
    let mut stream = FirstBytesDeadline::new(ours, 24, DEADLINE);
    assert_eq!(stream.read(&mut [0u8; 8]).await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn writes_pass_through() {
    let (mut peer, ours) = duplex(64);
    let mut stream = FirstBytesDeadline::new(ours, 24, DEADLINE);
    stream.write_all(b"settings").await.unwrap();
    let mut buf = [0u8; 8];
    peer.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"settings");
}
