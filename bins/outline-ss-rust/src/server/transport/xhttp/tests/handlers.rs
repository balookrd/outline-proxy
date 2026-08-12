//! Unit tests for the per-request body read bounds: a packet-up POST body must
//! read under a wall-clock timeout (not just a byte cap), and the stream-up
//! uplink pump must exit once its session is closed instead of leaking its task
//! on a body that has gone silent.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use bytes::Bytes;
use futures_util::{StreamExt, stream};

use super::XhttpSession;
use super::{PostBodyError, drain_stream_up_body, read_post_body};

/// A body that yields nothing and never ends — the slowloris shape.
fn stalling_body() -> Body {
    Body::from_stream(stream::pending::<Result<Bytes, std::io::Error>>())
}

/// A body that yields exactly one frame and then goes silent forever.
fn one_frame_then_silent(frame: &'static [u8]) -> Body {
    Body::from_stream(
        stream::once(async move { Ok::<Bytes, std::io::Error>(Bytes::from_static(frame)) })
            .chain(stream::pending::<Result<Bytes, std::io::Error>>()),
    )
}

#[tokio::test]
async fn post_body_read_times_out_on_a_stalled_body() {
    match read_post_body(stalling_body(), Duration::from_millis(50)).await {
        Err(PostBodyError::TimedOut) => {},
        Err(PostBodyError::TooLarge) => {
            panic!("a stalled body must time out, not report too-large")
        },
        Ok(_) => panic!("a body that never yields must not read as complete"),
    }
}

#[tokio::test]
async fn post_body_read_returns_a_complete_body() {
    let body = Body::from(Bytes::from_static(b"one packet"));
    let bytes = read_post_body(body, Duration::from_secs(5))
        .await
        .expect("a ready body reads");
    assert_eq!(bytes.as_ref(), b"one packet");
}

/// The stream-up pump, parked on a silent body, must notice the session being
/// closed (idle eviction / relay exit) within one poll interval and exit —
/// rather than leaking its task until the client finally sends or disconnects.
#[tokio::test]
async fn stream_up_pump_exits_when_session_closes() {
    let session = Arc::new(XhttpSession::new(Arc::from("stream-up"), None, None, None));
    let pump = tokio::spawn(drain_stream_up_body(
        Arc::clone(&session),
        one_frame_then_silent(b"hello"),
        Duration::from_millis(50),
    ));

    // The first frame lands in the ring, then the pump parks on the silent body.
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(!pump.is_finished(), "pump must stay alive while the session is open");
    assert!(
        session.pop_uplink_ready().is_some(),
        "the first frame was ingested before parking"
    );

    // Closing the session must let the pump exit within a poll interval.
    session.close();
    tokio::time::timeout(Duration::from_secs(1), pump)
        .await
        .expect("pump must exit within a poll interval of the close")
        .expect("join the pump task");
}
