use super::*;

use crate::http::body::MAX_REQUEST_BODY_BYTES;
use crate::http::tests::streamed_request;

fn test_state() -> DashboardState {
    DashboardState {
        refresh_interval_secs: 5,
        request_timeout_secs: 5,
        instances: Vec::new(),
    }
}

/// A dashboard body larger than [`MAX_REQUEST_BODY_BYTES`] must be rejected
/// with 413 instead of being buffered whole. The dashboard listener admits 64
/// concurrent connections — four times the control cap — so an unbounded
/// `collect()` here is the larger of the two exposures.
#[tokio::test]
async fn rejects_body_over_the_limit() {
    // Announce a body twice the ceiling, then stream just past the ceiling:
    // the answer must come from the limit, without the remaining announced
    // megabytes ever being sent — let alone buffered.
    let announced = MAX_REQUEST_BODY_BYTES * 2;
    let head = format!(
        "POST /dashboard/api/activate HTTP/1.1\r\nHost: localhost\r\n\
         Content-Type: application/json\r\nContent-Length: {announced}\r\n\
         Connection: close\r\n\r\n",
    );
    let parts = vec![head.into_bytes(), vec![b'a'; MAX_REQUEST_BODY_BYTES], vec![b'a'; 1]];
    let state = test_state();
    let (status, _body) = streamed_request(parts, move |stream| async move {
        let _ = super::super::handle_connection(stream, state).await;
    })
    .await;
    assert_eq!(status, 413, "oversized dashboard body must be rejected, not buffered");
}

/// The proxy envelope path (`/dashboard/api/uplinks` and friends) reads its
/// body through the same helper, so it is bounded too.
#[tokio::test]
async fn rejects_proxy_envelope_over_the_limit() {
    let announced = MAX_REQUEST_BODY_BYTES * 2;
    let head = format!(
        "POST /dashboard/api/uplinks HTTP/1.1\r\nHost: localhost\r\n\
         Content-Type: application/json\r\nContent-Length: {announced}\r\n\
         Connection: close\r\n\r\n",
    );
    let parts = vec![head.into_bytes(), vec![b'a'; MAX_REQUEST_BODY_BYTES], vec![b'a'; 1]];
    let state = test_state();
    let (status, _body) = streamed_request(parts, move |stream| async move {
        let _ = super::super::handle_connection(stream, state).await;
    })
    .await;
    assert_eq!(status, 413, "oversized proxy envelope must be rejected, not buffered");
}

/// A dashboard activate request without `soft` defaults to a hard switch, so the
/// aggregator forwards no `soft` field and the plain-activate wire shape is
/// unchanged.
#[test]
fn activate_request_defaults_soft_to_false() {
    let req: DashboardActivateRequest =
        serde_json::from_str(r#"{"targets":[{"instance":"i","group":"g","uplink":"u"}]}"#).unwrap();
    assert!(!req.soft, "soft must default to a hard switch");
}

/// The Soft switch control sends `soft: true`, which the aggregator forwards to
/// `/control/activate`.
#[test]
fn activate_request_parses_soft_true() {
    let req: DashboardActivateRequest = serde_json::from_str(
        r#"{"targets":[{"instance":"i","group":"g","uplink":"u"}],"soft":true}"#,
    )
    .unwrap();
    assert!(req.soft);
}
