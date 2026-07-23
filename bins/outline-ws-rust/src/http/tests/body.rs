use super::*;

use http_body_util::Full;

/// A body exactly at the ceiling is still accepted verbatim — the limit is an
/// upper bound, not an off-by-one rejection of legitimate traffic.
#[tokio::test]
async fn accepts_body_at_the_limit() {
    let payload = Bytes::from(vec![b'a'; MAX_REQUEST_BODY_BYTES]);
    let bytes = read_limited_body(Full::new(payload), "/test")
        .await
        .map_err(|response| response.status())
        .expect("body at the limit is allowed");
    assert_eq!(bytes.len(), MAX_REQUEST_BODY_BYTES);
}

/// One byte over the ceiling is refused with 413 instead of being buffered.
#[tokio::test]
async fn rejects_body_over_the_limit() {
    let payload = Bytes::from(vec![b'a'; MAX_REQUEST_BODY_BYTES + 1]);
    let response = read_limited_body(Full::new(payload), "/test")
        .await
        .expect_err("body over the limit must be refused");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
