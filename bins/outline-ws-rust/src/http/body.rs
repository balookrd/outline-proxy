//! Bounded request-body reading, shared by the control and dashboard planes.
//!
//! Every endpoint that consumes a body goes through [`read_limited_body`]: an
//! unbounded `collect()` lets one peer decide how much heap the process
//! commits, and each listener admits a whole cap's worth of them at once (16
//! control connections, 64 dashboard ones), so the worst case is that cap times
//! the largest body a client cares to send. The bodies here are small JSON
//! documents (a group/uplink pair, one uplink definition, a proxy envelope), so
//! a 1 MiB ceiling is orders of magnitude above legitimate use and still bounds
//! the damage.

use bytes::Bytes;
use http::header::{CONTENT_TYPE, HeaderValue};
use http::{Response, StatusCode};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Body;
use tracing::warn;

/// Hard ceiling on a single request body. Anything larger is answered with 413
/// and the rest of the body is never buffered.
pub(crate) const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

/// Read a request body into memory, refusing anything over
/// [`MAX_REQUEST_BODY_BYTES`].
///
/// On the error path the caller gets a ready-made JSON response — 413 for an
/// over-limit body, 400 for a transport-level read failure — so handlers stay a
/// single `match` away from their payload. The response type is the one both
/// planes already use (`ControlResponse` / `DashboardResponse` are aliases of
/// it). `endpoint` is a static label used only for the warn log.
pub(crate) async fn read_limited_body<B>(
    body: B,
    endpoint: &'static str,
) -> Result<Bytes, Response<Full<Bytes>>>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    match Limited::new(body, MAX_REQUEST_BODY_BYTES).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => {
            warn!(
                endpoint,
                limit_bytes = MAX_REQUEST_BODY_BYTES,
                "request body exceeds the limit; rejecting"
            );
            Err(json_error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"))
        },
        Err(error) => {
            warn!(endpoint, error = %error, "failed to read request body");
            Err(json_error(StatusCode::BAD_REQUEST, "failed to read request body"))
        },
    }
}

/// Same `{"error": …}` shape both planes emit, built here so this module does
/// not depend on either plane's response helpers.
fn json_error(status: StatusCode, message: &'static str) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&serde_json::json!({ "error": message }))
        .unwrap_or_else(|_| br#"{"error":"internal server error"}"#.to_vec());
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    response
}

#[cfg(test)]
#[path = "tests/body.rs"]
mod tests;
