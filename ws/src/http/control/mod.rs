//! Control-plane HTTP listener.
//!
//! Bound separately from the metrics listener so that read-only observability
//! access does not imply authority to mutate runtime state. Every request must
//! present a bearer token matching `[control].token`; there is no anonymous
//! access path.

mod apply;
mod handlers;
mod server;
mod topology;
mod uplinks_crud;

pub use apply::ApplyHandle;

pub use server::spawn_control_server;

use bytes::Bytes;
use http::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use serde::Serialize;
use tracing::warn;

use handlers::ErrorResponse;

pub(crate) type ControlResponse = Response<Full<Bytes>>;

pub(crate) fn is_authorized(request: &Request<Incoming>, expected: &str) -> bool {
    let Some(header) = request.headers().get(AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = header.to_str() else {
        return false;
    };
    let Some(presented) = value.strip_prefix("Bearer ").map(str::trim) else {
        return false;
    };
    constant_time_eq(presented.as_bytes(), expected.as_bytes())
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub(crate) fn unauthorized_response() -> ControlResponse {
    let mut response = plain_response(
        StatusCode::UNAUTHORIZED,
        "text/plain; charset=utf-8",
        Bytes::from_static(b"unauthorized\n"),
    );
    response
        .headers_mut()
        .insert("WWW-Authenticate", HeaderValue::from_static("Bearer"));
    response
}

pub(crate) fn plain_response(
    status: StatusCode,
    content_type: &'static str,
    body: Bytes,
) -> ControlResponse {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

pub(crate) fn json_response<T: Serialize>(status: StatusCode, payload: &T) -> ControlResponse {
    match serde_json::to_vec(payload) {
        Ok(body) => plain_response(status, "application/json; charset=utf-8", Bytes::from(body)),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "failed to serialize control JSON response");
            plain_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "application/json; charset=utf-8",
                Bytes::from_static(br#"{"error":"internal server error"}"#),
            )
        },
    }
}

pub(crate) fn require_method(
    method: &Method,
    expected: Method,
    expected_label: &'static str,
) -> Option<ControlResponse> {
    if *method == expected {
        return None;
    }
    Some(plain_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "application/json; charset=utf-8",
        Bytes::from(
            serde_json::to_vec(&ErrorResponse {
                error: match expected_label {
                    "GET" => "use GET",
                    "POST" => "use POST",
                    _ => "bad method",
                },
            })
            .unwrap_or_else(|_| br#"{"error":"bad method"}"#.to_vec()),
        ),
    ))
}

pub(crate) fn json_error(status: StatusCode, message: &'static str) -> ControlResponse {
    json_response(status, &ErrorResponse { error: message })
}

#[cfg(test)]
mod tests;
