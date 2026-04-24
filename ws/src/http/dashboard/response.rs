//! Shared response builders used by the dashboard server.

use bytes::Bytes;
use http::header::{HeaderValue, CONTENT_TYPE, LOCATION};
use http::{Response, StatusCode};
use http_body_util::Full;
use serde::Serialize;
use tracing::warn;

pub type DashboardResponse = Response<Full<Bytes>>;

pub fn redirect_response(location: &'static str) -> DashboardResponse {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::FOUND;
    response
        .headers_mut()
        .insert(LOCATION, HeaderValue::from_static(location));
    response
}

pub fn html_response(body: String) -> DashboardResponse {
    plain_response(StatusCode::OK, "text/html; charset=utf-8", Bytes::from(body))
}

pub fn json_response<T: Serialize>(status: StatusCode, payload: &T) -> DashboardResponse {
    match serde_json::to_vec(payload) {
        Ok(body) => plain_response(status, "application/json; charset=utf-8", Bytes::from(body)),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "failed to serialize dashboard JSON response");
            plain_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "application/json; charset=utf-8",
                Bytes::from_static(br#"{"error":"internal server error"}"#),
            )
        },
    }
}

pub fn json_error(status: StatusCode, message: &'static str) -> DashboardResponse {
    json_response(status, &serde_json::json!({ "error": message }))
}

pub fn plain_response(
    status: StatusCode,
    content_type: &'static str,
    body: Bytes,
) -> DashboardResponse {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}
