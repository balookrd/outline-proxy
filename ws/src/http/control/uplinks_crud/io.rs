//! Small request/response helpers shared by the CRUD handlers.

use http::{Request, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::http::control::{ControlResponse, json_error, json_response};

pub(super) async fn read_json<T: for<'de> Deserialize<'de>>(
    request: Request<Incoming>,
) -> Result<T, ControlResponse> {
    let body = request
        .into_body()
        .collect()
        .await
        .map_err(|e| {
            warn!(error = %e, "failed to read control request body");
            json_error(StatusCode::BAD_REQUEST, "failed to read request body")
        })?
        .to_bytes();
    serde_json::from_slice::<T>(&body).map_err(|e| {
        json_error_owned(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}"))
    })
}

pub(super) fn json_error_owned(status: StatusCode, message: String) -> ControlResponse {
    #[derive(Serialize)]
    struct Owned {
        error: String,
    }
    json_response(status, &Owned { error: message })
}
