//! Small request/response helpers shared by the CRUD handlers.

use http::{Request, StatusCode};
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};

use crate::http::body::read_limited_body;
use crate::http::control::{ControlResponse, json_response};

pub(super) async fn read_json<T: for<'de> Deserialize<'de>>(
    request: Request<Incoming>,
) -> Result<T, ControlResponse> {
    let body = read_limited_body(request.into_body(), "/control/uplinks").await?;
    serde_json::from_slice::<T>(&body)
        .map_err(|e| json_error_owned(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")))
}

pub(super) fn json_error_owned(status: StatusCode, message: String) -> ControlResponse {
    #[derive(Serialize)]
    struct Owned {
        error: String,
    }
    json_response(status, &Owned { error: message })
}
