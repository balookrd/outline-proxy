//! Helpers for bootstrapping application state from the parsed config.
//!
//! The per-user path route machinery that used to live here (`build_user_routes`,
//! `user_keys`, the stage-2 `build_*_route_map` builders and their route structs)
//! is gone: routing is now driven by `Config.endpoints` and built in one place,
//! [`super::endpoint_routes`]. Only this small HTTP-version helper — shared by the
//! transport handlers — remains.

use axum::http::Version;

use crate::metrics::Protocol;

pub(super) fn protocol_from_http_version(version: Version) -> Protocol {
    match version {
        Version::HTTP_2 => Protocol::Http2,
        _ => Protocol::Http1,
    }
}
