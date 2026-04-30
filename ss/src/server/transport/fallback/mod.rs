//! Fallback dispatch for unmatched HTTP requests: forwards them to
//! an upstream backend so the listener can masquerade as a regular
//! web service.
//!
//! Layout:
//! - [`shared`] — transport-agnostic helpers (header rewriting,
//!   hop-by-hop stripping, `X-Forwarded-*` injection, upstream
//!   request-parts builder) plus the per-process
//!   [`HttpFallbackContext`].
//! - [`h1_axum`] — TCP listener integration. Wired into the axum
//!   router as a 404-replacement handler that covers HTTP/1.1 and
//!   HTTP/2 (selected via ALPN). Driven by `apply_to_h1`.
//! - [`h3_stream`] — HTTP/3 listener integration, called from the
//!   per-stream handler in `server::h3::http`. Driven by
//!   `apply_to_h3`. Buffers the request body up-front; streams the
//!   response body chunk-by-chunk back over QUIC.

mod h1_axum;
mod h3_stream;
mod shared;

pub(in crate::server) use h1_axum::http_fallback_handler;
pub(in crate::server) use h3_stream::{h3_fallback_handle, send_h3_status_only_response};
pub(in crate::server) use shared::HttpFallbackContext;
