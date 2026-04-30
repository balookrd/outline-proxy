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
//!   HTTP/2 (selected via ALPN).
//!
//! An HTTP/3 adapter that reuses [`shared`] is planned alongside
//! `apply_to_h3` in `[http_fallback]`; until it lands the H3
//! listener keeps returning 404 for unmatched requests.

mod h1_axum;
mod shared;

pub(in crate::server) use h1_axum::http_fallback_handler;
pub(in crate::server) use shared::HttpFallbackContext;
