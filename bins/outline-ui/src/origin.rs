//! Origin guard for the UI listener: the checks that keep a foreign web page
//! from driving the panel through the operator's own browser.
//!
//! Reaching this listener is equivalent to holding every managed instance's
//! control token (`backend.rs` injects them server-side), so these checks matter
//! as much as the credential gate. Two shapes get past credentials on their own:
//!
//! * **DNS rebinding.** A page on `evil.example` with a short-TTL record that
//!   flips to `127.0.0.1` reaches a loopback-bound panel as a *same-origin*
//!   request — binding to loopback does not help, because the attacker's page
//!   runs on the operator's machine. Absent a `Host` check, `Host: evil.example`
//!   is served, and the page reads and mutates every instance.
//! * **CSRF via a simple request.** A cross-origin `POST` with no JSON body
//!   needs no preflight; with HTTP Basic configured, the browser reattaches the
//!   cached credentials on its own.
//!
//! Three checks, applied to every request before routing so a newly added route
//! cannot slip past them, and independently of whether a token is set:
//!
//! 1. **`Host`** must name this listener — loopback names/addresses, the address
//!    the panel is bound to, plus whatever the operator declared in
//!    `[server] allowed_hosts`. A rebound domain fails here: the browser still
//!    sends the attacker's *name* in `Host`, whatever it resolves to.
//! 2. **`Origin`**, when present, must be this panel's own origin. Browsers
//!    attach it to every non-GET request, so this is what actually sinks the
//!    CSRF. Absent `Origin` is allowed: `curl` and other non-browser clients
//!    never send one, and they are not the threat — a page cannot suppress it.
//! 3. **`Content-Type: application/json`** on any body-bearing method, which
//!    takes the "simple request" escape hatch away from the shapes that never
//!    carry `Origin` (older browsers, form posts).
//!
//! Ports are deliberately *not* part of the `Host` check: reaching the panel
//! through `kubectl port-forward` or an ingress is routine, and the port carries
//! no protection anyway. `Origin` is still matched against `Host` verbatim, port
//! included, so a different local port is a different origin and stays rejected.

use std::net::{IpAddr, SocketAddr};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{CONTENT_TYPE, HOST, ORIGIN};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tracing::warn;

/// What this listener accepts as "its own" origin.
#[derive(Clone, Debug)]
pub struct OriginPolicy {
    listen: SocketAddr,
    /// Extra host names from `[server] allowed_hosts`, normalised to bare
    /// lowercase host parts (port and IPv6 brackets stripped).
    allowed_hosts: Vec<String>,
}

impl OriginPolicy {
    pub fn new(listen: SocketAddr, allowed_hosts: &[String]) -> Self {
        let allowed_hosts = allowed_hosts
            .iter()
            .map(|entry| host_of_authority(entry).to_ascii_lowercase())
            .filter(|host| !host.is_empty())
            .collect();
        Self { listen, allowed_hosts }
    }

    /// The response to answer with when a request does not look like one to this
    /// panel from this panel; `None` means routing may proceed.
    fn rejection(&self, method: &Method, headers: &HeaderMap) -> Option<Response> {
        let host = headers.get(HOST).and_then(|value| value.to_str().ok()).unwrap_or("");
        if !self.host_allowed(host) {
            warn!(host, "request rejected: unexpected Host header");
            return Some((StatusCode::FORBIDDEN, "unexpected Host header\n").into_response());
        }

        if let Some(origin) = headers.get(ORIGIN) {
            let origin = origin.to_str().unwrap_or("");
            if !self.origin_allowed(origin, host) {
                warn!(origin, "request rejected: cross-origin request");
                return Some(
                    (StatusCode::FORBIDDEN, "cross-origin request rejected\n").into_response(),
                );
            }
        }

        if method_carries_body(method) {
            let content_type = headers
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");
            if !is_json_content_type(content_type) {
                return Some(
                    (
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "expected Content-Type: application/json\n",
                    )
                        .into_response(),
                );
            }
        }

        None
    }

    /// `Host` names this listener: a loopback address or name, the bound address
    /// itself (any literal address when bound to a wildcard, since the interface
    /// the operator browses through is not knowable here), or an
    /// operator-declared name.
    fn host_allowed(&self, host_header: &str) -> bool {
        let host = host_of_authority(host_header).to_ascii_lowercase();
        if host.is_empty() {
            return false;
        }
        if self.allowed_hosts.contains(&host) {
            return true;
        }
        match host.parse::<IpAddr>() {
            Ok(ip) => {
                ip.is_loopback() || self.listen.ip().is_unspecified() || ip == self.listen.ip()
            },
            Err(_) => host == "localhost",
        }
    }

    /// `Origin` is this panel's own. Matched against `Host` verbatim (scheme
    /// aside), which is what a browser sends for a same-origin request through
    /// any port mapping. An ingress that rewrites `Host` breaks that equality, so
    /// an operator-declared name is accepted too.
    fn origin_allowed(&self, origin: &str, host_header: &str) -> bool {
        // Opaque origins ("null", from a sandboxed frame or a `file://` page)
        // have no `://` and fall out here.
        let Some((scheme, authority)) = origin.split_once("://") else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return false;
        }
        let authority = authority.split('/').next().unwrap_or("").trim();
        if !authority.is_empty() && authority.eq_ignore_ascii_case(host_header.trim()) {
            return true;
        }
        let host = host_of_authority(authority).to_ascii_lowercase();
        !host.is_empty() && self.allowed_hosts.contains(&host)
    }
}

/// Enforces the origin policy ahead of route matching. Layered unconditionally,
/// so it runs whether or not a listener token is configured; the credential gate
/// sits outside it and answers first.
pub async fn enforce_origin(
    State(policy): State<OriginPolicy>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if let Some(rejection) = policy.rejection(request.method(), request.headers()) {
        return rejection;
    }
    next.run(request).await
}

/// Bare host of an `host[:port]` authority: IPv6 brackets and the port are
/// dropped, as is the DNS root dot (`localhost.` is `localhost`).
fn host_of_authority(authority: &str) -> &str {
    let authority = authority.trim();
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once(']').map_or(rest, |(host, _)| host)
    } else if authority.matches(':').count() > 1 {
        // A bare IPv6 literal — invalid in `Host`, but accepted in config.
        authority
    } else {
        authority.split(':').next().unwrap_or("")
    };
    host.strip_suffix('.').unwrap_or(host)
}

/// Methods whose requests may carry a body, and therefore must declare JSON.
/// Anything but the read-only trio, so a future `PUT` route is covered without
/// being listed here.
fn method_carries_body(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// `application/json`, with or without parameters (`; charset=utf-8`).
fn is_json_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/json")
}

#[cfg(test)]
#[path = "tests/origin.rs"]
mod tests;
