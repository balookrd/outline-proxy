use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{HeaderValue, Method, StatusCode, header};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

use crate::server::dashboard::{
    CONTROL_POOL_IDLE_TTL_SECS, CONTROL_POOL_MAX_IDLE_PER_TARGET, ControlPool, DashboardState,
    build_router, tls,
};

use super::*;

const LISTEN: &str = "127.0.0.1:7002";

fn policy(allowed_hosts: &[&str]) -> OriginPolicy {
    let allowed: Vec<String> = allowed_hosts.iter().map(|host| (*host).to_owned()).collect();
    OriginPolicy::new(LISTEN.parse().unwrap(), &allowed)
}

/// A dashboard with no listener credentials and no instances: these tests cover
/// the origin guard alone, which runs whether or not a token is set, and a
/// request that gets past it hits an empty instance list.
fn state(allowed_hosts: &[&str]) -> DashboardState {
    let allowed: Vec<String> = allowed_hosts.iter().map(|host| (*host).to_owned()).collect();
    DashboardState {
        request_timeout_secs: 5,
        refresh_interval_secs: 10,
        instances: Arc::from(Vec::new()),
        tls_connector: tls::connector(),
        token: None,
        origin_policy: OriginPolicy::new("127.0.0.1:0".parse().unwrap(), &allowed),
        control_pool: Arc::new(ControlPool::new(
            CONTROL_POOL_MAX_IDLE_PER_TARGET,
            Duration::from_secs(CONTROL_POOL_IDLE_TTL_SECS),
        )),
    }
}

async fn serve(state: DashboardState) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
    let addr = listener.local_addr().expect("listener address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, build_router(state)).await;
    });
    addr
}

/// Sends one request with the given method, path, and headers to a served
/// dashboard and returns the response status. `headers` are appended verbatim,
/// so a caller controls `Host`, `Origin`, and `Content-Type` exactly.
async fn request(
    state: DashboardState,
    method: Method,
    path: &str,
    headers: &[(header::HeaderName, &str)],
    body: Bytes,
) -> StatusCode {
    let addr = serve(state).await;
    let tcp = TcpStream::connect(addr).await.expect("connect to test dashboard");
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = hyper::Request::builder().method(method).uri(path);
    for (name, value) in headers {
        builder = builder.header(name, HeaderValue::from_str(value).expect("valid header"));
    }
    let response = sender
        .send_request(builder.body(Full::new(body)).expect("build request"))
        .await
        .expect("dashboard response");
    let status = response.status();
    // Drain so the connection closes cleanly.
    let _ = response.into_body().collect().await;
    status
}

/// A `POST` to the block route, whose real risk is a cross-origin form post: it
/// reads no JSON body of its own, so nothing would force a preflight without
/// the guard.
async fn block_request(
    state: DashboardState,
    headers: &[(header::HeaderName, &str)],
) -> StatusCode {
    request(
        state,
        Method::POST,
        "/dashboard/api/users/u/block?instance=i",
        headers,
        Bytes::new(),
    )
    .await
}

// --- Integration: the guard as wired into `build_router` --------------------

/// DNS rebinding: the attacker's domain resolves to `127.0.0.1`, so the packet
/// is local — but the browser still sends the attacker's name in `Host`, and
/// that is what gets caught, before any route or extractor runs.
#[tokio::test]
async fn rejects_rebound_host_on_post() {
    let status = block_request(
        state(&[]),
        &[(header::HOST, "rebind.attacker.example"), (header::CONTENT_TYPE, "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a rebound domain must not reach the panel");
}

/// The `Host` check covers reads too: `/dashboard/api/users` would otherwise let
/// a rebound page read every instance's users.
#[tokio::test]
async fn rejects_rebound_host_on_get() {
    let status = request(
        state(&[]),
        Method::GET,
        "/dashboard/api/users?instance=i",
        &[(header::HOST, "rebind.attacker.example")],
        Bytes::new(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The CSRF sink: a foreign page's `Origin` is refused on the block route even
/// though the request declares JSON.
#[tokio::test]
async fn rejects_cross_origin_block_post() {
    let status = block_request(
        state(&[]),
        &[
            (header::HOST, LISTEN),
            (header::ORIGIN, "http://attacker.example"),
            (header::CONTENT_TYPE, "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a cross-site Origin must be refused");
}

/// The other half of the CSRF fix: a body-bearing method with no JSON
/// content-type is a CORS "simple" request, so it needs no preflight. The block
/// route takes no JSON body, but the guard still demands the header, which the
/// packaged UI already sends and a form post cannot.
#[tokio::test]
async fn rejects_block_post_without_json_content_type() {
    let no_type = block_request(state(&[]), &[(header::HOST, LISTEN)]).await;
    assert_eq!(no_type, StatusCode::UNSUPPORTED_MEDIA_TYPE, "a bodyless declaration must 415");

    let text_plain =
        block_request(state(&[]), &[(header::HOST, LISTEN), (header::CONTENT_TYPE, "text/plain")])
            .await;
    assert_eq!(text_plain, StatusCode::UNSUPPORTED_MEDIA_TYPE, "text/plain must 415");
}

/// The panel's own page must keep working: same `Host`, matching `Origin`,
/// JSON content-type. With no instances the handler answers "unknown instance"
/// (404) — the point is that it *reached* the handler, i.e. not 403/415.
#[tokio::test]
async fn accepts_same_origin_block_post() {
    let status = block_request(
        state(&[]),
        &[
            (header::HOST, LISTEN),
            (header::ORIGIN, &format!("http://{LISTEN}")),
            (header::CONTENT_TYPE, "application/json"),
        ],
    )
    .await;
    assert_ne!(status, StatusCode::FORBIDDEN);
    assert_ne!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(status, StatusCode::NOT_FOUND, "reached the handler with an empty instance list");
}

/// An operator behind a reverse proxy declares the name once and both checks
/// follow: the proxied `Host` passes, and so does the matching `Origin` even
/// when the proxy rewrote `Host`.
#[tokio::test]
async fn accepts_operator_declared_host() {
    let status = block_request(
        state(&["panel.example.com"]),
        &[
            (header::HOST, "panel.example.com"),
            (header::ORIGIN, "https://panel.example.com"),
            (header::CONTENT_TYPE, "application/json"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "declared host must reach the handler");
}

/// GET routes stay reachable on a valid `Host`: the page and the instance list.
#[tokio::test]
async fn get_routes_stay_reachable() {
    let page =
        request(state(&[]), Method::GET, "/dashboard", &[(header::HOST, LISTEN)], Bytes::new())
            .await;
    assert_eq!(page, StatusCode::OK);

    let instances = request(
        state(&[]),
        Method::GET,
        "/dashboard/api/instances",
        &[(header::HOST, LISTEN)],
        Bytes::new(),
    )
    .await;
    assert_eq!(instances, StatusCode::OK);
}

// --- Unit: the policy helpers ------------------------------------------------

#[test]
fn host_check_ignores_the_port() {
    // `ssh -L 8888:127.0.0.1:7002` and container port mappings both reach the
    // panel on a port it never sees; the port carries no protection anyway.
    let policy = policy(&[]);
    assert!(policy.host_allowed("127.0.0.1:8888"));
    assert!(policy.host_allowed("localhost:8888"));
    assert!(policy.host_allowed("localhost"));
    assert!(policy.host_allowed("[::1]:8888"));
    assert!(!policy.host_allowed("attacker.example:7002"));
    assert!(!policy.host_allowed(""));
}

/// A trailing DNS root dot is the same name, and `Host` is case-insensitive.
#[test]
fn host_check_normalises_the_name() {
    let policy = policy(&["Panel.Example.COM"]);
    assert!(policy.host_allowed("LOCALHOST"));
    assert!(policy.host_allowed("localhost."));
    assert!(policy.host_allowed("panel.example.com"));
    assert!(policy.host_allowed("panel.example.com."));
    assert!(!policy.host_allowed("panel.example.com.attacker.example"));
}

/// Bound to a concrete address, only that address (and loopback) is "us"; bound
/// to a wildcard, any literal address is accepted — the protection against
/// rebinding is that a *name* is not.
#[test]
fn host_check_follows_the_bind_address() {
    let concrete = OriginPolicy::new("192.168.1.10:7002".parse().unwrap(), &[]);
    assert!(concrete.host_allowed("192.168.1.10"));
    assert!(concrete.host_allowed("127.0.0.1"));
    assert!(!concrete.host_allowed("192.168.1.11"));

    let wildcard = OriginPolicy::new("0.0.0.0:7002".parse().unwrap(), &[]);
    assert!(wildcard.host_allowed("192.168.1.11"));
    assert!(!wildcard.host_allowed("rebind.attacker.example"));
}

#[test]
fn origin_must_match_the_host_verbatim() {
    let policy = policy(&[]);
    assert!(policy.origin_allowed("http://127.0.0.1:8888", "127.0.0.1:8888"));
    assert!(policy.origin_allowed("http://localhost:8888", "localhost:8888"));
    // Same host, different port: a distinct origin, and a distinct local app.
    assert!(!policy.origin_allowed("http://127.0.0.1:3000", "127.0.0.1:8888"));
    assert!(!policy.origin_allowed("http://attacker.example", "127.0.0.1:7002"));
    // Opaque origin from a sandboxed frame or a `file://` page.
    assert!(!policy.origin_allowed("null", "127.0.0.1:7002"));
    // Non-HTTP schemes (a browser extension page, say) are not this panel.
    assert!(!policy.origin_allowed("chrome-extension://127.0.0.1:7002", "127.0.0.1:7002"));
}

#[test]
fn json_content_type_accepts_parameters_only() {
    assert!(is_json_content_type("application/json"));
    assert!(is_json_content_type("application/json; charset=utf-8"));
    assert!(is_json_content_type("application/json;charset=UTF-8"));
    assert!(is_json_content_type("APPLICATION/JSON"));
    assert!(!is_json_content_type("text/plain"));
    assert!(!is_json_content_type("application/json-patch+json"));
    assert!(!is_json_content_type(""));
}

/// The read-only trio is exempt; everything else must declare JSON, so a route
/// added on a method not listed here is covered by default.
#[test]
fn only_read_only_methods_skip_the_media_type_check() {
    assert!(!method_carries_body(&Method::GET));
    assert!(!method_carries_body(&Method::HEAD));
    assert!(!method_carries_body(&Method::OPTIONS));
    assert!(method_carries_body(&Method::POST));
    assert!(method_carries_body(&Method::PATCH));
    assert!(method_carries_body(&Method::DELETE));
    assert!(method_carries_body(&Method::PUT));
}
