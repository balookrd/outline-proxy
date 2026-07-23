use std::{io, net::SocketAddr, sync::Arc};

use axum::http::{HeaderValue, StatusCode, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

use crate::server::dashboard::{
    CONTROL_POOL_IDLE_TTL_SECS, CONTROL_POOL_MAX_IDLE_PER_TARGET, ControlPool, DashboardState,
    build_router, tls,
};

use super::*;

#[derive(Clone, Default)]
struct CaptureBuffer(Arc<Mutex<Vec<u8>>>);

impl io::Write for CaptureBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CaptureBuffer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Runs `body` under a thread-local subscriber and returns everything it logged.
fn captured_logs(body: impl FnOnce()) -> String {
    let buffer = CaptureBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer.clone())
        .with_ansi(false)
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::with_default(subscriber, body);
    let bytes = buffer.0.lock().clone();
    String::from_utf8(bytes).expect("captured logs are utf-8")
}

#[test]
fn warns_when_unauthenticated_dashboard_binds_to_unspecified_address() {
    let logs = captured_logs(|| {
        warn_if_unauthenticated_exposure("0.0.0.0:7002".parse().unwrap(), false);
    });

    assert!(logs.contains("WARN"), "expected a WARN record, got: {logs}");
    assert!(logs.contains("unauthenticated"), "warning should name the risk, got: {logs}");
    assert!(logs.contains("loopback"), "warning should name the remedy, got: {logs}");
}

#[test]
fn warns_when_unauthenticated_dashboard_binds_to_routable_address() {
    let logs = captured_logs(|| {
        warn_if_unauthenticated_exposure("10.0.0.5:7002".parse().unwrap(), false);
    });

    assert!(logs.contains("WARN"), "expected a WARN record, got: {logs}");
}

#[test]
fn stays_quiet_when_dashboard_binds_to_loopback() {
    let ipv4 = captured_logs(|| {
        warn_if_unauthenticated_exposure("127.0.0.1:7002".parse().unwrap(), false);
    });
    let ipv6 = captured_logs(|| {
        warn_if_unauthenticated_exposure("[::1]:7002".parse().unwrap(), false);
    });

    assert!(ipv4.is_empty(), "loopback bind should stay quiet, got: {ipv4}");
    assert!(ipv6.is_empty(), "loopback bind should stay quiet, got: {ipv6}");
}

#[test]
fn stays_quiet_when_exposed_dashboard_requires_credentials() {
    let logs = captured_logs(|| {
        warn_if_unauthenticated_exposure("0.0.0.0:7002".parse().unwrap(), true);
    });

    assert!(logs.is_empty(), "authenticated dashboard should stay quiet, got: {logs}");
}

#[test]
fn credentials_match_accepts_bearer_token() {
    let header = HeaderValue::from_static("Bearer secret");

    assert!(credentials_match(&header, "secret"));
}

#[test]
fn credentials_match_accepts_basic_password_for_any_username() {
    let header = basic_header("admin", "secret");
    let other_user = basic_header("someone-else", "secret");

    assert!(credentials_match(&header, "secret"));
    assert!(credentials_match(&other_user, "secret"));
}

#[test]
fn credentials_match_rejects_wrong_or_malformed_credentials() {
    assert!(!credentials_match(&HeaderValue::from_static("Bearer nope"), "secret"));
    assert!(!credentials_match(&basic_header("admin", "nope"), "secret"));
    assert!(!credentials_match(&HeaderValue::from_static("Basic ***"), "secret"));
    assert!(!credentials_match(&HeaderValue::from_static("Basic"), "secret"));
    assert!(!credentials_match(&HeaderValue::from_static("secret"), "secret"));
}

fn basic_header(user: &str, password: &str) -> HeaderValue {
    let encoded = STANDARD.encode(format!("{user}:{password}"));
    HeaderValue::from_str(&format!("Basic {encoded}")).expect("valid header")
}

fn state_with_token(token: Option<&str>) -> DashboardState {
    DashboardState {
        request_timeout_secs: 5,
        refresh_interval_secs: 10,
        instances: Arc::from(Vec::new()),
        tls_connector: tls::connector(),
        token: token.map(Arc::from),
        control_pool: Arc::new(ControlPool::new(
            CONTROL_POOL_MAX_IDLE_PER_TARGET,
            std::time::Duration::from_secs(CONTROL_POOL_IDLE_TTL_SECS),
        )),
    }
}

async fn serve_dashboard(state: DashboardState) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
    let addr = listener.local_addr().expect("listener address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, build_router(state)).await;
    });
    addr
}

/// Returns the response status and the `WWW-Authenticate` header, if any.
async fn get_dashboard_page(
    addr: SocketAddr,
    credentials: Option<HeaderValue>,
) -> (StatusCode, Option<String>) {
    let tcp = TcpStream::connect(addr).await.expect("connect to test dashboard");
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut request = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri("/dashboard")
        .header(header::HOST, addr.to_string());
    if let Some(credentials) = credentials {
        request = request.header(header::AUTHORIZATION, credentials);
    }
    let response = sender
        .send_request(request.body(Full::new(Bytes::new())).expect("build request"))
        .await
        .expect("dashboard response");

    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    (response.status(), challenge)
}

#[tokio::test]
async fn router_stays_open_when_no_token_is_configured() {
    let addr = serve_dashboard(state_with_token(None)).await;

    let (status, _) = get_dashboard_page(addr, None).await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn router_challenges_unauthenticated_requests_when_token_is_configured() {
    let addr = serve_dashboard(state_with_token(Some("secret"))).await;

    let (status, challenge) = get_dashboard_page(addr, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        challenge.as_deref().is_some_and(|value| value.starts_with("Basic ")),
        "browsers need a Basic challenge, got: {challenge:?}"
    );
}

#[tokio::test]
async fn router_rejects_wrong_credentials_when_token_is_configured() {
    let addr = serve_dashboard(state_with_token(Some("secret"))).await;

    let (status, _) = get_dashboard_page(addr, Some(basic_header("admin", "nope"))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn router_serves_page_for_matching_credentials() {
    let addr = serve_dashboard(state_with_token(Some("secret"))).await;

    let (basic, _) = get_dashboard_page(addr, Some(basic_header("admin", "secret"))).await;
    let (bearer, _) =
        get_dashboard_page(addr, Some(HeaderValue::from_static("Bearer secret"))).await;

    assert_eq!(basic, StatusCode::OK);
    assert_eq!(bearer, StatusCode::OK);
}
