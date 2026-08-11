use std::io;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::header::{CACHE_CONTROL, WWW_AUTHENTICATE};
use http::{Request, StatusCode};
use parking_lot::Mutex;
use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

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

fn basic_header(user: &str, password: &str) -> HeaderValue {
    let encoded = STANDARD.encode(format!("{user}:{password}"));
    HeaderValue::from_str(&format!("Basic {encoded}")).expect("valid header")
}

/// Builds a request the gate can inspect; the body type is irrelevant to it.
fn request_with(credentials: Option<HeaderValue>) -> Request<()> {
    let mut builder = Request::builder().method("POST").uri("/dashboard/api/activate");
    if let Some(credentials) = credentials {
        builder = builder.header(AUTHORIZATION, credentials);
    }
    builder.body(()).expect("valid request")
}

// ── warn_if_unauthenticated_exposure ──────────────────────────────────────

#[test]
fn warns_when_unauthenticated_dashboard_binds_to_unspecified_address() {
    let logs = captured_logs(|| {
        warn_if_unauthenticated_exposure("0.0.0.0:9092".parse().unwrap(), false);
    });

    assert!(logs.contains("WARN"), "expected a WARN record, got: {logs}");
    assert!(logs.contains("unauthenticated"), "warning should name the risk, got: {logs}");
    assert!(logs.contains("loopback"), "warning should name the remedy, got: {logs}");
}

#[test]
fn warns_when_unauthenticated_dashboard_binds_to_routable_address() {
    let logs = captured_logs(|| {
        warn_if_unauthenticated_exposure("10.0.0.5:9092".parse().unwrap(), false);
    });

    assert!(logs.contains("WARN"), "expected a WARN record, got: {logs}");
}

#[test]
fn stays_quiet_when_dashboard_binds_to_loopback() {
    let ipv4 = captured_logs(|| {
        warn_if_unauthenticated_exposure("127.0.0.1:9092".parse().unwrap(), false);
    });
    let ipv6 = captured_logs(|| {
        warn_if_unauthenticated_exposure("[::1]:9092".parse().unwrap(), false);
    });

    assert!(ipv4.is_empty(), "loopback bind should stay quiet, got: {ipv4}");
    assert!(ipv6.is_empty(), "loopback bind should stay quiet, got: {ipv6}");
}

#[test]
fn stays_quiet_when_exposed_dashboard_requires_credentials() {
    let logs = captured_logs(|| {
        warn_if_unauthenticated_exposure("0.0.0.0:9092".parse().unwrap(), true);
    });

    assert!(logs.is_empty(), "authenticated dashboard should stay quiet, got: {logs}");
}

// ── credentials_match ─────────────────────────────────────────────────────

#[test]
fn credentials_match_accepts_bearer_token() {
    assert!(credentials_match(&HeaderValue::from_static("Bearer secret"), "secret"));
}

#[test]
fn credentials_match_accepts_basic_password_for_any_username() {
    assert!(credentials_match(&basic_header("admin", "secret"), "secret"));
    assert!(credentials_match(&basic_header("someone-else", "secret"), "secret"));
}

#[test]
fn credentials_match_rejects_wrong_or_malformed_credentials() {
    assert!(!credentials_match(&HeaderValue::from_static("Bearer nope"), "secret"));
    assert!(!credentials_match(&HeaderValue::from_static("Bearer "), "secret"));
    assert!(!credentials_match(&basic_header("admin", "nope"), "secret"));
    assert!(!credentials_match(&basic_header("admin", ""), "secret"));
    assert!(!credentials_match(&HeaderValue::from_static("Basic ***"), "secret"));
    assert!(!credentials_match(&HeaderValue::from_static("Basic"), "secret"));
    assert!(!credentials_match(&HeaderValue::from_static("secret"), "secret"));
}

// ── reject_unauthorized ───────────────────────────────────────────────────

#[test]
fn no_configured_token_leaves_every_request_untouched() {
    assert!(reject_unauthorized(&request_with(None), None).is_none());
    assert!(
        reject_unauthorized(&request_with(Some(HeaderValue::from_static("Bearer x"))), None)
            .is_none(),
        "an unconfigured listener must not start rejecting credentials it never asked for"
    );
}

#[test]
fn configured_token_admits_both_credential_forms() {
    let bearer = request_with(Some(HeaderValue::from_static("Bearer secret")));
    let basic = request_with(Some(basic_header("admin", "secret")));

    assert!(reject_unauthorized(&bearer, Some("secret")).is_none());
    assert!(reject_unauthorized(&basic, Some("secret")).is_none());
}

#[test]
fn configured_token_refuses_missing_empty_and_wrong_credentials() {
    for credentials in [
        None,
        Some(HeaderValue::from_static("")),
        Some(HeaderValue::from_static("Bearer ")),
        Some(HeaderValue::from_static("Bearer nope")),
        Some(basic_header("admin", "nope")),
    ] {
        let refusal = reject_unauthorized(&request_with(credentials.clone()), Some("secret"));
        assert!(
            refusal.is_some(),
            "credentials {credentials:?} must not reach a mutating dashboard route"
        );
    }
}

/// Browsers need a challenge to prompt with, and the refusal must not be
/// cached by anything between the operator and the listener.
#[test]
fn refusal_challenges_the_browser_and_is_never_cached() {
    let refusal = reject_unauthorized(&request_with(None), Some("secret")).expect("refusal");

    assert_eq!(refusal.status(), StatusCode::UNAUTHORIZED);
    assert!(
        refusal
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("Basic ")),
        "browsers need a Basic challenge, got: {:?}",
        refusal.headers().get(WWW_AUTHENTICATE)
    );
    assert_eq!(
        refusal
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}
