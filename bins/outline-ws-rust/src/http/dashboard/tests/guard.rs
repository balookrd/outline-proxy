use super::*;

use crate::http::dashboard::DashboardState;
use crate::http::tests::streamed_request;

const LISTEN: &str = "127.0.0.1:9092";

fn policy(allowed_hosts: &[&str]) -> OriginPolicy {
    let allowed: Vec<String> = allowed_hosts.iter().map(|host| (*host).to_owned()).collect();
    OriginPolicy::new(LISTEN.parse().unwrap(), &allowed)
}

fn state(allowed_hosts: &[&str]) -> DashboardState {
    DashboardState {
        refresh_interval_secs: 5,
        request_timeout_secs: 5,
        // No listener credentials here: these tests cover the origin checks
        // alone, and the credential gate runs ahead of them (see `mod`).
        token: None,
        origin_policy: policy(allowed_hosts),
        instances: Vec::new(),
    }
}

/// One request against the real routing entry point, so the assertions cover
/// the guard *as wired*, not just its helpers.
async fn request(head: &str, state: DashboardState) -> (u16, String) {
    let parts = vec![head.as_bytes().to_vec()];
    streamed_request(parts, move |stream| async move {
        let _ = super::super::handle_connection(stream, state).await;
    })
    .await
}

/// A POST with an activate payload, assembled with the headers under test.
/// The state carries no instances, so a request that gets through answers 200
/// with a per-target "unknown instance" result — the point is that it *got
/// through*, not what the aggregator said.
fn activate_request(headers: &str) -> String {
    let body = r#"{"targets":[{"instance":"i","group":"g","uplink":"u"}]}"#;
    format!(
        "POST /dashboard/api/activate HTTP/1.1\r\nHost: {LISTEN}\r\n{headers}\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    )
}

/// `text/plain` is what makes the CSRF work: it is a CORS "simple" request, so
/// a foreign page can send it without a preflight. Refuse it before the body
/// is parsed.
#[tokio::test]
async fn rejects_text_plain_content_type() {
    let (status, _body) =
        request(&activate_request("Content-Type: text/plain\r\n"), state(&[])).await;
    assert_eq!(status, 415, "text/plain must not reach the JSON parser");
}

/// A body-bearing request with no `Content-Type` at all gets the same answer —
/// the check is "declares JSON", not "declares something else".
#[tokio::test]
async fn rejects_missing_content_type() {
    let (status, _body) = request(&activate_request(""), state(&[])).await;
    assert_eq!(status, 415, "a body without a declared type must not be parsed");
}

#[tokio::test]
async fn accepts_application_json() {
    let (status, _body) =
        request(&activate_request("Content-Type: application/json\r\n"), state(&[])).await;
    assert_eq!(status, 200, "the dashboard's own requests must keep working");
}

/// Browsers append the charset parameter routinely; the media type is what
/// matters.
#[tokio::test]
async fn accepts_application_json_with_charset() {
    let (status, _body) = request(
        &activate_request("Content-Type: application/json; charset=utf-8\r\n"),
        state(&[]),
    )
    .await;
    assert_eq!(status, 200, "a charset parameter must not change the media type");
}

/// The actual CSRF sink: a foreign page's `Origin` is refused even though the
/// request declares JSON.
#[tokio::test]
async fn rejects_cross_site_origin() {
    let (status, _body) = request(
        &activate_request("Content-Type: application/json\r\nOrigin: http://attacker.example\r\n"),
        state(&[]),
    )
    .await;
    assert_eq!(status, 403, "a cross-site Origin must be refused");
}

/// …and independently of the media type, so an attacker gains nothing by
/// dropping back to `text/plain`.
#[tokio::test]
async fn rejects_cross_site_origin_with_text_plain() {
    let (status, _body) = request(
        &activate_request("Content-Type: text/plain\r\nOrigin: http://attacker.example\r\n"),
        state(&[]),
    )
    .await;
    assert_eq!(status, 403, "cross-site rejection must not depend on Content-Type");
}

#[tokio::test]
async fn accepts_same_origin() {
    let (status, _body) = request(
        &activate_request(&format!(
            "Content-Type: application/json\r\nOrigin: http://{LISTEN}\r\n"
        )),
        state(&[]),
    )
    .await;
    assert_eq!(status, 200, "the panel's own page must keep working");
}

/// `curl` sends no `Origin`, and a web page cannot suppress the header, so a
/// missing one is not evidence of anything — refusing it would only break
/// scripted operators.
#[tokio::test]
async fn allows_missing_origin() {
    let (status, _body) =
        request(&activate_request("Content-Type: application/json\r\n"), state(&[])).await;
    assert_eq!(status, 200, "non-browser clients send no Origin");
}

/// DNS rebinding: the attacker's domain resolves to `127.0.0.1`, so the packet
/// really is local — but the browser still sends the attacker's name in
/// `Host`, and that is what gets caught.
#[tokio::test]
async fn rejects_foreign_host() {
    let body = r#"{"targets":[{"instance":"i","group":"g","uplink":"u"}]}"#;
    let head = format!(
        "POST /dashboard/api/activate HTTP/1.1\r\nHost: rebind.attacker.example\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    let (status, _body) = request(&head, state(&[])).await;
    assert_eq!(status, 403, "a rebound domain must not reach the panel");
}

/// The `Host` check covers reads too: `/dashboard/api/topology` answers with
/// instance topology, which a rebound page would otherwise be able to read.
#[tokio::test]
async fn rejects_foreign_host_on_get() {
    let head = "GET /dashboard/api/instances HTTP/1.1\r\nHost: rebind.attacker.example\r\n\
                Connection: close\r\n\r\n";
    let (status, _body) = request(head, state(&[])).await;
    assert_eq!(status, 403);
}

/// An operator behind a reverse proxy declares the name once and both checks
/// follow: the proxied `Host` passes, and so does the matching `Origin` even
/// when the proxy rewrote `Host` to the loopback listener.
#[tokio::test]
async fn accepts_operator_declared_host() {
    let body = r#"{"targets":[{"instance":"i","group":"g","uplink":"u"}]}"#;
    let head = format!(
        "POST /dashboard/api/activate HTTP/1.1\r\nHost: panel.example.com\r\n\
         Content-Type: application/json\r\nOrigin: https://panel.example.com\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    let (status, _body) = request(&head, state(&["panel.example.com"])).await;
    assert_eq!(status, 200);
}

/// GET routes keep working: the page itself, the instance list, and the
/// topology endpoint (404 here because the test state has no instances —
/// which already proves the request reached the handler).
#[tokio::test]
async fn get_routes_stay_reachable() {
    let cases = [
        ("GET /dashboard HTTP/1.1", 200),
        ("GET /dashboard/api/instances HTTP/1.1", 200),
        ("GET /dashboard/api/topology?instance=missing HTTP/1.1", 404),
    ];
    for (line, expected) in cases {
        let head = format!("{line}\r\nHost: {LISTEN}\r\nConnection: close\r\n\r\n");
        let (status, _body) = request(&head, state(&[])).await;
        assert_eq!(status, expected, "GET route must stay reachable: {line}");
    }
}

#[test]
fn host_check_ignores_the_port() {
    // `ssh -L 8888:127.0.0.1:9092` and container port mappings both reach the
    // panel on a port it never sees. The port carries no protection anyway:
    // a rebinding attacker has to target the real one.
    let policy = policy(&[]);
    assert!(policy.host_allowed("127.0.0.1:8888"));
    assert!(policy.host_allowed("localhost:8888"));
    assert!(policy.host_allowed("localhost"));
    assert!(policy.host_allowed("[::1]:8888"));
    assert!(!policy.host_allowed("attacker.example:9092"));
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

/// Bound to a concrete address, only that address (and loopback) is "us";
/// bound to a wildcard, the interface the operator browses through is not
/// knowable here, so any literal address is accepted — the protection against
/// rebinding is that a *name* is not.
#[test]
fn host_check_follows_the_bind_address() {
    let concrete = OriginPolicy::new("192.168.1.10:9092".parse().unwrap(), &[]);
    assert!(concrete.host_allowed("192.168.1.10"));
    assert!(concrete.host_allowed("127.0.0.1"));
    assert!(!concrete.host_allowed("192.168.1.11"));

    let wildcard = OriginPolicy::new("0.0.0.0:9092".parse().unwrap(), &[]);
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
    assert!(!policy.origin_allowed("http://attacker.example", "127.0.0.1:9092"));
    // Opaque origin from a sandboxed frame or a `file://` page.
    assert!(!policy.origin_allowed("null", "127.0.0.1:9092"));
    // Non-HTTP schemes (a browser extension page, say) are not this panel.
    assert!(!policy.origin_allowed("chrome-extension://127.0.0.1:9092", "127.0.0.1:9092"));
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
