use std::net::SocketAddr;

use axum::Router;
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::get;
use tokio::net::TcpListener;

use super::*;
use crate::config::InstanceConfig;

/// Spins a throwaway control API that echoes back what it received, so the test
/// asserts on the wire shape rather than on a mock's expectations.
async fn spawn_echo() -> SocketAddr {
    let app = Router::new().route(
        "/control/topology",
        get(|headers: HeaderMap| async move {
            let auth = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            (StatusCode::OK, format!("{{\"auth\":\"{auth}\"}}"))
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn instance(addr: SocketAddr) -> InstanceConfig {
    InstanceConfig {
        name: "probe".to_string(),
        control_url: format!("http://{addr}"),
        token: "inst-tok".to_string(),
    }
}

#[tokio::test]
async fn injects_the_instance_bearer_token() {
    let addr = spawn_echo().await;
    let backend = Backend::new(5);

    let response = backend
        .request(&instance(addr), Method::GET, "/control/topology", None)
        .await
        .expect("request succeeds");

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body.to_vec()).unwrap();
    assert!(
        body.contains("Bearer inst-tok"),
        "the instance token must be injected server-side, got: {body}"
    );
}

/// An unreachable instance must surface as an error naming that instance, not as
/// a panic or a hang that takes the whole page down. It must NOT name the
/// control host:port, though: that string reaches the browser verbatim as the
/// JSON `error` field (ss/api.rs, ws/api.rs just `format!("{error:#}")` this),
/// and `control_url` is otherwise deliberately never advertised to the
/// browser (see ss/api.rs's `list_instances` doc comment) — a connect-failure
/// message used to be the one place it leaked out anyway.
#[tokio::test]
async fn unreachable_instance_errors_and_names_itself() {
    let backend = Backend::new(1);
    let dead = InstanceConfig {
        name: "dead".to_string(),
        // Port 1 on loopback refuses immediately.
        control_url: "http://127.0.0.1:1".to_string(),
        token: "x".to_string(),
    };

    let error = backend
        .request(&dead, Method::GET, "/control/topology", None)
        .await
        .expect_err("must not succeed");

    let rendered = format!("{error:#}");
    assert!(rendered.contains("dead"), "error should identify the instance, got: {rendered}");
    assert!(
        !rendered.contains("127.0.0.1:1"),
        "error must not leak the control host:port to the browser, got: {rendered}"
    );
}

/// An instance behind a reverse proxy keeps its base path: cloud nodes are
/// reached as `https://host/rust-ws-exporter`, and dropping that prefix would
/// send every request to the wrong place.
#[test]
fn base_path_of_the_control_url_is_preserved() {
    let url = instance_url("https://cloud1.beerloga.su/rust-ws-exporter", "/control/topology")
        .expect("url builds");

    assert_eq!(url.as_str(), "https://cloud1.beerloga.su/rust-ws-exporter/control/topology");
}

/// The uplinks proxy forwards the browser's filters as a query string; dropping
/// them would leave the UI showing unfiltered results with no sign of it.
#[test]
fn query_string_in_the_path_is_forwarded() {
    let url =
        instance_url("http://127.0.0.1:9191", "/control/uplinks?group=main").expect("url builds");

    assert_eq!(url.as_str(), "http://127.0.0.1:9191/control/uplinks?group=main");
}
