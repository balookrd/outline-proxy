use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Request, StatusCode, Uri, header};
use bytes::Bytes;
use tokio::net::TcpListener;
use tower::ServiceExt as _;

use super::*;

fn state() -> WsState {
    WsState {
        backend: std::sync::Arc::new(crate::backend::Backend::new(5)),
        instances: std::sync::Arc::from(Vec::new()),
        refresh_ms: 5000,
    }
}

#[tokio::test]
async fn lists_configured_instances() {
    let response = router(state())
        .oneshot(Request::get("/dashboard/api/instances").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// A request naming an instance that is not configured must say so, not fall
/// through to a generic 404 the JS renders as an empty page.
#[tokio::test]
async fn topology_for_an_unknown_instance_is_reported() {
    let response = router(state())
        .oneshot(
            Request::get("/dashboard/api/topology?instance=nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8(body.to_vec()).unwrap().contains("unknown instance"));
}

/// One request captured by `spawn_recorder` below.
#[derive(Debug)]
struct Recorded {
    method: String,
    path: String,
    query: String,
    auth: String,
    body: String,
}

type Recorder = Arc<Mutex<Vec<Recorded>>>;

async fn record(
    State(records): State<Recorder>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    records.lock().unwrap().push(Recorded {
        method: method.to_string(),
        path: uri.path().to_string(),
        query: uri.query().unwrap_or("").to_string(),
        auth,
        body: String::from_utf8_lossy(&body).into_owned(),
    });
    StatusCode::OK
}

/// Spins a throwaway control API answering `/control/routes`,
/// `/control/routes/reorder`, `/control/uplink_groups`, and
/// `/control/uplink_groups/reorder`, recording method/path/`Authorization`/body
/// for every request it receives rather than asserting inline in the handler —
/// so a test can drive the real `router()` and inspect what actually reached
/// the node afterwards. One handler backs all four endpoints; the recorded
/// `path` is what tells them apart. Mirrors `crate::tests::backend::spawn_echo`'s
/// "assert on the wire shape, not a mock's expectations" approach.
async fn spawn_recorder() -> (SocketAddr, Recorder) {
    let records: Recorder = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/control/routes", get(record).post(record).patch(record).delete(record))
        .route("/control/routes/reorder", post(record))
        .route("/control/uplink_groups", get(record).post(record).patch(record).delete(record))
        .route("/control/uplink_groups/reorder", post(record))
        .with_state(Arc::clone(&records));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, records)
}

fn instance(addr: SocketAddr) -> InstanceConfig {
    InstanceConfig {
        name: "probe".to_string(),
        control_url: format!("http://{addr}"),
        token: "inst-tok".to_string(),
    }
}

fn state_with(instance: InstanceConfig) -> WsState {
    WsState {
        backend: std::sync::Arc::new(crate::backend::Backend::new(5)),
        instances: std::sync::Arc::from(vec![instance]),
        refresh_ms: 5000,
    }
}

/// Mirrors the uplinks CRUD proxy: GET on `/dashboard/api/routes?instance=X`
/// must reach `/control/routes` on that instance's control API with its
/// bearer token injected server-side, and any OTHER query params (filters)
/// must be forwarded too — only `instance` itself is stripped.
#[tokio::test]
async fn routes_proxy_forwards_get_with_token() {
    let (addr, records) = spawn_recorder().await;

    let response = router(state_with(instance(addr)))
        .oneshot(
            Request::get("/dashboard/api/routes?instance=probe&group=main")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let recorded = records.lock().unwrap();
    assert_eq!(recorded.len(), 1, "expected exactly one upstream request");
    assert_eq!(recorded[0].method, "GET");
    assert_eq!(recorded[0].path, "/control/routes");
    assert_eq!(recorded[0].query, "group=main", "filters besides `instance` must be forwarded");
    assert_eq!(
        recorded[0].auth, "Bearer inst-tok",
        "control token must be injected server-side"
    );
}

/// The reorder proxy must forward the envelope's inner `body` (`{from, to,
/// revision}`) to `/control/routes/reorder`, unlike `apply_proxy` whose
/// control body is ignored by the node either way — `/control/routes/reorder`
/// actually reads its request body (`ReorderBody` on the `outline-ws-rust`
/// side) and would reject an empty one.
#[tokio::test]
async fn routes_reorder_proxy_forwards_envelope_body_with_token() {
    let (addr, records) = spawn_recorder().await;
    let envelope = serde_json::json!({
        "instance": "probe",
        "body": { "from": 0, "to": 2, "revision": "deadbeef" },
    });

    let response = router(state_with(instance(addr)))
        .oneshot(
            Request::post("/dashboard/api/routes/reorder")
                .body(Body::from(envelope.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let recorded = records.lock().unwrap();
    assert_eq!(recorded.len(), 1, "expected exactly one upstream request");
    assert_eq!(recorded[0].method, "POST");
    assert_eq!(recorded[0].path, "/control/routes/reorder");
    assert_eq!(
        recorded[0].auth, "Bearer inst-tok",
        "control token must be injected server-side"
    );
    let forwarded: serde_json::Value =
        serde_json::from_str(&recorded[0].body).expect("forwarded body is JSON");
    assert_eq!(
        forwarded,
        serde_json::json!({ "from": 0, "to": 2, "revision": "deadbeef" }),
        "must forward the envelope's inner body, not drop it"
    );
}

/// Mirrors the routes CRUD proxy: GET on `/dashboard/api/groups?instance=X`
/// must reach `/control/uplink_groups` on that instance's control API with its
/// bearer token injected server-side, and any OTHER query params (filters)
/// must be forwarded too — only `instance` itself is stripped.
#[tokio::test]
async fn groups_get_forwards_instance_and_injects_token() {
    let (addr, records) = spawn_recorder().await;

    let response = router(state_with(instance(addr)))
        .oneshot(
            Request::get("/dashboard/api/groups?instance=probe&group=main")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let recorded = records.lock().unwrap();
    assert_eq!(recorded.len(), 1, "expected exactly one upstream request");
    assert_eq!(recorded[0].method, "GET");
    assert_eq!(recorded[0].path, "/control/uplink_groups");
    assert_eq!(recorded[0].query, "group=main", "filters besides `instance` must be forwarded");
    assert_eq!(
        recorded[0].auth, "Bearer inst-tok",
        "control token must be injected server-side"
    );
}
