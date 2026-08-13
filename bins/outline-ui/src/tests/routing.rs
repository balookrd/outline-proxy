use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt as _;

use super::*;

fn config() -> crate::config::UiConfig {
    crate::config::UiConfig {
        listen: "127.0.0.1:9000".parse().unwrap(),
        token: "s3cr3t".to_string(),
        request_timeout_secs: 5,
        refresh_interval_secs: 5,
        allowed_hosts: Vec::new(),
        ws: Vec::new(),
        ss: Vec::new(),
    }
}

fn authed(uri: &str) -> Request<Body> {
    Request::get(uri)
        .header(header::HOST, "127.0.0.1:9000")
        .header(header::AUTHORIZATION, "Bearer s3cr3t")
        .body(Body::empty())
        .unwrap()
}

/// The whole point of the extraction: the two dashboards share a port without
/// colliding, each answering its own API under its own prefix through the full
/// app (nesting + both middleware layers), not just the bare per-tree router.
#[tokio::test]
async fn both_trees_are_reachable_and_distinct() {
    let app = build_app(&config());

    let ws = app
        .clone()
        .oneshot(authed("/ws/dashboard/api/instances"))
        .await
        .unwrap();
    assert_eq!(ws.status(), StatusCode::OK);

    let ss = app.oneshot(authed("/ss/dashboard/api/instances")).await.unwrap();
    assert_eq!(ss.status(), StatusCode::OK);
}

/// `/` now serves the Svelte SPA shell rather than the old dashboard-listing
/// index (see `spa_index_without_feature_serves_stub_ok` and
/// `serves_spa_index_and_assets_with_feature` below); both dashboards remain
/// reachable directly, which `both_trees_are_reachable_and_distinct` already
/// covers.
///
/// Without `embed-assets` that shell degrades to a stub instead of panicking
/// — the default, node-less build (and its Rust CI gate) must stay green even
/// though nothing was ever `pnpm build`t.
#[tokio::test]
async fn spa_index_without_feature_serves_stub_ok() {
    let response = build_app(&config()).oneshot(authed("/")).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// The gate must cover both trees, not just the root.
#[tokio::test]
async fn every_tree_is_behind_the_credential_gate() {
    let app = build_app(&config());

    for uri in ["/", "/ws/dashboard", "/ss/dashboard", "/ws/dashboard/api/instances"] {
        let response = app
            .clone()
            .oneshot(
                Request::get(uri)
                    .header(header::HOST, "127.0.0.1:9000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "unguarded route: {uri}");
    }
}

/// Regression test for the origin-gate/DELETE seam: `origin.rs`'s
/// `method_carries_body` treats every non-GET/HEAD/OPTIONS method as
/// body-bearing, so a `DELETE` needs `Content-Type: application/json` to clear
/// the gate — same as any other mutation. The frontend's `deleteUser` used to
/// hand-roll `{ method: 'DELETE' }` with no headers at all, so it never made
/// it past this middleware to `delete_user`; every caller saw a bare "HTTP
/// 415" toast instead of whatever `/control/users/{id}` actually answered.
///
/// With the header present, this DELETE clears the gate and reaches routing:
/// the response is 404 "unknown instance" (not 415) because the test config
/// carries no `ss` instances, which is exactly the point — the instance
/// lookup failing is incidental, reaching `ss::api::forward` at all is what's
/// under test.
#[tokio::test]
async fn delete_with_json_content_type_clears_the_origin_gate() {
    let app = build_app(&config());

    let request = Request::delete("/ss/dashboard/api/users/someid?instance=nope")
        .header(header::HOST, "127.0.0.1:9000")
        .header(header::AUTHORIZATION, "Bearer s3cr3t")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// The mirror of the test above: the identical DELETE, minus the JSON
/// content type, is still rejected 415 at the origin gate — before routing
/// ever sees it. This documents the gate contract that the fix above (routing
/// every frontend mutation through one header-setting helper) satisfies: it
/// is the gate's job to demand the header, not routing's job to tolerate its
/// absence.
#[tokio::test]
async fn delete_without_content_type_is_rejected_by_the_origin_gate() {
    let app = build_app(&config());

    let request = Request::delete("/ss/dashboard/api/users/someid?instance=nope")
        .header(header::HOST, "127.0.0.1:9000")
        .header(header::AUTHORIZATION, "Bearer s3cr3t")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

/// Picks a real, currently-hashed asset name straight out of `frontend/dist`
/// — the same tree rust-embed indexed at compile time — instead of hardcoding
/// a content hash that changes on every frontend rebuild.
#[cfg(feature = "embed-assets")]
fn a_real_asset_name() -> String {
    let dist = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("frontend/dist");
    std::fs::read_dir(&dist)
        .unwrap_or_else(|e| panic!("read {}: {e}", dist.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .find(|name| name.ends_with(".js") || name.ends_with(".css"))
        .expect("frontend/dist must contain a hashed JS or CSS bundle")
}

/// With `embed-assets`, `/` and `/ui-assets/*` serve the real `frontend/dist`
/// compiled into the binary; a path outside that embedded tree still 404s.
#[cfg(feature = "embed-assets")]
#[tokio::test]
async fn serves_spa_index_and_assets_with_feature() {
    let app = build_app(&config());

    let index = app.clone().oneshot(authed("/")).await.unwrap();
    assert_eq!(index.status(), StatusCode::OK);
    let body = axum::body::to_bytes(index.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("<!doctype"), "expected the real dist index.html: {body}");

    let asset_name = a_real_asset_name();
    let asset = app
        .clone()
        .oneshot(authed(&format!("/ui-assets/{asset_name}")))
        .await
        .unwrap();
    assert_eq!(asset.status(), StatusCode::OK, "missing embedded asset: {asset_name}");

    let missing = app.oneshot(authed("/ui-assets/definitely-missing.js")).await.unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}
