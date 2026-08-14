//! `/ws/dashboard/api/*` handlers.
//!
//! Every handler resolves the named instance in the configured list and talks to
//! its control API through [`crate::backend`], which injects that instance's
//! bearer token server-side. The browser never sees a control token.

use anyhow::{Context, Result, bail};
use axum::extract::{RawQuery, State};
use axum::response::Response;
use bytes::Bytes;
use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::assets::{json_error, json_response};
use crate::config::InstanceConfig;

use super::WsState;

#[derive(Debug, Serialize)]
struct InstancesResponse {
    refresh_interval_secs: u64,
    instances: Vec<InstanceMeta>,
}

#[derive(Debug, Serialize)]
struct InstanceMeta {
    name: String,
}

#[derive(Debug, Serialize)]
struct InstanceView {
    name: String,
    ok: bool,
    topology: Option<Value>,
    error: Option<String>,
}

pub async fn list_instances(State(state): State<WsState>) -> Response {
    let instances = state
        .instances
        .iter()
        .map(|i| InstanceMeta { name: i.name.clone() })
        .collect::<Vec<_>>();
    let payload = InstancesResponse {
        refresh_interval_secs: state.refresh_ms / 1000,
        instances,
    };
    json_response(StatusCode::OK, &serde_json::to_value(payload).unwrap_or_default())
}

/// Looks up `?instance=` in a raw query string. Kept manual rather than using a
/// typed extractor because the uplinks proxy has to forward every *other*
/// parameter untouched, and a typed struct would silently drop them.
fn instance_param(query: Option<&str>) -> Option<String> {
    let raw = query.unwrap_or("");
    url::form_urlencoded::parse(raw.as_bytes())
        .find(|(k, _)| k == "instance")
        .map(|(_, v)| v.into_owned())
}

fn find<'a>(state: &'a WsState, name: &str) -> Option<&'a InstanceConfig> {
    state.instances.iter().find(|i| i.name == name)
}

pub async fn topology(State(state): State<WsState>, RawQuery(query): RawQuery) -> Response {
    let Some(name) = instance_param(query.as_deref()) else {
        return json_error(StatusCode::BAD_REQUEST, "missing instance query");
    };
    let Some(instance) = find(&state, &name) else {
        return json_error(StatusCode::NOT_FOUND, "unknown instance");
    };

    // A failing instance becomes a field in the answer, not an error response:
    // one unreachable node must not blank the whole page.
    let view = match fetch_topology(&state, instance).await {
        Ok(topology) => InstanceView {
            name: instance.name.clone(),
            ok: true,
            topology: Some(topology),
            error: None,
        },
        Err(error) => InstanceView {
            name: instance.name.clone(),
            ok: false,
            topology: None,
            error: Some(format!("{error:#}")),
        },
    };
    json_response(StatusCode::OK, &serde_json::to_value(view).unwrap_or_default())
}

async fn fetch_topology(state: &WsState, instance: &InstanceConfig) -> Result<Value> {
    let response = state
        .backend
        .request(instance, Method::GET, "/control/topology", None)
        .await?;
    if !response.status.is_success() {
        bail!("{} returned HTTP {}", instance.name, response.status);
    }
    serde_json::from_slice(&response.body).context("invalid topology JSON")
}

#[derive(Debug, Deserialize)]
struct ActivateRequest {
    targets: Vec<ActivateTarget>,
    #[serde(default)]
    transport: Option<String>,
    /// Operator soft switch: proxied to `/control/activate` as `soft: true` so
    /// the instance migrates live sessions via cluster resume instead of
    /// resetting them. Only honoured on cluster groups; the instance clamps it
    /// otherwise and echoes the effective value in each result's body.
    #[serde(default)]
    soft: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct ActivateTarget {
    instance: String,
    group: String,
    uplink: String,
}

#[derive(Debug, Serialize)]
struct ActivateResult {
    target: ActivateTarget,
    ok: bool,
    status: Option<u16>,
    body: Option<Value>,
    error: Option<String>,
}

pub async fn activate(State(state): State<WsState>, body: Bytes) -> Response {
    let payload: ActivateRequest = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(error) => {
            return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {error}"));
        },
    };
    if payload.targets.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "targets must not be empty");
    }
    if let Some(transport) = payload.transport.as_deref()
        && !matches!(transport, "tcp" | "udp" | "both")
    {
        return json_error(StatusCode::BAD_REQUEST, "transport must be tcp, udp, or both");
    }

    let mut results = Vec::with_capacity(payload.targets.len());
    for target in payload.targets {
        let result = match find(&state, &target.instance) {
            Some(instance) => {
                match activate_one(
                    &state,
                    instance,
                    &target,
                    payload.transport.as_deref(),
                    payload.soft,
                )
                .await
                {
                    Ok((status, body)) => ActivateResult {
                        target,
                        ok: status.is_success(),
                        status: Some(status.as_u16()),
                        body: Some(body),
                        error: None,
                    },
                    Err(error) => ActivateResult {
                        target,
                        ok: false,
                        status: None,
                        body: None,
                        error: Some(format!("{error:#}")),
                    },
                }
            },
            None => ActivateResult {
                target,
                ok: false,
                status: None,
                body: None,
                error: Some("unknown instance".to_string()),
            },
        };
        results.push(result);
    }

    json_response(StatusCode::OK, &serde_json::json!({ "results": results }))
}

async fn activate_one(
    state: &WsState,
    instance: &InstanceConfig,
    target: &ActivateTarget,
    transport: Option<&str>,
    soft: bool,
) -> Result<(StatusCode, Value)> {
    let mut payload = serde_json::json!({ "group": target.group, "uplink": target.uplink });
    if let Some(transport) = transport {
        payload["transport"] = Value::String(transport.to_string());
    }
    // Only send `soft` when set, so a plain activate stays byte-identical to the
    // pre-soft request shape (the instance defaults it to a hard switch).
    if soft {
        payload["soft"] = Value::Bool(true);
    }
    let body = Bytes::from(serde_json::to_vec(&payload)?);
    let response = state
        .backend
        .request(instance, Method::POST, "/control/activate", Some(body))
        .await?;
    Ok((response.status, parse_or_raw(&response.body)))
}

#[derive(Debug, Deserialize)]
struct SetEnabledRequest {
    instance: String,
    group: String,
    uplink: String,
    enabled: bool,
}

/// Proxies the operator on/off toggle to `/control/uplink_enabled`, keeping the
/// control token server-side; the browser only sends the four fields.
pub async fn set_enabled(State(state): State<WsState>, body: Bytes) -> Response {
    let payload: SetEnabledRequest = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(error) => {
            return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {error}"));
        },
    };
    let Some(instance) = find(&state, &payload.instance) else {
        return json_error(StatusCode::BAD_REQUEST, "unknown instance");
    };
    let request_body = serde_json::json!({
        "group": payload.group,
        "uplink": payload.uplink,
        "enabled": payload.enabled,
    });
    proxy_json(&state, instance, "/control/uplink_enabled", request_body).await
}

#[derive(Debug, Deserialize)]
struct ReselectRequest {
    instance: String,
    group: String,
    /// Defaults to `true`: reselect is intended to preserve live sessions via
    /// cluster resume where possible. Mirrors `/control/reselect`'s own default —
    /// the instance still clamps this to a hard switch off-cluster.
    #[serde(default = "default_reselect_soft")]
    soft: bool,
}

fn default_reselect_soft() -> bool {
    true
}

/// Proxies "reselect now" (forced weighted re-selection of the group's strict
/// active uplink). Unlike soft switch this is NOT gated on cluster resume:
/// re-selection is meaningful off-cluster too, it just switches hard there.
pub async fn reselect(State(state): State<WsState>, body: Bytes) -> Response {
    let payload: ReselectRequest = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(error) => {
            return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {error}"));
        },
    };
    let Some(instance) = find(&state, &payload.instance) else {
        return json_error(StatusCode::BAD_REQUEST, "unknown instance");
    };
    let request_body = serde_json::json!({ "group": payload.group, "soft": payload.soft });
    proxy_json(&state, instance, "/control/reselect", request_body).await
}

/// Shared tail of `set_enabled` and `reselect`: both answer
/// `{ok, body}` on success and `{ok: false, error}` when the instance is
/// unreachable, which is what their JS already expects.
async fn proxy_json(
    state: &WsState,
    instance: &InstanceConfig,
    path: &str,
    body: Value,
) -> Response {
    let bytes = match serde_json::to_vec(&body) {
        Ok(bytes) => Bytes::from(bytes),
        Err(error) => {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{error}"));
        },
    };
    match state.backend.request(instance, Method::POST, path, Some(bytes)).await {
        Ok(response) => json_response(
            response.status,
            &serde_json::json!({
                "ok": response.status.is_success(),
                "body": parse_or_raw(&response.body),
            }),
        ),
        Err(error) => json_response(
            StatusCode::BAD_GATEWAY,
            &serde_json::json!({ "ok": false, "error": format!("{error:#}") }),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct ProxyEnvelope {
    instance: String,
    #[serde(default)]
    body: Value,
}

/// `GET|POST|PATCH|DELETE /dashboard/api/uplinks` — CRUD passthrough to
/// `/control/uplinks`. GET carries the instance and filters in the query string;
/// the mutating methods carry an `{instance, body}` envelope.
pub async fn uplinks_proxy(
    State(state): State<WsState>,
    method: Method,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    proxy_crud(&state, method, query, body, "/control/uplinks").await
}

/// `GET|POST|PATCH|DELETE /dashboard/api/routes` — CRUD passthrough to
/// `/control/routes`. GET carries `instance` in the query; mutating methods
/// carry an `{instance, body}` envelope, same as uplinks.
pub async fn routes_proxy(
    State(state): State<WsState>,
    method: Method,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    proxy_crud(&state, method, query, body, "/control/routes").await
}

/// `POST /dashboard/api/apply` — asks the instance to hot-apply pending uplink
/// (and routing) changes. Carries an `{instance}` envelope; its callers omit
/// `body`, which `/control/apply` ignores regardless of content.
pub async fn apply_proxy(State(state): State<WsState>, body: Bytes) -> Response {
    proxy_envelope_post(&state, body, "/control/apply").await
}

/// `POST /dashboard/api/routes/reorder` — `{instance, body}` envelope to
/// `/control/routes/reorder`; `body` carries `{from, to, revision}` and is
/// forwarded verbatim, unlike `/control/apply` which never reads its body.
pub async fn routes_reorder_proxy(State(state): State<WsState>, body: Bytes) -> Response {
    proxy_envelope_post(&state, body, "/control/routes/reorder").await
}

/// `POST /dashboard/api/uplinks/reorder` — `{instance, body}` envelope to
/// `/control/uplinks/reorder`; `body` carries `{group, name, to}`, forwarded
/// verbatim (same envelope shape as routes reorder, different control path).
pub async fn uplinks_reorder_proxy(State(state): State<WsState>, body: Bytes) -> Response {
    proxy_envelope_post(&state, body, "/control/uplinks/reorder").await
}

/// Shared CRUD passthrough behind `uplinks_proxy`/`routes_proxy`: GET forwards
/// `instance` and any other filters as a query string; the mutating methods
/// carry an `{instance, body}` envelope. Verbatim behaviour of the original
/// `uplinks_proxy`, parameterized by the control `path`.
async fn proxy_crud(
    state: &WsState,
    method: Method,
    query: Option<String>,
    body: Bytes,
    path: &str,
) -> Response {
    let (name, forward_body, forward_query) = if method == Method::GET {
        let raw = query.unwrap_or_default();
        let mut name = None;
        let mut forwarded: Vec<(String, String)> = Vec::new();
        for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
            if k == "instance" {
                name = Some(v.into_owned());
            } else {
                forwarded.push((k.into_owned(), v.into_owned()));
            }
        }
        let Some(name) = name else {
            return json_error(StatusCode::BAD_REQUEST, "missing instance query");
        };
        let forwarded_query = if forwarded.is_empty() {
            None
        } else {
            Some(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(forwarded.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                    .finish(),
            )
        };
        (name, None, forwarded_query)
    } else {
        if body.is_empty() {
            return json_error(StatusCode::BAD_REQUEST, "missing instance");
        }
        let envelope: ProxyEnvelope = match serde_json::from_slice(&body) {
            Ok(envelope) => envelope,
            Err(error) => {
                return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {error}"));
            },
        };
        if envelope.instance.is_empty() {
            return json_error(StatusCode::BAD_REQUEST, "instance must not be empty");
        }
        let inner = envelope_body_bytes(&envelope.body);
        (envelope.instance, Some(inner), query)
    };

    let Some(instance) = find(state, &name) else {
        return json_error(StatusCode::NOT_FOUND, "unknown instance");
    };

    let full_path = match forward_query {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    };
    match state
        .backend
        .request(instance, method, &full_path, forward_body)
        .await
    {
        Ok(response) => json_response(response.status, &parse_or_raw(&response.body)),
        Err(error) => json_response(
            StatusCode::BAD_GATEWAY,
            &serde_json::json!({ "error": format!("{error:#}") }),
        ),
    }
}

/// Shared `{instance, body}` POST passthrough behind `apply_proxy`/
/// `routes_reorder_proxy`: parses the envelope, resolves the instance, and
/// forwards `body` (JSON-serialized, defaulting to `null` when the caller
/// omits it — every current `apply_proxy` caller does) to `path`.
///
/// `/control/apply` never reads its request body, so `apply_proxy` sending
/// `null` instead of the zero-byte body it used to hardcode is unobservable
/// there. `/control/routes/reorder` DOES read its body (`{from, to,
/// revision}`), so unlike that old apply-only shape this must forward the
/// envelope's `body` rather than discard it.
async fn proxy_envelope_post(state: &WsState, body: Bytes, path: &str) -> Response {
    if body.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "missing instance");
    }
    let envelope: ProxyEnvelope = match serde_json::from_slice(&body) {
        Ok(envelope) => envelope,
        Err(error) => {
            return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {error}"));
        },
    };
    if envelope.instance.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "instance must not be empty");
    }
    let Some(instance) = find(state, &envelope.instance) else {
        return json_error(StatusCode::NOT_FOUND, "unknown instance");
    };
    let inner = envelope_body_bytes(&envelope.body);
    match state.backend.request(instance, Method::POST, path, Some(inner)).await {
        Ok(response) => json_response(response.status, &parse_or_raw(&response.body)),
        Err(error) => json_response(
            StatusCode::BAD_GATEWAY,
            &serde_json::json!({ "error": format!("{error:#}") }),
        ),
    }
}

/// Serializes an envelope's `body` field back to bytes for forwarding to the
/// instance's control API. `unwrap_or_default` turns a (never-expected)
/// serialization failure of an already-deserialized `Value` into an empty
/// body rather than a panic. Shared by `proxy_crud`'s mutating branch and
/// `proxy_envelope_post`.
fn envelope_body_bytes(body: &Value) -> Bytes {
    Bytes::from(serde_json::to_vec(body).unwrap_or_default())
}

/// Control APIs answer JSON, but a proxy or a panic can put anything on the
/// wire. Non-JSON is handed to the browser as `{"raw": "..."}` rather than
/// turned into an error, so the operator sees what actually came back.
fn parse_or_raw(body: &Bytes) -> Value {
    serde_json::from_slice(body)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(body) }))
}
