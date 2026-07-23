//! `/dashboard/api/*` HTTP handlers.

use anyhow::{Context, Result, bail};
use http::{Method, Request, StatusCode};
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::DashboardInstanceConfig;
use crate::http::body::read_limited_body;

use super::DashboardState;
use super::backend_client::{instance_url, send_instance_request};
use super::response::{DashboardResponse, json_error, json_response};

#[derive(Debug, Serialize)]
struct DashboardInstancesResponse {
    refresh_interval_secs: u64,
    instances: Vec<DashboardInstanceMeta>,
}

#[derive(Debug, Serialize)]
struct DashboardInstanceMeta {
    name: String,
}

#[derive(Debug, Serialize)]
struct DashboardInstanceView {
    name: String,
    ok: bool,
    topology: Option<Value>,
    error: Option<String>,
}

pub async fn handle_instances(state: DashboardState) -> DashboardResponse {
    let instances = state
        .instances
        .iter()
        .map(|i| DashboardInstanceMeta { name: i.name.clone() })
        .collect();
    json_response(
        StatusCode::OK,
        &DashboardInstancesResponse {
            refresh_interval_secs: state.refresh_interval_secs,
            instances,
        },
    )
}

pub async fn handle_topology(
    request: Request<Incoming>,
    state: DashboardState,
) -> DashboardResponse {
    let raw_query = request.uri().query().unwrap_or("");
    let mut name: Option<String> = None;
    for (k, v) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        if k == "instance" {
            name = Some(v.into_owned());
            break;
        }
    }
    let Some(name) = name else {
        return json_error(StatusCode::BAD_REQUEST, "missing instance query");
    };
    let Some(instance) = state.instances.iter().find(|i| i.name == name) else {
        return json_error(StatusCode::NOT_FOUND, "unknown instance");
    };
    let view = match fetch_instance_topology(instance, state.request_timeout_secs).await {
        Ok(topology) => DashboardInstanceView {
            name: instance.name.clone(),
            ok: true,
            topology: Some(topology),
            error: None,
        },
        Err(error) => DashboardInstanceView {
            name: instance.name.clone(),
            ok: false,
            topology: None,
            error: Some(format!("{error:#}")),
        },
    };
    json_response(StatusCode::OK, &view)
}

#[derive(Debug, Deserialize)]
struct DashboardActivateRequest {
    targets: Vec<DashboardActivateTarget>,
    #[serde(default)]
    transport: Option<String>,
    /// Operator soft switch: proxied to `/control/activate` as `soft: true` so
    /// the instance migrates live sessions via cluster resume instead of
    /// resetting them. Only honoured on cluster groups (the dashboard only
    /// offers the control when `cluster_resume_enabled`); the instance clamps
    /// it otherwise and echoes the effective value in each result's body.
    #[serde(default)]
    soft: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct DashboardActivateTarget {
    instance: String,
    group: String,
    uplink: String,
}

#[derive(Debug, Serialize)]
struct DashboardActivateResponse {
    results: Vec<DashboardActivateResult>,
}

#[derive(Debug, Serialize)]
struct DashboardActivateResult {
    target: DashboardActivateTarget,
    ok: bool,
    status: Option<u16>,
    body: Option<Value>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DashboardSetEnabledRequest {
    instance: String,
    group: String,
    uplink: String,
    enabled: bool,
}

pub async fn handle_activate(
    request: Request<Incoming>,
    state: DashboardState,
) -> DashboardResponse {
    let body = match read_limited_body(request.into_body(), "/dashboard/api/activate").await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let payload: DashboardActivateRequest = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(error) => {
            let msg = format!("invalid JSON: {error}");
            return json_response(StatusCode::BAD_REQUEST, &serde_json::json!({ "error": msg }));
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
        let instance = state
            .instances
            .iter()
            .find(|instance| instance.name == target.instance);
        let result = match instance {
            Some(instance) => {
                match activate_instance(
                    instance,
                    &target,
                    payload.transport.as_deref(),
                    payload.soft,
                    state.request_timeout_secs,
                )
                .await
                {
                    Ok((status, body)) => DashboardActivateResult {
                        target,
                        ok: status.is_success(),
                        status: Some(status.as_u16()),
                        body: Some(body),
                        error: None,
                    },
                    Err(error) => DashboardActivateResult {
                        target,
                        ok: false,
                        status: None,
                        body: None,
                        error: Some(format!("{error:#}")),
                    },
                }
            },
            None => DashboardActivateResult {
                target,
                ok: false,
                status: None,
                body: None,
                error: Some("unknown instance".to_string()),
            },
        };
        results.push(result);
    }

    json_response(StatusCode::OK, &DashboardActivateResponse { results })
}

#[derive(Debug, Deserialize)]
struct ProxyEnvelope {
    instance: String,
    #[serde(default)]
    body: Value,
}

pub async fn handle_uplinks_proxy(
    request: Request<Incoming>,
    state: DashboardState,
) -> DashboardResponse {
    let method = request.method().clone();
    match method {
        Method::GET | Method::POST | Method::PATCH | Method::DELETE => {},
        _ => return json_error(StatusCode::METHOD_NOT_ALLOWED, "use GET/POST/PATCH/DELETE"),
    }

    // GET requests carry the instance (and optional filters) in the query
    // string; mutating methods carry an envelope `{instance, body}` in the
    // request body.
    let (instance_name, body, query) = if matches!(method, Method::GET) {
        let raw_query = request.uri().query().unwrap_or("").to_string();
        let mut name: Option<String> = None;
        let mut forwarded: Vec<(String, String)> = Vec::new();
        for (k, v) in url::form_urlencoded::parse(raw_query.as_bytes()) {
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
        let (envelope, query) = match parse_proxy_envelope(request).await {
            Ok(pair) => pair,
            Err(response) => return response,
        };
        (
            envelope.instance,
            Some(serde_json::to_vec(&envelope.body).unwrap_or_default()),
            query,
        )
    };

    let Some(instance) = state.instances.iter().find(|i| i.name == instance_name) else {
        return json_error(StatusCode::NOT_FOUND, "unknown instance");
    };

    let mut url = match instance_url(&instance.control_url, "/control/uplinks") {
        Ok(url) => url,
        Err(error) => {
            return json_response(
                StatusCode::BAD_GATEWAY,
                &serde_json::json!({ "error": format!("{error:#}") }),
            );
        },
    };
    if let Some(q) = query {
        url.set_query(Some(&q));
    }

    match send_instance_request(instance, method, url, body, state.request_timeout_secs).await {
        Ok((status, body)) => {
            let parsed: Value = serde_json::from_slice(&body)
                .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&body) }));
            json_response(status, &parsed)
        },
        Err(error) => json_response(
            StatusCode::BAD_GATEWAY,
            &serde_json::json!({ "error": format!("{error:#}") }),
        ),
    }
}

pub async fn handle_apply_proxy(
    request: Request<Incoming>,
    state: DashboardState,
) -> DashboardResponse {
    let (envelope, _) = match parse_proxy_envelope(request).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Some(instance) = state.instances.iter().find(|i| i.name == envelope.instance) else {
        return json_error(StatusCode::NOT_FOUND, "unknown instance");
    };
    let url = match instance_url(&instance.control_url, "/control/apply") {
        Ok(url) => url,
        Err(error) => {
            return json_response(
                StatusCode::BAD_GATEWAY,
                &serde_json::json!({ "error": format!("{error:#}") }),
            );
        },
    };
    match send_instance_request(
        instance,
        Method::POST,
        url,
        Some(Vec::new()),
        state.request_timeout_secs,
    )
    .await
    {
        Ok((status, body)) => {
            let parsed: Value = serde_json::from_slice(&body)
                .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&body) }));
            json_response(status, &parsed)
        },
        Err(error) => json_response(
            StatusCode::BAD_GATEWAY,
            &serde_json::json!({ "error": format!("{error:#}") }),
        ),
    }
}

async fn parse_proxy_envelope(
    request: Request<Incoming>,
) -> Result<(ProxyEnvelope, Option<String>), DashboardResponse> {
    let query = request.uri().query().map(str::to_owned);
    let bytes = match read_limited_body(request.into_body(), "/dashboard/api/proxy").await {
        Ok(bytes) => bytes,
        Err(response) => return Err(response),
    };
    let envelope: ProxyEnvelope = if bytes.is_empty() {
        return Err(json_error(StatusCode::BAD_REQUEST, "missing instance"));
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(error) => {
                return Err(json_response(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({ "error": format!("invalid JSON: {error}") }),
                ));
            },
        }
    };
    if envelope.instance.is_empty() {
        return Err(json_error(StatusCode::BAD_REQUEST, "instance must not be empty"));
    }
    Ok((envelope, query))
}

async fn fetch_instance_topology(
    instance: &DashboardInstanceConfig,
    request_timeout_secs: u64,
) -> Result<Value> {
    let url = instance_url(&instance.control_url, "/control/topology")?;
    let (status, body) =
        send_instance_request(instance, Method::GET, url, None, request_timeout_secs).await?;
    if !status.is_success() {
        bail!("{} returned HTTP {status}", instance.name);
    }
    serde_json::from_slice(&body).context("invalid topology JSON")
}

async fn activate_instance(
    instance: &DashboardInstanceConfig,
    target: &DashboardActivateTarget,
    transport: Option<&str>,
    soft: bool,
    request_timeout_secs: u64,
) -> Result<(StatusCode, Value)> {
    let url = instance_url(&instance.control_url, "/control/activate")?;
    let mut payload = serde_json::json!({
        "group": target.group,
        "uplink": target.uplink,
    });
    if let Some(transport) = transport {
        payload["transport"] = Value::String(transport.to_string());
    }
    // Only send `soft` when set, so a plain activate stays byte-identical to the
    // pre-soft request shape (the instance defaults it to a hard switch).
    if soft {
        payload["soft"] = Value::Bool(true);
    }
    let body = serde_json::to_vec(&payload)?;
    let (status, response_body) =
        send_instance_request(instance, Method::POST, url, Some(body), request_timeout_secs)
            .await?;
    let parsed = serde_json::from_slice(&response_body)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&response_body) }));
    Ok((status, parsed))
}

/// `POST /dashboard/api/set_enabled` — proxy the operator on/off toggle to the
/// target instance's `/control/uplink_enabled`. Keeps the control token
/// server-side; the browser only sends `{instance, group, uplink, enabled}`.
pub async fn handle_set_enabled(
    request: Request<Incoming>,
    state: DashboardState,
) -> DashboardResponse {
    let body = match read_limited_body(request.into_body(), "/dashboard/api/set_enabled").await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let payload: DashboardSetEnabledRequest = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(error) => {
            let msg = format!("invalid JSON: {error}");
            return json_response(StatusCode::BAD_REQUEST, &serde_json::json!({ "error": msg }));
        },
    };
    let Some(instance) = state.instances.iter().find(|i| i.name == payload.instance) else {
        return json_error(StatusCode::BAD_REQUEST, "unknown instance");
    };
    match set_enabled_instance(instance, &payload, state.request_timeout_secs).await {
        Ok((status, body)) => {
            json_response(status, &serde_json::json!({ "ok": status.is_success(), "body": body }))
        },
        Err(error) => json_response(
            StatusCode::BAD_GATEWAY,
            &serde_json::json!({ "ok": false, "error": format!("{error:#}") }),
        ),
    }
}

async fn set_enabled_instance(
    instance: &DashboardInstanceConfig,
    req: &DashboardSetEnabledRequest,
    request_timeout_secs: u64,
) -> Result<(StatusCode, Value)> {
    let url = instance_url(&instance.control_url, "/control/uplink_enabled")?;
    let payload = serde_json::json!({
        "group": req.group,
        "uplink": req.uplink,
        "enabled": req.enabled,
    });
    let body = serde_json::to_vec(&payload)?;
    let (status, response_body) =
        send_instance_request(instance, Method::POST, url, Some(body), request_timeout_secs)
            .await?;
    let parsed = serde_json::from_slice(&response_body)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&response_body) }));
    Ok((status, parsed))
}

#[cfg(test)]
#[path = "tests/api.rs"]
mod tests;
