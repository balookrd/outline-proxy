//! `/dashboard/api/*` HTTP handlers.

use anyhow::{bail, Context, Result};
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

use crate::config::DashboardInstanceConfig;

use super::backend_client::{instance_url, send_instance_request};
use super::response::{json_error, json_response, DashboardResponse};
use super::DashboardState;

#[derive(Debug, Serialize)]
struct DashboardTopologyResponse {
    refresh_interval_secs: u64,
    instances: Vec<DashboardInstanceView>,
}

#[derive(Debug, Serialize)]
struct DashboardInstanceView {
    name: String,
    ok: bool,
    topology: Option<Value>,
    error: Option<String>,
}

pub async fn handle_topology(state: DashboardState) -> DashboardResponse {
    let mut instances = Vec::with_capacity(state.instances.len());
    for instance in &state.instances {
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
        instances.push(view);
    }

    json_response(
        StatusCode::OK,
        &DashboardTopologyResponse {
            refresh_interval_secs: state.refresh_interval_secs,
            instances,
        },
    )
}

#[derive(Debug, Deserialize)]
struct DashboardActivateRequest {
    targets: Vec<DashboardActivateTarget>,
    #[serde(default)]
    transport: Option<String>,
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

pub async fn handle_activate(
    request: Request<Incoming>,
    state: DashboardState,
) -> DashboardResponse {
    let body = match request.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "failed to read dashboard activate body");
            return json_error(StatusCode::BAD_REQUEST, "invalid request body");
        },
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
    let (envelope, query) = match parse_proxy_envelope(request).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Some(instance) = state
        .instances
        .iter()
        .find(|i| i.name == envelope.instance)
    else {
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

    let body = if matches!(method, Method::GET) {
        None
    } else {
        Some(serde_json::to_vec(&envelope.body).unwrap_or_default())
    };
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
    let Some(instance) = state
        .instances
        .iter()
        .find(|i| i.name == envelope.instance)
    else {
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
    let bytes = match request.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "failed to read dashboard proxy body");
            return Err(json_error(StatusCode::BAD_REQUEST, "invalid request body"));
        },
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
    let body = serde_json::to_vec(&payload)?;
    let (status, response_body) = send_instance_request(
        instance,
        Method::POST,
        url,
        Some(body),
        request_timeout_secs,
    )
    .await?;
    let parsed = serde_json::from_slice(&response_body)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&response_body) }));
    Ok((status, parsed))
}
