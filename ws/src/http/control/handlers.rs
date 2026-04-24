use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use outline_uplink::{TransportKind, UplinkRegistry};

use super::topology::{ControlTopologyResponse, build_instance_topology, build_summary};
use super::{ControlResponse, json_error, json_response, plain_response, require_method};

#[derive(Debug, Deserialize)]
pub(crate) struct ActivateRequest {
    pub(crate) group: String,
    pub(crate) uplink: String,
    #[serde(default)]
    pub(crate) transport: Option<ActivateTransport>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ActivateTransport {
    Tcp,
    Udp,
    Both,
}

impl ActivateTransport {
    pub(crate) fn into_registry_transport(self) -> Option<TransportKind> {
        match self {
            Self::Tcp => Some(TransportKind::Tcp),
            Self::Udp => Some(TransportKind::Udp),
            Self::Both => None,
        }
    }
}

#[derive(Debug, Serialize)]
struct ActivateResponse {
    group: String,
    uplink: String,
    index: usize,
    transport: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct ErrorResponse<'a> {
    pub(crate) error: &'a str,
}

pub(crate) async fn handle_switch(
    request: &Request<Incoming>,
    uplinks: UplinkRegistry,
) -> ControlResponse {
    if request.method() != Method::POST {
        return plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"use POST\n"),
        );
    }
    let query = request.uri().query().unwrap_or("");
    let mut uplink_name: Option<String> = None;
    let mut group_name: Option<String> = None;
    let mut transport: Option<TransportKind> = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "uplink" | "name" => uplink_name = Some(value.into_owned()),
            "group" => group_name = Some(value.into_owned()),
            "transport" => match value.as_ref() {
                "tcp" => transport = Some(TransportKind::Tcp),
                "udp" => transport = Some(TransportKind::Udp),
                "both" | "all" | "" => transport = None,
                other => {
                    return plain_response(
                        StatusCode::BAD_REQUEST,
                        "text/plain; charset=utf-8",
                        Bytes::from(format!("invalid transport \"{other}\" (use tcp|udp|both)\n")),
                    );
                },
            },
            _ => {},
        }
    }
    let Some(name) = uplink_name else {
        return plain_response(
            StatusCode::BAD_REQUEST,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"missing required query parameter \"uplink\"\n"),
        );
    };
    match uplinks
        .set_active_uplink_by_name(group_name.as_deref(), &name, transport)
        .await
    {
        Ok((group, index)) => {
            info!(group = %group, uplink = %name, index, ?transport, "manual uplink switch");
            plain_response(
                StatusCode::OK,
                "text/plain; charset=utf-8",
                Bytes::from(format!(
                    "switched group \"{group}\" to uplink \"{name}\" (index {index})\n"
                )),
            )
        },
        Err(error) => {
            warn!(error = %format!("{error:#}"), uplink = %name, "manual uplink switch failed");
            plain_response(
                StatusCode::BAD_REQUEST,
                "text/plain; charset=utf-8",
                Bytes::from(format!("{error}\n")),
            )
        },
    }
}

pub(crate) async fn handle_topology(
    request: &Request<Incoming>,
    uplinks: UplinkRegistry,
) -> ControlResponse {
    if let Some(response) = require_method(request.method(), Method::GET, "GET") {
        return response;
    }
    let snapshots = uplinks.snapshots().await;
    json_response(
        StatusCode::OK,
        &ControlTopologyResponse {
            instance: build_instance_topology(&snapshots),
        },
    )
}

pub(crate) async fn handle_summary(
    request: &Request<Incoming>,
    uplinks: UplinkRegistry,
) -> ControlResponse {
    if let Some(response) = require_method(request.method(), Method::GET, "GET") {
        return response;
    }
    let snapshots = uplinks.snapshots().await;
    json_response(StatusCode::OK, &build_summary(&snapshots))
}

pub(crate) async fn handle_activate(
    request: Request<Incoming>,
    uplinks: UplinkRegistry,
) -> ControlResponse {
    if let Some(response) = require_method(request.method(), Method::POST, "POST") {
        return response;
    }

    let body = match request.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "failed to read /control/activate body");
            return json_error(StatusCode::BAD_REQUEST, "invalid request body");
        },
    };

    activate_from_json(&body, uplinks).await
}

pub(crate) async fn activate_from_json(body: &[u8], uplinks: UplinkRegistry) -> ControlResponse {
    let payload: ActivateRequest = match serde_json::from_slice(body) {
        Ok(payload) => payload,
        Err(error) => {
            let msg = format!("invalid JSON: {error}");
            return json_response(StatusCode::BAD_REQUEST, &serde_json::json!({ "error": msg }));
        },
    };
    if payload.group.trim().is_empty() || payload.uplink.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "\"group\" and \"uplink\" are required");
    }
    let transport = payload
        .transport
        .map(ActivateTransport::into_registry_transport)
        .flatten();
    match uplinks
        .set_active_uplink_by_name(Some(payload.group.trim()), payload.uplink.trim(), transport)
        .await
    {
        Ok((group, index)) => {
            info!(
                group = %group,
                uplink = %payload.uplink,
                index,
                ?transport,
                "manual uplink activation via /control/activate"
            );
            json_response(
                StatusCode::OK,
                &ActivateResponse {
                    group,
                    uplink: payload.uplink.trim().to_string(),
                    index,
                    transport: match payload.transport.unwrap_or(ActivateTransport::Both) {
                        ActivateTransport::Tcp => "tcp",
                        ActivateTransport::Udp => "udp",
                        ActivateTransport::Both => "both",
                    },
                },
            )
        },
        Err(error) => {
            warn!(error = %format!("{error:#}"), "manual /control/activate failed");
            let msg = format!("{error}");
            json_response(StatusCode::BAD_REQUEST, &serde_json::json!({ "error": msg }))
        },
    }
}

