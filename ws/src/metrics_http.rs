use std::convert::Infallible;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::header::{CONTENT_TYPE, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::config::MetricsConfig;
use crate::metrics::{record_metrics_http_request, render_prometheus};
use outline_uplink::{TransportKind, UplinkRegistry};

type MetricsResponse = Response<Full<Bytes>>;

pub fn spawn_metrics_server(config: MetricsConfig, uplinks: UplinkRegistry) {
    tokio::spawn(async move {
        if let Err(error) = run_metrics_server(config, uplinks).await {
            warn!(error = %format!("{error:#}"), "metrics server stopped");
        }
    });
}

async fn run_metrics_server(config: MetricsConfig, uplinks: UplinkRegistry) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind metrics listener {}", config.listen))?;
    info!(listen = %config.listen, "metrics server started");

    loop {
        let (stream, peer) = listener.accept().await.context("metrics accept failed")?;
        let uplinks = uplinks.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, uplinks).await {
                warn!(%peer, error = %format!("{error:#}"), "metrics request failed");
            }
        });
    }
}

async fn handle_connection(stream: TcpStream, uplinks: UplinkRegistry) -> Result<()> {
    let io = TokioIo::new(stream);
    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |request: Request<Incoming>| {
                let uplinks = uplinks.clone();
                async move { Ok::<_, Infallible>(handle_request(request, uplinks).await) }
            }),
        )
        .await
        .context("failed to serve metrics HTTP connection")?;
    Ok(())
}

async fn handle_request(request: Request<Incoming>, uplinks: UplinkRegistry) -> MetricsResponse {
    let path = request.uri().path();

    match path {
        "/metrics" => match render_metrics_response(uplinks).await {
            Ok(response) => {
                record_metrics_http_request("/metrics", 200);
                response
            },
            Err(error) => {
                warn!(error = %format!("{error:#}"), "failed to render metrics response");
                record_metrics_http_request("/metrics", 500);
                plain_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "text/plain; charset=utf-8",
                    Bytes::from_static(b"internal server error\n"),
                )
            },
        },
        "/switch" => {
            let response = handle_switch(&request, uplinks).await;
            record_metrics_http_request("/switch", response.status().as_u16());
            response
        },
        _ => {
            record_metrics_http_request(path, 404);
            plain_response(
                StatusCode::NOT_FOUND,
                "text/plain; charset=utf-8",
                Bytes::from_static(b"not found\n"),
            )
        },
    }
}

async fn handle_switch(
    request: &Request<Incoming>,
    uplinks: UplinkRegistry,
) -> MetricsResponse {
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

async fn render_metrics_response(uplinks: UplinkRegistry) -> Result<MetricsResponse> {
    let snapshots = uplinks.snapshots().await;
    let body = render_prometheus(&snapshots)?;
    Ok(plain_response(StatusCode::OK, "text/plain; version=0.0.4", Bytes::from(body)))
}

fn plain_response(status: StatusCode, content_type: &'static str, body: Bytes) -> MetricsResponse {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}
