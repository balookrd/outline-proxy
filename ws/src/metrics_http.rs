use std::convert::Infallible;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::header::{CONTENT_TYPE, HeaderValue};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::config::MetricsConfig;
use crate::metrics::{record_metrics_http_request, render_prometheus};
use crate::uplink::UplinkManager;

type MetricsResponse = Response<Full<Bytes>>;

pub fn spawn_metrics_server(config: MetricsConfig, uplinks: UplinkManager) {
    tokio::spawn(async move {
        if let Err(error) = run_metrics_server(config, uplinks).await {
            warn!(error = %format!("{error:#}"), "metrics server stopped");
        }
    });
}

async fn run_metrics_server(config: MetricsConfig, uplinks: UplinkManager) -> Result<()> {
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

async fn handle_connection(stream: TcpStream, uplinks: UplinkManager) -> Result<()> {
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

async fn handle_request(request: Request<Incoming>, uplinks: UplinkManager) -> MetricsResponse {
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

async fn render_metrics_response(uplinks: UplinkManager) -> Result<MetricsResponse> {
    let snapshot = uplinks.snapshot().await;
    let body = render_prometheus(&snapshot)?;
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
