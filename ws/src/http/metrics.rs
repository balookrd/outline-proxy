use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::header::{CONTENT_TYPE, HeaderValue};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::config::MetricsConfig;
use outline_metrics::{record_metrics_http_request, render_prometheus};
use outline_uplink::UplinkRegistry;

type MetricsResponse = Response<Full<Bytes>>;

pub fn spawn_metrics_server(config: MetricsConfig, uplinks: UplinkRegistry) {
    tokio::spawn(async move {
        if let Err(error) = run_metrics_server(config, uplinks).await {
            warn!(error = %format!("{error:#}"), "metrics server stopped");
        }
    });
}

/// Cap concurrent in-flight observability requests. Metrics is usually
/// scraped by one or two Prometheus instances, so 64 leaves ample slack
/// for overlapping scrapes without letting a slowloris hold sockets
/// unbounded.
const MAX_CONCURRENT_METRICS_CONNECTIONS: usize = 64;

/// Hard cap on how long a client may take to send its request headers.
/// Prevents slowloris-style idle holds against the observability plane.
const METRICS_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

async fn run_metrics_server(config: MetricsConfig, uplinks: UplinkRegistry) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind metrics listener {}", config.listen))?;
    info!(listen = %config.listen, "metrics server started");

    let conn_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_METRICS_CONNECTIONS));

    loop {
        let (stream, peer) = listener.accept().await.context("metrics accept failed")?;
        let uplinks = uplinks.clone();
        let permit = conn_sem
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed");
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(stream, uplinks).await {
                warn!(%peer, error = %format!("{error:#}"), "metrics request failed");
            }
        });
    }
}

async fn handle_connection(stream: TcpStream, uplinks: UplinkRegistry) -> Result<()> {
    let io = TokioIo::new(stream);
    http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(METRICS_HEADER_READ_TIMEOUT)
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
        _ => {
            record_metrics_http_request("other", 404);
            plain_response(
                StatusCode::NOT_FOUND,
                "text/plain; charset=utf-8",
                Bytes::from_static(b"not found\n"),
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
