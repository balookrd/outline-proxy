use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::config::MetricsConfig;
use crate::metrics::{record_metrics_http_request, render_prometheus};
use crate::uplink::UplinkManager;

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

async fn handle_connection(mut stream: TcpStream, uplinks: UplinkManager) -> Result<()> {
    let mut buf = [0u8; 4096];
    let read = stream
        .read(&mut buf)
        .await
        .context("failed to read metrics request")?;
    if read == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..read]);
    let first_line = request.lines().next().unwrap_or_default();
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");

    match path {
        "/metrics" => {
            let snapshot = uplinks.snapshot().await;
            let body = render_prometheus(&snapshot)?;
            write_response(
                &mut stream,
                200,
                "text/plain; version=0.0.4",
                body.as_bytes(),
            )
            .await?;
            record_metrics_http_request("/metrics", 200);
        }
        _ => {
            write_response(
                &mut stream,
                404,
                "text/plain; charset=utf-8",
                b"not found\n",
            )
            .await?;
            record_metrics_http_request(path, 404);
        }
    }

    Ok(())
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let status_text = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let headers = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .await
        .context("failed to write metrics headers")?;
    stream
        .write_all(body)
        .await
        .context("failed to write metrics body")?;
    Ok(())
}
