use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::config::StatusConfig;
use crate::metrics::{record_status_request, render_prometheus};
use crate::uplink::UplinkManager;

pub fn spawn_status_server(config: StatusConfig, uplinks: UplinkManager) {
    tokio::spawn(async move {
        if let Err(error) = run_status_server(config, uplinks).await {
            warn!(error = %format!("{error:#}"), "status server stopped");
        }
    });
}

async fn run_status_server(config: StatusConfig, uplinks: UplinkManager) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind status listener {}", config.listen))?;
    info!(listen = %config.listen, "status server started");

    loop {
        let (stream, peer) = listener.accept().await.context("status accept failed")?;
        let uplinks = uplinks.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, uplinks).await {
                warn!(%peer, error = %format!("{error:#}"), "status request failed");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, uplinks: UplinkManager) -> Result<()> {
    let mut buf = [0u8; 4096];
    let read = stream
        .read(&mut buf)
        .await
        .context("failed to read status request")?;
    if read == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..read]);
    let first_line = request.lines().next().unwrap_or_default();
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");

    match path {
        "/status" => {
            let snapshot = uplinks.snapshot().await;
            let body =
                serde_json::to_vec_pretty(&snapshot).context("failed to encode status json")?;
            write_response(&mut stream, 200, "application/json; charset=utf-8", &body).await?;
            record_status_request("/status", 200);
        }
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
            record_status_request("/metrics", 200);
        }
        _ => {
            write_response(
                &mut stream,
                404,
                "text/plain; charset=utf-8",
                b"not found\n",
            )
            .await?;
            record_status_request(path, 404);
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
        .context("failed to write status headers")?;
    stream
        .write_all(body)
        .await
        .context("failed to write status body")?;
    Ok(())
}
