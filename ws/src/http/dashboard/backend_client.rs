//! HTTP/1.1 client for talking to per-instance control APIs.
//!
//! Built on `hyper::client::conn::http1` so that chunked decoding, header
//! parsing and keep-alive semantics come from hyper rather than ad-hoc code.
//! Each call opens a fresh TCP (+ TLS) connection; `Connection: close` is
//! implied by dropping the `SendRequest` handle when the function returns.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONNECTION, CONTENT_TYPE, HOST};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use outline_transport::AbortOnDrop;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::config::DashboardInstanceConfig;

pub fn instance_url(base: &Url, path: &str) -> Result<Url> {
    let mut url = base.clone();
    let base_path = base.path().trim_end_matches('/');
    let suffix = path.strip_prefix('/').unwrap_or(path);
    let full_path = if base_path.is_empty() {
        format!("/{suffix}")
    } else {
        format!("{base_path}/{suffix}")
    };
    url.set_path(&full_path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

pub async fn send_instance_request(
    instance: &DashboardInstanceConfig,
    method: Method,
    url: Url,
    body: Option<Vec<u8>>,
    request_timeout_secs: u64,
) -> Result<(StatusCode, Bytes)> {
    timeout(
        Duration::from_secs(request_timeout_secs),
        send_inner(instance, method, url, body),
    )
    .await
    .context("instance request timed out")?
}

async fn send_inner(
    instance: &DashboardInstanceConfig,
    method: Method,
    url: Url,
    body: Option<Vec<u8>>,
) -> Result<(StatusCode, Bytes)> {
    if !matches!(url.scheme(), "http" | "https") {
        bail!("only http:// and https:// control URLs are supported");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("control_url has no host"))?
        .to_string();
    let port = url
        .port_or_known_default()
        .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    let path_and_query = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };

    let body_bytes = Bytes::from(body.unwrap_or_default());
    let host_header = if (url.scheme() == "https" && port == 443)
        || (url.scheme() == "http" && port == 80)
    {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let request = Request::builder()
        .method(method)
        .uri(&path_and_query)
        .header(HOST, host_header)
        .header(CONNECTION, "close")
        .header(AUTHORIZATION, format!("Bearer {}", instance.token))
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(body_bytes))
        .context("failed to build control request")?;

    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("failed to connect to {host}:{port}"))?;

    if url.scheme() == "https" {
        let connector = tls_connector();
        let server_name = ServerName::try_from(host.clone()).context("invalid TLS server name")?;
        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .context("TLS handshake with control API failed")?;
        exchange(tls_stream, request).await
    } else {
        exchange(tcp, request).await
    }
}

async fn exchange<T>(io: T, request: Request<Full<Bytes>>) -> Result<(StatusCode, Bytes)>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = http1::handshake(TokioIo::new(io))
        .await
        .context("HTTP/1 handshake with control API failed")?;
    // Bound the conn driver to this function's scope. Without it, peers
    // that ignore `Connection: close` (or merely delay the FIN) leave
    // the spawned task parked on `conn.await`, holding the TLS+TCP
    // socket as ESTABLISHED — every dashboard refresh leaks one FD per
    // such peer until ulimit triggers.
    let _driver = AbortOnDrop::new(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let response = sender
        .send_request(request)
        .await
        .context("control request failed")?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .context("failed to read control response body")?
        .to_bytes();
    Ok((status, body))
}

fn tls_connector() -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.extend(TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

#[cfg(test)]
#[path = "tests/backend_client.rs"]
mod tests;
