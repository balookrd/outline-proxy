//! HTTP/1.1 client for talking to per-instance control APIs.
//!
//! Built on `hyper::client::conn::http1` so that chunked decoding, header
//! parsing and keep-alive semantics come from hyper rather than ad-hoc code.
//! Each call opens a fresh TCP (+ TLS) connection; `Connection: close` is
//! implied by dropping the `SendRequest` handle when the function returns.
//!
//! No connection pool, deliberately: this service issues a handful of requests
//! per page view against at most a dozen instances, so a pool would optimise
//! something that is not hot while adding state to an otherwise stateless
//! process.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONNECTION, CONTENT_TYPE, HOST};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::warn;
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::config::InstanceConfig;

/// Aborts the wrapped task when dropped.
///
/// Local copy of the helper the client plane keeps in `outline-transport`,
/// duplicated rather than depended upon: pulling that crate in would drag the
/// whole transport stack into a process that only speaks plain HTTP.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Debug)]
pub struct BackendResponse {
    pub status: StatusCode,
    pub body: Bytes,
}

/// Talks to instance control APIs. Cheap to clone-by-`Arc`; holds only the
/// timeout and a TLS connector whose root store is built once.
pub struct Backend {
    timeout: Duration,
    tls: TlsConnector,
}

impl Backend {
    pub fn new(timeout_secs: u64) -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            timeout: Duration::from_secs(timeout_secs),
            tls: TlsConnector::from(Arc::new(config)),
        }
    }

    /// Sends one request to `instance`, injecting its bearer token server-side.
    ///
    /// Errors carry the instance name so a single broken node is identifiable in
    /// an aggregated response instead of failing the whole page anonymously.
    pub async fn request(
        &self,
        instance: &InstanceConfig,
        method: Method,
        path: &str,
        body: Option<Bytes>,
    ) -> Result<BackendResponse> {
        let url = instance_url(&instance.control_url, path)
            .with_context(|| format!("{}: bad control_url", instance.name))?;
        timeout(self.timeout, self.send(instance, method, url, body))
            .await
            .with_context(|| format!("{}: control request timed out", instance.name))?
            .with_context(|| format!("{}: control request failed", instance.name))
    }

    async fn send(
        &self,
        instance: &InstanceConfig,
        method: Method,
        url: Url,
        body: Option<Bytes>,
    ) -> Result<BackendResponse> {
        if !matches!(url.scheme(), "http" | "https") {
            bail!("only http:// and https:// control URLs are supported");
        }
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("control_url has no host"))?
            .to_string();
        let port =
            url.port_or_known_default()
                .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path_and_query = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_string(),
        };

        // A default port is omitted from `Host`, matching what a browser sends;
        // some control APIs compare the header against their own authority.
        let host_header =
            if (url.scheme() == "https" && port == 443) || (url.scheme() == "http" && port == 80) {
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
            .body(Full::new(body.unwrap_or_default()))
            .context("failed to build control request")?;

        // The browser-facing error (ss/api.rs, ws/api.rs just `format!("{error:#}")`
        // this whole chain into the JSON `error` field) must not name the control
        // host:port: `control_url` is otherwise deliberately never advertised to
        // the browser (see ss/api.rs's `list_instances` doc comment). The instance
        // NAME is still fine to surface — `request()` wraps this in one below —
        // and the host:port is not lost, just moved to the server-side log.
        let tcp = TcpStream::connect((host.as_str(), port)).await.map_err(|error| {
            warn!(
                instance = %instance.name,
                host = %host,
                port,
                %error,
                "failed to connect to control API"
            );
            anyhow::anyhow!("instance unreachable")
        })?;

        if url.scheme() == "https" {
            let server_name =
                ServerName::try_from(host.clone()).context("invalid TLS server name")?;
            let tls_stream = self
                .tls
                .connect(server_name, tcp)
                .await
                .context("TLS handshake with control API failed")?;
            exchange(tls_stream, request).await
        } else {
            exchange(tcp, request).await
        }
    }
}

/// Joins `path` onto the base path of `control_url`, so an instance reached
/// through a reverse proxy (`https://host/rust-ws-exporter`) keeps its prefix.
///
/// `path` may carry a query string (`/control/uplinks?group=main`): the uplinks
/// proxy forwards the browser's filters that way, and dropping them would leave
/// the UI silently showing unfiltered results.
fn instance_url(base: &str, path: &str) -> Result<Url> {
    let base = Url::parse(base).context("control_url is not a URL")?;
    let mut url = base.clone();
    let (path, query) = match path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path, None),
    };
    let base_path = base.path().trim_end_matches('/');
    let suffix = path.strip_prefix('/').unwrap_or(path);
    let full_path = if base_path.is_empty() {
        format!("/{suffix}")
    } else {
        format!("{base_path}/{suffix}")
    };
    url.set_path(&full_path);
    url.set_query(query);
    url.set_fragment(None);
    Ok(url)
}

async fn exchange<T>(io: T, request: Request<Full<Bytes>>) -> Result<BackendResponse>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = http1::handshake(TokioIo::new(io))
        .await
        .context("HTTP/1 handshake with control API failed")?;
    // Bound the conn driver to this function's scope. Without it, peers that
    // ignore `Connection: close` (or merely delay the FIN) leave the spawned
    // task parked on `conn.await`, holding the TLS+TCP socket as ESTABLISHED —
    // every page refresh leaks one FD per such peer until ulimit triggers.
    let _driver = AbortOnDrop(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let response = sender.send_request(request).await.context("control request failed")?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .context("failed to read control response body")?
        .to_bytes();
    Ok(BackendResponse { status, body })
}

#[cfg(test)]
#[path = "tests/backend.rs"]
mod tests;
