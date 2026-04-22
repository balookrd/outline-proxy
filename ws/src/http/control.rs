//! Control-plane HTTP listener.
//!
//! Bound separately from the metrics listener so that read-only observability
//! access does not imply authority to mutate runtime state. Every request must
//! present a bearer token matching `[control].token`; there is no anonymous
//! access path.

use std::convert::Infallible;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::config::ControlConfig;
use outline_metrics::record_metrics_http_request;
use outline_uplink::{TransportKind, UplinkRegistry};

type ControlResponse = Response<Full<Bytes>>;

struct ControlState {
    token: String,
    uplinks: UplinkRegistry,
}

pub fn spawn_control_server(config: ControlConfig, uplinks: UplinkRegistry) {
    let state = Arc::new(ControlState { token: config.token, uplinks });
    let listen = config.listen;
    tokio::spawn(async move {
        if let Err(error) = run_control_server(listen, state).await {
            warn!(error = %format!("{error:#}"), "control server stopped");
        }
    });
}

/// Cap concurrent in-flight control requests. The control plane is only
/// used for rare manual switches, so a tight ceiling bounds slowloris
/// impact without ever rate-limiting legitimate use.
const MAX_CONCURRENT_CONTROL_CONNECTIONS: usize = 16;

/// Hard cap on how long a client may take to send its request headers.
/// Slowloris must not be able to pin control-plane sockets — especially
/// because the bearer-token check happens *after* hyper has read the
/// headers, so an unauthenticated peer can otherwise stall us.
const CONTROL_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

async fn run_control_server(
    listen: std::net::SocketAddr,
    state: Arc<ControlState>,
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind control listener {listen}"))?;
    info!(%listen, "control server started");

    let conn_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONTROL_CONNECTIONS));

    loop {
        let (stream, peer) = listener.accept().await.context("control accept failed")?;
        let state = Arc::clone(&state);
        let permit = conn_sem
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed");
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(stream, state).await {
                warn!(%peer, error = %format!("{error:#}"), "control request failed");
            }
        });
    }
}

async fn handle_connection(stream: TcpStream, state: Arc<ControlState>) -> Result<()> {
    let io = TokioIo::new(stream);
    http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(CONTROL_HEADER_READ_TIMEOUT)
        .serve_connection(
            io,
            service_fn(move |request: Request<Incoming>| {
                let state = Arc::clone(&state);
                async move { Ok::<_, Infallible>(handle_request(request, state).await) }
            }),
        )
        .await
        .context("failed to serve control HTTP connection")?;
    Ok(())
}

async fn handle_request(request: Request<Incoming>, state: Arc<ControlState>) -> ControlResponse {
    let label_path: &'static str = match request.uri().path() {
        "/switch" => "/switch",
        _ => "other",
    };

    if !is_authorized(&request, &state.token) {
        record_metrics_http_request(label_path, 401);
        return unauthorized_response();
    }

    match label_path {
        "/switch" => {
            let response = handle_switch(&request, state.uplinks.clone()).await;
            record_metrics_http_request("/switch", response.status().as_u16());
            response
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

fn is_authorized(request: &Request<Incoming>, expected: &str) -> bool {
    let Some(header) = request.headers().get(AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = header.to_str() else {
        return false;
    };
    let Some(presented) = value.strip_prefix("Bearer ").map(str::trim) else {
        return false;
    };
    constant_time_eq(presented.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn unauthorized_response() -> ControlResponse {
    let mut response = plain_response(
        StatusCode::UNAUTHORIZED,
        "text/plain; charset=utf-8",
        Bytes::from_static(b"unauthorized\n"),
    );
    response
        .headers_mut()
        .insert("WWW-Authenticate", HeaderValue::from_static("Bearer"));
    response
}

async fn handle_switch(
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

fn plain_response(status: StatusCode, content_type: &'static str, body: Bytes) -> ControlResponse {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    /// Mirror of the predicate inside `is_authorized`. Kept in sync via the
    /// shared `constant_time_eq` and the same parsing rule (`Bearer ` prefix,
    /// then trim). Hyper's `Incoming` body type is opaque to test code, so we
    /// exercise the header logic directly against a `HeaderMap`.
    fn header_authorized(headers: &HeaderMap, expected: &str) -> bool {
        let Some(header) = headers.get(AUTHORIZATION) else {
            return false;
        };
        let Ok(value) = header.to_str() else {
            return false;
        };
        let Some(presented) = value.strip_prefix("Bearer ").map(str::trim) else {
            return false;
        };
        constant_time_eq(presented.as_bytes(), expected.as_bytes())
    }

    fn headers_with(authorization: Option<&str>) -> HeaderMap {
        let mut map = HeaderMap::new();
        if let Some(value) = authorization {
            map.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn constant_time_eq_matches_byte_for_byte() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn rejects_missing_or_malformed_authorization() {
        assert!(!header_authorized(&headers_with(None), "secret"));
        assert!(!header_authorized(&headers_with(Some("Basic secret")), "secret"));
        assert!(!header_authorized(&headers_with(Some("bearer secret")), "secret"));
    }

    #[test]
    fn accepts_matching_bearer_token() {
        assert!(header_authorized(&headers_with(Some("Bearer secret")), "secret"));
        assert!(header_authorized(&headers_with(Some("Bearer   secret  ")), "secret"));
    }

    #[test]
    fn rejects_mismatched_bearer_token() {
        assert!(!header_authorized(&headers_with(Some("Bearer wrong")), "secret"));
        assert!(!header_authorized(&headers_with(Some("Bearer secre")), "secret"));
        assert!(!header_authorized(&headers_with(Some("Bearer secrett")), "secret"));
    }
}
