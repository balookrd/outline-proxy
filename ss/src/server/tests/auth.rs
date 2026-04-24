use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use axum::http::{Method, Request, StatusCode, header};
use bytes::Bytes;
use http_body_util::Empty;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tokio::net::TcpListener;

use super::super::bootstrap::serve_listener;
use super::super::nat::NatTable;
use super::super::shutdown::ShutdownSignal;
use super::super::{DnsCache, build_app, build_user_routes};
use super::{basic_auth_header, build_test_state, sample_config, set_cookie_pair};
use crate::metrics::Metrics;

#[tokio::test]
async fn root_http_auth_challenges_allows_password_and_hides_other_paths() -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;

    let mut config = sample_config(addr);
    config.http_root_auth = true;
    config.http_root_realm = "My VPN \"Portal\"".into();
    let user_routes = build_user_routes(&config)?;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        user_routes,
        Metrics::new(&config),
        nat_table,
        dns_cache,
        true,
        config.http_root_realm.clone(),
    );
    let app = build_app(routes, services, auth);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();

    let response = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}/"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE),
        Some(&header::HeaderValue::from_static("Basic realm=\"My VPN \\\"Portal\\\"\""))
    );
    assert!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .context("missing auth challenge cookie")?
            .to_str()?
            .contains("Max-Age=300")
    );
    let challenge_cookie = set_cookie_pair(&response)?;
    assert_eq!(challenge_cookie, "outline_ss_root_auth=0");

    let response = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}/"))
                .header(header::COOKIE, challenge_cookie.as_str())
                .header(header::AUTHORIZATION, basic_auth_header("secret-b"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .context("missing auth reset cookie")?
            .to_str()?
            .contains("Max-Age=0")
    );

    let response = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}/tcp"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}/anything"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn root_http_auth_returns_403_after_three_failed_password_attempts() -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;

    let mut config = sample_config(addr);
    config.http_root_auth = true;
    let user_routes = build_user_routes(&config)?;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        user_routes,
        Metrics::new(&config),
        nat_table,
        dns_cache,
        true,
        config.http_root_realm.clone(),
    );
    let app = build_app(routes, services, auth);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();

    let response = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}/"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    let mut cookie = set_cookie_pair(&response)?;

    for attempt in 1..=3 {
        let response = client
            .request(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("http://{addr}/"))
                    .header(header::COOKIE, cookie.as_str())
                    .header(header::AUTHORIZATION, basic_auth_header("wrong-password"))
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;

        let expected_status = if attempt < 3 {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::FORBIDDEN
        };
        assert_eq!(response.status(), expected_status);
        assert!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .context("missing auth attempt cookie")?
                .to_str()?
                .contains("Max-Age=300")
        );
        cookie = set_cookie_pair(&response)?;
        assert_eq!(cookie, format!("outline_ss_root_auth={attempt}"));
    }

    server.abort();
    let _ = server.await;
    Ok(())
}
