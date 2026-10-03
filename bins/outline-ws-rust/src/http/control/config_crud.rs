//! Read and patch top-level and subsystem configuration (`[probe]`, `[socks5]`,
//! `[tun]`, `[dial]`, `[padding]`, `[quic]`, `[h2]`, `[tcp_timeouts]`).
//!
//! Edits the on-disk TOML document in place (via `toml_edit`, preserving
//! comments and table ordering).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use http::{Method, Request, StatusCode};
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use tokio::fs;
use toml_edit::{DocumentMut, Item, Table, Value, value};

use super::config_edit::{json_error_owned, read_json, write_document_atomic};
use super::server::ControlState;
use super::{ControlResponse, json_error, json_response, plain_response};

const LABEL: &str = "/control/config";

#[derive(Debug, Serialize, Deserialize)]
pub struct WsConfigResponse {
    pub config_path: Option<String>,
    pub probe: Option<ProbeConfigView>,
    pub socks5: Option<Socks5ConfigView>,
    pub tun: Option<TunConfigView>,
    pub dial: Option<DialConfigView>,
    pub padding: Option<PaddingConfigView>,
    pub quic: Option<QuicConfigView>,
    pub h2: Option<H2ConfigView>,
    pub tcp_timeouts: Option<TcpTimeoutsConfigView>,
    pub fingerprint_profile: Option<String>,
    pub prefer_public_ipv6_src: Option<bool>,
    pub direct_fwmark: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfigView {
    pub interval_secs: Option<u64>,
    pub timeout_secs: Option<u64>,
    pub max_concurrent: Option<usize>,
    pub max_dials: Option<usize>,
    pub min_failures: Option<usize>,
    pub attempts: Option<usize>,
    pub skip_when_active: Option<bool>,
    pub liveness_interval_secs: Option<u64>,
    pub endpoint_check: Option<bool>,
    pub endpoint_check_timeout_ms: Option<u64>,
    pub http_urls: Option<Vec<String>>,
    pub tls_targets: Option<Vec<String>>,
    pub dns_server: Option<String>,
    pub dns_port: Option<u16>,
    pub dns_name: Option<String>,
    pub tcp_host: Option<String>,
    pub tcp_port: Option<u16>,
    pub ws_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Socks5UserView {
    pub username: String,
    pub has_password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5ConfigView {
    pub listen: Option<String>,
    pub username: Option<String>,
    pub has_password: bool,
    #[serde(default)]
    pub users: Vec<Socks5UserView>,
    pub users_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfigView {
    pub name: Option<String>,
    pub mtu: Option<usize>,
    pub max_flows: Option<usize>,
    pub max_carrier_flows: Option<usize>,
    pub idle_timeout_secs: Option<u64>,
    pub max_concurrent_upstream_dials: Option<usize>,
    pub ipsec_bypass: Option<bool>,
    pub sniff_quic: Option<bool>,
    pub route_by_sni: Option<bool>,
    pub gso: Option<bool>,
    pub gro: Option<bool>,
    pub uso: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DialConfigView {
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaddingConfigView {
    pub enabled: Option<bool>,
    pub min_bytes: Option<u16>,
    pub max_bytes: Option<u16>,
    pub cover: Option<bool>,
    pub cover_jitter_min_ms: Option<u64>,
    pub cover_jitter_max_ms: Option<u64>,
    pub react_to_throttle: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfigView {
    pub stream_receive_window: Option<u32>,
    pub receive_window: Option<u32>,
    pub keepalive_secs: Option<u64>,
    pub idle_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H2ConfigView {
    pub initial_stream_window_size: Option<u32>,
    pub initial_connection_window_size: Option<u32>,
    pub keepalive_interval_secs: Option<u64>,
    pub keepalive_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpTimeoutsConfigView {
    pub post_client_eof_downstream_secs: Option<u64>,
    pub upstream_response_secs: Option<u64>,
    pub socks_upstream_idle_secs: Option<u64>,
    pub direct_idle_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WsConfigPatch {
    pub probe: Option<ProbeConfigPatch>,
    pub socks5: Option<Socks5ConfigPatch>,
    pub tun: Option<TunConfigPatch>,
    pub dial: Option<DialConfigPatch>,
    pub padding: Option<PaddingConfigPatch>,
    pub quic: Option<QuicConfigPatch>,
    pub h2: Option<H2ConfigPatch>,
    pub tcp_timeouts: Option<TcpTimeoutsConfigPatch>,
    pub fingerprint_profile: Option<String>,
    pub prefer_public_ipv6_src: Option<bool>,
    pub direct_fwmark: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProbeConfigPatch {
    pub interval_secs: Option<u64>,
    pub timeout_secs: Option<u64>,
    pub max_concurrent: Option<usize>,
    pub max_dials: Option<usize>,
    pub min_failures: Option<usize>,
    pub attempts: Option<usize>,
    pub skip_when_active: Option<bool>,
    pub liveness_interval_secs: Option<u64>,
    pub endpoint_check: Option<bool>,
    pub endpoint_check_timeout_ms: Option<u64>,
    pub http_urls: Option<Vec<String>>,
    pub tls_targets: Option<Vec<String>>,
    pub dns_server: Option<String>,
    pub dns_port: Option<u16>,
    pub dns_name: Option<String>,
    pub tcp_host: Option<String>,
    pub tcp_port: Option<u16>,
    pub ws_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5UserPatch {
    pub username: String,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Socks5ConfigPatch {
    pub listen: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub users: Option<Vec<Socks5UserPatch>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunConfigPatch {
    pub name: Option<String>,
    pub mtu: Option<usize>,
    pub max_flows: Option<usize>,
    pub max_carrier_flows: Option<usize>,
    pub idle_timeout_secs: Option<u64>,
    pub max_concurrent_upstream_dials: Option<usize>,
    pub ipsec_bypass: Option<bool>,
    pub sniff_quic: Option<bool>,
    pub route_by_sni: Option<bool>,
    pub gso: Option<bool>,
    pub gro: Option<bool>,
    pub uso: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DialConfigPatch {
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PaddingConfigPatch {
    pub enabled: Option<bool>,
    pub min_bytes: Option<u16>,
    pub max_bytes: Option<u16>,
    pub cover: Option<bool>,
    pub cover_jitter_min_ms: Option<u64>,
    pub cover_jitter_max_ms: Option<u64>,
    pub react_to_throttle: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuicConfigPatch {
    pub stream_receive_window: Option<u32>,
    pub receive_window: Option<u32>,
    pub keepalive_secs: Option<u64>,
    pub idle_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct H2ConfigPatch {
    pub initial_stream_window_size: Option<u32>,
    pub initial_connection_window_size: Option<u32>,
    pub keepalive_interval_secs: Option<u64>,
    pub keepalive_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TcpTimeoutsConfigPatch {
    pub post_client_eof_downstream_secs: Option<u64>,
    pub upstream_response_secs: Option<u64>,
    pub socks_upstream_idle_secs: Option<u64>,
    pub direct_idle_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct WsConfigMutationResponse {
    pub status: &'static str,
    pub apply_required: bool,
    pub restart_required: bool,
}

pub(crate) async fn handle_config(
    request: Request<Incoming>,
    state: Arc<ControlState>,
) -> ControlResponse {
    match *request.method() {
        Method::GET => handle_get_config(state).await,
        Method::PATCH => handle_patch_config(request, state).await,
        _ => plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "application/json; charset=utf-8",
            bytes::Bytes::from_static(br#"{"error":"use GET or PATCH"}"#),
        ),
    }
}

async fn handle_get_config(state: Arc<ControlState>) -> ControlResponse {
    let Some(path) = &state.config_path else {
        return json_error(
            StatusCode::CONFLICT,
            "config file path unknown; control endpoints need on-disk config",
        );
    };

    let raw = match fs::read_to_string(path).await {
        Ok(s) => s,
        Err(err) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read config: {err}"),
            );
        },
    };

    let doc = match raw.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(err) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("config is not valid TOML: {err}"),
            );
        },
    };

    let config_path = Some(path.display().to_string());
    let probe = extract_probe(&doc);
    let socks5 = extract_socks5(&doc);
    let tun = extract_tun(&doc);
    let dial = extract_dial(&doc);
    let padding = extract_padding(&doc);
    let quic = extract_quic(&doc);
    let h2 = extract_h2(&doc);
    let tcp_timeouts = extract_tcp_timeouts(&doc);

    let fingerprint_profile = doc
        .get("fingerprint_profile")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let prefer_public_ipv6_src = doc.get("prefer_public_ipv6_src").and_then(|v| v.as_bool());

    let direct_fwmark = doc
        .get("direct_fwmark")
        .and_then(|v| v.as_integer())
        .map(|n| n as u32);

    json_response(
        StatusCode::OK,
        &WsConfigResponse {
            config_path,
            probe,
            socks5,
            tun,
            dial,
            padding,
            quic,
            h2,
            tcp_timeouts,
            fingerprint_profile,
            prefer_public_ipv6_src,
            direct_fwmark,
        },
    )
}

fn extract_probe(doc: &DocumentMut) -> Option<ProbeConfigView> {
    let tbl = doc
        .get("outline")
        .and_then(Item::as_table)
        .and_then(|t| t.get("probe"))
        .and_then(Item::as_table)
        .or_else(|| doc.get("probe").and_then(Item::as_table))?;
    let http_urls = tbl.get("http").and_then(Item::as_table).map(|h| {
        if let Some(urls) = h.get("urls").and_then(Item::as_array) {
            urls.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        } else if let Some(url) = h.get("url").and_then(Item::as_str) {
            vec![url.to_string()]
        } else {
            Vec::new()
        }
    });

    let tls_targets = tbl.get("tls").and_then(Item::as_table).map(|t| {
        if let Some(targets) = t.get("targets").and_then(Item::as_array) {
            targets
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        } else if let Some(target) = t.get("target").and_then(Item::as_str) {
            vec![target.to_string()]
        } else {
            Vec::new()
        }
    });

    let dns = tbl.get("dns").and_then(Item::as_table);
    let dns_server = dns
        .and_then(|d| d.get("server"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let dns_port = dns
        .and_then(|d| d.get("port"))
        .and_then(|v| v.as_integer())
        .map(|n| n as u16);
    let dns_name = dns
        .and_then(|d| d.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let tcp = tbl.get("tcp").and_then(Item::as_table);
    let tcp_host = tcp
        .and_then(|t| t.get("host"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let tcp_port = tcp
        .and_then(|t| t.get("port"))
        .and_then(|v| v.as_integer())
        .map(|n| n as u16);

    let ws = tbl.get("ws").and_then(Item::as_table);
    let ws_enabled = ws
        .and_then(|w| w.get("enabled"))
        .and_then(|v| v.as_bool())
        .or(Some(true));

    Some(ProbeConfigView {
        interval_secs: tbl
            .get("interval_secs")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
        timeout_secs: tbl.get("timeout_secs").and_then(|v| v.as_integer()).map(|n| n as u64),
        max_concurrent: tbl
            .get("max_concurrent")
            .and_then(|v| v.as_integer())
            .map(|n| n as usize),
        max_dials: tbl.get("max_dials").and_then(|v| v.as_integer()).map(|n| n as usize),
        min_failures: tbl
            .get("min_failures")
            .and_then(|v| v.as_integer())
            .map(|n| n as usize),
        attempts: tbl.get("attempts").and_then(|v| v.as_integer()).map(|n| n as usize),
        skip_when_active: tbl.get("skip_when_active").and_then(|v| v.as_bool()).or(Some(true)),
        liveness_interval_secs: tbl
            .get("liveness_interval_secs")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
        endpoint_check: tbl.get("endpoint_check").and_then(|v| v.as_bool()).or(Some(true)),
        endpoint_check_timeout_ms: tbl
            .get("endpoint_check_timeout_ms")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
        http_urls,
        tls_targets,
        dns_server,
        dns_port,
        dns_name,
        tcp_host,
        tcp_port,
        ws_enabled,
    })
}

fn extract_socks5(doc: &DocumentMut) -> Option<Socks5ConfigView> {
    let tbl = doc.get("socks5").and_then(Item::as_table)?;
    let listen = tbl.get("listen").and_then(|v| v.as_str()).map(|s| s.to_string());
    let mut users = Vec::new();

    if let Some(arr_of_tables) = tbl.get("users").and_then(Item::as_array_of_tables) {
        for t in arr_of_tables.iter() {
            if let Some(u) = t.get("username").and_then(Item::as_str) {
                let has_password = t
                    .get("password")
                    .and_then(Item::as_str)
                    .is_some_and(|p| !p.is_empty());
                users.push(Socks5UserView { username: u.to_string(), has_password });
            }
        }
    } else if let Some(arr) = tbl.get("users").and_then(Item::as_array) {
        for it in arr.iter() {
            if let Some(inline) = it.as_inline_table()
                && let Some(u) = inline.get("username").and_then(Value::as_str)
            {
                let has_password = inline
                    .get("password")
                    .and_then(Value::as_str)
                    .is_some_and(|p| !p.is_empty());
                users.push(Socks5UserView { username: u.to_string(), has_password });
            }
        }
    }

    let single_username = tbl.get("username").and_then(|v| v.as_str()).map(|s| s.to_string());
    let single_has_password = tbl
        .get("password")
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    if users.is_empty()
        && let Some(ref u) = single_username
    {
        users.push(Socks5UserView {
            username: u.clone(),
            has_password: single_has_password,
        });
    }

    let users_count = users.len();

    Some(Socks5ConfigView {
        listen,
        username: single_username,
        has_password: single_has_password,
        users,
        users_count,
    })
}

fn extract_tun(doc: &DocumentMut) -> Option<TunConfigView> {
    let tbl = doc.get("tun").and_then(Item::as_table)?;
    let gso = tbl.get("gso").and_then(|v| v.as_bool()).or(Some(true));
    let gro = tbl.get("gro").and_then(|v| v.as_bool()).or(gso);
    let uso = tbl.get("uso").and_then(|v| v.as_bool()).or(gso);
    let sniff_quic = tbl.get("sniff_quic").and_then(|v| v.as_bool()).or(Some(true));

    Some(TunConfigView {
        name: tbl.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()),
        mtu: tbl.get("mtu").and_then(|v| v.as_integer()).map(|n| n as usize),
        max_flows: tbl.get("max_flows").and_then(|v| v.as_integer()).map(|n| n as usize),
        max_carrier_flows: tbl
            .get("max_carrier_flows")
            .and_then(|v| v.as_integer())
            .map(|n| n as usize),
        idle_timeout_secs: tbl
            .get("idle_timeout_secs")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
        max_concurrent_upstream_dials: tbl
            .get("max_concurrent_upstream_dials")
            .and_then(|v| v.as_integer())
            .map(|n| n as usize),
        ipsec_bypass: tbl.get("ipsec_bypass").and_then(|v| v.as_bool()),
        sniff_quic,
        route_by_sni: tbl.get("route_by_sni").and_then(|v| v.as_bool()),
        gso,
        gro,
        uso,
    })
}

fn extract_dial(doc: &DocumentMut) -> Option<DialConfigView> {
    let tbl = doc.get("dial").and_then(Item::as_table)?;
    Some(DialConfigView {
        timeout_secs: tbl.get("timeout_secs").and_then(|v| v.as_integer()).map(|n| n as u64),
    })
}

fn extract_padding(doc: &DocumentMut) -> Option<PaddingConfigView> {
    let tbl = doc.get("padding").and_then(Item::as_table)?;
    Some(PaddingConfigView {
        enabled: tbl.get("enabled").and_then(|v| v.as_bool()),
        min_bytes: tbl.get("min_bytes").and_then(|v| v.as_integer()).map(|n| n as u16),
        max_bytes: tbl.get("max_bytes").and_then(|v| v.as_integer()).map(|n| n as u16),
        cover: tbl.get("cover").and_then(|v| v.as_bool()),
        cover_jitter_min_ms: tbl
            .get("cover_jitter_min_ms")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
        cover_jitter_max_ms: tbl
            .get("cover_jitter_max_ms")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
        react_to_throttle: tbl.get("react_to_throttle").and_then(|v| v.as_bool()),
    })
}

fn extract_quic(doc: &DocumentMut) -> Option<QuicConfigView> {
    let tbl = doc.get("quic").and_then(Item::as_table)?;
    Some(QuicConfigView {
        stream_receive_window: tbl
            .get("stream_receive_window")
            .and_then(|v| v.as_integer())
            .map(|n| n as u32),
        receive_window: tbl
            .get("receive_window")
            .and_then(|v| v.as_integer())
            .map(|n| n as u32),
        keepalive_secs: tbl
            .get("keepalive_secs")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
        idle_timeout_secs: tbl
            .get("idle_timeout_secs")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
    })
}

fn extract_h2(doc: &DocumentMut) -> Option<H2ConfigView> {
    let tbl = doc.get("h2").and_then(Item::as_table)?;
    Some(H2ConfigView {
        initial_stream_window_size: tbl
            .get("initial_stream_window_size")
            .and_then(|v| v.as_integer())
            .map(|n| n as u32),
        initial_connection_window_size: tbl
            .get("initial_connection_window_size")
            .and_then(|v| v.as_integer())
            .map(|n| n as u32),
        keepalive_interval_secs: tbl
            .get("keepalive_interval_secs")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
        keepalive_timeout_secs: tbl
            .get("keepalive_timeout_secs")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
    })
}

fn extract_tcp_timeouts(doc: &DocumentMut) -> Option<TcpTimeoutsConfigView> {
    let tbl = doc.get("tcp_timeouts").and_then(Item::as_table)?;
    Some(TcpTimeoutsConfigView {
        post_client_eof_downstream_secs: tbl
            .get("post_client_eof_downstream_secs")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
        upstream_response_secs: tbl
            .get("upstream_response_secs")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
        socks_upstream_idle_secs: tbl
            .get("socks_upstream_idle_secs")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
        direct_idle_secs: tbl
            .get("direct_idle_secs")
            .and_then(|v| v.as_integer())
            .map(|n| n as u64),
    })
}

async fn handle_patch_config(
    request: Request<Incoming>,
    state: Arc<ControlState>,
) -> ControlResponse {
    let Some(path) = state.config_path.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            "config file path unknown; control endpoints need on-disk config",
        );
    };

    let patch: WsConfigPatch = match read_json(request, LABEL).await {
        Ok(v) => v,
        Err(err) => return err,
    };

    // 1. Validation
    if let Some(probe) = &patch.probe {
        if let Some(i) = probe.interval_secs
            && i == 0
        {
            return json_error(StatusCode::BAD_REQUEST, "probe.interval_secs must be > 0");
        }
        if let Some(t) = probe.timeout_secs
            && t == 0
        {
            return json_error(StatusCode::BAD_REQUEST, "probe.timeout_secs must be > 0");
        }
        if let Some(mf) = probe.min_failures
            && mf == 0
        {
            return json_error(StatusCode::BAD_REQUEST, "probe.min_failures must be > 0");
        }
        if let Some(urls) = &probe.http_urls {
            for u in urls {
                if url::Url::parse(u).is_err() {
                    return json_error_owned(
                        StatusCode::BAD_REQUEST,
                        format!("invalid probe HTTP url: {u}"),
                    );
                }
            }
        }
    }

    if let Some(s5) = &patch.socks5 {
        if let Some(listen) = &s5.listen
            && !listen.trim().is_empty()
            && listen.trim().parse::<SocketAddr>().is_err()
        {
            return json_error(StatusCode::BAD_REQUEST, "invalid socks5.listen socket address");
        }
        if let Some(users) = &s5.users {
            for u in users {
                let uname = u.username.trim();
                if uname.is_empty() {
                    return json_error(
                        StatusCode::BAD_REQUEST,
                        "socks5 user username cannot be empty",
                    );
                }
                if uname.len() > 255 {
                    return json_error(
                        StatusCode::BAD_REQUEST,
                        "socks5 username is too long (max 255 bytes)",
                    );
                }
                if let Some(pass) = &u.password
                    && pass.len() > 255
                {
                    return json_error(
                        StatusCode::BAD_REQUEST,
                        "socks5 password is too long (max 255 bytes)",
                    );
                }
            }
        }
    }

    if let Some(padding) = &patch.padding {
        if let (Some(min), Some(max)) = (padding.min_bytes, padding.max_bytes)
            && min > max
        {
            return json_error(
                StatusCode::BAD_REQUEST,
                "padding min_bytes cannot exceed max_bytes",
            );
        }
        if let (Some(min), Some(max)) = (padding.cover_jitter_min_ms, padding.cover_jitter_max_ms)
            && min > max
        {
            return json_error(
                StatusCode::BAD_REQUEST,
                "padding cover_jitter_min_ms cannot exceed max_ms",
            );
        }
    }

    if let Some(profile) = &patch.fingerprint_profile {
        let p = profile.trim().to_lowercase();
        if p != "off"
            && p != "none"
            && p != "disabled"
            && p != "stable"
            && p != "random"
            && p != "per-host"
        {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid fingerprint_profile (accepted: off, stable, random)",
            );
        }
    }

    let _guard = state.config_write_lock.lock().await;
    let raw = match fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(err) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read config: {err}"),
            );
        },
    };

    let mut doc = match raw.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(err) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("config is not valid TOML: {err}"),
            );
        },
    };

    // Apply patches
    if let Some(probe) = &patch.probe {
        apply_probe_patch(&mut doc, probe);
    }
    if let Some(s5) = &patch.socks5 {
        apply_socks5_patch(&mut doc, s5);
    }
    if let Some(tun) = &patch.tun {
        apply_tun_patch(&mut doc, tun);
    }
    if let Some(dial) = &patch.dial {
        apply_dial_patch(&mut doc, dial);
    }
    if let Some(pad) = &patch.padding {
        apply_padding_patch(&mut doc, pad);
    }
    if let Some(quic) = &patch.quic {
        apply_quic_patch(&mut doc, quic);
    }
    if let Some(h2) = &patch.h2 {
        apply_h2_patch(&mut doc, h2);
    }
    if let Some(timeouts) = &patch.tcp_timeouts {
        apply_tcp_timeouts_patch(&mut doc, timeouts);
    }
    if let Some(fp) = &patch.fingerprint_profile {
        doc.insert("fingerprint_profile", value(fp.trim()));
    }
    if let Some(pref) = patch.prefer_public_ipv6_src
        && (pref || doc.contains_key("prefer_public_ipv6_src"))
    {
        doc.insert("prefer_public_ipv6_src", value(pref));
    }
    if let Some(fwmark) = patch.direct_fwmark {
        doc.insert("direct_fwmark", value(fwmark as i64));
    }

    if let Err(err) = write_document_atomic(&path, &doc).await {
        return json_error_owned(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to write config: {err:#}"),
        );
    }

    let restart_required = patch.socks5.is_some()
        || patch.tun.is_some()
        || patch.dial.is_some()
        || patch.quic.is_some()
        || patch.h2.is_some()
        || patch.tcp_timeouts.is_some();

    json_response(
        StatusCode::OK,
        &WsConfigMutationResponse {
            status: "ok",
            apply_required: true,
            restart_required,
        },
    )
}

fn get_or_create_table<'a>(doc: &'a mut DocumentMut, key: &str) -> &'a mut Table {
    if !doc.contains_key(key) || !doc[key].is_table() {
        let mut tbl = Table::new();
        tbl.set_implicit(false);
        doc.insert(key, Item::Table(tbl));
    }
    doc[key].as_table_mut().expect("table inserted above")
}

fn get_or_create_subtable<'a>(parent: &'a mut Table, key: &str) -> &'a mut Table {
    if !parent.contains_key(key) || !parent[key].is_table() {
        let mut tbl = Table::new();
        tbl.set_implicit(false);
        parent.insert(key, Item::Table(tbl));
    }
    parent[key].as_table_mut().expect("subtable inserted above")
}

fn get_or_create_probe_table(doc: &mut DocumentMut) -> &mut Table {
    let has_outline_probe = doc
        .get("outline")
        .and_then(Item::as_table)
        .is_some_and(|o| o.contains_key("probe"));
    if has_outline_probe || (doc.contains_key("outline") && !doc.contains_key("probe")) {
        let outline = get_or_create_table(doc, "outline");
        get_or_create_subtable(outline, "probe")
    } else {
        get_or_create_table(doc, "probe")
    }
}

fn apply_probe_patch(doc: &mut DocumentMut, patch: &ProbeConfigPatch) {
    let tbl = get_or_create_probe_table(doc);

    if let Some(v) = patch.interval_secs {
        tbl.insert("interval_secs", value(v as i64));
    }
    if let Some(v) = patch.timeout_secs {
        tbl.insert("timeout_secs", value(v as i64));
    }
    if let Some(v) = patch.max_concurrent {
        tbl.insert("max_concurrent", value(v as i64));
    }
    if let Some(v) = patch.max_dials {
        tbl.insert("max_dials", value(v as i64));
    }
    if let Some(v) = patch.min_failures {
        tbl.insert("min_failures", value(v as i64));
    }
    if let Some(v) = patch.attempts {
        tbl.insert("attempts", value(v as i64));
    }
    if let Some(v) = patch.skip_when_active {
        tbl.insert("skip_when_active", value(v));
    }
    if let Some(v) = patch.liveness_interval_secs {
        tbl.insert("liveness_interval_secs", value(v as i64));
    }
    if let Some(v) = patch.endpoint_check {
        tbl.insert("endpoint_check", value(v));
    }
    if let Some(v) = patch.endpoint_check_timeout_ms {
        tbl.insert("endpoint_check_timeout_ms", value(v as i64));
    }

    if let Some(urls) = &patch.http_urls {
        let mut arr = toml_edit::Array::new();
        for u in urls {
            if !u.trim().is_empty() {
                arr.push(u.trim());
            }
        }
        if arr.is_empty() {
            tbl.remove("http");
        } else {
            let http_tbl = get_or_create_subtable(tbl, "http");
            http_tbl.insert("urls", Item::Value(toml_edit::Value::Array(arr)));
            http_tbl.remove("url");
        }
    }

    if let Some(targets) = &patch.tls_targets {
        let mut arr = toml_edit::Array::new();
        for t in targets {
            if !t.trim().is_empty() {
                arr.push(t.trim());
            }
        }
        if arr.is_empty() {
            tbl.remove("tls");
        } else {
            let tls_tbl = get_or_create_subtable(tbl, "tls");
            tls_tbl.insert("targets", Item::Value(toml_edit::Value::Array(arr)));
            tls_tbl.remove("target");
        }
    }

    if patch.dns_server.is_some() || patch.dns_port.is_some() || patch.dns_name.is_some() {
        if let Some(srv) = &patch.dns_server {
            if !srv.trim().is_empty() {
                let dns_tbl = get_or_create_subtable(tbl, "dns");
                dns_tbl.insert("server", value(srv.trim()));
                if let Some(port) = patch.dns_port {
                    dns_tbl.insert("port", value(port as i64));
                }
                if let Some(name) = &patch.dns_name {
                    dns_tbl.insert("name", value(name.trim()));
                }
            } else {
                tbl.remove("dns");
            }
        } else if tbl.contains_key("dns") {
            let dns_tbl = get_or_create_subtable(tbl, "dns");
            if let Some(port) = patch.dns_port {
                dns_tbl.insert("port", value(port as i64));
            }
            if let Some(name) = &patch.dns_name {
                dns_tbl.insert("name", value(name.trim()));
            }
        }
    }

    if patch.tcp_host.is_some() || patch.tcp_port.is_some() {
        if let Some(host) = &patch.tcp_host {
            if !host.trim().is_empty() {
                let tcp_tbl = get_or_create_subtable(tbl, "tcp");
                tcp_tbl.insert("host", value(host.trim()));
                if let Some(port) = patch.tcp_port {
                    tcp_tbl.insert("port", value(port as i64));
                }
            } else {
                tbl.remove("tcp");
            }
        } else if patch.tcp_port.is_some() && tbl.contains_key("tcp") {
            let tcp_tbl = get_or_create_subtable(tbl, "tcp");
            if let Some(port) = patch.tcp_port {
                tcp_tbl.insert("port", value(port as i64));
            }
        }
    }

    if let Some(ws_en) = patch.ws_enabled
        && (!ws_en || tbl.contains_key("ws"))
    {
        let ws_tbl = get_or_create_subtable(tbl, "ws");
        ws_tbl.insert("enabled", value(ws_en));
    }
}

fn apply_socks5_patch(doc: &mut DocumentMut, patch: &Socks5ConfigPatch) {
    let tbl = get_or_create_table(doc, "socks5");
    if let Some(l) = &patch.listen {
        if l.trim().is_empty() {
            tbl.remove("listen");
        } else {
            tbl.insert("listen", value(l.trim()));
        }
    }

    if let Some(new_users) = &patch.users {
        let mut existing_passwords = HashMap::new();
        if let Some(arr_of_tables) = tbl.get("users").and_then(Item::as_array_of_tables) {
            for t in arr_of_tables.iter() {
                if let (Some(u), Some(p)) = (
                    t.get("username").and_then(Item::as_str),
                    t.get("password").and_then(Item::as_str),
                ) {
                    existing_passwords.insert(u.to_string(), p.to_string());
                }
            }
        } else if let Some(arr) = tbl.get("users").and_then(Item::as_array) {
            for it in arr.iter() {
                if let Some(inline) = it.as_inline_table()
                    && let (Some(u), Some(p)) = (
                        inline.get("username").and_then(Value::as_str),
                        inline.get("password").and_then(Value::as_str),
                    )
                {
                    existing_passwords.insert(u.to_string(), p.to_string());
                }
            }
        }
        if let (Some(u), Some(p)) = (
            tbl.get("username").and_then(Item::as_str),
            tbl.get("password").and_then(Item::as_str),
        ) {
            existing_passwords.insert(u.to_string(), p.to_string());
        }

        tbl.remove("username");
        tbl.remove("password");

        let filtered_users: Vec<_> =
            new_users.iter().filter(|u| !u.username.trim().is_empty()).collect();

        if filtered_users.is_empty() {
            tbl.remove("users");
        } else {
            let mut aot = toml_edit::ArrayOfTables::new();
            for u in filtered_users {
                let uname = u.username.trim();
                let mut user_tbl = Table::new();
                user_tbl.insert("username", value(uname));

                let pass = match &u.password {
                    Some(p) if !p.trim().is_empty() && p.trim() != "********" => {
                        Some(p.trim().to_string())
                    },
                    _ => existing_passwords.get(uname).cloned(),
                };

                if let Some(p) = pass {
                    user_tbl.insert("password", value(p));
                }
                aot.push(user_tbl);
            }
            tbl.insert("users", Item::ArrayOfTables(aot));
        }
    } else {
        if let Some(u) = &patch.username {
            if u.trim().is_empty() {
                tbl.remove("username");
            } else {
                tbl.remove("users");
                tbl.insert("username", value(u.trim()));
            }
        }
        if let Some(p) = &patch.password {
            if p.trim().is_empty() {
                tbl.remove("password");
            } else if p.trim() != "********" {
                tbl.insert("password", value(p.trim()));
            }
        }
    }
}

fn apply_tun_patch(doc: &mut DocumentMut, patch: &TunConfigPatch) {
    let tbl = get_or_create_table(doc, "tun");
    if let Some(n) = &patch.name {
        tbl.insert("name", value(n.trim()));
    }
    if let Some(m) = patch.mtu {
        tbl.insert("mtu", value(m as i64));
    }
    if let Some(f) = patch.max_flows {
        tbl.insert("max_flows", value(f as i64));
    }
    if let Some(c) = patch.max_carrier_flows {
        tbl.insert("max_carrier_flows", value(c as i64));
    }
    if let Some(t) = patch.idle_timeout_secs {
        tbl.insert("idle_timeout_secs", value(t as i64));
    }
    if let Some(d) = patch.max_concurrent_upstream_dials {
        tbl.insert("max_concurrent_upstream_dials", value(d as i64));
    }
    if let Some(b) = patch.ipsec_bypass {
        tbl.insert("ipsec_bypass", value(b));
    }
    if let Some(sq) = patch.sniff_quic {
        tbl.insert("sniff_quic", value(sq));
    }
    if let Some(rs) = patch.route_by_sni {
        tbl.insert("route_by_sni", value(rs));
    }
    if let Some(gso) = patch.gso {
        tbl.insert("gso", value(gso));
    }
    if let Some(gro) = patch.gro {
        tbl.insert("gro", value(gro));
    }
    if let Some(uso) = patch.uso {
        tbl.insert("uso", value(uso));
    }
}

fn apply_dial_patch(doc: &mut DocumentMut, patch: &DialConfigPatch) {
    let tbl = get_or_create_table(doc, "dial");
    if let Some(t) = patch.timeout_secs {
        tbl.insert("timeout_secs", value(t as i64));
    }
}

fn apply_padding_patch(doc: &mut DocumentMut, patch: &PaddingConfigPatch) {
    let tbl = get_or_create_table(doc, "padding");
    if let Some(en) = patch.enabled {
        tbl.insert("enabled", value(en));
    }
    if let Some(min) = patch.min_bytes {
        tbl.insert("min_bytes", value(min as i64));
    }
    if let Some(max) = patch.max_bytes {
        tbl.insert("max_bytes", value(max as i64));
    }
    if let Some(c) = patch.cover {
        tbl.insert("cover", value(c));
    }
    if let Some(jmin) = patch.cover_jitter_min_ms {
        tbl.insert("cover_jitter_min_ms", value(jmin as i64));
    }
    if let Some(jmax) = patch.cover_jitter_max_ms {
        tbl.insert("cover_jitter_max_ms", value(jmax as i64));
    }
    if let Some(r) = patch.react_to_throttle {
        tbl.insert("react_to_throttle", value(r));
    }
}

fn apply_quic_patch(doc: &mut DocumentMut, patch: &QuicConfigPatch) {
    let tbl = get_or_create_table(doc, "quic");
    if let Some(v) = patch.stream_receive_window {
        tbl.insert("stream_receive_window", value(v as i64));
    }
    if let Some(v) = patch.receive_window {
        tbl.insert("receive_window", value(v as i64));
    }
    if let Some(v) = patch.keepalive_secs {
        tbl.insert("keepalive_secs", value(v as i64));
    }
    if let Some(v) = patch.idle_timeout_secs {
        tbl.insert("idle_timeout_secs", value(v as i64));
    }
}

fn apply_h2_patch(doc: &mut DocumentMut, patch: &H2ConfigPatch) {
    let tbl = get_or_create_table(doc, "h2");
    if let Some(v) = patch.initial_stream_window_size {
        tbl.insert("initial_stream_window_size", value(v as i64));
    }
    if let Some(v) = patch.initial_connection_window_size {
        tbl.insert("initial_connection_window_size", value(v as i64));
    }
    if let Some(v) = patch.keepalive_interval_secs {
        tbl.insert("keepalive_interval_secs", value(v as i64));
    }
    if let Some(v) = patch.keepalive_timeout_secs {
        tbl.insert("keepalive_timeout_secs", value(v as i64));
    }
}

fn apply_tcp_timeouts_patch(doc: &mut DocumentMut, patch: &TcpTimeoutsConfigPatch) {
    let tbl = get_or_create_table(doc, "tcp_timeouts");
    if let Some(v) = patch.post_client_eof_downstream_secs {
        tbl.insert("post_client_eof_downstream_secs", value(v as i64));
    }
    if let Some(v) = patch.upstream_response_secs {
        tbl.insert("upstream_response_secs", value(v as i64));
    }
    if let Some(v) = patch.socks_upstream_idle_secs {
        tbl.insert("socks_upstream_idle_secs", value(v as i64));
    }
    if let Some(v) = patch.direct_idle_secs {
        tbl.insert("direct_idle_secs", value(v as i64));
    }
}
