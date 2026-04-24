//! `/control/apply` — hot-apply pending `[[uplink_group.uplinks]]` changes.
//!
//! Re-runs [`crate::config::load_config`] against the on-disk file (with
//! the same CLI `Args` the process was launched with, so CLI overrides
//! still apply), validates, and then swaps the new group list into the
//! live [`UplinkRegistry`] via [`UplinkRegistry::apply_new_groups`].
//!
//! Only the `groups` field of the reloaded config is applied. Other fields
//! (`listen`, `socks5_auth`, `tun`, `routing`, `metrics`, `dashboard`,
//! `h2`, `udp_*_buf_bytes`, `tcp_timeouts`, `direct_fwmark`) continue to
//! reflect the values from process startup; changing them requires a full
//! restart. A successful apply is reported in the response.

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use hyper::body::Incoming;
use serde::Serialize;
use tokio::sync::Mutex;
use tracing::{info, warn};

use outline_uplink::UplinkRegistry;

use crate::config::{Args, load_config};

use super::{ControlResponse, json_response, plain_response};

/// Cross-cutting runtime state needed to re-read the config file and swap
/// the live registry. Constructed in `bootstrap::run_with_config` and
/// threaded into [`super::server::ControlState`].
pub struct ApplyHandle {
    pub config_path: PathBuf,
    pub args: Args,
    pub dns_cache: Arc<outline_transport::DnsCache>,
    pub state_store: Option<Arc<outline_uplink::StateStore>>,
    pub registry: UplinkRegistry,
    /// Serialises concurrent `/control/apply` requests. Reloading config
    /// and swapping the registry is not safe to run twice in parallel —
    /// the second caller could see a half-swapped state.
    pub lock: Mutex<()>,
}

#[derive(Debug, Serialize)]
struct ApplyResponse {
    applied: bool,
    groups: usize,
    total_uplinks: usize,
    default_group: String,
}

pub(crate) async fn handle_apply(
    request: Request<Incoming>,
    handle: Arc<ApplyHandle>,
) -> ControlResponse {
    if request.method() != Method::POST {
        return plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "application/json; charset=utf-8",
            Bytes::from_static(br#"{"error":"use POST"}"#),
        );
    }

    let _guard = handle.lock.lock().await;

    // Re-read & re-validate the on-disk config using the same CLI Args
    // the process was launched with. This catches bad edits (e.g. TOML
    // errors, unknown groups referenced by [[route]]) before touching the
    // live registry.
    let new_config = match load_config(&handle.config_path, &handle.args).await {
        Ok(cfg) => cfg,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "apply aborted: config reload failed");
            return json_error_owned(
                StatusCode::BAD_REQUEST,
                format!("config reload failed: {error:#}"),
            );
        },
    };

    // Swap only the uplink groups. Other config fields are ignored for
    // hot-apply; changing them requires a restart.
    if let Err(error) = handle
        .registry
        .apply_new_groups(
            new_config.groups,
            Arc::clone(&handle.dns_cache),
            handle.state_store.clone(),
        )
        .await
    {
        warn!(error = %format!("{error:#}"), "apply aborted: registry swap failed");
        return json_error_owned(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("registry swap failed: {error:#}"),
        );
    }

    let default_group = handle.registry.default_group_name();
    let groups = handle.registry.group_count();
    let total_uplinks = handle.registry.total_uplinks();
    info!(groups, total_uplinks, %default_group, "uplink registry hot-applied via /control/apply");

    json_response(
        StatusCode::OK,
        &ApplyResponse {
            applied: true,
            groups,
            total_uplinks,
            default_group,
        },
    )
}

fn json_error_owned(status: StatusCode, message: String) -> ControlResponse {
    #[derive(Serialize)]
    struct Owned {
        error: String,
    }
    json_response(status, &Owned { error: message })
}
