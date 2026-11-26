//! Allocator introspection.
//!
//! External measurement can only say how much dirty memory the process holds
//! (`smaps` says 139 MiB in three mimalloc arenas on .104), never how much of
//! it is live data. That difference decides whether there is fragmentation
//! worth acting on or the memory is simply in use, and every plan for the
//! remaining RSS rests on it. This endpoint reports the allocator's own view:
//! what it has committed, and what it is actually holding.
//!
//! Read-only and cheap — `mi_stats_get_json` walks aggregated counters, not the
//! heap — so it is safe to call against a production node.

use http::{Method, StatusCode};
use serde::Serialize;

use super::{ControlResponse, json_response, require_method};

#[derive(Serialize)]
struct AllocReport {
    allocator: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats_error: Option<String>,
}

pub(super) async fn handle_alloc(
    request: &http::Request<hyper::body::Incoming>,
) -> ControlResponse {
    if let Some(response) = require_method(request.method(), Method::GET, "GET") {
        return response;
    }
    json_response(StatusCode::OK, &report())
}

/// jemalloc reports `allocated` (live bytes), `resident` (what the process
/// holds from the OS), and their gap — the fragmentation, measured rather than
/// inferred. `retained` is address space kept mapped but decommitted, which
/// costs no RSS.
#[cfg(all(feature = "jemalloc", not(windows)))]
fn report() -> AllocReport {
    use tikv_jemalloc_ctl::{epoch, stats};

    // jemalloc's statistics are snapshots refreshed on demand; without
    // advancing the epoch every read returns the values from process start.
    if let Err(error) = epoch::advance() {
        return AllocReport {
            allocator: "jemalloc",
            stats: None,
            stats_error: Some(format!("failed to advance the stats epoch: {error}")),
        };
    }

    let read = |name: &'static str, value: Result<usize, tikv_jemalloc_ctl::Error>| {
        value.map_err(|error| format!("{name}: {error}"))
    };
    let stats = (|| -> Result<serde_json::Value, String> {
        Ok(serde_json::json!({
            "allocated": read("allocated", stats::allocated::read())?,
            "active": read("active", stats::active::read())?,
            "metadata": read("metadata", stats::metadata::read())?,
            "resident": read("resident", stats::resident::read())?,
            "mapped": read("mapped", stats::mapped::read())?,
            "retained": read("retained", stats::retained::read())?,
            // `page` must equal `kernel_page`; see `memory::allocator_page_sizes`.
            "page": crate::memory::allocator_page_sizes().map(|(jemalloc, _)| jemalloc),
            "kernel_page": crate::memory::allocator_page_sizes().map(|(_, kernel)| kernel),
        }))
    })();

    match stats {
        Ok(stats) => AllocReport {
            allocator: "jemalloc",
            stats: Some(stats),
            stats_error: None,
        },
        Err(error) => AllocReport {
            allocator: "jemalloc",
            stats: None,
            stats_error: Some(error),
        },
    }
}

#[cfg(any(windows, not(feature = "jemalloc")))]
fn report() -> AllocReport {
    AllocReport {
        allocator: "system",
        stats: None,
        stats_error: Some("built without a tracked allocator".to_owned()),
    }
}
