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
    /// Absent when the allocator exposes no counters (non-mimalloc builds).
    #[serde(skip_serializing_if = "Option::is_none")]
    process: Option<ProcessInfo>,
    /// `mi_stats_get_json` verbatim, so the reply carries whatever the
    /// allocator reports rather than a subset chosen today.
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats_error: Option<String>,
}

#[derive(Serialize)]
struct ProcessInfo {
    elapsed_msecs: usize,
    user_msecs: usize,
    system_msecs: usize,
    current_rss_bytes: usize,
    peak_rss_bytes: usize,
    /// What the allocator asked the OS to back. The gap against `stats` is the
    /// memory held but not in use — the fragmentation this endpoint exists to
    /// size.
    current_commit_bytes: usize,
    peak_commit_bytes: usize,
    page_faults: usize,
}

pub(super) async fn handle_alloc(
    request: &http::Request<hyper::body::Incoming>,
) -> ControlResponse {
    if let Some(response) = require_method(request.method(), Method::GET, "GET") {
        return response;
    }
    json_response(StatusCode::OK, &report())
}

#[cfg(feature = "mimalloc")]
fn report() -> AllocReport {
    let (stats, stats_error) = match stats_json() {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error)),
    };
    AllocReport {
        allocator: "mimalloc",
        process: Some(process_info()),
        stats,
        stats_error,
    }
}

/// jemalloc answers the question mimalloc's release build cannot: `allocated`
/// is live bytes, `resident` is what the process holds from the OS, and the gap
/// between them — `active - allocated` inside runs, `resident - active` in
/// pages not yet returned — is the fragmentation, measured rather than
/// inferred. `retained` is address space kept mapped but decommitted, which
/// costs no RSS.
#[cfg(feature = "jemalloc")]
fn report() -> AllocReport {
    use tikv_jemalloc_ctl::{epoch, stats};

    // jemalloc's statistics are snapshots refreshed on demand; without
    // advancing the epoch every read returns the values from process start.
    if let Err(error) = epoch::advance() {
        return AllocReport {
            allocator: "jemalloc",
            process: None,
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
        }))
    })();

    match stats {
        Ok(stats) => AllocReport {
            allocator: "jemalloc",
            process: None,
            stats: Some(stats),
            stats_error: None,
        },
        Err(error) => AllocReport {
            allocator: "jemalloc",
            process: None,
            stats: None,
            stats_error: Some(error),
        },
    }
}

#[cfg(not(any(feature = "mimalloc", feature = "jemalloc")))]
fn report() -> AllocReport {
    AllocReport {
        allocator: "system",
        process: None,
        stats: None,
        stats_error: Some("built without a tracked allocator".to_owned()),
    }
}

#[cfg(feature = "mimalloc")]
fn process_info() -> ProcessInfo {
    let mut info = [0usize; 8];
    // SAFETY: `mi_process_info` writes one `usize` per pointer and takes no
    // ownership; all eight point into a live local array.
    unsafe {
        libmimalloc_sys::mi_process_info(
            &mut info[0],
            &mut info[1],
            &mut info[2],
            &mut info[3],
            &mut info[4],
            &mut info[5],
            &mut info[6],
            &mut info[7],
        );
    }
    ProcessInfo {
        elapsed_msecs: info[0],
        user_msecs: info[1],
        system_msecs: info[2],
        current_rss_bytes: info[3],
        peak_rss_bytes: info[4],
        current_commit_bytes: info[5],
        peak_commit_bytes: info[6],
        page_faults: info[7],
    }
}

/// Buffer handed to `mi_stats_get_json`. The report is a few KiB; 256 KiB is
/// slack enough that a future mimalloc adding counters cannot silently truncate
/// it, and it is freed as soon as this function returns.
#[cfg(feature = "mimalloc")]
const STATS_BUF_BYTES: usize = 256 * 1024;

#[cfg(feature = "mimalloc")]
fn stats_json() -> Result<serde_json::Value, String> {
    let mut buf = vec![0i8; STATS_BUF_BYTES];
    // SAFETY: mimalloc writes a NUL-terminated string of at most `buf.len()`
    // bytes into the buffer and returns it, or NULL when the buffer is too
    // small. Nothing is allocated on our behalf, so nothing needs freeing.
    let written = unsafe {
        libmimalloc_sys::mi_stats_get_json(buf.len(), buf.as_mut_ptr().cast::<std::ffi::c_char>())
    };
    if written.is_null() {
        return Err(format!("mi_stats_get_json needs more than {STATS_BUF_BYTES} bytes"));
    }
    // SAFETY: non-NULL return means mimalloc NUL-terminated the buffer above.
    let json = unsafe { std::ffi::CStr::from_ptr(written) };
    let json = json
        .to_str()
        .map_err(|error| format!("stats are not UTF-8: {error}"))?;
    serde_json::from_str(json).map_err(|error| format!("stats are not valid JSON: {error}"))
}
