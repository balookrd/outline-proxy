//! Tests for the UDP flow-reader's clean-close classification.

use anyhow::anyhow;
use outline_transport::WsClosed;

use super::is_clean_ws_close;

#[test]
fn bare_ws_closed_is_clean() {
    let err = anyhow::Error::from(WsClosed);
    assert!(
        is_clean_ws_close(&err),
        "a bare WsClosed marker must classify as a clean close, not a runtime failure",
    );
}

#[test]
fn ws_closed_under_context_is_clean() {
    // The reader propagates the read error up through `?`, which can layer
    // additional context on top of the typed marker. The chain walk must still
    // find `WsClosed` underneath — otherwise a routine close would be charged
    // as a data-plane failure the moment any context is added.
    let err = anyhow::Error::from(WsClosed).context("reading UDP downlink packet");
    assert!(
        is_clean_ws_close(&err),
        "WsClosed beneath a context layer must still classify as a clean close",
    );
}

#[test]
fn dirty_read_error_is_not_clean() {
    // A real transport error (e.g. the 1013 "front alive, back dead" close)
    // carries no WsClosed marker and MUST still escalate as a runtime failure.
    let err = anyhow!("websocket read failed: IO error: Invalid close code: 1013");
    assert!(
        !is_clean_ws_close(&err),
        "a genuine read error must NOT be suppressed as a clean close",
    );
}
