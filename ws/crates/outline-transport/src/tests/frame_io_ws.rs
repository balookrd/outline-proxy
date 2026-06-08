use std::time::Duration;

use super::{WS_READ_IDLE_TIMEOUT, carrier_liveness};

/// On the H3 carrier the QUIC layer owns liveness, so the WS read-idle
/// watchdog and the client keepalive Ping must both be disabled — a
/// server-delivered Pong on a quiet H3 stream risks a connection-level
/// `H3_INTERNAL_ERROR`, so WS-frame liveness cannot be relied on. Any
/// configured keepalive is dropped on this carrier.
#[test]
fn h3_carrier_disables_watchdog_and_keepalive() {
    assert_eq!(carrier_liveness(true, Some(Duration::from_secs(60))), (None, None));
    assert_eq!(carrier_liveness(true, None), (None, None));
}

/// On h1/h2 there is no shared QUIC keep-alive underneath, so the WS
/// read-idle watchdog stays and the configured keepalive is honoured
/// verbatim (including `None`, which disables outbound Pings).
#[test]
fn non_h3_carrier_keeps_watchdog_and_honours_keepalive() {
    let keepalive = Some(Duration::from_secs(60));
    assert_eq!(carrier_liveness(false, keepalive), (Some(WS_READ_IDLE_TIMEOUT), keepalive));
    assert_eq!(carrier_liveness(false, None), (Some(WS_READ_IDLE_TIMEOUT), None));
}
