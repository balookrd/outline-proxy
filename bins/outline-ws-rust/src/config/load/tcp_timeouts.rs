use std::time::Duration;

use crate::proxy::TcpTimeouts;

use super::super::schema::TcpTimeoutsSection;

pub(super) fn load_tcp_timeouts(section: Option<&TcpTimeoutsSection>) -> TcpTimeouts {
    let defaults = TcpTimeouts::DEFAULT;
    let Some(s) = section else { return defaults };
    TcpTimeouts {
        post_client_eof_downstream: s
            .post_client_eof_downstream_secs
            .map(Duration::from_secs)
            .unwrap_or(defaults.post_client_eof_downstream),
        upstream_response: s
            .upstream_response_secs
            .map(Duration::from_secs)
            .unwrap_or(defaults.upstream_response),
        socks_upstream_idle: s
            .socks_upstream_idle_secs
            .map(Duration::from_secs)
            .unwrap_or(defaults.socks_upstream_idle),
        direct_idle: s
            .direct_idle_secs
            .map(Duration::from_secs)
            .unwrap_or(defaults.direct_idle),
    }
}
