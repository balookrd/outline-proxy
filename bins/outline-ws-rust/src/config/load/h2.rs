use super::super::schema::H2Section;
use super::super::types::H2Config;

pub(super) fn load_h2_config(h2: Option<&H2Section>) -> H2Config {
    // Windows left unset (`None`) keep the carrier's default
    // (`outline_transport` `carrier_windows`: `ws_h2` 8 MiB stream / 32 MiB
    // connection, `xhttp_h2` 2 MiB / 5 MiB), not a browser's. Set them in
    // `[h2]` to override, e.g. lower on memory-tight hosts.
    H2Config {
        initial_stream_window_size: h2.and_then(|s| s.initial_stream_window_size),
        initial_connection_window_size: h2.and_then(|s| s.initial_connection_window_size),
        keepalive_interval_secs: h2.and_then(|s| s.keepalive_interval_secs),
        keepalive_timeout_secs: h2.and_then(|s| s.keepalive_timeout_secs),
    }
}
