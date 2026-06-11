use super::super::schema::H2Section;
use super::super::types::H2Config;

pub(super) fn load_h2_config(h2: Option<&H2Section>) -> H2Config {
    H2Config {
        initial_stream_window_size: h2
            .and_then(|s| s.initial_stream_window_size)
            .unwrap_or(1024 * 1024),
        initial_connection_window_size: h2
            .and_then(|s| s.initial_connection_window_size)
            .unwrap_or(2 * 1024 * 1024),
    }
}
