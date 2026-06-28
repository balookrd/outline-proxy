use super::super::schema::H2Section;
use super::super::types::H2Config;

pub(super) fn load_h2_config(h2: Option<&H2Section>) -> H2Config {
    // Defaults sized so a single long-RTT carrier stream stays throughput-bound
    // by the link, not the window: at ~1 s tunnel RTT a 1 MiB window caps one
    // flow near 10 Mbit (`window / RTT`). 8 MiB / 32 MiB lifts that ceiling;
    // reduce via `[h2]` on memory-tight hosts.
    H2Config {
        initial_stream_window_size: h2
            .and_then(|s| s.initial_stream_window_size)
            .unwrap_or(8 * 1024 * 1024),
        initial_connection_window_size: h2
            .and_then(|s| s.initial_connection_window_size)
            .unwrap_or(32 * 1024 * 1024),
    }
}
