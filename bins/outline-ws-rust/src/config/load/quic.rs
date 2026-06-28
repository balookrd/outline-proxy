use super::super::schema::QuicSection;
use super::super::types::QuicConfig;

pub(super) fn load_quic_config(quic: Option<&QuicSection>) -> QuicConfig {
    // Defaults sized so a single long-RTT carrier stream stays throughput-bound
    // by the link, not the window: at ~1 s tunnel RTT quinn's default ~1 MiB
    // stream window caps one flow near 10 Mbit (`window / RTT`). 8 MiB / 64 MiB
    // lifts that ceiling for raw-QUIC and HTTP/3 carriers; reduce on
    // memory-tight hosts.
    QuicConfig {
        stream_receive_window: quic
            .and_then(|q| q.stream_receive_window)
            .unwrap_or(8 * 1024 * 1024),
        receive_window: quic.and_then(|q| q.receive_window).unwrap_or(64 * 1024 * 1024),
    }
}
