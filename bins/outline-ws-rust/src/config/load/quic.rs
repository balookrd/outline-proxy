use super::super::schema::QuicSection;
use super::super::types::QuicConfig;

pub(super) fn load_quic_config(quic: Option<&QuicSection>) -> QuicConfig {
    // Windows and idle default to the dial's browser profile
    // (`outline_transport` quic/tp_profile.rs); explicit values override it.
    QuicConfig {
        stream_receive_window: quic.and_then(|q| q.stream_receive_window),
        receive_window: quic.and_then(|q| q.receive_window),
        keepalive_secs: quic.and_then(|q| q.keepalive_secs),
        idle_timeout_secs: quic.and_then(|q| q.idle_timeout_secs),
        udp_datagrams: quic.and_then(|q| q.udp_datagrams).unwrap_or(true),
    }
}
