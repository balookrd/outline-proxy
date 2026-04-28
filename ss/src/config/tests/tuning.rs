use super::{TuningOverrides, TuningPreset, TuningProfile};

#[test]
fn overrides_apply_on_top_of_preset() {
    let mut tuning = TuningPreset::Medium.preset();
    tuning.apply_overrides(&TuningOverrides {
        h3_udp_socket_buffer_bytes: Some(2 * 1024 * 1024),
        h3_max_concurrent_bidi_streams: Some(128),
        ..TuningOverrides::default()
    });
    assert_eq!(tuning.h3_udp_socket_buffer_bytes, 2 * 1024 * 1024);
    assert_eq!(tuning.h3_max_concurrent_bidi_streams, 128);
    assert_eq!(
        tuning.h3_connection_window_bytes,
        TuningProfile::MEDIUM.h3_connection_window_bytes,
    );
}

#[test]
fn rejects_stream_window_above_connection_window() {
    let mut tuning = TuningProfile::LARGE;
    tuning.h3_stream_window_bytes = tuning.h3_connection_window_bytes + 1;
    let error = tuning.validate().unwrap_err().to_string();
    assert!(error.contains("h3_stream_window_bytes"));
    assert!(error.contains("must not exceed"));
}

#[test]
fn rejects_zero_udp_socket_buffer() {
    let mut tuning = TuningProfile::LARGE;
    tuning.h3_udp_socket_buffer_bytes = 0;
    let error = tuning.validate().unwrap_err().to_string();
    assert!(error.contains("h3_udp_socket_buffer_bytes"));
}

#[test]
fn rejects_oversized_h3_connection_window() {
    let mut tuning = TuningProfile::LARGE;
    tuning.h3_connection_window_bytes = (u32::MAX as u64) + 1;
    let error = tuning.validate().unwrap_err().to_string();
    assert!(error.contains("h3_connection_window_bytes"));
}

#[test]
fn rejects_zero_ws_data_channel_capacity() {
    let mut tuning = TuningProfile::LARGE;
    tuning.ws_data_channel_capacity = 0;
    let error = tuning.validate().unwrap_err().to_string();
    assert!(error.contains("ws_data_channel_capacity"));
}

#[test]
fn ws_data_channel_capacity_override_applies() {
    let mut tuning = TuningPreset::Small.preset();
    assert_eq!(tuning.ws_data_channel_capacity, 16);
    tuning.apply_overrides(&TuningOverrides {
        ws_data_channel_capacity: Some(96),
        ..TuningOverrides::default()
    });
    assert_eq!(tuning.ws_data_channel_capacity, 96);
}
