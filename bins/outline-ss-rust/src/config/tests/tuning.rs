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
fn per_user_nat_cap_defaults_per_profile_and_takes_overrides() {
    // Non-zero on every profile so a single tenant can no longer claim the
    // whole NAT table, yet each stays a fraction of that profile's global
    // `udp_nat_max_entries` and comfortably above a legitimate client's fan-out.
    assert_eq!(TuningProfile::SMALL.udp_nat_max_entries_per_user, 1_024);
    assert_eq!(TuningProfile::MEDIUM.udp_nat_max_entries_per_user, 2_048);
    assert_eq!(TuningProfile::LARGE.udp_nat_max_entries_per_user, 4_096);
    for preset in [TuningPreset::Small, TuningPreset::Medium, TuningPreset::Large] {
        let tuning = preset.preset();
        assert!(
            tuning.udp_nat_max_entries_per_user < tuning.udp_nat_max_entries,
            "the per-user share must stay below the global cap it sits under",
        );
    }

    let mut tuning = TuningPreset::Medium.preset();
    tuning.apply_overrides(&TuningOverrides {
        udp_nat_max_entries_per_user: Some(512),
        ..TuningOverrides::default()
    });
    assert_eq!(tuning.udp_nat_max_entries_per_user, 512);
    assert_eq!(tuning.udp_nat_max_entries, TuningProfile::MEDIUM.udp_nat_max_entries);
    tuning.validate().unwrap();

    // `0` remains a valid opt-out back to global-cap-only behaviour.
    tuning.apply_overrides(&TuningOverrides {
        udp_nat_max_entries_per_user: Some(0),
        ..TuningOverrides::default()
    });
    assert_eq!(tuning.udp_nat_max_entries_per_user, 0);
    tuning.validate().unwrap();
}

#[test]
fn per_user_replay_cap_defaults_per_profile_and_takes_overrides() {
    // Non-zero on every profile so one tenant spraying unique session ids / salts
    // can no longer fill the global replay cap and starve the others, yet each
    // stays a fraction of that profile's global `udp_replay_max_sessions`.
    assert_eq!(TuningProfile::SMALL.udp_replay_max_sessions_per_user, 4_096);
    assert_eq!(TuningProfile::MEDIUM.udp_replay_max_sessions_per_user, 8_192);
    assert_eq!(TuningProfile::LARGE.udp_replay_max_sessions_per_user, 16_384);
    for preset in [TuningPreset::Small, TuningPreset::Medium, TuningPreset::Large] {
        let tuning = preset.preset();
        assert!(
            tuning.udp_replay_max_sessions_per_user < tuning.udp_replay_max_sessions,
            "the per-user share must stay below the global replay cap it sits under",
        );
    }

    let mut tuning = TuningPreset::Medium.preset();
    tuning.apply_overrides(&TuningOverrides {
        udp_replay_max_sessions_per_user: Some(512),
        ..TuningOverrides::default()
    });
    assert_eq!(tuning.udp_replay_max_sessions_per_user, 512);
    assert_eq!(tuning.udp_replay_max_sessions, TuningProfile::MEDIUM.udp_replay_max_sessions);
    tuning.validate().unwrap();

    // `0` remains a valid opt-out back to global-cap-only behaviour.
    tuning.apply_overrides(&TuningOverrides {
        udp_replay_max_sessions_per_user: Some(0),
        ..TuningOverrides::default()
    });
    assert_eq!(tuning.udp_replay_max_sessions_per_user, 0);
    tuning.validate().unwrap();
}

#[test]
fn per_source_ip_xhttp_cap_defaults_to_disabled_and_takes_overrides() {
    for preset in [TuningPreset::Small, TuningPreset::Medium, TuningPreset::Large] {
        assert_eq!(
            preset.preset().xhttp_max_sessions_per_ip,
            0,
            "the per-source-IP XHTTP cap must stay opt-in (it keys on the transport peer, \
             which is the CDN edge behind a fronting proxy)",
        );
    }

    let mut tuning = TuningPreset::Medium.preset();
    tuning.apply_overrides(&TuningOverrides {
        xhttp_max_sessions_per_ip: Some(64),
        ..TuningOverrides::default()
    });
    assert_eq!(tuning.xhttp_max_sessions_per_ip, 64);
    assert_eq!(tuning.xhttp_max_sessions, TuningProfile::MEDIUM.xhttp_max_sessions);
    tuning.validate().unwrap();
}

#[test]
fn tcp_handshake_replay_cap_defaults_mirror_udp_and_take_overrides() {
    // The TCP handshake salt cap mirrors the UDP replay session cap per profile.
    assert_eq!(TuningProfile::SMALL.tcp_handshake_replay_max_salts, 16_384);
    assert_eq!(TuningProfile::MEDIUM.tcp_handshake_replay_max_salts, 65_536);
    assert_eq!(TuningProfile::LARGE.tcp_handshake_replay_max_salts, 262_144);

    let mut tuning = TuningPreset::Medium.preset();
    tuning.apply_overrides(&TuningOverrides {
        tcp_handshake_replay_max_salts: Some(0),
        ..TuningOverrides::default()
    });
    // `0` is a valid opt-out, just like the UDP replay cap.
    assert_eq!(tuning.tcp_handshake_replay_max_salts, 0);
    tuning.validate().unwrap();
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
