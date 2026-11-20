use std::io::Write;
use tempfile::NamedTempFile;

use crate::process_controller::{
    MAX_LOG_LINES, ProcessController, ProcessState, find_outline_ws_binary,
};
use crate::profile_store::{AppSettings, ProfileStore, ServerProfile};

#[test]
fn test_process_controller_initial_state_and_logs() {
    let controller = ProcessController::new();
    assert_eq!(controller.state(), ProcessState::Stopped);
    assert_eq!(controller.uptime_secs(), None);
    assert!(controller.logs().is_empty());

    // Push 1050 lines into ring buffer
    for i in 0..1050 {
        controller.push_log(format!("Log message {i}"), None);
    }

    let logs = controller.logs();
    assert_eq!(logs.len(), MAX_LOG_LINES);
    assert_eq!(logs.first().unwrap(), "Log message 50");
    assert_eq!(logs.last().unwrap(), "Log message 1049");
}

#[test]
fn test_find_outline_ws_binary_with_env_override() {
    // Create a temporary dummy executable file
    let mut temp_bin = NamedTempFile::new().expect("failed to create temp file");
    writeln!(temp_bin, "dummy binary").unwrap();
    let temp_path = temp_bin.path().to_path_buf();

    // SAFETY: Setting environment variable in isolated unit test.
    unsafe {
        std::env::set_var("OUTLINE_WS_BIN", &temp_path);
    }

    let found = find_outline_ws_binary();
    assert!(found.is_ok());
    assert_eq!(found.unwrap(), temp_path);

    // SAFETY: Cleaning up environment variable in isolated unit test.
    unsafe {
        std::env::remove_var("OUTLINE_WS_BIN");
    }
}

#[test]
fn test_process_controller_status_response() {
    let temp_file = NamedTempFile::new().unwrap();
    let store = ProfileStore::open(temp_file.path().to_path_buf()).unwrap();

    let profile = ServerProfile {
        name: "Test Server".to_string(),
        link: "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws#Test%20Server"
            .to_string(),
        ..Default::default()
    };
    store.add_profile(profile.clone()).unwrap();

    let controller = ProcessController::new();
    let status = controller.status_response(&store);

    assert_eq!(status.state, ProcessState::Stopped);
    assert_eq!(status.active_profile_id.as_deref(), Some(profile.id.as_str()));
    assert_eq!(status.active_profile_name.as_deref(), Some("Test Server"));
    assert_eq!(status.mode, "socks5");
    assert!(!status.tcp_only);
    assert_eq!(status.uptime_secs, None);
}

#[test]
fn test_process_controller_lifecycle_with_mock_process() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        // Create a mock executable script
        let temp_dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let mock_bin = {
            use std::os::unix::fs::PermissionsExt;
            let script_path = temp_dir.path().join("mock-ws");
            let mut f = std::fs::File::create(&script_path).unwrap();
            writeln!(f, "#!/bin/sh\necho 'Mock ws-rust ready'\nsleep 10").unwrap();
            let mut perms = f.metadata().unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();
            script_path
        };

        #[cfg(windows)]
        let mock_bin = {
            let bat_path = temp_dir.path().join("mock-ws.bat");
            let mut f = std::fs::File::create(&bat_path).unwrap();
            writeln!(f, "@echo off\r\necho Mock ws-rust ready\r\nping 127.0.0.1 -n 10 >nul")
                .unwrap();
            bat_path
        };

        // SAFETY: Setting environment variable in isolated unit test.
        unsafe {
            std::env::set_var("OUTLINE_WS_BIN", &mock_bin);
        }

        let controller = ProcessController::new();
        let profile = ServerProfile {
            name: "Mock Profile".to_string(),
            link: "vless://test@127.0.0.1:443?type=ws".to_string(),
            ..Default::default()
        };
        let settings = AppSettings::default();

        // Start process
        let start_res = controller.start(&profile, &settings, None).await;
        assert!(start_res.is_ok(), "Process start failed: {:?}", start_res);

        let current_state = controller.state();
        assert!(
            matches!(current_state, ProcessState::Running { .. }),
            "Expected Running state, got {:?}",
            current_state
        );
        assert!(controller.uptime_secs().is_some());

        // Stop process
        let stop_res = controller.stop(None).await;
        assert!(stop_res.is_ok());
        assert_eq!(controller.state(), ProcessState::Stopped);
        assert_eq!(controller.uptime_secs(), None);

        // SAFETY: Cleaning up environment variable in isolated unit test.
        unsafe {
            std::env::remove_var("OUTLINE_WS_BIN");
        }
    });
}
