use std::sync::Arc;
use tempfile::NamedTempFile;

use crate::AppState;
use crate::process_controller::{ProcessController, ProcessState};
use crate::profile_store::{AppSettings, ProfileStore, ServerProfile};

#[test]
fn test_app_state_crud_and_settings() {
    let temp_file = NamedTempFile::new().unwrap();
    let store = Arc::new(ProfileStore::open(temp_file.path().to_path_buf()).unwrap());
    let controller = Arc::new(ProcessController::new());
    let update_manager = Arc::new(crate::updater::UpdateManager::new());

    let state = AppState {
        profile_store: store.clone(),
        process_controller: controller.clone(),
        update_manager,
    };

    // 1. Initially no profiles
    assert!(state.profile_store.profiles().is_empty());

    // 2. Add profile
    let profile = ServerProfile {
        name: "Test Profile".to_string(),
        link: "vless://test-uuid@1.2.3.4:443?type=ws#Test%20Profile".to_string(),
        ..Default::default()
    };
    state.profile_store.add_profile(profile.clone()).unwrap();

    let profiles = state.profile_store.profiles();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].id, profile.id);
    assert_eq!(state.profile_store.active_profile_id().as_deref(), Some(profile.id.as_str()));

    // 3. Settings update
    let initial_settings = state.profile_store.settings();
    assert_eq!(initial_settings.proxy_mode, "socks5");
    assert!(!initial_settings.tcp_only);

    let updated_settings = AppSettings {
        proxy_mode: "tun".to_string(),
        tcp_only: true,
        socks_port: 1085,
        autostart: true,
        start_minimized: true,
        reconnect_after_update: false,
    };
    state.profile_store.update_settings(updated_settings.clone()).unwrap();

    let current_settings = state.profile_store.settings();
    assert_eq!(current_settings, updated_settings);

    // 4. Status response via controller
    let status = state.process_controller.status_response(&state.profile_store);
    assert_eq!(status.state, ProcessState::Stopped);
    assert_eq!(status.mode, "tun");
    assert!(status.tcp_only);
    assert_eq!(status.active_profile_name.as_deref(), Some("Test Profile"));

    // 5. Remove profile
    state.profile_store.remove_profile(&profile.id).unwrap();
    assert!(state.profile_store.profiles().is_empty());

    // 6. Controller is_running predicate
    assert!(!state.process_controller.is_running());
}

#[test]
fn test_get_app_version_command() {
    tauri::async_runtime::block_on(async {
        let version = crate::commands::get_app_version().await.expect("app version info");
        assert!(!version.version.is_empty());
        assert!(!version.channel.is_empty());
        assert!(!version.commit.is_empty());
        assert!(!version.display_string.is_empty());
    });
}
