use std::sync::Arc;
use tauri::{Emitter, Manager};

pub mod commands;
pub mod config_generator;
pub mod process_controller;
pub mod profile_store;
pub mod proxy_manager;
pub mod traffic_monitor;
pub mod tray;
pub mod updater;
pub mod version;

#[cfg(test)]
mod tests;

pub use process_controller::ProcessController;
pub use profile_store::ProfileStore;

/// Global application state shared across Tauri commands and system tray.
#[derive(Clone)]
pub struct AppState {
    pub profile_store: Arc<ProfileStore>,
    pub process_controller: Arc<ProcessController>,
    pub update_manager: Arc<updater::UpdateManager>,
}

pub fn run() {
    #[cfg(target_os = "windows")]
    unsafe {
        // Enforce Per-Monitor V2 DPI awareness to prevent Windows DWM bitmap stretching/blurring.
        windows_sys::Win32::UI::HiDpi::SetProcessDpiAwarenessContext(
            windows_sys::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
        );
    }

    let profile_store = Arc::new(ProfileStore::load().unwrap_or_else(|e| {
        tracing::warn!("Failed to load existing profiles, initializing empty: {e}");
        ProfileStore::empty(ProfileStore::default_storage_path())
    }));
    let process_controller = Arc::new(ProcessController::new());
    let update_manager = Arc::new(updater::UpdateManager::new());

    let app_state = AppState {
        profile_store: profile_store.clone(),
        process_controller: process_controller.clone(),
        update_manager: update_manager.clone(),
    };

    let app_state_for_setup = Arc::new(app_state.clone());

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::connect,
            commands::disconnect,
            commands::get_profiles,
            commands::add_profile,
            commands::remove_profile,
            commands::select_profile,
            commands::rename_profile,
            commands::get_logs,
            commands::get_settings,
            commands::update_settings,
            commands::update_subscription,
            commands::get_app_version,
            commands::get_update_state,
            commands::check_for_updates,
            commands::install_update,
        ])
        .setup(move |app| {
            tracing_subscriber::fmt::init();
            tracing::info!("Outline Proxy Windows starting");

            let app_handle = app.handle();
            tray::init_tray(app_handle, app_state_for_setup.clone())?;
            updater::UpdateManager::spawn_scheduler(
                app_handle.clone(),
                app_state_for_setup.clone(),
            );

            let settings = app_state_for_setup.profile_store.settings();
            if !settings.start_minimized
                && let Some(window) = app.get_webview_window("main")
            {
                let _ = window.show();
            }

            if settings.reconnect_after_update {
                let mut updated_settings = settings.clone();
                updated_settings.reconnect_after_update = false;
                let _ = app_state_for_setup.profile_store.update_settings(updated_settings);

                let state_clone = app_state_for_setup.clone();
                let app_handle_clone = app.handle().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    if let Some(profile) = state_clone.profile_store.active_profile() {
                        let current_settings = state_clone.profile_store.settings();
                        let _ = state_clone
                            .process_controller
                            .start(&profile, &current_settings, Some(&app_handle_clone))
                            .await;
                        let _ = tray::update_tray_menu(&app_handle_clone, &state_clone);
                        let _ = app_handle_clone.emit("profiles-updated", ());
                    }
                });
            }

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app_handle, event| {
        if let tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit = event {
            tracing::info!("Application exiting, ensuring proxy and process cleanup");
            let _ = proxy_manager::SystemProxyManager::disable();
            let state = app_handle.state::<AppState>();
            tauri::async_runtime::block_on(async {
                let _ = state.process_controller.stop(None).await;
            });
        }
    });
}
