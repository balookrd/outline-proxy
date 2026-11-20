#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use tauri::Manager;

pub mod commands;
pub mod config_generator;
pub mod process_controller;
pub mod profile_store;
pub mod proxy_manager;
pub mod tray;

#[cfg(test)]
mod tests;

use process_controller::ProcessController;
use profile_store::ProfileStore;

/// Global application state shared across Tauri commands and system tray.
#[derive(Clone)]
pub struct AppState {
    pub profile_store: Arc<ProfileStore>,
    pub process_controller: Arc<ProcessController>,
}

fn main() {
    let profile_store = Arc::new(ProfileStore::load().unwrap_or_else(|e| {
        tracing::warn!("Failed to load existing profiles, initializing empty: {e}");
        ProfileStore::empty(ProfileStore::default_storage_path())
    }));
    let process_controller = Arc::new(ProcessController::new());

    let app_state = AppState {
        profile_store: profile_store.clone(),
        process_controller: process_controller.clone(),
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
            commands::get_logs,
            commands::get_settings,
            commands::update_settings,
            commands::update_subscription,
        ])
        .setup(move |app| {
            tracing_subscriber::fmt::init();
            tracing::info!("Outline Proxy Windows starting");

            let app_handle = app.handle();
            tray::init_tray(app_handle, app_state_for_setup.clone())?;

            let settings = app_state_for_setup.profile_store.settings();
            if !settings.start_minimized
                && let Some(window) = app.get_webview_window("main")
            {
                let _ = window.show();
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
