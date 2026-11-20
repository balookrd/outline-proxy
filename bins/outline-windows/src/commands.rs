use tauri::{AppHandle, Emitter, State};

use crate::AppState;
use crate::process_controller::ConnectionStatusResponse;
use crate::profile_store::{AppSettings, ServerProfile, SubscriptionFetcher};

/// Returns the current connection status and active profile info.
#[tauri::command]
pub async fn get_status(state: State<'_, AppState>) -> Result<ConnectionStatusResponse, String> {
    Ok(state.process_controller.status_response(&state.profile_store))
}

/// Connects to a proxy profile. If `profile_id` is supplied, it is selected first.
#[tauri::command]
pub async fn connect(
    profile_id: Option<String>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    if let Some(id) = profile_id {
        state.profile_store.select_profile(&id).map_err(|e| e.to_string())?;
    }

    let profile = state
        .profile_store
        .active_profile()
        .ok_or_else(|| "No profile available to connect".to_string())?;
    let settings = state.profile_store.settings();

    state
        .process_controller
        .start(&profile, &settings, Some(&app))
        .await
        .map_err(|e| e.to_string())?;

    let _ = crate::tray::update_tray_menu(&app, &state);
    let _ = app.emit("profiles-updated", ());
    Ok(())
}

/// Disconnects the active proxy process and disables system proxy.
#[tauri::command]
pub async fn disconnect(state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    state
        .process_controller
        .stop(Some(&app))
        .await
        .map_err(|e| e.to_string())?;

    let _ = crate::tray::update_tray_menu(&app, &state);
    Ok(())
}

/// Returns the list of all configured server profiles.
#[tauri::command]
pub async fn get_profiles(state: State<'_, AppState>) -> Result<Vec<ServerProfile>, String> {
    Ok(state.profile_store.profiles())
}

/// Parses and adds a new server profile from a link or subscription URL.
#[tauri::command]
pub async fn add_profile(
    link: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<ServerProfile, String> {
    let mut profile = ServerProfile::from_link(&link).map_err(|e| e.to_string())?;

    if profile.is_subscription() {
        match SubscriptionFetcher::fetch_subscription_content(&profile.config_url).await {
            Ok(content) => {
                profile.cached_toml = content;
            },
            Err(e) => {
                tracing::warn!("Failed to fetch initial subscription content: {e}");
            },
        }
    }

    state
        .profile_store
        .add_profile(profile.clone())
        .map_err(|e| e.to_string())?;

    let _ = crate::tray::update_tray_menu(&app, &state);
    let _ = app.emit("profiles-updated", ());
    Ok(profile)
}

/// Removes a server profile by its ID.
#[tauri::command]
pub async fn remove_profile(
    id: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    state.profile_store.remove_profile(&id).map_err(|e| e.to_string())?;

    let _ = crate::tray::update_tray_menu(&app, &state);
    let _ = app.emit("profiles-updated", ());
    Ok(())
}

/// Selects the active server profile by ID.
#[tauri::command]
pub async fn select_profile(
    id: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    state.profile_store.select_profile(&id).map_err(|e| e.to_string())?;

    let _ = crate::tray::update_tray_menu(&app, &state);
    let _ = app.emit("profiles-updated", ());
    Ok(())
}

/// Returns all log entries from the ring buffer.
#[tauri::command]
pub async fn get_logs(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    Ok(state.process_controller.logs())
}

/// Returns the current application settings.
#[tauri::command]
pub async fn get_settings(state: State<'_, AppState>) -> Result<AppSettings, String> {
    Ok(state.profile_store.settings())
}

/// Updates application settings and refreshes tray menu.
#[tauri::command]
pub async fn update_settings(
    settings: AppSettings,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    state
        .profile_store
        .update_settings(settings)
        .map_err(|e| e.to_string())?;

    let _ = crate::tray::update_tray_menu(&app, &state);
    let _ = app.emit("settings-updated", ());
    Ok(())
}

/// Fetches remote content for a subscription profile and updates cached configuration.
#[tauri::command]
pub async fn update_subscription(
    profile_id: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<usize, String> {
    let profile = SubscriptionFetcher::update_subscription(&state.profile_store, &profile_id)
        .await
        .map_err(|e| e.to_string())?;

    let _ = crate::tray::update_tray_menu(&app, &state);
    let _ = app.emit("profiles-updated", ());
    Ok(profile.cached_toml.len())
}
