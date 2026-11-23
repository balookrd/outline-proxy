use std::sync::Arc;

use anyhow::{Context, Result};
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};

use crate::AppState;
use crate::process_controller::ProcessState;

pub const TRAY_ID: &str = "main-tray";

/// Builds the tray dynamic menu according to current application state.
pub fn build_tray_menu(app: &AppHandle, state: &AppState) -> Result<Menu<Wry>> {
    let menu = Menu::new(app).context("failed to create base tray menu")?;

    let process_state = state.process_controller.state();
    let is_running = matches!(process_state, ProcessState::Running { .. });
    let is_starting = matches!(process_state, ProcessState::Starting);
    let is_stopping = matches!(process_state, ProcessState::Stopping);

    let active_profile = state.profile_store.active_profile();
    let settings = state.profile_store.settings();

    // 1. Status indicator item (disabled / info-only)
    let status_text = match &process_state {
        ProcessState::Running { .. } => {
            let name = active_profile
                .as_ref()
                .map(|p| p.display_name())
                .unwrap_or_else(|| "Connected".to_string());
            format!("● Connected: {name}")
        },
        ProcessState::Starting => "◌ Connecting...".to_string(),
        ProcessState::Stopping => "◌ Disconnecting...".to_string(),
        ProcessState::Error(err) => format!("✕ Error: {err}"),
        ProcessState::Stopped => "○ Disconnected".to_string(),
    };

    let status_item = MenuItem::with_id(app, "status_info", status_text, false, None::<&str>)
        .context("failed to create status menu item")?;
    menu.append(&status_item)?;

    // 2. Connect / Disconnect button
    let connect_title = if is_running || is_starting {
        "Disconnect"
    } else {
        "Connect"
    };
    let connect_enabled = !is_starting && !is_stopping;
    let connect_item =
        MenuItem::with_id(app, "toggle_connect", connect_title, connect_enabled, None::<&str>)?;
    menu.append(&connect_item)?;

    menu.append(&PredefinedMenuItem::separator(app)?)?;

    // 3. Servers submenu
    let servers_submenu = Submenu::with_id(app, "servers_submenu", "Servers", true)?;
    let profiles = state.profile_store.profiles();
    let active_id = state.profile_store.active_profile_id();

    if profiles.is_empty() {
        let no_servers =
            MenuItem::with_id(app, "no_servers", "(No servers configured)", false, None::<&str>)?;
        servers_submenu.append(&no_servers)?;
    } else {
        for profile in &profiles {
            let item_id = format!("select_server:{}", profile.id);
            let is_selected = active_id.as_deref() == Some(&profile.id);
            let item = CheckMenuItem::with_id(
                app,
                item_id,
                profile.display_name(),
                true,
                is_selected,
                None::<&str>,
            )?;
            servers_submenu.append(&item)?;
        }
    }
    menu.append(&servers_submenu)?;

    menu.append(&PredefinedMenuItem::separator(app)?)?;

    // 4. Operating Mode (SOCKS5 / TUN)
    let mode_submenu = Submenu::with_id(app, "mode_submenu", "Proxy Mode", true)?;
    let is_socks = settings.proxy_mode.eq_ignore_ascii_case("socks5");
    let is_tun = settings.proxy_mode.eq_ignore_ascii_case("tun");

    let socks_item = CheckMenuItem::with_id(
        app,
        "mode_socks5",
        "SOCKS5 System Proxy",
        !is_running,
        is_socks,
        None::<&str>,
    )?;
    let tun_item = CheckMenuItem::with_id(
        app,
        "mode_tun",
        "TUN Virtual Device (All Traffic)",
        !is_running,
        is_tun,
        None::<&str>,
    )?;
    mode_submenu.append(&socks_item)?;
    mode_submenu.append(&tun_item)?;
    menu.append(&mode_submenu)?;

    // 5. TCP-only toggle
    let tcp_only_item = CheckMenuItem::with_id(
        app,
        "toggle_tcp_only",
        "TCP Only (H2/H1)",
        !is_running,
        settings.tcp_only,
        None::<&str>,
    )?;
    menu.append(&tcp_only_item)?;

    menu.append(&PredefinedMenuItem::separator(app)?)?;

    // 6. Navigation items
    let show_window_item =
        MenuItem::with_id(app, "show_window", "Show Window", true, None::<&str>)?;
    let settings_item = MenuItem::with_id(app, "open_settings", "Settings", true, None::<&str>)?;
    let logs_item = MenuItem::with_id(app, "open_logs", "Logs", true, None::<&str>)?;

    menu.append(&show_window_item)?;
    menu.append(&settings_item)?;
    menu.append(&logs_item)?;

    let upd = state.update_manager.state();
    let (update_title, update_enabled) = if upd.installing {
        ("Installing update...".to_string(), false)
    } else if upd.checking {
        ("Checking for updates...".to_string(), false)
    } else if let Some(ref info) = upd.available {
        (format!("Install Update {}...", info.label), true)
    } else {
        ("Check for Updates...".to_string(), true)
    };
    let update_item =
        MenuItem::with_id(app, "check_updates", update_title, update_enabled, None::<&str>)?;
    menu.append(&update_item)?;

    menu.append(&PredefinedMenuItem::separator(app)?)?;

    // 7. Quit
    let quit_item = MenuItem::with_id(app, "quit", "Exit", true, None::<&str>)?;
    menu.append(&quit_item)?;

    Ok(menu)
}

/// Updates the tray icon menu dynamically to reflect updated status or profile selection.
pub fn update_tray_menu(app: &AppHandle, state: &AppState) -> Result<()> {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let menu = build_tray_menu(app, state)?;
        tray.set_menu(Some(menu)).context("failed to update tray icon menu")?;
    }
    Ok(())
}

/// Initializes the system tray icon, its context menu, and click handlers.
pub fn init_tray(app: &AppHandle, state: Arc<AppState>) -> Result<()> {
    let menu = build_tray_menu(app, &state)?;

    let state_for_menu = state.clone();

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("Outline Proxy")
        .menu(&menu)
        .on_menu_event(move |app_handle, event| {
            let event_id = event.id().as_ref();
            handle_tray_menu_event(app_handle, &state_for_menu, event_id);
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    if window.is_visible().unwrap_or(false) {
                        let _ = window.hide();
                    } else {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
            }
        });

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    builder.build(app).context("failed to build tray icon")?;

    Ok(())
}

fn handle_tray_menu_event(app: &AppHandle, state: &Arc<AppState>, event_id: &str) {
    match event_id {
        "toggle_connect" => {
            let app_clone = app.clone();
            let state_clone = state.clone();
            tokio::spawn(async move {
                let process_state = state_clone.process_controller.state();
                if matches!(process_state, ProcessState::Running { .. } | ProcessState::Starting) {
                    let _ = state_clone.process_controller.stop(Some(&app_clone)).await;
                } else if let Some(profile) = state_clone.profile_store.active_profile() {
                    let settings = state_clone.profile_store.settings();
                    let _ = state_clone
                        .process_controller
                        .start(&profile, &settings, Some(&app_clone))
                        .await;
                }
                let _ = update_tray_menu(&app_clone, &state_clone);
            });
        },
        "mode_socks5" => {
            let mut settings = state.profile_store.settings();
            settings.proxy_mode = "socks5".to_string();
            let _ = state.profile_store.update_settings(settings);
            let _ = update_tray_menu(app, state);
            let _ = app.emit("settings-updated", ());
        },
        "mode_tun" => {
            let mut settings = state.profile_store.settings();
            settings.proxy_mode = "tun".to_string();
            let _ = state.profile_store.update_settings(settings);
            let _ = update_tray_menu(app, state);
            let _ = app.emit("settings-updated", ());
        },
        "toggle_tcp_only" => {
            let mut settings = state.profile_store.settings();
            settings.tcp_only = !settings.tcp_only;
            let _ = state.profile_store.update_settings(settings);
            let _ = update_tray_menu(app, state);
            let _ = app.emit("settings-updated", ());
        },
        "show_window" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        },
        "open_settings" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
                let _ = app.emit("navigate", "settings");
            }
        },
        "open_logs" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
                let _ = app.emit("navigate", "logs");
            }
        },
        "check_updates" => {
            let current = state.update_manager.state();
            if current.available.is_some() {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                    let _ = app.emit("navigate", "update");
                }
            } else if !current.checking && !current.installing {
                let app_clone = app.clone();
                let state_clone = state.clone();
                tauri::async_runtime::spawn(async move {
                    if let Ok(crate::updater::UpdateCheckResult::Available(_)) = state_clone
                        .update_manager
                        .run_check(true, Some(&app_clone), &state_clone)
                        .await
                        && let Some(window) = app_clone.get_webview_window("main")
                    {
                        let _ = window.show();
                        let _ = window.set_focus();
                        let _ = app_clone.emit("navigate", "update");
                    }
                });
            }
        },
        "quit" => {
            let app_clone = app.clone();
            let state_clone = state.clone();
            tokio::spawn(async move {
                let _ = state_clone.process_controller.stop(Some(&app_clone)).await;
                app_clone.exit(0);
            });
        },
        other if other.starts_with("select_server:") => {
            let profile_id = &other["select_server:".len()..];
            let _ = state.profile_store.select_profile(profile_id);
            let _ = update_tray_menu(app, state);
            let _ = app.emit("profiles-updated", ());
        },
        _ => {},
    }
}
