#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod config_generator;
pub mod profile_store;
pub mod proxy_manager;

#[cfg(test)]
mod tests;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|_app| {
            tracing_subscriber::fmt::init();
            tracing::info!("Outline Proxy Windows starting");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
