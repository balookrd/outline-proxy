use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tauri::Emitter;

use crate::config_generator::ConfigGenerator;
use crate::profile_store::{AppSettings, ProfileStore, ServerProfile};
use crate::proxy_manager::SystemProxyManager;

/// Maximum number of log lines retained in memory.
pub const MAX_LOG_LINES: usize = 1000;

/// Process state for the background `outline-ws-rust` child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "camelCase")]
pub enum ProcessState {
    Stopped,
    Starting,
    Running { pid: u32 },
    Stopping,
    Error(String),
}

/// Comprehensive connection status returned to frontend and tray.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionStatusResponse {
    pub state: ProcessState,
    pub active_profile_id: Option<String>,
    pub active_profile_name: Option<String>,
    pub mode: String, // "socks5" | "tun"
    pub tcp_only: bool,
    pub uptime_secs: Option<u64>,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug)]
pub struct SafeHandle(pub windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
unsafe impl Send for SafeHandle {}
#[cfg(windows)]
unsafe impl Sync for SafeHandle {}

/// Representation of an active background process.
enum RunningChild {
    Tokio(tokio::process::Child),
    #[cfg(windows)]
    Win32Handle {
        handle: SafeHandle,
        _pid: u32,
    },
}

/// Locates the `outline-ws-rust` binary across environment variables, adjacent folders,
/// build directories and system PATH.
pub fn find_outline_ws_binary() -> Result<PathBuf> {
    // 1. Explicit override via OUTLINE_WS_BIN env var
    if let Ok(path_str) = std::env::var("OUTLINE_WS_BIN") {
        let path = PathBuf::from(path_str);
        if path.is_file() {
            return Ok(path);
        }
    }

    #[cfg(windows)]
    let bin_name = "outline-ws-rust.exe";
    #[cfg(not(windows))]
    let bin_name = "outline-ws-rust";

    // 2. Adjacent to current executable
    if let Ok(current_exe) = std::env::current_exe()
        && let Some(parent) = current_exe.parent()
    {
        let candidate = parent.join(bin_name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    // 3. Search in workspace target directories (target/debug, target/release)
    let search_roots = [
        PathBuf::from("."),
        PathBuf::from(".."),
        PathBuf::from("../.."),
        PathBuf::from("../../.."),
    ];

    for root in &search_roots {
        let release_candidate = root.join("target").join("release").join(bin_name);
        if release_candidate.is_file() {
            return Ok(release_candidate);
        }
        let debug_candidate = root.join("target").join("debug").join(bin_name);
        if debug_candidate.is_file() {
            return Ok(debug_candidate);
        }
    }

    // 4. Search in PATH
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(bin_name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    bail!(
        "outline-ws-rust binary not found. Set OUTLINE_WS_BIN or place {bin_name} in target directory or PATH"
    );
}

/// Controller managing the background `outline-ws-rust` process, system proxy toggling,
/// and log ring buffer.
pub struct ProcessController {
    state: Arc<RwLock<ProcessState>>,
    logs: Arc<RwLock<VecDeque<String>>>,
    active_config_path: Arc<RwLock<Option<PathBuf>>>,
    child_handle: Arc<tokio::sync::Mutex<Option<RunningChild>>>,
    started_at: Arc<RwLock<Option<Instant>>>,
}

impl Default for ProcessController {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessController {
    /// Creates a new `ProcessController` in `Stopped` state.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(ProcessState::Stopped)),
            logs: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_LOG_LINES))),
            active_config_path: Arc::new(RwLock::new(None)),
            child_handle: Arc::new(tokio::sync::Mutex::new(None)),
            started_at: Arc::new(RwLock::new(None)),
        }
    }

    /// Returns the current state of the process.
    pub fn state(&self) -> ProcessState {
        self.state.read().unwrap().clone()
    }

    /// Returns elapsed uptime seconds if running.
    pub fn uptime_secs(&self) -> Option<u64> {
        let lock = self.started_at.read().unwrap();
        lock.map(|instant| instant.elapsed().as_secs())
    }

    /// Returns snapshot of all logs currently stored in the ring buffer.
    pub fn logs(&self) -> Vec<String> {
        let lock = self.logs.read().unwrap();
        lock.iter().cloned().collect()
    }

    /// Appends a log line to the ring buffer and emits an event to Tauri.
    pub fn push_log(&self, line: String, app_handle: Option<&tauri::AppHandle>) {
        Self::append_log(&self.logs, line, app_handle);
    }

    fn append_log(
        logs: &Arc<RwLock<VecDeque<String>>>,
        line: String,
        app_handle: Option<&tauri::AppHandle>,
    ) {
        {
            let mut lock = logs.write().unwrap();
            if lock.len() >= MAX_LOG_LINES {
                lock.pop_front();
            }
            lock.push_back(line.clone());
        }

        if let Some(app) = app_handle {
            let _ = app.emit("log-message", &line);
        }
    }

    /// Returns a full status response struct.
    pub fn status_response(&self, store: &ProfileStore) -> ConnectionStatusResponse {
        let active_profile = store.active_profile();
        let settings = store.settings();

        ConnectionStatusResponse {
            state: self.state(),
            active_profile_id: active_profile.as_ref().map(|p| p.id.clone()),
            active_profile_name: active_profile.as_ref().map(|p| p.display_name()),
            mode: settings.proxy_mode,
            tcp_only: settings.tcp_only,
            uptime_secs: self.uptime_secs(),
        }
    }

    /// Starts `outline-ws-rust` with the given profile and settings.
    pub async fn start(
        &self,
        profile: &ServerProfile,
        settings: &AppSettings,
        app_handle: Option<&tauri::AppHandle>,
    ) -> Result<()> {
        let current_state = self.state();
        if matches!(current_state, ProcessState::Running { .. } | ProcessState::Starting) {
            bail!("Process is already starting or running");
        }

        {
            let mut state_lock = self.state.write().unwrap();
            *state_lock = ProcessState::Starting;
        }
        self.emit_status_change(app_handle);

        let tun_enabled = settings.proxy_mode.eq_ignore_ascii_case("tun");
        let toml_content =
            ConfigGenerator::generate(profile, settings.tcp_only, settings.socks_port, tun_enabled);

        let binary_path = match find_outline_ws_binary() {
            Ok(p) => p,
            Err(e) => {
                let err_msg = format!("Failed to locate outline-ws binary: {e}");
                self.set_error(&err_msg, app_handle);
                bail!(err_msg);
            },
        };

        // Write configuration to temporary file
        let temp_filename = format!("outline_ws_{:016x}.toml", rand::random::<u64>());
        let temp_path = std::env::temp_dir().join(temp_filename);
        if let Err(e) = std::fs::write(&temp_path, &toml_content) {
            let err_msg = format!("Failed to write temporary config: {e}");
            self.set_error(&err_msg, app_handle);
            bail!(err_msg);
        }

        {
            let mut cfg_lock = self.active_config_path.write().unwrap();
            *cfg_lock = Some(temp_path.clone());
        }

        self.push_log(
            format!(
                "Starting outline-ws-rust (mode: {}, binary: {})",
                if tun_enabled { "TUN" } else { "SOCKS5" },
                binary_path.display()
            ),
            app_handle,
        );

        // Spawn process
        let spawn_result = self
            .spawn_process(&binary_path, &temp_path, tun_enabled, app_handle)
            .await;

        match spawn_result {
            Ok((child, pid)) => {
                {
                    let mut lock = self.child_handle.lock().await;
                    *lock = Some(child);
                }
                {
                    let mut state_lock = self.state.write().unwrap();
                    *state_lock = ProcessState::Running { pid };
                }
                {
                    let mut start_lock = self.started_at.write().unwrap();
                    *start_lock = Some(Instant::now());
                }

                // If SOCKS5 mode, enable system proxy
                if !tun_enabled {
                    if let Err(e) =
                        SystemProxyManager::enable_socks5("127.0.0.1", settings.socks_port)
                    {
                        tracing::warn!("Failed to enable system SOCKS5 proxy: {e}");
                        self.push_log(
                            format!("Warning: failed to enable system proxy: {e}"),
                            app_handle,
                        );
                    } else {
                        self.push_log(
                            format!(
                                "System SOCKS5 proxy enabled on 127.0.0.1:{}",
                                settings.socks_port
                            ),
                            app_handle,
                        );
                    }
                }

                self.push_log(
                    format!("outline-ws-rust started successfully (PID {pid})"),
                    app_handle,
                );
                self.emit_status_change(app_handle);
                Ok(())
            },
            Err(e) => {
                let err_msg = format!("Failed to spawn process: {e}");
                self.set_error(&err_msg, app_handle);
                self.cleanup_temp_config();
                bail!(err_msg);
            },
        }
    }

    async fn spawn_process(
        &self,
        binary_path: &Path,
        config_path: &Path,
        _tun_enabled: bool,
        app_handle: Option<&tauri::AppHandle>,
    ) -> Result<(RunningChild, u32)> {
        #[cfg(windows)]
        {
            if _tun_enabled {
                // On Windows TUN requires administrative elevation (UAC prompt via runas)
                match unsafe { spawn_with_uac(binary_path, config_path) } {
                    Ok((handle, pid)) => {
                        return Ok((
                            RunningChild::Win32Handle { handle: SafeHandle(handle), _pid: pid },
                            pid,
                        ));
                    },
                    Err(e) => {
                        tracing::warn!(
                            "UAC spawn failed ({e}), falling back to standard command spawn"
                        );
                    },
                }
            }
        }

        // Standard Tokio async command spawn
        let mut cmd = tokio::process::Command::new(binary_path);
        cmd.arg("--config").arg(config_path);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to execute binary at {}", binary_path.display()))?;

        let pid = child.id().unwrap_or(0);

        // Pipe stdout
        if let Some(stdout) = child.stdout.take() {
            let logs = self.logs.clone();
            let app = app_handle.cloned();
            tokio::spawn(async move {
                use tokio::io::AsyncBufReadExt;
                let reader = tokio::io::BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    Self::append_log(&logs, line, app.as_ref());
                }
            });
        }

        // Pipe stderr
        if let Some(stderr) = child.stderr.take() {
            let logs = self.logs.clone();
            let app = app_handle.cloned();
            tokio::spawn(async move {
                use tokio::io::AsyncBufReadExt;
                let reader = tokio::io::BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    Self::append_log(&logs, line, app.as_ref());
                }
            });
        }

        Ok((RunningChild::Tokio(child), pid))
    }

    /// Stops the running background process, resets system proxy, and deletes temp files.
    pub async fn stop(&self, app_handle: Option<&tauri::AppHandle>) -> Result<()> {
        let current_state = self.state();
        if current_state == ProcessState::Stopped {
            return Ok(());
        }

        {
            let mut state_lock = self.state.write().unwrap();
            *state_lock = ProcessState::Stopping;
        }
        self.emit_status_change(app_handle);
        self.push_log("Stopping outline-ws-rust...".to_string(), app_handle);

        // Terminate child
        {
            let mut child_lock = self.child_handle.lock().await;
            if let Some(child) = child_lock.take() {
                match child {
                    RunningChild::Tokio(mut tokio_child) => {
                        let _ = tokio_child.kill().await;
                        let _ = tokio_child.wait().await;
                    },
                    #[cfg(windows)]
                    RunningChild::Win32Handle { handle, .. } => unsafe {
                        kill_win32_process(handle);
                    },
                }
            }
        }

        // Disable system proxy
        if let Err(e) = SystemProxyManager::disable() {
            tracing::warn!("Failed to disable system proxy upon stop: {e}");
        }

        // Remove temporary config
        self.cleanup_temp_config();

        {
            let mut start_lock = self.started_at.write().unwrap();
            *start_lock = None;
        }
        {
            let mut state_lock = self.state.write().unwrap();
            *state_lock = ProcessState::Stopped;
        }

        self.push_log("outline-ws-rust stopped".to_string(), app_handle);
        self.emit_status_change(app_handle);
        Ok(())
    }

    fn cleanup_temp_config(&self) {
        let mut cfg_lock = self.active_config_path.write().unwrap();
        if let Some(path) = cfg_lock.take() {
            let _ = std::fs::remove_file(path);
        }
    }

    fn set_error(&self, message: &str, app_handle: Option<&tauri::AppHandle>) {
        {
            let mut state_lock = self.state.write().unwrap();
            *state_lock = ProcessState::Error(message.to_string());
        }
        self.push_log(format!("Error: {message}"), app_handle);
        self.emit_status_change(app_handle);
    }

    fn emit_status_change(&self, app_handle: Option<&tauri::AppHandle>) {
        if let Some(app) = app_handle {
            let state = self.state();
            let _ = app.emit("status-changed", &state);
        }
    }
}

#[cfg(windows)]
unsafe fn spawn_with_uac(
    binary_path: &Path,
    config_path: &Path,
) -> Result<(windows_sys::Win32::Foundation::HANDLE, u32)> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Threading::GetProcessId;
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let verb: Vec<u16> = std::ffi::OsStr::new("runas")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let file: Vec<u16> = binary_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let params_str = format!("--config \"{}\"", config_path.display());
    let params: Vec<u16> = std::ffi::OsStr::new(&params_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut sei: SHELLEXECUTEINFOW = std::mem::zeroed();
    sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = verb.as_ptr();
    sei.lpFile = file.as_ptr();
    sei.lpParameters = params.as_ptr();
    sei.nShow = SW_HIDE;

    if unsafe { ShellExecuteExW(&mut sei) } == 0 {
        bail!(
            "ShellExecuteExW (runas) failed with OS error: {}",
            std::io::Error::last_os_error()
        );
    }

    let handle = sei.hProcess;
    if handle.is_null() {
        bail!("ShellExecuteExW succeeded but returned null process handle");
    }

    let pid = unsafe { GetProcessId(handle) };
    Ok((handle, pid))
}

#[cfg(windows)]
unsafe fn kill_win32_process(handle: SafeHandle) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::TerminateProcess;

    unsafe {
        TerminateProcess(handle.0, 1);
        CloseHandle(handle.0);
    }
}
