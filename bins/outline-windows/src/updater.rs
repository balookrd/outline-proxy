use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tauri::Emitter;

pub const STARTUP_CHECK_DELAY_SECS: u64 = 5;
pub const WEEKLY_CHECK_INTERVAL_SECS: u64 = 7 * 24 * 60 * 60;
pub const SCHEDULER_POLL_INTERVAL_SECS: u64 = 60 * 60;

/// Returns the current Unix timestamp in whole seconds.
pub fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Returns true if a periodic weekly check should run now.
///
/// Treats missing/zero timestamps and system clock rollbacks (`now_secs < last`) as due.
pub fn is_periodic_check_due(
    last_check_secs: Option<u64>,
    now_secs: u64,
    interval_secs: u64,
) -> bool {
    match last_check_secs {
        None | Some(0) => true,
        Some(last) if now_secs < last => true,
        Some(last) => now_secs - last >= interval_secs,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateState {
    pub checking: bool,
    pub installing: bool,
    pub available: Option<UpdateInfo>,
    pub status: Option<String>,
}

/// Shared coordinator for startup, weekly periodic, and manual update checks.
pub struct UpdateManager {
    state: std::sync::RwLock<UpdateState>,
}

impl Default for UpdateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl UpdateManager {
    pub fn new() -> Self {
        Self {
            state: std::sync::RwLock::new(UpdateState::default()),
        }
    }

    pub fn state(&self) -> UpdateState {
        self.state.read().unwrap().clone()
    }

    pub fn begin_check(&self, interactive: bool) -> bool {
        let mut lock = self.state.write().unwrap();
        if lock.checking || lock.installing {
            return false;
        }
        lock.checking = true;
        if interactive {
            lock.status = Some("проверка обновлений…".to_string());
        }
        true
    }

    pub fn finish_check(
        &self,
        result: &Result<UpdateCheckResult, String>,
        interactive: bool,
    ) -> UpdateState {
        let mut lock = self.state.write().unwrap();
        lock.checking = false;
        match result {
            Ok(UpdateCheckResult::Available(info)) => {
                lock.available = Some(info.clone());
                lock.status = Some(if interactive {
                    format!("доступно {}", info.label)
                } else {
                    format!("доступно {} — нажмите", info.label)
                });
            },
            Ok(UpdateCheckResult::UpToDate) => {
                lock.available = None;
                lock.status = if interactive {
                    Some("актуальная версия".to_string())
                } else {
                    None
                };
            },
            Err(_) => {
                if interactive {
                    lock.status = Some("ошибка проверки".to_string());
                }
            },
        }
        lock.clone()
    }

    pub fn begin_install(&self) -> bool {
        let mut lock = self.state.write().unwrap();
        if lock.installing {
            return false;
        }
        lock.installing = true;
        lock.checking = false;
        true
    }

    pub fn finish_install_failed(&self) -> UpdateState {
        let mut lock = self.state.write().unwrap();
        lock.installing = false;
        lock.clone()
    }

    pub async fn run_check(
        &self,
        interactive: bool,
        app: Option<&tauri::AppHandle>,
        state: &crate::AppState,
    ) -> Result<UpdateCheckResult, String> {
        if !interactive && let Some(info) = self.state().available {
            return Ok(UpdateCheckResult::Available(info));
        }

        if !self.begin_check(interactive) {
            return Err("Update check is already in progress".to_string());
        }

        if interactive && let Some(app_handle) = app {
            let _ = crate::tray::update_tray_menu(app_handle, state);
            let _ = app_handle.emit("update-state-changed", self.state());
        }

        let ver = crate::version::AppVersion::current();
        let res = UpdateChecker::check(&ver.channel, &ver.commit, &ver.version).await;
        if res.is_ok()
            && let Err(e) = state.profile_store.set_last_update_check(current_unix_secs())
        {
            tracing::warn!("Failed to persist last_update_check: {e}");
        }

        let new_state = self.finish_check(&res, interactive);
        if let Some(app_handle) = app {
            let _ = crate::tray::update_tray_menu(app_handle, state);
            let _ = app_handle.emit("update-state-changed", new_state);
        }
        res
    }

    /// Spawns the startup silent check (after 5s) and an hourly poll that triggers
    /// a quiet background check whenever 7 days have passed since the last success.
    pub fn spawn_scheduler(app: tauri::AppHandle, state: std::sync::Arc<crate::AppState>) {
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(STARTUP_CHECK_DELAY_SECS)).await;

            let initial = state.update_manager.state();
            if !initial.checking
                && !initial.installing
                && initial.available.is_none()
                && let Err(e) = state.update_manager.run_check(false, Some(&app), &state).await
            {
                tracing::warn!("Startup update check failed: {e}");
            }

            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(SCHEDULER_POLL_INTERVAL_SECS));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await;

            loop {
                ticker.tick().await;
                let st = state.update_manager.state();
                if st.checking || st.installing || st.available.is_some() {
                    continue;
                }
                if is_periodic_check_due(
                    state.profile_store.last_update_check(),
                    current_unix_secs(),
                    WEEKLY_CHECK_INTERVAL_SECS,
                ) && let Err(e) = state.update_manager.run_check(false, Some(&app), &state).await
                {
                    tracing::warn!("Periodic weekly update check failed: {e}");
                }
            }
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub label: String,
    #[serde(alias = "asset_name")]
    pub asset_name: String,
    #[serde(alias = "download_url")]
    pub download_url: String,
    #[serde(alias = "checksums_url")]
    pub checksums_url: Option<String>,
    pub notes: String,
    pub commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "update", rename_all = "camelCase")]
pub enum UpdateCheckResult {
    UpToDate,
    Available(UpdateInfo),
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    target_commitish: Option<String>,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Clone, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

pub struct UpdateChecker;

impl UpdateChecker {
    pub async fn check(
        channel: &str,
        current_commit: &str,
        current_version: &str,
    ) -> Result<UpdateCheckResult, String> {
        let client = reqwest::Client::builder()
            .user_agent(format!("OutlineProxy-Windows/{current_version}"))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

        if channel.eq_ignore_ascii_case("release") {
            Self::check_release(&client, current_version).await
        } else {
            Self::check_nightly(&client, current_commit).await
        }
    }

    async fn check_nightly(
        client: &reqwest::Client,
        current_commit: &str,
    ) -> Result<UpdateCheckResult, String> {
        let url =
            "https://api.github.com/repos/balookrd/outline-proxy/releases/tags/windows-nightly";
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch nightly release info: {e}"))?;

        if resp.status().as_u16() == 404 {
            return Err("Nightly release tag windows-nightly not found".into());
        }
        if !resp.status().is_success() {
            return Err(format!("GitHub API error: HTTP {}", resp.status()));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("Failed to read nightly release body: {e}"))?;
        let release: GithubRelease = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Failed to parse GitHub release JSON: {e}"))?;

        let checksums_url = release
            .assets
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case("SHA256SUMS.txt"))
            .map(|a| a.browser_download_url.clone());

        for asset in &release.assets {
            if let Some(sha) = parse_nightly_asset(&asset.name) {
                if crate::version::AppVersion::same_commit(&sha, current_commit) {
                    return Ok(UpdateCheckResult::UpToDate);
                } else {
                    let short_sha = if sha.len() >= 8 { &sha[..8] } else { &sha };
                    return Ok(UpdateCheckResult::Available(UpdateInfo {
                        label: format!("nightly ({short_sha})"),
                        asset_name: asset.name.clone(),
                        download_url: asset.browser_download_url.clone(),
                        checksums_url,
                        notes: release.body.unwrap_or_default(),
                        commit: sha,
                    }));
                }
            }
        }

        Err("No Windows x86_64 zip asset found in windows-nightly release".into())
    }

    async fn check_release(
        client: &reqwest::Client,
        current_version: &str,
    ) -> Result<UpdateCheckResult, String> {
        let url = "https://api.github.com/repos/balookrd/outline-proxy/releases/latest";
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch latest release: {e}"))?;

        if resp.status().as_u16() == 404 {
            return Err("No published release found at /releases/latest".into());
        }
        if !resp.status().is_success() {
            return Err(format!("GitHub API error: HTTP {}", resp.status()));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("Failed to read latest release body: {e}"))?;
        let release: GithubRelease = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Failed to parse GitHub release JSON: {e}"))?;

        Self::evaluate_release(release, current_version)
    }

    fn evaluate_release(
        release: GithubRelease,
        current_version: &str,
    ) -> Result<UpdateCheckResult, String> {
        let tag = release.tag_name.trim();
        let is_release_tag = tag
            .strip_prefix('v')
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()));
        if release.draft || !is_release_tag {
            return Err(format!("Unexpected latest release tag: {}", release.tag_name));
        }

        let (major, minor, patch) = parse_semver(tag)
            .ok_or_else(|| format!("Invalid release tag version: {}", release.tag_name))?;
        let candidate_ver = format!("{major}.{minor}.{patch}");

        if !is_newer_version(&candidate_ver, current_version) {
            return Ok(UpdateCheckResult::UpToDate);
        }

        let asset = release
            .assets
            .iter()
            .find(|a| {
                a.name.starts_with("OutlineProxy-")
                    && a.name.ends_with("-Windows-x86_64.zip")
                    && !a.name.contains("nightly")
            })
            .cloned()
            .ok_or_else(|| {
                format!("No Windows x86_64 zip asset found in release {}", release.tag_name)
            })?;

        let checksums_url = release
            .assets
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case("SHA256SUMS.txt"))
            .map(|a| a.browser_download_url.clone());

        Ok(UpdateCheckResult::Available(UpdateInfo {
            label: format!("v{candidate_ver}"),
            asset_name: asset.name,
            download_url: asset.browser_download_url,
            checksums_url,
            notes: release.body.unwrap_or_default(),
            commit: release.target_commitish.unwrap_or_default(),
        }))
    }
}

pub struct UpdateInstaller;

impl UpdateInstaller {
    pub async fn download_and_verify<F>(
        update: &UpdateInfo,
        on_progress: F,
    ) -> Result<PathBuf, String>
    where
        F: Fn(u64, u64) + Send + 'static,
    {
        let client = reqwest::Client::builder()
            .user_agent("OutlineProxy-Windows-Updater")
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

        // Fetch and parse SHA256SUMS.txt - mandatory security check
        let checksums_url = update.checksums_url.as_deref().ok_or_else(|| {
            "В релизе отсутствует SHA256SUMS.txt — установка непроверенной сборки заблокирована"
                .to_string()
        })?;

        let resp = client
            .get(checksums_url)
            .send()
            .await
            .map_err(|e| format!("Не удалось скачать SHA256SUMS.txt: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("Ошибка загрузки SHA256SUMS.txt (HTTP {})", resp.status()));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| format!("Не удалось прочитать SHA256SUMS.txt: {e}"))?;
        let expected_sha256 = parse_checksums(&text, &update.asset_name).ok_or_else(|| {
            format!("В SHA256SUMS.txt не найдена контрольная сумма для {}", update.asset_name)
        })?;

        let mut resp = client
            .get(&update.download_url)
            .send()
            .await
            .map_err(|e| format!("Failed to download update: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("Failed to download update: HTTP {}", resp.status()));
        }

        let total_bytes = resp.content_length().unwrap_or(0);
        let tmp_path = std::env::temp_dir().join(format!(
            "outline-update-{}-{}.zip",
            std::process::id(),
            rand::random::<u32>()
        ));

        let file = std::fs::File::create(&tmp_path)
            .map_err(|e| format!("Failed to create temporary file {}: {e}", tmp_path.display()))?;
        let mut writer = std::io::BufWriter::new(file);

        let mut context = ring::digest::Context::new(&ring::digest::SHA256);
        let mut downloaded_bytes = 0u64;

        use std::io::Write;
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    context.update(&chunk);
                    if let Err(e) = writer.write_all(&chunk) {
                        let _ = std::fs::remove_file(&tmp_path);
                        return Err(format!("Failed to write to file: {e}"));
                    }
                    downloaded_bytes += chunk.len() as u64;
                    on_progress(downloaded_bytes, total_bytes);
                },
                Ok(None) => break,
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(format!("Download stream error: {e}"));
                },
            }
        }

        if let Err(e) = writer.flush() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!("Failed to flush downloaded file: {e}"));
        }
        drop(writer);

        let digest = context.finish();
        let calculated_hash = to_hex(digest.as_ref());

        if !calculated_hash.eq_ignore_ascii_case(&expected_sha256) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!(
                "Контрольная сумма SHA-256 не совпала для {}: ожидалось {}, получено {}",
                update.asset_name, expected_sha256, calculated_hash
            ));
        }

        Ok(tmp_path)
    }

    pub fn stage_update(zip_path: &Path, staging_dir: &Path) -> Result<(), String> {
        if staging_dir.exists() {
            std::fs::remove_dir_all(staging_dir).map_err(|e| {
                format!("Failed to clear staging dir {}: {e}", staging_dir.display())
            })?;
        }
        std::fs::create_dir_all(staging_dir)
            .map_err(|e| format!("Failed to create staging dir {}: {e}", staging_dir.display()))?;

        let file = std::fs::File::open(zip_path)
            .map_err(|e| format!("Failed to open zip archive {}: {e}", zip_path.display()))?;
        let mut archive =
            zip::ZipArchive::new(file).map_err(|e| format!("Invalid zip archive: {e}"))?;

        for i in 0..archive.len() {
            let mut zip_file = archive
                .by_index(i)
                .map_err(|e| format!("Failed to read zip entry #{i}: {e}"))?;

            // ZIP-SLIP PROTECTION: enclosed_name ensures the path is relative and doesn't escape root
            let enclosed_name = zip_file.enclosed_name().ok_or_else(|| {
                format!(
                    "Zip slip path traversal detected: {}",
                    zip_file.name().ok().as_deref().unwrap_or("unknown")
                )
            })?;

            let dest_path = staging_dir.join(enclosed_name);

            if zip_file.is_dir() {
                std::fs::create_dir_all(&dest_path).map_err(|e| {
                    format!("Failed to create directory {}: {e}", dest_path.display())
                })?;
            } else {
                if let Some(parent) = dest_path.parent()
                    && !parent.exists()
                {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        format!("Failed to create parent dir {}: {e}", parent.display())
                    })?;
                }

                let mut out_file = std::fs::File::create(&dest_path).map_err(|e| {
                    format!("Failed to create destination file {}: {e}", dest_path.display())
                })?;
                std::io::copy(&mut zip_file, &mut out_file)
                    .map_err(|e| format!("Failed to extract file {}: {e}", dest_path.display()))?;

                #[cfg(unix)]
                if let Some(mode) = zip_file.unix_mode() {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(&dest_path, std::fs::Permissions::from_mode(mode));
                }
            }
        }

        Ok(())
    }

    /// Builds the self-deleting Windows `.cmd` script that waits for the
    /// current process to exit, copies the staged update into the target
    /// directory, removes any legacy `outline-ws-rust.exe`, and relaunches.
    pub fn build_update_script(
        staging_dir: &Path,
        target_exe: &Path,
        current_pid: u32,
    ) -> Result<String, String> {
        let target_dir = target_exe
            .parent()
            .ok_or_else(|| "Target executable has no parent directory".to_string())?;

        let staging_str = staging_dir.to_str().ok_or("Staging dir has non-UTF8 path")?;
        let target_dir_str = target_dir.to_str().ok_or("Target dir has non-UTF8 path")?;
        if target_dir_str.is_empty() {
            return Err("Target executable has no parent directory".to_string());
        }
        let target_exe_str = target_exe.to_str().ok_or("Target exe has non-UTF8 path")?;

        Ok(format!(
            "@echo off\r\n\
            setlocal DisableDelayedExpansion\r\n\
            set TARGET_PID={current_pid}\r\n\
            set STAGING_DIR={staging_str}\r\n\
            set TARGET_DIR={target_dir_str}\r\n\
            set TARGET_EXE={target_exe_str}\r\n\
            \r\n\
            :wait_loop\r\n\
            tasklist /FI \"PID eq %TARGET_PID%\" 2>NUL | find /I \"%TARGET_PID%\" >NUL\r\n\
            if not errorlevel 1 (\r\n\
                timeout /t 1 /nobreak >NUL\r\n\
                goto wait_loop\r\n\
            )\r\n\
            \r\n\
            timeout /t 1 /nobreak >NUL\r\n\
            \r\n\
            xcopy /Y /Q /E \"%STAGING_DIR%\\*\" \"%TARGET_DIR%\\\" >NUL\r\n\
            if errorlevel 1 (\r\n\
                copy /Y \"%STAGING_DIR%\\*.*\" \"%TARGET_DIR%\\\" >NUL\r\n\
            )\r\n\
            \r\n\
            if exist \"%TARGET_DIR%\\outline-ws-rust.exe\" del /F /Q \"%TARGET_DIR%\\outline-ws-rust.exe\" >NUL 2>&1\r\n\
            \r\n\
            start \"\" \"%TARGET_EXE%\"\r\n\
            \r\n\
            rmdir /S /Q \"%STAGING_DIR%\" >NUL 2>&1\r\n\
            (goto) 2>nul & del \"%~f0\"\r\n"
        ))
    }

    pub fn launch_updater(
        staging_dir: &Path,
        target_exe: &Path,
        current_pid: u32,
    ) -> Result<(), String> {
        let script_content = Self::build_update_script(staging_dir, target_exe, current_pid)?;

        let script_path = std::env::temp_dir().join(format!("outline_update_{current_pid}.cmd"));
        std::fs::write(&script_path, script_content)
            .map_err(|e| format!("Failed to write update script {}: {e}", script_path.display()))?;

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            const DETACHED_PROCESS: u32 = 0x00000008;

            let script_str = script_path
                .to_str()
                .ok_or("Script path contains non-UTF8 characters")?;

            let mut cmd = std::process::Command::new("cmd.exe");
            cmd.args(["/c", "start", "/min", "cmd.exe", "/c", script_str]);
            cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
            cmd.spawn()
                .map_err(|e| format!("Failed to spawn updater script: {e}"))?;
        }

        #[cfg(not(windows))]
        {
            tracing::info!(
                "launch_updater simulated on non-windows: script={}",
                script_path.display()
            );
        }

        Ok(())
    }
}

pub fn parse_checksums(content: &str, target_asset: &str) -> Option<String> {
    let target_name = Path::new(target_asset)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(target_asset);

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }

        let rest = line[hash.len()..].trim();
        let filename = rest.strip_prefix('*').unwrap_or(rest).trim();
        let file_basename = Path::new(filename)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(filename);

        if file_basename.eq_ignore_ascii_case(target_name) {
            return Some(hash.to_ascii_lowercase());
        }
    }
    None
}

pub fn parse_nightly_asset(asset_name: &str) -> Option<String> {
    let s = asset_name.strip_prefix("OutlineProxy-nightly-")?;
    let s = s.strip_suffix("-Windows-x86_64.zip")?;
    if s.is_empty() {
        return None;
    }
    Some(s.to_string())
}

pub fn parse_semver(v: &str) -> Option<(u32, u32, u32)> {
    let clean = v.trim().strip_prefix("windows-").unwrap_or(v.trim());
    let clean = clean.strip_prefix('v').unwrap_or(clean);
    let main_part = clean.split(['-', '+']).next()?;
    let mut parts = main_part.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    let patch: u32 = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

pub fn is_newer_version(candidate: &str, current: &str) -> bool {
    match (parse_semver(candidate), parse_semver(current)) {
        (Some(c), Some(cur)) => c > cur,
        _ => false,
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    #[test]
    fn test_parse_checksums_txt_with_asterisk_and_space() {
        let content = "\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  OutlineProxy-nightly-971282b6-Windows-x86_64.zip\n\
ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb *OutlineProxy-v1.9.2-Windows-x86_64.zip\n\
";
        let c1 = parse_checksums(content, "OutlineProxy-nightly-971282b6-Windows-x86_64.zip");
        assert_eq!(
            c1.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );

        let c2 = parse_checksums(content, "OutlineProxy-v1.9.2-Windows-x86_64.zip");
        assert_eq!(
            c2.as_deref(),
            Some("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb")
        );

        let c3 = parse_checksums(content, "non-existent-file.zip");
        assert_eq!(c3, None);
    }

    #[test]
    fn test_evaluate_nightly_release_asset_name() {
        let valid = "OutlineProxy-nightly-971282b6-Windows-x86_64.zip";
        assert_eq!(parse_nightly_asset(valid).as_deref(), Some("971282b6"));

        let valid_dirty = "OutlineProxy-nightly-971282b6-dirty-Windows-x86_64.zip";
        assert_eq!(parse_nightly_asset(valid_dirty).as_deref(), Some("971282b6-dirty"));

        let invalid1 = "OutlineProxy-v1.9.2-Windows-x86_64.zip";
        assert_eq!(parse_nightly_asset(invalid1), None);

        let invalid2 = "OutlineProxy-nightly-971282b6-Linux-x86_64.tar.gz";
        assert_eq!(parse_nightly_asset(invalid2), None);
    }

    #[test]
    fn test_zip_slip_protection() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let zip_path = temp_dir.path().join("malicious.zip");
        let staging_dir = temp_dir.path().join("staging");

        // Create a zip with zip-slip entry: "../../evil.txt"
        {
            let file = std::fs::File::create(&zip_path).expect("create zip");
            let mut zip = zip::ZipWriter::new(file);
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            zip.start_file("../../evil.txt", options).expect("start file");
            zip.write_all(b"malicious content").expect("write evil file");
            zip.finish().expect("finish zip");
        }

        let result = UpdateInstaller::stage_update(&zip_path, &staging_dir);
        assert!(result.is_err(), "Stage update must reject zip slip paths");
        let err = result.unwrap_err();
        assert!(
            err.to_lowercase().contains("slip")
                || err.to_lowercase().contains("invalid")
                || err.to_lowercase().contains("traversal"),
            "Error should indicate path traversal / zip slip: {err}"
        );

        // Verify that evil.txt was NOT written outside staging dir
        let evil_target = temp_dir.path().join("evil.txt");
        assert!(!evil_target.exists(), "Evil file must not exist");
    }

    #[test]
    fn test_stage_update_valid_zip() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let zip_path = temp_dir.path().join("good.zip");
        let staging_dir = temp_dir.path().join("staging");

        {
            let file = std::fs::File::create(&zip_path).expect("create zip");
            let mut zip = zip::ZipWriter::new(file);
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            zip.start_file("OutlineProxy.exe", options).expect("start file");
            zip.write_all(b"binary content").expect("write file");

            zip.add_directory("subfolder/", options).expect("add dir");
            zip.start_file("subfolder/config.json", options)
                .expect("start nested file");
            zip.write_all(b"{}").expect("write nested file");
            zip.finish().expect("finish zip");
        }

        let res = UpdateInstaller::stage_update(&zip_path, &staging_dir);
        assert!(res.is_ok(), "Expected valid unpack: {:?}", res);
        assert!(staging_dir.join("OutlineProxy.exe").exists());
        assert!(staging_dir.join("subfolder/config.json").exists());
    }

    #[test]
    fn test_semver_and_version_comparison() {
        assert_eq!(parse_semver("1.9.2"), Some((1, 9, 2)));
        assert_eq!(parse_semver("v1.9.2"), Some((1, 9, 2)));
        assert_eq!(parse_semver("v26.11.0"), Some((26, 11, 0)));
        assert_eq!(parse_semver("26.11.0"), Some((26, 11, 0)));
        assert_eq!(parse_semver("windows-v1.10.0"), Some((1, 10, 0)));
        assert_eq!(parse_semver("windows-1.10.0-rc1"), Some((1, 10, 0)));

        assert!(is_newer_version("1.9.3", "1.9.2"));
        assert!(is_newer_version("1.10.0", "1.9.9"));
        assert!(is_newer_version("2.0.0", "1.99.99"));
        assert!(is_newer_version("26.11.0", "1.9.2"));
        assert!(is_newer_version("26.12.0", "26.11.5"));
        assert!(is_newer_version("27.1.0", "26.12.9"));
        assert!(!is_newer_version("26.11.0", "26.11.0"));
        assert!(!is_newer_version("1.9.2", "1.9.2"));
        assert!(!is_newer_version("1.9.1", "1.9.2"));
    }

    #[test]
    fn test_evaluate_release_calver() {
        let release = GithubRelease {
            tag_name: "v26.11.0".to_string(),
            draft: false,
            body: Some("Unified release".to_string()),
            target_commitish: Some("abcdef12".to_string()),
            assets: vec![
                GithubAsset {
                    name: "OutlineProxy-v26.11.0-Windows-x86_64.zip".to_string(),
                    browser_download_url: "https://example.invalid/win.zip".to_string(),
                },
                GithubAsset {
                    name: "SHA256SUMS.txt".to_string(),
                    browser_download_url: "https://example.invalid/SHA256SUMS.txt".to_string(),
                },
            ],
        };

        let avail = UpdateChecker::evaluate_release(release, "1.9.2").expect("available");
        assert_eq!(
            avail,
            UpdateCheckResult::Available(UpdateInfo {
                label: "v26.11.0".to_string(),
                asset_name: "OutlineProxy-v26.11.0-Windows-x86_64.zip".to_string(),
                download_url: "https://example.invalid/win.zip".to_string(),
                checksums_url: Some("https://example.invalid/SHA256SUMS.txt".to_string()),
                notes: "Unified release".to_string(),
                commit: "abcdef12".to_string(),
            })
        );

        let same_ver = GithubRelease {
            tag_name: "v26.11.0".to_string(),
            draft: false,
            body: None,
            target_commitish: None,
            assets: vec![],
        };
        assert_eq!(
            UpdateChecker::evaluate_release(same_ver, "26.11.0").expect("up-to-date"),
            UpdateCheckResult::UpToDate
        );
    }

    #[test]
    fn test_to_hex() {
        let bytes = [0xde, 0xad, 0xbe, 0xef];
        assert_eq!(to_hex(&bytes), "deadbeef");
    }

    #[test]
    fn test_build_update_script_removes_legacy_binary() {
        let staging = std::path::PathBuf::from("Temp").join("outline-staging");
        let target_exe = std::path::PathBuf::from("OutlineProxy").join("OutlineProxy.exe");
        let script = UpdateInstaller::build_update_script(&staging, &target_exe, 4242)
            .expect("script generation should succeed");

        let copy_cmd = "copy /Y \"%STAGING_DIR%\\*.*\" \"%TARGET_DIR%\\\" >NUL";
        let cleanup_cmd = "if exist \"%TARGET_DIR%\\outline-ws-rust.exe\" del /F /Q \"%TARGET_DIR%\\outline-ws-rust.exe\" >NUL 2>&1";
        let start_cmd = "start \"\" \"%TARGET_EXE%\"";

        let copy_pos = script.find(copy_cmd).expect("copy fallback present");
        let cleanup_pos = script.find(cleanup_cmd).expect("legacy binary cleanup present");
        let start_pos = script.find(start_cmd).expect("restart command present");

        assert!(copy_pos < cleanup_pos, "cleanup must run after copy");
        assert!(cleanup_pos < start_pos, "cleanup must run before restarting app");
        assert!(script.contains("set TARGET_PID=4242\r\n"));
    }

    #[test]
    fn test_build_update_script_rejects_bare_filename() {
        let staging = std::path::PathBuf::from("Temp").join("outline-staging");
        let err =
            UpdateInstaller::build_update_script(&staging, Path::new("OutlineProxy.exe"), 4242)
                .expect_err("bare executable filename without parent directory should fail");
        assert!(err.contains("no parent directory"), "unexpected error: {err}");
    }
}
