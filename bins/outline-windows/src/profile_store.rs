use std::path::PathBuf;
use std::sync::RwLock;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

/// Generates a random UUID v4 string.
fn generate_id() -> String {
    let mut bytes: [u8; 16] = rand::random();
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant RFC 4122
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

/// Returns the current Unix timestamp in fractional seconds.
fn current_timestamp() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Helper to decode percent-encoded strings (URL fragments, query values).
fn percent_decode(input: &str) -> String {
    let mut bytes = Vec::new();
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next();
            let h2 = chars.next();
            if let (Some(c1), Some(c2)) = (h1, h2) {
                if let Ok(hex_str) = std::str::from_utf8(&[c1, c2])
                    && let Ok(byte) = u8::from_str_radix(hex_str, 16)
                {
                    bytes.push(byte);
                    continue;
                }
                bytes.push(b'%');
                bytes.push(c1);
                bytes.push(c2);
            } else {
                bytes.push(b'%');
                if let Some(c1) = h1 {
                    bytes.push(c1);
                }
            }
        } else if b == b'+' {
            bytes.push(b' ');
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8_lossy(&bytes).to_string()
}

/// Decodes base64 string handling both standard and URL-safe variants, with or without padding.
pub fn decode_base64_flexible(input: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

    let cleaned = input.trim();
    if let Ok(bytes) = STANDARD.decode(cleaned) {
        return Ok(bytes);
    }
    if let Ok(bytes) = URL_SAFE.decode(cleaned) {
        return Ok(bytes);
    }
    if let Ok(bytes) = STANDARD_NO_PAD.decode(cleaned) {
        return Ok(bytes);
    }
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(cleaned) {
        return Ok(bytes);
    }
    bail!("failed to base64-decode string")
}

/// Represents a single server profile or subscription.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServerProfile {
    pub id: String,
    pub name: String,
    pub transport: String, // "vless" | "ss" | "subscription"
    #[serde(default)]
    pub link: String,
    #[serde(default)]
    pub padding_enabled: bool,
    #[serde(default)]
    pub tcp_only: bool,
    #[serde(default)]
    pub raw_toml_override: String,
    #[serde(default)]
    pub config_url: String,
    #[serde(default)]
    pub cached_toml: String,
    #[serde(default)]
    pub updated_at: f64,
}

impl Default for ServerProfile {
    fn default() -> Self {
        Self {
            id: generate_id(),
            name: "New Profile".to_string(),
            transport: "vless".to_string(),
            link: String::new(),
            padding_enabled: false,
            tcp_only: false,
            raw_toml_override: String::new(),
            config_url: String::new(),
            cached_toml: String::new(),
            updated_at: current_timestamp(),
        }
    }
}

impl ServerProfile {
    /// Returns true if this profile is backed by an HTTP(S) subscription.
    pub fn is_subscription(&self) -> bool {
        !self.config_url.trim().is_empty()
    }

    /// Derives a display name for the profile.
    pub fn display_name(&self) -> String {
        let trimmed = self.name.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
        if self.is_subscription() {
            return "Subscription".to_string();
        }
        if let Some(host) = self.server_host() {
            return host;
        }
        format!("{} server", self.transport.to_uppercase())
    }

    /// Extracts the target server host if available.
    pub fn server_host(&self) -> Option<String> {
        if !self.link.is_empty()
            && let Some(host) = Self::extract_host(&self.link)
        {
            return Some(host);
        }
        if !self.cached_toml.is_empty() {
            for line in self.cached_toml.lines() {
                let trimmed = line.trim();
                if (trimmed.starts_with("link =") || trimmed.starts_with("link="))
                    && let Some(host) = Self::extract_host(trimmed)
                {
                    return Some(host);
                }
            }
        }
        if !self.config_url.is_empty()
            && let Ok(url) = url::Url::parse(&self.config_url)
            && let Some(host) = url.host_str()
        {
            return Some(host.to_string());
        }
        None
    }

    /// Extracts host from a link or config line.
    pub fn extract_host(link_or_url: &str) -> Option<String> {
        let trimmed = link_or_url.trim().trim_matches('"').trim_matches('\'');
        if let Ok(url) = url::Url::parse(trimmed)
            && let Some(host) = url.host_str()
        {
            return Some(host.to_string());
        }
        if let Some(at_idx) = trimmed.rfind('@') {
            let after_at = &trimmed[at_idx + 1..];
            let host_port = after_at.split(&['?', '#', '/'][..]).next()?;
            let host = host_port.split(':').next()?;
            if !host.is_empty() {
                return Some(host.to_string());
            }
        }
        None
    }

    /// Parses a share link (`vless://...`, `ss://...`, `outline://...`, `https://...`) into a `ServerProfile`.
    pub fn from_link(raw_link: &str) -> Result<Self> {
        let mut trimmed = raw_link.trim().to_string();
        if trimmed.is_empty() {
            bail!("link cannot be empty");
        }

        // Handle outline:// protocol wrappers
        if let Some(rest) = trimmed.strip_prefix("outline://") {
            let rest_trimmed = rest.trim();
            if rest_trimmed.starts_with("ss://") || rest_trimmed.starts_with("vless://") {
                trimmed = rest_trimmed.to_string();
            } else if let Ok(bytes) = decode_base64_flexible(rest_trimmed) {
                if let Ok(decoded) = std::str::from_utf8(&bytes) {
                    let decoded_trimmed = decoded.trim();
                    if decoded_trimmed.starts_with("ss://")
                        || decoded_trimmed.starts_with("vless://")
                    {
                        trimmed = decoded_trimmed.to_string();
                    } else {
                        trimmed = rest_trimmed.to_string();
                    }
                } else {
                    trimmed = rest_trimmed.to_string();
                }
            } else {
                trimmed = rest_trimmed.to_string();
            }
        }

        // Subscriptions
        if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
            return Ok(Self {
                id: generate_id(),
                name: "Subscription".to_string(),
                transport: "subscription".to_string(),
                link: String::new(),
                padding_enabled: false,
                tcp_only: false,
                raw_toml_override: String::new(),
                config_url: trimmed,
                cached_toml: String::new(),
                updated_at: current_timestamp(),
            });
        }

        let transport = if trimmed.starts_with("vless://") {
            "vless".to_string()
        } else if trimmed.starts_with("ss://") {
            "ss".to_string()
        } else {
            bail!("unsupported link scheme, expected vless://, ss://, outline:// or http(s)://");
        };

        // Extract fragment name e.g. #MyServer
        let name = if let Some(hash_idx) = trimmed.find('#') {
            let fragment = &trimmed[hash_idx + 1..];
            let decoded = percent_decode(fragment);
            if !decoded.is_empty() {
                decoded
            } else {
                Self::extract_host(&trimmed)
                    .unwrap_or_else(|| format!("{} server", transport.to_uppercase()))
            }
        } else {
            Self::extract_host(&trimmed)
                .unwrap_or_else(|| format!("{} server", transport.to_uppercase()))
        };

        Ok(Self {
            id: generate_id(),
            name,
            transport,
            link: trimmed,
            padding_enabled: false,
            tcp_only: false,
            raw_toml_override: String::new(),
            config_url: String::new(),
            cached_toml: String::new(),
            updated_at: current_timestamp(),
        })
    }
}

/// Application settings for Outline Proxy Windows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    #[serde(default = "default_proxy_mode")]
    pub proxy_mode: String, // "socks5" | "tun"
    #[serde(default)]
    pub tcp_only: bool,
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default)]
    pub start_minimized: bool,
}

fn default_proxy_mode() -> String {
    "socks5".to_string()
}

fn default_socks_port() -> u16 {
    1080
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            proxy_mode: default_proxy_mode(),
            tcp_only: false,
            socks_port: default_socks_port(),
            autostart: false,
            start_minimized: false,
        }
    }
}

/// Serializable state for persistent profile storage.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProfileStoreData {
    pub profiles: Vec<ServerProfile>,
    pub selected_id: Option<String>,
    #[serde(default)]
    pub settings: AppSettings,
}

/// Thread-safe persistent profile store.
pub struct ProfileStore {
    storage_path: PathBuf,
    data: RwLock<ProfileStoreData>,
}

impl ProfileStore {
    /// Returns the standard path to `profiles.json`:
    /// `%APPDATA%\OutlineProxy\profiles.json` on Windows,
    /// `$HOME/.config/OutlineProxy/profiles.json` on other platforms.
    pub fn default_storage_path() -> PathBuf {
        #[cfg(windows)]
        {
            if let Some(appdata) = std::env::var_os("APPDATA") {
                return PathBuf::from(appdata).join("OutlineProxy").join("profiles.json");
            }
        }

        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join(".config")
                .join("OutlineProxy")
                .join("profiles.json");
        }

        PathBuf::from("OutlineProxy").join("profiles.json")
    }

    /// Loads or initializes the profile store at the default path.
    pub fn load() -> Result<Self> {
        Self::open(Self::default_storage_path())
    }

    /// Opens or initializes the profile store at a specific file path.
    pub fn open(storage_path: PathBuf) -> Result<Self> {
        let data = if storage_path.exists() {
            let raw_content = std::fs::read_to_string(&storage_path).with_context(|| {
                format!("failed to read profiles from {}", storage_path.display())
            })?;
            let content = raw_content.strip_prefix('\u{feff}').unwrap_or(&raw_content);
            if content.trim().is_empty() {
                ProfileStoreData::default()
            } else {
                serde_json::from_str::<ProfileStoreData>(content).with_context(|| {
                    format!("failed to parse JSON from {}", storage_path.display())
                })?
            }
        } else {
            ProfileStoreData::default()
        };

        Ok(Self { storage_path, data: RwLock::new(data) })
    }

    /// Creates an empty profile store with default settings at a specific file path without reading from disk.
    pub fn empty(storage_path: PathBuf) -> Self {
        Self {
            storage_path,
            data: RwLock::new(ProfileStoreData::default()),
        }
    }

    /// Saves the current profiles and selection to disk.
    pub fn save(&self) -> Result<()> {
        let data_clone = {
            let lock = self.data.read().map_err(|_| anyhow!("lock poisoned"))?;
            lock.clone()
        };

        if let Some(parent) = self.storage_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }

        let json = serde_json::to_string_pretty(&data_clone)
            .context("failed to serialize profiles data")?;
        std::fs::write(&self.storage_path, json).with_context(|| {
            format!("failed to write profiles to {}", self.storage_path.display())
        })?;
        Ok(())
    }

    /// Returns a list of all profiles.
    pub fn profiles(&self) -> Vec<ServerProfile> {
        let lock = self.data.read().unwrap();
        lock.profiles.clone()
    }

    /// Returns the currently active profile.
    pub fn active_profile(&self) -> Option<ServerProfile> {
        let lock = self.data.read().unwrap();
        if let Some(ref selected_id) = lock.selected_id
            && let Some(profile) = lock.profiles.iter().find(|p| p.id == *selected_id)
        {
            return Some(profile.clone());
        }
        lock.profiles.first().cloned()
    }

    /// Returns the ID of the currently active profile.
    pub fn active_profile_id(&self) -> Option<String> {
        let lock = self.data.read().unwrap();
        lock.selected_id
            .clone()
            .or_else(|| lock.profiles.first().map(|p| p.id.clone()))
    }

    /// Sets the active profile by ID and persists to disk.
    pub fn select_profile(&self, id: &str) -> Result<()> {
        {
            let mut lock = self.data.write().map_err(|_| anyhow!("lock poisoned"))?;
            if !lock.profiles.iter().any(|p| p.id == id) {
                bail!("profile with id '{id}' not found");
            }
            lock.selected_id = Some(id.to_string());
        }
        self.save()
    }

    /// Adds a new profile to the store and persists.
    pub fn add_profile(&self, profile: ServerProfile) -> Result<()> {
        {
            let mut lock = self.data.write().map_err(|_| anyhow!("lock poisoned"))?;
            if lock.selected_id.is_none() {
                lock.selected_id = Some(profile.id.clone());
            }
            lock.profiles.push(profile);
        }
        self.save()
    }

    /// Updates an existing profile by matching `id` and persists.
    pub fn update_profile(&self, profile: ServerProfile) -> Result<()> {
        {
            let mut lock = self.data.write().map_err(|_| anyhow!("lock poisoned"))?;
            if let Some(idx) = lock.profiles.iter().position(|p| p.id == profile.id) {
                lock.profiles[idx] = profile;
            } else {
                bail!("profile with id '{}' not found for update", profile.id);
            }
        }
        self.save()
    }

    /// Removes a profile by ID and persists.
    pub fn remove_profile(&self, id: &str) -> Result<()> {
        {
            let mut lock = self.data.write().map_err(|_| anyhow!("lock poisoned"))?;
            lock.profiles.retain(|p| p.id != id);
            if lock.selected_id.as_deref() == Some(id) {
                lock.selected_id = lock.profiles.first().map(|p| p.id.clone());
            }
        }
        self.save()
    }

    /// Returns the current application settings.
    pub fn settings(&self) -> AppSettings {
        let lock = self.data.read().unwrap();
        lock.settings.clone()
    }

    /// Updates the application settings and persists to disk.
    pub fn update_settings(&self, settings: AppSettings) -> Result<()> {
        {
            let mut lock = self.data.write().map_err(|_| anyhow!("lock poisoned"))?;
            lock.settings = settings;
        }
        self.save()
    }
}

/// Helper for fetching subscriptions from remote servers.
pub struct SubscriptionFetcher;

impl SubscriptionFetcher {
    /// Fetches the raw content of an HTTP(S) subscription.
    ///
    /// If the response body is valid base64 (common for V2Ray / Shadowsocks subscription links),
    /// it attempts to decode it before returning.
    pub async fn fetch_subscription_content(url: &str) -> Result<String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .context("failed to build HTTP client")?;

        let response = client
            .get(url)
            .header("User-Agent", "OutlineProxy-Windows/1.0")
            .send()
            .await
            .with_context(|| format!("HTTP request to '{url}' failed"))?;

        if !response.status().is_success() {
            bail!("subscription HTTP request failed with status: {}", response.status());
        }

        let body = response
            .text()
            .await
            .context("failed to read response body as text")?;

        // Attempt base64 decoding if the body is base64-encoded
        if let Ok(decoded_bytes) = decode_base64_flexible(body.trim())
            && let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes)
        {
            return Ok(decoded_str.to_string());
        }

        Ok(body)
    }

    /// Updates the specified subscription profile in the store with freshly downloaded content.
    pub async fn update_subscription(
        store: &ProfileStore,
        profile_id: &str,
    ) -> Result<ServerProfile> {
        let mut profile = {
            let profiles = store.profiles();
            profiles
                .into_iter()
                .find(|p| p.id == profile_id)
                .ok_or_else(|| anyhow!("subscription profile '{}' not found", profile_id))?
        };

        if !profile.is_subscription() {
            bail!("profile '{}' is not a subscription", profile_id);
        }

        let content = Self::fetch_subscription_content(&profile.config_url).await?;
        profile.cached_toml = content;
        profile.updated_at = current_timestamp();
        store.update_profile(profile.clone())?;
        Ok(profile)
    }
}
