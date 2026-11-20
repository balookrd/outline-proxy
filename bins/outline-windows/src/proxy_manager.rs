use anyhow::Result;

/// Manages system SOCKS5 proxy configuration.
///
/// On Windows, this configures HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
/// and notifies the WinINet subsystem via `InternetSetOptionW`.
/// On non-Windows platforms, a thread-safe mock implementation is provided for cross-platform
/// compilation and testing.
pub struct SystemProxyManager;

#[cfg(windows)]
impl SystemProxyManager {
    const INTERNET_SETTINGS_KEY: &'static str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    /// Enables the system SOCKS5 proxy pointing to `host:port`.
    pub fn enable_socks5(host: &str, port: u16) -> Result<()> {
        use anyhow::Context;
        use winreg::RegKey;
        use winreg::enums::HKEY_CURRENT_USER;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (settings, _) = hkcu
            .create_subkey(Self::INTERNET_SETTINGS_KEY)
            .context("failed to open Internet Settings registry key for writing")?;

        let proxy_server = format!("socks={host}:{port}");
        settings
            .set_value("ProxyServer", &proxy_server)
            .context("failed to write ProxyServer to registry")?;
        settings
            .set_value("ProxyEnable", &1u32)
            .context("failed to write ProxyEnable to registry")?;

        Self::notify_wininet()?;
        tracing::info!(host = %host, port = %port, "System SOCKS5 proxy enabled");
        Ok(())
    }

    /// Disables the system proxy (`ProxyEnable = 0`).
    pub fn disable() -> Result<()> {
        use anyhow::Context;
        use winreg::RegKey;
        use winreg::enums::HKEY_CURRENT_USER;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (settings, _) = hkcu
            .create_subkey(Self::INTERNET_SETTINGS_KEY)
            .context("failed to open Internet Settings registry key for writing")?;

        settings
            .set_value("ProxyEnable", &0u32)
            .context("failed to disable ProxyEnable in registry")?;

        Self::notify_wininet()?;
        tracing::info!("System SOCKS5 proxy disabled");
        Ok(())
    }

    /// Checks whether the system proxy is currently enabled in the registry.
    pub fn is_enabled() -> Result<bool> {
        use anyhow::Context;
        use winreg::RegKey;
        use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let settings = hkcu
            .open_subkey_with_flags(Self::INTERNET_SETTINGS_KEY, KEY_READ)
            .context("failed to open Internet Settings registry key for reading")?;

        let enabled: u32 = settings.get_value("ProxyEnable").unwrap_or(0);
        Ok(enabled != 0)
    }

    /// Notifies WinINet to reload proxy settings immediately.
    fn notify_wininet() -> Result<()> {
        use windows_sys::Win32::Networking::WinInet::{
            INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
        };

        unsafe {
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null_mut(),
                0,
            );
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null_mut(),
                0,
            );
        }
        Ok(())
    }
}

#[cfg(not(windows))]
static MOCK_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(not(windows))]
static MOCK_SERVER: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

#[cfg(not(windows))]
impl SystemProxyManager {
    /// Mock implementation for non-Windows platforms.
    pub fn enable_socks5(host: &str, port: u16) -> Result<()> {
        MOCK_ENABLED.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut server = MOCK_SERVER.lock().unwrap();
        *server = Some(format!("socks={host}:{port}"));
        tracing::info!(host = %host, port = %port, "[mock] System SOCKS5 proxy enabled");
        Ok(())
    }

    /// Mock implementation for non-Windows platforms.
    pub fn disable() -> Result<()> {
        MOCK_ENABLED.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut server = MOCK_SERVER.lock().unwrap();
        *server = None;
        tracing::info!("[mock] System SOCKS5 proxy disabled");
        Ok(())
    }

    /// Mock implementation for non-Windows platforms.
    pub fn is_enabled() -> Result<bool> {
        Ok(MOCK_ENABLED.load(std::sync::atomic::Ordering::SeqCst))
    }

    #[doc(hidden)]
    pub fn mock_current_server() -> Option<String> {
        MOCK_SERVER.lock().unwrap().clone()
    }
}
