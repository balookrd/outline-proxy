use crate::proxy_manager::SystemProxyManager;

#[test]
fn test_system_proxy_manager_toggle() {
    // Disable first
    SystemProxyManager::disable().expect("disable proxy");
    assert!(!SystemProxyManager::is_enabled().expect("check is_enabled"));

    // Enable SOCKS5
    SystemProxyManager::enable_socks5("127.0.0.1", 1080).expect("enable proxy");
    assert!(SystemProxyManager::is_enabled().expect("check is_enabled"));

    // Disable again
    SystemProxyManager::disable().expect("disable proxy");
    assert!(!SystemProxyManager::is_enabled().expect("check is_enabled"));
}
