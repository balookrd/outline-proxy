import Foundation

/// Operational mode of Outline Proxy on macOS.
public enum ProxyMode: String, CaseIterable, Codable, Sendable {
    /// Standard SOCKS5 proxy configuring system settings via networksetup.
    /// Requires no administrator/root privileges.
    case socks5 = "socks5"

    /// Full L3 VPN capturing all network traffic via macOS native `utun` interface.
    /// Prompts for administrator credentials (Touch ID / password) upon launch.
    case tun = "tun"

    public var title: String {
        switch self {
        case .socks5:
            return "SOCKS5 (Системный прокси)"
        case .tun:
            return "TUN (Полный VPN)"
        }
    }

    public var shortTitle: String {
        switch self {
        case .socks5:
            return "SOCKS5"
        case .tun:
            return "TUN (VPN)"
        }
    }

    public var summary: String {
        switch self {
        case .socks5:
            return "Работает без прав root. Настраивает системный прокси для браузеров и приложений."
        case .tun:
            return "Требует пароль администратора / Touch ID. Перехватывает весь трафик macOS (L3 utun)."
        }
    }
}
