import Foundation

/// A saved server profile for Outline Proxy macOS.
///
/// Models both manual links (VLESS / Shadowsocks) and HTTPS config subscriptions,
/// matching the Android model.
public struct ServerProfile: Identifiable, Codable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var transport: String // "vless" | "ss"
    public var link: String      // vless://... or ss://...
    public var paddingEnabled: Bool
    public var rawTomlOverride: String
    public var configUrl: String
    public var cachedToml: String
    public var updatedAt: Double

    public init(
        id: String = UUID().uuidString,
        name: String = "",
        transport: String = "vless",
        link: String = "",
        paddingEnabled: Bool = false,
        rawTomlOverride: String = "",
        configUrl: String = "",
        cachedToml: String = "",
        updatedAt: Double = Date().timeIntervalSince1970
    ) {
        self.id = id
        self.name = name
        self.transport = transport
        self.link = link
        self.paddingEnabled = paddingEnabled
        self.rawTomlOverride = rawTomlOverride
        self.configUrl = configUrl
        self.cachedToml = cachedToml
        self.updatedAt = updatedAt
    }

    public var isSubscription: Bool {
        !configUrl.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Parses a share link (`ss://...`, `vless://...`, `outline://...`) into a profile.
    public static func from(link: String) -> ServerProfile? {
        var trimmed = link.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return nil }

        // Support outline:// protocol wrappers if present
        if trimmed.lowercased().hasPrefix("outline://") {
            // Some outline links wrap ss:// or access keys
            trimmed = String(trimmed.dropFirst("outline://".count))
        }

        var transport = "vless"
        if trimmed.lowercased().hasPrefix("vless://") {
            transport = "vless"
        } else if trimmed.lowercased().hasPrefix("ss://") {
            transport = "ss"
        } else if trimmed.lowercased().hasPrefix("https://") || trimmed.lowercased().hasPrefix("http://") {
            // Subscription URL
            return ServerProfile(
                name: "Подписка",
                configUrl: trimmed
            )
        } else {
            return nil
        }

        // Try extracting fragment name (e.g. #ServerName)
        var name = "Сервер"
        if let hashIndex = trimmed.firstIndex(of: "#") {
            let fragment = String(trimmed[trimmed.index(after: hashIndex)...])
            if let decoded = fragment.removingPercentEncoding, !decoded.isEmpty {
                name = decoded
            } else if !fragment.isEmpty {
                name = fragment
            }
        } else {
            // Derive fallback name from host
            name = extractHost(from: trimmed) ?? (transport.uppercased() + " сервер")
        }

        return ServerProfile(
            name: name,
            transport: transport,
            link: trimmed
        )
    }

    public var serverHost: String? {
        if !link.isEmpty, let host = ServerProfile.extractHost(from: link) {
            return host
        }
        if !configUrl.isEmpty, let url = URL(string: configUrl), let host = url.host {
            return host
        }
        return nil
    }

    public var displayName: String {
        if !name.isEmpty && name != "Подписка" {
            return name
        }
        if let host = serverHost {
            let parts = host.split(separator: ".")
            if let first = parts.first, !first.isEmpty && first != "www" {
                return String(first)
            }
            return host
        }
        return name.isEmpty ? "cloud" : name
    }

    public static func extractHost(from urlStr: String) -> String? {
        guard let atIndex = urlStr.lastIndex(of: "@") else { return nil }
        let afterAt = urlStr[urlStr.index(after: atIndex)...]
        let hostPort = afterAt.prefix { $0 != "?" && $0 != "#" && $0 != "/" }
        let host = hostPort.split(separator: ":").first
        return host.map(String.init)
    }
}
