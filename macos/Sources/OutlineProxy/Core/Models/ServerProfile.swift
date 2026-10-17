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
    public var tcpOnly: Bool
    public var rawTomlOverride: String
    public var configUrl: String
    public var cachedToml: String
    public var updatedAt: Double

    enum CodingKeys: String, CodingKey {
        case id, name, transport, link, paddingEnabled, tcpOnly, rawTomlOverride, configUrl, cachedToml, updatedAt
    }

    public init(
        id: String = UUID().uuidString,
        name: String = "",
        transport: String = "vless",
        link: String = "",
        paddingEnabled: Bool = false,
        tcpOnly: Bool = false,
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
        self.tcpOnly = tcpOnly
        self.rawTomlOverride = rawTomlOverride
        self.configUrl = configUrl
        self.cachedToml = cachedToml
        self.updatedAt = updatedAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        transport = try container.decode(String.self, forKey: .transport)
        link = try container.decode(String.self, forKey: .link)
        paddingEnabled = try container.decodeIfPresent(Bool.self, forKey: .paddingEnabled) ?? false
        tcpOnly = try container.decodeIfPresent(Bool.self, forKey: .tcpOnly) ?? false
        rawTomlOverride = try container.decodeIfPresent(String.self, forKey: .rawTomlOverride) ?? ""
        configUrl = try container.decodeIfPresent(String.self, forKey: .configUrl) ?? ""
        cachedToml = try container.decodeIfPresent(String.self, forKey: .cachedToml) ?? ""
        updatedAt = try container.decodeIfPresent(Double.self, forKey: .updatedAt) ?? Date().timeIntervalSince1970
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
        if !cachedToml.isEmpty {
            for line in cachedToml.components(separatedBy: .newlines) {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("link =") || trimmed.hasPrefix("link=") {
                    if let host = ServerProfile.extractHost(from: trimmed) {
                        return host
                    }
                }
            }
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
