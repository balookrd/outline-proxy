import Foundation

/// Manages macOS system SOCKS5 proxy settings via `networksetup`.
public final class SystemProxyManager: @unchecked Sendable {
    public static let shared = SystemProxyManager()

    private let lock = NSLock()
    private var managedServices: Set<String> = []

    private init() {}

    /// Enables SOCKS5 proxy for the active physical network service.
    public func enableProxy(host: String = "127.0.0.1", port: Int = 1080) {
        lock.lock()
        defer { lock.unlock() }

        let services = getActiveNetworkServices()
        for service in services {
            setProxy(service: service, host: host, port: port, enabled: true)
            managedServices.insert(service)
        }
    }

    /// Disables SOCKS5 proxy on all currently managed or active services.
    public func disableProxy() {
        lock.lock()
        defer { lock.unlock() }

        var targets = managedServices
        if targets.isEmpty {
            targets = Set(getActiveNetworkServices())
        }

        for service in targets {
            setProxy(service: service, host: "127.0.0.1", port: 1080, enabled: false)
        }
        managedServices.removeAll()
    }

    /// Ensures no stale local proxy settings are left enabled from an earlier unexpected crash.
    public func cleanupStaleSettings() {
        let services = getActiveNetworkServices()
        for service in services {
            if isLocalProxyEnabled(service: service) {
                setProxy(service: service, host: "127.0.0.1", port: 1080, enabled: false)
            }
        }
    }

    // MARK: - Internal Helpers

    private func setProxy(service: String, host: String, port: Int, enabled: Bool) {
        if enabled {
            _ = runCommand("/usr/sbin/networksetup", ["-setsocksfirewallproxy", service, host, "\(port)"])
            _ = runCommand("/usr/sbin/networksetup", ["-setsocksfirewallproxystate", service, "on"])
        } else {
            _ = runCommand("/usr/sbin/networksetup", ["-setsocksfirewallproxystate", service, "off"])
        }
    }

    private func isLocalProxyEnabled(service: String) -> Bool {
        let output = runCommand("/usr/sbin/networksetup", ["-getsocksfirewallproxy", service])
        let isEnabled = output.contains("Enabled: Yes")
        let isLocalhost = output.contains("Server: 127.0.0.1") || output.contains("Server: localhost")
        return isEnabled && isLocalhost
    }

    /// Returns list of network service names currently active / configured.
    public func getActiveNetworkServices() -> [String] {
        // Find default route interface
        let routeOutput = runCommand("/sbin/route", ["-n", "get", "default"])
        var defaultIface = ""
        for line in routeOutput.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("interface:") {
                defaultIface = trimmed.replacingOccurrences(of: "interface:", with: "").trimmingCharacters(in: .whitespaces)
                break
            }
        }

        let allServices = getNetworkServiceMapping()
        if !defaultIface.isEmpty, let activeService = allServices[defaultIface] {
            return [activeService]
        }

        if let wifi = allServices.values.first(where: { $0.localizedCaseInsensitiveContains("Wi-Fi") }) {
            return [wifi]
        }

        return Array(allServices.values)
    }

    private func getNetworkServiceMapping() -> [String: String] {
        var mapping: [String: String] = [:]
        let output = runCommand("/usr/sbin/networksetup", ["-listnetworkserviceorder"])
        let lines = output.components(separatedBy: .newlines)

        var currentService: String?
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("(") && trimmed.contains(")") && !trimmed.contains("Hardware Port:") {
                if let closeParen = trimmed.firstIndex(of: ")") {
                    currentService = String(trimmed[trimmed.index(after: closeParen)...]).trimmingCharacters(in: .whitespaces)
                }
            } else if trimmed.contains("Device:"), let service = currentService {
                if let devRange = trimmed.range(of: "Device: ") {
                    let rest = trimmed[devRange.upperBound...]
                    let dev = rest.prefix { $0 != ")" && $0 != "," }.trimmingCharacters(in: .whitespaces)
                    if !dev.isEmpty {
                        mapping[String(dev)] = service
                    }
                }
                currentService = nil
            }
        }
        return mapping
    }

    @discardableResult
    private func runCommand(_ launchPath: String, _ arguments: [String]) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            // Read pipe before waiting for exit to prevent pipe buffer deadlock
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return String(data: data, encoding: .utf8) ?? ""
        } catch {
            return ""
        }
    }
}
