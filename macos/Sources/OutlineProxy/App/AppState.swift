import Foundation
import AppKit

/// High-level application state and action coordinator.
@MainActor
public final class AppState: ObservableObject {
    public static let shared = AppState()

    public enum ConnectionStatus: Equatable {
        case disconnected
        case connecting
        case connected(serverName: String)
        case disconnecting
        case error(String)
    }

    @Published public private(set) var status: ConnectionStatus = .disconnected
    @Published public private(set) var mode: ProxyMode = .socks5
    @Published public private(set) var currentLogs: [String] = []

    private init() {
        // Load saved proxy mode preference
        if let savedModeStr = UserDefaults.standard.string(forKey: "OutlineProxy.Mode"),
           let savedMode = ProxyMode(rawValue: savedModeStr) {
            self.mode = savedMode
        }

        // Monitor process controller callbacks
        ProcessController.shared.onStateChanged = { [weak self] state in
            Task { @MainActor [weak self] in
                guard let self = self else { return }
                switch state {
                case .stopped:
                    if case .disconnecting = self.status {
                        self.status = .disconnected
                    } else if case .connected = self.status {
                        // Unexpected exit
                        Task.detached(priority: .utility) {
                            SystemProxyManager.shared.disableProxy()
                        }
                        self.status = .disconnected
                    }
                case .starting:
                    self.status = .connecting
                case .running:
                    let name = ProfileStore.shared.activeProfile?.name ?? "Сервер"
                    self.status = .connected(serverName: name)
                case .stopping:
                    self.status = .disconnecting
                case .error(let msg):
                    Task.detached(priority: .utility) {
                        SystemProxyManager.shared.disableProxy()
                    }
                    self.status = .error(msg)
                }
                NotificationCenter.default.post(name: NSNotification.Name("AppStateUpdated"), object: nil)
            }
        }

        // Clean up any stale system proxy on launch in background
        Task.detached(priority: .utility) {
            SystemProxyManager.shared.cleanupStaleSettings()
        }
    }

    public var isConnected: Bool {
        if case .connected = status { return true }
        return false
    }

    public func setMode(_ newMode: ProxyMode) {
        guard mode != newMode else { return }
        let wasConnected = isConnected
        if wasConnected {
            disconnect()
        }

        mode = newMode
        UserDefaults.standard.set(newMode.rawValue, forKey: "OutlineProxy.Mode")
        NotificationCenter.default.post(name: NSNotification.Name("AppStateUpdated"), object: nil)

        if wasConnected {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { [weak self] in
                self?.connect()
            }
        }
    }

    public func toggleConnection() {
        if isConnected {
            disconnect()
        } else {
            connect()
        }
    }

    public func connect() {
        guard let profile = ProfileStore.shared.activeProfile else {
            status = .error("Нет активного профиля. Добавьте сервер в настройках.")
            return
        }

        status = .connecting
        NotificationCenter.default.post(name: NSNotification.Name("AppStateUpdated"), object: nil)

        let targetMode = self.mode

        Task.detached(priority: .userInitiated) {
            var currentProfile = profile

            // 1. If subscription and cache is empty, fetch it first
            if currentProfile.isSubscription && currentProfile.cachedToml.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                do {
                    currentProfile = try await SubscriptionFetcher.updateSubscription(currentProfile)
                } catch {
                    await MainActor.run {
                        AppState.shared.status = .error("Ошибка загрузки подписки: \(error.localizedDescription)")
                        NotificationCenter.default.post(name: NSNotification.Name("AppStateUpdated"), object: nil)
                    }
                    return
                }
            }

            // 2. Generate config adapted for current mode
            let toml = ConfigGenerator.generateConfig(for: currentProfile, mode: targetMode, socksPort: 1080)

            // 3. Start process and apply proxy
            do {
                switch targetMode {
                case .socks5:
                    try ProcessController.shared.start(withConfigToml: toml, mode: .socks5)
                    SystemProxyManager.shared.enableProxy(port: 1080)
                case .tun:
                    SystemProxyManager.shared.disableProxy()
                    try ProcessController.shared.start(withConfigToml: toml, mode: .tun, serverHost: currentProfile.serverHost)
                }

                let serverName = currentProfile.name
                await MainActor.run {
                    AppState.shared.status = .connected(serverName: serverName)
                    NotificationCenter.default.post(name: NSNotification.Name("AppStateUpdated"), object: nil)
                }
            } catch {
                SystemProxyManager.shared.disableProxy()
                await MainActor.run {
                    AppState.shared.status = .error(error.localizedDescription)
                    NotificationCenter.default.post(name: NSNotification.Name("AppStateUpdated"), object: nil)
                }
            }
        }
    }

    public func disconnect() {
        status = .disconnecting
        NotificationCenter.default.post(name: NSNotification.Name("AppStateUpdated"), object: nil)

        Task.detached(priority: .userInitiated) {
            SystemProxyManager.shared.disableProxy()
            ProcessController.shared.stop()
            await MainActor.run {
                AppState.shared.status = .disconnected
                NotificationCenter.default.post(name: NSNotification.Name("AppStateUpdated"), object: nil)
            }
        }
    }

    public func switchProfile(to id: String) {
        ProfileStore.shared.selectProfile(id: id)
        if isConnected {
            disconnect()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { [weak self] in
                self?.connect()
            }
        }
    }

    public func cleanupOnExit() {
        SystemProxyManager.shared.disableProxy()
        ProcessController.shared.stop()
    }
}
