import AppKit
import Foundation

/// Controls the Menu Bar Status Item and its dynamic dropdown menu.
@MainActor
public final class StatusMenuController: NSObject, NSMenuDelegate {
    public static let shared = StatusMenuController()

    private var statusItem: NSStatusItem?
    private let menu = NSMenu()

    override private init() {
        super.init()
    }

    public func setup() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem?.menu = menu
        menu.delegate = self

        updateStatusIcon()
        rebuildMenu()

        // Listen for state changes
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleStateUpdate),
            name: NSNotification.Name("AppStateUpdated"),
            object: nil
        )

        ProfileStore.shared.onProfilesChanged = { [weak self] in
            DispatchQueue.main.async {
                self?.rebuildMenu()
            }
        }
    }

    @objc private func handleStateUpdate() {
        updateStatusIcon()
        rebuildMenu()
    }

    public func menuWillOpen(_ menu: NSMenu) {
        rebuildMenu()
    }

    private func updateStatusIcon() {
        guard let button = statusItem?.button else { return }

        switch AppState.shared.status {
        case .connected:
            let iconName = (AppState.shared.mode == .tun) ? "shield.fill" : "network"
            button.image = NSImage(systemSymbolName: iconName, accessibilityDescription: "Outline Proxy — Подключено")
        case .connecting, .disconnecting:
            button.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Outline Proxy — Подключение")
        case .disconnected, .error:
            button.image = NSImage(systemSymbolName: "shield", accessibilityDescription: "Outline Proxy — Отключено")
        }
        button.image?.isTemplate = true
    }

    public func rebuildMenu() {
        menu.removeAllItems()

        // 0. Open Main Window
        let showWindowItem = NSMenuItem(title: "Показать Outline Proxy", action: #selector(openMainWindowAction), keyEquivalent: "o")
        showWindowItem.target = self
        menu.addItem(showWindowItem)

        menu.addItem(NSMenuItem.separator())

        // 1. Status Header
        let statusTitle: String
        let modeSuffix = " [\(AppState.shared.mode.shortTitle)]"
        switch AppState.shared.status {
        case .connected(let server):
            statusTitle = "● Подключено: \(server)\(modeSuffix)"
        case .connecting:
            statusTitle = "◌ Подключение...\(modeSuffix)"
        case .disconnecting:
            statusTitle = "◌ Отключение..."
        case .disconnected:
            statusTitle = "○ Отключено\(modeSuffix)"
        case .error(let msg):
            statusTitle = "⚠ Ошибка: \(msg)"
        }

        let headerItem = NSMenuItem(title: statusTitle, action: nil, keyEquivalent: "")
        headerItem.isEnabled = false
        menu.addItem(headerItem)

        // 2. Connect / Disconnect Toggle
        let toggleTitle = AppState.shared.isConnected ? "Отключить" : "Подключить"
        let toggleItem = NSMenuItem(title: toggleTitle, action: #selector(toggleAction), keyEquivalent: "c")
        toggleItem.target = self
        menu.addItem(toggleItem)

        menu.addItem(NSMenuItem.separator())

        // 3. Mode Selection
        let modeHeader = NSMenuItem(title: "Режим работы:", action: nil, keyEquivalent: "")
        modeHeader.isEnabled = false
        menu.addItem(modeHeader)

        let currentMode = AppState.shared.mode
        for mode in ProxyMode.allCases {
            let item = NSMenuItem(title: "   " + mode.title, action: #selector(selectModeAction(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = mode.rawValue
            item.state = (mode == currentMode) ? .on : .off
            menu.addItem(item)
        }

        menu.addItem(NSMenuItem.separator())

        // 4. Servers list
        let profiles = ProfileStore.shared.profiles
        if !profiles.isEmpty {
            let serversHeader = NSMenuItem(title: "Серверы:", action: nil, keyEquivalent: "")
            serversHeader.isEnabled = false
            menu.addItem(serversHeader)

            let activeId = ProfileStore.shared.activeProfileId
            for profile in profiles {
                let displayName = profile.name.isEmpty ? "Сервер" : profile.name
                let item = NSMenuItem(title: "   " + displayName, action: #selector(selectServerAction(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = profile.id
                item.state = (profile.id == activeId) ? .on : .off
                menu.addItem(item)
            }
        }

        // 5. Quick Actions
        let addItem = NSMenuItem(title: "Добавить сервер...", action: #selector(addServerAction), keyEquivalent: "a")
        addItem.target = self
        menu.addItem(addItem)

        let hasSubscriptions = profiles.contains { $0.isSubscription }
        if hasSubscriptions {
            let refreshItem = NSMenuItem(title: "Обновить подписки", action: #selector(refreshSubscriptionsAction), keyEquivalent: "r")
            refreshItem.target = self
            menu.addItem(refreshItem)
        }

        menu.addItem(NSMenuItem.separator())

        // 6. Diagnostics & Settings
        let logItem = NSMenuItem(title: "Журнал (логи)...", action: #selector(openLogsAction), keyEquivalent: "l")
        logItem.target = self
        menu.addItem(logItem)

        let settingsItem = NSMenuItem(title: "Настройки...", action: #selector(openSettingsAction), keyEquivalent: ",")
        settingsItem.target = self
        menu.addItem(settingsItem)

        // Theme selection submenu
        let themeMenu = NSMenu()
        for mode in AppThemeMode.allCases {
            let title: String
            switch mode {
            case .system: title = "Системная (авто)"
            case .light: title = "Светлая"
            case .dark: title = "Тёмная"
            }
            let itm = NSMenuItem(title: title, action: #selector(selectThemeModeAction(_:)), keyEquivalent: "")
            itm.target = self
            itm.representedObject = mode.rawValue
            itm.state = (ThemeManager.shared.mode == mode) ? .on : .off
            themeMenu.addItem(itm)
        }
        let themeItem = NSMenuItem(title: "Тема оформления", action: nil, keyEquivalent: "")
        themeItem.submenu = themeMenu
        menu.addItem(themeItem)

        menu.addItem(NSMenuItem.separator())

        // 7. Quit
        let quitItem = NSMenuItem(title: "Завершить Outline Proxy", action: #selector(quitAction), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)
    }

    @objc private func selectThemeModeAction(_ sender: NSMenuItem) {
        if let raw = sender.representedObject as? String, let m = AppThemeMode(rawValue: raw) {
            ThemeManager.shared.mode = m
        }
    }

    // MARK: - Actions

    @objc private func openMainWindowAction() {
        MainWindowController.shared.show()
    }

    @objc private func toggleAction() {
        AppState.shared.toggleConnection()
        NotificationCenter.default.post(name: NSNotification.Name("AppStateUpdated"), object: nil)
    }

    @objc private func selectModeAction(_ sender: NSMenuItem) {
        if let raw = sender.representedObject as? String, let newMode = ProxyMode(rawValue: raw) {
            AppState.shared.setMode(newMode)
        }
    }

    @objc private func selectServerAction(_ sender: NSMenuItem) {
        if let id = sender.representedObject as? String {
            AppState.shared.switchProfile(to: id)
            NotificationCenter.default.post(name: NSNotification.Name("AppStateUpdated"), object: nil)
        }
    }

    @objc private func addServerAction() {
        SettingsWindowController.shared.show()
    }

    @objc private func refreshSubscriptionsAction() {
        Task {
            for profile in ProfileStore.shared.profiles where profile.isSubscription {
                _ = try? await SubscriptionFetcher.updateSubscription(profile)
            }
            await MainActor.run {
                self.rebuildMenu()
            }
        }
    }

    @objc private func openLogsAction() {
        LogWindowController.shared.show()
    }

    @objc private func openSettingsAction() {
        SettingsWindowController.shared.show()
    }

    @objc private func quitAction() {
        AppState.shared.cleanupOnExit()
        NSApp.terminate(nil)
    }
}
