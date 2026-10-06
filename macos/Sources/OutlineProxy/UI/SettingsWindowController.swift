import AppKit

/// Pure AppKit window controller for managing server profiles, subscriptions, and proxy modes.
@MainActor
public final class SettingsWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate {
    public static let shared = SettingsWindowController()

    private let tableView = NSTableView()
    private var profiles: [ServerProfile] = []

    private let bannerIcon = NSImageView()
    private let modePopUpButton = NSPopUpButton()
    private let themePopUpButton = NSPopUpButton()
    private let bannerSubtitle = NSTextField(labelWithString: "")

    private init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 700, height: 460),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Настройки — Outline Proxy"
        window.center()
        window.isReleasedWhenClosed = false

        super.init(window: window)

        setupUI()

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleAppStateUpdated),
            name: NSNotification.Name("AppStateUpdated"),
            object: nil
        )

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleThemeChanged),
            name: ThemeManager.themeChangedNotification,
            object: nil
        )
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    private func setupUI() {
        guard let contentView = window?.contentView else { return }

        // 1. Top banner (Mode Selector)
        let bannerBox = NSBox()
        bannerBox.boxType = .custom
        bannerBox.fillColor = NSColor.controlBackgroundColor
        bannerBox.cornerRadius = 8
        bannerBox.translatesAutoresizingMaskIntoConstraints = false

        bannerIcon.translatesAutoresizingMaskIntoConstraints = false

        modePopUpButton.translatesAutoresizingMaskIntoConstraints = false
        modePopUpButton.removeAllItems()
        for mode in ProxyMode.allCases {
            modePopUpButton.addItem(withTitle: mode.title)
            modePopUpButton.lastItem?.representedObject = mode.rawValue
        }
        modePopUpButton.target = self
        modePopUpButton.action = #selector(modeChanged(_:))

        bannerSubtitle.font = NSFont.systemFont(ofSize: 11)
        bannerSubtitle.textColor = .secondaryLabelColor
        bannerSubtitle.translatesAutoresizingMaskIntoConstraints = false

        let bannerTextStack = NSStackView(views: [modePopUpButton, bannerSubtitle])
        bannerTextStack.orientation = .vertical
        bannerTextStack.alignment = .leading
        bannerTextStack.spacing = 4
        bannerTextStack.translatesAutoresizingMaskIntoConstraints = false

        themePopUpButton.translatesAutoresizingMaskIntoConstraints = false
        themePopUpButton.removeAllItems()
        themePopUpButton.addItem(withTitle: "Тема: Системная")
        themePopUpButton.lastItem?.representedObject = AppThemeMode.system.rawValue
        themePopUpButton.addItem(withTitle: "Тема: Светлая")
        themePopUpButton.lastItem?.representedObject = AppThemeMode.light.rawValue
        themePopUpButton.addItem(withTitle: "Тема: Тёмная")
        themePopUpButton.lastItem?.representedObject = AppThemeMode.dark.rawValue
        themePopUpButton.target = self
        themePopUpButton.action = #selector(themeChanged(_:))
        updateThemeUI()

        bannerBox.addSubview(bannerIcon)
        bannerBox.addSubview(bannerTextStack)
        bannerBox.addSubview(themePopUpButton)

        NSLayoutConstraint.activate([
            bannerIcon.leadingAnchor.constraint(equalTo: bannerBox.leadingAnchor, constant: 14),
            bannerIcon.centerYAnchor.constraint(equalTo: bannerBox.centerYAnchor),
            bannerIcon.widthAnchor.constraint(equalToConstant: 26),
            bannerIcon.heightAnchor.constraint(equalToConstant: 26),

            bannerTextStack.leadingAnchor.constraint(equalTo: bannerIcon.trailingAnchor, constant: 12),
            bannerTextStack.centerYAnchor.constraint(equalTo: bannerBox.centerYAnchor),

            themePopUpButton.trailingAnchor.constraint(equalTo: bannerBox.trailingAnchor, constant: -14),
            themePopUpButton.centerYAnchor.constraint(equalTo: bannerBox.centerYAnchor),
            bannerTextStack.trailingAnchor.constraint(lessThanOrEqualTo: themePopUpButton.leadingAnchor, constant: -12),
            bannerBox.heightAnchor.constraint(equalToConstant: 58)
        ])

        updateModeUI()

        // 2. Table view for profiles
        let colActive = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("Active"))
        colActive.title = "Статус"
        colActive.width = 65

        let colName = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("Name"))
        colName.title = "Имя сервера"
        colName.width = 160

        let colType = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("Type"))
        colType.title = "Протокол"
        colType.width = 85

        let colLink = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("Link"))
        colLink.title = "Ссылка подключения / URL подписки"
        colLink.width = 330

        tableView.addTableColumn(colActive)
        tableView.addTableColumn(colName)
        tableView.addTableColumn(colType)
        tableView.addTableColumn(colLink)
        tableView.dataSource = self
        tableView.delegate = self
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.rowHeight = 24

        let scroll = NSScrollView()
        scroll.documentView = tableView
        scroll.hasVerticalScroller = true
        scroll.translatesAutoresizingMaskIntoConstraints = false

        // 3. Buttons toolbar
        let addButton = NSButton(title: "Добавить...", target: self, action: #selector(addAction))
        let pasteButton = NSButton(title: "Вставить из буфера", target: self, action: #selector(pasteAction))
        let selectButton = NSButton(title: "Сделать активным", target: self, action: #selector(selectAction))
        let removeButton = NSButton(title: "Удалить", target: self, action: #selector(removeAction))
        let closeButton = NSButton(title: "Закрыть", target: self, action: #selector(closeAction))

        let leftButtons = NSStackView(views: [addButton, pasteButton, selectButton, removeButton])
        leftButtons.orientation = .horizontal
        leftButtons.spacing = 8
        leftButtons.translatesAutoresizingMaskIntoConstraints = false

        let bottomStack = NSStackView(views: [leftButtons, NSView(), closeButton])
        bottomStack.orientation = .horizontal
        bottomStack.translatesAutoresizingMaskIntoConstraints = false

        contentView.addSubview(bannerBox)
        contentView.addSubview(scroll)
        contentView.addSubview(bottomStack)

        NSLayoutConstraint.activate([
            bannerBox.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 12),
            bannerBox.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 12),
            bannerBox.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -12),

            scroll.topAnchor.constraint(equalTo: bannerBox.bottomAnchor, constant: 12),
            scroll.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 12),
            scroll.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -12),
            scroll.bottomAnchor.constraint(equalTo: bottomStack.topAnchor, constant: -12),

            bottomStack.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 12),
            bottomStack.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -12),
            bottomStack.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -12),
            bottomStack.heightAnchor.constraint(equalToConstant: 30)
        ])
    }

    public func show() {
        reloadProfiles()
        updateModeUI()
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func updateModeUI() {
        let currentMode = AppState.shared.mode
        for (index, item) in modePopUpButton.itemArray.enumerated() {
            if let raw = item.representedObject as? String, raw == currentMode.rawValue {
                modePopUpButton.selectItem(at: index)
                break
            }
        }

        bannerSubtitle.stringValue = currentMode.summary
        if let iconURL = Bundle.main.url(forResource: "AppIcon_round", withExtension: "png") ??
                         Bundle.main.url(forResource: "AppIcon", withExtension: "png"),
           let img = NSImage(contentsOf: iconURL) {
            bannerIcon.image = img
        } else {
            let iconName = (currentMode == .tun) ? "shield.fill" : "network"
            bannerIcon.image = NSImage(systemSymbolName: iconName, accessibilityDescription: nil)
        }
    }

    @objc private func modeChanged(_ sender: NSPopUpButton) {
        guard let item = sender.selectedItem,
              let raw = item.representedObject as? String,
              let newMode = ProxyMode(rawValue: raw) else { return }

        AppState.shared.setMode(newMode)
        updateModeUI()
    }

    @objc private func handleAppStateUpdated() {
        updateModeUI()
        reloadProfiles()
    }

    private func updateThemeUI() {
        let currentTheme = ThemeManager.shared.mode
        for (index, item) in themePopUpButton.itemArray.enumerated() {
            if let raw = item.representedObject as? String, raw == currentTheme.rawValue {
                themePopUpButton.selectItem(at: index)
                break
            }
        }
    }

    @objc private func themeChanged(_ sender: NSPopUpButton) {
        guard let item = sender.selectedItem,
              let raw = item.representedObject as? String,
              let newTheme = AppThemeMode(rawValue: raw) else { return }

        ThemeManager.shared.mode = newTheme
    }

    @objc private func handleThemeChanged() {
        updateThemeUI()
    }

    private func reloadProfiles() {
        profiles = ProfileStore.shared.profiles
        tableView.reloadData()
    }

    // MARK: - NSTableViewDataSource & Delegate

    public func numberOfRows(in tableView: NSTableView) -> Int {
        return profiles.count
    }

    public func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row < profiles.count, let col = tableColumn else { return nil }
        let profile = profiles[row]
        let isActive = (profile.id == ProfileStore.shared.activeProfileId)

        let cell = NSTextField(labelWithString: "")
        cell.font = NSFont.systemFont(ofSize: 12)

        switch col.identifier.rawValue {
        case "Active":
            cell.stringValue = isActive ? "● АКТИВЕН" : ""
            cell.font = NSFont.boldSystemFont(ofSize: 10)
            cell.textColor = isActive ? .systemGreen : .secondaryLabelColor
        case "Name":
            cell.stringValue = profile.name.isEmpty ? "Без названия" : profile.name
            if isActive { cell.font = NSFont.boldSystemFont(ofSize: 12) }
        case "Type":
            cell.stringValue = profile.isSubscription ? "Подписка" : profile.transport.uppercased()
        case "Link":
            cell.stringValue = profile.isSubscription ? profile.configUrl : profile.link
            cell.textColor = .secondaryLabelColor
            cell.cell?.truncatesLastVisibleLine = true
        default:
            break
        }
        return cell
    }

    // MARK: - Actions

    @objc private func addAction() {
        let alert = NSAlert()
        alert.messageText = "Добавить сервер или подписку"
        alert.informativeText = "Вставьте ссылку vless://, ss:// или URL подписки https://:"
        alert.alertStyle = .informational

        let input = NSTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 24))
        input.placeholderString = "vless://..., ss://... или https://..."
        alert.accessoryView = input

        alert.addButton(withTitle: "Добавить")
        alert.addButton(withTitle: "Отмена")

        let resp = alert.runModal()
        if resp == .alertFirstButtonReturn {
            let text = input.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if let profile = ServerProfile.from(link: text) {
                ProfileStore.shared.addProfile(profile)
                reloadProfiles()
                if profile.isSubscription {
                    Task {
                        _ = try? await SubscriptionFetcher.updateSubscription(profile)
                        await MainActor.run {
                            self.reloadProfiles()
                        }
                    }
                }
            } else {
                showError("Не удалось распознать ссылку. Поддерживаются vless://, ss:// и https://.")
            }
        }
    }

    @objc private func pasteAction() {
        guard let text = NSPasteboard.general.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !text.isEmpty else {
            showError("Буфер обмена пуст.")
            return
        }

        if let profile = ServerProfile.from(link: text) {
            ProfileStore.shared.addProfile(profile)
            reloadProfiles()
            if profile.isSubscription {
                Task {
                    _ = try? await SubscriptionFetcher.updateSubscription(profile)
                    await MainActor.run {
                        self.reloadProfiles()
                    }
                }
            }
        } else {
            showError("Не удалось распознать ссылку vless://, ss:// или URL подписки в буфере обмена.")
        }
    }

    @objc private func selectAction() {
        let row = tableView.selectedRow
        guard row >= 0 && row < profiles.count else { return }
        let profile = profiles[row]
        AppState.shared.switchProfile(to: profile.id)
        reloadProfiles()
    }

    @objc private func removeAction() {
        let row = tableView.selectedRow
        guard row >= 0 && row < profiles.count else { return }
        let profile = profiles[row]
        ProfileStore.shared.removeProfile(id: profile.id)
        reloadProfiles()
    }

    @objc private func closeAction() {
        window?.close()
    }

    private func showError(_ msg: String) {
        let alert = NSAlert()
        alert.messageText = "Ошибка"
        alert.informativeText = msg
        alert.alertStyle = .warning
        alert.runModal()
    }
}
