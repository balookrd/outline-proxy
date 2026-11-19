import AppKit

/// Pure AppKit window controller dedicated to managing server profiles and subscriptions.
@MainActor
public final class ServersWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate {
    public static let shared = ServersWindowController()

    private let tableView = NSTableView()
    private var profiles: [ServerProfile] = []
    private let activateButton = NSButton()
    private let addButton = NSButton()
    private let renameButton = NSButton()
    private let removeButton = NSButton()

    private init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 680, height: 460),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Серверы и подписки — Outline Proxy"
        window.center()
        window.isReleasedWhenClosed = false

        super.init(window: window)

        setupUI()
        reloadProfiles()

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleProfilesChanged),
            name: NSNotification.Name("ProfilesChanged"),
            object: nil
        )

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleProfilesChanged),
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

    public func show() {
        applyTheme()
        reloadProfiles()

        if let mainWin = MainWindowController.shared.window, mainWin.isVisible {
            let mainFrame = mainWin.frame
            if let win = window {
                let x = mainFrame.origin.x + (mainFrame.width - win.frame.width) / 2.0
                let y = mainFrame.origin.y + (mainFrame.height - win.frame.height) / 2.0
                win.setFrameOrigin(NSPoint(x: x, y: y))
            }
        } else {
            window?.center()
        }

        window?.makeKeyAndOrderFront(nil)
        window?.orderFrontRegardless()
        NSApp.activate(ignoringOtherApps: true)
    }

    private func setupUI() {
        guard let contentView = window?.contentView else { return }

        let scrollView = NSScrollView()
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = false
        scrollView.borderType = .bezelBorder

        tableView.delegate = self
        tableView.dataSource = self
        tableView.rowHeight = 32
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.target = self
        tableView.doubleAction = #selector(activateAction)

        let colActive = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("Active"))
        colActive.title = "Статус"
        colActive.width = 90
        tableView.addTableColumn(colActive)

        let colName = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("Name"))
        colName.title = "Название"
        colName.width = 160
        tableView.addTableColumn(colName)

        let colType = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("Type"))
        colType.title = "Тип"
        colType.width = 120
        tableView.addTableColumn(colType)

        let colLink = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("Link"))
        colLink.title = "Ссылка / URL подписки"
        colLink.width = 270
        tableView.addTableColumn(colLink)

        scrollView.documentView = tableView

        // Table context menu
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "Сделать активным", action: #selector(activateAction), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Переименовать...", action: #selector(renameAction), keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Удалить", action: #selector(removeAction), keyEquivalent: ""))
        tableView.menu = menu

        // Button bar
        activateButton.title = "Сделать активным"
        activateButton.bezelStyle = .rounded
        activateButton.target = self
        activateButton.action = #selector(activateAction)

        addButton.title = "+ Добавить сервер"
        addButton.bezelStyle = .rounded
        addButton.target = self
        addButton.action = #selector(addAction)

        renameButton.title = "Переименовать"
        renameButton.bezelStyle = .rounded
        renameButton.target = self
        renameButton.action = #selector(renameAction)

        removeButton.title = "Удалить"
        removeButton.bezelStyle = .rounded
        removeButton.target = self
        removeButton.action = #selector(removeAction)

        let buttonStack = NSStackView(views: [activateButton, addButton, renameButton, removeButton])
        buttonStack.orientation = .horizontal
        buttonStack.spacing = 10
        buttonStack.translatesAutoresizingMaskIntoConstraints = false

        contentView.addSubview(scrollView)
        contentView.addSubview(buttonStack)

        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 16),
            scrollView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            scrollView.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            scrollView.bottomAnchor.constraint(equalTo: buttonStack.topAnchor, constant: -16),

            buttonStack.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            buttonStack.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -16),
        ])
    }

    private func reloadProfiles() {
        profiles = ProfileStore.shared.profiles
        tableView.reloadData()
    }

    private func applyTheme() {
        guard let win = window else { return }
        let palette = ThemeManager.shared.palette(for: win)
        win.appearance = palette.isDark ? NSAppearance(named: .darkAqua) : NSAppearance(named: .aqua)
        win.backgroundColor = palette.windowBackground
    }

    @objc private func handleProfilesChanged() {
        reloadProfiles()
    }

    @objc private func handleThemeChanged() {
        applyTheme()
        tableView.reloadData()
    }

    // MARK: - Table View

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
            cell.stringValue = profile.displayName
            if isActive { cell.font = NSFont.boldSystemFont(ofSize: 12) }
        case "Type":
            let isTcpOnly = profile.tcpOnly || AppState.shared.tcpOnly
            let baseType = profile.isSubscription ? "Подписка" : profile.transport.uppercased()
            cell.stringValue = isTcpOnly ? "\(baseType) (TCP)" : baseType
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

    @objc private func activateAction() {
        let row = tableView.selectedRow
        guard row >= 0 && row < profiles.count else { return }
        let profile = profiles[row]
        ProfileStore.shared.selectProfile(id: profile.id)
        tableView.reloadData()
    }

    @objc private func addAction() {
        let alert = NSAlert()
        alert.messageText = "Добавить сервер или подписку"
        alert.informativeText = "Вставьте ссылку vless://, ss:// или URL подписки https://:"

        let input = NSTextField(frame: NSRect(x: 0, y: 0, width: 440, height: 24))
        input.placeholderString = "vless://... или https://..."
        alert.accessoryView = input

        alert.addButton(withTitle: "Добавить")
        alert.addButton(withTitle: "Отмена")

        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let text = input.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }

        if text.hasPrefix("http://") || text.hasPrefix("https://") {
            let profile = ServerProfile(
                name: "Подписка",
                transport: "vless",
                link: "",
                configUrl: text
            )
            ProfileStore.shared.addProfile(profile)
            Task { [weak self] in
                if let updated = try? await SubscriptionFetcher.updateSubscription(profile) {
                    await MainActor.run {
                        ProfileStore.shared.updateProfile(updated)
                        self?.reloadProfiles()
                    }
                }
            }
        } else if let profile = ServerProfile.from(link: text) {
            ProfileStore.shared.addProfile(profile)
        } else {
            let errorAlert = NSAlert()
            errorAlert.messageText = "Не удалось распознать ссылку. Поддерживаются ссылки vless://, ss:// и URL подписок https://"
            errorAlert.alertStyle = .warning
            errorAlert.addButton(withTitle: "OK")
            errorAlert.runModal()
            return
        }
        reloadProfiles()
    }

    @objc private func renameAction() {
        let row = tableView.selectedRow
        guard row >= 0 && row < profiles.count else { return }
        let profile = profiles[row]

        let alert = NSAlert()
        alert.messageText = "Переименовать сервер или подписку"
        alert.informativeText = "Введите новое название для «\(profile.displayName)»:"

        let input = NSTextField(frame: NSRect(x: 0, y: 0, width: 340, height: 24))
        input.stringValue = profile.displayName
        alert.accessoryView = input

        alert.addButton(withTitle: "Сохранить")
        alert.addButton(withTitle: "Отмена")

        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let newName = input.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !newName.isEmpty else { return }

        var updated = profile
        updated.name = newName
        ProfileStore.shared.updateProfile(updated)
        reloadProfiles()
    }

    @objc private func removeAction() {
        let row = tableView.selectedRow
        guard row >= 0 && row < profiles.count else { return }
        let profile = profiles[row]

        let alert = NSAlert()
        alert.messageText = "Удалить сервер?"
        alert.informativeText = "Вы действительно хотите удалить «\(profile.displayName)»?"
        alert.addButton(withTitle: "Удалить")
        alert.addButton(withTitle: "Отмена")
        alert.buttons.first?.hasDestructiveAction = true

        guard alert.runModal() == .alertFirstButtonReturn else { return }
        ProfileStore.shared.removeProfile(id: profile.id)
        reloadProfiles()
    }
}
