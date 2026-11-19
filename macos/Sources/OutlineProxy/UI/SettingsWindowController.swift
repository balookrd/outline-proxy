import AppKit

/// Pure AppKit window controller for managing system preferences (proxy mode, TCP only, TUN helper, appearance).
@MainActor
public final class SettingsWindowController: NSWindowController {
    public static let shared = SettingsWindowController()

    // MARK: - Block 1: Mode Selector
    private let modeBox = NSBox()
    private let bannerIcon = NSImageView()
    private let modeTitle = NSTextField(labelWithString: "Режим перехвата трафика")
    private let bannerSubtitle = NSTextField(labelWithString: "")
    private let modePopUpButton = NSPopUpButton()

    // MARK: - Block 2: TCP Only Box
    private let tcpOnlyBox = NSBox()
    private let tcpOnlyIcon = NSImageView()
    private let tcpOnlyTitle = NSTextField(labelWithString: "Режим «Только TCP» (без HTTP/3)")
    private let tcpOnlySubtitle = NSTextField(labelWithString: "Отключает QUIC/H3 (UDP 443) и переводит туннели на HTTP/2 / HTTP/1.1 для сетей с блокировкой UDP.")
    private let tcpOnlySwitch = NSSwitch()

    // MARK: - Block 3: TUN Passwordless Helper Box
    private let tunAuthBox = NSBox()
    private let tunAuthIcon = NSImageView()
    private let tunAuthTitle = NSTextField(labelWithString: "Режим TUN (VPN): запуск без пароля")
    private let tunAuthSubtitle = NSTextField(labelWithString: "")
    private let tunAuthButton = NSButton()

    // MARK: - Block 4: Theme Box
    private let themeBox = NSBox()
    private let themeIcon = NSImageView()
    private let themeTitle = NSTextField(labelWithString: "Тема оформления")
    private let themeSubtitle = NSTextField(labelWithString: "Внешний вид интерфейса: системный, светлый или тёмный режим.")
    private let themePopUpButton = NSPopUpButton()

    // MARK: - Footer
    private let versionLabel = NSTextField(labelWithString: AppVersion.displayString)
    private let closeButton = NSButton()

    private init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 440),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Настройки — Outline Proxy"
        window.center()
        window.isReleasedWhenClosed = false
        window.setContentSize(NSSize(width: 520, height: 440))

        super.init(window: window)

        setupUI()
        updateModeUI()
        updateTunAuthUI()
        updateTcpOnlyUI()
        updateThemeUI()
        applyTheme()

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

        DistributedNotificationCenter.default().addObserver(
            self,
            selector: #selector(handleThemeChanged),
            name: NSNotification.Name("AppleInterfaceThemeChangedNotification"),
            object: nil
        )
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    public func show() {
        updateModeUI()
        updateTunAuthUI()
        updateTcpOnlyUI()
        updateThemeUI()
        applyTheme()
        window?.makeKeyAndOrderFront(nil)
        window?.orderFrontRegardless()
        NSApp.activate(ignoringOtherApps: true)
    }

    private func setupUI() {
        guard let contentView = window?.contentView else { return }

        // 1. Mode Box
        modeBox.boxType = .custom
        modeBox.cornerRadius = 10
        modeBox.translatesAutoresizingMaskIntoConstraints = false

        bannerIcon.translatesAutoresizingMaskIntoConstraints = false

        modeTitle.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        modeTitle.translatesAutoresizingMaskIntoConstraints = false

        bannerSubtitle.font = NSFont.systemFont(ofSize: 11)
        bannerSubtitle.cell?.wraps = true
        bannerSubtitle.lineBreakMode = .byWordWrapping
        bannerSubtitle.maximumNumberOfLines = 2
        bannerSubtitle.translatesAutoresizingMaskIntoConstraints = false

        let modeTextStack = NSStackView(views: [modeTitle, bannerSubtitle])
        modeTextStack.orientation = .vertical
        modeTextStack.alignment = .leading
        modeTextStack.spacing = 3
        modeTextStack.translatesAutoresizingMaskIntoConstraints = false

        modePopUpButton.translatesAutoresizingMaskIntoConstraints = false
        modePopUpButton.removeAllItems()
        for mode in ProxyMode.allCases {
            modePopUpButton.addItem(withTitle: mode.title)
            modePopUpButton.lastItem?.representedObject = mode.rawValue
        }
        modePopUpButton.target = self
        modePopUpButton.action = #selector(modeChanged(_:))
        modePopUpButton.setContentHuggingPriority(.required, for: .horizontal)
        modePopUpButton.setContentCompressionResistancePriority(.required, for: .horizontal)

        modeBox.addSubview(bannerIcon)
        modeBox.addSubview(modeTextStack)
        modeBox.addSubview(modePopUpButton)

        // 2. TCP Only Box
        tcpOnlyBox.boxType = .custom
        tcpOnlyBox.cornerRadius = 10
        tcpOnlyBox.translatesAutoresizingMaskIntoConstraints = false

        tcpOnlyIcon.image = NSImage(systemSymbolName: "network.badge.shield.half.filled", accessibilityDescription: nil)
        tcpOnlyIcon.contentTintColor = NSColor.systemBlue
        tcpOnlyIcon.translatesAutoresizingMaskIntoConstraints = false

        tcpOnlyTitle.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        tcpOnlyTitle.translatesAutoresizingMaskIntoConstraints = false

        tcpOnlySubtitle.font = NSFont.systemFont(ofSize: 11)
        tcpOnlySubtitle.cell?.wraps = true
        tcpOnlySubtitle.lineBreakMode = .byWordWrapping
        tcpOnlySubtitle.maximumNumberOfLines = 2
        tcpOnlySubtitle.translatesAutoresizingMaskIntoConstraints = false

        let tcpTextStack = NSStackView(views: [tcpOnlyTitle, tcpOnlySubtitle])
        tcpTextStack.orientation = .vertical
        tcpTextStack.alignment = .leading
        tcpTextStack.spacing = 3
        tcpTextStack.translatesAutoresizingMaskIntoConstraints = false

        tcpOnlySwitch.translatesAutoresizingMaskIntoConstraints = false
        tcpOnlySwitch.target = self
        tcpOnlySwitch.action = #selector(tcpOnlyAction(_:))

        tcpOnlyBox.addSubview(tcpOnlyIcon)
        tcpOnlyBox.addSubview(tcpTextStack)
        tcpOnlyBox.addSubview(tcpOnlySwitch)

        // 3. TUN Auth Box
        tunAuthBox.boxType = .custom
        tunAuthBox.cornerRadius = 10
        tunAuthBox.translatesAutoresizingMaskIntoConstraints = false

        tunAuthIcon.translatesAutoresizingMaskIntoConstraints = false

        tunAuthTitle.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        tunAuthTitle.translatesAutoresizingMaskIntoConstraints = false

        tunAuthSubtitle.font = NSFont.systemFont(ofSize: 11)
        tunAuthSubtitle.cell?.wraps = true
        tunAuthSubtitle.lineBreakMode = .byWordWrapping
        tunAuthSubtitle.maximumNumberOfLines = 2
        tunAuthSubtitle.translatesAutoresizingMaskIntoConstraints = false

        let tunTextStack = NSStackView(views: [tunAuthTitle, tunAuthSubtitle])
        tunTextStack.orientation = .vertical
        tunTextStack.alignment = .leading
        tunTextStack.spacing = 3
        tunTextStack.translatesAutoresizingMaskIntoConstraints = false

        tunAuthButton.translatesAutoresizingMaskIntoConstraints = false
        tunAuthButton.bezelStyle = .rounded
        tunAuthButton.target = self
        tunAuthButton.action = #selector(tunAuthAction)
        tunAuthButton.setContentHuggingPriority(.required, for: .horizontal)
        tunAuthButton.setContentCompressionResistancePriority(.required, for: .horizontal)

        tunAuthBox.addSubview(tunAuthIcon)
        tunAuthBox.addSubview(tunTextStack)
        tunAuthBox.addSubview(tunAuthButton)

        // 4. Theme Box
        themeBox.boxType = .custom
        themeBox.cornerRadius = 10
        themeBox.translatesAutoresizingMaskIntoConstraints = false

        themeIcon.image = NSImage(systemSymbolName: "circle.lefthalf.filled", accessibilityDescription: "Тема оформления")
        themeIcon.contentTintColor = NSColor.systemPurple
        themeIcon.translatesAutoresizingMaskIntoConstraints = false

        themeTitle.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        themeTitle.translatesAutoresizingMaskIntoConstraints = false

        themeSubtitle.font = NSFont.systemFont(ofSize: 11)
        themeSubtitle.cell?.wraps = true
        themeSubtitle.lineBreakMode = .byWordWrapping
        themeSubtitle.maximumNumberOfLines = 2
        themeSubtitle.translatesAutoresizingMaskIntoConstraints = false

        let themeTextStack = NSStackView(views: [themeTitle, themeSubtitle])
        themeTextStack.orientation = .vertical
        themeTextStack.alignment = .leading
        themeTextStack.spacing = 3
        themeTextStack.translatesAutoresizingMaskIntoConstraints = false

        themePopUpButton.translatesAutoresizingMaskIntoConstraints = false
        themePopUpButton.removeAllItems()
        themePopUpButton.addItem(withTitle: "Системная")
        themePopUpButton.lastItem?.representedObject = AppThemeMode.system.rawValue
        themePopUpButton.addItem(withTitle: "Светлая")
        themePopUpButton.lastItem?.representedObject = AppThemeMode.light.rawValue
        themePopUpButton.addItem(withTitle: "Тёмная")
        themePopUpButton.lastItem?.representedObject = AppThemeMode.dark.rawValue
        themePopUpButton.target = self
        themePopUpButton.action = #selector(themeChanged(_:))
        themePopUpButton.setContentHuggingPriority(.required, for: .horizontal)
        themePopUpButton.setContentCompressionResistancePriority(.required, for: .horizontal)

        themeBox.addSubview(themeIcon)
        themeBox.addSubview(themeTextStack)
        themeBox.addSubview(themePopUpButton)

        // Footer
        versionLabel.font = NSFont.systemFont(ofSize: 11, weight: .regular)
        versionLabel.toolTip = AppVersion.fullDiagnosticString
        versionLabel.translatesAutoresizingMaskIntoConstraints = false

        closeButton.title = "Закрыть"
        closeButton.bezelStyle = .rounded
        closeButton.target = self
        closeButton.action = #selector(closeAction)
        closeButton.keyEquivalent = "\r"
        closeButton.translatesAutoresizingMaskIntoConstraints = false

        let spacer = NSView()
        spacer.translatesAutoresizingMaskIntoConstraints = false
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let bottomStack = NSStackView(views: [versionLabel, spacer, closeButton])
        bottomStack.orientation = .horizontal
        bottomStack.alignment = .centerY
        bottomStack.translatesAutoresizingMaskIntoConstraints = false

        contentView.addSubview(modeBox)
        contentView.addSubview(tcpOnlyBox)
        contentView.addSubview(tunAuthBox)
        contentView.addSubview(themeBox)
        contentView.addSubview(bottomStack)

        NSLayoutConstraint.activate([
            // Block 1: Mode
            modeBox.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 18),
            modeBox.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            modeBox.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            modeBox.heightAnchor.constraint(equalToConstant: 76),

            bannerIcon.leadingAnchor.constraint(equalTo: modeBox.leadingAnchor, constant: 14),
            bannerIcon.centerYAnchor.constraint(equalTo: modeBox.centerYAnchor),
            bannerIcon.widthAnchor.constraint(equalToConstant: 24),
            bannerIcon.heightAnchor.constraint(equalToConstant: 24),

            modeTextStack.leadingAnchor.constraint(equalTo: bannerIcon.trailingAnchor, constant: 12),
            modeTextStack.centerYAnchor.constraint(equalTo: modeBox.centerYAnchor),
            modeTextStack.trailingAnchor.constraint(lessThanOrEqualTo: modePopUpButton.leadingAnchor, constant: -12),

            modePopUpButton.trailingAnchor.constraint(equalTo: modeBox.trailingAnchor, constant: -14),
            modePopUpButton.centerYAnchor.constraint(equalTo: modeBox.centerYAnchor),

            // Block 2: TCP Only
            tcpOnlyBox.topAnchor.constraint(equalTo: modeBox.bottomAnchor, constant: 14),
            tcpOnlyBox.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            tcpOnlyBox.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            tcpOnlyBox.heightAnchor.constraint(equalToConstant: 76),

            tcpOnlyIcon.leadingAnchor.constraint(equalTo: tcpOnlyBox.leadingAnchor, constant: 14),
            tcpOnlyIcon.centerYAnchor.constraint(equalTo: tcpOnlyBox.centerYAnchor),
            tcpOnlyIcon.widthAnchor.constraint(equalToConstant: 22),
            tcpOnlyIcon.heightAnchor.constraint(equalToConstant: 22),

            tcpTextStack.leadingAnchor.constraint(equalTo: tcpOnlyIcon.trailingAnchor, constant: 12),
            tcpTextStack.centerYAnchor.constraint(equalTo: tcpOnlyBox.centerYAnchor),
            tcpTextStack.trailingAnchor.constraint(lessThanOrEqualTo: tcpOnlySwitch.leadingAnchor, constant: -12),

            tcpOnlySwitch.trailingAnchor.constraint(equalTo: tcpOnlyBox.trailingAnchor, constant: -14),
            tcpOnlySwitch.centerYAnchor.constraint(equalTo: tcpOnlyBox.centerYAnchor),

            // Block 3: TUN Auth
            tunAuthBox.topAnchor.constraint(equalTo: tcpOnlyBox.bottomAnchor, constant: 14),
            tunAuthBox.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            tunAuthBox.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            tunAuthBox.heightAnchor.constraint(equalToConstant: 76),

            tunAuthIcon.leadingAnchor.constraint(equalTo: tunAuthBox.leadingAnchor, constant: 14),
            tunAuthIcon.centerYAnchor.constraint(equalTo: tunAuthBox.centerYAnchor),
            tunAuthIcon.widthAnchor.constraint(equalToConstant: 22),
            tunAuthIcon.heightAnchor.constraint(equalToConstant: 22),

            tunTextStack.leadingAnchor.constraint(equalTo: tunAuthIcon.trailingAnchor, constant: 12),
            tunTextStack.centerYAnchor.constraint(equalTo: tunAuthBox.centerYAnchor),
            tunTextStack.trailingAnchor.constraint(lessThanOrEqualTo: tunAuthButton.leadingAnchor, constant: -12),

            tunAuthButton.trailingAnchor.constraint(equalTo: tunAuthBox.trailingAnchor, constant: -14),
            tunAuthButton.centerYAnchor.constraint(equalTo: tunAuthBox.centerYAnchor),

            // Block 4: Theme
            themeBox.topAnchor.constraint(equalTo: tunAuthBox.bottomAnchor, constant: 14),
            themeBox.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            themeBox.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            themeBox.heightAnchor.constraint(equalToConstant: 76),

            themeIcon.leadingAnchor.constraint(equalTo: themeBox.leadingAnchor, constant: 14),
            themeIcon.centerYAnchor.constraint(equalTo: themeBox.centerYAnchor),
            themeIcon.widthAnchor.constraint(equalToConstant: 22),
            themeIcon.heightAnchor.constraint(equalToConstant: 22),

            themeTextStack.leadingAnchor.constraint(equalTo: themeIcon.trailingAnchor, constant: 12),
            themeTextStack.centerYAnchor.constraint(equalTo: themeBox.centerYAnchor),
            themeTextStack.trailingAnchor.constraint(lessThanOrEqualTo: themePopUpButton.leadingAnchor, constant: -12),

            themePopUpButton.trailingAnchor.constraint(equalTo: themeBox.trailingAnchor, constant: -14),
            themePopUpButton.centerYAnchor.constraint(equalTo: themeBox.centerYAnchor),

            // Footer
            bottomStack.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            bottomStack.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            bottomStack.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -16),
            bottomStack.heightAnchor.constraint(equalToConstant: 32)
        ])
    }

    private func applyTheme() {
        guard let win = window else { return }
        let palette = ThemeManager.shared.palette(for: win)

        win.appearance = palette.isDark ? NSAppearance(named: .darkAqua) : NSAppearance(named: .aqua)
        win.backgroundColor = palette.windowBackground

        let boxes = [modeBox, tcpOnlyBox, tunAuthBox, themeBox]
        for box in boxes {
            box.fillColor = palette.contentCardBg
            box.borderColor = palette.cardBorder
            box.borderWidth = 1.0
        }

        modeTitle.textColor = palette.primaryText
        tcpOnlyTitle.textColor = palette.primaryText
        tunAuthTitle.textColor = palette.primaryText
        themeTitle.textColor = palette.primaryText

        bannerSubtitle.textColor = palette.secondaryText
        tcpOnlySubtitle.textColor = palette.secondaryText
        themeSubtitle.textColor = palette.secondaryText
        versionLabel.textColor = palette.secondaryText

        updateTunAuthUI()
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
            bannerIcon.contentTintColor = NSColor.systemBlue
        }
    }

    @objc private func modeChanged(_ sender: NSPopUpButton) {
        guard let item = sender.selectedItem,
              let raw = item.representedObject as? String,
              let newMode = ProxyMode(rawValue: raw) else { return }

        AppState.shared.setMode(newMode)
        updateModeUI()
    }

    private func updateTcpOnlyUI() {
        tcpOnlySwitch.state = AppState.shared.tcpOnly ? .on : .off
    }

    @objc private func tcpOnlyAction(_ sender: NSSwitch) {
        AppState.shared.setTcpOnly(sender.state == .on)
    }

    private func updateTunAuthUI() {
        let isConfigured = PrivilegedHelperManager.shared.isSudoersConfigured()
        let palette = ThemeManager.shared.palette(for: window)
        if isConfigured {
            tunAuthIcon.image = NSImage(systemSymbolName: "checkmark.shield.fill", accessibilityDescription: "Настроено")
            tunAuthIcon.contentTintColor = palette.statusGreen
            tunAuthSubtitle.stringValue = "Настроено: TUN (VPN) подключается в 1 клик без ввода пароля."
            tunAuthSubtitle.textColor = palette.statusGreen
            tunAuthButton.title = "Удалить правило"
        } else {
            tunAuthIcon.image = NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "Требуется пароль")
            tunAuthIcon.contentTintColor = palette.statusAmber
            tunAuthSubtitle.stringValue = "Требуется ввод пароля. Нажмите, чтобы разрешить запуск в 1 клик."
            tunAuthSubtitle.textColor = palette.secondaryText
            tunAuthButton.title = "Настроить в 1 клик..."
        }
    }

    @objc private func tunAuthAction() {
        let isConfigured = PrivilegedHelperManager.shared.isSudoersConfigured()
        if isConfigured {
            let alert = NSAlert()
            alert.messageText = "Удалить правило беспарольного доступа?"
            alert.informativeText = "После удаления при каждом подключении TUN (VPN) снова потребуется вводить системный пароль администратора."
            alert.addButton(withTitle: "Удалить")
            alert.addButton(withTitle: "Отмена")
            alert.alertStyle = .warning
            if alert.runModal() == .alertFirstButtonReturn {
                do {
                    try PrivilegedHelperManager.shared.removeSudoersRule()
                    updateTunAuthUI()
                    NotificationCenter.default.post(name: NSNotification.Name("AppStateUpdated"), object: nil)
                } catch {
                    NSAlert(error: error).runModal()
                }
            }
        } else {
            do {
                try PrivilegedHelperManager.shared.installSudoersRule()
                updateTunAuthUI()
                NotificationCenter.default.post(name: NSNotification.Name("AppStateUpdated"), object: nil)

                let alert = NSAlert()
                alert.messageText = "Беспарольный доступ настроен!"
                alert.informativeText = "Теперь полноэкранный L3 TUN туннель подключается и отключается мгновенно в один клик без запроса системного пароля."
                alert.addButton(withTitle: "Отлично")
                alert.runModal()
            } catch {
                NSAlert(error: error).runModal()
            }
        }
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
        applyTheme()
    }

    @objc private func handleThemeChanged() {
        updateThemeUI()
        applyTheme()
    }

    @objc private func handleAppStateUpdated() {
        updateModeUI()
        updateTunAuthUI()
        updateTcpOnlyUI()
    }

    @objc private func closeAction() {
        window?.close()
    }
}
