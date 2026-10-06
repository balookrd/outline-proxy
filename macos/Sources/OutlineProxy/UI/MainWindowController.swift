import AppKit
import Foundation

// MARK: - Custom Views

/// Image view without intrinsic content size, avoiding autolayout blown ups.
final class DecorativeImageView: NSImageView {
    override var intrinsicContentSize: NSSize {
        return NSSize(width: NSView.noIntrinsicMetric, height: NSView.noIntrinsicMetric)
    }
}

/// Material card view matching Android rounded surfaces with border.
final class AndroidCardView: NSView {
    init(cornerRadius: CGFloat = 26) {
        super.init(frame: .zero)
        wantsLayer = true
        layer?.cornerRadius = cornerRadius
        layer?.masksToBounds = true
        layer?.borderWidth = 1.0
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func applyTheme(bg: NSColor, border: NSColor) {
        layer?.backgroundColor = bg.cgColor
        layer?.borderColor = border.cgColor
    }
}

/// Quick link circle item (48pt circular bubble with icon and 2-line title below).
final class AndroidQuickLinkItem: NSView {
    private let bubble = NSView()
    private let iconView = NSImageView()
    private let titleLabel = NSTextField(labelWithString: "")
    private let onClick: () -> Void

    init(title: String, symbol: String, onClick: @escaping () -> Void) {
        self.onClick = onClick
        super.init(frame: .zero)
        setup(title: title, symbol: symbol)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    private func setup(title: String, symbol: String) {
        wantsLayer = true
        translatesAutoresizingMaskIntoConstraints = false

        bubble.wantsLayer = true
        bubble.layer?.cornerRadius = 26
        bubble.translatesAutoresizingMaskIntoConstraints = false
        addSubview(bubble)

        iconView.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
        iconView.imageScaling = .scaleProportionallyUpOrDown
        iconView.translatesAutoresizingMaskIntoConstraints = false
        bubble.addSubview(iconView)

        titleLabel.stringValue = title
        titleLabel.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        titleLabel.alignment = .center
        titleLabel.maximumNumberOfLines = 1
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        addSubview(titleLabel)

        NSLayoutConstraint.activate([
            bubble.topAnchor.constraint(equalTo: topAnchor),
            bubble.centerXAnchor.constraint(equalTo: centerXAnchor),
            bubble.widthAnchor.constraint(equalToConstant: 52),
            bubble.heightAnchor.constraint(equalToConstant: 52),

            iconView.centerXAnchor.constraint(equalTo: bubble.centerXAnchor),
            iconView.centerYAnchor.constraint(equalTo: bubble.centerYAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 24),
            iconView.heightAnchor.constraint(equalToConstant: 24),

            titleLabel.topAnchor.constraint(equalTo: bubble.bottomAnchor, constant: 8),
            titleLabel.centerXAnchor.constraint(equalTo: centerXAnchor),
            titleLabel.leadingAnchor.constraint(greaterThanOrEqualTo: leadingAnchor),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor),
            titleLabel.bottomAnchor.constraint(equalTo: bottomAnchor)
        ])

        let click = NSClickGestureRecognizer(target: self, action: #selector(handleClick))
        addGestureRecognizer(click)
    }

    func applyTheme(bubbleBg: NSColor, iconColor: NSColor, textColor: NSColor) {
        bubble.layer?.backgroundColor = bubbleBg.cgColor
        iconView.contentTintColor = iconColor
        titleLabel.textColor = textColor
    }

    @objc private func handleClick() {
        onClick()
    }
}

/// Material pill action button with strictly centered icon and title, avoiding AppKit NSButtonCell margin bugs.
final class ActionPillButton: NSButton {
    private let contentStack = NSStackView()
    private let iconImageView = NSImageView()
    private let titleLabel = NSTextField(labelWithString: "")

    init(title: String, icon: NSImage? = nil, font: NSFont = .systemFont(ofSize: 14, weight: .bold), cornerRadius: CGFloat = 20) {
        super.init(frame: .zero)
        self.isBordered = false
        self.bezelStyle = .regularSquare
        self.wantsLayer = true
        self.layer?.cornerRadius = cornerRadius
        self.layer?.masksToBounds = true
        self.title = ""
        self.image = nil

        contentStack.orientation = .horizontal
        contentStack.alignment = .centerY
        contentStack.spacing = 8
        contentStack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(contentStack)

        iconImageView.translatesAutoresizingMaskIntoConstraints = false
        iconImageView.imageScaling = .scaleProportionallyDown
        contentStack.addArrangedSubview(iconImageView)

        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        titleLabel.font = font
        titleLabel.isBezeled = false
        titleLabel.drawsBackground = false
        titleLabel.isEditable = false
        titleLabel.isSelectable = false
        titleLabel.lineBreakMode = .byClipping
        contentStack.addArrangedSubview(titleLabel)

        NSLayoutConstraint.activate([
            contentStack.centerXAnchor.constraint(equalTo: centerXAnchor),
            contentStack.centerYAnchor.constraint(equalTo: centerYAnchor),
            contentStack.leadingAnchor.constraint(greaterThanOrEqualTo: leadingAnchor, constant: 12),
            contentStack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -12)
        ])

        update(title: title, icon: icon)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func update(title: String, icon: NSImage?) {
        titleLabel.stringValue = title
        iconImageView.image = icon
        iconImageView.isHidden = (icon == nil)
    }

    func setCustomColors(bg: NSColor, text: NSColor, iconColor: NSColor? = nil, border: NSColor? = nil, borderWidth: CGFloat = 0) {
        layer?.backgroundColor = bg.cgColor
        titleLabel.textColor = text
        iconImageView.contentTintColor = iconColor ?? text
        if let border = border, borderWidth > 0 {
            layer?.borderColor = border.cgColor
            layer?.borderWidth = borderWidth
        } else {
            layer?.borderWidth = 0
        }
    }

    override func hitTest(_ point: NSPoint) -> NSView? {
        if bounds.contains(point) && isEnabled {
            return self
        }
        return super.hitTest(point)
    }
}

// MARK: - Main Application Window Controller

@MainActor
public final class MainWindowController: NSWindowController, NSWindowDelegate {
    public static let shared = MainWindowController()

    // 1. Header Banner
    private let headerCard = AndroidCardView(cornerRadius: 22)
    private let headerImageView = DecorativeImageView()
    private let themeToggleButton = NSButton()

    // 2. Status Card
    private let statusCard = AndroidCardView(cornerRadius: 28)
    private let mapImageView = DecorativeImageView()
    private let ringImageView = DecorativeImageView()
    private let statusDotView = NSView()
    private let statusLabel = NSTextField(labelWithString: "Отключено")
    private let serverTitleLabel = NSTextField(labelWithString: "cloud")
    private let subTypeLabel = NSTextField(labelWithString: "Подписка")
    private let badgeContainer = NSView()
    private let badgeLabel = NSTextField(labelWithString: "Активна")
    private let refreshSubtitleLabel = NSTextField(labelWithString: "Обновлено недавно · каждые 12 ч")
    private let chevronButton = NSButton()

    // Stats strip
    private let statsContainer = NSView()
    private let statDivider = NSBox()
    private var statHeaderLabels: [NSTextField] = []
    private var statIconViews: [NSImageView] = []
    private let durationValueLabel = NSTextField(labelWithString: "00:00:00")
    private let modeValueLabel = NSTextField(labelWithString: "SOCKS5")
    private let protocolValueLabel = NSTextField(labelWithString: "VLESS/H3")

    // 3. Mode selector
    private let modeCard = AndroidCardView(cornerRadius: 18)
    private let modeTitleIcon = NSImageView()
    private let modeTitleLabel = NSTextField(labelWithString: "Режим перехвата трафика:")
    private let socks5TabButton = NSButton()
    private let tunTabButton = NSButton()
    private let modeHintLabel = NSTextField(labelWithString: "")

    // 4. Action Row (Add Server & Big Connect)
    private let addServerButton = ActionPillButton(
        title: "Добавить сервер",
        icon: NSImage(systemSymbolName: "plus", accessibilityDescription: nil)?
            .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 13.5, weight: .bold)),
        font: .systemFont(ofSize: 13.5, weight: .semibold),
        cornerRadius: 20
    )
    private let actionButton = ActionPillButton(
        title: "Подключить",
        icon: NSImage(systemSymbolName: "power", accessibilityDescription: nil)?
            .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 14.5, weight: .bold)),
        font: .systemFont(ofSize: 14.5, weight: .bold),
        cornerRadius: 20
    )

    // 5. Quick Links
    private let quickLinksCard = AndroidCardView(cornerRadius: 24)
    private var quickLinkItems: [AndroidQuickLinkItem] = []

    // 6. Footer
    private let footerLabel = NSTextField(labelWithString: AppVersion.displayString)

    // Timer
    private var durationTimer: Timer?
    private var connectedSince: Date?

    private init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 380, height: 690),
            styleMask: [.titled, .closable, .miniaturizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.setContentSize(NSSize(width: 380, height: 690))
        window.minSize = NSSize(width: 380, height: 690)
        window.maxSize = NSSize(width: 380, height: 690)
        window.title = "Outline Proxy"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isMovableByWindowBackground = true
        window.center()
        window.isReleasedWhenClosed = false

        super.init(window: window)
        window.delegate = self

        setupUI()

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleStateUpdate),
            name: NSNotification.Name("AppStateUpdated"),
            object: nil
        )

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(themeDidChange),
            name: ThemeManager.themeChangedNotification,
            object: nil
        )

        DistributedNotificationCenter.default().addObserver(
            self,
            selector: #selector(themeDidChange),
            name: NSNotification.Name("AppleInterfaceThemeChangedNotification"),
            object: nil
        )

        ProfileStore.shared.onProfilesChanged = { [weak self] in
            DispatchQueue.main.async {
                self?.refreshServerInfo()
            }
        }

        applyCurrentTheme()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    private func setupUI() {
        guard let contentView = window?.contentView else { return }

        let rootStack = NSStackView()
        rootStack.orientation = .vertical
        rootStack.spacing = 14
        rootStack.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(rootStack)

        NSLayoutConstraint.activate([
            rootStack.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 36),
            rootStack.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -16),
            rootStack.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            rootStack.widthAnchor.constraint(equalToConstant: 348)
        ])

        // 1. Header Banner
        setupHeaderBanner()
        rootStack.addArrangedSubview(headerCard)

        // 2. Status Card
        setupStatusCard()
        rootStack.addArrangedSubview(statusCard)

        // 3. Operational Mode
        setupModeSelector()
        rootStack.addArrangedSubview(modeCard)

        // 4. Action Row
        let actionRow = setupActionRow()
        rootStack.addArrangedSubview(actionRow)

        // 5. Quick Links
        setupQuickLinks()
        rootStack.addArrangedSubview(quickLinksCard)

        // All cards strictly match rootStack width (348pt) to never touch or exceed window bounds
        NSLayoutConstraint.activate([
            headerCard.widthAnchor.constraint(equalTo: rootStack.widthAnchor),
            statusCard.widthAnchor.constraint(equalTo: rootStack.widthAnchor),
            modeCard.widthAnchor.constraint(equalTo: rootStack.widthAnchor),
            actionRow.widthAnchor.constraint(equalTo: rootStack.widthAnchor),
            quickLinksCard.widthAnchor.constraint(equalTo: rootStack.widthAnchor)
        ])

        // Flexible spacer
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .vertical)
        rootStack.addArrangedSubview(spacer)

        // 6. Version Footer
        footerLabel.stringValue = AppVersion.displayString
        footerLabel.toolTip = AppVersion.fullDiagnosticString
        footerLabel.font = NSFont.systemFont(ofSize: 11, weight: .regular)
        footerLabel.alignment = .center
        rootStack.addArrangedSubview(footerLabel)
    }

    // MARK: - Subviews Setup

    private func setupHeaderBanner() {
        headerCard.translatesAutoresizingMaskIntoConstraints = false
        headerImageView.imageScaling = .scaleAxesIndependently
        headerImageView.translatesAutoresizingMaskIntoConstraints = false
        headerCard.addSubview(headerImageView)

        // Theme toggle button (Sun / Moon) in header top-right
        themeToggleButton.wantsLayer = true
        themeToggleButton.isBordered = false
        themeToggleButton.bezelStyle = .regularSquare
        themeToggleButton.layer?.cornerRadius = 15
        themeToggleButton.layer?.masksToBounds = true
        themeToggleButton.target = self
        themeToggleButton.action = #selector(toggleThemeAction)
        themeToggleButton.translatesAutoresizingMaskIntoConstraints = false
        headerCard.addSubview(themeToggleButton)

        NSLayoutConstraint.activate([
            headerCard.heightAnchor.constraint(equalToConstant: 86),
            headerImageView.topAnchor.constraint(equalTo: headerCard.topAnchor),
            headerImageView.bottomAnchor.constraint(equalTo: headerCard.bottomAnchor),
            headerImageView.leadingAnchor.constraint(equalTo: headerCard.leadingAnchor),
            headerImageView.trailingAnchor.constraint(equalTo: headerCard.trailingAnchor),

            themeToggleButton.topAnchor.constraint(equalTo: headerCard.topAnchor, constant: 10),
            themeToggleButton.trailingAnchor.constraint(equalTo: headerCard.trailingAnchor, constant: -10),
            themeToggleButton.widthAnchor.constraint(equalToConstant: 30),
            themeToggleButton.heightAnchor.constraint(equalToConstant: 30)
        ])
    }

    private func setupStatusCard() {
        statusCard.translatesAutoresizingMaskIntoConstraints = false

        // Dotted world map background
        if let mapURL = Bundle.main.url(forResource: "ic_worldmap", withExtension: "png"),
           let mapImg = NSImage(contentsOf: mapURL) {
            mapImg.isTemplate = true
            mapImageView.image = mapImg
        }
        mapImageView.imageScaling = .scaleAxesIndependently
        mapImageView.translatesAutoresizingMaskIntoConstraints = false
        statusCard.addSubview(mapImageView)

        let cardStack = NSStackView()
        cardStack.orientation = .vertical
        cardStack.spacing = 14
        cardStack.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        cardStack.translatesAutoresizingMaskIntoConstraints = false
        statusCard.addSubview(cardStack)

        NSLayoutConstraint.activate([
            mapImageView.topAnchor.constraint(equalTo: statusCard.topAnchor),
            mapImageView.bottomAnchor.constraint(equalTo: statusCard.bottomAnchor),
            mapImageView.leadingAnchor.constraint(equalTo: statusCard.leadingAnchor),
            mapImageView.trailingAnchor.constraint(equalTo: statusCard.trailingAnchor),

            cardStack.topAnchor.constraint(equalTo: statusCard.topAnchor),
            cardStack.bottomAnchor.constraint(equalTo: statusCard.bottomAnchor),
            cardStack.leadingAnchor.constraint(equalTo: statusCard.leadingAnchor),
            cardStack.trailingAnchor.constraint(equalTo: statusCard.trailingAnchor)
        ])

        // Top Row: Big Ring Emblem (82x82) + Details + Chevron
        let topRow = NSStackView()
        topRow.orientation = .horizontal
        topRow.alignment = .centerY
        topRow.spacing = 16

        ringImageView.imageScaling = .scaleProportionallyUpOrDown
        ringImageView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            ringImageView.widthAnchor.constraint(equalToConstant: 82),
            ringImageView.heightAnchor.constraint(equalToConstant: 82)
        ])
        topRow.addArrangedSubview(ringImageView)

        let infoColumn = NSStackView()
        infoColumn.orientation = .vertical
        infoColumn.alignment = .leading
        infoColumn.spacing = 3

        // Status row: dot + text
        let statusRow = NSStackView()
        statusRow.orientation = .horizontal
        statusRow.alignment = .centerY
        statusRow.spacing = 6

        statusDotView.wantsLayer = true
        statusDotView.layer?.cornerRadius = 5
        statusDotView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            statusDotView.widthAnchor.constraint(equalToConstant: 10),
            statusDotView.heightAnchor.constraint(equalToConstant: 10)
        ])
        statusRow.addArrangedSubview(statusDotView)

        statusLabel.font = NSFont.systemFont(ofSize: 12.5, weight: .semibold)
        statusRow.addArrangedSubview(statusLabel)
        infoColumn.addArrangedSubview(statusRow)

        // Server Name (Huge 24pt Bold)
        serverTitleLabel.font = NSFont.systemFont(ofSize: 24, weight: .bold)
        serverTitleLabel.lineBreakMode = .byTruncatingTail
        infoColumn.addArrangedSubview(serverTitleLabel)

        // Subtitle row with Active Badge
        let subRow = NSStackView()
        subRow.orientation = .horizontal
        subRow.alignment = .centerY
        subRow.spacing = 8

        subTypeLabel.font = NSFont.systemFont(ofSize: 12.5)
        subRow.addArrangedSubview(subTypeLabel)

        badgeContainer.wantsLayer = true
        badgeContainer.layer?.cornerRadius = 6
        badgeContainer.translatesAutoresizingMaskIntoConstraints = false

        badgeLabel.font = NSFont.systemFont(ofSize: 11, weight: .semibold)
        badgeLabel.translatesAutoresizingMaskIntoConstraints = false
        badgeContainer.addSubview(badgeLabel)

        NSLayoutConstraint.activate([
            badgeLabel.topAnchor.constraint(equalTo: badgeContainer.topAnchor, constant: 2),
            badgeLabel.bottomAnchor.constraint(equalTo: badgeContainer.bottomAnchor, constant: -2),
            badgeLabel.leadingAnchor.constraint(equalTo: badgeContainer.leadingAnchor, constant: 8),
            badgeLabel.trailingAnchor.constraint(equalTo: badgeContainer.trailingAnchor, constant: -8)
        ])
        subRow.addArrangedSubview(badgeContainer)
        infoColumn.addArrangedSubview(subRow)

        // Refresh interval text
        refreshSubtitleLabel.font = NSFont.systemFont(ofSize: 11)
        infoColumn.addArrangedSubview(refreshSubtitleLabel)

        topRow.addArrangedSubview(infoColumn)

        // Elegant SF Symbols Chevron
        chevronButton.image = NSImage(systemSymbolName: "chevron.right", accessibilityDescription: "Серверы")
        chevronButton.imagePosition = .imageOnly
        chevronButton.target = self
        chevronButton.action = #selector(openServersAction)
        chevronButton.isBordered = false
        chevronButton.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            chevronButton.widthAnchor.constraint(equalToConstant: 20),
            chevronButton.heightAnchor.constraint(equalToConstant: 24)
        ])
        topRow.addArrangedSubview(chevronButton)

        cardStack.addArrangedSubview(topRow)

        // Live stats strip when connected
        setupStatsStrip()
        cardStack.addArrangedSubview(statsContainer)

        let click = NSClickGestureRecognizer(target: self, action: #selector(openServersAction))
        statusCard.addGestureRecognizer(click)
    }

    private func setupStatsStrip() {
        statsContainer.translatesAutoresizingMaskIntoConstraints = false

        statDivider.boxType = .separator
        statDivider.translatesAutoresizingMaskIntoConstraints = false
        statsContainer.addSubview(statDivider)

        let stripRow = NSStackView()
        stripRow.orientation = .horizontal
        stripRow.distribution = .fillEqually
        stripRow.alignment = .centerY
        stripRow.translatesAutoresizingMaskIntoConstraints = false
        statsContainer.addSubview(stripRow)

        NSLayoutConstraint.activate([
            statDivider.topAnchor.constraint(equalTo: statsContainer.topAnchor),
            statDivider.leadingAnchor.constraint(equalTo: statsContainer.leadingAnchor),
            statDivider.trailingAnchor.constraint(equalTo: statsContainer.trailingAnchor),
            statDivider.heightAnchor.constraint(equalToConstant: 1),

            stripRow.topAnchor.constraint(equalTo: statDivider.bottomAnchor, constant: 8),
            stripRow.leadingAnchor.constraint(equalTo: statsContainer.leadingAnchor),
            stripRow.trailingAnchor.constraint(equalTo: statsContainer.trailingAnchor),
            stripRow.bottomAnchor.constraint(equalTo: statsContainer.bottomAnchor),
            stripRow.heightAnchor.constraint(equalToConstant: 36)
        ])

        stripRow.addArrangedSubview(createStatColumn(title: "ДЛИТЕЛЬНОСТЬ", icon: "clock", valueLabel: durationValueLabel))
        stripRow.addArrangedSubview(createStatColumn(title: "РЕЖИМ", icon: "shield", valueLabel: modeValueLabel))
        stripRow.addArrangedSubview(createStatColumn(title: "ПРОТОКОЛ", icon: "waveform", valueLabel: protocolValueLabel))
    }

    private func createStatColumn(title: String, icon: String, valueLabel: NSTextField) -> NSView {
        let col = NSStackView()
        col.orientation = .vertical
        col.alignment = .centerX
        col.spacing = 2

        let headRow = NSStackView()
        headRow.orientation = .horizontal
        headRow.alignment = .centerY
        headRow.spacing = 4

        let iconView = NSImageView()
        iconView.image = NSImage(systemSymbolName: icon, accessibilityDescription: nil)
        iconView.translatesAutoresizingMaskIntoConstraints = false
        iconView.widthAnchor.constraint(equalToConstant: 11).isActive = true
        iconView.heightAnchor.constraint(equalToConstant: 11).isActive = true
        statIconViews.append(iconView)
        headRow.addArrangedSubview(iconView)

        let cap = NSTextField(labelWithString: title)
        cap.font = NSFont.systemFont(ofSize: 8.5, weight: .bold)
        statHeaderLabels.append(cap)
        headRow.addArrangedSubview(cap)
        col.addArrangedSubview(headRow)

        valueLabel.font = NSFont.systemFont(ofSize: 13, weight: .bold)
        valueLabel.alignment = .center
        col.addArrangedSubview(valueLabel)

        return col
    }

    private func setupModeSelector() {
        modeCard.translatesAutoresizingMaskIntoConstraints = false

        let box = NSStackView()
        box.orientation = .vertical
        box.spacing = 10
        box.alignment = .centerX
        box.translatesAutoresizingMaskIntoConstraints = false
        modeCard.addSubview(box)

        NSLayoutConstraint.activate([
            box.topAnchor.constraint(equalTo: modeCard.topAnchor, constant: 14),
            box.bottomAnchor.constraint(equalTo: modeCard.bottomAnchor, constant: -14),
            box.leadingAnchor.constraint(equalTo: modeCard.leadingAnchor, constant: 16),
            box.trailingAnchor.constraint(equalTo: modeCard.trailingAnchor, constant: -16)
        ])

        let titleRow = NSStackView()
        titleRow.orientation = .horizontal
        titleRow.alignment = .centerY
        titleRow.spacing = 6

        modeTitleIcon.image = NSImage(systemSymbolName: "globe", accessibilityDescription: nil)
        modeTitleIcon.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            modeTitleIcon.widthAnchor.constraint(equalToConstant: 13),
            modeTitleIcon.heightAnchor.constraint(equalToConstant: 13)
        ])
        titleRow.addArrangedSubview(modeTitleIcon)

        modeTitleLabel.font = NSFont.systemFont(ofSize: 11.5, weight: .bold)
        titleRow.addArrangedSubview(modeTitleLabel)
        box.addArrangedSubview(titleRow)

        let tabRow = NSStackView()
        tabRow.orientation = .horizontal
        tabRow.spacing = 8
        tabRow.distribution = .fillEqually
        tabRow.translatesAutoresizingMaskIntoConstraints = false
        tabRow.heightAnchor.constraint(equalToConstant: 36).isActive = true

        socks5TabButton.translatesAutoresizingMaskIntoConstraints = false
        socks5TabButton.heightAnchor.constraint(equalToConstant: 36).isActive = true
        socks5TabButton.title = "SOCKS5 (Прокси)"
        socks5TabButton.target = self
        socks5TabButton.action = #selector(selectSocks5Action)
        tabRow.addArrangedSubview(socks5TabButton)

        tunTabButton.translatesAutoresizingMaskIntoConstraints = false
        tunTabButton.heightAnchor.constraint(equalToConstant: 36).isActive = true
        tunTabButton.title = "TUN (VPN)"
        tunTabButton.target = self
        tunTabButton.action = #selector(selectTunAction)
        tabRow.addArrangedSubview(tunTabButton)

        box.addArrangedSubview(tabRow)

        modeHintLabel.font = NSFont.systemFont(ofSize: 11)
        modeHintLabel.alignment = .center
        modeHintLabel.lineBreakMode = .byWordWrapping
        modeHintLabel.preferredMaxLayoutWidth = 280
        box.addArrangedSubview(modeHintLabel)

        NSLayoutConstraint.activate([
            tabRow.widthAnchor.constraint(equalToConstant: 248),
            tabRow.centerXAnchor.constraint(equalTo: box.centerXAnchor),
            modeHintLabel.widthAnchor.constraint(lessThanOrEqualToConstant: 280)
        ])
    }

    private func updateModeUI() {
        let palette = ThemeManager.shared.palette(for: window)
        let isTun = (AppState.shared.mode == .tun)
        styleTab(button: tunTabButton, isSelected: isTun, palette: palette)
        styleTab(button: socks5TabButton, isSelected: !isTun, palette: palette)
        updateModeHint()
    }

    private func styleTab(button: NSButton, isSelected: Bool, palette: ThemePalette) {
        button.wantsLayer = true
        button.isBordered = false
        button.bezelStyle = .regularSquare
        button.layer?.cornerRadius = 10
        button.font = NSFont.systemFont(ofSize: 11.5, weight: isSelected ? .bold : .medium)
        if isSelected {
            button.layer?.backgroundColor = palette.tabSelectedBg.cgColor
            button.layer?.borderWidth = 0
            button.contentTintColor = palette.tabSelectedText
        } else {
            button.layer?.backgroundColor = palette.tabUnselectedBg.cgColor
            button.layer?.borderWidth = 1.0
            button.layer?.borderColor = palette.tabUnselectedBorder.cgColor
            button.contentTintColor = palette.tabUnselectedText
        }
    }

    @objc private func selectSocks5Action() {
        AppState.shared.setMode(.socks5)
        updateModeUI()
    }

    @objc private func selectTunAction() {
        AppState.shared.setMode(.tun)
        updateModeUI()
    }

    private func setupActionRow() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.spacing = 12
        row.distribution = .fillEqually
        row.translatesAutoresizingMaskIntoConstraints = false
        row.heightAnchor.constraint(equalToConstant: 56).isActive = true

        addServerButton.target = self
        addServerButton.action = #selector(addServerAction)
        addServerButton.translatesAutoresizingMaskIntoConstraints = false
        addServerButton.heightAnchor.constraint(equalToConstant: 56).isActive = true
        row.addArrangedSubview(addServerButton)

        actionButton.target = self
        actionButton.action = #selector(toggleConnectionAction)
        actionButton.translatesAutoresizingMaskIntoConstraints = false
        actionButton.heightAnchor.constraint(equalToConstant: 56).isActive = true
        row.addArrangedSubview(actionButton)

        // Strict 50/50 width constraint so buttons never stretch unevenly
        addServerButton.widthAnchor.constraint(equalTo: actionButton.widthAnchor).isActive = true

        return row
    }

    private func setupQuickLinks() {
        quickLinksCard.translatesAutoresizingMaskIntoConstraints = false

        let row = NSStackView()
        row.orientation = .horizontal
        row.distribution = .fillEqually
        row.spacing = 20
        row.edgeInsets = NSEdgeInsets(top: 16, left: 32, bottom: 16, right: 32)
        row.translatesAutoresizingMaskIntoConstraints = false
        quickLinksCard.addSubview(row)

        NSLayoutConstraint.activate([
            row.topAnchor.constraint(equalTo: quickLinksCard.topAnchor),
            row.bottomAnchor.constraint(equalTo: quickLinksCard.bottomAnchor),
            row.leadingAnchor.constraint(equalTo: quickLinksCard.leadingAnchor),
            row.trailingAnchor.constraint(equalTo: quickLinksCard.trailingAnchor)
        ])

        // Only 2 buttons requested by user: Logs and Settings
        let logsItem = AndroidQuickLinkItem(title: "Журнал (логи)", symbol: "doc.text.magnifyingglass") { [weak self] in
            self?.openLogsAction()
        }
        let settingsItem = AndroidQuickLinkItem(title: "Настройки", symbol: "gearshape.fill") { [weak self] in
            self?.openSettingsAction()
        }

        quickLinkItems = [logsItem, settingsItem]
        row.addArrangedSubview(logsItem)
        row.addArrangedSubview(settingsItem)

        logsItem.widthAnchor.constraint(equalTo: settingsItem.widthAnchor).isActive = true
    }

    // MARK: - Theme Management

    @objc private func toggleThemeAction() {
        ThemeManager.shared.toggle(for: window)
        applyCurrentTheme()
    }

    @objc private func themeDidChange() {
        applyCurrentTheme()
    }

    private func applyCurrentTheme() {
        guard let win = window else { return }
        let palette = ThemeManager.shared.palette(for: win)

        // 1. Window appearance & background
        win.appearance = palette.isDark ? NSAppearance(named: .darkAqua) : NSAppearance(named: .aqua)
        win.backgroundColor = palette.windowBackground

        // 2. Header
        headerCard.applyTheme(bg: palette.headerCardBg, border: palette.cardBorder)
        if let logoURL = Bundle.main.url(forResource: palette.logoAsset, withExtension: "png") {
            headerImageView.image = NSImage(contentsOf: logoURL)
        }

        // Theme toggle button icon & style
        if palette.isDark {
            themeToggleButton.image = NSImage(systemSymbolName: "sun.max.fill", accessibilityDescription: "Светлая тема")
            themeToggleButton.contentTintColor = NSColor(red: 0xFB/255.0, green: 0xBF/255.0, blue: 0x24/255.0, alpha: 1.0)
            themeToggleButton.layer?.backgroundColor = NSColor(white: 0.0, alpha: 0.40).cgColor
            themeToggleButton.layer?.borderWidth = 1.0
            themeToggleButton.layer?.borderColor = NSColor(white: 1.0, alpha: 0.18).cgColor
            themeToggleButton.toolTip = "Включить светлую тему"
        } else {
            themeToggleButton.image = NSImage(systemSymbolName: "moon.fill", accessibilityDescription: "Тёмная тема")
            themeToggleButton.contentTintColor = NSColor(red: 0x1E/255.0, green: 0x3A/255.0, blue: 0x8A/255.0, alpha: 1.0)
            themeToggleButton.layer?.backgroundColor = NSColor(white: 1.0, alpha: 0.75).cgColor
            themeToggleButton.layer?.borderWidth = 1.0
            themeToggleButton.layer?.borderColor = palette.cardBorder.cgColor
            themeToggleButton.toolTip = "Включить тёмную тему"
        }

        // 3. Status card
        statusCard.applyTheme(bg: palette.contentCardBg, border: palette.cardBorder)
        mapImageView.contentTintColor = palette.mapTint
        if let ringURL = Bundle.main.url(forResource: palette.ringAsset, withExtension: "png") {
            ringImageView.image = NSImage(contentsOf: ringURL)
        }

        serverTitleLabel.textColor = palette.primaryText
        subTypeLabel.textColor = palette.secondaryText
        badgeContainer.layer?.backgroundColor = palette.badgeBg.cgColor
        badgeLabel.textColor = palette.badgeText
        refreshSubtitleLabel.textColor = palette.secondaryText
        chevronButton.contentTintColor = palette.chevronTint

        // Stats
        for lbl in statHeaderLabels {
            lbl.textColor = palette.secondaryText
        }
        for icn in statIconViews {
            icn.contentTintColor = palette.bubbleIcon
        }
        durationValueLabel.textColor = palette.primaryText
        modeValueLabel.textColor = palette.primaryText
        protocolValueLabel.textColor = palette.primaryText

        // 4. Mode Card
        modeCard.applyTheme(bg: palette.contentCardBg, border: palette.cardBorder)
        modeTitleIcon.contentTintColor = palette.bubbleIcon
        modeTitleLabel.textColor = palette.primaryText
        modeHintLabel.textColor = palette.secondaryText
        updateModeUI()

        // 5. Action Row
        addServerButton.setCustomColors(
            bg: palette.addServerBg,
            text: palette.addServerText,
            iconColor: palette.addServerText,
            border: palette.addServerBorder,
            borderWidth: 1.2
        )

        // 6. Quick Links
        quickLinksCard.applyTheme(bg: palette.contentCardBg, border: palette.cardBorder)
        for item in quickLinkItems {
            item.applyTheme(bubbleBg: palette.bubbleBg, iconColor: palette.bubbleIcon, textColor: palette.bubbleText)
        }

        // 7. Footer
        footerLabel.textColor = palette.secondaryText
        footerLabel.stringValue = AppVersion.displayString
        footerLabel.toolTip = AppVersion.fullDiagnosticString

        // Refresh State & Server Info
        refreshServerInfo()
        handleStateUpdate()
    }

    // MARK: - State Updates

    public var isWindowVisible: Bool {
        return window?.isVisible == true && window?.isMiniaturized == false
    }

    public func show() {
        applyCurrentTheme()
        NSApp.setActivationPolicy(.regular)
        if window?.isMiniaturized == true {
            window?.deminiaturize(nil)
        }
        window?.makeKeyAndOrderFront(nil)
        window?.orderFrontRegardless()
        NSApp.activate(ignoringOtherApps: true)
    }

    private func refreshServerInfo() {
        if let profile = ProfileStore.shared.activeProfile {
            serverTitleLabel.stringValue = profile.displayName
            if profile.isSubscription {
                subTypeLabel.stringValue = "Подписка"
                badgeContainer.isHidden = false
                refreshSubtitleLabel.stringValue = "Обновлено недавно · каждые 12 ч"
            } else {
                subTypeLabel.stringValue = "\(profile.transport.uppercased())"
                badgeContainer.isHidden = true
                refreshSubtitleLabel.stringValue = "Прямое подключение к серверу"
            }
        } else {
            serverTitleLabel.stringValue = "Нет сервера"
            subTypeLabel.stringValue = "Добавьте профиль"
            badgeContainer.isHidden = true
            refreshSubtitleLabel.stringValue = "Нажмите «+ Добавить сервер»"
        }
    }

    @objc private func handleStateUpdate() {
        let palette = ThemeManager.shared.palette(for: window)
        refreshServerInfo()
        updateModeUI()

        switch AppState.shared.status {
        case .connected(let name):
            statusDotView.layer?.backgroundColor = palette.statusGreen.cgColor
            statusLabel.stringValue = "Подключено"
            statusLabel.textColor = palette.statusGreen
            serverTitleLabel.stringValue = name.isEmpty ? "cloud" : name

            let pwrOffConfig = NSImage.SymbolConfiguration(pointSize: 15, weight: .bold)
            let pwrOffIcon = NSImage(systemSymbolName: "power.circle.fill", accessibilityDescription: nil)?.withSymbolConfiguration(pwrOffConfig)
            actionButton.update(title: "Отключить", icon: pwrOffIcon)
            actionButton.setCustomColors(bg: palette.disconnectBg, text: palette.disconnectText)
            actionButton.isEnabled = true

            statsContainer.isHidden = false
            modeValueLabel.stringValue = AppState.shared.mode.shortTitle
            if connectedSince == nil {
                connectedSince = Date()
                startDurationTimer()
            }

        case .connecting:
            statusDotView.layer?.backgroundColor = palette.bubbleIcon.cgColor
            statusLabel.stringValue = "Подключение..."
            statusLabel.textColor = palette.bubbleIcon

            let spinConfig = NSImage.SymbolConfiguration(pointSize: 13, weight: .bold)
            let spinIcon = NSImage(systemSymbolName: "arrow.triangle.2.circlepath", accessibilityDescription: nil)?.withSymbolConfiguration(spinConfig)
            actionButton.update(title: "Подключение...", icon: spinIcon)
            actionButton.setCustomColors(bg: palette.connectBg.withAlphaComponent(0.6), text: palette.connectText)
            actionButton.isEnabled = false
            statsContainer.isHidden = true

        case .disconnecting:
            statusDotView.layer?.backgroundColor = palette.statusAmber.cgColor
            statusLabel.stringValue = "Отключение..."
            statusLabel.textColor = palette.statusAmber

            actionButton.update(title: "Отключение...", icon: nil)
            actionButton.setCustomColors(bg: palette.contentCardBg, text: palette.primaryText)
            actionButton.isEnabled = false
            statsContainer.isHidden = true

        case .disconnected:
            statusDotView.layer?.backgroundColor = palette.statusGray.cgColor
            statusLabel.stringValue = "Отключено"
            statusLabel.textColor = palette.statusGray

            let pwrConfig = NSImage.SymbolConfiguration(pointSize: 14.5, weight: .bold)
            let pwrIcon = NSImage(systemSymbolName: "power", accessibilityDescription: nil)?.withSymbolConfiguration(pwrConfig)
            actionButton.update(title: "Подключить", icon: pwrIcon)
            actionButton.setCustomColors(bg: palette.connectBg, text: palette.connectText)
            actionButton.isEnabled = (ProfileStore.shared.activeProfile != nil)

            statsContainer.isHidden = true
            stopDurationTimer()
            connectedSince = nil

        case .error(let msg):
            statusDotView.layer?.backgroundColor = palette.disconnectBg.cgColor
            statusLabel.stringValue = "Ошибка: \(msg)"
            statusLabel.textColor = palette.disconnectBg

            actionButton.title = "  Повторить"
            actionButton.image = NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: nil)
            actionButton.imagePosition = .imageLeading
            actionButton.layer?.backgroundColor = palette.connectBg.cgColor
            actionButton.contentTintColor = palette.connectText
            actionButton.isEnabled = true

            statsContainer.isHidden = true
            stopDurationTimer()
            connectedSince = nil
        }
    }

    private func updateModeHint() {
        if AppState.shared.mode == .tun {
            if PrivilegedHelperManager.shared.isSudoersConfigured() {
                modeHintLabel.stringValue = "L3 TUN VPN: туннель в 1 клик без пароля (DNS, игры, все приложения)"
            } else {
                modeHintLabel.stringValue = "L3 TUN VPN: системный туннель (настройте 1 клик в Настройках)"
            }
        } else {
            modeHintLabel.stringValue = "SOCKS5: локальный прокси без root (браузеры и программы)"
        }
    }

    private func startDurationTimer() {
        stopDurationTimer()
        durationTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self = self, let since = self.connectedSince else { return }
                let elapsed = Int(Date().timeIntervalSince(since))
                let hours = elapsed / 3600
                let minutes = (elapsed % 3600) / 60
                let seconds = elapsed % 60
                self.durationValueLabel.stringValue = String(format: "%02d:%02d:%02d", hours, minutes, seconds)
            }
        }
    }

    private func stopDurationTimer() {
        durationTimer?.invalidate()
        durationTimer = nil
        durationValueLabel.stringValue = "00:00:00"
    }

    // MARK: - Actions

    @objc private func toggleConnectionAction() {
        AppState.shared.toggleConnection()
    }

    @objc private func openServersAction() {
        SettingsWindowController.shared.show()
    }

    @objc private func addServerAction() {
        SettingsWindowController.shared.show()
    }

    @objc private func openLogsAction() {
        LogWindowController.shared.show()
    }

    @objc private func openSettingsAction() {
        SettingsWindowController.shared.show()
    }

    public func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }

    public func windowDidChangeEffectiveAppearance(_ notification: Notification) {
        if ThemeManager.shared.mode == .system {
            applyCurrentTheme()
        }
    }
}
