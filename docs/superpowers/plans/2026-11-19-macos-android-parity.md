# План реализации: Паритет интерфейса macOS с Android (Статистика сессии, протоколы TCP/UDP, разделение серверов и настроек)

> **Для исполнителей:** ОБЯЗАТЕЛЬНЫЙ НАВЫК: используйте `superpowers:subagent-driven-development` (рекомендуется) или `superpowers:executing-plans` для пошаговой реализации этого плана. Шаги используют синтаксис чекбоксов (`- [ ]`).

**Цель:** Привести приложение Outline Proxy для macOS к паритету с Android по информативности дашборда (прямое имя профиля, таймер сессии, счетчики трафика uplink/downlink, протоколы TCP/UDP с поддержкой H1/H2/H3) и разделить управление серверами и системные настройки на отдельные экраны.

**Архитектура:** Имя профиля возвращается без неявной подстановки домена; создается легковесный сервис `NetworkTrafficMonitor` для динамического замера байтов; полоса `StatsStrip` в `MainWindowController` перестраивается на 3 колонки (длительность, трафик, протоколы); создается специализированный `ServersWindowController`, а `SettingsWindowController` очищается от таблицы серверов под сугубо системные настройки.

**Стек технологий:** Swift 5.9, AppKit (Pure AppKit без сторонних зависимостей), macOS 13.0+, BSD `getifaddrs` / Darwin socket APIs.

## Глобальные ограничения

- Язык диалогов, планов, документации и логов — русский.
- Соблюдение правил оформления текста и терминологии монорепозитория (`carrier` = «носитель», `gate` = «гейт»).
- Swift-код должен компилироваться через `swift build` в каталоге `macos/` без ошибок и предупреждений.
- Сохранение полной совместимости со светлой и тёмной темами оформления (`ThemeManager`).
- Строгая изоляция: не затрагивать нерелевантные крейты или `android/`.

---

### Task 1: Исправление отображения имени профиля на карточке (`ServerProfile.swift`)

**Файлы:**
- Изменить: `macos/Sources/OutlineProxy/Core/Models/ServerProfile.swift:130-145`

**Интерфейсы:**
- Предоставляет: `displayName: String` — возвращает исходное `name` профиля, если оно задано. Не подменяет имя «Подписка» на имя первого хоста из TOML.

- [ ] **Шаг 1: Проверить текущую реализацию `displayName`**

В файле `macos/Sources/OutlineProxy/Core/Models/ServerProfile.swift` строки 132-144:
```swift
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
```

- [ ] **Шаг 2: Реализовать корректную логику `displayName`**

Заменить метод `displayName` на:
```swift
    public var displayName: String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            return trimmed
        }
        if isSubscription {
            return "Подписка"
        }
        if let host = serverHost {
            return host
        }
        return transport.uppercased() + " сервер"
    }
```

- [ ] **Шаг 3: Проверить сборку Swift**

Выполнить: `cd macos && swift build`
Ожидается: `Build complete!`

- [ ] **Шаг 4: Зафиксировать изменения в git**

Выполнить:
```bash
git commit -m "fix(macos): display exact profile name on status card without host substitution" -- macos/Sources/OutlineProxy/Core/Models/ServerProfile.swift
```

---

### Task 2: Сервис подсчета сетевого трафика (`NetworkTrafficMonitor.swift`)

**Файлы:**
- Создать: `macos/Sources/OutlineProxy/Core/Services/NetworkTrafficMonitor.swift`

**Интерфейсы:**
- Предоставляет:
  - `NetworkTrafficMonitor.shared.start(mode: ProxyMode)`
  - `NetworkTrafficMonitor.shared.stop()`
  - `NetworkTrafficMonitor.shared.currentBytes() -> (tx: UInt64, rx: UInt64)`
  - `NetworkTrafficMonitor.formatBytes(_ bytes: UInt64) -> String`

- [ ] **Шаг 1: Написать класс `NetworkTrafficMonitor`**

Создать файл `macos/Sources/OutlineProxy/Core/Services/NetworkTrafficMonitor.swift` с реализацией подсчета байтов через `getifaddrs` для интерфейсов `utun` (в режиме TUN) и сетевых интерфейсов (в режиме SOCKS5) с фиксацией базового уровня на момент старта:

```swift
import Foundation
import Darwin

/// Monitors network traffic (transmitted/received bytes) for active proxy sessions.
public final class NetworkTrafficMonitor: @unchecked Sendable {
    public static let shared = NetworkTrafficMonitor()

    private let lock = NSLock()
    private var baseTx: UInt64 = 0
    private var baseRx: UInt64 = 0
    private var isTracking = false
    private var targetInterfacePrefix: String = "utun"

    private init() {}

    /// Starts tracking traffic from current baseline.
    public func start(mode: ProxyMode) {
        lock.lock()
        defer { lock.unlock() }

        targetInterfacePrefix = (mode == .tun) ? "utun" : ""
        let snapshot = readBytes(prefix: targetInterfacePrefix)
        baseTx = snapshot.tx
        baseRx = snapshot.rx
        isTracking = true
    }

    /// Stops tracking.
    public func stop() {
        lock.lock()
        defer { lock.unlock() }
        isTracking = false
        baseTx = 0
        baseRx = 0
    }

    /// Returns bytes moved since session start: (tx: uploaded/uplink, rx: downloaded/downlink).
    public func currentBytes() -> (tx: UInt64, rx: UInt64) {
        lock.lock()
        defer { lock.unlock() }

        guard isTracking else { return (0, 0) }
        let now = readBytes(prefix: targetInterfacePrefix)

        let tx = now.tx >= baseTx ? (now.tx - baseTx) : 0
        let rx = now.rx >= baseRx ? (now.rx - baseRx) : 0
        return (tx, rx)
    }

    /// Reads total interface bytes from system ifaddrs.
    private func readBytes(prefix: String) -> (tx: UInt64, rx: UInt64) {
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let first = ifap else {
            return (0, 0)
        }
        defer { freeifaddrs(ifap) }

        var totalTx: UInt64 = 0
        var totalRx: UInt64 = 0

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            let name = String(cString: current.pointee.ifa_name)
            let addr = current.pointee.ifa_addr

            // Check AF_LINK socket address
            if let addr = addr, addr.pointee.sa_family == UInt8(AF_LINK) {
                let matches: Bool
                if prefix.isEmpty {
                    // SOCKS5: track primary non-loopback active interfaces (en, utun, etc.)
                    matches = name.hasPrefix("en") || name.hasPrefix("utun") || name.hasPrefix("ap")
                } else {
                    matches = name.hasPrefix(prefix)
                }

                if matches, let data = current.pointee.ifa_data {
                    let ifData = data.assumingMemoryBound(to: if_data64.self)
                    totalTx += ifData.pointee.ifi_obytes
                    totalRx += ifData.pointee.ifi_ibytes
                }
            }
            cursor = current.pointee.ifa_next
        }

        return (totalTx, totalRx)
    }

    /// Formats raw byte count into human-readable string (e.g. "120 Б", "1.2 КБ", "45.8 МБ", "2.1 ГБ").
    public static func formatBytes(_ bytes: UInt64) -> String {
        if bytes < 1024 {
            return "\(bytes) Б"
        }
        let kb = Double(bytes) / 1024.0
        if kb < 1024.0 {
            return String(format: "%.1f КБ", kb)
        }
        let mb = kb / 1024.0
        if mb < 1024.0 {
            return String(format: "%.1f МБ", mb)
        }
        let gb = mb / 1024.0
        return String(format: "%.2f ГБ", gb)
    }
}
```

- [ ] **Шаг 2: Проверить компиляцию**

Выполнить: `cd macos && swift build`
Ожидается: `Build complete!`

- [ ] **Шаг 3: Зафиксировать изменения в git**

Выполнить:
```bash
git commit -m "feat(macos): add NetworkTrafficMonitor for session bytes tracking" -- macos/Sources/OutlineProxy/Core/Services/NetworkTrafficMonitor.swift
```

---

### Task 3: Редизайн полосы статистики (`StatsStrip`) в `MainWindowController.swift`

**Файлы:**
- Изменить: `macos/Sources/OutlineProxy/UI/MainWindowController.swift:200-260, 480-570, 890-970`

**Интерфейсы:**
- Потребляет: `NetworkTrafficMonitor.shared`, `ProfileStore.shared.activeProfile`, `AppState.shared`.
- Создает 3 колонки:
  1. Длительность: иконка таймера, `00:00:00`, `чч:мм:сс`.
  2. Трафик: иконка графика, две строки `↑ <uplink>` и `↓ <downlink>`, обновляется каждую секунду.
  3. Протокол: иконка пульса, две строки `TCP  <Семейство>/<Носитель>` и `UDP  <Семейство>/<Носитель>`.

- [ ] **Шаг 1: Обновить свойства и верстку `statsContainer`**

Заменить старые элементы (`modeValueLabel`, `protocolValueLabel` и одиночные подписи) на новые:
```swift
    // Stats strip (Android parity)
    private let statsContainer = NSView()
    private let statDivider1 = NSBox()
    private let statDivider2 = NSBox()

    // 1. Duration column
    private let durationIconView = NSImageView()
    private let durationHeaderLabel = NSTextField(labelWithString: "ДЛИТЕЛЬНОСТЬ")
    private let durationValueLabel = NSTextField(labelWithString: "00:00:00")
    private let durationCaptionLabel = NSTextField(labelWithString: "чч:мм:сс")

    // 2. Traffic column
    private let trafficIconView = NSImageView()
    private let trafficHeaderLabel = NSTextField(labelWithString: "ТРАФИК")
    private let trafficUpIcon = NSTextField(labelWithString: "↑")
    private let trafficUpValueLabel = NSTextField(labelWithString: "0 Б")
    private let trafficDownIcon = NSTextField(labelWithString: "↓")
    private let trafficDownValueLabel = NSTextField(labelWithString: "0 Б")

    // 3. Protocol column
    private let protocolIconView = NSImageView()
    private let protocolHeaderLabel = NSTextField(labelWithString: "ПРОТОКОЛ")
    private let tcpTagLabel = NSTextField(labelWithString: "TCP")
    private let tcpCarrierLabel = NSTextField(labelWithString: "—")
    private let udpTagLabel = NSTextField(labelWithString: "UDP")
    private let udpCarrierLabel = NSTextField(labelWithString: "—")
```

- [ ] **Шаг 2: Реализовать определение протоколов TCP и UDP с поддержкой H3 / H2 / H1**

Добавить метод вычисления строки протокола:
```swift
    private func updateCarrierLines() {
        guard let profile = ProfileStore.shared.activeProfile else {
            tcpCarrierLabel.stringValue = "—"
            udpCarrierLabel.stringValue = "—"
            return
        }

        let isTcpOnly = AppState.shared.tcpOnly || profile.tcpOnly
        let transportFamily = profile.transport.uppercased() // VLESS / SS / XHTTP / WS

        // Determine mode and HTTP version (H3, H2, H1)
        var carrierMode = "H3"
        let fullConfig = profile.cachedToml + profile.link
        if fullConfig.contains("alpn=h3") {
            carrierMode = isTcpOnly ? "H2" : "H3"
        } else if fullConfig.contains("alpn=h2") || fullConfig.contains("http/2") {
            carrierMode = "H2"
        } else if fullConfig.contains("http/1.1") || fullConfig.contains("h1") {
            carrierMode = "H1"
        }

        // Submode (e.g. XHTTP or WS)
        let subMode: String
        if fullConfig.contains("xhttp") {
            subMode = "XHTTP"
        } else if fullConfig.contains("ws") {
            subMode = "WS"
        } else {
            subMode = transportFamily
        }

        let tcpString: String
        if subMode == transportFamily {
            tcpString = "\(transportFamily)/\(carrierMode)"
        } else {
            tcpString = "\(transportFamily)/\(subMode)/\(carrierMode)"
        }

        tcpCarrierLabel.stringValue = tcpString

        if isTcpOnly {
            udpCarrierLabel.stringValue = "—"
            udpCarrierLabel.textColor = .tertiaryLabelColor
        } else {
            udpCarrierLabel.stringValue = tcpString
            let palette = ThemeManager.shared.palette(for: window)
            udpCarrierLabel.textColor = palette.statsValueText
        }
    }
```

- [ ] **Шаг 3: Обновлять трафик и таймер в тике `Timer`**

В таймере `durationTimer`:
- Каждую секунду форматировать `elapsed` в `00:00:00`.
- Опрашивать `NetworkTrafficMonitor.shared.currentBytes()`, обновлять `trafficUpValueLabel` и `trafficDownValueLabel`.
- При старте подключения вызывать `NetworkTrafficMonitor.shared.start(mode: AppState.shared.mode)`.
- При остановке вызывать `NetworkTrafficMonitor.shared.stop()`.

- [ ] **Шаг 4: Проверить сборку Swift**

Выполнить: `cd macos && swift build`
Ожидается: `Build complete!`

- [ ] **Шаг 5: Зафиксировать изменения в git**

Выполнить:
```bash
git commit -m "feat(macos): implement Android-parity stats strip with traffic and dual tcp/udp carriers" -- macos/Sources/OutlineProxy/UI/MainWindowController.swift
```

---

### Task 4: Создание специализированного окна серверов (`ServersWindowController.swift`)

**Файлы:**
- Создать: `macos/Sources/OutlineProxy/UI/ServersWindowController.swift`

**Интерфейсы:**
- Предоставляет: `ServersWindowController.shared.show()`
- Управляет: таблицей профилей `ProfileStore.shared`, добавлением по URL/ссылке, выбором активного и удалением.

- [ ] **Шаг 1: Написать `ServersWindowController.swift`**

Создать контроллер окна серверов с чистой таблицей профилей (`NSTableView`), индикатором «● АКТИВЕН», кнопками «Сделать активным», «+ Добавить сервер или подписку» и «Удалить»:

```swift
import AppKit

/// Pure AppKit window controller dedicated to managing server profiles and subscriptions.
@MainActor
public final class ServersWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate {
    public static let shared = ServersWindowController()

    private let tableView = NSTableView()
    private var profiles: [ServerProfile] = []
    private let activateButton = NSButton()
    private let addButton = NSButton()
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
            selector: #selector(handleThemeChanged),
            name: ThemeManager.themeChangedNotification,
            object: nil
        )
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    public func show() {
        reloadProfiles()
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

        // Button bar
        activateButton.title = "Сделать активным"
        activateButton.bezelStyle = .rounded
        activateButton.target = self
        activateButton.action = #selector(activateAction)

        addButton.title = "+ Добавить сервер"
        addButton.bezelStyle = .rounded
        addButton.target = self
        addButton.action = #selector(addAction)

        removeButton.title = "Удалить"
        removeButton.bezelStyle = .rounded
        removeButton.target = self
        removeButton.action = #selector(removeAction)

        let buttonStack = NSStackView(views: [activateButton, addButton, removeButton])
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

    @objc private func handleProfilesChanged() {
        reloadProfiles()
    }

    @objc private func handleThemeChanged() {
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
        AppState.shared.selectProfile(id: profile.id)
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
            Task {
                if let updated = try? await SubscriptionFetcher.updateSubscription(profile) {
                    await MainActor.run {
                        ProfileStore.shared.updateProfile(updated)
                    }
                }
            }
        } else if let profile = ServerProfile.parse(link: text) {
            ProfileStore.shared.addProfile(profile)
        }
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
```

- [ ] **Шаг 2: Проверить сборку Swift**

Выполнить: `cd macos && swift build`
Ожидается: `Build complete!`

- [ ] **Шаг 3: Зафиксировать изменения в git**

Выполнить:
```bash
git commit -m "feat(macos): create dedicated ServersWindowController for server and subscription management" -- macos/Sources/OutlineProxy/UI/ServersWindowController.swift
```

---

### Task 5: Рефакторинг `SettingsWindowController.swift` в окно чистых настроек

**Файлы:**
- Изменить: `macos/Sources/OutlineProxy/UI/SettingsWindowController.swift`

**Интерфейсы:**
- Предоставляет: `SettingsWindowController.shared.show()`
- Убирает: таблицу профилей, кнопки управления профилями.
- Содержит:
  - Режим перехвата трафика (`ProxyMode`).
  - Тумблер «Только TCP» (`NSSwitch`).
  - Беспарольный запуск TUN (`PrivilegedHelperManager`).
  - Выбор темы оформления (`ThemeManager`).

- [ ] **Шаг 1: Очистить и перекомпоновать `SettingsWindowController.swift`**

1. Удалить свойства `tableView`, `profiles`, `activateButton`, `addButton`, `removeButton`.
2. Окно сделать размером $520 \times 440$ pt без изменения размера.
3. Разместить 4 аккуратных блока:
   - Блок 1: Режим перехвата трафика (`modePopUpButton`, `bannerSubtitle`).
   - Блок 2: Режим «Только TCP» (`tcpOnlyBox`, `tcpOnlySwitch`, `tcpOnlySubtitle`).
   - Блок 3: Режим TUN без пароля (`tunAuthBox`, `tunAuthButton`, `tunAuthSubtitle`).
   - Блок 4: Тема оформления (`themePopUpButton`).

- [ ] **Шаг 2: Проверить сборку Swift**

Выполнить: `cd macos && swift build`
Ожидается: `Build complete!`

- [ ] **Шаг 3: Зафиксировать изменения в git**

Выполнить:
```bash
git commit -m "refactor(macos): remove server table from SettingsWindowController and focus strictly on system preferences" -- macos/Sources/OutlineProxy/UI/SettingsWindowController.swift
```

---

### Task 6: Обновление вызовов и точек входа во всех контроллерах

**Файлы:**
- Изменить: `macos/Sources/OutlineProxy/UI/MainWindowController.swift:1030-1050`
- Изменить: `macos/Sources/OutlineProxy/UI/StatusMenuController.swift:240-270`
- Изменить: `macos/Sources/OutlineProxy/UI/MainMenuController.swift:225-240`

**Интерфейсы:**
- Клик по карточке сервера, стрелке `>` или кнопке «+ Добавить сервер» $\to$ `ServersWindowController.shared.show()`.
- Клик по «Настройки» в Quick Links $\to$ `SettingsWindowController.shared.show()`.
- Меню Status Bar: пункт «Серверы...» открывает `ServersWindowController`, пункт «Настройки...» открывает `SettingsWindowController`.

- [ ] **Шаг 1: Обновить методы в `MainWindowController.swift`**

```swift
    @objc private func openServersAction() {
        ServersWindowController.shared.show()
    }

    @objc private func addServerAction() {
        ServersWindowController.shared.show()
    }

    @objc private func openSettingsAction() {
        SettingsWindowController.shared.show()
    }
```

- [ ] **Шаг 2: Обновить методы в `StatusMenuController.swift`**

Добавить пункт «Серверы...» (`openServersAction`) и разделить его с «Настройки...» (`openSettingsAction`):
```swift
    @objc private func openServersAction() {
        ServersWindowController.shared.show()
    }

    @objc private func openSettingsAction() {
        SettingsWindowController.shared.show()
    }
```

- [ ] **Шаг 3: Обновить меню в `MainMenuController.swift`**

Развести горячие клавиши: `⌘,` для `openSettingsAction`, и добавить пункт меню «Серверы...» для `ServersWindowController.shared.show()`.

- [ ] **Шаг 4: Проверить сборку Swift**

Выполнить: `cd macos && swift build`
Ожидается: `Build complete!`

- [ ] **Шаг 5: Зафиксировать изменения в git**

Выполнить:
```bash
git commit -m "feat(macos): wire navigation routes to separate Servers and Settings windows" -- macos/Sources/OutlineProxy/UI/MainWindowController.swift macos/Sources/OutlineProxy/UI/StatusMenuController.swift macos/Sources/OutlineProxy/UI/MainMenuController.swift
```

---

### Task 7: Сквозная верификация и запуск гейтов проверки

**Файлы:**
- Все затронутые файлы проекта.

- [ ] **Шаг 1: Полная сборка Swift-бандла**

Выполнить:
```bash
cd macos && swift build -c release
```
Ожидается: успешная компиляция release-версии.

- [ ] **Шаг 2: Проверка CI-гейта монорепозитория**

Выполнить:
```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
cargo test --workspace --exclude sockudo-ws
```
Ожидается: все проверки проходят зелёными без предупреждений.

- [ ] **Шаг 3: Финальный коммит и отчет**

Сформировать отчет о проделанной работе и продемонстрировать выполненные изменения.
