import AppKit

/// Builds and manages the standard macOS Application Main Menu (`NSApp.mainMenu`).
/// Ensures system-standard shortcuts (Cmd+Q, Cmd+W, Cmd+M, Cmd+H, Cmd+C, Cmd+V, Cmd+A)
/// and menu bar items function properly in pure-code AppKit applications.
@MainActor
public final class MainMenuController {

    public static func setup() {
        let mainMenu = NSMenu()

        let appName = Bundle.main.infoDictionary?["CFBundleDisplayName"] as? String
            ?? Bundle.main.infoDictionary?["CFBundleName"] as? String
            ?? "Outline Proxy"

        // 1. Application Menu ("Outline Proxy")
        let appMenuItem = NSMenuItem()
        let appMenu = NSMenu(title: appName)
        appMenuItem.submenu = appMenu

        let aboutItem = NSMenuItem(
            title: "О программе \(appName)",
            action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)),
            keyEquivalent: ""
        )
        aboutItem.target = NSApp
        appMenu.addItem(aboutItem)

        appMenu.addItem(NSMenuItem.separator())

        let settingsItem = NSMenuItem(
            title: "Настройки...",
            action: #selector(openSettingsAction),
            keyEquivalent: ","
        )
        settingsItem.target = self
        appMenu.addItem(settingsItem)

        appMenu.addItem(NSMenuItem.separator())

        // Standard Services submenu
        let servicesItem = NSMenuItem(title: "Службы", action: nil, keyEquivalent: "")
        let servicesMenu = NSMenu(title: "Службы")
        servicesItem.submenu = servicesMenu
        NSApp.servicesMenu = servicesMenu
        appMenu.addItem(servicesItem)

        appMenu.addItem(NSMenuItem.separator())

        let hideItem = NSMenuItem(
            title: "Скрыть \(appName)",
            action: #selector(NSApplication.hide(_:)),
            keyEquivalent: "h"
        )
        hideItem.target = NSApp
        appMenu.addItem(hideItem)

        let hideOthersItem = NSMenuItem(
            title: "Скрыть остальные",
            action: #selector(NSApplication.hideOtherApplications(_:)),
            keyEquivalent: "h"
        )
        hideOthersItem.keyEquivalentModifierMask = [.command, .option]
        hideOthersItem.target = NSApp
        appMenu.addItem(hideOthersItem)

        let showAllItem = NSMenuItem(
            title: "Показать все",
            action: #selector(NSApplication.unhideAllApplications(_:)),
            keyEquivalent: ""
        )
        showAllItem.target = NSApp
        appMenu.addItem(showAllItem)

        appMenu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(
            title: "Завершить \(appName)",
            action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: "q"
        )
        quitItem.target = NSApp
        appMenu.addItem(quitItem)

        mainMenu.addItem(appMenuItem)

        // 2. File Menu ("Файл")
        let fileMenuItem = NSMenuItem()
        let fileMenu = NSMenu(title: "Файл")
        fileMenuItem.submenu = fileMenu

        let openMainItem = NSMenuItem(
            title: "Главное окно",
            action: #selector(openMainWindowAction),
            keyEquivalent: "o"
        )
        openMainItem.target = self
        fileMenu.addItem(openMainItem)

        let toggleItem = NSMenuItem(
            title: "Подключить / Отключить",
            action: #selector(toggleConnectionAction),
            keyEquivalent: "c"
        )
        toggleItem.keyEquivalentModifierMask = [.command, .shift]
        toggleItem.target = self
        fileMenu.addItem(toggleItem)

        fileMenu.addItem(NSMenuItem.separator())

        // Cmd+W: performClose routed through First Responder to the active window
        let closeItem = NSMenuItem(
            title: "Закрыть окно",
            action: #selector(NSWindow.performClose(_:)),
            keyEquivalent: "w"
        )
        closeItem.target = nil
        fileMenu.addItem(closeItem)

        mainMenu.addItem(fileMenuItem)

        // 3. Edit Menu ("Правка") — critical for text editing & clipboard shortcuts
        let editMenuItem = NSMenuItem()
        let editMenu = NSMenu(title: "Правка")
        editMenuItem.submenu = editMenu

        let undoItem = NSMenuItem(title: "Отменить", action: #selector(UndoManager.undo), keyEquivalent: "z")
        undoItem.target = nil
        editMenu.addItem(undoItem)

        let redoItem = NSMenuItem(title: "Повторить", action: #selector(UndoManager.redo), keyEquivalent: "Z")
        redoItem.keyEquivalentModifierMask = [.command, .shift]
        redoItem.target = nil
        editMenu.addItem(redoItem)

        editMenu.addItem(NSMenuItem.separator())

        let cutItem = NSMenuItem(title: "Вырезать", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        cutItem.target = nil
        editMenu.addItem(cutItem)

        let copyItem = NSMenuItem(title: "Скопировать", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        copyItem.target = nil
        editMenu.addItem(copyItem)

        let pasteItem = NSMenuItem(title: "Вставить", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        pasteItem.target = nil
        editMenu.addItem(pasteItem)

        let selectAllItem = NSMenuItem(title: "Выбрать все", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        selectAllItem.target = nil
        editMenu.addItem(selectAllItem)

        mainMenu.addItem(editMenuItem)

        // 4. View Menu ("Вид")
        let viewMenuItem = NSMenuItem()
        let viewMenu = NSMenu(title: "Вид")
        viewMenuItem.submenu = viewMenu

        let logsItem = NSMenuItem(
            title: "Журнал (логи)...",
            action: #selector(openLogsAction),
            keyEquivalent: "l"
        )
        logsItem.target = self
        viewMenu.addItem(logsItem)

        mainMenu.addItem(viewMenuItem)

        // 5. Window Menu ("Окно")
        let windowMenuItem = NSMenuItem()
        let windowMenu = NSMenu(title: "Окно")
        windowMenuItem.submenu = windowMenu

        let minimizeItem = NSMenuItem(
            title: "Свернуть",
            action: #selector(NSWindow.performMiniaturize(_:)),
            keyEquivalent: "m"
        )
        minimizeItem.target = nil
        windowMenu.addItem(minimizeItem)

        let zoomItem = NSMenuItem(
            title: "Изменить масштаб",
            action: #selector(NSWindow.performZoom(_:)),
            keyEquivalent: ""
        )
        zoomItem.target = nil
        windowMenu.addItem(zoomItem)

        windowMenu.addItem(NSMenuItem.separator())

        let bringAllItem = NSMenuItem(
            title: "Все окна на передний план",
            action: #selector(NSApplication.arrangeInFront(_:)),
            keyEquivalent: ""
        )
        bringAllItem.target = NSApp
        windowMenu.addItem(bringAllItem)

        NSApp.windowsMenu = windowMenu
        mainMenu.addItem(windowMenuItem)

        // 6. Help Menu ("Справка")
        let helpMenuItem = NSMenuItem()
        let helpMenu = NSMenu(title: "Справка")
        helpMenuItem.submenu = helpMenu

        let githubItem = NSMenuItem(
            title: "Репозиторий Outline Proxy на GitHub",
            action: #selector(openGitHubAction),
            keyEquivalent: ""
        )
        githubItem.target = self
        helpMenu.addItem(githubItem)

        mainMenu.addItem(helpMenuItem)

        NSApp.mainMenu = mainMenu
    }

    // MARK: - Actions

    @objc private static func openMainWindowAction() {
        MainWindowController.shared.show()
    }

    @objc private static func openSettingsAction() {
        SettingsWindowController.shared.show()
    }

    @objc private static func openLogsAction() {
        LogWindowController.shared.show()
    }

    @objc private static func toggleConnectionAction() {
        AppState.shared.toggleConnection()
    }

    @objc private static func openGitHubAction() {
        if let url = URL(string: "https://github.com/balookrd/outline-proxy") {
            NSWorkspace.shared.open(url)
        }
    }
}
