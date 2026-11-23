import AppKit
import Foundation

/// Drives the update flow from the UI: the version footer and the status menu
/// both ask it to check, it shows the release-notes dialog and runs the install.
@MainActor
public final class UpdateController {
    public static let shared = UpdateController()

    /// Posted whenever [status] or [available] changes.
    public static let didChange = NSNotification.Name("UpdateStatusChanged")

    private static let lastCheckKey = "OutlineProxy.LastUpdateCheck"
    private static let reconnectKey = "OutlineProxy.ReconnectAfterUpdate"

    /// What the version footer appends ("проверка…", "загрузка 42%"); nil when
    /// there is nothing to report.
    public private(set) var status: String? { didSet { notify() } }
    /// A newer build found by the last check, kept so a second click goes
    /// straight to the dialog.
    public private(set) var available: UpdateChecker.Update? { didSet { notify() } }
    /// One check or download at a time.
    public private(set) var busy = false { didSet { notify() } }

    private var timer: Timer?

    private init() {}

    /// Called once at launch.
    public func start() {
        UpdateInstaller.cleanupLeftovers()

        // The app quit itself to install an update while connected: pick the
        // tunnel back up so the update is invisible apart from the restart.
        if UserDefaults.standard.bool(forKey: Self.reconnectKey) {
            UserDefaults.standard.removeObject(forKey: Self.reconnectKey)
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                if !AppState.shared.isConnected { AppState.shared.connect() }
            }
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + UpdateSchedule.startupDelay) { [weak self] in
            self?.checkInBackground(force: true)
        }
        timer = Timer.scheduledTimer(withTimeInterval: UpdateSchedule.pollInterval, repeats: true) { _ in
            Task { @MainActor in UpdateController.shared.checkInBackground(force: false) }
        }
    }

    /// Footer / menu click: show a known update, otherwise ask GitHub.
    public func checkInteractively() {
        if busy { return }
        if let update = available {
            presentDialog(for: update)
            return
        }
        busy = true
        status = "проверка обновлений…"
        Task {
            let result = await UpdateChecker.check()
            busy = false
            switch result {
            case .available(let update):
                markChecked()
                available = update
                status = "доступно \(update.label)"
                presentDialog(for: update)
            case .upToDate:
                markChecked()
                status = "актуальная версия"
            case .failed(let reason):
                status = "не удалось проверить: \(reason)"
            }
        }
    }

    /// Quiet startup / weekly check: an available build only shows up in the footer
    /// and the menu — nothing is downloaded until the user asks.
    private func checkInBackground(force: Bool) {
        if busy || available != nil { return }
        let last = UserDefaults.standard.double(forKey: Self.lastCheckKey)
        guard UpdateSchedule.isDue(lastCheck: last, now: Date().timeIntervalSince1970, force: force) else {
            return
        }
        busy = true
        Task {
            let result = await UpdateChecker.check()
            busy = false
            switch result {
            case .available(let update):
                markChecked()
                available = update
                status = "доступно \(update.label) — нажмите"
            case .upToDate:
                markChecked()
            case .failed:
                // Silent: the next hourly tick retries.
                break
            }
        }
    }

    private func markChecked() {
        UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: Self.lastCheckKey)
    }

    // MARK: - Dialog

    private func presentDialog(for update: UpdateChecker.Update) {
        let blocker = UpdateInstaller.inPlaceBlocker()
        var message = "Для канала \(AppVersion.channel) опубликована сборка \(update.label)."
        let confirmTitle: String
        if let blocker {
            message += "\n\nАвтоустановка недоступна: \(blocker). DMG будет сохранён в «Загрузки» и открыт — перетащите приложение в «Программы»."
            confirmTitle = "Скачать"
        } else {
            message += "\n\nПриложение скачает её, заменит себя и перезапустится."
            if AppState.shared.isConnected {
                message += " Туннель переподключится сам."
            }
            confirmTitle = "Установить и перезапустить"
        }
        UpdateDialog.show(
            title: "Доступно обновление",
            message: message,
            notes: ReleaseNotes.format(update.notes),
            confirmTitle: confirmTitle
        ) { [weak self] in
            self?.install(update)
        }
    }

    // MARK: - Install

    private func install(_ update: UpdateChecker.Update) {
        if busy { return }
        busy = true
        status = "загрузка 0%"
        Task {
            let dmg: URL
            do {
                dmg = try await UpdateInstaller.download(update) { percent in
                    Task { @MainActor in
                        let controller = UpdateController.shared
                        if controller.busy { controller.status = "загрузка \(percent)%" }
                    }
                }
            } catch {
                busy = false
                status = "ошибка загрузки: \(error.localizedDescription)"
                return
            }

            // Set only when an in-place install was attempted and failed; a known
            // blocker was already explained in the dialog.
            var installError: String?
            if UpdateInstaller.inPlaceBlocker() == nil {
                status = "установка…"
                do {
                    let staged = try await Task.detached { try UpdateInstaller.stage(dmg: dmg) }.value
                    try UpdateInstaller.launchSwapper(for: staged)
                    if AppState.shared.isConnected {
                        UserDefaults.standard.set(true, forKey: Self.reconnectKey)
                    }
                    AppState.shared.cleanupOnExit()
                    NSApp.terminate(nil)
                    return
                } catch {
                    installError = error.localizedDescription
                }
            }

            // Could not replace the bundle: hand the DMG to the user instead.
            busy = false
            do {
                let saved = try UpdateInstaller.handOff(dmg: dmg, assetName: update.assetName)
                status = "DMG открыт — перетащите приложение в «Программы»"
                if let installError {
                    let alert = NSAlert()
                    alert.messageText = "Обновление не установилось автоматически"
                    alert.informativeText = "\(installError).\n\nПроверенный образ сохранён в \(saved.path) и открыт в Finder: перетащите Outline Proxy в «Программы» с заменой и запустите заново."
                    alert.runModal()
                }
            } catch {
                status = "не удалось сохранить DMG: \(error.localizedDescription)"
            }
        }
    }

    private func notify() {
        NotificationCenter.default.post(name: Self.didChange, object: nil)
    }
}
