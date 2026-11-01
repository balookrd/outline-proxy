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
    /// Background checks run at most this often; a manual check always runs.
    private static let backgroundInterval: TimeInterval = 24 * 60 * 60

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

        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in
            self?.checkInBackgroundIfDue()
        }
        timer = Timer.scheduledTimer(withTimeInterval: 60 * 60, repeats: true) { _ in
            Task { @MainActor in UpdateController.shared.checkInBackgroundIfDue() }
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

    /// Quiet daily check: an available build only shows up in the footer and
    /// the menu — nothing is downloaded until the user asks.
    private func checkInBackgroundIfDue() {
        if busy || available != nil { return }
        let last = UserDefaults.standard.double(forKey: Self.lastCheckKey)
        guard Date().timeIntervalSince1970 - last >= Self.backgroundInterval else { return }
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
        let alert = NSAlert()
        alert.messageText = "Доступно обновление"
        var info = "Для канала \(AppVersion.channel) опубликована сборка \(update.label)."
        if let blocker {
            info += "\n\nАвтоустановка недоступна: \(blocker). DMG будет сохранён в «Загрузки» и открыт — перетащите приложение в «Программы»."
            alert.addButton(withTitle: "Скачать")
        } else {
            info += "\n\nПриложение скачает её, заменит себя и перезапустится."
            if AppState.shared.isConnected {
                info += " Туннель переподключится сам."
            }
            alert.addButton(withTitle: "Установить и перезапустить")
        }
        alert.informativeText = info
        alert.addButton(withTitle: "Позже")

        let notes = ReleaseNotes.format(update.notes)
        if !notes.isEmpty {
            alert.accessoryView = notesView(notes)
        }

        NSApp.activate(ignoringOtherApps: true)
        if alert.runModal() == .alertFirstButtonReturn {
            install(update)
        }
    }

    /// A long changelog scrolls inside the dialog instead of growing it off-screen.
    private func notesView(_ notes: [NoteLine]) -> NSView {
        let text = NSMutableAttributedString()
        let body = NSFont.systemFont(ofSize: 12)
        let bold = NSFont.systemFont(ofSize: 12, weight: .semibold)
        let bullet = NSMutableParagraphStyle()
        bullet.headIndent = 14
        bullet.paragraphSpacing = 2
        let header = NSMutableParagraphStyle()
        header.paragraphSpacingBefore = 8
        header.paragraphSpacing = 2

        text.append(NSAttributedString(string: "Что нового\n", attributes: [.font: bold, .foregroundColor: NSColor.labelColor]))
        for line in notes {
            switch line {
            case .header(let s):
                text.append(NSAttributedString(string: s + "\n", attributes: [
                    .font: bold, .paragraphStyle: header, .foregroundColor: NSColor.labelColor,
                ]))
            case .bullet(let s):
                text.append(NSAttributedString(string: "•  " + s + "\n", attributes: [
                    .font: body, .paragraphStyle: bullet, .foregroundColor: NSColor.labelColor,
                ]))
            case .text(let s):
                text.append(NSAttributedString(string: s + "\n", attributes: [
                    .font: body, .foregroundColor: NSColor.labelColor,
                ]))
            }
        }

        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 380, height: 240))
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        let textView = NSTextView(frame: scroll.contentView.bounds)
        textView.isEditable = false
        textView.isSelectable = true
        textView.drawsBackground = false
        textView.textContainerInset = NSSize(width: 6, height: 6)
        textView.autoresizingMask = [.width]
        textView.textStorage?.setAttributedString(text)
        scroll.documentView = textView
        return scroll
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
