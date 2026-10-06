import AppKit

/// Main application delegate managing lifecycle and menu-bar setup.
@MainActor
public final class AppDelegate: NSObject, NSApplicationDelegate {
    private var sigintSource: DispatchSourceSignal?
    private var sigtermSource: DispatchSourceSignal?

    public func applicationDidFinishLaunching(_ notification: Notification) {
        // Standard application mode ensures the app is visible in the Dock/taskbar
        NSApp.setActivationPolicy(.regular)

        // Setup AppleEvent reopen listener for guaranteed dock/taskbar click handling
        setupReopenEventHandler()

        // Modern safe signal handling on main queue
        setupSignalHandlers()

        StatusMenuController.shared.setup()

        // Show Android-styled main window upon application launch
        MainWindowController.shared.show()
    }

    /// Invoked when user clicks the Dock/taskbar icon while the application is already running.
    public func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        MainWindowController.shared.show()
        return true
    }

    /// Invoked whenever the application gains active focus (e.g. via Taskbar, Dock, App Switcher).
    public func applicationDidBecomeActive(_ notification: Notification) {
        if !MainWindowController.shared.isWindowVisible {
            MainWindowController.shared.show()
        }
    }

    public func applicationWillTerminate(_ notification: Notification) {
        AppState.shared.cleanupOnExit()
    }

    private func setupReopenEventHandler() {
        let eventManager = NSAppleEventManager.shared()
        eventManager.setEventHandler(
            self,
            andSelector: #selector(handleReopenAppleEvent(_:withReplyEvent:)),
            forEventClass: AEEventClass(0x61657674), // 'aevt'
            andEventID: AEEventID(0x72617070)        // 'rapp' (kAEReopenApplication)
        )
        eventManager.setEventHandler(
            self,
            andSelector: #selector(handleReopenAppleEvent(_:withReplyEvent:)),
            forEventClass: AEEventClass(0x61657674), // 'aevt'
            andEventID: AEEventID(0x6f617070)        // 'oapp' (kAEOpenApplication)
        )
    }

    @objc private func handleReopenAppleEvent(_ event: NSAppleEventDescriptor, withReplyEvent reply: NSAppleEventDescriptor) {
        MainWindowController.shared.show()
    }

    private func setupSignalHandlers() {
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)

        let sigint = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        sigint.setEventHandler {
            AppState.shared.cleanupOnExit()
            exit(0)
        }
        sigint.resume()
        self.sigintSource = sigint

        let sigterm = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        sigterm.setEventHandler {
            AppState.shared.cleanupOnExit()
            exit(0)
        }
        sigterm.resume()
        self.sigtermSource = sigterm
    }
}
