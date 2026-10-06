import AppKit

/// Main application delegate managing lifecycle and menu-bar setup.
@MainActor
public final class AppDelegate: NSObject, NSApplicationDelegate {
    private var sigintSource: DispatchSourceSignal?
    private var sigtermSource: DispatchSourceSignal?

    public func applicationDidFinishLaunching(_ notification: Notification) {
        // Accessory mode ensures the app runs in the status bar without polluting the macOS Dock
        NSApp.setActivationPolicy(.accessory)

        // Set application icon from bundled resources if available
        if let iconURL = Bundle.main.url(forResource: "AppIcon", withExtension: "png") ??
                         Bundle.main.url(forResource: "AppIcon_round", withExtension: "png"),
           let img = NSImage(contentsOf: iconURL) {
            NSApp.applicationIconImage = img
        }

        // Modern safe signal handling on main queue
        setupSignalHandlers()

        StatusMenuController.shared.setup()

        // Show Android-styled main window upon application launch
        MainWindowController.shared.show()
    }

    public func applicationWillTerminate(_ notification: Notification) {
        AppState.shared.cleanupOnExit()
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
