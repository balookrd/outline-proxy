import AppKit

MainActor.assumeIsolated {
    setbuf(stdout, nil)
    setbuf(stderr, nil)
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.run()
}
