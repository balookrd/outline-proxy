import AppKit

/// Pure AppKit window controller for viewing process logs in real time.
@MainActor
public final class LogWindowController: NSWindowController, NSWindowDelegate {
    public static let shared = LogWindowController()

    private var textView: NSTextView!
    private var scrollView: NSScrollView!
    private let lineCountLabel = NSTextField(labelWithString: "0 строк")
    private var updateTimer: Timer?
    private var lastRenderedCount: Int = -1

    private init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 760, height: 480),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Журнал событий — Outline Proxy"
        window.center()
        window.isReleasedWhenClosed = false

        super.init(window: window)
        window.delegate = self

        setupUI()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    private func setupUI() {
        guard let contentView = window?.contentView else { return }

        // Configure robust NSScrollView and inner NSTextView
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = false
        scroll.autohidesScrollers = true
        scroll.borderType = .noBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false

        let contentSize = scroll.contentSize
        let text = NSTextView(frame: NSRect(origin: .zero, size: contentSize))
        text.minSize = NSSize(width: 0.0, height: contentSize.height)
        text.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        text.isVerticallyResizable = true
        text.isHorizontallyResizable = false
        text.autoresizingMask = [.width]
        text.textContainer?.containerSize = NSSize(width: contentSize.width, height: CGFloat.greatestFiniteMagnitude)
        text.textContainer?.widthTracksTextView = true

        text.isEditable = false
        text.isSelectable = true
        text.isRichText = false
        text.importsGraphics = false
        text.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        text.textColor = .textColor
        text.backgroundColor = .textBackgroundColor

        scroll.documentView = text
        self.scrollView = scroll
        self.textView = text

        // Bottom toolbar
        let copyButton = NSButton(title: "Копировать всё", target: self, action: #selector(copyAllAction))
        let clearButton = NSButton(title: "Очистить", target: self, action: #selector(clearAction))

        lineCountLabel.font = NSFont.systemFont(ofSize: 11)
        lineCountLabel.textColor = .secondaryLabelColor

        let bottomStack = NSStackView(views: [copyButton, clearButton, lineCountLabel])
        bottomStack.orientation = .horizontal
        bottomStack.spacing = 10
        bottomStack.translatesAutoresizingMaskIntoConstraints = false

        contentView.addSubview(scroll)
        contentView.addSubview(bottomStack)

        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 12),
            scroll.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 12),
            scroll.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -12),
            scroll.bottomAnchor.constraint(equalTo: bottomStack.topAnchor, constant: -10),

            bottomStack.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 12),
            bottomStack.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -12),
            bottomStack.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -10),
            bottomStack.heightAnchor.constraint(equalToConstant: 28)
        ])
    }

    public func show() {
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        renderLogs()
        startUpdateTimer()
    }

    public func windowWillClose(_ notification: Notification) {
        stopUpdateTimer()
    }

    private func startUpdateTimer() {
        stopUpdateTimer()
        updateTimer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.checkAndRenderLogs()
            }
        }
    }

    private func stopUpdateTimer() {
        updateTimer?.invalidate()
        updateTimer = nil
    }

    private func checkAndRenderLogs() {
        let currentCount = ProcessController.shared.logCount
        if currentCount != lastRenderedCount {
            renderLogs()
        }
    }

    private func renderLogs() {
        let logs = ProcessController.shared.logs
        lastRenderedCount = logs.count
        textView.string = logs.joined(separator: "\n")
        lineCountLabel.stringValue = "\(logs.count) строк"

        let length = (textView.string as NSString).length
        if length > 0 {
            textView.scrollRangeToVisible(NSRange(location: length, length: 0))
        }
    }

    @objc private func copyAllAction() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(textView.string, forType: .string)
    }

    @objc private func clearAction() {
        textView.string = ""
        lastRenderedCount = 0
        lineCountLabel.stringValue = "0 строк"
    }
}
