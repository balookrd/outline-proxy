import AppKit

/// The "update available" window: release notes in a scrollable list plus
/// install / later buttons.
///
/// Deliberately not an `NSAlert` with an accessory view: inside `runModal` the
/// alert jumped the notes to the middle on open and the scroll view ignored the
/// mouse wheel (only dragging the scroller worked). An ordinary, non-modal panel
/// keeps the run loop in its normal mode, so scrolling behaves like in every
/// other window of the app.
@MainActor
final class UpdateDialog: NSObject, NSWindowDelegate {
    /// The open dialog, kept alive while its panel is on screen.
    private static var current: UpdateDialog?

    private let panel: NSPanel
    private let textView: NSTextView?
    private let onConfirm: () -> Void

    static func show(
        title: String,
        message: String,
        notes: [NoteLine],
        confirmTitle: String,
        onConfirm: @escaping () -> Void
    ) {
        current?.panel.close()
        let dialog = UpdateDialog(title: title, message: message, notes: notes, confirmTitle: confirmTitle, onConfirm: onConfirm)
        current = dialog
        dialog.present()
    }

    private init(title: String, message: String, notes: [NoteLine], confirmTitle: String, onConfirm: @escaping () -> Void) {
        self.onConfirm = onConfirm
        panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 440, height: 200),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        panel.title = "Обновление Outline Proxy"
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false

        let icon = NSImageView(image: NSApp.applicationIconImage ?? NSImage())
        icon.translatesAutoresizingMaskIntoConstraints = false
        icon.widthAnchor.constraint(equalToConstant: 56).isActive = true
        icon.heightAnchor.constraint(equalToConstant: 56).isActive = true

        let titleLabel = NSTextField(labelWithString: title)
        titleLabel.font = NSFont.systemFont(ofSize: 15, weight: .semibold)
        let messageLabel = NSTextField(wrappingLabelWithString: message)
        messageLabel.font = NSFont.systemFont(ofSize: 12.5)
        messageLabel.preferredMaxLayoutWidth = 320

        let textStack = NSStackView(views: [titleLabel, messageLabel])
        textStack.orientation = .vertical
        textStack.alignment = .leading
        textStack.spacing = 6

        let header = NSStackView(views: [icon, textStack])
        header.orientation = .horizontal
        header.alignment = .top
        header.spacing = 14

        var rows: [NSView] = [header]
        if notes.isEmpty {
            textView = nil
        } else {
            let scroll = NSTextView.scrollableTextView()
            scroll.hasVerticalScroller = true
            scroll.borderType = .bezelBorder
            scroll.translatesAutoresizingMaskIntoConstraints = false
            scroll.heightAnchor.constraint(equalToConstant: 260).isActive = true
            let notesView = scroll.documentView as! NSTextView
            notesView.isEditable = false
            notesView.isSelectable = true
            notesView.drawsBackground = false
            notesView.textContainerInset = NSSize(width: 6, height: 6)
            notesView.textStorage?.setAttributedString(Self.render(notes))
            notesView.setSelectedRange(NSRange(location: 0, length: 0))
            textView = notesView
            rows.append(scroll)
        }

        let later = NSButton(title: "Позже", target: nil, action: nil)
        later.keyEquivalent = "\u{1b}"
        let confirm = NSButton(title: confirmTitle, target: nil, action: nil)
        confirm.keyEquivalent = "\r"
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let buttons = NSStackView(views: [spacer, later, confirm])
        buttons.orientation = .horizontal
        buttons.spacing = 10
        rows.append(buttons)

        let root = NSStackView(views: rows)
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 16
        root.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        root.translatesAutoresizingMaskIntoConstraints = false
        for row in rows where row !== header {
            row.widthAnchor.constraint(equalTo: root.widthAnchor, constant: -40).isActive = true
        }

        let content = NSView()
        content.addSubview(root)
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            root.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            root.topAnchor.constraint(equalTo: content.topAnchor),
            root.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            content.widthAnchor.constraint(equalToConstant: 440),
        ])
        panel.contentView = content
        // Keyboard focus on the default button, not in the notes: a focused
        // text view scrolls itself to its selection.
        panel.initialFirstResponder = confirm

        super.init()
        later.target = self
        later.action = #selector(laterClicked)
        confirm.target = self
        confirm.action = #selector(confirmClicked)
        panel.delegate = self
    }

    private func present() {
        panel.layoutIfNeeded()
        panel.setContentSize(panel.contentView!.fittingSize)
        panel.center()
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        scrollNotesToTop()
        // Layout settles after the first display pass; pin the top once more.
        DispatchQueue.main.async { [weak self] in self?.scrollNotesToTop() }
    }

    private func scrollNotesToTop() {
        guard let textView, let clip = textView.enclosingScrollView?.contentView else { return }
        clip.scroll(to: .zero)
        textView.enclosingScrollView?.reflectScrolledClipView(clip)
    }

    @objc private func laterClicked() {
        panel.close()
    }

    @objc private func confirmClicked() {
        panel.close()
        onConfirm()
    }

    func windowWillClose(_ notification: Notification) {
        if Self.current === self { Self.current = nil }
    }

    private static func render(_ notes: [NoteLine]) -> NSAttributedString {
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
        return text
    }
}
