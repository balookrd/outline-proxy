import Foundation

/// One rendered line of cleaned-up release notes.
public enum NoteLine: Equatable {
    /// A section heading, rendered bold (e.g. "⭐ Features").
    case header(String)
    /// A list item, rendered with a "•" marker.
    case bullet(String)
    /// A plain paragraph line.
    case text(String)
}

/// Turns a GitHub release body (Markdown, as produced by git-cliff) into a flat
/// list of displayable lines for the update dialog — a port of the Android
/// client's `ReleaseNotes.kt`.
///
/// Deliberately a tiny, forgiving cleaner rather than a Markdown parser: the
/// dialog only shows a changelog. Returns an empty list when there is nothing
/// user-facing to show, so the caller can fall back to the plain dialog.
public enum ReleaseNotes {
    public static func format(_ raw: String) -> [NoteLine] {
        var lines: [NoteLine] = []
        for rawLine in raw.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            // Checked before the level-2 rule so a level-3 heading is never
            // mistaken for it.
            if line.hasPrefix("### ") {
                lines.append(.header(stripInline(String(line.dropFirst(4)))))
            } else if line.hasPrefix("## ") {
                // "## What's Changed in <tag>" duplicates the dialog title.
                continue
            } else if line.hasPrefix("**Full Changelog**") {
                // Technical compare link, not a user-facing change.
                continue
            } else if line.hasPrefix("- ") || line.hasPrefix("* ") {
                lines.append(.bullet(stripInline(String(line.dropFirst(2)))))
            } else if case .bullet(let previous)? = lines.last {
                // git-cliff wraps long entries; a continuation line belongs to
                // the bullet above it.
                lines[lines.count - 1] = .bullet(previous + " " + stripInline(line))
            } else {
                lines.append(.text(stripInline(line)))
            }
        }
        // Nothing structured survived: signal the caller to fall back.
        let structured = lines.contains { line in
            if case .text = line { return false }
            return true
        }
        return structured ? lines : []
    }

    /// Strip the only inline markup git-cliff emits: bold `**…**`.
    private static func stripInline(_ s: String) -> String {
        s.replacingOccurrences(of: "**", with: "").trimmingCharacters(in: .whitespaces)
    }
}
