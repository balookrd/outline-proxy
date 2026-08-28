package com.outline.proxy

/** One rendered line of cleaned-up release notes. */
sealed interface NoteLine {
    /** A section heading, rendered bold (e.g. "⭐ Features"). */
    data class Header(val text: String) : NoteLine

    /** A list item, rendered with a "•" marker. */
    data class Bullet(val text: String) : NoteLine

    /** A plain paragraph line. */
    data class Text(val text: String) : NoteLine
}

/**
 * Turns a GitHub release body (Markdown, as produced by git-cliff) into a flat
 * list of displayable lines for the update dialog.
 *
 * Deliberately a tiny, forgiving cleaner rather than a Markdown parser: the
 * dialog only ever shows a short changelog, and a real Markdown dependency would
 * cost R8 keep-rules the app does not want. Anything it does not recognise falls
 * through to [NoteLine.Text] unharmed.
 *
 * Returns an empty list when there is nothing user-facing to show — an empty
 * body, a nightly with no notes, or a body that is only the "Full Changelog"
 * link — so the caller can fall back to the plain dialog.
 */
object ReleaseNotes {
    fun format(raw: String): List<NoteLine> {
        val lines = mutableListOf<NoteLine>()
        for (rawLine in raw.lineSequence()) {
            val line = rawLine.trim()
            when {
                line.isEmpty() -> continue
                // "### ⭐ Features" -> Header("⭐ Features"). Checked before the
                // level-2 rule so a level-3 heading is never mistaken for it.
                line.startsWith("### ") ->
                    lines += NoteLine.Header(stripInline(line.removePrefix("### ")))
                // "## What's Changed in <tag>" duplicates the dialog title; drop
                // any level-2 heading.
                line.startsWith("## ") -> continue
                // Technical compare link, not a user-facing change.
                line.startsWith("**Full Changelog**") -> continue
                // "- **scope**: msg" / "* msg" -> Bullet.
                line.startsWith("- ") || line.startsWith("* ") ->
                    lines += NoteLine.Bullet(stripInline(line.drop(2)))
                else -> lines += NoteLine.Text(stripInline(line))
            }
        }
        // Nothing structured survived: signal the caller to fall back.
        return if (lines.any { it is NoteLine.Header || it is NoteLine.Bullet }) lines else emptyList()
    }

    /** Strip the only inline markup git-cliff emits: bold `**…**`. */
    private fun stripInline(s: String): String = s.replace("**", "").trim()
}
