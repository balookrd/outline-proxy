package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ReleaseNotesTest {
    @Test
    fun `git-cliff body yields clean headers and bullets`() {
        val body = """
            ## What's Changed in android-v1.3.0

            ### ⭐ Features
            - **android**: Localize UI by system locale
            - **android**: Persistent notification you can keep

            ### 🐛 Bug Fixes
            - **android**: Keep the session traffic counter

            ### 🎨 Styling & UI
            - **android**: Preserve original breathing room in launcher icons

            **Full Changelog**: https://github.com/balookrd/outline-proxy/compare/android-v1.2.0...android-v1.3.0
        """.trimIndent()

        val out = ReleaseNotes.format(body)

        assertEquals(
            listOf(
                NoteLine.Header("⭐ Features"),
                NoteLine.Bullet("android: Localize UI by system locale"),
                NoteLine.Bullet("android: Persistent notification you can keep"),
                NoteLine.Header("🐛 Bug Fixes"),
                NoteLine.Bullet("android: Keep the session traffic counter"),
                NoteLine.Header("🎨 Styling & UI"),
                NoteLine.Bullet("android: Preserve original breathing room in launcher icons"),
            ),
            out,
        )
        assertTrue(out.none { lineText(it).contains("**") })
        assertTrue(out.none { lineText(it).contains("#") })
    }

    @Test
    fun `breaking section is preserved`() {
        val body = """
            ## What's Changed in ss-v2.0.0

            ### ⚠️ BREAKING CHANGES
            - **config**: Remove per-user carrier paths
        """.trimIndent()

        val out = ReleaseNotes.format(body)

        assertEquals(NoteLine.Header("⚠️ BREAKING CHANGES"), out.first())
        assertTrue(out.contains(NoteLine.Bullet("config: Remove per-user carrier paths")))
    }

    @Test
    fun `body with only the compare link falls back to empty`() {
        val body =
            "**Full Changelog**: https://github.com/balookrd/outline-proxy/compare/ui-nightly...android-v1.2.0"
        assertEquals(emptyList<NoteLine>(), ReleaseNotes.format(body))
    }

    @Test
    fun `empty body is empty`() {
        assertEquals(emptyList<NoteLine>(), ReleaseNotes.format(""))
    }

    @Test
    fun `scope bold is stripped from a bullet`() {
        assertEquals(
            listOf(NoteLine.Bullet("uplink: Base status latency on round-trip")),
            ReleaseNotes.format("- **uplink**: Base status latency on round-trip"),
        )
    }

    private fun lineText(line: NoteLine): String = when (line) {
        is NoteLine.Header -> line.text
        is NoteLine.Bullet -> line.text
        is NoteLine.Text -> line.text
    }
}
