package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateCheckerTest {

    @Test
    fun `evaluateRelease detects newer CalVer release over legacy 1_9_x`() {
        val release = UpdateChecker.ReleaseMeta(
            tagName = "v26.11.0",
            draft = false,
            body = "### ⭐ Features\n- Unified release",
            assets = listOf(
                UpdateChecker.ReleaseAsset(
                    name = "outline-proxy-26.11.0-arm64-v8a.apk",
                    downloadUrl = "https://example.invalid/outline-proxy-26.11.0-arm64-v8a.apk",
                ),
            ),
        )

        val result = UpdateChecker.evaluateRelease(release, "1.9.1")
        assertTrue(result is UpdateChecker.Result.Available)
        val avail = result as UpdateChecker.Result.Available
        assertEquals("v26.11.0", avail.label)
        assertEquals("outline-proxy-26.11.0-arm64-v8a.apk", avail.assetName)
    }

    @Test
    fun `evaluateRelease compares CalVer minor and patch numerically`() {
        val newerPatch = UpdateChecker.ReleaseMeta(
            tagName = "v26.11.1",
            draft = false,
            body = "",
            assets = listOf(
                UpdateChecker.ReleaseAsset(
                    name = "outline-proxy-26.11.1-arm64-v8a.apk",
                    downloadUrl = "https://example.invalid/apk",
                ),
            ),
        )
        assertTrue(UpdateChecker.evaluateRelease(newerPatch, "26.11.0") is UpdateChecker.Result.Available)
        assertEquals(UpdateChecker.Result.UpToDate, UpdateChecker.evaluateRelease(newerPatch, "26.11.1"))
        assertEquals(UpdateChecker.Result.UpToDate, UpdateChecker.evaluateRelease(newerPatch, "26.12.0"))
        assertEquals(UpdateChecker.Result.UpToDate, UpdateChecker.evaluateRelease(newerPatch, "27.1.0"))
    }

    @Test
    fun `evaluateRelease rejects release without APK or draft`() {
        val noApk = UpdateChecker.ReleaseMeta(
            tagName = "v26.11.0",
            draft = false,
            body = "",
            assets = listOf(UpdateChecker.ReleaseAsset("SHA256SUMS.txt", "https://example.invalid/sums")),
        )
        assertTrue(UpdateChecker.evaluateRelease(noApk, "1.9.1") is UpdateChecker.Result.Failed)

        val draft = noApk.copy(
            draft = true,
            assets = listOf(UpdateChecker.ReleaseAsset("outline-proxy-26.11.0-arm64-v8a.apk", "https://example.invalid/apk")),
        )
        assertTrue(UpdateChecker.evaluateRelease(draft, "1.9.1") is UpdateChecker.Result.Failed)
    }

    @Test
    fun `sanitizeFilename keeps legitimate apk names`() {
        assertEquals(
            "outline-proxy-v1.9.1-arm64-v8a.apk",
            UpdateChecker.sanitizeFilename("outline-proxy-v1.9.1-arm64-v8a.apk"),
        )
    }

    @Test
    fun `sanitizeFilename strips path components and traversal`() {
        assertEquals(
            "update.apk",
            UpdateChecker.sanitizeFilename("../../update.apk"),
        )
        assertEquals(
            "trojan.apk",
            UpdateChecker.sanitizeFilename("subdir/nested\\trojan.apk"),
        )
        assertEquals(
            "evil.apk",
            UpdateChecker.sanitizeFilename("/etc/passwd/../../evil.apk"),
        )
    }

    @Test
    fun `sanitizeFilename falls back to default on non-apk or empty names`() {
        assertEquals("outline-proxy-update.apk", UpdateChecker.sanitizeFilename(""))
        assertEquals("outline-proxy-update.apk", UpdateChecker.sanitizeFilename("../../"))
        assertEquals("outline-proxy-update.apk", UpdateChecker.sanitizeFilename("malicious.so"))
        assertEquals("outline-proxy-update.apk", UpdateChecker.sanitizeFilename(".apk"))
    }
}
