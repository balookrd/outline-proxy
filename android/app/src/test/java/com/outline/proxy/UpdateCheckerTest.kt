package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Test

class UpdateCheckerTest {

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
