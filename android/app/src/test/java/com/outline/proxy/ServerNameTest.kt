package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ServerNameTest {
    @Test fun remarkPreferredPlain() {
        assertEquals("Germany", ServerProfile.deriveName("vless://uuid@de.example.com:443?x=1#Germany"))
    }
    @Test fun remarkPercentDecoded() {
        assertEquals("DE Berlin", ServerProfile.deriveName("vless://uuid@h:443#DE%20Berlin"))
    }
    @Test fun remarkEmojiFlag() {
        assertEquals("🇩🇪", ServerProfile.deriveName("ss://YWVzOnB3@h.example.com:8388#%F0%9F%87%A9%F0%9F%87%AA"))
    }
    @Test fun hostFallbackWhenNoRemark() {
        assertEquals("de.example.com", ServerProfile.deriveName("vless://uuid@de.example.com:443?x=1"))
    }
    @Test fun ssBase64UserinfoHost() {
        assertEquals("h.example.com", ServerProfile.hostOf("ss://YWVzLTI1Ni1nY206cHc@h.example.com:8388"))
    }
    @Test fun httpsSubscriptionHost() {
        assertEquals("sub.example.com", ServerProfile.deriveName("https://sub.example.com/path/cfg?token=abc"))
    }
    @Test fun ipv6Literal() {
        assertEquals("2001:db8::1", ServerProfile.hostOf("vless://uuid@[2001:db8::1]:443"))
    }
    @Test fun trailingPathQueryStripped() {
        assertEquals("h.example.com", ServerProfile.hostOf("https://h.example.com/a/b?q=1"))
    }
    @Test fun garbageIsNull() {
        assertNull(ServerProfile.hostOf("   "))
        assertNull(ServerProfile.remarkOf("vless://uuid@h:443"))
    }
    @Test fun ssStandardBase64SlashInUserinfo() {
        assertEquals("h.example.com", ServerProfile.hostOf("ss://ab/cdefgh@h.example.com:8388"))
    }
    @Test fun remarkLiteralPlusPreserved() {
        assertEquals("A+B", ServerProfile.deriveName("vless://uuid@h:443#A+B"))
    }
    @Test fun remarkWithNewlinesIsSanitized() {
        assertEquals("malicious section", ServerProfile.deriveName("vless://uuid@h:443#malicious%0Asection"))
        assertEquals("foo bar", ServerProfile.remarkOf("vless://uuid@h:443#foo%0D%0Abar"))
    }
    @Test fun escapeTomlStringEscapesSpecialCharacters() {
        assertEquals("safe", ServerProfile.escapeTomlString("safe"))
        assertEquals("line1\\nline2", ServerProfile.escapeTomlString("line1\nline2"))
        assertEquals("line1\\r\\nline2", ServerProfile.escapeTomlString("line1\r\nline2"))
        assertEquals("quote\\\"and\\\\backslash", ServerProfile.escapeTomlString("quote\"and\\backslash"))
        assertEquals("tab\\tchar", ServerProfile.escapeTomlString("tab\tchar"))
        assertEquals("\\u0000\\u001f", ServerProfile.escapeTomlString("\u0000\u001F"))
    }
    @Test fun toConfigTomlEscapesInjectedSections() {
        val profile = ServerProfile(
            name = "injected\"\n[[malicious]]\nkey = \"value",
            transport = "vless",
            vlessLink = "vless://id@host:443#comment\"\n[injected]",
        )
        val toml = profile.toToml()
        org.junit.Assert.assertFalse(toml.contains("\n[[malicious]]\n"))
        org.junit.Assert.assertFalse(toml.contains("\n[injected]\n"))
        org.junit.Assert.assertTrue(toml.contains("name = \"injected\\\"\\n[[malicious]]\\nkey = \\\"value\""))
    }
}
