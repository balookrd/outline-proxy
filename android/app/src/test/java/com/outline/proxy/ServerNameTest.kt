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
}
