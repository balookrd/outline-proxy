package com.outline.proxy.keepalive

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VendorProfilesTest {

    @Test fun xiaomiFamilyMapsToOneProfile() {
        assertEquals(VendorId.XIAOMI, vendorProfileFor("Xiaomi")?.id)
        assertEquals(VendorId.XIAOMI, vendorProfileFor("Redmi")?.id)
        assertEquals(VendorId.XIAOMI, vendorProfileFor("POCO")?.id)
    }

    @Test fun matchIsCaseInsensitive() {
        assertEquals(VendorId.XIAOMI, vendorProfileFor("XIAOMI")?.id)
        assertEquals(VendorId.HUAWEI, vendorProfileFor("HuaWei")?.id)
    }

    @Test fun honorIsNotHuawei() {
        assertEquals(VendorId.HONOR, vendorProfileFor("HONOR")?.id)
        assertEquals(VendorId.HONOR, vendorProfileFor("hihonor")?.id)
    }

    /** One UI has no autostart list at all — only its own battery policy. */
    @Test fun samsungHasBatteryOnlyNoAutostart() {
        val samsung = vendorProfileFor("samsung")
        assertEquals(VendorId.SAMSUNG, samsung?.id)
        assertTrue(samsung!!.autostart.isEmpty())
        assertTrue(samsung.battery.isNotEmpty())
    }

    /** Near-stock skins get no vendor card whatsoever. */
    @Test fun stockVendorsHaveNoProfile() {
        assertNull(vendorProfileFor("Google"))
        assertNull(vendorProfileFor("motorola"))
        assertNull(vendorProfileFor("Sony"))
        assertNull(vendorProfileFor("Nothing"))
        assertNull(vendorProfileFor(null))
        assertNull(vendorProfileFor(""))
    }

    @Test fun xiaomiCarriesBothScreens() {
        val xiaomi = vendorProfileFor("xiaomi")!!
        assertEquals("com.miui.securitycenter", xiaomi.autostart.first().packageName)
        assertEquals("com.miui.powerkeeper", xiaomi.battery.first().packageName)
    }

    /**
     * Every profile must be able to render the cards it claims: a non-empty
     * autostart list needs either a toggle name or its own multi-step wording,
     * and battery screens are pointless without text explaining them.
     */
    @Test fun everyProfileCanRenderItsCards() {
        for (profile in VENDOR_PROFILES) {
            if (profile.autostart.isNotEmpty()) {
                assertTrue(
                    "profile ${profile.id} has autostart screens but no wording",
                    profile.autostartToggle != null || profile.autostartDesc != 0,
                )
            }
            if (profile.battery.isNotEmpty()) {
                assertTrue(
                    "profile ${profile.id} has battery screens but no wording",
                    profile.batteryDesc != null,
                )
            }
        }
    }

    @Test fun manufacturersAreLowercaseAndUnique() {
        val all = VENDOR_PROFILES.flatMap { it.manufacturers }
        assertEquals(all.map { it.lowercase() }, all)
        assertEquals(all.distinct().size, all.size)
    }
}
