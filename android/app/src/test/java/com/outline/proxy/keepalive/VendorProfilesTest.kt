package com.outline.proxy.keepalive

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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

    /**
     * Samsung's screens are addressed by action, not by class: the Activity behind
     * the allowlist was renamed between One UI versions, and the component name
     * that libraries still copy around (`sm.ui.battery.BatteryActivity`) resolves
     * on no current build. The first entry must be the deeplink that opens the
     * allowlist itself, selected by `activity_type = 2`.
     */
    @Test fun samsungUsesDocumentedActionsNotClassNames() {
        val battery = vendorProfileFor("samsung")!!.battery
        assertTrue(battery.all { it.className == null && it.action != null })
        assertEquals(
            "com.samsung.android.sm.ACTION_OPEN_CHECKABLE_LISTACTIVITY",
            battery.first().action,
        )
        assertEquals(2, battery.first().intExtras["activity_type"])
    }

    /** A screen is addressed one way or the other, never both and never neither. */
    @Test fun everyScreenHasExactlyOneAddress() {
        for (profile in VENDOR_PROFILES) {
            for (screen in profile.autostart + profile.battery) {
                assertTrue(
                    "screen in ${profile.id} must have exactly one of className/action",
                    (screen.className == null) != (screen.action == null),
                )
            }
        }
    }

    /**
     * Components proven dead or fictional by manifest audit must never come back —
     * they all trace to the judemanutd/AutoStarter library, which copies them
     * around unverified. Each string here was checked against real firmware and
     * found either renamed away or never shipped.
     */
    @Test fun knownDeadComponentsAreGone() {
        val dead = listOf(
            "com.samsung.android.sm.ui.battery.BatteryActivity", // gone since 2019
            "com.iqoo.secure.ui.phoneoptimize.AddWhiteListActivity", // never shipped
            "com.meizu.safe.permission.PermissionMainActivity", // wrong screen, dead on Flyme 12
            "com.huawei.systemmanager.optimize.process.ProtectActivity", // gone since EMUI 5
            "com.oneplus.security.chainlaunch.view.ChainLaunchAppListActivity", // never in any manifest
            "com.oppo.safe.permission.startup.StartupAppListActivity", // com.oppo.safe absent since ColorOS
        )
        val used = VENDOR_PROFILES.flatMap { it.autostart + it.battery }.mapNotNull { it.className }
        for (d in dead) assertFalse("$d must not be referenced", d in used)
    }

    /** Transsion has a real Phone Master component; it must not be left empty. */
    @Test fun transsionCarriesAComponent() {
        assertTrue(vendorProfileFor("tecno")!!.autostart.isNotEmpty())
    }

    @Test fun manufacturersAreLowercaseAndUnique() {
        val all = VENDOR_PROFILES.flatMap { it.manufacturers }
        assertEquals(all.map { it.lowercase() }, all)
        assertEquals(all.distinct().size, all.size)
    }
}
