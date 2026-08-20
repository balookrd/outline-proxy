package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The picker lists network-capable apps (those requesting INTERNET), not just
 * launchable ones — so Android Auto and network system apps without a launcher
 * icon show up. Pure filtering/sorting, no PackageManager.
 */
class FilterNetworkAppsTest {

    private fun raw(pkg: String, label: String, internet: Boolean) = RawApp(pkg, label, internet)

    @Test
    fun `apps without INTERNET are dropped`() {
        val out = filterNetworkApps(
            listOf(raw("a.net", "Aa", true), raw("b.local", "Bb", false)),
            selfPackage = "self",
        )
        assertEquals(listOf(AppInfo("a.net", "Aa")), out)
    }

    @Test
    fun `own package is excluded`() {
        val out = filterNetworkApps(
            listOf(raw("self", "Me", true), raw("a.net", "Aa", true)),
            selfPackage = "self",
        )
        assertEquals(listOf(AppInfo("a.net", "Aa")), out)
    }

    @Test
    fun `results are deduped by package and sorted by label`() {
        val out = filterNetworkApps(
            listOf(
                raw("z.pkg", "Zeta", true),
                raw("a.pkg", "alpha", true),
                raw("a.pkg", "alpha duplicate", true),
                raw("m.pkg", "Mike", true),
            ),
            selfPackage = "self",
        )
        assertEquals(
            listOf(AppInfo("a.pkg", "alpha"), AppInfo("m.pkg", "Mike"), AppInfo("z.pkg", "Zeta")),
            out,
        )
    }
}

/**
 * Allowlist and denylist are stored independently; switching modes must not move
 * or drop a selection. A legacy single-list install seeds both sets so nothing
 * is lost on upgrade.
 */
class ResolveSplitConfigTest {

    @Test
    fun `legacy shared set seeds both allow and deny`() {
        val cfg = resolveSplitConfig(
            mode = SplitMode.DENYLIST,
            allow = null,
            deny = null,
            legacy = setOf("x.pkg", "y.pkg"),
        )
        assertEquals(SplitMode.DENYLIST, cfg.mode)
        assertEquals(setOf("x.pkg", "y.pkg"), cfg.allowPackages)
        assertEquals(setOf("x.pkg", "y.pkg"), cfg.denyPackages)
    }

    @Test
    fun `allow and deny stay independent when new keys are present`() {
        val cfg = resolveSplitConfig(
            mode = SplitMode.ALLOWLIST,
            allow = setOf("a.pkg"),
            deny = setOf("d.pkg"),
            legacy = null,
        )
        assertEquals(setOf("a.pkg"), cfg.allowPackages)
        assertEquals(setOf("d.pkg"), cfg.denyPackages)
    }

    @Test
    fun `legacy is ignored once either new key exists`() {
        val cfg = resolveSplitConfig(
            mode = SplitMode.OFF,
            allow = setOf("a.pkg"),
            deny = null,
            legacy = setOf("old.pkg"),
        )
        assertEquals(setOf("a.pkg"), cfg.allowPackages)
        assertEquals(emptySet<String>(), cfg.denyPackages)
    }
}
