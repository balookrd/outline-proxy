package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateScheduleTest {

    @Test
    fun `isPeriodicCheckDue treats missing or rolled-back timestamps as due`() {
        assertTrue(UpdateSchedule.isPeriodicCheckDue(0L, 1_000_000L))
        assertTrue(UpdateSchedule.isPeriodicCheckDue(-10L, 1_000_000L))
        assertTrue(UpdateSchedule.isPeriodicCheckDue(2_000_000L, 1_000_000L))
    }

    @Test
    fun `isPeriodicCheckDue respects weekly interval boundary`() {
        val base = 1_700_000_000_000L
        val week = UpdateSchedule.WEEKLY_INTERVAL_MS

        assertFalse(UpdateSchedule.isPeriodicCheckDue(base, base))
        assertFalse(UpdateSchedule.isPeriodicCheckDue(base, base + week - 1L))
        assertTrue(UpdateSchedule.isPeriodicCheckDue(base, base + week))
        assertTrue(UpdateSchedule.isPeriodicCheckDue(base, base + week + 60_000L))
    }

    @Test
    fun `shouldNotify deduplicates by release label`() {
        assertTrue(UpdateSchedule.shouldNotify("v26.11.2", null))
        assertFalse(UpdateSchedule.shouldNotify("v26.11.2", "v26.11.2"))
        assertTrue(UpdateSchedule.shouldNotify("v26.11.3", "v26.11.2"))
        assertFalse(UpdateSchedule.shouldNotify("", null))
        assertFalse(UpdateSchedule.shouldNotify("   ", null))
    }

    @Test
    fun `isCachedUpdateValid invalidates cache when build identity changes`() {
        val build1 = UpdateSchedule.currentBuildId("release", "26.11.2", "d3c5a757")
        val build2 = UpdateSchedule.currentBuildId("release", "26.11.3", "abcdef12")
        val nightly1 = UpdateSchedule.currentBuildId("nightly", "0.1.0-nightly", "1111111")
        val nightly2 = UpdateSchedule.currentBuildId("nightly", "0.1.0-nightly", "2222222")

        assertEquals("release:26.11.2:d3c5a757", build1)
        assertTrue(UpdateSchedule.isCachedUpdateValid(build1, build1))
        assertFalse(UpdateSchedule.isCachedUpdateValid(build1, build2))
        assertFalse(UpdateSchedule.isCachedUpdateValid(nightly1, nightly2))
        assertFalse(UpdateSchedule.isCachedUpdateValid(null, build1))
        assertFalse(UpdateSchedule.isCachedUpdateValid("", build1))
    }
}
