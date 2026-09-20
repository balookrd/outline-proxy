package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AutomationPolicyTest {

    @Test
    fun `normalizeSsid handles quotes, whitespace, and unknown placeholders`() {
        assertNull(AutomationPolicy.normalizeSsid(null))
        assertNull(AutomationPolicy.normalizeSsid(""))
        assertNull(AutomationPolicy.normalizeSsid("   "))
        assertNull(AutomationPolicy.normalizeSsid("<unknown ssid>"))
        assertNull(AutomationPolicy.normalizeSsid("\"<unknown ssid>\""))
        assertNull(AutomationPolicy.normalizeSsid("\"\""))

        assertEquals("Home-5G", AutomationPolicy.normalizeSsid("\"Home-5G\""))
        assertEquals("Office WiFi", AutomationPolicy.normalizeSsid("Office WiFi"))
        assertEquals("CoffeeShop", AutomationPolicy.normalizeSsid("  \"CoffeeShop\"  "))
    }

    @Test
    fun `airplane mode - disabled feature does nothing`() {
        val actionOn = AutomationPolicy.decideAirplaneMode(
            airplaneModeEnabled = true,
            pauseOnAirplaneMode = false,
            tunnelActive = true,
            pausedByAirplane = false,
            userIntentShouldRun = true,
        )
        assertEquals(AutomationAction.DO_NOTHING, actionOn)

        val actionOff = AutomationPolicy.decideAirplaneMode(
            airplaneModeEnabled = false,
            pauseOnAirplaneMode = false,
            tunnelActive = false,
            pausedByAirplane = true,
            userIntentShouldRun = true,
        )
        assertEquals(AutomationAction.DO_NOTHING, actionOff)
    }

    @Test
    fun `airplane mode on pauses running or intended tunnel`() {
        val actionActive = AutomationPolicy.decideAirplaneMode(
            airplaneModeEnabled = true,
            pauseOnAirplaneMode = true,
            tunnelActive = true,
            pausedByAirplane = false,
            userIntentShouldRun = true,
        )
        assertEquals(AutomationAction.PAUSE_TUNNEL, actionActive)

        val actionIntended = AutomationPolicy.decideAirplaneMode(
            airplaneModeEnabled = true,
            pauseOnAirplaneMode = true,
            tunnelActive = false,
            pausedByAirplane = false,
            userIntentShouldRun = true,
        )
        assertEquals(AutomationAction.PAUSE_TUNNEL, actionIntended)

        val actionNoIntent = AutomationPolicy.decideAirplaneMode(
            airplaneModeEnabled = true,
            pauseOnAirplaneMode = true,
            tunnelActive = false,
            pausedByAirplane = false,
            userIntentShouldRun = false,
        )
        assertEquals(AutomationAction.DO_NOTHING, actionNoIntent)
    }

    @Test
    fun `airplane mode off resumes only if paused by airplane and user still wants tunnel`() {
        val actionResume = AutomationPolicy.decideAirplaneMode(
            airplaneModeEnabled = false,
            pauseOnAirplaneMode = true,
            tunnelActive = false,
            pausedByAirplane = true,
            userIntentShouldRun = true,
        )
        assertEquals(AutomationAction.RESUME_TUNNEL, actionResume)

        val actionUserCancelled = AutomationPolicy.decideAirplaneMode(
            airplaneModeEnabled = false,
            pauseOnAirplaneMode = true,
            tunnelActive = false,
            pausedByAirplane = true,
            userIntentShouldRun = false,
        )
        assertEquals(AutomationAction.DO_NOTHING, actionUserCancelled)

        val actionWasNotPaused = AutomationPolicy.decideAirplaneMode(
            airplaneModeEnabled = false,
            pauseOnAirplaneMode = true,
            tunnelActive = false,
            pausedByAirplane = false,
            userIntentShouldRun = true,
        )
        assertEquals(AutomationAction.DO_NOTHING, actionWasNotPaused)
    }

    @Test
    fun `wifi pause on selected - pauses on trusted network unless manual override`() {
        val trusted = setOf("Home-5G", "Office")

        // Entering trusted Wi-Fi while tunnel is active -> PAUSE
        val actionEnter = AutomationPolicy.decideWifiChange(
            wifiAutomationEnabled = true,
            wifiMode = WifiRuleMode.PAUSE_ON_SELECTED,
            currentSsid = "\"Home-5G\"",
            trustedSsids = trusted,
            tunnelActive = true,
            pausedByWifi = false,
            userIntentShouldRun = true,
        )
        assertEquals(AutomationAction.PAUSE_TUNNEL, actionEnter)

        // Starting VPN while already on trusted Wi-Fi -> PAUSE immediately
        val actionStartOnTrusted = AutomationPolicy.decideWifiChange(
            wifiAutomationEnabled = true,
            wifiMode = WifiRuleMode.PAUSE_ON_SELECTED,
            currentSsid = "Home-5G",
            trustedSsids = trusted,
            tunnelActive = false,
            pausedByWifi = false,
            userIntentShouldRun = true,
        )
        assertEquals(AutomationAction.PAUSE_TUNNEL, actionStartOnTrusted)

        // Manual override for this SSID suppresses pause
        val actionOverride = AutomationPolicy.decideWifiChange(
            wifiAutomationEnabled = true,
            wifiMode = WifiRuleMode.PAUSE_ON_SELECTED,
            currentSsid = "Home-5G",
            trustedSsids = trusted,
            tunnelActive = true,
            pausedByWifi = false,
            userIntentShouldRun = true,
            manualOverrideSsid = "Home-5G",
        )
        assertEquals(AutomationAction.DO_NOTHING, actionOverride)
    }

    @Test
    fun `wifi pause on selected - resumes when leaving trusted network`() {
        val trusted = setOf("Home-5G")

        // Leaving Home-5G to cellular (currentSsid = null)
        val actionLeaveToCellular = AutomationPolicy.decideWifiChange(
            wifiAutomationEnabled = true,
            wifiMode = WifiRuleMode.PAUSE_ON_SELECTED,
            currentSsid = null,
            trustedSsids = trusted,
            tunnelActive = false,
            pausedByWifi = true,
            userIntentShouldRun = true,
        )
        assertEquals(AutomationAction.RESUME_TUNNEL, actionLeaveToCellular)

        // Leaving Home-5G to public Wi-Fi
        val actionLeaveToPublic = AutomationPolicy.decideWifiChange(
            wifiAutomationEnabled = true,
            wifiMode = WifiRuleMode.PAUSE_ON_SELECTED,
            currentSsid = "Airport_Free_Wifi",
            trustedSsids = trusted,
            tunnelActive = false,
            pausedByWifi = true,
            userIntentShouldRun = true,
        )
        assertEquals(AutomationAction.RESUME_TUNNEL, actionLeaveToPublic)

        // If user explicitly turned off VPN while paused, do not resume
        val actionNoIntent = AutomationPolicy.decideWifiChange(
            wifiAutomationEnabled = true,
            wifiMode = WifiRuleMode.PAUSE_ON_SELECTED,
            currentSsid = null,
            trustedSsids = trusted,
            tunnelActive = false,
            pausedByWifi = true,
            userIntentShouldRun = false,
        )
        assertEquals(AutomationAction.DO_NOTHING, actionNoIntent)
    }

    @Test
    fun `wifi connect on selected - connects on trusted and pauses outside`() {
        val trusted = setOf("Office")

        // Connect on trusted
        val actionEnter = AutomationPolicy.decideWifiChange(
            wifiAutomationEnabled = true,
            wifiMode = WifiRuleMode.CONNECT_ON_SELECTED,
            currentSsid = "Office",
            trustedSsids = trusted,
            tunnelActive = false,
            pausedByWifi = false,
            userIntentShouldRun = true,
        )
        assertEquals(AutomationAction.RESUME_TUNNEL, actionEnter)

        // Pause when leaving
        val actionLeave = AutomationPolicy.decideWifiChange(
            wifiAutomationEnabled = true,
            wifiMode = WifiRuleMode.CONNECT_ON_SELECTED,
            currentSsid = "CoffeeShop",
            trustedSsids = trusted,
            tunnelActive = true,
            pausedByWifi = false,
            userIntentShouldRun = true,
        )
        assertEquals(AutomationAction.PAUSE_TUNNEL, actionLeave)
    }
}
