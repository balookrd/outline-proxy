package com.outline.proxy

/**
 * Action determining what the automation subsystem should ask the VPN service to do.
 */
enum class AutomationAction {
    /** Keep the current state intact. */
    DO_NOTHING,

    /** Temporarily tear down the tunnel without clearing user intent (`shouldRun`). */
    PAUSE_TUNNEL,

    /** Bring the tunnel back up because the trigger condition cleared. */
    RESUME_TUNNEL,
}

/**
 * Policy mode for trusted Wi-Fi automation.
 */
enum class WifiRuleMode {
    /**
     * Pause the tunnel when joining a selected network (e.g., home or office);
     * resume when disconnecting or switching to an unlisted network.
     */
    PAUSE_ON_SELECTED,

    /**
     * Connect the tunnel only when on selected networks; pause elsewhere.
     */
    CONNECT_ON_SELECTED,
}

/**
 * Pure decision rules for network automation, kept free of Android framework
 * dependencies so it is fully unit-testable.
 */
object AutomationPolicy {

    /**
     * Normalizes an SSID string, stripping quotation marks added by Android's WifiInfo
     * and ignoring unknown/blank SSIDs.
     */
    fun normalizeSsid(rawSsid: String?): String? {
        if (rawSsid == null) return null
        val trimmed = rawSsid.trim()
        val stripped = if (trimmed.startsWith("\"") && trimmed.endsWith("\"") && trimmed.length >= 2) {
            trimmed.substring(1, trimmed.length - 1).trim()
        } else {
            trimmed
        }
        return if (stripped.isEmpty() || stripped == "<unknown ssid>") null else stripped
    }

    /**
     * Determines the action when airplane mode changes.
     *
     * @param airplaneModeEnabled whether airplane mode is currently ON.
     * @param pauseOnAirplaneMode whether the user enabled the auto-pause option.
     * @param tunnelActive whether the native tunnel is currently running.
     * @param pausedByAirplane whether the tunnel was previously paused by airplane mode.
     * @param userIntentShouldRun whether user intended the VPN to run (`KeepAliveState.shouldRun`).
     */
    fun decideAirplaneMode(
        airplaneModeEnabled: Boolean,
        pauseOnAirplaneMode: Boolean,
        tunnelActive: Boolean,
        pausedByAirplane: Boolean,
        userIntentShouldRun: Boolean,
    ): AutomationAction {
        if (!pauseOnAirplaneMode) return AutomationAction.DO_NOTHING

        return if (airplaneModeEnabled) {
            // When airplane mode turns ON, pause if the tunnel is active or was intended to run.
            if (tunnelActive || userIntentShouldRun) {
                AutomationAction.PAUSE_TUNNEL
            } else {
                AutomationAction.DO_NOTHING
            }
        } else {
            // When airplane mode turns OFF, resume only if it was paused by airplane mode
            // and the user hasn't explicitly disabled the VPN in the meantime.
            if (pausedByAirplane && userIntentShouldRun) {
                AutomationAction.RESUME_TUNNEL
            } else {
                AutomationAction.DO_NOTHING
            }
        }
    }

    /**
     * Determines the action when the active network or Wi-Fi SSID changes.
     *
     * @param wifiAutomationEnabled whether Wi-Fi rule automation is enabled in settings.
     * @param wifiMode whether to pause or connect on selected networks.
     * @param isOnWifi whether the device is currently connected to a Wi-Fi network.
     * @param currentSsid the normalized SSID of the current Wi-Fi network, or null if cellular/disconnected/unknown.
     * @param trustedSsids the set of user-selected SSIDs (normalized).
     * @param tunnelActive whether the native tunnel is currently running.
     * @param pausedByWifi whether the tunnel is currently in a paused state due to Wi-Fi automation.
     * @param userIntentShouldRun whether user intended the VPN to run (`KeepAliveState.shouldRun`).
     * @param manualOverrideSsid if user explicitly hit "Connect" while on this SSID, suppress pausing.
     */
    fun decideWifiChange(
        wifiAutomationEnabled: Boolean,
        wifiMode: WifiRuleMode,
        isOnWifi: Boolean,
        currentSsid: String?,
        trustedSsids: Set<String>,
        tunnelActive: Boolean,
        pausedByWifi: Boolean,
        userIntentShouldRun: Boolean,
        manualOverrideSsid: String? = null,
    ): AutomationAction {
        if (!wifiAutomationEnabled) return AutomationAction.DO_NOTHING

        val normalized = normalizeSsid(currentSsid)

        return when (wifiMode) {
            WifiRuleMode.PAUSE_ON_SELECTED -> {
                if (isOnWifi) {
                    if (normalized != null) {
                        if (trustedSsids.contains(normalized)) {
                            // Suppress pausing if user explicitly connected on this exact network
                            if (normalized == manualOverrideSsid) {
                                AutomationAction.DO_NOTHING
                            } else if (tunnelActive || (!pausedByWifi && userIntentShouldRun)) {
                                AutomationAction.PAUSE_TUNNEL
                            } else {
                                // Already paused and inactive -> do nothing
                                AutomationAction.DO_NOTHING
                            }
                        } else {
                            // Explicitly connected to an untrusted / foreign Wi-Fi network
                            if (pausedByWifi && userIntentShouldRun && !tunnelActive) {
                                AutomationAction.RESUME_TUNNEL
                            } else {
                                AutomationAction.DO_NOTHING
                            }
                        }
                    } else {
                        // Connected to Wi-Fi, but SSID is hidden/unknown (background restrictions,
                        // screen off, Doze mode, or pending handshake).
                        // Keep current pause state to avoid falsely resuming while still on trusted Wi-Fi.
                        AutomationAction.DO_NOTHING
                    }
                } else {
                    // Completely left Wi-Fi (switched to cellular or no network)
                    if (pausedByWifi && userIntentShouldRun && !tunnelActive) {
                        AutomationAction.RESUME_TUNNEL
                    } else {
                        AutomationAction.DO_NOTHING
                    }
                }
            }

            WifiRuleMode.CONNECT_ON_SELECTED -> {
                if (isOnWifi) {
                    if (normalized != null) {
                        if (trustedSsids.contains(normalized)) {
                            // On selected Wi-Fi where VPN is required
                            if ((pausedByWifi || !tunnelActive) && userIntentShouldRun) {
                                AutomationAction.RESUME_TUNNEL
                            } else {
                                AutomationAction.DO_NOTHING
                            }
                        } else {
                            // On an unselected Wi-Fi network -> pause tunnel
                            if (tunnelActive || (!pausedByWifi && userIntentShouldRun)) {
                                AutomationAction.PAUSE_TUNNEL
                            } else {
                                AutomationAction.DO_NOTHING
                            }
                        }
                    } else {
                        // Connected to Wi-Fi, but SSID is unknown: preserve existing state
                        AutomationAction.DO_NOTHING
                    }
                } else {
                    // Off Wi-Fi -> pause tunnel outside selected networks
                    if (tunnelActive || (!pausedByWifi && userIntentShouldRun)) {
                        AutomationAction.PAUSE_TUNNEL
                    } else {
                        AutomationAction.DO_NOTHING
                    }
                }
            }
        }
    }
}
