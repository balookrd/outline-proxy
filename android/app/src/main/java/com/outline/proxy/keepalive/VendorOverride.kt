package com.outline.proxy.keepalive

import android.content.Context
import android.os.Build
import com.outline.proxy.BuildConfig

/**
 * Which manufacturer the vendor checklist should treat this device as.
 *
 * Vendor cards can only be seen on real vendor firmware, which no emulator has,
 * so a debug build reads an override from preferences — letting a CLI run walk
 * through every skin and screenshot the result. Release builds never read it:
 * `BuildConfig.DEBUG` is a compile-time constant, so the branch (and the
 * preference name with it) is folded away.
 *
 * Set it on a debug build with:
 * ```
 * adb shell "run-as com.outline.proxy sh -c \
 *   'cat > /data/data/com.outline.proxy/shared_prefs/outline_debug.xml'" < override.xml
 * ```
 * where `override.xml` holds `<string name="vendor_manufacturer">xiaomi</string>`.
 * Force-stop the app first — otherwise it rewrites the file from its in-memory copy.
 */
internal object VendorOverride {

    fun manufacturer(context: Context): String? {
        if (BuildConfig.DEBUG) {
            val override = context
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getString(KEY_MANUFACTURER, null)
                ?.takeIf { it.isNotBlank() }
            if (override != null) return override
        }
        return Build.MANUFACTURER
    }

    private const val PREFS = "outline_debug"
    private const val KEY_MANUFACTURER = "vendor_manufacturer"
}
