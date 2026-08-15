package com.outline.proxy

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

/**
 * The app's Material 3 theme. The colour scheme follows the system:
 *
 *  - Android 12+ (API 31): the device's dynamic "Material You" palette, in its
 *    dark or light variant per the system setting.
 *  - Older releases: the plain Material 3 dark/light baseline, still switched by
 *    the system dark-theme toggle.
 *
 * `isSystemInDarkTheme()` recomposes on the setting change, so flipping the
 * system theme reskins the app live, without a restart.
 */
@Composable
fun OutlineTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val colorScheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        dark -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = colorScheme, content = content)
}
