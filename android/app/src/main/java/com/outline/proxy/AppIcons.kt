package com.outline.proxy

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.util.LruCache
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.produceState
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * How many icons to keep. At the sizes the picker draws them (~40dp) each costs a
 * few KB, so this bounds the cache at roughly a megabyte — enough to scroll a
 * long list without reloading, small enough not to matter.
 */
private const val ICON_CACHE_ENTRIES = 128

private val iconCache = LruCache<String, ImageBitmap>(ICON_CACHE_ENTRIES)

/**
 * The icon for [packageName], or null while it loads — and for apps whose icon
 * cannot be read at all.
 *
 * A phone can hold several hundred network-capable apps, so icons are never
 * loaded alongside the list: each row asks for its own once it scrolls into view,
 * off the main thread, and the result is rasterised to display size before being
 * cached. Keeping full-resolution adaptive icons for every installed app would
 * cost far more memory than the picker is worth. The load is cancelled
 * automatically when the row leaves the composition.
 */
@Composable
fun rememberAppIcon(packageName: String, size: Dp): State<ImageBitmap?> {
    val context = LocalContext.current
    val sizePx = with(LocalDensity.current) { size.roundToPx() }
    return produceState<ImageBitmap?>(
        initialValue = iconCache.get(packageName),
        packageName,
        sizePx,
    ) {
        if (value == null) {
            value = withContext(Dispatchers.IO) { loadAppIcon(context, packageName, sizePx) }
        }
    }
}

private fun loadAppIcon(context: Context, packageName: String, sizePx: Int): ImageBitmap? {
    iconCache.get(packageName)?.let { return it }
    // An app can be uninstalled between building the list and drawing its row.
    val drawable = runCatching {
        context.packageManager.getApplicationIcon(packageName)
    }.getOrNull() ?: return null
    val icon = drawable.rasterise(sizePx).asImageBitmap()
    iconCache.put(packageName, icon)
    return icon
}

/**
 * Draw a drawable at exactly [sizePx]. Goes through a canvas rather than reusing
 * an intrinsic bitmap because adaptive icons — the common case now — are composed
 * from layers and have none.
 */
private fun Drawable.rasterise(sizePx: Int): Bitmap {
    val bitmap = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888)
    setBounds(0, 0, sizePx, sizePx)
    draw(Canvas(bitmap))
    return bitmap
}
