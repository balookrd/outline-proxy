package com.outline.proxy

import android.app.DownloadManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Checks GitHub for a newer build of *this* app's channel and hands the APK to
 * the system downloader.
 *
 * The app deliberately does not install anything itself: `REQUEST_INSTALL_PACKAGES`
 * is the permission Play Protect weighs most heavily next to a VPN service and
 * `QUERY_ALL_PACKAGES` (see the `USE_EXACT_ALARM` removal in the changelog), and
 * an updater is not worth re-earning that flag. The download lands in the user's
 * Downloads folder and they tap it themselves.
 *
 * Channels come from [BuildConfig.CHANNEL] and are identified differently
 * because they are versioned differently: a release is a tag (`android-v1.1.3`)
 * and compares by version, while every nightly shares the rolling
 * `android-nightly` tag and is identified only by the commit baked into its
 * asset name.
 */
object UpdateChecker {
    private const val TAG = "UpdateChecker"
    private const val REPO = "balookrd/outline-proxy"
    private const val NIGHTLY_TAG = "android-nightly"
    private const val RELEASE_TAG_PREFIX = "android-v"
    private const val ASSET_SUFFIX = "-arm64-v8a.apk"
    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 15_000

    /** What a check found. */
    sealed interface Result {
        /** This build is the newest one published for its channel. */
        data object UpToDate : Result

        /** A newer build exists; [label] names it the way its channel does. */
        data class Available(val label: String, val assetName: String, val url: String) : Result

        data class Failed(val reason: String) : Result
    }

    /**
     * Ask GitHub what the newest build on this channel is. Network work, so it
     * runs off the caller's thread; every failure is reported rather than thrown
     * — an updater must never be the reason the app misbehaves.
     */
    suspend fun check(): Result = withContext(Dispatchers.IO) {
        runCatching {
            if (BuildConfig.CHANNEL == "release") checkRelease() else checkNightly()
        }.getOrElse { error ->
            Log.w(TAG, "update check failed", error)
            Result.Failed(error.message ?: error.javaClass.simpleName)
        }
    }

    /**
     * Nightlies all publish under one rolling tag, so "newer" cannot be a version
     * comparison — it is "the published asset was built from a different commit
     * than this build". The commit rides in the asset name
     * (`outline-proxy-nightly-<sha>-arm64-v8a.apk`), which is why it is stamped
     * there in the first place.
     */
    private fun checkNightly(): Result {
        val release = JSONObject(get("https://api.github.com/repos/$REPO/releases/tags/$NIGHTLY_TAG"))
        val asset = apkAsset(release) ?: return Result.Failed("no APK in the nightly release")
        val name = asset.getString("name")
        val sha = name.removePrefix("outline-proxy-nightly-").removeSuffix(ASSET_SUFFIX)
        return if (sha.isNotEmpty() && sha == BuildConfig.GIT_SHA) {
            Result.UpToDate
        } else {
            Result.Available("nightly · $sha", name, asset.getString("browser_download_url"))
        }
    }

    /**
     * Releases carry their version in the tag, so the newest `android-v*` tag
     * wins — `/releases/latest` is no help here, since the repository also
     * publishes server and client releases and the newest of *those* would be
     * reported instead.
     */
    private fun checkRelease(): Result {
        val releases = JSONArray(get("https://api.github.com/repos/$REPO/releases?per_page=30"))
        var best: JSONObject? = null
        var bestVersion: List<Int> = emptyList()
        for (i in 0 until releases.length()) {
            val release = releases.getJSONObject(i)
            val tag = release.optString("tag_name")
            if (!tag.startsWith(RELEASE_TAG_PREFIX) || release.optBoolean("draft")) continue
            val version = versionParts(tag.removePrefix(RELEASE_TAG_PREFIX))
            if (compareVersions(version, bestVersion) > 0) {
                best = release
                bestVersion = version
            }
        }
        val release = best ?: return Result.Failed("no $RELEASE_TAG_PREFIX* release published yet")
        if (compareVersions(bestVersion, versionParts(BuildConfig.VERSION_NAME)) <= 0) {
            return Result.UpToDate
        }
        val asset = apkAsset(release) ?: return Result.Failed("no APK in ${release.optString("tag_name")}")
        return Result.Available(
            "v${release.optString("tag_name").removePrefix(RELEASE_TAG_PREFIX)}",
            asset.getString("name"),
            asset.getString("browser_download_url"),
        )
    }

    /** Where a fetched APK ended up, or why it did not. */
    sealed interface Download {
        /** [uri] is the saved APK, ready to be handed to an installer. */
        data class Saved(val uri: String) : Download

        data class Failed(val reason: String) : Download
    }

    /**
     * Fetch the APK into the user's Downloads folder.
     *
     * Deliberately not `DownloadManager`: that runs in another app, so with the
     * tunnel up its traffic is captured by the VPN like any other app's, and an
     * update download then depends on the very link the user may be updating to
     * fix. This app excludes its own package from the tunnel (see
     * `OutlineVpnService.applySplitTunnel`), so fetching in-process always goes
     * out on the underlying network.
     */
    suspend fun download(
        context: Context,
        update: Result.Available,
        onProgress: (Int) -> Unit = {},
    ): Download =
        withContext(Dispatchers.IO) {
            runCatching { save(context, update, onProgress) }.getOrElse { error ->
                Log.w(TAG, "update download failed", error)
                Download.Failed(error.message ?: error.javaClass.simpleName)
            }
        }

    private fun save(
        context: Context,
        update: Result.Available,
        onProgress: (Int) -> Unit,
    ): Download {
        var connection: HttpURLConnection? = null
        try {
            connection = (URL(update.url).openConnection() as HttpURLConnection).apply {
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                instanceFollowRedirects = true
            }
            val code = connection.responseCode
            if (code != HttpURLConnection.HTTP_OK) throw IllegalStateException("HTTP $code")
            val total = connection.contentLengthLong
            return connection.inputStream.use { body ->
                writeToDownloads(context, update.assetName, body, total, onProgress)
            }
        } finally {
            connection?.disconnect()
        }
    }

    /**
     * Publish the APK where the user can find and tap it. From API 29 that is
     * the shared Downloads collection through MediaStore, which needs no storage
     * permission; older devices would need `WRITE_EXTERNAL_STORAGE` for the same
     * place, so they get the app's own external files directory instead — a new
     * permission is not worth it for a two-release tail.
     */
    private fun writeToDownloads(
        context: Context,
        name: String,
        body: java.io.InputStream,
        total: Long,
        onProgress: (Int) -> Unit,
    ): Download {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val resolver = context.contentResolver
            val pending = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, "application/vnd.android.package-archive")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, pending)
                ?: throw IllegalStateException("MediaStore refused the download entry")
            // IS_PENDING hides the half-written file from other apps; clearing it
            // is what publishes the APK, so it must happen only after the copy.
            resolver.openOutputStream(uri).use { out ->
                requireNotNull(out) { "no output stream for $uri" }
                copyReporting(body, out, total, onProgress)
            }
            resolver.update(uri, ContentValues().apply { put(MediaStore.Downloads.IS_PENDING, 0) }, null, null)
            Log.i(TAG, "saved update to $uri ($name)")
            return Download.Saved(uri.toString())
        }
        val dir = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
            ?: throw IllegalStateException("no external files directory")
        val file = java.io.File(dir, name)
        file.outputStream().use { out -> copyReporting(body, out, total, onProgress) }
        Log.i(TAG, "saved update to ${file.absolutePath}")
        return Download.Saved(android.net.Uri.fromFile(file).toString())
    }

    /**
     * Copy the body through, reporting whole percents as they change. The
     * percentage is what the version footer shows while a download runs — an
     * update that only says "downloading…" is indistinguishable from one that
     * has stalled.
     */
    private fun copyReporting(
        body: java.io.InputStream,
        out: java.io.OutputStream,
        total: Long,
        onProgress: (Int) -> Unit,
    ) {
        val buffer = ByteArray(64 * 1024)
        var copied = 0L
        var lastPercent = -1
        while (true) {
            val read = body.read(buffer)
            if (read < 0) break
            out.write(buffer, 0, read)
            copied += read
            if (total > 0) {
                val percent = ((copied * 100) / total).toInt().coerceIn(0, 100)
                if (percent != lastPercent) {
                    lastPercent = percent
                    onProgress(percent)
                }
            }
        }
        out.flush()
    }

    /**
     * Hand the downloaded APK to whatever can install it.
     *
     * Preferred route is the system Downloads UI: it is a permitted install
     * source, so tapping the APK there installs it, whereas launching the
     * installer from here would dead-end on devices where this app — which
     * deliberately does not hold `REQUEST_INSTALL_PACKAGES` — is not an allowed
     * source. `ACTION_VIEW` on the file is the fallback for devices with no
     * Downloads UI.
     */
    fun openForInstall(context: Context, uri: String) {
        val downloads = Intent(DownloadManager.ACTION_VIEW_DOWNLOADS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (downloads.resolveActivity(context.packageManager) != null) {
            context.startActivity(downloads)
            return
        }
        val view = Intent(Intent.ACTION_VIEW)
            .setDataAndType(android.net.Uri.parse(uri), "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION)
        context.startActivity(view)
    }

    private fun apkAsset(release: JSONObject): JSONObject? {
        val assets = release.optJSONArray("assets") ?: return null
        for (i in 0 until assets.length()) {
            val asset = assets.getJSONObject(i)
            if (asset.optString("name").endsWith(ASSET_SUFFIX)) return asset
        }
        return null
    }

    private fun get(url: String): String {
        var connection: HttpURLConnection? = null
        try {
            connection = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                setRequestProperty("Accept", "application/vnd.github+json")
            }
            val code = connection.responseCode
            if (code != HttpURLConnection.HTTP_OK) throw IllegalStateException("HTTP $code")
            return connection.inputStream.bufferedReader().use { it.readText() }
        } finally {
            connection?.disconnect()
        }
    }

    /** `1.1.2` → `[1, 1, 2]`; non-numeric parts (a `-rc1` suffix) stop the parse. */
    private fun versionParts(version: String): List<Int> =
        version.split('.').map { part -> part.takeWhile(Char::isDigit).toIntOrNull() ?: 0 }

    private fun compareVersions(a: List<Int>, b: List<Int>): Int {
        for (i in 0 until maxOf(a.size, b.size)) {
            val diff = (a.getOrElse(i) { 0 }) - (b.getOrElse(i) { 0 })
            if (diff != 0) return diff
        }
        return 0
    }
}
