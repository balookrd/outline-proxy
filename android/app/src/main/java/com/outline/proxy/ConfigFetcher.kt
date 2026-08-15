package com.outline.proxy

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/** Whether a fetched body is one of our client configs, not an error page. */
object ConfigValidation {

    /**
     * A response only replaces the cache if it actually looks like a ws-rust
     * client config. This is the guard against a URL that answers 200 with an
     * HTML captcha, a redirect stub or a 404 body: overwriting a working cache
     * with that would silently break the tunnel.
     *
     * The markers are the sections that define a tunnel — `[tun]` or an
     * `[[outline.uplinks]]` table. A stray `[padding]` or plain text is not
     * enough.
     */
    fun looksLikeConfig(text: String): Boolean {
        if (text.isBlank()) return false
        return text.contains("[tun]") || text.contains("[[outline.uplinks]]")
    }
}

/** Outcome of a subscription fetch; never throws to the caller. */
sealed interface FetchResult {
    data class Success(val toml: String) : FetchResult
    data class Failure(val reason: String) : FetchResult
}

/**
 * Downloads a subscription config over HTTPS.
 *
 * The config carries server UUIDs and passwords, so plain HTTP is refused before
 * any connection. The URL's path is itself a secret token, so it is never logged
 * in full — only a masked form.
 */
object ConfigFetcher {

    private const val TAG = "ConfigFetcher"
    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val READ_TIMEOUT_MS = 15_000
    private const val MAX_BYTES = 200 * 1024

    suspend fun fetch(rawUrl: String): FetchResult = withContext(Dispatchers.IO) {
        val url = rawUrl.trim()
        if (!url.startsWith("https://", ignoreCase = true)) {
            return@withContext FetchResult.Failure("URL must start with https://")
        }

        var connection: HttpURLConnection? = null
        try {
            connection = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                requestMethod = "GET"
                // HttpURLConnection follows http->http and https->https, but not
                // cross-protocol; that is exactly the https-only stance we want.
                instanceFollowRedirects = true
                setRequestProperty("Accept", "text/plain, application/toml, */*")
            }

            val code = connection.responseCode
            if (code != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "fetch ${mask(url)} -> HTTP $code")
                return@withContext FetchResult.Failure("HTTP $code")
            }

            val body = connection.inputStream.use { input ->
                val buffer = ByteArray(MAX_BYTES + 1)
                var read = 0
                while (read < buffer.size) {
                    val n = input.read(buffer, read, buffer.size - read)
                    if (n < 0) break
                    read += n
                }
                if (read > MAX_BYTES) {
                    return@withContext FetchResult.Failure("config larger than ${MAX_BYTES / 1024} KB")
                }
                String(buffer, 0, read, Charsets.UTF_8)
            }

            if (!ConfigValidation.looksLikeConfig(body)) {
                Log.w(TAG, "fetch ${mask(url)} -> body is not a config")
                return@withContext FetchResult.Failure("response is not a config")
            }

            Log.i(TAG, "fetch ${mask(url)} -> ok, ${body.length} chars")
            FetchResult.Success(body)
        } catch (e: Exception) {
            Log.w(TAG, "fetch ${mask(url)} failed: ${e.javaClass.simpleName}")
            FetchResult.Failure(e.message ?: e.javaClass.simpleName)
        } finally {
            connection?.disconnect()
        }
    }

    /**
     * The path holds a secret token, so logs get host plus the last few
     * characters only — enough to tell two subscriptions apart, not enough to
     * reconstruct the URL.
     */
    private fun mask(url: String): String = runCatching {
        val parsed = URL(url)
        val tail = url.takeLast(6)
        "${parsed.host}/…$tail"
    }.getOrDefault("<url>")
}
