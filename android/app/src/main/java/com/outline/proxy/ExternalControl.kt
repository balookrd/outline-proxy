package com.outline.proxy

import android.content.Context
import java.net.URLDecoder
import java.security.MessageDigest

/**
 * External control over the `outline://` URI scheme, for automation apps
 * (Tasker, shortcuts, `adb shell am start`) that drive the tunnel from outside.
 *
 * Grammar — the command sits in the authority position, the rest is a query:
 *
 * ```
 * outline://connect                  # bring up the profile selected in the UI
 * outline://connect?profile=<name|id>
 * outline://disconnect
 * outline://toggle[?profile=<name|id>]
 * …&token=<secret>                   # required once a secret is configured
 * ```
 *
 * Scheme, command and query keys are case-insensitive; values are
 * percent-decoded. Everything here is pure Kotlin so it can be unit-tested on
 * the JVM — [ControlActivity] owns the Android-side execution.
 */
sealed interface ControlCommand {
    /** Bring the tunnel up. [profile] is a profile name or id; null = whatever the UI has selected. */
    data class Connect(val profile: String?) : ControlCommand

    /** Tear the tunnel down. */
    data object Disconnect : ControlCommand

    /** Down if the tunnel is up, otherwise [Connect]. */
    data class Toggle(val profile: String?) : ControlCommand
}

/** Why a control URI was turned down. Rendered to the user by [ControlActivity]. */
enum class RejectReason {
    /** Not an `outline://` URI at all — a foreign scheme or empty input. */
    NOT_A_CONTROL_URI,

    /** The scheme matched but the command is not one we implement. */
    UNKNOWN_COMMAND,

    /** External control is switched off in the app's settings. */
    DISABLED,

    /** A secret is configured and the caller supplied a wrong one (or none). */
    BAD_TOKEN,
}

/** The outcome of parsing a URI. Says nothing about whether the caller may run it. */
sealed interface ControlUri {
    data class Valid(val command: ControlCommand, val token: String?) : ControlUri

    data class Invalid(val reason: RejectReason) : ControlUri
}

/** External-control settings, owned by [ExternalControlStore]. */
data class ExternalControlConfig(
    val enabled: Boolean = true,
    /** Blank = no secret required. */
    val token: String = "",
)

private const val SCHEME = "outline://"
private const val KEY_PROFILE = "profile"
private const val KEY_TOKEN = "token"

/** Parse an `outline://` URI. Never throws — malformed input becomes [ControlUri.Invalid]. */
fun parseControlUri(raw: String?): ControlUri {
    val uri = raw?.trim().orEmpty()
    if (!uri.startsWith(SCHEME, ignoreCase = true)) {
        return ControlUri.Invalid(RejectReason.NOT_A_CONTROL_URI)
    }

    val body = uri.substring(SCHEME.length).substringBefore('#')
    val params = parseQuery(body.substringAfter('?', ""))
    // Tolerate both `outline://connect` and `outline:///connect`, with or
    // without a trailing slash; anything deeper is not a command we know.
    val name = body.substringBefore('?').trim('/').lowercase()
    val profile = params[KEY_PROFILE]?.trim()?.takeIf { it.isNotEmpty() }

    val command = when (name) {
        "connect" -> ControlCommand.Connect(profile)
        "disconnect" -> ControlCommand.Disconnect
        "toggle" -> ControlCommand.Toggle(profile)
        else -> return ControlUri.Invalid(RejectReason.UNKNOWN_COMMAND)
    }
    return ControlUri.Valid(command, params[KEY_TOKEN])
}

/**
 * Gate a parsed URI against the user's settings. Returns null when the command
 * may run, otherwise the reason to turn it down.
 */
fun checkAccess(token: String?, config: ExternalControlConfig): RejectReason? {
    if (!config.enabled) return RejectReason.DISABLED
    if (config.token.isEmpty()) return null

    val expected = config.token.toByteArray(Charsets.UTF_8)
    val supplied = (token ?: "").toByteArray(Charsets.UTF_8)
    // Content-independent comparison: a secret in a URI is guessable one
    // character at a time if the check short-circuits.
    return if (MessageDigest.isEqual(expected, supplied)) null else RejectReason.BAD_TOKEN
}

/**
 * Pick the profile a command refers to. [selector] is matched against ids
 * first, then names (case-insensitively); a null selector falls back to the
 * profile selected in the UI, mirroring what the Connect button does.
 * Returns null when nothing matches — a URI never creates a profile.
 */
fun resolveProfile(
    profiles: List<ServerProfile>,
    selector: String?,
    selectedId: String?,
): ServerProfile? {
    if (selector == null) {
        return profiles.firstOrNull { it.id == selectedId } ?: profiles.firstOrNull()
    }
    return profiles.firstOrNull { it.id == selector }
        ?: profiles.firstOrNull { it.name.equals(selector, ignoreCase = true) }
}

/** `a=1&b=2` → map, keys lowercased, values percent-decoded, first occurrence wins. */
private fun parseQuery(query: String): Map<String, String> {
    if (query.isEmpty()) return emptyMap()
    val params = mutableMapOf<String, String>()
    query.split('&').forEach { pair ->
        if (pair.isEmpty()) return@forEach
        val key = pair.substringBefore('=').lowercase()
        if (key.isEmpty() || params.containsKey(key)) return@forEach
        params[key] = decode(pair.substringAfter('=', ""))
    }
    return params
}

/** Percent-decode, falling back to the raw value on malformed escapes. */
private fun decode(value: String): String =
    runCatching { URLDecoder.decode(value, "UTF-8") }.getOrDefault(value)

/** Persists the external-control settings in SharedPreferences. */
class ExternalControlStore(context: Context) {
    private val prefs = context.getSharedPreferences("outline_external", Context.MODE_PRIVATE)

    fun load(): ExternalControlConfig = ExternalControlConfig(
        enabled = prefs.getBoolean(KEY_ENABLED, true),
        token = prefs.getString(KEY_SECRET, "").orEmpty(),
    )

    fun save(config: ExternalControlConfig) {
        prefs.edit()
            .putBoolean(KEY_ENABLED, config.enabled)
            .putString(KEY_SECRET, config.token)
            .apply()
    }

    companion object {
        private const val KEY_ENABLED = "enabled"
        private const val KEY_SECRET = "token"
    }
}
