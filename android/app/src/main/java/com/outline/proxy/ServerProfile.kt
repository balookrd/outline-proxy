package com.outline.proxy

import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * A saved server profile. Structured fields are rendered into a ws-rust client
 * TOML config by [toToml]. Two transports are supported:
 *
 *  - `vless`: paste a standard `vless://UUID@host:port?...#name` share link;
 *    ws-rust expands it at load time.
 *  - `ss`   : Shadowsocks-over-WS/XHTTP — carrier URL + mode + cipher + password.
 *
 * `rawTomlOverride`, when non-blank, is used verbatim instead of the generated
 * TOML — an escape hatch for configs the structured form can't yet express
 * (fallbacks, groups, combined paths, multiple uplinks).
 *
 * `configUrl`, when non-blank, makes this a *subscription*: the whole config is
 * fetched from that HTTPS URL and kept in [cachedToml], refreshed in the
 * background. The URL is then the single source of truth — [toToml] returns the
 * cache and ignores the override and the structured fields.
 */
data class ServerProfile(
    val id: String = UUID.randomUUID().toString(),
    val name: String = "",
    val transport: String = "vless", // "vless" | "ss"
    // VLESS
    val vlessLink: String = "",
    // SS
    val ssLink: String = "",
    // Common
    val paddingEnabled: Boolean = false,
    val rawTomlOverride: String = "",
    // Subscription
    val configUrl: String = "",
    val cachedToml: String = "",
    val updatedAt: Long = 0L,
) {
    /** This profile's config is fetched from [configUrl] rather than built locally. */
    val isSubscription: Boolean get() = configUrl.isNotBlank()

    fun toToml(): String {
        // A subscription's config is whatever was last fetched — nothing else may
        // leak into it, so this wins over both the override and the fields.
        if (isSubscription) return cachedToml
        if (rawTomlOverride.isNotBlank()) return rawTomlOverride

        val sb = StringBuilder()
        // Native TUN: the fd comes from VpnService, not this path, but the loader
        // needs a non-empty [tun].path to activate TUN. sniffing=true is required
        // for the TLS/QUIC SNI cases (e.g. YouTube on TV).
        sb.append("[tun]\n")
        sb.append("path = \"vpn\"\n")
        sb.append("mtu = ").append(TUN_MTU).append("\n\n")
        sb.append("[tun.tcp]\n")
        sb.append("sniffing = true\n\n")

        sb.append("[[outline.uplinks]]\n")
        sb.append("name = \"").append(name.ifBlank { "primary" }).append("\"\n")
        sb.append("transport = \"").append(transport).append("\"\n")
        when (transport) {
            "vless" -> {
                sb.append("link = \"").append(vlessLink).append("\"\n")
            }
            "ss" -> {
                // ss:// share link carries carrier + cipher + password.
                sb.append("link = \"").append(ssLink).append("\"\n")
            }
        }
        sb.append("\n[padding]\n")
        sb.append("enabled = ").append(paddingEnabled).append("\n")
        return sb.toString()
    }

    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("name", name)
        put("transport", transport)
        put("vlessLink", vlessLink)
        put("ssLink", ssLink)
        put("paddingEnabled", paddingEnabled)
        put("rawTomlOverride", rawTomlOverride)
        put("configUrl", configUrl)
        put("cachedToml", cachedToml)
        put("updatedAt", updatedAt)
    }

    companion object {
        /** Single source of the tunnel MTU: the `[tun] mtu` emitted into the config
         *  MUST match `VpnService.Builder.setMtu` (OutlineVpnService). */
        const val TUN_MTU = 1500

        fun fromJson(o: JSONObject): ServerProfile = ServerProfile(
            id = o.optString("id", UUID.randomUUID().toString()),
            name = o.optString("name", ""),
            transport = o.optString("transport", "vless"),
            vlessLink = o.optString("vlessLink", ""),
            ssLink = o.optString("ssLink", ""),
            paddingEnabled = o.optBoolean("paddingEnabled", false),
            rawTomlOverride = o.optString("rawTomlOverride", ""),
            configUrl = o.optString("configUrl", ""),
            cachedToml = o.optString("cachedToml", ""),
            updatedAt = o.optLong("updatedAt", 0L),
        )

        fun listToJson(profiles: List<ServerProfile>): String {
            val arr = JSONArray()
            profiles.forEach { arr.put(it.toJson()) }
            return arr.toString()
        }

        fun listFromJson(s: String?): List<ServerProfile> {
            if (s.isNullOrBlank()) return emptyList()
            return runCatching {
                val arr = JSONArray(s)
                (0 until arr.length()).map { fromJson(arr.getJSONObject(it)) }
            }.getOrDefault(emptyList())
        }
    }
}
