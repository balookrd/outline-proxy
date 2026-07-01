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
    val socksListen: String = "127.0.0.1:1080",
    val rawTomlOverride: String = "",
) {
    fun toToml(): String {
        if (rawTomlOverride.isNotBlank()) return rawTomlOverride

        val sb = StringBuilder()
        sb.append("[socks5]\n")
        sb.append("listen = \"").append(socksListen).append("\"\n\n")

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
        put("socksListen", socksListen)
        put("rawTomlOverride", rawTomlOverride)
    }

    companion object {
        fun fromJson(o: JSONObject): ServerProfile = ServerProfile(
            id = o.optString("id", UUID.randomUUID().toString()),
            name = o.optString("name", ""),
            transport = o.optString("transport", "vless"),
            vlessLink = o.optString("vlessLink", ""),
            ssLink = o.optString("ssLink", ""),
            paddingEnabled = o.optBoolean("paddingEnabled", false),
            socksListen = o.optString("socksListen", "127.0.0.1:1080"),
            rawTomlOverride = o.optString("rawTomlOverride", ""),
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
