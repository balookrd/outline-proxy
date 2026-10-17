package com.outline.proxy

/**
 * Transforms client configuration and share links to run strictly over TCP (h2/h1),
 * eliminating HTTP/3 (QUIC/UDP) carriers.
 *
 * Used when the user enables "TCP only" mode to avoid handshake timeouts and
 * endless fallback loops in networks where UDP/QUIC (port 443 UDP) is blocked or throttled.
 */
object TcpOnlyConfig {

    private val XHTTP_H3_REGEX = Regex("""(?m)^(\s*(?:vless_mode|ss_mode|tcp_mode|udp_mode)\s*=\s*["'])xhttp_h3(["'])""")
    private val WS_H3_REGEX = Regex("""(?m)^(\s*(?:vless_mode|ss_mode|tcp_mode|udp_mode)\s*=\s*["'])ws_h3(["'])""")
    private val LINK_LINE_REGEX = Regex("""(?m)^(\s*link\s*=\s*["'])([^"']+)(["'])""")
    private val ALPN_PARAM_REGEX = Regex("""([?&]alpn=)([^&#]*)""", RegexOption.IGNORE_CASE)

    /**
     * Rewrite share-link URL so that any H3 ALPN token is replaced with H2.
     * If the link contains `alpn=h3`, `alpn=h3,h2`, `alpn=h3%2Ch2`, or `alpn=h2,h3`,
     * it is normalized to `alpn=h2`.
     */
    fun enforceLink(link: String): String {
        val trimmed = link.trim()
        if (trimmed.isEmpty()) return link
        if (!ALPN_PARAM_REGEX.containsMatchIn(trimmed)) {
            return link
        }
        return ALPN_PARAM_REGEX.replace(trimmed) { mr ->
            val prefix = mr.groupValues[1]
            val value = mr.groupValues[2].lowercase()
            if (value.contains("h3")) {
                prefix + "h2"
            } else {
                mr.value
            }
        }
    }

    /**
     * Rewrite a full client TOML configuration (structured, raw override, or subscription)
     * so that all H3 carrier modes (`xhttp_h3`, `ws_h3`) and H3 ALPN tokens in links
     * are downgraded to their H2 equivalents (`xhttp_h2`, `ws_h2`, `alpn=h2`).
     */
    fun apply(toml: String): String {
        if (toml.isBlank()) return toml

        var result = XHTTP_H3_REGEX.replace(toml, "$1xhttp_h2$2")
        result = WS_H3_REGEX.replace(result, "$1ws_h2$2")

        result = LINK_LINE_REGEX.replace(result) { mr ->
            val prefix = mr.groupValues[1]
            val linkUrl = mr.groupValues[2]
            val suffix = mr.groupValues[3]
            val rewritten = enforceLink(linkUrl)
            "$prefix$rewritten$suffix"
        }

        return result
    }
}
