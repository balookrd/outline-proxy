package com.outline.proxy

/**
 * Sanitizes and optimizes client TOML configuration for mobile cellular battery life.
 *
 * Prevents mobile radio/RRC exhaustion and CPU wakeups by enforcing:
 * 1. Warm standby pools disabled (`warm_standby_tcp = 0`, `warm_standby_udp = 0`).
 * 2. Background carrier loss sampling disabled (`loss_sample_interval_secs = 0`).
 * 3. Standby keepalives disabled (`tcp_ws_standby_keepalive_secs = 0`, `warm_probe_keepalive_secs = 0`).
 * 4. Active TCP keepalive relaxed (`tcp_active_keepalive_secs >= 120`).
 * 5. Probing interval bounded (`interval_secs >= 300`).
 * 6. HTTP/2 and QUIC carrier keepalive intervals stretched (`[h2]` 60s/20s, `[quic]` 25s/60s).
 */
object MobilePowerConfig {

    private val SECTION_HEADER_REGEX = Regex("""^\s*(\[+[^\[\]]+\]+)\s*$""")
    private val KEY_VALUE_REGEX = Regex("""^\s*([a-zA-Z0-9_-]+)\s*=\s*(.*)$""")

    fun sanitize(toml: String): String {
        if (toml.isBlank()) return toml

        val lines = toml.lines()
        val sections = mutableListOf<Section>()
        var currentHeader: String? = null
        var currentLines = mutableListOf<String>()

        for (line in lines) {
            val headerMatch = SECTION_HEADER_REGEX.matchEntire(line)
            if (headerMatch != null) {
                sections.add(Section(currentHeader, currentLines))
                currentHeader = headerMatch.groupValues[1].trim()
                currentLines = mutableListOf()
            } else {
                currentLines.add(line)
            }
        }
        sections.add(Section(currentHeader, currentLines))

        var foundLoadBalancing = false
        var foundH2 = false
        var foundQuic = false

        for (section in sections) {
            val h = section.header?.lowercase()?.trim() ?: continue
            when {
                h == "[outline.load_balancing]" -> {
                    foundLoadBalancing = true
                    sanitizeLoadBalancing(section)
                }
                h == "[[uplink_group]]" || h == "[uplink_group]" -> {
                    sanitizeUplinkGroup(section)
                }
                h == "[outline.probe]" -> {
                    sanitizeProbe(section)
                }
                h == "[h2]" -> {
                    foundH2 = true
                    sanitizeH2(section)
                }
                h == "[quic]" -> {
                    foundQuic = true
                    sanitizeQuic(section)
                }
            }
        }

        val extraSections = mutableListOf<String>()
        if (!foundLoadBalancing) {
            extraSections.add(
                """
                [outline.load_balancing]
                warm_standby_tcp = 0
                warm_standby_udp = 0
                loss_sample_interval_secs = 0
                tcp_ws_standby_keepalive_secs = 0
                warm_probe_keepalive_secs = 0
                tcp_active_keepalive_secs = 120
                """.trimIndent()
            )
        }
        if (!foundH2) {
            extraSections.add(
                """
                [h2]
                keepalive_interval_secs = 60
                keepalive_timeout_secs = 20
                """.trimIndent()
            )
        }
        if (!foundQuic) {
            extraSections.add(
                """
                [quic]
                keepalive_secs = 25
                idle_timeout_secs = 60
                """.trimIndent()
            )
        }

        val result = StringBuilder()
        for (section in sections) {
            if (section.header != null) {
                result.append(section.header).append("\n")
            }
            for (line in section.lines) {
                result.append(line).append("\n")
            }
        }

        if (extraSections.isNotEmpty()) {
            if (result.isNotBlank() && !result.endsWith("\n\n")) {
                result.append("\n")
            }
            for (extra in extraSections) {
                result.append(extra).append("\n\n")
            }
        }

        return result.toString().trimEnd() + "\n"
    }

    private class Section(val header: String?, val lines: MutableList<String>)

    private fun sanitizeUplinkGroup(section: Section) {
        setOrAddKey(section.lines, "warm_standby_tcp", "0")
        setOrAddKey(section.lines, "warm_standby_udp", "0")
    }

    private fun sanitizeLoadBalancing(section: Section) {
        setOrAddKey(section.lines, "warm_standby_tcp", "0")
        setOrAddKey(section.lines, "warm_standby_udp", "0")
        setOrAddKey(section.lines, "loss_sample_interval_secs", "0")
        setOrAddKey(section.lines, "tcp_ws_standby_keepalive_secs", "0")
        setOrAddKey(section.lines, "warm_probe_keepalive_secs", "0")

        val currentActive = getKeyIntValue(section.lines, "tcp_active_keepalive_secs")
        if (currentActive == null || currentActive < 120) {
            setOrAddKey(section.lines, "tcp_active_keepalive_secs", "120")
        }
    }

    private fun sanitizeProbe(section: Section) {
        val currentInterval = getKeyIntValue(section.lines, "interval_secs")
        if (currentInterval == null || currentInterval < 300) {
            setOrAddKey(section.lines, "interval_secs", "300")
        }
    }

    private fun sanitizeH2(section: Section) {
        val currentInterval = getKeyIntValue(section.lines, "keepalive_interval_secs")
        if (currentInterval == null || currentInterval < 60) {
            setOrAddKey(section.lines, "keepalive_interval_secs", "60")
        }
        val currentTimeout = getKeyIntValue(section.lines, "keepalive_timeout_secs")
        if (currentTimeout == null || currentTimeout < 20) {
            setOrAddKey(section.lines, "keepalive_timeout_secs", "20")
        }
    }

    private fun sanitizeQuic(section: Section) {
        val currentKeepalive = getKeyIntValue(section.lines, "keepalive_secs")
        if (currentKeepalive == null || currentKeepalive < 25) {
            setOrAddKey(section.lines, "keepalive_secs", "25")
        }
        val currentIdle = getKeyIntValue(section.lines, "idle_timeout_secs")
        if (currentIdle == null || currentIdle < 60) {
            setOrAddKey(section.lines, "idle_timeout_secs", "60")
        }
    }

    private fun getKeyIntValue(lines: List<String>, key: String): Long? {
        for (line in lines) {
            val match = KEY_VALUE_REGEX.matchEntire(line) ?: continue
            if (match.groupValues[1] == key) {
                val valuePart = match.groupValues[2].split('#')[0].trim()
                return valuePart.toLongOrNull()
            }
        }
        return null
    }

    private fun setOrAddKey(lines: MutableList<String>, key: String, newValue: String) {
        for (i in lines.indices) {
            val match = KEY_VALUE_REGEX.matchEntire(lines[i]) ?: continue
            if (match.groupValues[1] == key) {
                // Keep inline comment if present
                val commentIdx = lines[i].indexOf('#')
                val comment = if (commentIdx >= 0) " " + lines[i].substring(commentIdx) else ""
                lines[i] = "$key = $newValue$comment"
                return
            }
        }
        lines.add("$key = $newValue")
    }
}
