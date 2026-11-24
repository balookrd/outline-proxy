#!/bin/bash
set -e

# tun-runner.sh: Privileged helper script managing root-privileged utun process and routing on macOS.
# Used by Outline Proxy macOS client for TUN (Full VPN) mode.
#
# SECURITY INVARIANTS:
# 1. The binary path is strictly fixed to root-owned /Library/Application Support/OutlineProxy/outline-client.
# 2. The run directory is strictly fixed to root-owned /var/run/outline-proxy (mode 0755, root-writable only).
# 3. Arbitrary binary paths or run directories from CLI arguments are strictly rejected.
# 4. Host parameters and config links are sanitized (leading `-` forbidden) to prevent option/command injection.
# 5. IPv6 traffic is rejected via loopback during TUN session to prevent IPv6 VPN leaks with instant IPv4 fallback.

SYSTEM_BIN="/Library/Application Support/OutlineProxy/outline-client"
RUN_DIR="/var/run/outline-proxy"

is_valid_host() {
    local candidate="${1:-}"
    [ -n "$candidate" ] && printf '%s\n' "$candidate" | grep -Eq '^[a-zA-Z0-9][a-zA-Z0-9.:-]*$'
}

is_valid_ipv4() {
    local candidate="${1:-}"
    [ -n "$candidate" ] && printf '%s\n' "$candidate" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
}

extract_valid_hosts() {
    local cfg="${1:-}"
    local extra_host="${2:-}"
    local raw_hosts=""
    local sq="'"

    if [ -n "$cfg" ] && [ -f "$cfg" ]; then
        local link_hosts ws_hosts addr_hosts
        link_hosts=$(grep -E '^[[:space:]]*link[[:space:]]*=' "$cfg" 2>/dev/null \
            | sed -E "s/.*@\[?([^]:/?#\"${sq}[:space:]]+)\]?.*/\1/" || true)
        ws_hosts=$(grep -E '^[[:space:]]*(tcp_|udp_)?ws_url[[:space:]]*=' "$cfg" 2>/dev/null \
            | sed -E "s/.*:\/\/\[?([^]:/?#\"${sq}[:space:]]+)\]?.*/\1/" || true)
        addr_hosts=$(grep -E '^[[:space:]]*server_addr[[:space:]]*=' "$cfg" 2>/dev/null \
            | sed -E "s/^[^=]*=[[:space:]]*[\"${sq}]\[?([^]:/?#\"${sq}[:space:]]+)\]?.*/\1/" || true)
        raw_hosts=$(printf '%s\n%s\n%s\n' "$link_hosts" "$ws_hosts" "$addr_hosts")
    fi

    if [ -n "$extra_host" ]; then
        raw_hosts=$(printf '%s\n%s\n' "$raw_hosts" "$extra_host")
    fi

    while IFS= read -r candidate; do
        [ -z "$candidate" ] && continue
        if is_valid_host "$candidate"; then
            printf '%s\n' "$candidate"
        fi
    done <<< "$raw_hosts" | sort -u
}

if [ "${TUN_RUNNER_LIB_ONLY:-0}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi

ACTION="${1:-}"

check_binary() {
    if [ ! -f "$SYSTEM_BIN" ]; then
        echo "ERROR: System binary not found: $SYSTEM_BIN" >&2
        echo "Please install or reinstall the privileged helper from Outline Proxy settings." >&2
        exit 1
    fi

    # Verify ownership is root (uid 0)
    BIN_UID=$(stat -f '%u' "$SYSTEM_BIN" 2>/dev/null || echo -1)
    if [ "$BIN_UID" -ne 0 ]; then
        echo "ERROR: $SYSTEM_BIN is not owned by root (UID $BIN_UID)" >&2
        exit 1
    fi

    if [ ! -x "$SYSTEM_BIN" ]; then
        echo "ERROR: $SYSTEM_BIN is not executable" >&2
        exit 1
    fi
}

init_run_dir() {
    mkdir -p "$RUN_DIR"
    chmod 0755 "$RUN_DIR"
    chown root:wheel "$RUN_DIR" 2>/dev/null || true
}

case "$ACTION" in
    start)
        check_binary
        init_run_dir

        CONFIG="${2:-}"
        RAW_SERVER_HOST="${3:-}"

        if [ -z "$CONFIG" ]; then
            echo "Usage: $0 start <config_path> [server_host]" >&2
            exit 1
        fi

        if [ ! -f "$CONFIG" ]; then
            echo "ERROR: Config file not found: $CONFIG" >&2
            exit 1
        fi

        # Sanitize server_host: only permit RFC 1123 domain names / IP addresses without leading '-'
        SERVER_HOST=""
        if [ -n "$RAW_SERVER_HOST" ]; then
            if is_valid_host "$RAW_SERVER_HOST"; then
                SERVER_HOST="$RAW_SERVER_HOST"
            else
                echo "WARNING: server_host contains invalid characters, ignoring: $RAW_SERVER_HOST" >&2
            fi
        fi

        PID_FILE="$RUN_DIR/tun.pid"
        GW_FILE="$RUN_DIR/tun.gw"
        SERVER_IP_FILE="$RUN_DIR/tun.server_ip"
        LOG_FILE="$RUN_DIR/tun.log"
        STATE_FILE="$RUN_DIR/tun.state.toml"

        # 1. Clean up any stale routes or processes from prior unclean terminations
        if [ -f "$PID_FILE" ]; then
            OLD_PID=$(cat "$PID_FILE" 2>/dev/null || true)
            if [ -n "$OLD_PID" ] && [ "$OLD_PID" -gt 1 ] 2>/dev/null; then
                kill -9 "$OLD_PID" 2>/dev/null || true
            fi
            rm -f "$PID_FILE"
        fi
        /sbin/route -q delete -net 0.0.0.0/1 10.0.85.1 >/dev/null 2>&1 || true
        /sbin/route -q delete -net 128.0.0.0/1 10.0.85.1 >/dev/null 2>&1 || true
        /sbin/route -q delete -inet6 ::/1 ::1 >/dev/null 2>&1 || /sbin/route -q delete -inet6 ::/1 >/dev/null 2>&1 || true
        /sbin/route -q delete -inet6 8000::/1 ::1 >/dev/null 2>&1 || /sbin/route -q delete -inet6 8000::/1 >/dev/null 2>&1 || true

        # 2. Determine default physical gateway before TUN routes are installed
        DEFAULT_GW=$(/sbin/route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')
        if ! is_valid_ipv4 "$DEFAULT_GW"; then
            DEFAULT_GW=$(netstat -rn -f inet 2>/dev/null | awk '/^default/ {print $2}' | head -n 1)
        fi
        if ! is_valid_ipv4 "$DEFAULT_GW"; then
            echo "ERROR: Unable to determine valid IPv4 default gateway (got: '$DEFAULT_GW')" >&2
            exit 1
        fi
        echo "$DEFAULT_GW" > "$GW_FILE"

        # Clean prior host routes if leftover
        if [ -f "$SERVER_IP_FILE" ]; then
            while IFS= read -r OLD_IP; do
                if is_valid_ipv4 "$OLD_IP"; then
                    /sbin/route -q delete -host "$OLD_IP" "$DEFAULT_GW" >/dev/null 2>&1 \
                        || /sbin/route -q delete -host "$OLD_IP" >/dev/null 2>&1 || true
                fi
            done < "$SERVER_IP_FILE"
            rm -f "$SERVER_IP_FILE"
        fi

        : > "$LOG_FILE"
        chmod 0644 "$LOG_FILE" 2>/dev/null || true

        # 3. Resolve all server host endpoints and set host routes to prevent routing loops
        ALL_HOSTS=$(extract_valid_hosts "$CONFIG" "$SERVER_HOST")

        : > "$SERVER_IP_FILE"
        while IFS= read -r HOST; do
            [ -z "$HOST" ] && continue
            if ! is_valid_host "$HOST"; then
                continue
            fi

            HOST_IPS=""
            if is_valid_ipv4 "$HOST"; then
                HOST_IPS="$HOST"
            else
                HOST_IPS=$( {
                    dscacheutil -q host -a name "$HOST" 2>/dev/null | awk '/^ip_address:/ {print $2}'
                    dig +short A "$HOST" 2>/dev/null
                } | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u || true )
            fi

            for IP in $HOST_IPS; do
                if is_valid_ipv4 "$IP"; then
                    if ! grep -Fxq "$IP" "$SERVER_IP_FILE" 2>/dev/null; then
                        /sbin/route -q delete -host "$IP" >/dev/null 2>&1 || true
                        if /sbin/route -n add -host "$IP" "$DEFAULT_GW" >/dev/null 2>&1; then
                            echo "$IP" >> "$SERVER_IP_FILE"
                        else
                            echo "WARNING: failed to add host bypass route for $IP via $DEFAULT_GW" >> "$LOG_FILE"
                        fi
                    fi
                fi
            done
        done <<< "$ALL_HOSTS"

        # 4. Launch outline-client in background from fixed root-owned path with isolated STATE_PATH
        STATE_PATH="$STATE_FILE" "$SYSTEM_BIN" --config "$CONFIG" >> "$LOG_FILE" 2>&1 &
        WS_PID=$!
        echo "$WS_PID" > "$PID_FILE"
        chmod 0644 "$PID_FILE" "$LOG_FILE" 2>/dev/null || true

        # 5. Wait for utun device initialization (up to 3 seconds)
        READY=0
        for _ in $(seq 1 30); do
            if ! kill -0 "$WS_PID" 2>/dev/null; then
                echo "ERROR: outline-client terminated unexpectedly. Log:" >&2
                cat "$LOG_FILE" >&2
                exit 1
            fi
            if ifconfig | grep -q "10.0.85.2"; then
                READY=1
                break
            fi
            sleep 0.1
        done

        if [ "$READY" -ne 1 ]; then
            echo "WARNING: utun device with 10.0.85.2 not detected within 3 seconds, applying routes anyway..." >&2
        fi

        # 6. Add default sub-routes via utun point-to-point peer (10.0.85.1)
        /sbin/route -n add -net 0.0.0.0/1 10.0.85.1 >/dev/null
        /sbin/route -n add -net 128.0.0.0/1 10.0.85.1 >/dev/null

        # 7. Mitigate IPv6 VPN leak: reject non-link-local IPv6 traffic for instant IPv4 fallback
        /sbin/route -q add -inet6 ::/1 ::1 -reject >/dev/null 2>&1 || true
        /sbin/route -q add -inet6 8000::/1 ::1 -reject >/dev/null 2>&1 || true

        echo "SUCCESS: TUN VPN active (PID: $WS_PID)"
        ;;

    stop)
        init_run_dir
        PID_FILE="$RUN_DIR/tun.pid"
        GW_FILE="$RUN_DIR/tun.gw"
        SERVER_IP_FILE="$RUN_DIR/tun.server_ip"

        # 1. Terminate process
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE" 2>/dev/null || true)
            if [ -n "$PID" ] && [ "$PID" -gt 1 ] 2>/dev/null; then
                kill -TERM "$PID" 2>/dev/null || true
                sleep 0.5
                kill -9 "$PID" 2>/dev/null || true
            fi
            rm -f "$PID_FILE"
        fi

        # 2. Delete routing table entries
        /sbin/route -q delete -net 0.0.0.0/1 10.0.85.1 >/dev/null 2>&1 || true
        /sbin/route -q delete -net 128.0.0.0/1 10.0.85.1 >/dev/null 2>&1 || true

        # 3. Clear IPv6 reject/blackhole routes
        /sbin/route -q delete -inet6 ::/1 ::1 >/dev/null 2>&1 || /sbin/route -q delete -inet6 ::/1 >/dev/null 2>&1 || true
        /sbin/route -q delete -inet6 8000::/1 ::1 >/dev/null 2>&1 || /sbin/route -q delete -inet6 8000::/1 >/dev/null 2>&1 || true

        # 4. Clear host routes
        if [ -f "$SERVER_IP_FILE" ]; then
            GW=""
            if [ -f "$GW_FILE" ]; then
                GW=$(cat "$GW_FILE" 2>/dev/null || true)
            fi
            while IFS= read -r IP; do
                if is_valid_ipv4 "$IP"; then
                    if is_valid_ipv4 "$GW"; then
                        /sbin/route -q delete -host "$IP" "$GW" >/dev/null 2>&1 \
                            || /sbin/route -q delete -host "$IP" >/dev/null 2>&1 || true
                    else
                        /sbin/route -q delete -host "$IP" >/dev/null 2>&1 || true
                    fi
                fi
            done < "$SERVER_IP_FILE"
            rm -f "$SERVER_IP_FILE" "$GW_FILE"
        fi

        echo "SUCCESS: TUN VPN stopped and routes cleared."
        ;;

    status)
        PID_FILE="$RUN_DIR/tun.pid"
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE" 2>/dev/null || true)
            if [ -n "$PID" ] && [ "$PID" -gt 1 ] 2>/dev/null && ps -p "$PID" >/dev/null 2>&1; then
                echo "running:$PID"
                exit 0
            fi
        fi
        echo "stopped"
        ;;

    *)
        echo "Unknown action: $ACTION" >&2
        echo "Usage: $0 {start|stop|status}" >&2
        exit 1
        ;;
esac
