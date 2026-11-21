#!/bin/bash
set -e

# tun-runner.sh: Privileged helper script managing root-privileged utun process and routing on macOS.
# Used by Outline Proxy macOS client for TUN (Full VPN) mode.
#
# SECURITY INVARIANTS:
# 1. The binary path is strictly fixed to root-owned /Library/Application Support/OutlineProxy/outline-client.
# 2. The run directory is strictly fixed to root-owned /var/run/outline-proxy (mode 0700).
# 3. Arbitrary binary paths or run directories from CLI arguments are strictly rejected.
# 4. Host parameters and config links are sanitized to avoid shell command injections.
# 5. IPv6 traffic is blackholed during TUN session to prevent IPv6 VPN leaks.

SYSTEM_BIN="/Library/Application Support/OutlineProxy/outline-client"
RUN_DIR="/var/run/outline-proxy"

ACTION="$1"

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

        CONFIG="$2"
        RAW_SERVER_HOST="${3:-}"

        if [ -z "$CONFIG" ]; then
            echo "Usage: $0 start <config_path> [server_host]" >&2
            exit 1
        fi

        if [ ! -f "$CONFIG" ]; then
            echo "ERROR: Config file not found: $CONFIG" >&2
            exit 1
        fi

        # Sanitize server_host: only permit RFC 1123 domain names / IPv4 / IPv6 addresses
        SERVER_HOST=""
        if [ -n "$RAW_SERVER_HOST" ]; then
            if echo "$RAW_SERVER_HOST" | grep -Eq '^[a-zA-Z0-9.:-]+$'; then
                SERVER_HOST="$RAW_SERVER_HOST"
            else
                echo "WARNING: server_host contains invalid characters, ignoring: $RAW_SERVER_HOST" >&2
            fi
        fi

        PID_FILE="$RUN_DIR/tun.pid"
        GW_FILE="$RUN_DIR/tun.gw"
        SERVER_IP_FILE="$RUN_DIR/tun.server_ip"
        LOG_FILE="$RUN_DIR/tun.log"

        # 1. Clean up any stale routes or processes from prior unclean terminations
        if [ -f "$PID_FILE" ]; then
            OLD_PID=$(cat "$PID_FILE" 2>/dev/null || true)
            if [ -n "$OLD_PID" ] && [ "$OLD_PID" -gt 1 ]; then
                kill -9 "$OLD_PID" 2>/dev/null || true
            fi
            rm -f "$PID_FILE"
        fi
        /sbin/route -q delete -net 0.0.0.0/1 10.0.85.1 >/dev/null 2>&1 || true
        /sbin/route -q delete -net 128.0.0.0/1 10.0.85.1 >/dev/null 2>&1 || true
        /sbin/route -q delete -inet6 ::/1 >/dev/null 2>&1 || true
        /sbin/route -q delete -inet6 8000::/1 >/dev/null 2>&1 || true

        # 2. Determine default physical gateway
        DEFAULT_GW=$(/sbin/route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')
        if [ -z "$DEFAULT_GW" ]; then
            DEFAULT_GW=$(netstat -rn -f inet 2>/dev/null | awk '/^default/ {print $2}' | head -n 1)
        fi
        echo "$DEFAULT_GW" > "$GW_FILE"

        # Clean prior host routes if leftover
        if [ -f "$SERVER_IP_FILE" ] && [ -n "$DEFAULT_GW" ]; then
            while IFS= read -r OLD_IP; do
                [ -n "$OLD_IP" ] && /sbin/route -q delete -host -- "$OLD_IP" "$DEFAULT_GW" >/dev/null 2>&1 || true
            done < "$SERVER_IP_FILE"
            rm -f "$SERVER_IP_FILE"
        fi

        # 3. Resolve all server host endpoints and set host routes to prevent routing loops
        ALL_HOSTS=""
        if [ -f "$CONFIG" ]; then
            CONFIG_HOSTS=$(grep -E 'link\s*=' "$CONFIG" | sed -E 's/.*@([^:/?#]+).*/\1/' | sort -u || true)
            ALL_HOSTS="$CONFIG_HOSTS"
        fi
        if [ -n "$SERVER_HOST" ]; then
            ALL_HOSTS=$(printf "%s\n%s" "$ALL_HOSTS" "$SERVER_HOST" | sort -u)
        fi

        : > "$SERVER_IP_FILE"
        while IFS= read -r HOST; do
            [ -z "$HOST" ] && continue
            # Validate HOST token strictly against RFC 1123 / IP address characters
            if ! echo "$HOST" | grep -Eq '^[a-zA-Z0-9.:-]+$'; then
                continue
            fi

            HOST_IPS=""
            if echo "$HOST" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
                HOST_IPS="$HOST"
            else
                HOST_IPS=$(dig +short -- "$HOST" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
                if [ -z "$HOST_IPS" ]; then
                    HOST_IPS=$(dscacheutil -q host -a name "$HOST" 2>/dev/null | awk '/ip_address:/ {print $2}' || true)
                fi
            fi

            for IP in $HOST_IPS; do
                if [ -n "$IP" ] && [ -n "$DEFAULT_GW" ]; then
                    if ! grep -Fxq "$IP" "$SERVER_IP_FILE" 2>/dev/null; then
                        echo "$IP" >> "$SERVER_IP_FILE"
                        /sbin/route add -host -- "$IP" "$DEFAULT_GW" >/dev/null 2>&1 || true
                    fi
                fi
            done
        done <<< "$ALL_HOSTS"

        # 4. Launch outline-client in background from fixed root-owned path
        "$SYSTEM_BIN" --config "$CONFIG" > "$LOG_FILE" 2>&1 &
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
        /sbin/route add -net 0.0.0.0/1 10.0.85.1
        /sbin/route add -net 128.0.0.0/1 10.0.85.1

        # 7. Mitigate IPv6 VPN leak: blackhole non-link-local IPv6 traffic
        /sbin/route -q add -inet6 ::/1 -blackhole >/dev/null 2>&1 || /sbin/route -q add -inet6 ::/1 ::1 -blackhole >/dev/null 2>&1 || true
        /sbin/route -q add -inet6 8000::/1 -blackhole >/dev/null 2>&1 || /sbin/route -q add -inet6 8000::/1 ::1 -blackhole >/dev/null 2>&1 || true

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
            if [ -n "$PID" ] && [ "$PID" -gt 1 ]; then
                kill -TERM "$PID" 2>/dev/null || true
                sleep 0.5
                kill -9 "$PID" 2>/dev/null || true
            fi
            rm -f "$PID_FILE"
        fi

        # 2. Delete routing table entries
        /sbin/route -q delete -net 0.0.0.0/1 10.0.85.1 >/dev/null 2>&1 || true
        /sbin/route -q delete -net 128.0.0.0/1 10.0.85.1 >/dev/null 2>&1 || true

        # 3. Clear IPv6 blackhole routes
        /sbin/route -q delete -inet6 ::/1 >/dev/null 2>&1 || true
        /sbin/route -q delete -inet6 8000::/1 >/dev/null 2>&1 || true

        # 4. Clear host routes
        if [ -f "$SERVER_IP_FILE" ] && [ -f "$GW_FILE" ]; then
            GW=$(cat "$GW_FILE" 2>/dev/null || true)
            while IFS= read -r IP; do
                if [ -n "$IP" ] && [ -n "$GW" ]; then
                    /sbin/route -q delete -host -- "$IP" "$GW" >/dev/null 2>&1 || true
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
            if [ -n "$PID" ] && [ "$PID" -gt 1 ] && ps -p "$PID" >/dev/null 2>&1; then
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
