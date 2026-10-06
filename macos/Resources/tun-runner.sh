#!/bin/bash
set -e

# tun-runner.sh: Helper script managing root-privileged utun process and routing on macOS.
# Used by Outline Proxy macOS client for TUN (Full VPN) mode.

ACTION="$1"

case "$ACTION" in
    start)
        BIN="$2"
        CONFIG="$3"
        SERVER_HOST="$4"
        RUN_DIR="$5"

        if [ -z "$BIN" ] || [ -z "$CONFIG" ] || [ -z "$RUN_DIR" ]; then
            echo "Usage: $0 start <bin_path> <config_path> <server_host> <run_dir>" >&2
            exit 1
        fi

        mkdir -p "$RUN_DIR"
        PID_FILE="$RUN_DIR/tun.pid"
        GW_FILE="$RUN_DIR/tun.gw"
        SERVER_IP_FILE="$RUN_DIR/tun.server_ip"
        LOG_FILE="$RUN_DIR/tun.log"

        # 1. Clean up any stale routes or processes from prior unclean terminations
        if [ -f "$PID_FILE" ]; then
            OLD_PID=$(cat "$PID_FILE" 2>/dev/null || true)
            if [ -n "$OLD_PID" ]; then
                kill -9 "$OLD_PID" 2>/dev/null || true
            fi
            rm -f "$PID_FILE"
        fi
        /sbin/route -q delete -net 0.0.0.0/1 10.0.85.1 >/dev/null 2>&1 || true
        /sbin/route -q delete -net 128.0.0.0/1 10.0.85.1 >/dev/null 2>&1 || true

        # 2. Determine default physical gateway
        DEFAULT_GW=$(/sbin/route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')
        if [ -z "$DEFAULT_GW" ]; then
            DEFAULT_GW=$(netstat -rn -f inet 2>/dev/null | awk '/^default/ {print $2}' | head -n 1)
        fi
        echo "$DEFAULT_GW" > "$GW_FILE"

        # 3. Resolve server host and set host route to prevent routing loops
        SERVER_IP=""
        if [ -n "$SERVER_HOST" ]; then
            if echo "$SERVER_HOST" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
                SERVER_IP="$SERVER_HOST"
            else
                SERVER_IP=$(dig +short "$SERVER_HOST" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1)
                if [ -z "$SERVER_IP" ]; then
                    SERVER_IP=$(dscacheutil -q host -a name "$SERVER_HOST" 2>/dev/null | awk '/ip_address:/ {print $2}' | head -n 1)
                fi
            fi
        fi

        if [ -n "$SERVER_IP" ] && [ -n "$DEFAULT_GW" ]; then
            echo "$SERVER_IP" > "$SERVER_IP_FILE"
            /sbin/route add -host "$SERVER_IP" "$DEFAULT_GW" >/dev/null 2>&1 || true
        fi

        # 4. Launch outline-ws-rust in background
        "$BIN" --config "$CONFIG" > "$LOG_FILE" 2>&1 &
        WS_PID=$!
        echo "$WS_PID" > "$PID_FILE"

        # 5. Wait for utun device initialization (up to 3 seconds)
        READY=0
        for _ in $(seq 1 30); do
            if ! kill -0 "$WS_PID" 2>/dev/null; then
                echo "ERROR: outline-ws-rust terminated unexpectedly. Log:" >&2
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

        echo "SUCCESS: TUN VPN active (PID: $WS_PID)"
        ;;

    stop)
        RUN_DIR="$2"
        if [ -z "$RUN_DIR" ]; then
            echo "Usage: $0 stop <run_dir>" >&2
            exit 1
        fi

        PID_FILE="$RUN_DIR/tun.pid"
        GW_FILE="$RUN_DIR/tun.gw"
        SERVER_IP_FILE="$RUN_DIR/tun.server_ip"

        # 1. Terminate process
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE" 2>/dev/null || true)
            if [ -n "$PID" ]; then
                kill -TERM "$PID" 2>/dev/null || true
                sleep 0.5
                kill -9 "$PID" 2>/dev/null || true
            fi
            rm -f "$PID_FILE"
        fi

        # 2. Delete routing table entries
        /sbin/route -q delete -net 0.0.0.0/1 10.0.85.1 >/dev/null 2>&1 || true
        /sbin/route -q delete -net 128.0.0.0/1 10.0.85.1 >/dev/null 2>&1 || true

        if [ -f "$SERVER_IP_FILE" ] && [ -f "$GW_FILE" ]; then
            SIP=$(cat "$SERVER_IP_FILE" 2>/dev/null || true)
            GW=$(cat "$GW_FILE" 2>/dev/null || true)
            if [ -n "$SIP" ] && [ -n "$GW" ]; then
                /sbin/route -q delete -host "$SIP" "$GW" >/dev/null 2>&1 || true
            fi
            rm -f "$SERVER_IP_FILE" "$GW_FILE"
        fi

        echo "SUCCESS: TUN VPN stopped and routes cleared."
        ;;

    status)
        RUN_DIR="$2"
        PID_FILE="$RUN_DIR/tun.pid"
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE" 2>/dev/null || true)
            if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
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
