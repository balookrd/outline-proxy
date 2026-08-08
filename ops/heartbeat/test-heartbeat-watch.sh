#!/usr/bin/env bash
#
# test-heartbeat-watch.sh — offline behaviour tests for the heartbeat watcher.
# Runs anywhere python3 exists; touches nothing outside its temp directory.

set -euo pipefail
cd "$(dirname "$0")"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

log="$tmp/heartbeat.log"
state="$tmp/state.json"
fails=0

# Fixed clock so the tests never depend on wall time. 2026-08-07 12:00:00 +0300.
now=1786100400

# nginx combined format; only the bracketed timestamp is parsed.
hb_line() {
	local epoch="$1"
	local ts
	ts="$(TZ=Europe/Moscow date -r "$epoch" '+%d/%b/%Y:%H:%M:%S %z' 2>/dev/null ||
		TZ=Europe/Moscow date -d "@$epoch" '+%d/%b/%Y:%H:%M:%S %z')"
	printf '198.18.1.102 - - [%s] "POST /hb/token HTTP/1.1" 204 0 "-" "Grafana"\n' "$ts"
}

check() {
	local name="$1" expected="$2" actual="$3"
	if [ "$actual" = "$expected" ]; then
		echo "ok   — $name"
	else
		echo "FAIL — $name: expected '$expected', got '$actual'" >&2
		fails=$((fails + 1))
	fi
}

run() { ./heartbeat-watch --log "$log" --state "$state" --now "$1" --simulate; }
dry() { ./heartbeat-watch --log "$log" --state "$state" --now "$1" --dry-run; }

# 1. A heartbeat two minutes old is healthy and says nothing.
hb_line $((now - 120)) > "$log"
check "fresh heartbeat is up" "state=up" "$(run "$now")"

# 2. Sixteen minutes of silence crosses the 15-minute threshold and mails once.
hb_line $((now - 960)) > "$log"
check "stale heartbeat alerts" "state=down send=DOWN" "$(run "$now")"

# 3. Still down five minutes later: no second mail before the repeat interval.
check "no repeat before interval" "state=down send=none" "$(run $((now + 300)))"

# 4. Past the six-hour repeat interval it mails again.
check "repeat after interval" "state=down send=DOWN" "$(run $((now + 21900)))"

# 5. Recovery mails exactly once, then goes quiet.
hb_line $((now + 21900)) > "$log"
check "recovery mails resolved" "state=up send=RESOLVED" "$(run $((now + 21950)))"
check "recovered stays quiet" "state=up" "$(run $((now + 22000)))"

# 6. Right after logrotate the live log is empty and the age lives in .1 —
#    reading only the live file here would invent an outage every night.
hb_line $((now + 22000)) > "$log.1"
: > "$log"
check "falls back to rotated log" "state=up" "$(run $((now + 22100)))"

# 7. Before the very first heartbeat there is nothing to judge, and a fresh
#    install must not mail. Absent logs are silence, not an outage.
rm -f "$log" "$log.1" "$state"
check "no log yet is not an outage" "state=up" "$(run "$now")"

# 8. --dry-run is a diagnostic a human runs by hand; if it advanced the state
#    file it would mark the outage "already notified" and swallow the next
#    real alert. It must print its verdict and change nothing.
hb_line $((now - 960)) > "$log"
printf '{"state": "up", "notified_at": 0}' > "$state"
before="$(cat "$state")"
check "dry-run reports the outage" "state=down send=DOWN" "$(dry "$now")"
check "dry-run leaves state untouched" "$before" "$(cat "$state")"

[ "$fails" -eq 0 ] || { echo "$fails test(s) failed" >&2; exit 1; }
echo "all tests passed"
