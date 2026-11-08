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

# 13. A real run where nothing could be delivered (no SMTP settings, no
#     Telegram) exits non-zero and keeps the state, so the next run retries
#     instead of believing the owner was told.
hb_line $((now - 960)) > "$log"
printf '{"state": "up", "notified_at": 0}' > "$state"
before="$(cat "$state")"
rc=0
env -u SMTP_HOST -u TELEGRAM_BOT_TOKEN ./heartbeat-watch --log "$log" --state "$state" --now "$now" 2>/dev/null || rc=$?
check "undelivered alert exits non-zero" "1" "$rc"
check "undelivered alert keeps state for retry" "$before" "$(cat "$state")"

# 9-12. Delivery across channels, with fake senders (no network). Loads the
#    script as a module; it has no .py suffix, hence SourceFileLoader.
python3 - "$PWD/heartbeat-watch" "$tmp" <<'PY' || fails=$((fails + 1))
import importlib.machinery, importlib.util, os, sys

path, tmp = sys.argv[1], sys.argv[2]
loader = importlib.machinery.SourceFileLoader("hbw", path)
spec = importlib.util.spec_from_loader("hbw", loader)
hbw = importlib.util.module_from_spec(spec)
loader.exec_module(hbw)

bad = 0
def check(name, expected, actual):
    global bad
    if expected == actual:
        print(f"ok   — {name}")
    else:
        print(f"FAIL — {name}: expected {expected!r}, got {actual!r}", file=sys.stderr)
        bad += 1

def ok(kind, age, now): pass
def boom(kind, age, now): raise OSError("unreachable")

# 9. One dead channel must not cost the other its message.
check("both channels delivered", (2, []), hbw.deliver([("mail", ok), ("telegram", ok)], "DOWN", 960, 0))
sent, errors = hbw.deliver([("mail", boom), ("telegram", ok)], "DOWN", 960, 0)
check("telegram still sent when mail fails", (1, ["mail"]), (sent, [e[0] for e in errors]))

# 10. Telegram is off unless its token is configured: mail-only hosts keep working.
for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "TELEGRAM_PROXY", "TELEGRAM_PROXY_USER"):
    os.environ.pop(k, None)
check("telegram off without token", ["mail"], [n for n, _ in hbw.channels()])
os.environ.update(TELEGRAM_BOT_TOKEN="123:abc", TELEGRAM_CHAT_ID="-42",
                  TELEGRAM_PROXY="socks5h://[::1]:31080", TELEGRAM_PROXY_USER='mmv:p"a\\ss')
check("telegram on with token", ["mail", "telegram"], [n for n, _ in hbw.channels()])

# 11. The curl config carries every secret (nothing on argv) with quotes and
#     backslashes escaped, and goes through the SOCKS proxy with remote DNS.
cfg = hbw.telegram_curl_config("DOWN", 960, 0)
check("proxy is socks5h", True, 'proxy = "socks5h://[::1]:31080"' in cfg)
check("proxy password escaped", True, 'proxy-user = "mmv:p\\"a\\\\ss"' in cfg)
check("token only in url", True, 'url = "https://api.telegram.org/bot123:abc/sendMessage"' in cfg)
check("chat id sent", True, 'data-urlencode = "chat_id=-42"' in cfg)
check("text is one config line", True, all(not l.startswith("monitoring") for l in cfg.splitlines()))
check("http errors fail curl", True, "fail" in cfg.splitlines())

check("test message is labelled", True, "test message" in hbw.compose("TEST", None, 0)[0])

# 12. A failing curl surfaces as an exception, so deliver() counts it.
os.environ["HEARTBEAT_CURL"] = "false"
try:
    hbw.send_telegram("DOWN", 960, 0)
    check("curl failure raises", "raised", "returned")
except Exception:
    check("curl failure raises", "raised", "raised")

sys.exit(1 if bad else 0)
PY

[ "$fails" -eq 0 ] || { echo "$fails test(s) failed" >&2; exit 1; }
echo "all tests passed"
