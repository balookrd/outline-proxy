# Uplink Email Alerting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Send email when a fleet uplink degrades, a client stops reporting, or the monitoring host itself dies.

**Architecture:** Grafana 13 unified alerting on `.102` evaluates six rules against VictoriaMetrics and mails through Gmail SMTP; everything is provisioned from files in this repository. A seventh always-firing rule pushes a heartbeat to nginx receivers on `cloud1` and `cloud2`, each of which mails independently if the heartbeat stops — that is the only path that survives the death of `.102`.

**Tech Stack:** Grafana OSS 13.0.2 (docker), VictoriaMetrics (docker), nginx, python3 stdlib (`smtplib`), systemd timers, bash.

Design document: [`docs/superpowers/specs/2026-08-07-uplink-email-alerting-design.md`](../specs/2026-08-07-uplink-email-alerting-design.md).

## Global Constraints

- **Never commit or push without the owner asking.** Every task below ends with a "propose the commit" step: show the diff, state the commit message, wait. This overrides the usual TDD habit of committing automatically.
- **Never restart, reload or reconfigure anything on a production node without explicit per-action approval.** Approval to deploy is not approval to restart. Steps needing it are marked **[NEEDS APPROVAL]**.
- **One node at a time.** `cloud1` is fully deployed and verified before `cloud2` is touched.
- **No secrets in the repository.** Files carry the literal placeholder `__HEARTBEAT_TOKEN__`; the deploy script substitutes it from a host-local file. The Gmail app password is written by the owner, never by an agent, and never echoed into a transcript.
- Fixed values, copied verbatim from the spec and verified on the fleet on 2026-08-07:
  - Grafana datasource UID: `adnsc1wi03doga` (name `prometheus`, type `prometheus`, url `http://198.18.1.102:8428`, is_default).
  - Grafana container: `-p 4000:3000`, `--user 1000:1000`, provisioning bind-mounted from `/opt/grafana/provisioning`, launcher `/opt/grafana/grafana.sh`.
  - Heartbeat receivers: `cloud1.beerloga.su`, `cloud2.beerloga.su`. On both, port 443 belongs to `outline-ss-rust`, which forwards unrecognised HTTPS to nginx on `127.0.0.1:8080` with `proxy_protocol`; the matching server block is in `/etc/nginx/sites-enabled/beerloga.su` with `server_name *.beerloga.su`.
  - Heartbeat staleness threshold: 15 minutes. Watcher interval: 5 minutes. Re-notify interval while down: 6 hours.
- Repository conventions: `ops/**` READMEs are Russian prose, code and code comments are English, shell is `bash` with `set -euo pipefail` and tab indentation, installers are idempotent (see [`ops/watchdog/install.sh`](../../../ops/watchdog/install.sh) as the reference implementation).

## Progress (2026-08-07)

Everything that lives in the repository is written and verified; everything that
touches a production node is not started, because it needs secrets only the owner
can write and approvals only the owner can give.

- **Done:** Task 1 (watcher + 8 passing tests), Task 2 (nginx snippet, units,
  installer, README), Task 6 (contact points, policy tree, deploy script),
  Task 7 (six rules, all expressions replayed against live data),
  Task 8 (dead man's switch rule), and the documentation part of Task 5
  (`ops/grafana/README.md`).
- **Not started:** Task 3 and Task 4 (deploy to `cloud1`/`cloud2`), the
  deployment part of Task 5 (SMTP secret and container re-create), the actual
  `deploy.sh` run, and Task 9 (end-to-end validation).
- **Nothing is committed** — per the global constraint above.

Two deviations from the plan as first written, both found by verification and
already folded into the text below: `ClientRestarted` applies `resets` per series
instead of to a `sum` (the aggregated form also fires when a series appears or
disappears), and it got its own daily-digest route because restarts turned out to
run ~13 per week on `ubuntu`.

---

### Task 1: Heartbeat watcher script and its tests

The watcher is the only piece with real logic, so it is built and tested on its own, offline, before any node is touched. Tests run on the development machine — python3 and bash are all they need.

**Files:**
- Create: `ops/heartbeat/heartbeat-watch`
- Test: `ops/heartbeat/test-heartbeat-watch.sh`

**Interfaces:**
- Produces: an executable `heartbeat-watch` taking `--log PATH`, `--state PATH`, `--threshold SECONDS` (default 900), `--repeat SECONDS` (default 21600), `--now EPOCH` (test hook, defaults to wall clock), `--dry-run` (print the mail decision instead of sending). Exit code is 0 whether or not mail was sent; non-zero only on usage or I/O error. In `--dry-run` it prints exactly one line per run, of the form `state=up`, `state=down send=DOWN`, `state=down send=none`, or `state=up send=RESOLVED`.
- Consumes: `/etc/heartbeat-watch/smtp.env` at runtime for `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`, `MAIL_TO` (read from the process environment, populated by systemd `EnvironmentFile=`). Task 2 installs it; Task 3 fills it in.

- [ ] **Step 1: Write the failing test**

Create `ops/heartbeat/test-heartbeat-watch.sh`:

```bash
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

run() { ./heartbeat-watch --log "$log" --state "$state" --now "$1" --dry-run; }

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

[ "$fails" -eq 0 ] || { echo "$fails test(s) failed" >&2; exit 1; }
echo "all tests passed"
```

Make it executable: `chmod +x ops/heartbeat/test-heartbeat-watch.sh`

- [ ] **Step 2: Run it to verify it fails**

Run: `./ops/heartbeat/test-heartbeat-watch.sh`
Expected: FAIL — `./heartbeat-watch: No such file or directory` (the script does not exist yet).

- [ ] **Step 3: Write the watcher**

Create `ops/heartbeat/heartbeat-watch`:

```python
#!/usr/bin/env python3
#
# heartbeat-watch — mail the owner when the Grafana dead man's switch stops
# reporting. Runs on cloud1/cloud2 from a systemd timer; deliberately uses
# nothing but the standard library, because the whole point of this watcher is
# to keep working when the monitoring host it watches is gone.

import argparse
import email.message
import json
import os
import re
import smtplib
import socket
import ssl
import sys
import time
from datetime import datetime

# nginx combined log: 1.2.3.4 - - [07/Aug/2026:12:00:00 +0300] "POST ..." 204 0
TS_RE = re.compile(r"\[([^\]]+)\]")
TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def last_heartbeat(log_path):
    """Epoch seconds of the most recent heartbeat, or None if there was never one.

    Reads the rotated file as well: logrotate runs nightly, and for the minutes
    between the rotation and the next heartbeat the live log is empty. Judging
    by the live file alone would report an outage every night.
    """
    for path in (log_path, log_path + ".1"):
        try:
            with open(path, "rb") as fh:
                lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        except FileNotFoundError:
            continue
        if not lines:
            continue
        match = TS_RE.search(lines[-1].decode("utf-8", "replace"))
        if not match:
            continue
        try:
            return int(datetime.strptime(match.group(1), TS_FMT).timestamp())
        except ValueError:
            continue
    return None


def load_state(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError):
        return {"state": "up", "notified_at": 0}


def save_state(path, state):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, path)


def send_mail(kind, age, now):
    """Send through the same Gmail account Grafana uses. Raises on failure."""
    host = os.environ["SMTP_HOST"]
    user = os.environ["SMTP_USER"]
    password = os.environ["SMTP_PASSWORD"]
    to = os.environ["MAIL_TO"]
    observer = socket.gethostname()
    stamp = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(now))

    msg = email.message.EmailMessage()
    msg["From"] = user
    msg["To"] = to
    if kind == "DOWN":
        msg["Subject"] = f"[{observer}] outline: no heartbeat from .102"
        body = (
            f"No heartbeat from the Grafana dead man's switch on .102.\n\n"
            f"Observer:      {observer}\n"
            f"Last heartbeat: {'never' if age is None else str(int(age)) + ' seconds ago'}\n"
            f"Checked at:    {stamp}\n\n"
            f"Mail from only one observer usually means the path to that observer\n"
            f"is broken. Mail from both cloud1 and cloud2 means .102 itself is down.\n"
        )
    else:
        msg["Subject"] = f"[{observer}] outline: heartbeat from .102 resumed"
        body = f"Heartbeat resumed.\n\nObserver: {observer}\nAt:       {stamp}\n"
    msg.set_content(body)

    with smtplib.SMTP(host.split(":")[0], int(host.split(":")[1]), timeout=30) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        smtp.login(user, password)
        smtp.send_message(msg)


def main():
    ap = argparse.ArgumentParser(description="alert when the heartbeat stops")
    ap.add_argument("--log", default="/var/log/nginx/heartbeat.log")
    ap.add_argument("--state", default="/var/lib/heartbeat-watch/state.json")
    ap.add_argument("--threshold", type=int, default=900)
    ap.add_argument("--repeat", type=int, default=21600)
    ap.add_argument("--now", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    now = args.now if args.now is not None else int(time.time())
    last = last_heartbeat(args.log)
    state = load_state(args.state)

    # No log at all means the receiver has never been hit — a fresh install,
    # not an outage. Staying quiet here is what keeps the first deploy silent.
    down = last is not None and (now - last) > args.threshold
    age = None if last is None else now - last

    send = None
    if down and state["state"] != "down":
        send = "DOWN"
    elif down and (now - state.get("notified_at", 0)) >= args.repeat:
        send = "DOWN"
    elif not down and state["state"] == "down":
        send = "RESOLVED"

    if args.dry_run:
        label = "down" if down else "up"
        suffix = f" send={send or 'none'}" if (down or send) else ""
        print(f"state={label}{suffix}")
    elif send:
        send_mail(send, age, now)

    if send == "DOWN":
        state = {"state": "down", "notified_at": now}
    elif down:
        state["state"] = "down"
    else:
        state = {"state": "up", "notified_at": 0}
    save_state(args.state, state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Make it executable: `chmod +x ops/heartbeat/heartbeat-watch`

- [ ] **Step 4: Run the tests to verify they pass**

Run: `./ops/heartbeat/test-heartbeat-watch.sh`
Expected: seven `ok — ...` lines and `all tests passed`, exit 0.

If test 3 fails with `send=DOWN` instead of `send=none`, the repeat-interval branch is comparing against the wrong timestamp — `notified_at` must be the time mail was *sent*, not the time of the last run.

- [ ] **Step 5: Propose the commit**

Show the diff and propose, without running it until the owner asks:

```bash
git add ops/heartbeat/heartbeat-watch ops/heartbeat/test-heartbeat-watch.sh && git commit -m "feat(ops): add heartbeat watcher for the alerting dead man's switch"
```

---

### Task 2: Heartbeat receiver packaging (nginx snippet, units, installer)

Everything a cloud node needs, still without touching one.

**Files:**
- Create: `ops/heartbeat/nginx-heartbeat.conf`
- Create: `ops/heartbeat/heartbeat-watch.service`
- Create: `ops/heartbeat/heartbeat-watch.timer`
- Create: `ops/heartbeat/install.sh`
- Create: `ops/heartbeat/README.md`

**Interfaces:**
- Consumes: `heartbeat-watch` from Task 1.
- Produces: `install.sh`, run as root from a copy of this directory on the target node. It requires `/etc/heartbeat-watch/token` to exist (one line, the shared heartbeat token) and refuses to run without it. It installs the watcher to `/usr/local/sbin/heartbeat-watch`, the units, and `/etc/nginx/snippets/heartbeat.conf` with the token substituted, then adds a single `include snippets/heartbeat.conf;` line to the `*.beerloga.su` server block if absent. It validates with `nginx -t` and **stops before reloading nginx**, printing the command for the owner to approve.

- [ ] **Step 1: Write the nginx snippet**

Create `ops/heartbeat/nginx-heartbeat.conf`:

```nginx
# Heartbeat receiver for the Grafana dead man's switch on .102.
#
# Included from the *.beerloga.su server block on 127.0.0.1:8080 — the one
# outline-ss-rust forwards unrecognised HTTPS traffic to. That is why this needs
# no listener, no certificate and no new port of its own: it inherits the TLS
# front the node already presents on 443.
#
# The token is substituted by install.sh from /etc/heartbeat-watch/token. The
# file in the repository keeps the placeholder, so the token never lands in git.
location = /hb/__HEARTBEAT_TOKEN__ {
	access_log /var/log/nginx/heartbeat.log combined;
	return 204;
}
```

- [ ] **Step 2: Write the systemd units**

Create `ops/heartbeat/heartbeat-watch.service`:

```ini
[Unit]
Description=Alert by mail when the Grafana heartbeat from .102 stops
Documentation=file:/usr/local/share/heartbeat-watch/README.md

[Service]
Type=oneshot
EnvironmentFile=/etc/heartbeat-watch/smtp.env
ExecStart=/usr/local/sbin/heartbeat-watch
# The watcher reads an nginx log and writes one small state file. Nothing else
# on this host is its business.
ProtectSystem=strict
ReadWritePaths=/var/lib/heartbeat-watch
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
```

Create `ops/heartbeat/heartbeat-watch.timer`:

```ini
[Unit]
Description=Check the .102 heartbeat every five minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
```

- [ ] **Step 3: Write the installer**

Create `ops/heartbeat/install.sh`:

```bash
#!/usr/bin/env bash
#
# install.sh — install the heartbeat receiver on a cloud node. Idempotent.
# Copy this directory to the node and run: sudo ./install.sh
#
# Deliberately stops short of reloading nginx: this node terminates production
# traffic, and reloading it is the owner's call, not the installer's.

set -euo pipefail
cd "$(dirname "$0")"

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }

site=/etc/nginx/sites-enabled/beerloga.su
token_file=/etc/heartbeat-watch/token

[ -s "$token_file" ] || {
	echo "missing $token_file — write the shared heartbeat token there first" >&2
	echo "  (same token as the Grafana webhook URL; mode 0600, root-owned)" >&2
	exit 1
}
[ -f "$site" ] || { echo "no $site on this host — wrong node?" >&2; exit 1; }

token="$(tr -d '\n' < "$token_file")"
case "$token" in
	*[!A-Za-z0-9_-]*) echo "token has characters that do not belong in a URL path" >&2; exit 1 ;;
esac

echo "==> installing watcher + units"
install -D -m 0755 heartbeat-watch          /usr/local/sbin/heartbeat-watch
install -D -m 0644 heartbeat-watch.service  /etc/systemd/system/heartbeat-watch.service
install -D -m 0644 heartbeat-watch.timer    /etc/systemd/system/heartbeat-watch.timer
install -D -m 0644 README.md                /usr/local/share/heartbeat-watch/README.md
install -d -m 0755                          /var/lib/heartbeat-watch

echo "==> installing nginx snippet"
sed "s|__HEARTBEAT_TOKEN__|$token|" nginx-heartbeat.conf > /etc/nginx/snippets/heartbeat.conf
chmod 0644 /etc/nginx/snippets/heartbeat.conf

if grep -q 'snippets/heartbeat.conf' "$site"; then
	echo "==> $site already includes the snippet"
else
	echo "==> adding the include to $site"
	cp -p "$site" "$site.bak.$(date +%Y%m%d%H%M%S)"
	# Anchor on the listen line, not on server_name: the file opens with a
	# commented-out :80 block carrying the same server_name, and appending after
	# the first match would drop the include outside any server block.
	python3 - "$site" <<-'PY'
		import sys

		path = sys.argv[1]
		anchor = "listen 127.0.0.1:8080 proxy_protocol;"
		src = open(path, encoding="utf-8").read()

		if src.count(anchor) != 1:
		    sys.exit(f"expected exactly one {anchor!r} in {path}, found {src.count(anchor)}")

		src = src.replace(anchor, anchor + "\n\n    include snippets/heartbeat.conf;", 1)
		open(path, "w", encoding="utf-8").write(src)
	PY
fi

echo "==> checking the nginx configuration"
if ! nginx -t; then
	echo "nginx -t failed — the include was NOT activated; fix or restore from the .bak" >&2
	exit 1
fi

systemctl daemon-reload
systemctl enable --now heartbeat-watch.timer

cat <<'EOF'

==> installed. Two things remain, both for the owner:

  1. Write /etc/heartbeat-watch/smtp.env (mode 0600, root) with:
         SMTP_HOST=smtp.gmail.com:587
         SMTP_USER=<the gmail address>
         SMTP_PASSWORD=<the 16-character app password>
         MAIL_TO=<the recipient>

  2. Activate the nginx include — this reloads production nginx:
         sudo systemctl reload nginx
EOF
```

Make it executable: `chmod +x ops/heartbeat/install.sh`

- [ ] **Step 4: Verify the installer refuses to run without a token**

Run on the development machine (it must fail before touching anything):

```bash
bash -n ops/heartbeat/install.sh && echo "syntax ok"
```

Expected: `syntax ok`. Then confirm the guard order by reading the script: the `id -u` check comes first, the token check second, the site check third — no `install` command runs before all three pass.

- [ ] **Step 5: Write the README**

Create `ops/heartbeat/README.md` (Russian prose, per repository convention), covering: зачем нужен (Grafana не может сообщить о собственной смерти), как устроена цепочка `.102 → nginx → лог → watcher → письмо`, почему наблюдателей два и как читать письмо от одного против письма от обоих, где лежат секреты, и как проверить вручную (`curl -sS -o /dev/null -w '%{http_code}\n' https://cloud1.beerloga.su/hb/<token>` → `204`).

- [ ] **Step 6: Propose the commit**

```bash
git add ops/heartbeat && git commit -m "feat(ops): package the heartbeat receiver for cloud nodes"
```

---

### Task 3: Deploy the heartbeat receiver to cloud1

First production node. Nothing here is reversible by itself, so each step is verified before the next.

**Files:**
- Modify (on the node): `/etc/nginx/sites-enabled/beerloga.su`, `/etc/nginx/snippets/heartbeat.conf`

- [ ] **Step 1: Owner writes the secrets on cloud1**

Ask the owner to run these two commands themselves (the agent must not see the password):

```bash
ssh sysadm@cloud1.beerloga.su 'sudo install -d -m 0700 /etc/heartbeat-watch && printf "%s" "PASTE_TOKEN_HERE" | sudo tee /etc/heartbeat-watch/token >/dev/null && sudo chmod 0600 /etc/heartbeat-watch/token'
```

```bash
ssh sysadm@cloud1.beerloga.su 'sudo tee /etc/heartbeat-watch/smtp.env >/dev/null <<EOF
SMTP_HOST=smtp.gmail.com:587
SMTP_USER=maxim.malykhin@gmail.com
SMTP_PASSWORD=PASTE_APP_PASSWORD_HERE
MAIL_TO=maxim.malykhin@gmail.com
EOF
sudo chmod 0600 /etc/heartbeat-watch/smtp.env'
```

The token is a shared secret invented once for this deployment — 32 URL-safe characters, generated by the owner with `openssl rand -base64 24 | tr -d "=+/"`. The same value goes on `cloud2` and into the Grafana webhook URLs in Task 8.

- [ ] **Step 2: Copy the directory and run the installer**

```bash
rsync -a --delete ops/heartbeat/ sysadm@cloud1.beerloga.su:/tmp/heartbeat/ && ssh sysadm@cloud1.beerloga.su 'cd /tmp/heartbeat && sudo ./install.sh'
```

Expected: `==> installing watcher + units`, `==> adding the include to /etc/nginx/sites-enabled/beerloga.su`, `nginx: configuration file /etc/nginx/nginx.conf test is successful`, then the two-item reminder. The timer is enabled but the receiver is not live yet — nginx has not reloaded.

- [ ] **Step 3: [NEEDS APPROVAL] Reload nginx on cloud1**

Ask the owner explicitly: this reloads nginx on a node terminating production traffic. `reload` is graceful (workers finish in flight requests), and `nginx -t` already passed, but it is still a production action.

```bash
ssh sysadm@cloud1.beerloga.su 'sudo systemctl reload nginx'
```

- [ ] **Step 4: Verify the receiver answers and logs**

```bash
ssh sysadm@cloud1.beerloga.su 'curl -sS -o /dev/null -w "%{http_code}\n" https://cloud1.beerloga.su/hb/$(sudo cat /etc/heartbeat-watch/token) && sudo tail -1 /var/log/nginx/heartbeat.log'
```

Expected: `204`, then one combined-format log line ending in `204 0 "-" "curl/..."`. A `404` means the include did not land in the right server block; a `200` with HTML means the request reached the default site instead.

- [ ] **Step 5: Verify the watcher reads it as healthy**

```bash
ssh sysadm@cloud1.beerloga.su 'sudo /usr/local/sbin/heartbeat-watch --dry-run'
```

Expected: `state=up`. This proves the log path, the timestamp parsing and the state file all agree on a real nginx log — the tests in Task 1 used a synthetic one.

- [ ] **Step 6: Verify the timer is scheduled**

```bash
ssh sysadm@cloud1.beerloga.su 'systemctl list-timers heartbeat-watch.timer --no-pager'
```

Expected: one row with a NEXT time within five minutes.

Note: from now until Task 8 lands, the heartbeat is only fed by hand. The watcher will therefore start reporting `state=down` after 15 minutes and, once `smtp.env` is filled in, will mail. That is correct behaviour on a receiver whose sender does not exist yet — either accept the mail as expected noise, or keep `smtp.env` unwritten until Task 8, which makes the watcher fail loudly in the journal instead of mailing. Choose one and tell the owner which.

---

### Task 4: Deploy the heartbeat receiver to cloud2

Identical to Task 3, on the second node, only after `cloud1` is verified. Repeated in full rather than referenced, because the deploy may be executed out of order or by someone reading only this task.

- [ ] **Step 1: Owner writes the secrets on cloud2**

```bash
ssh sysadm@cloud2.beerloga.su 'sudo install -d -m 0700 /etc/heartbeat-watch && printf "%s" "PASTE_SAME_TOKEN_HERE" | sudo tee /etc/heartbeat-watch/token >/dev/null && sudo chmod 0600 /etc/heartbeat-watch/token'
```

```bash
ssh sysadm@cloud2.beerloga.su 'sudo tee /etc/heartbeat-watch/smtp.env >/dev/null <<EOF
SMTP_HOST=smtp.gmail.com:587
SMTP_USER=maxim.malykhin@gmail.com
SMTP_PASSWORD=PASTE_APP_PASSWORD_HERE
MAIL_TO=maxim.malykhin@gmail.com
EOF
sudo chmod 0600 /etc/heartbeat-watch/smtp.env'
```

The token must be byte-identical to the one on `cloud1` — one webhook URL path serves both.

- [ ] **Step 2: Copy the directory and run the installer**

```bash
rsync -a --delete ops/heartbeat/ sysadm@cloud2.beerloga.su:/tmp/heartbeat/ && ssh sysadm@cloud2.beerloga.su 'cd /tmp/heartbeat && sudo ./install.sh'
```

Expected: same output as on `cloud1`, ending with `nginx: configuration file ... test is successful`.

- [ ] **Step 3: [NEEDS APPROVAL] Reload nginx on cloud2**

```bash
ssh sysadm@cloud2.beerloga.su 'sudo systemctl reload nginx'
```

- [ ] **Step 4: Verify the receiver and the watcher**

```bash
ssh sysadm@cloud2.beerloga.su 'curl -sS -o /dev/null -w "%{http_code}\n" https://cloud2.beerloga.su/hb/$(sudo cat /etc/heartbeat-watch/token) && sudo /usr/local/sbin/heartbeat-watch --dry-run'
```

Expected: `204` then `state=up`.

---

### Task 5: SMTP for Grafana

The only task that restarts a container. It comes before any alert rule so that the very first rule to fire already has a working mail path.

**Files:**
- Modify (on `.102`): `/opt/grafana/grafana.sh`
- Create (on `.102`): `/opt/grafana/secrets/smtp`
- Modify: `ops/grafana/README.md`

- [ ] **Step 1: Owner writes the app password on .102**

Ask the owner to run this themselves, with their own 16-character Gmail app password:

```bash
ssh mmv@198.18.1.102 'sudo install -d -m 0700 -o 1000 -g 1000 /opt/grafana/secrets && printf "%s" "PASTE_APP_PASSWORD_HERE" | sudo tee /opt/grafana/secrets/smtp >/dev/null && sudo chmod 0600 /opt/grafana/secrets/smtp && sudo chown 1000:1000 /opt/grafana/secrets/smtp'
```

`printf` without `\n` is deliberate: a trailing newline would become part of the password. Owner `1000:1000` matches the container user.

- [ ] **Step 2: Verify the file before restarting anything**

```bash
ssh mmv@198.18.1.102 'sudo stat -c "%n %a %U:%G %s bytes" /opt/grafana/secrets/smtp'
```

Expected: `... 600 ...:... 16 bytes`. Exactly 16 bytes — 17 means a newline slipped in and SMTP auth will fail with a misleading "username and password not accepted".

- [ ] **Step 3: Edit the launcher**

On `.102`, add to `/opt/grafana/grafana.sh`, inside the `docker run` invocation, after the existing `-v /opt/grafana/provisioning:...` line:

```bash
   -v /opt/grafana/secrets:/etc/grafana/secrets:ro \
   -e GF_SMTP_ENABLED=true \
   -e GF_SMTP_HOST=smtp.gmail.com:587 \
   -e GF_SMTP_USER=maxim.malykhin@gmail.com \
   -e GF_SMTP_PASSWORD__FILE=/etc/grafana/secrets/smtp \
   -e GF_SMTP_FROM_ADDRESS=maxim.malykhin@gmail.com \
   -e GF_SMTP_FROM_NAME="outline alerting" \
```

Keep a copy of the previous launcher first — the directory already holds `grafana.sh.bak.20260805105505`, so follow that convention:

```bash
ssh mmv@198.18.1.102 'sudo cp -p /opt/grafana/grafana.sh /opt/grafana/grafana.sh.bak.$(date +%Y%m%d%H%M%S)'
```

- [ ] **Step 4: [NEEDS APPROVAL] Re-create the Grafana container**

`grafana.sh` pulls, stops, removes and re-runs the container, so this is a full restart of Grafana — dashboards are unavailable for a few seconds. It also pulls `grafana/grafana-oss:latest`, which may bring a **new Grafana version**; say so when asking, and check the version afterwards.

```bash
ssh mmv@198.18.1.102 'sudo sh /opt/grafana/grafana.sh'
```

- [ ] **Step 5: Verify Grafana came back with SMTP enabled**

```bash
ssh mmv@198.18.1.102 'sudo docker exec grafana grafana server -v; sudo docker logs grafana 2>&1 | tail -20; curl -s -o /dev/null -w "grafana http=%{http_code}\n" http://127.0.0.1:4000/login'
```

Expected: a version line (note it — compare against 13.0.2), no `smtp` errors in the log, `grafana http=200`.

- [ ] **Step 6: Owner sends a test mail**

In the Grafana UI (`http://198.18.1.102:4000` → Alerting → Contact points), the owner opens the default contact point and clicks **Test**. Expected: a mail arrives. A failure here is an SMTP problem — wrong app password, or a trailing newline in the secret file — and must be fixed before Task 6.

- [ ] **Step 7: Document and propose the commit**

Extend `ops/grafana/README.md` (create it if absent, Russian prose) with the SMTP section: which env vars the launcher carries, why the password lives in a file rather than an env value, the exact `printf`-without-newline requirement, and the 16-byte check.

```bash
git add ops/grafana/README.md && git commit -m "docs(ops): document the Grafana SMTP setup for alerting"
```

---

### Task 6: Contact points and notification policy

**Files:**
- Create: `ops/grafana/alerting/contact-points.yaml`
- Create: `ops/grafana/alerting/policies.yaml`
- Create: `ops/grafana/alerting/deploy.sh`

**Interfaces:**
- Produces: contact points named `email-owner` and `heartbeat-observers`; the notification policy tree routing everything to `email-owner` except `alertname = DeadMansSwitch`. Tasks 7 and 8 reference those names.
- Produces: `deploy.sh`, run from the development machine, which substitutes `__HEARTBEAT_TOKEN__` from a local file and copies the alerting YAML to `.102`.

- [ ] **Step 1: Write the contact points**

Create `ops/grafana/alerting/contact-points.yaml`:

```yaml
# Grafana contact points, provisioned from file.
#
# Deployed to /opt/grafana/provisioning/alerting/ by deploy.sh, which
# substitutes __HEARTBEAT_TOKEN__ from a host-local file so the token stays out
# of git. The SMTP credentials are not here: they are container environment
# (see ops/grafana/README.md).
apiVersion: 1

contactPoints:
  - orgId: 1
    name: email-owner
    receivers:
      - uid: email-owner-1
        type: email
        settings:
          addresses: maxim.malykhin@gmail.com
          # One mail per alert group rather than one per alert — grouping is
          # what keeps a fleet-wide event from arriving as six messages.
          singleEmail: true

  - orgId: 1
    name: heartbeat-observers
    receivers:
      # Two independent observers. One of them mailing means that observer's
      # path is probably broken; both mailing means .102 is genuinely down.
      - uid: heartbeat-cloud1
        type: webhook
        settings:
          url: https://cloud1.beerloga.su/hb/__HEARTBEAT_TOKEN__
          httpMethod: POST
        disableResolveMessage: true
      - uid: heartbeat-cloud2
        type: webhook
        settings:
          url: https://cloud2.beerloga.su/hb/__HEARTBEAT_TOKEN__
          httpMethod: POST
        disableResolveMessage: true
```

- [ ] **Step 2: Write the notification policy**

Create `ops/grafana/alerting/policies.yaml`:

```yaml
# Grafana notification policy tree, provisioned from file.
apiVersion: 1

policies:
  - orgId: 1
    receiver: email-owner
    group_by: [alertname, instance]
    group_wait: 30s
    group_interval: 5m
    # Twelve hours, not five minutes: an ongoing problem should be one mail a
    # day, not a stream. The fleet has taught us that a burst right after a
    # restart is not a regression — long `for` durations and a long repeat are
    # both part of not crying wolf.
    repeat_interval: 12h
    routes:
      # The dead man's switch is not a notification — it is a pulse. It leaves
      # the tree immediately and never reaches the mail contact point.
      - receiver: heartbeat-observers
        object_matchers:
          - [alertname, =, DeadMansSwitch]
        group_wait: 0s
        group_interval: 1m
        repeat_interval: 5m

      # Client restarts are frequent — measured on 2026-08-07, roughly 13 per
      # week on ubuntu and 12 on debian. Under the default route that would be
      # a mail most days. Collapsing the whole fleet into one group with a
      # daily repeat turns it into a digest, which is all an info-level signal
      # deserves.
      - receiver: email-owner
        object_matchers:
          - [alertname, =, ClientRestarted]
        group_by: [alertname]
        group_wait: 5m
        group_interval: 30m
        repeat_interval: 24h
```

- [ ] **Step 3: Write the deploy script**

Create `ops/grafana/alerting/deploy.sh`:

```bash
#!/usr/bin/env bash
#
# deploy.sh — push the Grafana alerting provisioning to the gateway.
# Run from the development machine: ./deploy.sh
#
# Copying is not enough: alerting provisioning runs once at startup, so Grafana
# must be restarted afterwards. Dashboards have a poller; alerting does not.

set -euo pipefail
cd "$(dirname "$0")"

host=${GRAFANA_HOST:-mmv@198.18.1.102}
token_file=${HEARTBEAT_TOKEN_FILE:-$HOME/.config/outline/heartbeat-token}
dest=/opt/grafana/provisioning/alerting

[ -s "$token_file" ] || {
	echo "missing $token_file — put the shared heartbeat token there (mode 0600)" >&2
	exit 1
}
token="$(tr -d '\n' < "$token_file")"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for f in rules.yaml contact-points.yaml policies.yaml; do
	[ -f "$f" ] || { echo "missing $f" >&2; exit 1; }
	sed "s|__HEARTBEAT_TOKEN__|$token|g" "$f" > "$tmp/$f"
done

# A YAML syntax error would otherwise surface only as a silent no-op in the
# Grafana log, hours later, with the old rules still in force. PyYAML is present
# on the gateway but not on every development machine, so fall back to ruby's
# psych, which ships with the macOS system ruby.
if python3 -c 'import yaml' 2>/dev/null; then
	python3 -c "
import sys, yaml
for p in sys.argv[1:]:
    yaml.safe_load(open(p))
print('yaml ok (pyyaml)')
" "$tmp"/*.yaml
elif command -v ruby >/dev/null; then
	# safe_load(File.read) rather than safe_load_file: the system ruby on macOS
	# ships a psych old enough to lack the latter.
	ruby -ryaml -e 'ARGV.each { |p| YAML.safe_load(File.read(p)) }; puts "yaml ok (psych)"' "$tmp"/*.yaml
else
	echo "no YAML parser available (pyyaml or ruby) — refusing to deploy unchecked" >&2
	exit 1
fi

echo "==> copying to $host:$dest"
scp -q "$tmp"/*.yaml "$host:/tmp/"
# shellcheck disable=SC2029  # $dest is ours, not the remote shell's
ssh "$host" "sudo install -D -m 0640 -o 1000 -g 1000 /tmp/rules.yaml $dest/rules.yaml && sudo install -D -m 0640 -o 1000 -g 1000 /tmp/contact-points.yaml $dest/contact-points.yaml && sudo install -D -m 0640 -o 1000 -g 1000 /tmp/policies.yaml $dest/policies.yaml && rm -f /tmp/rules.yaml /tmp/contact-points.yaml /tmp/policies.yaml"

echo "==> done. Grafana picks the files up within its provisioning poll; check with:"
echo "    ssh $host 'sudo docker logs --since 2m grafana 2>&1 | grep -i provision'"
```

Make it executable: `chmod +x ops/grafana/alerting/deploy.sh`

Note: `deploy.sh` requires `rules.yaml`, which Task 7 creates. Until then it exits with `missing rules.yaml` — deliberately, so a half-finished provisioning set is never deployed.

- [ ] **Step 4: Verify the YAML parses and the placeholder is present**

```bash
python3 -c "import yaml,sys; [yaml.safe_load(open(p)) for p in sys.argv[1:]]; print('yaml ok')" ops/grafana/alerting/contact-points.yaml ops/grafana/alerting/policies.yaml && grep -c '__HEARTBEAT_TOKEN__' ops/grafana/alerting/contact-points.yaml
```

Expected: `yaml ok` then `2` — one placeholder per observer, and no real token anywhere in the repository.

- [ ] **Step 5: Propose the commit**

```bash
git add ops/grafana/alerting && git commit -m "feat(ops): provision Grafana contact points and notification policy"
```

---

### Task 7: The six alert rules

**Files:**
- Create: `ops/grafana/alerting/rules.yaml`

**Interfaces:**
- Consumes: datasource UID `adnsc1wi03doga`; contact point `email-owner` via the default policy from Task 6.
- Produces: rule group `uplink` in folder `Alerts`, with rule UIDs `uplink-target-down`, `uplink-all-down`, `uplink-loss-high`, `uplink-failover-storm`, `uplink-cert-expiring`, `uplink-client-restarted`. Task 8 adds a seventh rule to a separate group in the same file.

Every rule uses the same two-node shape: refId `A` is an instant PromQL query returning **1 when there is a problem and 0 otherwise** (that is what the `bool` modifier is for), and refId `C` is a threshold expression firing above 0. Writing the comparison in PromQL rather than in the threshold node keeps the alerting condition readable as a single line and identical to what can be pasted into the VictoriaMetrics UI.

- [ ] **Step 1: Verify every rule expression against real data first**

Before writing YAML, confirm each expression returns what the rule assumes. Run against the live database:

```bash
ssh mmv@198.18.1.102 'for q in "up{job=~\"rust-ws-exporter|rust-ss-exporter\"} < bool 1" "sum by (instance) (outline_ws_uplink_health_effective) < bool 1" "outline_ws_uplink_carrier_loss_ratio > bool 0.05" "sum by (instance) (increase(outline_ws_uplink_failovers_total{job=\"rust-ws-exporter\"}[15m])) > bool 30" "(outline_ws_uplink_cert_expiry_timestamp_seconds - time()) / 86400 < bool 14" "resets(sum by (instance) (outline_ws_uplink_selected_total)[1h:1m]) > bool 0"; do echo "-- $q"; curl -sG http://127.0.0.1:8428/api/v1/query --data-urlencode "query=$q" | jq -r "[.data.result[].value[1]] | \"values: \" + (unique | join(\",\"))"; done'
```

Expected: every line reads `values: 0` (nothing is wrong right now), possibly with a `1` on `resets` if a client restarted within the hour. A line reading `values: ` (empty) means the expression returned no series at all — that rule would be permanently NoData and must be fixed before going further.

- [ ] **Step 2: Write the rules**

Create `ops/grafana/alerting/rules.yaml`:

```yaml
# Grafana alert rules, provisioned from file.
#
# Thresholds come from replaying seven days of fleet data, not from taste; the
# reasoning for each number is in
# docs/superpowers/specs/2026-08-07-uplink-email-alerting-design.md.
#
# Every rule's query A returns 1 on a problem and 0 otherwise (the `bool`
# modifier), and condition C fires above 0.
#
# noDataState and execErrState are OK everywhere on purpose: a dead
# VictoriaMetrics would otherwise turn every rule into its own alert, and that
# failure is already covered — the dead man's switch queries the datasource too,
# so it goes silent and both observers mail.
apiVersion: 1

groups:
  - orgId: 1
    name: uplink
    folder: Alerts
    interval: 1m
    rules:
      - uid: uplink-target-down
        title: TargetDown
        condition: C
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: '{{ $labels.instance }} ({{ $labels.job }}) stopped reporting'
          description: >-
            No successful scrape for five minutes. Either the process is gone or
            the path to it is. Five minutes is above every ordinary scrape gap
            seen in the last week (1-7 minutes) and below the real outages.
        noDataState: OK
        execErrState: OK
        data:
          - refId: A
            relativeTimeRange: {from: 600, to: 0}
            datasourceUid: adnsc1wi03doga
            model:
              refId: A
              editorMode: code
              instant: true
              expr: 'up{job=~"rust-ws-exporter|rust-ss-exporter"} < bool 1'
          - refId: C
            datasourceUid: __expr__
            model:
              refId: C
              type: threshold
              expression: A
              conditions:
                - evaluator: {type: gt, params: [0]}

      - uid: uplink-all-down
        title: AllUplinksDown
        condition: C
        for: 3m
        labels:
          severity: critical
        annotations:
          summary: '{{ $labels.instance }} has no healthy uplink at all'
          description: >-
            Every leg on this client is unhealthy — no tunnel. Baseline is 12
            healthy legs on cloud1/cloud2 and 4 on debian/ubuntu, so zero is
            unambiguous.
        noDataState: OK
        execErrState: OK
        data:
          - refId: A
            relativeTimeRange: {from: 600, to: 0}
            datasourceUid: adnsc1wi03doga
            model:
              refId: A
              editorMode: code
              instant: true
              expr: 'sum by (instance) (outline_ws_uplink_health_effective) < bool 1'
          - refId: C
            datasourceUid: __expr__
            model:
              refId: C
              type: threshold
              expression: A
              conditions:
                - evaluator: {type: gt, params: [0]}

      - uid: uplink-loss-high
        title: UplinkCarrierLossHigh
        condition: C
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: '{{ $labels.uplink }}/{{ $labels.transport }} on {{ $labels.instance }} is losing packets'
          description: >-
            Carrier loss above 5% for ten minutes. The threshold matches the
            loss-failover threshold already calibrated on .102 and .104; the
            ten-minute sustain is what separates this from the spikes that reach
            42% for a single sample.
        noDataState: OK
        execErrState: OK
        data:
          - refId: A
            relativeTimeRange: {from: 900, to: 0}
            datasourceUid: adnsc1wi03doga
            model:
              refId: A
              editorMode: code
              instant: true
              expr: 'outline_ws_uplink_carrier_loss_ratio > bool 0.05'
          - refId: C
            datasourceUid: __expr__
            model:
              refId: C
              type: threshold
              expression: A
              conditions:
                - evaluator: {type: gt, params: [0]}

      - uid: uplink-failover-storm
        title: UplinkFailoverStorm
        condition: C
        for: 0s
        labels:
          severity: warning
        annotations:
          summary: '{{ $labels.instance }} is churning through uplinks'
          description: >-
            More than 30 failovers in 15 minutes. Peaks over the last week were
            63 (debian), 50 (cloud1), 28 (ubuntu) and 24 (cloud2); at a threshold
            of 10 this rule would have been true for over half the week on two
            nodes. No `for` is needed — the 15-minute window is the sustain.
        noDataState: OK
        execErrState: OK
        data:
          - refId: A
            relativeTimeRange: {from: 1800, to: 0}
            datasourceUid: adnsc1wi03doga
            model:
              refId: A
              editorMode: code
              instant: true
              expr: 'sum by (instance) (increase(outline_ws_uplink_failovers_total{job="rust-ws-exporter"}[15m])) > bool 30'
          - refId: C
            datasourceUid: __expr__
            model:
              refId: C
              type: threshold
              expression: A
              conditions:
                - evaluator: {type: gt, params: [0]}

      - uid: uplink-cert-expiring
        title: UplinkCertExpiringSoon
        condition: C
        for: 1h
        labels:
          severity: info
        annotations:
          summary: 'certificate for {{ $labels.uplink }} expires in under 14 days'
          description: >-
            Seen from {{ $labels.instance }}. The nearest expiry on 2026-08-07
            was 49 days out, so this stays silent until it matters.
        noDataState: OK
        execErrState: OK
        data:
          - refId: A
            relativeTimeRange: {from: 3900, to: 0}
            datasourceUid: adnsc1wi03doga
            model:
              refId: A
              editorMode: code
              instant: true
              expr: '(outline_ws_uplink_cert_expiry_timestamp_seconds - time()) / 86400 < bool 14'
          - refId: C
            datasourceUid: __expr__
            model:
              refId: C
              type: threshold
              expression: A
              conditions:
                - evaluator: {type: gt, params: [0]}

      - uid: uplink-client-restarted
        title: ClientRestarted
        condition: C
        for: 0s
        labels:
          severity: info
        annotations:
          summary: 'outline-ws-rust restarted on {{ $labels.instance }}'
          description: >-
            Detected as a counter reset: the client exports no
            process_start_time_seconds, so a restart shows up as
            outline_ws_uplink_selected_total going backwards. `resets` is applied
            per series and only then aggregated — on a `sum` the same expression
            would also fire whenever a series appears or disappears, which is not
            a restart. Frequent by nature (~13 per week on ubuntu), so its own
            notification route collapses it into a daily digest.
        noDataState: OK
        execErrState: OK
        data:
          - refId: A
            relativeTimeRange: {from: 3900, to: 0}
            datasourceUid: adnsc1wi03doga
            model:
              refId: A
              editorMode: code
              instant: true
              expr: 'max by (instance) (resets(outline_ws_uplink_selected_total[1h])) > bool 0'
          - refId: C
            datasourceUid: __expr__
            model:
              refId: C
              type: threshold
              expression: A
              conditions:
                - evaluator: {type: gt, params: [0]}
```

- [ ] **Step 3: Verify the YAML parses**

```bash
python3 -c "import yaml; d=yaml.safe_load(open('ops/grafana/alerting/rules.yaml')); print('rules:', sum(len(g['rules']) for g in d['groups']))"
```

Expected: `rules: 6`.

- [ ] **Step 4: Deploy**

```bash
./ops/grafana/alerting/deploy.sh
```

Expected: `yaml ok`, `==> copying to ...`, `==> done.`

- [ ] **Step 5: Verify Grafana accepted them**

```bash
ssh mmv@198.18.1.102 'sudo docker logs --since 3m grafana 2>&1 | grep -iE "provision|alert" | tail -20'
```

Expected: provisioning lines, no `error`. A `failed to provision alerting` line names the offending rule — fix the file and re-run `deploy.sh`; no restart needed.

Then confirm in the database that six rules exist:

```bash
ssh mmv@198.18.1.102 'sudo python3 -c "
import sqlite3
c=sqlite3.connect(\"file:/opt/grafana/data/grafana.db?mode=ro\",uri=True)
for r in c.execute(\"select uid,title from alert_rule order by uid\"):
    print(\"|\".join(r))
"'
```

Expected: the six `uplink-*` UIDs.

- [ ] **Step 6: Verify none of them is firing**

In the UI (Alerting → Alert rules) all six should read **Normal**. Any rule sitting in `Alerting` immediately after provisioning means its expression is inverted — a `bool` comparison pointing the wrong way returns 1 for the healthy case.

- [ ] **Step 7: Propose the commit**

```bash
git add ops/grafana/alerting/rules.yaml && git commit -m "feat(ops): add uplink degradation alert rules"
```

---

### Task 8: The dead man's switch

**Files:**
- Modify: `ops/grafana/alerting/rules.yaml`

**Interfaces:**
- Consumes: contact point `heartbeat-observers` and the `alertname = DeadMansSwitch` route from Task 6; the receivers deployed in Tasks 3 and 4.
- Produces: rule UID `heartbeat-dead-man` in a second group named `heartbeat`.

- [ ] **Step 1: Add the rule**

Append to `ops/grafana/alerting/rules.yaml`, as a second entry under `groups:`:

```yaml
  - orgId: 1
    name: heartbeat
    folder: Alerts
    interval: 1m
    rules:
      # Always firing, by design. Its notifications are the pulse that cloud1
      # and cloud2 listen for; silence is the signal.
      #
      # The condition runs through the datasource rather than being a constant:
      # `count(up)` needs VictoriaMetrics to answer. If VM dies, this query
      # errors, execErrState sends the rule to OK, the pulse stops and both
      # observers mail. A `vector(1)` condition would keep pulsing over a dead
      # database and hide exactly the outage this is here to catch.
      - uid: heartbeat-dead-man
        title: DeadMansSwitch
        condition: C
        for: 0s
        labels:
          severity: none
        annotations:
          summary: 'pulse from .102 — this alert is always firing on purpose'
        noDataState: OK
        execErrState: OK
        data:
          - refId: A
            relativeTimeRange: {from: 600, to: 0}
            datasourceUid: adnsc1wi03doga
            model:
              refId: A
              editorMode: code
              instant: true
              expr: 'count(up) >= bool 1'
          - refId: C
            datasourceUid: __expr__
            model:
              refId: C
              type: threshold
              expression: A
              conditions:
                - evaluator: {type: gt, params: [0]}
```

- [ ] **Step 2: Verify and deploy**

```bash
python3 -c "import yaml; d=yaml.safe_load(open('ops/grafana/alerting/rules.yaml')); print('groups:', [g['name'] for g in d['groups']], 'rules:', sum(len(g['rules']) for g in d['groups']))" && ./ops/grafana/alerting/deploy.sh
```

Expected: `groups: ['uplink', 'heartbeat'] rules: 7`, then a clean deploy.

- [ ] **Step 3: Verify the pulse arrives on both observers**

Wait two minutes, then:

```bash
for h in cloud1 cloud2; do echo "== $h"; ssh sysadm@$h.beerloga.su 'sudo tail -2 /var/log/nginx/heartbeat.log; sudo /usr/local/sbin/heartbeat-watch --dry-run'; done
```

Expected on each: recent log lines with `"POST /hb/... HTTP/1.1" 204` and a `Grafana` user agent, then `state=up`. A missing line on one node only means that node's URL or token is wrong; missing on both means the route or the contact point name does not match.

- [ ] **Step 4: Confirm the pulse does not reach the mailbox**

In the UI, Alerting → Notification policies, confirm `DeadMansSwitch` matches the child route and not the default. Also confirm no mail arrived from the always-firing rule — if one did, the `object_matchers` line is wrong and every alert group is now going to both destinations.

- [ ] **Step 5: Propose the commit**

```bash
git add ops/grafana/alerting/rules.yaml && git commit -m "feat(ops): add the dead man's switch heartbeat rule"
```

---

### Task 9: End-to-end validation

The only task that exercises failure paths. Nothing here is permanent, but each step deliberately breaks something, so each is announced before it runs.

- [ ] **Step 1: Prove an alert reaches the mailbox**

Temporarily add a rule that is always true, deploy, wait for `group_wait` (30s) plus one evaluation, confirm the mail, then remove it and deploy again.

Add to the `uplink` group in `rules.yaml`:

```yaml
      - uid: uplink-selftest
        title: AlertingSelfTest
        condition: C
        for: 0s
        labels:
          severity: info
        annotations:
          summary: 'self-test — delete this rule once the mail arrives'
        noDataState: OK
        execErrState: OK
        data:
          - refId: A
            relativeTimeRange: {from: 600, to: 0}
            datasourceUid: adnsc1wi03doga
            model:
              refId: A
              editorMode: code
              instant: true
              expr: 'count(up) >= bool 1'
          - refId: C
            datasourceUid: __expr__
            model:
              refId: C
              type: threshold
              expression: A
              conditions:
                - evaluator: {type: gt, params: [0]}
```

Run `./ops/grafana/alerting/deploy.sh`, wait ~2 minutes, confirm the mail, then delete the rule from the file and run `deploy.sh` again. Confirm the resolved mail arrives too — that proves resolved notifications work, which matters more than the firing path, because it is what tells the owner a problem ended.

- [ ] **Step 2: [NEEDS APPROVAL] Prove the dead man's switch fires**

This is the only test that covers the case the whole design exists for, and it cannot be faked: the pulse must genuinely stop for 15 minutes. Ask the owner before starting, and say it will produce two mails.

Pause the rule in the UI (Alerting → Alert rules → DeadMansSwitch → Pause), note the time, and wait 15 minutes.

Expected: two mails, subjects `[cloud1] outline: no heartbeat from .102` and `[cloud2] ...`, arriving within five minutes of each other.

- [ ] **Step 3: Prove recovery**

Un-pause the rule. Within five minutes, expect two more mails: `heartbeat from .102 resumed` from each observer. Then confirm both watchers are quiet again:

```bash
for h in cloud1 cloud2; do ssh sysadm@$h.beerloga.su 'sudo /usr/local/sbin/heartbeat-watch --dry-run'; done
```

Expected: `state=up` twice, with no `send=`.

- [ ] **Step 4: Record the outcome in the spec**

Update the Validation section of the design document with what actually happened: which tests ran, on which date, and anything that behaved differently from the design. A spec that says "will be validated" a month later is worse than no spec.

- [ ] **Step 5: Propose the final commit**

```bash
git add docs/superpowers/specs/2026-08-07-uplink-email-alerting-design.md && git commit -m "docs: record alerting validation results"
```

---

## Rollback

Each piece backs out independently, which is why they were deployed in this order:

- **Alert rules or policies** — delete the file from `/opt/grafana/provisioning/alerting/` and Grafana drops what it provisioned; `disableDeletion` is not set for alerting, so removal is honoured.
- **SMTP** — restore `/opt/grafana/grafana.sh` from the `.bak` written in Task 5 and re-run it. Grafana comes back without mail; rules keep evaluating.
- **Heartbeat receiver** — `systemctl disable --now heartbeat-watch.timer` stops the mail; removing the `include snippets/heartbeat.conf;` line and reloading nginx removes the endpoint. The `.bak` of the site file written by `install.sh` is the fallback if the include was inserted in the wrong block.
- **Everything** — the fleet returns to having no alerting, which is where it started today.
