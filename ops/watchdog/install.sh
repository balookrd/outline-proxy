#!/usr/bin/env bash
#
# install.sh — install the liveness watchdog on this host. Idempotent.
# Copy this directory to the node and run: sudo ./install.sh
#
# Enables one timer per outline unit this host actually runs, so the same
# script serves a client-only box, a server-only box, or one running both.

set -euo pipefail
cd "$(dirname "$0")"

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }

echo "==> installing script + units"
install -D -m 0755 outline-watchdog          /usr/local/sbin/outline-watchdog
install -D -m 0644 'outline-watchdog@.service' /etc/systemd/system/'outline-watchdog@.service'
install -D -m 0644 'outline-watchdog@.timer'   /etc/systemd/system/'outline-watchdog@.timer'
install -D -m 0644 README.md                 /usr/local/share/outline-watchdog/README.md
systemctl daemon-reload

enabled=0
for unit in outline-ws-rust outline-ss-rust; do
	if ! systemctl cat "$unit.service" >/dev/null 2>&1; then
		echo "==> $unit not present here, skipping"
		continue
	fi
	# Presence of the unit file is not enough. Server-only nodes ship the
	# client unit but leave it `disabled` on purpose; watching it would mean a
	# timer firing every minute forever for something nobody intends to run.
	# Watch what the host means to run — enabled, or running right now (a unit
	# started by hand). A unit that is enabled but currently stopped still gets
	# a watchdog: it is expected back, and the watchdog no-ops while it is down.
	if systemctl is-enabled --quiet "$unit.service" 2>/dev/null ||
		systemctl is-active --quiet "$unit.service"; then
		echo "==> enabling watchdog for $unit"
		systemctl enable --now "outline-watchdog@$unit.timer"
		enabled=$((enabled + 1))
	else
		echo "==> $unit present but disabled here, skipping"
		# Undo a watchdog left behind by an earlier install, so a node that
		# stops running a unit stops being watched for it.
		if systemctl is-enabled --quiet "outline-watchdog@$unit.timer" 2>/dev/null; then
			echo "    (removing the stale watchdog timer for it)"
			systemctl disable --now "outline-watchdog@$unit.timer"
		fi
	fi
done

[ "$enabled" -gt 0 ] || { echo "no outline units to watch on this host" >&2; exit 1; }

echo
echo "==> timers:"
systemctl list-timers 'outline-watchdog@*' --no-pager | head -n $((enabled + 2))
echo
echo "Check it: sudo /usr/local/sbin/outline-watchdog outline-ws-rust; echo \$?"
echo "Logs:     journalctl -t outline-watchdog"
