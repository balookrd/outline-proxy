#!/usr/bin/env bash
#
# install.sh — install the liveness watchdog on this host. Idempotent.
# Copy this directory to the node and run: sudo ./install.sh
#
# Enables one timer per outline unit that actually exists here, so the same
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
	# `list-unit-files` rather than `is-active`: a unit that is currently
	# stopped still deserves a watchdog once it is started again.
	if systemctl list-unit-files "$unit.service" >/dev/null 2>&1 &&
		systemctl cat "$unit.service" >/dev/null 2>&1; then
		echo "==> enabling watchdog for $unit"
		systemctl enable --now "outline-watchdog@$unit.timer"
		enabled=$((enabled + 1))
	else
		echo "==> $unit not present here, skipping"
	fi
done

[ "$enabled" -gt 0 ] || { echo "no outline units found on this host" >&2; exit 1; }

echo
echo "==> timers:"
systemctl list-timers 'outline-watchdog@*' --no-pager | head -n $((enabled + 2))
echo
echo "Check it: sudo /usr/local/sbin/outline-watchdog outline-ws-rust; echo \$?"
echo "Logs:     journalctl -t outline-watchdog"
