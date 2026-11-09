#!/usr/bin/env bash
#
# install.sh — install per-host GRE accounting on this host. Idempotent.
# Copy this directory to the node and run: sudo ./install.sh
#
# Loads the nftables table `inet hostacct` (counts only, never drops) and a
# 15-second timer that writes hostacct.prom for the node_exporter textfile
# collector. node_exporter itself must be started with
# --collector.textfile.directory pointing at /run/node_exporter/textfile
# (or at the host path mounted into its container).

set -euo pipefail
cd "$(dirname "$0")"

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }
ip link show gre1 >/dev/null 2>&1 || { echo "no gre1 on this host" >&2; exit 1; }

echo "==> installing table, script and units"
install -D -m 0644 hostacct.nft             /etc/hostacct.nft
install -D -m 0755 hostacct-metrics         /usr/local/sbin/hostacct-metrics
install -D -m 0644 hostacct.service         /etc/systemd/system/hostacct.service
install -D -m 0644 hostacct-metrics.service /etc/systemd/system/hostacct-metrics.service
install -D -m 0644 hostacct-metrics.timer   /etc/systemd/system/hostacct-metrics.timer
install -D -m 0644 README.md                /usr/local/share/hostacct/README.md
systemctl daemon-reload

echo "==> loading table"
systemctl enable hostacct.service
systemctl restart hostacct.service
systemctl enable --now hostacct-metrics.timer

/usr/local/sbin/hostacct-metrics
echo
echo "==> /run/node_exporter/textfile/hostacct.prom:"
head -n 12 /run/node_exporter/textfile/hostacct.prom
