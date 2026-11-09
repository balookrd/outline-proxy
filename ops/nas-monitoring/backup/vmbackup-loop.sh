#!/bin/sh
# Daily vmbackup of the NAS VictoriaMetrics into /backup/victoria-metrics.
#
# vmbackup asks VictoriaMetrics for a snapshot through the API and copies
# incrementally against what is already in the destination, so the result is
# consistent while the database keeps writing.
#
# RUN_AT_UTC is HH:MM in UTC: busybox in this image has no tzdata, so TZ names
# would be ignored silently. 01:15 UTC = 04:15 MSK, after grafana-backup.
# ONCE=1 runs one backup immediately and exits (manual check).
set -u
RUN_AT_UTC=${RUN_AT_UTC:-01:15}

run() {
	/vmbackup-prod \
		-storageDataPath=/victoria-metrics-data \
		-snapshot.createURL=http://victoria-metrics:8428/snapshot/create \
		-dst=fs:///backup/victoria-metrics
}

if [ "${ONCE:-0}" = 1 ]; then
	run
	exit $?
fi

while :; do
	now=$(date -u +%s)
	next=$(date -u -d "$(date -u +%Y-%m-%d) ${RUN_AT_UTC}:00" +%s)
	[ "$next" -le "$now" ] && next=$((next + 86400))
	echo "next vmbackup at $(date -u -d "@$next") (in $((next - now)) s)"
	sleep $((next - now))
	run || echo "vmbackup failed with exit code $?" >&2
done
