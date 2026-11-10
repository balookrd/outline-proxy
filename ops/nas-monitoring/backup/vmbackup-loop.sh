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
#
# After a successful run the script pushes
# nas_backup_last_success_timestamp_seconds{backup="vmbackup"} to PUSH_URL;
# vmalert's BackupStale / BackupMissing alert on it.
set -u
RUN_AT_UTC=${RUN_AT_UTC:-01:15}
PUSH_URL=${PUSH_URL:-http://victoria-metrics:8428/api/v1/import/prometheus}

# A malformed value used to make busybox date print nothing, sleep got a
# negative number and returned at once, and vmbackup ran back to back. Refuse
# to start instead: docker restarts the container with a growing delay and the
# log says why.
case $RUN_AT_UTC in
[01][0-9]:[0-5][0-9] | 2[0-3]:[0-5][0-9]) ;;
*)
	echo "RUN_AT_UTC must be HH:MM in UTC, got '$RUN_AT_UTC'" >&2
	exit 1
	;;
esac

# A failed push is logged, not fatal: the backup itself succeeded, and a
# missing sample shows up as BackupStale anyway.
report_success() {
	wget -q -O /dev/null -T 10 \
		--post-data "nas_backup_last_success_timestamp_seconds{backup=\"vmbackup\"} $(date -u +%s)" \
		"$PUSH_URL" || echo "could not report success to $PUSH_URL" >&2
}

run() {
	/vmbackup-prod \
		-storageDataPath=/victoria-metrics-data \
		-snapshot.createURL=http://victoria-metrics:8428/snapshot/create \
		-dst=fs:///backup/victoria-metrics &&
		report_success
}

if [ "${ONCE:-0}" = 1 ]; then
	run
	exit $?
fi

while :; do
	now=$(date -u +%s)
	next=$(date -u -d "$(date -u +%Y-%m-%d) ${RUN_AT_UTC}:00" +%s) || next=
	case $next in
	'' | *[!0-9]*)
		# Never spin: without a valid time, wait a minute and retry.
		echo "cannot compute the next run time, retrying in 60 s" >&2
		sleep 60
		continue
		;;
	esac
	[ "$next" -le "$now" ] && next=$((next + 86400))
	echo "next vmbackup at $(date -u -d "@$next") (in $((next - now)) s)"
	sleep $((next - now))
	run || echo "vmbackup failed with exit code $?" >&2
done
