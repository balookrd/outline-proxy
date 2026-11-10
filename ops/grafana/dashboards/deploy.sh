#!/usr/bin/env bash
#
# deploy.sh — push the dashboards to Grafana.
# Run from the development machine:
#   ./deploy.sh [file.json ...]         # legacy: copy to the docker Grafana on .102
#   ./deploy.sh --nas [file.json ...]   # NAS: copy into /volume2/grafana/dashboards
#
# With no file arguments every *.json in this directory is used. Copying alone
# changes nothing on screen: Grafana provisions dashboards once at startup, so a
# restart is required afterwards (`updateIntervalSeconds` does not re-read
# anything on 13.0.2 — verified 2026-08-09).

set -euo pipefail
cd "$(dirname "$0")"

host=${GRAFANA_HOST:-mmv@198.18.1.102}
dest=/opt/grafana/data/dashboards

nas=0
case "${1:-}" in
--nas) nas=1; shift ;;
esac

files=("$@")
if [ ${#files[@]} -eq 0 ]; then
	# A bare glob would pass the literal "*.json" through on an empty directory.
	shopt -s nullglob
	files=(*.json)
	if [ "$nas" = 1 ]; then
		# Binary-specific dashboards live next to their binaries, and on the
		# NAS they must all be deployed together: the provider runs with
		# disableDeletion=false, so a dashboard missing from the mounted
		# directory gets DELETED from the database on the next start.
		files+=(../../../bins/outline-ss-rust/grafana/*.json)
		files+=(../../../bins/outline-ws-rust/grafana/*.json)
	fi
fi
[ ${#files[@]} -gt 0 ] || { echo "no dashboards to deploy" >&2; exit 1; }

for f in "${files[@]}"; do
	[ -f "$f" ] || { echo "missing $f" >&2; exit 1; }
	# A malformed dashboard is skipped silently by the provisioner, leaving the
	# previous version on screen and no error anywhere obvious.
	python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$f" ||
		{ echo "$f is not valid JSON — refusing to deploy" >&2; exit 1; }
done
echo "==> json ok: ${files[*]}"

if [ "$nas" = 1 ]; then
	# NAS Grafana (ops/nas-monitoring): dashboards live in the dashboards/
	# subdirectory of the /volume2/grafana shared folder, which the container
	# sees as /var/lib/grafana/dashboards. sysadm (uid 1000) may write there
	# under the UGOS ACL, so no sudo and no chown.
	nas_host=${NAS_HOST:-sysadm@198.18.1.105}
	nas_dest=/volume2/grafana/dashboards
	ssh "$nas_host" "mkdir -p $nas_dest"
	# -O: the NAS sftp-server rejects scp's default SFTP mode ("dest open: No
	# such file"); the legacy protocol works.
	scp -O -q "${files[@]}" "$nas_host:$nas_dest/"
	cat <<EOF

==> copied to $nas_host:$nas_dest. Grafana provisions dashboards at startup,
    so restart it (a production action — ask the owner first):

    ssh $nas_host 'docker restart grafana'
    ssh $nas_host 'docker logs --since 2m grafana 2>&1 | grep "provision dashboards"'
EOF
	exit 0
fi

scp -q "${files[@]}" "$host:/tmp/"
ssh "$host" "
	set -e
	for f in ${files[*]}; do
		sudo install -m 0644 -o 1000 -g 1000 \"/tmp/\$f\" \"$dest/\$f\"
		rm -f \"/tmp/\$f\"
	done
"

cat <<EOF

==> copied, but NOT yet on screen. Restart is a production action, so ask the
    owner first, then:

    ssh $host 'sudo docker restart grafana'

    and confirm it took:

    ssh $host 'sudo docker logs --since 2m grafana 2>&1 | grep "provision dashboards"'
EOF
