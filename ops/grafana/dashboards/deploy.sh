#!/usr/bin/env bash
#
# deploy.sh — push the node-level dashboards to the gateway.
# Run from the development machine: ./deploy.sh [file.json ...]
#
# With no arguments every *.json in this directory is copied. Copying alone
# changes nothing on screen: Grafana provisions dashboards once at startup, so a
# restart is required afterwards (`updateIntervalSeconds` does not re-read
# anything on 13.0.2 — verified 2026-08-09).

set -euo pipefail
cd "$(dirname "$0")"

host=${GRAFANA_HOST:-mmv@198.18.1.102}
dest=/opt/grafana/data/dashboards

files=("$@")
if [ ${#files[@]} -eq 0 ]; then
	# A bare glob would pass the literal "*.json" through on an empty directory.
	shopt -s nullglob
	files=(*.json)
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
