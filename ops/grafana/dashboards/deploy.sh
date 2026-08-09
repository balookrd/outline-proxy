#!/usr/bin/env bash
#
# deploy.sh — push the dashboards to Grafana.
# Run from the development machine:
#   ./deploy.sh [file.json ...]         # legacy: copy to the docker Grafana on .102
#   ./deploy.sh --k3s [file.json ...]   # cluster: one ConfigMap per dashboard
#
# With no file arguments every *.json in this directory is used. Copying alone
# changes nothing on screen: Grafana provisions dashboards once at startup, so a
# restart is required afterwards (`updateIntervalSeconds` does not re-read
# anything on 13.0.2 — verified 2026-08-09).

set -euo pipefail
cd "$(dirname "$0")"

host=${GRAFANA_HOST:-mmv@198.18.1.102}
dest=/opt/grafana/data/dashboards

k3s=0
if [ "${1:-}" = "--k3s" ]; then
	k3s=1
	shift
fi

files=("$@")
if [ ${#files[@]} -eq 0 ]; then
	# A bare glob would pass the literal "*.json" through on an empty directory.
	shopt -s nullglob
	files=(*.json)
	if [ "$k3s" = 1 ]; then
		# Binary-specific dashboards live next to their binaries, and in the
		# cluster they must all be deployed together: the provider runs with
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

if [ "$k3s" = 1 ]; then
	# Cluster mode: each dashboard becomes its own ConfigMap, because a single
	# one would run into the 1 MiB object limit. The manifests are generated
	# rather than committed — otherwise the same JSON would live twice in the
	# repository and the copies would drift.
	command -v kubectl >/dev/null || { echo "kubectl not in PATH" >&2; exit 1; }
	: "${KUBECONFIG:?set KUBECONFIG (e.g. ~/.kube/k3s-home.yaml)}"
	for f in "${files[@]}"; do
		name="grafana-dashboard-$(basename "$f" .json)"
		# --server-side is not optional here: a client-side apply stores the
		# whole object in the last-applied-configuration annotation, and
		# annotations cap at 256 KB. outline-ws-rust-dashboard.json is 252 KB,
		# so it fits the 1 MiB ConfigMap but blows the annotation limit.
		kubectl create configmap "$name" -n monitoring --from-file="$f" \
			--dry-run=client -o yaml |
			kubectl apply --server-side --force-conflicts -f -
	done
	cat <<EOF

==> ConfigMaps applied. If you ADDED a dashboard, its ConfigMap is not mounted
    yet — add a source to the projected volume in
    apps/monitoring/grafana.yaml and re-apply the Deployment:

$(for f in "${files[@]}"; do echo "      - configMap: { name: grafana-dashboard-$(basename "$f" .json) }"; done)

    Grafana provisions dashboards at startup, so restart the pod to pick up
    changes (a production action — ask the owner first):

    kubectl -n monitoring rollout restart deploy/grafana
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
