#!/usr/bin/env bash
#
# deploy.sh — copy the compose project to the NAS.
#   ./deploy.sh          # copy files only
#   ./deploy.sh --up     # copy, then `docker compose up -d` (production action:
#                        # ask the owner first)
#
# The SMTP password is not in git: put it into
# /volume1/docker/monitoring/secrets/smtp once (README.md, "Секрет SMTP").

set -euo pipefail
cd "$(dirname "$0")"

host=${NAS_HOST:-sysadm@198.18.1.105}
dest=/volume1/docker/monitoring

docker compose -f docker-compose.yaml config -q

ssh "$host" "mkdir -p $dest/victoria-metrics $dest/grafana/datasources $dest/grafana/dashboards-provider $dest/backup"
scp -q -O docker-compose.yaml "$host:$dest/"
scp -q -O victoria-metrics/scrape.yaml "$host:$dest/victoria-metrics/"
scp -q -O grafana/datasources/*.yaml "$host:$dest/grafana/datasources/"
scp -q -O grafana/dashboards-provider/*.yaml "$host:$dest/grafana/dashboards-provider/"
scp -q -O backup/* "$host:$dest/backup/"
ssh "$host" "test -s $dest/secrets/smtp" ||
	{ echo "missing $dest/secrets/smtp on the NAS (README.md)" >&2; exit 1; }
echo "==> copied to $host:$dest"

if [ "${1:-}" = "--up" ]; then
	ssh "$host" "cd $dest && docker compose up -d && docker compose ps"
fi
