#!/usr/bin/env bash
#
# deploy.sh — copy the jellyfin-backup compose project to the NAS.
#   ./deploy.sh          # copy files only
#   ./deploy.sh --up     # copy, then recreate the container (production
#                        # action: ask the owner first)
#
# The script is mounted as a directory, so a copied jellyfin-backup.py is
# visible at once but the running loop keeps the old code until a restart:
# --up restarts the container even when compose sees no config change.

set -euo pipefail
cd "$(dirname "$0")"

host=${NAS_HOST:-sysadm@198.18.1.105}
dest=/volume1/docker/jellyfin-backup

docker compose -f docker-compose.yaml config -q
python3 -m py_compile jellyfin-backup.py

ssh "$host" "mkdir -p $dest"
# -O: UGOS refuses SFTP-mode scp.
scp -q -O docker-compose.yaml jellyfin-backup.py "$host:$dest/"
echo "==> copied to $host:$dest"

if [ "${1:-}" = "--up" ]; then
	ssh "$host" "cd $dest && docker compose up -d && docker compose restart jellyfin-backup && docker compose ps"
fi
