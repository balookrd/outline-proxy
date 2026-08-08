#!/usr/bin/env bash
#
# install-on-104.sh — install the p9 backup job on the NanoPi. Idempotent.
# Copy this whole directory to the board and run: sudo ./install-on-104.sh
#
# Does NOT start a backup and does NOT enable the timer until you've filled in
# /etc/default/nanopi104-backup (it stops and tells you if NFS_HOST is unset).

set -euo pipefail
cd "$(dirname "$0")"

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }

echo "==> ensuring NFS client + e2fsprogs are present"
if ! command -v /sbin/mount.nfs >/dev/null 2>&1 && ! command -v /usr/sbin/mount.nfs >/dev/null 2>&1; then
	apt-get update
	apt-get install -y --no-install-recommends nfs-common
fi
command -v /usr/sbin/e2image >/dev/null 2>&1 || apt-get install -y --no-install-recommends e2fsprogs

echo "==> installing script + units"
install -D -m 0755 backup-p9.sh            /usr/local/sbin/backup-p9.sh
install -D -m 0644 nanopi104-backup.service /etc/systemd/system/nanopi104-backup.service
install -D -m 0644 nanopi104-backup.timer   /etc/systemd/system/nanopi104-backup.timer
install -D -m 0644 README.md                /usr/local/share/nanopi104-backup/README.md

# Never overwrite an existing, edited config.
if [ ! -f /etc/default/nanopi104-backup ]; then
	install -D -m 0644 nanopi104-backup.default /etc/default/nanopi104-backup
	echo "==> wrote /etc/default/nanopi104-backup (EDIT NFS_HOST/NFS_EXPORT)"
else
	echo "==> keeping existing /etc/default/nanopi104-backup"
fi

systemctl daemon-reload

if grep -q '^NFS_HOST=CHANGE-ME' /etc/default/nanopi104-backup; then
	cat <<'EOF'

Almost done. Now:
  1. edit /etc/default/nanopi104-backup  (set NFS_HOST and NFS_EXPORT)
  2. test once:   sudo systemctl start nanopi104-backup.service
                  journalctl -u nanopi104-backup.service -n 40 --no-pager
  3. enable weekly:  sudo systemctl enable --now nanopi104-backup.timer
                     systemctl list-timers nanopi104-backup.timer
EOF
	exit 0
fi

echo "==> enabling weekly timer"
systemctl enable --now nanopi104-backup.timer
systemctl list-timers nanopi104-backup.timer --no-pager || true
echo "==> done. Test a run now with: sudo systemctl start nanopi104-backup.service"
