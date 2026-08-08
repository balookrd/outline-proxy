#!/usr/bin/env bash
#
# backup-p9.sh — periodic backup of the NanoPi .104 userdata partition to NFS.
#
# WHY only p9: the card (/dev/mmcblk0) is a Rockchip raw-boot layout. p1..p7 are
# raw bootloader/kernel/dtb blobs and p8 (rootfs) is the stock FriendlyElec image
# — both are recreated by re-flashing the ORIGINAL vendor image onto a fresh card.
# The only thing that carries live, hand-made state is p9 ("userdata", ext4),
# which is the overlayfs upperdir (/data/root) — configs, systemd drop-ins,
# zram-swap unit, everything we ever changed lives there. So we back up p9 only.
#
# Model: PUSH. This script runs ON the NanoPi, mounts NFS itself, and streams the
# image straight onto it. p9 is NOT visible as a normal mount in the running
# namespace (initramfs assembles the overlay and switch_root's away), so we read
# the block device /dev/mmcblk0p9 directly.
#
# Default MODE=e2image: e2image -ra reads ONLY the ~1 GiB of used ext4 blocks
# (not the whole 28 GiB partition) yet emits a normal, sparse ext4 image. That
# keeps the read load off the fragile 1 GiB board AND makes restore portable —
# the image is plain ext4, so `gunzip | dd` restores it on macOS or Linux with no
# special tooling. MODE=dd is a raw fallback (reads the full 28 GiB incl. garbage
# in free space → large image); avoid unless you have a reason.
#
# Consistency: p9 is the live overlay backing store, so the snapshot is
# crash-consistent (like a power-cut — ext4 journal replays on restore). Configs
# are static; at worst a few seconds of in-flight logs are inconsistent. Set
# STOP_SERVICES=1 to quiesce outline-ws-rust during the snapshot if you want less
# write churn (it does NOT unmount p9; the overlay stays live either way).
#
# Root required. Intended to be driven by nanopi104-backup.timer (which also caps
# memory via cgroup so the backup job itself can't trigger the OOM-livelock).

set -euo pipefail

### --- Config (edit NFS_HOST / NFS_EXPORT, or pass via environment) ----------
NFS_HOST="${NFS_HOST:-CHANGE-ME.nfs.host}"      # <-- EDIT: NFS server IP/hostname
NFS_EXPORT="${NFS_EXPORT:-/export/nanopi-backups}" # <-- EDIT: exported path
NFS_OPTS="${NFS_OPTS:-vers=4,soft,timeo=50,retrans=3,noatime,nolock}"
NFS_SUBDIR="${NFS_SUBDIR:-nanopi104}"           # subdir under the export
KEEP="${KEEP:-6}"                                # how many images to retain
MODE="${MODE:-e2image}"                          # e2image (used blocks) | dd (raw)
STOP_SERVICES="${STOP_SERVICES:-0}"              # 1 = stop outline-ws-rust while snapshotting
DEV="${DEV:-/dev/mmcblk0p9}"                      # userdata partition
HOST_TAG="${HOST_TAG:-nanopi104}"
SERVICE="${SERVICE:-outline-ws-rust.service}"
### --------------------------------------------------------------------------

log()  { printf '%s  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
die()  { log "ERROR: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1 || [ -x "/usr/sbin/$1" ] || [ -x "/sbin/$1" ]; }
# Prefer sbin tools that may be outside a stripped-down PATH.
export PATH="/usr/sbin:/sbin:$PATH"

MNT=""
SERVICE_STOPPED=0
cleanup() {
	rc=$?
	if [ "$SERVICE_STOPPED" = 1 ]; then
		log "restarting $SERVICE"
		systemctl start "$SERVICE" 2>/dev/null || log "WARN: could not restart $SERVICE"
	fi
	if [ -n "$MNT" ] && mountpoint -q "$MNT" 2>/dev/null; then
		umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
	fi
	[ -n "$MNT" ] && rmdir "$MNT" 2>/dev/null || true
	[ "$rc" -eq 0 ] && log "backup OK" || log "backup FAILED (rc=$rc)"
	exit "$rc"
}
trap cleanup EXIT INT TERM

### --- Preflight -------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo, or run via the systemd unit)"
[ -b "$DEV" ] || die "$DEV is not a block device"
have gzip || die "gzip not found"
have mount.nfs || have mount.nfs4 || die "NFS client missing — install it: apt-get install -y nfs-common"
case "$MODE" in
	e2image) have e2image || die "e2image not found (package e2fsprogs)";;
	dd)      have dd || die "dd not found";;
	*)       die "unknown MODE='$MODE' (use e2image or dd)";;
esac
[ "$NFS_HOST" = "CHANGE-ME.nfs.host" ] && die "edit NFS_HOST/NFS_EXPORT at the top of this script first"

### --- Filesystem stats (for sizing + manifest) -----------------------------
read -r BLOCK_COUNT FREE_BLOCKS BLOCK_SIZE < <(
	dumpe2fs -h "$DEV" 2>/dev/null | awk -F: '
		/Block count/   {bc=$2}
		/Free blocks/   {fb=$2}
		/Block size/    {bs=$2}
		END {print bc+0, fb+0, bs+0}'
)
[ "${BLOCK_SIZE:-0}" -gt 0 ] || die "could not read ext4 superblock on $DEV"
USED_BLOCKS=$(( BLOCK_COUNT - FREE_BLOCKS ))
USED_BYTES=$(( USED_BLOCKS * BLOCK_SIZE ))
FS_BYTES=$(( BLOCK_COUNT * BLOCK_SIZE ))
log "p9: fs=$(( FS_BYTES / 1024 / 1024 ))MiB used=$(( USED_BYTES / 1024 / 1024 ))MiB mode=$MODE"

### --- Mount NFS -------------------------------------------------------------
MNT="$(mktemp -d /run/nfs-backup.XXXXXX)"
log "mounting ${NFS_HOST}:${NFS_EXPORT} (${NFS_OPTS})"
mount -t nfs -o "$NFS_OPTS" "${NFS_HOST}:${NFS_EXPORT}" "$MNT" \
	|| die "NFS mount failed"
DEST="$MNT/$NFS_SUBDIR"
mkdir -p "$DEST" || die "cannot create $DEST on NFS"

# Space check: require used-bytes + 512 MiB headroom (compressed image is smaller,
# so this is a generous floor).
AVAIL=$(df -PB1 "$DEST" | awk 'NR==2{print $4+0}')
NEED=$(( USED_BYTES + 512 * 1024 * 1024 ))
[ "$AVAIL" -ge "$NEED" ] || die "not enough space on NFS: avail=$(( AVAIL/1024/1024 ))MiB need>=$(( NEED/1024/1024 ))MiB"

### --- Snapshot --------------------------------------------------------------
TS="$(date +%Y%m%d-%H%M%S)"
NAME="${HOST_TAG}-p9-${TS}.${MODE}.img.gz"
TMP="$DEST/.${NAME}.partial"

sync
if [ "$STOP_SERVICES" = 1 ]; then
	log "stopping $SERVICE for a quiescent snapshot"
	systemctl stop "$SERVICE" && SERVICE_STOPPED=1 || log "WARN: stop $SERVICE failed, continuing live"
	sync
fi

log "writing $NAME"
set -o pipefail
case "$MODE" in
	e2image)
		# -r raw image, -a copy used data blocks, -p progress. Read-only on $DEV.
		ionice -c3 nice -n19 e2image -ra -p "$DEV" - </dev/null \
			| ionice -c3 nice -n19 gzip -1 > "$TMP"
		;;
	dd)
		ionice -c3 nice -n19 dd if="$DEV" bs=4M status=none </dev/null \
			| ionice -c3 nice -n19 gzip -1 > "$TMP"
		;;
esac

# Restart the service immediately after the read pass, before the slower
# verify/checksum/rotate steps run.
if [ "$SERVICE_STOPPED" = 1 ]; then
	log "restarting $SERVICE"
	systemctl start "$SERVICE" && SERVICE_STOPPED=0 || log "WARN: could not restart $SERVICE"
fi

### --- Verify + manifest -----------------------------------------------------
log "verifying gzip integrity"
gzip -t "$TMP" || die "gzip integrity check failed"
IMG_BYTES=$(stat -c%s "$TMP")
SHA=$(sha256sum "$TMP" | awk '{print $1}')

mv -f "$TMP" "$DEST/$NAME"
printf '%s  %s\n' "$SHA" "$NAME" > "$DEST/${NAME}.sha256"
cat > "$DEST/${NAME}.meta" <<META
host=$(uname -n)
kernel=$(uname -r)
date_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
mode=$MODE
device=$DEV
fs_uuid=$(blkid -s UUID -o value "$DEV" 2>/dev/null)
part_uuid=$(blkid -s PARTUUID -o value "$DEV" 2>/dev/null)
fs_bytes=$FS_BYTES
used_bytes=$USED_BYTES
block_count=$BLOCK_COUNT
block_size=$BLOCK_SIZE
image_bytes=$IMG_BYTES
image_sha256=$SHA
restore_min_target_bytes=$FS_BYTES
META
log "stored $NAME ($(( IMG_BYTES / 1024 / 1024 ))MiB, sha256=${SHA:0:12}…)"

### --- Rotation --------------------------------------------------------------
mapfile -t OLD < <(ls -1t "$DEST"/${HOST_TAG}-p9-*.img.gz 2>/dev/null | tail -n +"$(( KEEP + 1 ))")
for f in "${OLD[@]:-}"; do
	[ -n "$f" ] || continue
	log "pruning old backup $(basename "$f")"
	rm -f "$f" "$f.sha256" "$f.meta"
done

sync
# umount happens in cleanup()
