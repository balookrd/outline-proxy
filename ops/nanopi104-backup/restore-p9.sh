#!/usr/bin/env bash
#
# restore-p9.sh — write a p9 backup image onto the userdata partition of a fresh
# NanoPi .104 card. Run on macOS or Linux with the card in a reader.
#
# FULL RECOVERY IS TWO PHASES (see README):
#   1. Flash the ORIGINAL FriendlyElec vendor image onto the new card
#      (recreates GPT + raw boot p1..p7 + rootfs p8 + a stock, grown p9).
#   2. Run THIS script to overwrite p9 with your latest backup.
#
# The image produced by backup-p9.sh (e2image -ra) is a plain, sparse ext4 image
# the size of the original filesystem (~28 GiB nominal). Restoring it is just
# `gunzip | dd` onto the p9 partition — no ext4 tooling needed on macOS. The only
# hard requirement is that the target p9 partition is >= the image's filesystem
# size (that's why phase 1 uses a card of the same size or larger and lets the
# vendor image grow p9 to fill the disk).
#
# Safety: this script REFUSES to touch internal/system disks, shows you exactly
# what will be erased, and requires you to type the target name plus YES.

set -euo pipefail

IMG="${1:-}"
TARGET_ARG="${2:-}"   # optional: whole-disk device of the card (e.g. /dev/disk4 or /dev/sdb)

usage() {
	cat >&2 <<EOF
Usage: $0 <p9-image.img.gz> [card-whole-disk-device]

  <p9-image.img.gz>   a *.e2image.img.gz (or *.dd.img.gz) produced by backup-p9.sh
  [card-device]       optional; if omitted you'll pick interactively
                      macOS example: /dev/disk4     Linux example: /dev/sdb  or /dev/mmcblk0

The card must ALREADY be flashed with the original FriendlyElec image (phase 1).
EOF
	exit 2
}

[ -n "$IMG" ] || usage
[ -f "$IMG" ] || { echo "no such image: $IMG" >&2; exit 2; }
case "$IMG" in *.gz) ;; *) echo "expected a .gz image" >&2; exit 2;; esac

OS="$(uname -s)"
log() { printf '\033[1m%s\033[0m\n' "$*"; }

# Verify the gzip stream before we touch any disk.
log "==> verifying image integrity (gzip -t)"
gzip -t "$IMG" || { echo "image is corrupt" >&2; exit 1; }
if [ -f "${IMG}.sha256" ]; then
	log "==> verifying sha256"
	( cd "$(dirname "$IMG")" && \
	  if command -v sha256sum >/dev/null; then sha256sum -c "$(basename "$IMG").sha256"; \
	  else shasum -a 256 -c "$(basename "$IMG").sha256"; fi ) \
	  || { echo "sha256 mismatch" >&2; exit 1; }
fi

# Minimum target size the image needs, from the .meta sidecar if present.
MIN_TARGET_BYTES=0
if [ -f "${IMG}.meta" ]; then
	MIN_TARGET_BYTES=$(awk -F= '/^restore_min_target_bytes=/{print $2+0}' "${IMG}.meta")
fi

###############################################################################
# macOS
###############################################################################
if [ "$OS" = "Darwin" ]; then
	if [ -z "$TARGET_ARG" ]; then
		log "==> external physical disks:"
		diskutil list external physical || true
		echo
		read -r -p "Enter the card's whole-disk device (e.g. /dev/disk4): " TARGET_ARG
	fi
	[ -n "$TARGET_ARG" ] || { echo "no target given" >&2; exit 2; }
	DISK="${TARGET_ARG#/dev/}"; DISK="${DISK#r}"        # normalize to diskN
	WHOLE="/dev/$DISK"

	# Refuse internal disks.
	if ! diskutil info "$WHOLE" 2>/dev/null | grep -qiE 'Removable Media:.*(Removable|removable)|Internal:.*No|Device Location:.*External'; then
		echo "SAFETY: $WHOLE does not look like an external/removable disk. Aborting." >&2
		exit 1
	fi
	P9="${WHOLE}s9"; RAW="/dev/r${DISK}s9"
	diskutil info "$P9" >/dev/null 2>&1 || {
		echo "partition $P9 not found — did you flash the original image first (phase 1)?" >&2
		exit 1; }
	TGT_BYTES=$(diskutil info "$P9" | awk -F'[()]' '/Disk Size|Partition Size|Volume Size/{print $2; exit}' | awk '{print $1}')

	log "==> TARGET: $P9  (raw $RAW)"
	diskutil info "$P9" | grep -iE 'Device Node|Volume Name|Partition Type|Disk Size|Partition Size' || true
	if [ "${MIN_TARGET_BYTES:-0}" -gt 0 ] && [ -n "${TGT_BYTES:-}" ] && [ "$TGT_BYTES" -gt 0 ] && [ "$TGT_BYTES" -lt "$MIN_TARGET_BYTES" ]; then
		echo "SAFETY: target p9 ($TGT_BYTES B) < image fs ($MIN_TARGET_BYTES B). Use a larger card / grow p9." >&2
		exit 1
	fi
	echo
	log "This will ERASE $P9 and overwrite it with $IMG"
	read -r -p "Type '$P9' to confirm: " c1; [ "$c1" = "$P9" ] || { echo "mismatch, aborting"; exit 1; }
	read -r -p "Type YES to proceed: " c2;  [ "$c2" = "YES" ]  || { echo "aborting"; exit 1; }

	log "==> unmounting $WHOLE"
	diskutil unmountDisk "$WHOLE"
	log "==> restoring (gunzip | dd → $RAW). This can take a few minutes."
	# shellcheck disable=SC2024
	gunzip -c "$IMG" | sudo dd of="$RAW" bs=4m
	sync
	log "==> ejecting"
	diskutil eject "$WHOLE" || true
	log "DONE. On macOS the ext4 journal will be replayed by the NanoPi on first boot."
	log "     (fsck/resize2fs can't run on macOS; the vendor image already sized p9.)"
	exit 0
fi

###############################################################################
# Linux
###############################################################################
if [ "$OS" = "Linux" ]; then
	if [ -z "$TARGET_ARG" ]; then
		log "==> block devices:"
		lsblk -dpo NAME,SIZE,TYPE,TRAN,RM,MODEL || true
		echo
		read -r -p "Enter the card's whole-disk device (e.g. /dev/sdb or /dev/mmcblk0): " TARGET_ARG
	fi
	[ -n "$TARGET_ARG" ] || { echo "no target given" >&2; exit 2; }
	WHOLE="$TARGET_ARG"
	[ -b "$WHOLE" ] || { echo "$WHOLE is not a block device" >&2; exit 1; }

	# Refuse the disk that hosts the running root filesystem.
	ROOT_SRC=$(findmnt -no SOURCE / 2>/dev/null || true)
	ROOT_DISK=$(lsblk -no PKNAME "$ROOT_SRC" 2>/dev/null | head -1)
	if [ -n "$ROOT_DISK" ] && [ "/dev/$ROOT_DISK" = "$WHOLE" ]; then
		echo "SAFETY: $WHOLE hosts the running root filesystem. Aborting." >&2
		exit 1
	fi
	RM=$(lsblk -dno RM "$WHOLE" 2>/dev/null | tr -d ' ')
	if [ "$RM" != "1" ]; then
		log "WARNING: $WHOLE is not flagged removable (RM=$RM). Double-check this is the card."
	fi

	# p9 naming: mmcblk0 -> mmcblk0p9 ; sdb -> sdb9
	case "$WHOLE" in
		*[0-9]) P9="${WHOLE}p9" ;;
		*)      P9="${WHOLE}9"  ;;
	esac
	[ -b "$P9" ] || { echo "partition $P9 not found — flash the original image first (phase 1)?" >&2; exit 1; }
	TGT_BYTES=$(blockdev --getsize64 "$P9" 2>/dev/null || echo 0)

	log "==> TARGET partition: $P9"
	lsblk -po NAME,SIZE,FSTYPE,LABEL,MOUNTPOINT "$WHOLE" || true
	if [ "${MIN_TARGET_BYTES:-0}" -gt 0 ] && [ "$TGT_BYTES" -gt 0 ] && [ "$TGT_BYTES" -lt "$MIN_TARGET_BYTES" ]; then
		echo "SAFETY: target p9 ($TGT_BYTES B) < image fs ($MIN_TARGET_BYTES B)." >&2
		echo "Use a card >= the original, or grow p9 with parted before restoring." >&2
		exit 1
	fi
	echo
	log "This will ERASE $P9 and overwrite it with $IMG"
	read -r -p "Type '$P9' to confirm: " c1; [ "$c1" = "$P9" ] || { echo "mismatch, aborting"; exit 1; }
	read -r -p "Type YES to proceed: " c2;  [ "$c2" = "YES" ]  || { echo "aborting"; exit 1; }

	log "==> unmounting any mounted parts of $WHOLE"
	for part in $(lsblk -lnpo NAME "$WHOLE" | tail -n +2); do
		umount "$part" 2>/dev/null || true
	done
	log "==> restoring (gunzip | dd → $P9)"
	# shellcheck disable=SC2024
	gunzip -c "$IMG" | sudo dd of="$P9" bs=4M conv=fsync status=progress
	sync
	log "==> fsck + grow filesystem to fill the partition"
	sudo e2fsck -fy "$P9" || true      # -y: auto-fix crash-consistent journal replay
	sudo resize2fs "$P9" || true       # grow to partition if the card is larger
	sync
	log "DONE. Card is ready — put it in the NanoPi."
	exit 0
fi

echo "unsupported OS: $OS" >&2
exit 1
