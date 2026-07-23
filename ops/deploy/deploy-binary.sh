#!/usr/bin/env bash
#
# deploy-binary.sh — push one locally-built binary to one node.
#
# Run from the workstation:
#   ops/deploy/deploy-binary.sh <host> <unit> <local-binary> [keep]
#
#   host   ssh target, e.g. sysadm@cloud3.beerloga.su
#   unit   outline-ss-rust | outline-ws-rust
#   file   path to the cross-built binary
#   keep   backups to retain (default 3)
#
# This is the hand-rolled `scp && cp && install && restart` we kept typing,
# with the parts that are easy to skip under time pressure made mandatory:
#
#   * refuses a binary built for the wrong architecture (the fleet is mixed —
#     .104 is aarch64, everything else x86_64);
#   * verifies the bytes that landed are the bytes we built;
#   * keeps a timestamped backup and rotates old ones BY MTIME, so a fleet
#     does not silently accumulate a gigabyte of them the way ours did;
#   * verifies the service actually serves after the restart, and rolls back
#     to the backup it just took when it does not.

set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*"; }

[ $# -ge 3 ] || die "usage: $0 <host> <unit> <local-binary> [keep]"
HOST="$1"
UNIT="$2"
LOCAL="$3"
KEEP="${4:-3}"

case "$UNIT" in
	outline-ws-rust) PORT=9091 ;;
	outline-ss-rust) PORT=9090 ;;
	*) die "unknown unit '$UNIT' (expected outline-ws-rust or outline-ss-rust)" ;;
esac

[ -f "$LOCAL" ] || die "no such file: $LOCAL"

# `shasum` on macOS, `sha256sum` on Linux — the workstation may be either.
if command -v sha256sum >/dev/null 2>&1; then
	SUM=$(sha256sum "$LOCAL" | cut -d' ' -f1)
else
	SUM=$(shasum -a 256 "$LOCAL" | cut -d' ' -f1)
fi

# Architecture of the artifact, as `uname -m` spells it on the target.
case "$(file -b "$LOCAL")" in
	*x86-64*) ARCH=x86_64 ;;
	*aarch64*) ARCH=aarch64 ;;
	*) die "cannot tell the architecture of $LOCAL — is it an ELF binary?" ;;
esac

log "$HOST: $UNIT <- $(basename "$LOCAL") ($ARCH, ${SUM:0:12})"

# The binary travels by scp, not down the same stdin the remote script rides.
STAGE="/tmp/$UNIT.deploy.$$"
scp -q -o BatchMode=yes -o ConnectTimeout=15 "$LOCAL" "$HOST:$STAGE" ||
	die "failed to copy $LOCAL to $HOST"

ssh -o BatchMode=yes -o ConnectTimeout=15 "$HOST" \
	"UNIT='$UNIT' PORT='$PORT' SUM='$SUM' ARCH='$ARCH' KEEP='$KEEP' NEW='$STAGE' bash -s" <<'REMOTE'
set -euo pipefail
BIN="/usr/local/bin/$UNIT"
trap 'rm -f "$NEW"' EXIT

host_arch=$(uname -m)
[ "$host_arch" = "$ARCH" ] ||
	{ echo "error: host is $host_arch, binary is $ARCH" >&2; exit 1; }

chmod 0755 "$NEW"
got=$(sha256sum "$NEW" | cut -d' ' -f1)
[ "$got" = "$SUM" ] ||
	{ echo "error: transfer corrupted (${got:0:12} != ${SUM:0:12})" >&2; exit 1; }

backup=""
if [ -f "$BIN" ]; then
	backup="$BIN.bak.$(date +%Y%m%d%H%M%S)"
	# `cp -a` keeps mode and ownership, so a rollback restores the file as it
	# was rather than as root's umask would have made it.
	sudo -n cp -a "$BIN" "$backup"
	echo "    backup: $(basename "$backup")"

	# Rotate by mtime, never by name: the fleet carries both timestamped and
	# labelled backups (.bak.pre-<feature>), and alphabetical order puts a
	# fresh label before an old one — which deletes the rollback you want.
	pruned=0
	while IFS= read -r -d '' entry; do
		f="${entry#*$'\t'}"
		sudo -n rm -f "$f"
		pruned=$((pruned + 1))
	done < <(find /usr/local/bin -maxdepth 1 -type f -name "$(basename "$BIN").bak.*" \
		-printf '%T@\t%p\0' 2>/dev/null | sort -z -n | head -z -n "-$KEEP")
	[ "$pruned" -gt 0 ] && echo "    rotated: removed $pruned old backup(s), keeping $KEEP"
fi

sudo -n install -o root -g root -m 0755 "$NEW" "$BIN"
sudo -n systemctl restart "$UNIT"

# Verify it actually serves, not merely that systemd started something.
ok=0
for _ in $(seq 1 15); do
	sleep 2
	systemctl is-active --quiet "$UNIT" || continue
	code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/metrics" || true)
	[ "$code" = "200" ] && { ok=1; break; }
done

if [ "$ok" != 1 ]; then
	echo "error: $UNIT did not serve /metrics after the restart" >&2
	if [ -n "$backup" ]; then
		echo "    rolling back to $(basename "$backup")" >&2
		sudo -n cp -a "$backup" "$BIN"
		sudo -n systemctl restart "$UNIT"
		sleep 5
		echo "    rollback: $UNIT is $(systemctl is-active "$UNIT")" >&2
	fi
	exit 1
fi

live=$(sudo -n sha256sum "$BIN" | cut -d' ' -f1)
[ "$live" = "$SUM" ] || { echo "error: installed binary does not match" >&2; exit 1; }
echo "    ok: $UNIT active, /metrics 200, ${live:0:12}, $(ls -1 "$BIN".bak.* 2>/dev/null | wc -l | tr -d ' ') backup(s) kept"
REMOTE
