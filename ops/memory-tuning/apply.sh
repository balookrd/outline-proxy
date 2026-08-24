#!/usr/bin/env bash
#
# apply.sh — push the memory-tuning source of truth (fleet.tsv) to the nodes.
#
# Run from the development machine:
#   ./apply.sh                 # every node in fleet.tsv
#   ./apply.sh <host>          # one node (match on the ssh target)
#   ./apply.sh --dry-run       # show what would change, touch nothing
#
# For each service with a limit in the table it writes ONE canonical drop-in
#   /etc/systemd/system/<unit>.service.d/20-memory.conf
# then applies the cgroup limits to the running service WITHOUT a restart.
#
# Why this exists: the limits used to be hand-placed, lived only on the nodes,
# were lost on reprovision, and carried MIMALLOC_* env that jemalloc ignores.
# The table is now the single source; the node is made to match it.
#
# Three cleanups happen on every node so the canonical file is the only thing
# in play:
#   * 30-mem-tuning.conf is removed — dead MIMALLOC_* env.
#   * /etc/systemd/system.control/<unit>.d is removed — stale `set-property`
#     overrides (persistent, and higher priority than our file) would otherwise
#     win after a reboot and mask the table.
#   * THREAD_STACK_SIZE_KB (clients only) moves to its own 30-thread-stack.conf,
#     since it is a runtime knob, not a memory limit.
#
# Limits apply live; env (thread stack) only takes effect on the next restart,
# but its value does not change here, so nothing needs restarting.

set -euo pipefail
cd "$(dirname "$0")"

TABLE=fleet.tsv
DRY=0
ONLY=""
for arg in "$@"; do
	case "$arg" in
		--dry-run) DRY=1 ;;
		-*) echo "unknown flag: $arg" >&2; exit 2 ;;
		*) ONLY="$arg" ;;
	esac
done

log()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[err]\033[0m %s\n' "$*" >&2; exit 1; }

[ -f "$TABLE" ] || die "$TABLE not found (run from ops/memory-tuning/)"

# Convert "700M" etc. to MiB for the "limit above current RSS" safety check.
to_mib() {
	case "$1" in
		*M) echo "${1%M}" ;;
		*G) echo $(( ${1%G} * 1024 )) ;;
		*)  echo "$(( $1 / 1048576 ))" ;;
	esac
}

# Emitted on the node: build the canonical drop-in, clean the stale files, apply
# limits live. Kept as one heredoc so a single ssh round-trip does everything.
# $1 unit  $2 high  $3 max  $4 want_thread_stack(0/1)  $5 dry(0/1)
remote_script() {
	cat <<'REMOTE'
set -eu
unit="$1"; high="$2"; max="$3"; want_stack="$4"; dry="$5"
d="/etc/systemd/system/${unit}.service.d"
mem="$d/20-memory.conf"
stack="$d/30-thread-stack.conf"
legacy="$d/30-mem-tuning.conf"
ctl="/etc/systemd/system.control/${unit}.service.d"

hi_b=$(systemctl show "$unit" -p MemoryHigh --value 2>/dev/null || echo -)
mx_b=$(systemctl show "$unit" -p MemoryMax --value 2>/dev/null || echo -)
cur=$(systemctl show "$unit" -p MemoryCurrent --value 2>/dev/null || echo 0)
cur_mib=$(( cur / 1048576 ))

want_mem="[Service]
MemoryAccounting=yes
MemoryHigh=${high}
MemoryMax=${max}"

# Safety: High must sit above the live RSS, or applying it triggers an
# immediate reclaim storm on a process already over the new soft limit.
high_mib=${high%M}
if [ "$cur_mib" -ge "$high_mib" ]; then
	echo "  REFUSE $unit: current ${cur_mib}MiB >= new High ${high_mib}MiB (would reclaim-storm)"
	exit 3
fi

changes=""
[ -f "$mem" ] && cur_mem=$(cat "$mem") || cur_mem=""
managed_mem="# Managed by ops/memory-tuning/apply.sh from fleet.tsv — do not edit on the node.
$want_mem"
[ "$cur_mem" != "$managed_mem" ] && changes="$changes limits"
[ -f "$legacy" ] && changes="$changes drop-legacy-mimalloc-env"
[ -d "$ctl" ] && changes="$changes drop-setproperty-override"
if [ "$want_stack" = 1 ]; then
	[ -f "$stack" ] || changes="$changes thread-stack"
fi

if [ -z "$changes" ]; then
	echo "  ok $unit: already matches (live ${cur_mib}MiB, High=$((hi_b/1048576)) Max=$((mx_b/1048576)))"
	exit 0
fi

if [ "$dry" = 1 ]; then
	echo "  DRY $unit: would change:$changes  (target High=${high} Max=${max})"
	exit 0
fi

install -d -m 0755 "$d"
printf '%s\n' "$managed_mem" > "$mem"
rm -f "$legacy"
rm -rf "$ctl"
if [ "$want_stack" = 1 ]; then
	printf '%s\n' "# Managed by ops/memory-tuning/apply.sh — do not edit on the node.
[Service]
Environment=THREAD_STACK_SIZE_KB=512" > "$stack"
fi
systemctl daemon-reload
# Apply the cgroup limits to the running service now. --runtime writes to /run
# (does not fight the persistent 20-memory.conf, which the unit re-reads on the
# next start); the value is identical, so live and persisted agree.
systemctl set-property --runtime "$unit" MemoryHigh="$high" MemoryMax="$max"
hi_a=$(systemctl show "$unit" -p MemoryHigh --value)
mx_a=$(systemctl show "$unit" -p MemoryMax --value)
echo "  applied $unit:$changes -> live High=$((hi_a/1048576)) Max=$((mx_a/1048576)) (current ${cur_mib}MiB)"
REMOTE
}

apply_unit() {
	local host="$1" unit="$2" high="$3" max="$4" stack="$5"
	[ "$high" = "-" ] && return 0
	# ssh joins the extra args onto the remote command with spaces, so this runs
	# `sudo bash -s <unit> <high> <max> <stack> <dry>` on the node, with the
	# script arriving on stdin and the args landing as $1..$5.
	ssh -o ConnectTimeout=15 "$host" sudo bash -s \
		"$unit" "$high" "$max" "$stack" "$DRY" <<<"$(remote_script)" \
		|| warn "$host $unit: apply returned non-zero (see message above)"
}

changed=0
while IFS=$'\t ' read -r host ws_high ws_max ss_high ss_max _rest; do
	case "$host" in ''|\#*) continue ;; esac
	[ -n "$ONLY" ] && [ "$host" != "$ONLY" ] && continue
	log "$host"
	apply_unit "$host" outline-ws-rust "$ws_high" "$ws_max" 1
	apply_unit "$host" outline-ss-rust "$ss_high" "$ss_max" 0
	changed=1
done < <(grep -vE '^\s*#|^\s*$' "$TABLE")

[ "$changed" = 1 ] || die "no matching node${ONLY:+ for '$ONLY'} in $TABLE"
[ "$DRY" = 1 ] && log "dry-run: nothing was changed"
exit 0
