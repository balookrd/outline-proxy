# shellcheck shell=bash
#
# Shared helpers for the provision-node scripts.
#
# Sourced by collect-from-reference.sh (runs on a workstation), install.sh
# (runs on the target node) and register-uplink-user.sh (runs on a workstation
# and talks to peer nodes over ssh). Keep it POSIX-ish bash 3.2 compatible:
# collect runs on macOS, whose /bin/bash is still 3.2 — no associative arrays,
# no ${var,,}.

set -o pipefail

: "${DRY_RUN:=0}"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_DIM=""; C_OFF=""
fi

log()  { printf '%s==>%s %s\n' "$C_BLUE" "$C_OFF" "$*"; }
ok()   { printf '%s  ok%s %s\n' "$C_GREEN" "$C_OFF" "$*"; }
warn() { printf '%swarn%s %s\n' "$C_YELLOW" "$C_OFF" "$*" >&2; }
die()  { printf '%serr %s %s\n' "$C_RED" "$C_OFF" "$*" >&2; exit 1; }
dim()  { printf '%s     %s%s\n' "$C_DIM" "$*" "$C_OFF"; }

# Echo the command, then run it — unless DRY_RUN is set, in which case only echo.
run() {
    if [ "$DRY_RUN" = "1" ]; then
        printf '%s     [dry-run] %s%s\n' "$C_DIM" "$*" "$C_OFF"
        return 0
    fi
    printf '%s     + %s%s\n' "$C_DIM" "$*" "$C_OFF"
    "$@"
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# normalize_name <string> — uppercase, non-alphanumerics folded to '_'.
# Used to turn uplink names ("beerloga-1") into env-var fragments.
normalize_name() {
    printf '%s' "$1" | tr '[:lower:]' '[:upper:]' | tr -c '[:alnum:]' '_' | sed 's/_*$//'
}

# sha256_of <file> — portable digest (coreutils on Linux, BSD tool on macOS).
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# manifest_get <manifest-file> <key> — read a `key=value` line.
manifest_get() {
    sed -n "s/^$2=//p" "$1" | head -1
}

# confirm <prompt> — interactive y/N gate, auto-yes when ASSUME_YES=1.
confirm() {
    if [ "${ASSUME_YES:-0}" = "1" ]; then
        return 0
    fi
    printf '%s [y/N] ' "$1"
    read -r reply
    case "$reply" in
        y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}
