#!/usr/bin/env bash
#
# Snapshot a configured fleet node (the "reference") into a self-contained
# bundle that install.sh can unroll onto a fresh node.
#
# What counts as "the node" differs by node family, so the paths, units,
# containers and secrets live in a profile under profiles/ rather than in this
# script. The chosen profile travels inside the bundle, which keeps the bundle
# self-describing on the target.
#
# Runs on a workstation and only reads from the reference over ssh — it never
# writes to it and never restarts anything there.
#
# Usage:
#   ./collect-from-reference.sh --reference sysadm@cloud1.beerloga.su \
#       --profile cloud1 --out ./bundle-cloud1
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

REFERENCE=""
OUT=""
PROFILE=""
FORCE=0

usage() {
    cat <<'EOF'
Usage: collect-from-reference.sh --reference <user@host> --profile <name|path> \
           --out <dir> [--force]

  --reference <user@host>  ssh target of the configured node to snapshot
  --profile <name|path>    profile describing this node family: a name under
                           profiles/ (cloud1, nuxt) or a path to a .conf
  --out <dir>              bundle directory to create
  --force                  overwrite an existing bundle directory

The bundle keeps secrets (service configs, access keys, ACME material, ocserv
passwords) under <dir>/secrets with mode 0700. Treat the whole
directory as sensitive: do not commit it.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --reference) REFERENCE="${2:-}"; shift 2 ;;
        --profile) PROFILE="${2:-}"; shift 2 ;;
        --out) OUT="${2:-}"; shift 2 ;;
        --force) FORCE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage; die "unknown argument: $1" ;;
    esac
done

[ -n "$REFERENCE" ] || { usage; die "--reference is required"; }
[ -n "$OUT" ] || { usage; die "--out is required"; }
[ -n "$PROFILE" ] || { usage; die "--profile is required (try: $(ls "$SCRIPT_DIR/profiles" | sed 's/\.conf$//' | tr '\n' ' '))"; }

need_cmd ssh

PROFILE_FILE="$PROFILE"
[ -f "$PROFILE_FILE" ] || PROFILE_FILE="$SCRIPT_DIR/profiles/$PROFILE.conf"
[ -f "$PROFILE_FILE" ] || die "profile not found: $PROFILE"
PROFILE_NAME="$(basename "$PROFILE_FILE" .conf)"

# Defaults so a profile can leave a section out entirely.
OPT_PATHS=(); OPT_EXCLUDES=""; BIN_PATHS=(); UNIT_PATHS=()
ETC_NGINX_PATHS=(); ETC_SYSCTL_PATHS=(); ETC_DOCKER_PATHS=(); NETWORK_PATHS=()
SECRET_TARS=(); SECRET_TAR_EXCLUDES=""; SECRET_FILES=(); DOCKER_RUN_SCRIPTS=(); ETC_EXTRA_PATHS=()
DOCKER_IMAGE_EXCLUDE_RE=''
PACKAGES_ALLOW_RE=''; PACKAGES_FORCE=()
# shellcheck source=/dev/null
. "$PROFILE_FILE"
log "profile $PROFILE_NAME — ${PROFILE_DESCRIPTION:-no description}"

if [ -e "$OUT" ] && [ "$FORCE" != "1" ]; then
    die "$OUT already exists (pass --force to overwrite)"
fi

REF_SSH() { ssh -o BatchMode=yes "$REFERENCE" "$@"; }

log "probing reference $REFERENCE"
REF_HOST="$(REF_SSH 'hostname -s')" || die "cannot reach $REFERENCE"
REF_ARCH="$(REF_SSH 'uname -m')"
REF_OS="$(REF_SSH '. /etc/os-release && echo "$ID $VERSION_ID"')"
REF_SSH 'sudo -n true' >/dev/null 2>&1 || die "passwordless sudo not available on $REFERENCE"
REF_IPV4="$(REF_SSH "ip -o -4 addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -1")"
REF_IPV6="$(REF_SSH "ip -o -6 addr show scope global | awk '{print \$4}' | cut -d/ -f1 | grep -v '^fd' | head -1")" || true
REF_WAN_IF="$(REF_SSH "ip -o -4 route show default | awk '{print \$5; exit}'")"
# Recorded so the install can tell "this node has its own identity" from "this
# node is a disk-image clone that kept the reference's": a shared machine-id
# means a shared journal id and DHCP DUID between two live hosts.
REF_MACHINE_ID="$(REF_SSH 'cat /etc/machine-id 2>/dev/null' | head -1)" || REF_MACHINE_ID=""
REF_IPV6_PREFIX=""
if [ -n "${REF_IPV6:-}" ]; then
    REF_IPV6_PREFIX="$(REF_SSH "ip -o -6 route show proto kernel | awk '{print \$1}' | grep -vE '^(fe80|fd|fc)' | head -1")" || true
fi
ok "reference: $REF_HOST ($REF_OS, $REF_ARCH, $REF_IPV4 on $REF_WAN_IF${REF_IPV6:+, $REF_IPV6})"

rm -rf "$OUT"
mkdir -p "$OUT/payload" "$OUT/secrets"
chmod 700 "$OUT/secrets"
cp "$PROFILE_FILE" "$OUT/profile.conf"
# Files the repo owns rather than the reference (the unbound stack, for one).
# They travel in the bundle for the same reason profile.conf does: a bundle
# describes a node completely, and re-running an old one reproduces the node it
# described instead of picking up whatever the scripts have grown since.
if [ -d "$SCRIPT_DIR/assets" ]; then
    cp -R "$SCRIPT_DIR/assets" "$OUT/assets"
    dim "assets/ copied into the bundle"
fi

# ---------------------------------------------------------------- tar helpers

# pull_tar <output-file> <exclude-csv> <path...>
# Paths are given relative to / so the archive unrolls with `tar -C /`.
pull_tar() {
    local out="$1"; shift
    local excludes="$1"; shift
    local ex_args="" item
    local IFS_SAVE="$IFS"
    IFS=','
    for item in $excludes; do
        if [ -n "$item" ]; then
            ex_args="$ex_args --exclude='$item'"
        fi
    done
    IFS="$IFS_SAVE"
    # `|| [ $? -eq 1 ]` keeps tar's "file changed as we read it" warning from
    # aborting the whole collection on a live node.
    REF_SSH "sudo tar czf - -C / $ex_args $* 2>/dev/null || [ \$? -eq 1 ]" > "$out"
    [ -s "$out" ] || die "collected empty archive: $out"
    # A truncated stream still looks non-empty; only a full listing proves the
    # archive survived the trip.
    tar tzf "$out" >/dev/null 2>&1 || die "collected a corrupt archive: $out"
    dim "$(basename "$out") — $(wc -c < "$out" | tr -d ' ') bytes"
}

# pull_file <remote-path> <local-path> [mode]
pull_file() {
    REF_SSH "sudo cat '$1'" > "$2" || die "cannot read $1 from reference"
    if [ -n "${3:-}" ]; then
        chmod "$3" "$2"
    fi
}

# Filter a path list down to what actually exists on the reference, so a
# profile may name optional components without failing the collection.
existing_paths() {
    local wanted="$*" found
    found="$(REF_SSH "for p in $wanted; do sudo test -e \"/\$p\" && echo \"\$p\"; done" || true)"
    printf '%s' "$found" | tr '\n' ' '
}

# ------------------------------------------------------------------- payload

collect_group() {
    local label="$1" archive="$2" excludes="$3"; shift 3
    local present
    present="$(existing_paths "$@")"
    if [ -z "$present" ]; then
        warn "$label: nothing to collect (profile lists none of these paths)"
        return 0
    fi
    log "collecting $label"
    # shellcheck disable=SC2086
    pull_tar "$OUT/payload/$archive" "$excludes" $present
}

collect_group "/opt (profile whitelist)" opt.tar.gz "$OPT_EXCLUDES" "${OPT_PATHS[@]}"
collect_group "binaries" usr-local.tar.gz '' "${BIN_PATHS[@]}"
collect_group "systemd units" systemd.tar.gz '' "${UNIT_PATHS[@]}"
collect_group "nginx" etc-nginx.tar.gz '' "${ETC_NGINX_PATHS[@]}"
collect_group "sysctl" etc-sysctl.tar.gz '' "${ETC_SYSCTL_PATHS[@]}"
collect_group "docker daemon config" etc-docker.tar.gz '' "${ETC_DOCKER_PATHS[@]}"
if [ ${#ETC_EXTRA_PATHS[@]} -gt 0 ]; then
    collect_group "extra /etc config" etc-extra.tar.gz '' "${ETC_EXTRA_PATHS[@]}"
fi
if [ ${#NETWORK_PATHS[@]} -gt 0 ]; then
    collect_group "network config (reference only, never applied)" \
        network.tar.gz '' "${NETWORK_PATHS[@]}"
fi

log "collecting root crontab"
# `crontab -l` exits 1 when root has no crontab at all — a bare reference, not
# an error worth aborting the collection for.
if ! REF_SSH 'sudo crontab -l' > "$OUT/crontab.root" 2>/dev/null; then
    : > "$OUT/crontab.root"
    warn "reference has no root crontab — bundling an empty one"
fi

log "collecting docker image list"
# Only images backing a running container: a long-lived node accumulates dozens
# of exited one-shot containers (lego runs, for one) whose images are pulled on
# demand anyway.
if ! REF_SSH 'sudo docker ps --format "{{.Image}}" | sort -u' \
        > "$OUT/docker-images.list" 2>/dev/null; then
    : > "$OUT/docker-images.list"
    warn "cannot list docker images on the reference — bundling an empty list"
elif [ -n "$DOCKER_IMAGE_EXCLUDE_RE" ]; then
    # A container the reference runs but the profile does not carry over.
    dropped="$(grep -E "$DOCKER_IMAGE_EXCLUDE_RE" "$OUT/docker-images.list" | tr '\n' ' ')" || true
    if [ -n "$dropped" ]; then
        grep -vE "$DOCKER_IMAGE_EXCLUDE_RE" "$OUT/docker-images.list" > "$OUT/docker-images.list.tmp" || true
        mv "$OUT/docker-images.list.tmp" "$OUT/docker-images.list"
        dim "image(s) excluded by the profile: $dropped"
    fi
fi

# Containers with no compose file and no accurate script on disk: rebuild a run
# script from what is actually running.
for spec in ${DOCKER_RUN_SCRIPTS[@]+"${DOCKER_RUN_SCRIPTS[@]}"}; do
    container="${spec%%:*}"
    target_path="${spec#*:}"
    log "generating a run script for container '$container'"
    image="$(REF_SSH "sudo docker inspect $container --format '{{.Config.Image}}'" 2>/dev/null || true)"
    if [ -z "$image" ]; then
        warn "no container '$container' on the reference — skipping its run script"
        continue
    fi
    c_env="$(REF_SSH "sudo docker inspect $container --format '{{range .Config.Env}}{{println .}}{{end}}'")"
    c_binds="$(REF_SSH "sudo docker inspect $container --format '{{range .HostConfig.Binds}}{{println .}}{{end}}'")"
    c_caps="$(REF_SSH "sudo docker inspect $container --format '{{range .HostConfig.CapAdd}}{{println .}}{{end}}'")"
    out_file="$OUT/$(basename "$target_path")"
    {
        echo '#!/bin/bash'
        echo '#'
        echo "# Regenerated by collect-from-reference.sh from the running '$container'"
        echo "# container on $REF_HOST. Recreates it; safe to re-run."
        echo 'set -euo pipefail'
        echo
        echo "docker stop $container 2>/dev/null || true"
        echo "docker rm -f $container 2>/dev/null || true"
        echo
        echo 'docker run -d \'
        echo "  --name $container \\"
        echo '  --restart always \'
        echo '  --net=host \'
        echo '  --security-opt no-new-privileges \'
        echo '  --device /dev/net/tun \'
        printf '%s\n' "$c_caps" | while read -r cap; do
            if [ -n "$cap" ]; then
                echo "  --cap-add ${cap#CAP_} \\"
            fi
        done
        printf '%s\n' "$c_binds" | while read -r bind; do
            if [ -n "$bind" ]; then
                echo "  -v $bind \\"
            fi
        done
        # PATH comes from the image; carrying it over would pin the image's own
        # PATH into the run command for no reason.
        printf '%s\n' "$c_env" | while read -r env; do
            case "$env" in
                ""|PATH=*|OC_VERSION=*) continue ;;
            esac
            echo "  -e $env \\"
        done
        echo "  $image"
    } > "$out_file"
    chmod +x "$out_file"
    srv_cn="$(printf '%s\n' "$c_env" | sed -n 's/^SRV_CN=//p' | head -1)"
    [ "$container" = "ocserv" ] && OCSERV_IMAGE="$image" && OCSERV_CN="$srv_cn"
    ok "$container: $image${srv_cn:+ (SRV_CN=$srv_cn)}"
    echo "$target_path" >> "$OUT/docker-run-scripts.list"
done

# ------------------------------------------------------------------- secrets

log "collecting secrets"
for spec in ${SECRET_TARS[@]+"${SECRET_TARS[@]}"}; do
    name="${spec%%:*}"
    paths="${spec#*:}"
    excludes="${SECRET_TAR_EXCLUDES//%REF_HOST%/$REF_HOST}"
    present="$(existing_paths "$paths")"
    if [ -z "$present" ]; then
        warn "secret group '$name': none of its paths exist on the reference"
        continue
    fi
    # shellcheck disable=SC2086
    pull_tar "$OUT/secrets/$name.tar.gz" "$excludes" $present
done

for spec in ${SECRET_FILES[@]+"${SECRET_FILES[@]}"}; do
    remote="${spec%%:*}"
    rest="${spec#*:}"
    name="${rest%%:*}"
    optional="${rest#*:}"
    if REF_SSH "sudo test -f '$remote'"; then
        pull_file "$remote" "$OUT/secrets/$name" 600
    elif [ "$optional" = "optional" ]; then
        dim "optional secret absent on the reference: $remote"
    else
        die "missing secret on the reference: $remote"
    fi
done
chmod 600 "$OUT"/secrets/*

# ------------------------------------------------------------------ manifest

log "writing manifest"
SS_VERSION="$(REF_SSH '/usr/local/bin/outline-ss-rust --version 2>/dev/null' | head -1)" || SS_VERSION=""
WS_VERSION="$(REF_SSH '/usr/local/bin/outline-ws-rust --version 2>/dev/null' | head -1)" || WS_VERSION=""
# save-keys.sh used to pass the keys directory to the binary as
# `--write-access-keys-dir`; since the generator moved to ops/access-keys
# (2026-08-11) it is `--out-dir`. Accept both so a reference node on either side
# still resolves — a reference that matches neither would hand the bundle an
# empty ACCESS_KEYS_DIR and the clone would silently generate nothing.
# Capture just the argument, not the rest of the line: save-keys.sh may keep the
# whole invocation on one physical line, in which case a greedy match would drag
# the following flags into KEYS_DIR.
KEYS_DIR="$(REF_SSH "sed -n 's#.*--out-dir *\([^ ]*\).*#\1#p;s#.*--write-access-keys-dir *\([^ ]*\).*#\1#p' /opt/outline/outline-ss-rust/save-keys.sh 2>/dev/null" | tr -d ' \\' | head -1)" || KEYS_DIR=""

# apt-mark showmanual, filtered by the profile: only packages someone installed
# on purpose for this node family end up in the bundle.
REF_SSH 'apt-mark showmanual | sort' > "$OUT/packages.list.raw"
grep -E "$PACKAGES_ALLOW_RE" "$OUT/packages.list.raw" > "$OUT/packages.list" || true
for pkg in ${PACKAGES_FORCE[@]+"${PACKAGES_FORCE[@]}"}; do
    grep -qx "$pkg" "$OUT/packages.list" || echo "$pkg" >> "$OUT/packages.list"
done
sort -u -o "$OUT/packages.list" "$OUT/packages.list"
rm -f "$OUT/packages.list.raw"

cat > "$OUT/MANIFEST" <<EOF
bundle_version=3
profile=$PROFILE_NAME
reference_target=$REFERENCE
reference_host=$REF_HOST
reference_os=$REF_OS
reference_arch=$REF_ARCH
reference_machine_id=${REF_MACHINE_ID:-}
reference_ipv4=$REF_IPV4
reference_wan_if=$REF_WAN_IF
reference_ipv6=${REF_IPV6:-}
reference_ipv6_prefix=${REF_IPV6_PREFIX:-}
collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ss_version=$SS_VERSION
ws_version=$WS_VERSION
access_keys_dir=$KEYS_DIR
ocserv_image=${OCSERV_IMAGE:-}
ocserv_srv_cn=${OCSERV_CN:-}
EOF

# Written in `sha256sum -c` format (two spaces, ./-prefixed path) so install.sh
# can verify it with the stock tool on the target. sha256_of picks the right
# local binary — collection runs on macOS as often as on Linux.
( cd "$OUT" && find . -type f ! -name SHA256SUMS | sort | while read -r f; do
    printf '%s  %s\n' "$(sha256_of "$f")" "$f"
  done > SHA256SUMS )

ok "bundle written to $OUT"
dim "profile $PROFILE_NAME, reference $REF_HOST${SS_VERSION:+, $SS_VERSION}"
echo
echo "Next:"
echo "  rsync -a --delete '$OUT/' sysadm@<new-node>:/tmp/provision-bundle/"
echo "  rsync -a '$SCRIPT_DIR/' sysadm@<new-node>:/tmp/provision-node/"
echo "  ssh sysadm@<new-node> 'sudo /tmp/provision-node/install.sh --bundle /tmp/provision-bundle --host <name>'"
