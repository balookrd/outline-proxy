#!/usr/bin/env bash
#
# Unroll a bundle produced by collect-from-reference.sh onto a fresh node.
#
# The bundle carries the profile it was collected with, so this script holds no
# per-node-family knowledge: which units to enable, which containers to start,
# how ddns runs and what to verify all come from profile.conf inside the bundle.
#
# Runs ON the target node as root. Every phase is idempotent: re-running the
# script after a failure (or after editing one phase) is safe.
#
# Usage:
#   sudo ./install.sh --bundle /tmp/provision-bundle --host cloud2
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

BUNDLE=""
HOST=""
DOMAIN=""
OCSERV_CN=""
UPLINK_CREDS=""
SHARED_UPLINKS=""
JOIN_SHARED_DNS=0
ALLOW_SHARED_UPLINK_CREDS=0
NEW_IPV6_PREFIX=""
NEW_IPV4=""
NEW_WAN_IF=""
ONLY=""
SKIP=""
# Consumed by confirm() in lib/common.sh; exported so it is visibly in use.
export ASSUME_YES=0

ALL_PHASES="preflight identity packages users files secrets rehost uplinks network ddns certs cron services verify"

usage() {
    cat <<'EOF'
Usage: sudo install.sh --bundle <dir> --host <short-name> [options]

  --bundle <dir>              bundle directory from collect-from-reference.sh
  --host <name>               short hostname of this node, e.g. cloud2
  --domain <fqdn>             defaults to <host>.beerloga.su
  --ipv6-prefix <cidr>        this node's routed IPv6 /64. Dual-stack profiles
                              rewrite ndppd, the firewall and the bring-up unit
                              with it. Defaults to the /64 on this host
  --ipv4 <addr>               this node's public IPv4; defaults to the address
                              on the default route. Rewrites firewall rules that
                              name the reference by address
  --wan-if <iface>            this node's WAN interface; defaults to the one the
                              default route uses. Rewrites firewall rules that
                              name the reference's interface
  --ocserv-cn <fqdn>          ocserv SRV_CN; defaults to any<N>.beerloga.su
                              derived from the digit in --host
  --uplink-creds <file>       per-uplink credentials for this node, as written
                              by register-uplink-user.sh
  --shared-uplink <name>      uplink that deliberately keeps the reference's
                              credentials because the peer accounts for nodes
                              by alias (repeatable)
  --allow-shared-uplink-creds keep the reference's uplink credentials wholesale
  --join-shared-dns           also install the cron line that adds this node to
                              the shared cloud.beerloga.su record. Off by
                              default: joining sends live client traffic here.
  --only <phases>             run only these (space/comma separated)
  --skip <phases>             run everything except these
  --list-phases               print the phase list and exit
  --dry-run                   print what would run, change nothing
  --yes                       do not prompt

Phases: preflight identity packages users files secrets rehost uplinks network
        ddns certs cron services verify

The network phase never touches a live interface: it unpacks the reference's
interface definitions into /root/provision-network-<host> for a human to merge.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --bundle) BUNDLE="${2:-}"; shift 2 ;;
        --host) HOST="${2:-}"; shift 2 ;;
        --domain) DOMAIN="${2:-}"; shift 2 ;;
        --ipv6-prefix) NEW_IPV6_PREFIX="${2:-}"; shift 2 ;;
        --ipv4) NEW_IPV4="${2:-}"; shift 2 ;;
        --wan-if) NEW_WAN_IF="${2:-}"; shift 2 ;;
        --ocserv-cn) OCSERV_CN="${2:-}"; shift 2 ;;
        --uplink-creds) UPLINK_CREDS="${2:-}"; shift 2 ;;
        --shared-uplink) SHARED_UPLINKS="$SHARED_UPLINKS ${2:-}"; shift 2 ;;
        --allow-shared-uplink-creds) ALLOW_SHARED_UPLINK_CREDS=1; shift ;;
        --join-shared-dns) JOIN_SHARED_DNS=1; shift ;;
        --only) ONLY="${2:-}"; shift 2 ;;
        --skip) SKIP="${2:-}"; shift 2 ;;
        --list-phases) echo "$ALL_PHASES" | tr ' ' '\n'; exit 0 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --yes) ASSUME_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage; die "unknown argument: $1" ;;
    esac
done

[ -n "$BUNDLE" ] || { usage; die "--bundle is required"; }
[ -n "$HOST" ] || { usage; die "--host is required"; }
[ -d "$BUNDLE" ] || die "bundle directory not found: $BUNDLE"
[ -f "$BUNDLE/MANIFEST" ] || die "$BUNDLE/MANIFEST missing — not a bundle"
[ -f "$BUNDLE/profile.conf" ] || die "$BUNDLE/profile.conf missing — bundle predates profiles, re-collect it"

REF_HOST="$(manifest_get "$BUNDLE/MANIFEST" reference_host)"
REF_ARCH="$(manifest_get "$BUNDLE/MANIFEST" reference_arch)"
REF_OCSERV_CN="$(manifest_get "$BUNDLE/MANIFEST" ocserv_srv_cn)"
REF_IPV6_PREFIX="$(manifest_get "$BUNDLE/MANIFEST" reference_ipv6_prefix)"
REF_IPV4="$(manifest_get "$BUNDLE/MANIFEST" reference_ipv4)"
REF_WAN_IF="$(manifest_get "$BUNDLE/MANIFEST" reference_wan_if)"
ACCESS_KEYS_DIR="$(manifest_get "$BUNDLE/MANIFEST" access_keys_dir)"
PROFILE_NAME="$(manifest_get "$BUNDLE/MANIFEST" profile)"
[ -n "$REF_HOST" ] || die "MANIFEST has no reference_host"

# Profile defaults, so a profile may leave any section out.
REHOST_FILES=(); REHOST_IPV6_FILES=(); REHOST_IPV4_FILES=(); REHOST_IFACE_FILES=()
COMPOSE_REQUIRED_ARGS=(); VERIFY_SELF_DNS=0
ASSET_FILES=(); NGINX_LOCATIONS=()
ENABLE_UNITS=(); INSTALL_ONLY_UNITS=(); NET_BRINGUP_EXEC=(); NET_BRINGUP_EXEC_STOP=()
NET_BRINGUP_BEFORE=
DOCKER_START=(); VERIFY_UNITS=(); VERIFY_TIMERS=(); VERIFY_METRICS=(); VERIFY_PORTS=()
CERT_DOMAINS=(); DDNS_MODE="none"; DDNS_BUILD=""; DDNS_START=""; DDNS_IMAGE=""
CERT_ISSUE_CMD=""
NGINX_SITE=""; OCCTL_SYMLINK=0; ACCESS_KEYS_REGEN=0; IPV6=0
CERT_NEEDS_WEBROOT=0; REQUIRES_UPLINK_CREDS=0
# shellcheck source=/dev/null
. "$BUNDLE/profile.conf"

DOMAIN="${DOMAIN:-$HOST.beerloga.su}"
# This node's own identity, used to rewrite whatever names the reference's.
# Detected rather than required: on a correctly addressed host the defaults are
# right, and a wrong guess is visible in the rehost report.
NEW_WAN_IF="${NEW_WAN_IF:-$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')}"
NEW_IPV4="${NEW_IPV4:-$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)}"
if [ -z "$NEW_IPV6_PREFIX" ]; then
    # On an IPv4-only host the grep filters everything out and returns 1, which
    # under pipefail would abort the script before it printed anything.
    NEW_IPV6_PREFIX="$(ip -o -6 route show proto kernel 2>/dev/null | awk '{print $1}' \
        | grep -vE '^(fe80|fd|fc)' | head -1)" || NEW_IPV6_PREFIX=""
fi
if [ -z "$OCSERV_CN" ] && [ -n "$REF_OCSERV_CN" ]; then
    # any1.beerloga.su on cloud1 → any2.beerloga.su on cloud2: the node index
    # is what differs, so carry the digit from --host into the ocserv CN.
    node_index="$(printf '%s' "$HOST" | tr -cd '0-9')"
    if [ -n "$node_index" ]; then
        OCSERV_CN="$(printf '%s' "$REF_OCSERV_CN" | sed "s/[0-9][0-9]*/$node_index/")"
    fi
fi

should_run() {
    local phase="$1"
    if [ -n "$ONLY" ]; then
        printf '%s' "$ONLY" | tr ',' ' ' | tr ' ' '\n' | grep -qx "$phase" || return 1
    fi
    if [ -n "$SKIP" ]; then
        printf '%s' "$SKIP" | tr ',' ' ' | tr ' ' '\n' | grep -qx "$phase" && return 1
    fi
    return 0
}

# untar_payload <archive-basename> — a profile that skips a group leaves no
# archive behind, which is not an error.
untar_payload() {
    local archive="$BUNDLE/payload/$1"
    if [ ! -f "$archive" ]; then
        dim "no $1 in this bundle — skipping"
        return 0
    fi
    run tar xzf "$archive" -C /
}

# asset_path <relative-path> — locate a repo-owned asset.
#
# Assets are shipped twice on purpose: collect-from-reference.sh copies the
# assets/ tree into the bundle (a bundle stays self-describing, and its
# SHA256SUMS then covers the assets too), and the same tree travels beside this
# script. The bundle wins, so re-running an old bundle reproduces the node it
# described; a bundle collected before assets existed falls back to the scripts.
asset_path() {
    if [ -f "$BUNDLE/assets/$1" ]; then
        printf '%s' "$BUNDLE/assets/$1"
    elif [ -f "$SCRIPT_DIR/assets/$1" ]; then
        printf '%s' "$SCRIPT_DIR/assets/$1"
    else
        return 1
    fi
}

# ------------------------------------------------------------------ preflight

phase_preflight() {
    log "phase preflight"
    [ "$(id -u)" = "0" ] || die "must run as root (use sudo)"

    local id version arch
    id="$(. /etc/os-release && echo "$ID")"
    version="$(. /etc/os-release && echo "$VERSION_ID")"
    arch="$(uname -m)"
    [ "$id" = "ubuntu" ] || warn "reference was Ubuntu, this host is $id"
    [ "$arch" = "$REF_ARCH" ] || die "arch mismatch: bundle is $REF_ARCH, host is $arch"
    ok "$id $version $arch, profile $PROFILE_NAME, bundle from $REF_HOST"

    if [ -f "$BUNDLE/SHA256SUMS" ] && command -v sha256sum >/dev/null 2>&1; then
        ( cd "$BUNDLE" && sha256sum --quiet -c SHA256SUMS ) \
            || die "bundle checksum verification failed"
        ok "bundle checksums verified"
    else
        warn "no SHA256SUMS in bundle — skipping integrity check"
    fi

    # A node that does not own its own name will issue a certificate for
    # someone else's address and register the wrong DDNS record.
    local resolved local_ips
    # Loopback answers come from this host's own /etc/hosts entry, which says
    # nothing about where the rest of the world sends traffic for this name.
    # `|| resolved=""` matters: with pipefail, a grep that filters everything out
    # returns 1 and would abort the whole phase.
    resolved="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' \
                | grep -v '^127\.' | sort -u | tr '\n' ' ')" || resolved=""
    local_ips="$(ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ')"
    if [ -z "$resolved" ]; then
        warn "$DOMAIN resolves only via /etc/hosts (or not at all) — check public DNS before the certs phase"
    else
        local matched=0 ip
        for ip in $resolved; do
            case " $local_ips " in *" $ip "*) matched=1 ;; esac
        done
        if [ "$matched" = "1" ]; then
            ok "$DOMAIN resolves to this host ($resolved)"
        else
            warn "$DOMAIN resolves to $resolved but this host has $local_ips"
        fi
    fi

    if [ "$IPV6" = "1" ]; then
        if ip -6 route show default | grep -q .; then
            ok "IPv6 default route present"
        else
            warn "profile $PROFILE_NAME is dual-stack but this host has no IPv6 default route"
        fi
        if [ -z "$NEW_IPV6_PREFIX" ] && [ -n "$REF_IPV6_PREFIX" ]; then
            warn "no --ipv6-prefix given: staged network files keep $REF_HOST's $REF_IPV6_PREFIX"
        fi
    fi

    local free_mb
    free_mb="$(df -Pm / | awk 'NR==2 {print $4}')"
    [ "$free_mb" -gt 2048 ] || warn "only ${free_mb}MB free on / — docker images need room"

    if [ "$REQUIRES_UPLINK_CREDS" = "1" ] && [ -z "$UPLINK_CREDS" ] \
       && [ "$ALLOW_SHARED_UPLINK_CREDS" != "1" ]; then
        die "no --uplink-creds given. Generate them with register-uplink-user.sh, or pass --allow-shared-uplink-creds to dial peers as $REF_HOST does."
    fi
    [ -z "$UPLINK_CREDS" ] || [ -f "$UPLINK_CREDS" ] || die "uplink creds file not found: $UPLINK_CREDS"
}

# ------------------------------------------------------------------- identity
#
# What a disk-image clone carries over before any bundle is unrolled: the
# reference's machine-id, its hostname and its /etc/hosts line. None of it comes
# from the bundle, so nothing else in this script would ever notice — and each
# one is a live fault. Two nodes with the same machine-id share a journal id and
# a DHCP DUID; a stale hostname makes the node answer to (and certify) the wrong
# name; and `127.0.1.1 <reference-fqdn>` in /etc/hosts is what a resolver
# running on this host hands out to the whole network (see COMPOSE_REQUIRED_ARGS).

phase_identity() {
    log "phase identity"

    local ref_mid cur_mid
    ref_mid="$(manifest_get "$BUNDLE/MANIFEST" reference_machine_id)"
    cur_mid="$(cat /etc/machine-id 2>/dev/null || true)"
    if [ -z "$cur_mid" ]; then
        warn "no /etc/machine-id — generating one"
        run systemd-machine-id-setup
    elif [ -z "$ref_mid" ]; then
        dim "bundle predates reference_machine_id — cannot tell this node's id from $REF_HOST's"
    elif [ "$cur_mid" = "$ref_mid" ]; then
        warn "machine-id is $REF_HOST's ($cur_mid) — a clone kept it; regenerating"
        run rm -f /etc/machine-id /var/lib/dbus/machine-id
        run systemd-machine-id-setup
        if command -v dbus-uuidgen >/dev/null 2>&1; then
            run bash -c 'dbus-uuidgen --ensure'
        fi
        dim "already-running services keep the old id until this node reboots"
    else
        ok "machine-id is this node's own"
    fi

    local cur_host
    cur_host="$(hostname -s 2>/dev/null || true)"
    if [ "$cur_host" = "$HOST" ]; then
        ok "hostname is $cur_host"
    elif [ "$cur_host" = "$REF_HOST" ]; then
        warn "hostname is still $REF_HOST — setting it to $DOMAIN"
        run hostnamectl set-hostname "$DOMAIN"
    else
        dim "hostname is $cur_host (neither $HOST nor $REF_HOST) — left alone"
    fi

    if [ -f /etc/hosts ] && grep -q "\b$REF_HOST\b" /etc/hosts; then
        warn "/etc/hosts names $REF_HOST — rewriting it to $HOST"
        run sed -i "s/\b$REF_HOST\b/$HOST/g" /etc/hosts
    else
        dim "/etc/hosts does not name $REF_HOST"
    fi
}

# ------------------------------------------------------------------- packages

phase_packages() {
    log "phase packages"
    export DEBIAN_FRONTEND=noninteractive

    if [ ! -f /etc/apt/keyrings/docker.asc ]; then
        run install -m 0755 -d /etc/apt/keyrings
        run bash -c "curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc"
        run chmod a+r /etc/apt/keyrings/docker.asc
    fi
    if [ ! -f /etc/apt/sources.list.d/docker.list ]; then
        local codename
        codename="$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")"
        run bash -c "echo 'deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $codename stable' > /etc/apt/sources.list.d/docker.list"
    fi

    run apt-get update -qq
    # curl/ca-certificates are needed before the docker repo can be fetched, so
    # they are installed unconditionally rather than read from packages.list.
    run apt-get install -y -qq ca-certificates curl gnupg apt-transport-https

    local pkgs
    pkgs="$(tr '\n' ' ' < "$BUNDLE/packages.list")"
    # Word splitting of the package list is deliberate.
    # shellcheck disable=SC2086
    run apt-get install -y -qq $pkgs
    ok "packages installed: $pkgs"

    if [ -f "$BUNDLE/payload/etc-docker.tar.gz" ]; then
        local before after
        before="$(sha256_of /etc/docker/daemon.json 2>/dev/null || echo none)"
        untar_payload etc-docker.tar.gz
        after="$(sha256_of /etc/docker/daemon.json 2>/dev/null || echo none)"
        if [ "$before" != "$after" ]; then
            run systemctl restart docker
            ok "docker daemon.json applied, docker restarted"
        fi
    fi
    run systemctl enable --now docker
}

# ---------------------------------------------------------------------- users

phase_users() {
    log "phase users"
    getent group certs >/dev/null || run groupadd --system certs

    if ! getent passwd outline-ss-rust >/dev/null; then
        run useradd --system --user-group --no-create-home \
            --home-dir /var/lib/outline-ss-rust --shell /usr/sbin/nologin outline-ss-rust
    fi
    if ! getent passwd outline-ws >/dev/null; then
        run useradd --system --user-group --no-create-home \
            --home-dir /home/outline-ws --shell /usr/sbin/nologin outline-ws
    fi

    run usermod -aG certs outline-ss-rust
    if getent passwd sysadm >/dev/null; then
        run usermod -aG certs,docker sysadm
    fi

    run install -d -o outline-ss-rust -g outline-ss-rust -m 0755 /var/lib/outline-ss-rust
    run install -d -o root -g root -m 0755 /var/lib/outline-ws-rust /var/log/outline-ws-rust
    ok "service accounts ready"
}

# ---------------------------------------------------------------------- files
#
# Most of what lands on a node is whatever the reference had. A few files are
# the other way round: the repo owns them and every node gets the same copy.
#
# The unbound stack is why this exists. It was collected-only, so each node kept
# whatever its reference happened to have, and the four live nodes drifted apart
# without anything noticing: cloud1/cloud2 ran unbound-exporter with no
# `restart: unless-stopped`, so it died at the first reboot and never came back,
# while nuxt/nuxt2 had no exporter at all and `control-enable: no` in
# unbound.conf, which would have starved one anyway. Both were found and fixed
# by hand on 2026-08-08. A file listed in ASSET_FILES cannot drift that way: the
# repo copy is written over whatever the bundle carried.

# ASSET_FILES entries are "<asset-path>:<target>[:mode]", the asset path being
# relative to assets/. %HOST% and %DOMAIN% expand to this node's identity, so an
# asset can carry per-node paths (dnsproxy's certificates) and still be one file.
install_asset_files() {
    [ ${#ASSET_FILES[@]} -gt 0 ] || return 0
    local spec src target mode rest source body tmp
    for spec in "${ASSET_FILES[@]}"; do
        src="${spec%%:*}"; rest="${spec#*:}"
        target="${rest%%:*}"; mode="${rest#*:}"
        [ "$mode" != "$target" ] || mode="0644"
        if ! source="$(asset_path "$src")"; then
            warn "asset $src is neither in the bundle nor beside install.sh — $target left as collected"
            continue
        fi
        body="$(sed -e "s|%HOST%|$HOST|g" -e "s|%DOMAIN%|$DOMAIN|g" "$source")"
        if [ -f "$target" ] && [ "$body" = "$(cat "$target")" ]; then
            dim "asset: $target already matches $src"
            continue
        fi
        if [ "$DRY_RUN" = "1" ]; then
            dim "[dry-run] would write $target from assets/$src"
            continue
        fi
        tmp="$(mktemp)"
        printf '%s\n' "$body" > "$tmp"
        install -d -o root -g root -m 0755 "$(dirname "$target")"
        install -m "$mode" -o root -g root "$tmp" "$target"
        rm -f "$tmp"
        ok "asset: wrote $target from assets/$src"
    done
}

# NGINX_LOCATIONS entries are "<location>:<proxy_pass URL>". The site file comes
# from the reference, so a location the reference never had (the unbound
# exporter on nuxt, until 2026-08-08) would otherwise be missing on every node
# cloned from it — and a missing location is invisible from the node itself:
# the exporter answers on 127.0.0.1:9167 while the scrape through 443 404s.
ensure_nginx_locations() {
    [ ${#NGINX_LOCATIONS[@]} -gt 0 ] || return 0
    local site="/etc/nginx/sites-available/$NGINX_SITE"
    [ -f "$site" ] || { warn "nginx: $site not found — cannot ensure locations"; return 0; }

    local spec location url close blocks tmp
    # Locations go into the last server block, which on this site is the only
    # one. Say so rather than guessing silently if a reference grows a second.
    blocks="$(grep -c '^server[[:space:]]*{' "$site")" || blocks=0
    [ "$blocks" -le 1 ] || warn "nginx: $site has $blocks server blocks — locations go into the last one"

    for spec in "${NGINX_LOCATIONS[@]}"; do
        location="${spec%%:*}"; url="${spec#*:}"
        if grep -qF "location $location" "$site"; then
            dim "nginx: $site already serves $location"
            continue
        fi
        close="$(grep -n '^}' "$site" | tail -1 | cut -d: -f1)"
        if [ -z "$close" ]; then
            warn "nginx: no closing brace at column 0 in $site — add $location by hand"
            continue
        fi
        if [ "$DRY_RUN" = "1" ]; then
            dim "[dry-run] would add location $location → $url to $site"
            continue
        fi
        tmp="$(mktemp)"
        awk -v n="$close" -v loc="$location" -v url="$url" \
            'NR == n { printf "    location %s {\n        proxy_pass %s;\n    }\n", loc, url } { print }' \
            "$site" > "$tmp"
        cat "$tmp" > "$site"
        rm -f "$tmp"
        ok "nginx: added location $location → $url"
    done
}

phase_files() {
    log "phase files"
    untar_payload opt.tar.gz
    untar_payload usr-local.tar.gz
    untar_payload systemd.tar.gz
    untar_payload etc-nginx.tar.gz
    untar_payload etc-sysctl.tar.gz
    untar_payload etc-extra.tar.gz

    # After the payload, so a repo-owned file wins over the reference's copy of
    # the same path even when a stale bundle still carries one.
    install_asset_files

    if [ -n "$NGINX_SITE" ]; then
        ensure_nginx_locations
        run ln -sfn "/etc/nginx/sites-available/$NGINX_SITE" "/etc/nginx/sites-enabled/$NGINX_SITE"
    fi
    if [ "$OCCTL_SYMLINK" = "1" ]; then
        run ln -sfn /opt/ocserv/bin/occtl.sh /usr/bin/occtl
    fi
    if [ -n "$ACCESS_KEYS_DIR" ]; then
        run install -d -o root -g root -m 0755 "$ACCESS_KEYS_DIR"
    fi

    # Run scripts regenerated from live containers during collection.
    if [ -f "$BUNDLE/docker-run-scripts.list" ]; then
        local target
        while IFS= read -r target; do
            [ -n "$target" ] || continue
            run install -m 0755 "$BUNDLE/$(basename "$target")" "$target"
        done < "$BUNDLE/docker-run-scripts.list"
    fi

    write_bringup_unit

    run sysctl --system -q
    ok "files unrolled, sysctl applied"
}

# On the reference these commands hang off ifupdown `post-up`/`up` hooks in
# /etc/network/interfaces. That file is not carried over (it also defines the
# reference's addresses and GRE tunnels), and on a netplan/networkd host the
# hooks would never fire anyway — so the same commands are re-expressed as a
# oneshot unit. Without it a clone comes up with no firewall, no MASQUERADE and
# no local route for its /64: an exit node that does not forward and does not
# filter.
write_bringup_unit() {
    [ ${#NET_BRINGUP_EXEC[@]} -gt 0 ] || return 0

    local unit=/etc/systemd/system/post-up.service
    local body cmd
    # Not Documentation=: systemd expects URLs there and logs a warning per word.
    body="[Unit]
Description=Post-up network hooks (firewall, marks, routes) for $HOST
# Generated by ops/provision-node/install.sh from profile $PROFILE_NAME.
Wants=network-online.target
After=network-online.target"
    [ -z "$NET_BRINGUP_BEFORE" ] || body="$body
Before=$NET_BRINGUP_BEFORE"
    body="$body

[Service]
Type=oneshot
RemainAfterExit=yes"
    # network-online.target can be satisfied by IPv4 alone, so the firewall
    # script may run before this node has an IPv6 prefix to detect. Passing it
    # in removes the race: the v6 rules no longer depend on boot ordering.
    if [ "$IPV6" = "1" ] && [ -n "$NEW_IPV6_PREFIX" ]; then
        body="$body
Environment=WAN_V6_PREFIX=$NEW_IPV6_PREFIX"
    fi
    for cmd in "${NET_BRINGUP_EXEC[@]}"; do
        body="$body
ExecStart=${cmd//%IPV6_PREFIX%/$NEW_IPV6_PREFIX}"
    done
    for cmd in ${NET_BRINGUP_EXEC_STOP[@]+"${NET_BRINGUP_EXEC_STOP[@]}"}; do
        body="$body
ExecStop=${cmd//%IPV6_PREFIX%/$NEW_IPV6_PREFIX}"
    done
    body="$body

[Install]
WantedBy=multi-user.target"

    if [ "$DRY_RUN" = "1" ]; then
        dim "[dry-run] would write $unit:"
        printf '%s\n' "$body" | sed 's/^/       /'
        return 0
    fi
    printf '%s\n' "$body" > "$unit"
    chmod 0644 "$unit"
    ok "wrote $unit"
}

# -------------------------------------------------------------------- secrets

phase_secrets() {
    log "phase secrets"
    local archive name
    for archive in "$BUNDLE"/secrets/*.tar.gz; do
        [ -f "$archive" ] || continue
        run tar xzf "$archive" -C /
    done

    if [ -d /etc/outline-ss-rust ]; then
        run chown -R outline-ss-rust:outline-ss-rust /etc/outline-ss-rust
        run chmod 0750 /etc/outline-ss-rust
        run bash -c 'find /etc/outline-ss-rust -maxdepth 1 -type f -exec chmod 0640 {} +'
    fi
    if [ -d /etc/outline-ws-rust ]; then
        run chown -R outline-ws:outline-ws /etc/outline-ws-rust
        run chmod 0750 /etc/outline-ws-rust
        run bash -c 'find /etc/outline-ws-rust -maxdepth 1 -type f -exec chmod 0640 {} +'
        run install -d -o outline-ws -g outline-ws -m 0750 /etc/outline-ws-rust/instances
    fi

    if [ -f "$BUNDLE/secrets/users.txt" ]; then
        run install -m 0644 -o root -g root "$BUNDLE/secrets/users.txt" \
            /opt/outline/outline-ss-rust/users.txt
    fi
    if [ -f "$BUNDLE/secrets/ocserv-ocpasswd" ]; then
        run install -m 0600 -o root -g root "$BUNDLE/secrets/ocserv-ocpasswd" \
            /opt/ocserv/conf/ocpasswd
    fi

    # permission-certs.sh is the reference's own idea of how the ACME material
    # should be owned; run it rather than duplicating the rules here. It adds
    # outline-ss-rust to the certs group, so the account must already exist —
    # the users phase creates it, but --only secrets can skip that.
    if [ -x /opt/beerloga/permission-certs.sh ]; then
        if getent passwd outline-ss-rust >/dev/null; then
            run bash -c '/opt/beerloga/permission-certs.sh || true'
        else
            warn "outline-ss-rust user missing — skipping permission-certs.sh (run the users phase first)"
        fi
    fi
    ok "secrets installed"
}

# --------------------------------------------------------------------- rehost
#
# Everything that names the reference node has to name this one instead. Each
# substitution is checked: a silent miss would leave the new node pointing at
# the reference's certificate or DDNS record.

rehost_file() {
    local file="$1" from="$2" to="$3"
    [ -f "$file" ] || { warn "rehost: $file not found"; return 0; }
    local hits
    hits="$(grep -c "\b$from\b" "$file" || true)"
    if [ "$hits" = "0" ]; then
        if grep -q "\b$to\b" "$file"; then
            dim "rehost: $file already names $to"
        else
            warn "rehost: $file mentions neither $from nor $to — check it by hand"
        fi
        return 0
    fi
    run sed -i "s/\b$from\b/$to/g" "$file"
    dim "rehost: $file — $hits occurrence(s) $from → $to"
}

# Prefixes carry '/' and ':', so escape the separator rather than \b-matching.
rehost_prefix_file() {
    local file="$1" from="$2" to="$3"
    [ -f "$file" ] || { warn "rehost: $file not found"; return 0; }
    if ! grep -qF "$from" "$file"; then
        dim "rehost: $file does not mention $from"
        return 0
    fi
    run sed -i "s|$(printf '%s' "$from" | sed 's/[|]/\\|/g')|$to|g" "$file"
    dim "rehost: $file — IPv6 prefix $from → $to"
}

# A flag the reference's compose file predates and every clone needs. Declared
# by the profile as "<compose-file>:<service>:<flag>" and inserted at the head of
# that service's `command:` list when it is not already there.
#
# The one that made this necessary: dnsproxy resolves from hosts files by
# default, and with `network_mode: host` docker hands the container a copy of
# the node's /etc/hosts — so a resolver serving the whole fleet answered
# `<node>.beerloga.su → 127.0.1.1` for its own name, and everything that dialled
# the node by name landed on the caller's own port 443 instead (2026-08-08).
apply_compose_required_args() {
    local spec file service flag rest
    for spec in ${COMPOSE_REQUIRED_ARGS[@]+"${COMPOSE_REQUIRED_ARGS[@]}"}; do
        file="${spec%%:*}"; rest="${spec#*:}"
        service="${rest%%:*}"; flag="${rest#*:}"
        if [ ! -f "$file" ]; then
            warn "compose: $file not found — cannot ensure $flag on $service"
            continue
        fi
        if grep -qF -- "$flag" "$file"; then
            dim "compose: $service in $file already carries $flag"
            continue
        fi
        local tmp
        tmp="$(mktemp)"
        awk -v service="$service" -v flag="$flag" '
            # Service headers sit at one indent level inside `services:`. Keys
            # nested deeper (volumes:, depends_on:) are part of the service, so
            # only a header at the service level ends the block.
            /^[[:space:]]+[A-Za-z0-9_.-]+:[[:space:]]*$/ {
                header = $0
                sub(/^[[:space:]]+/, "", header)
                sub(/:[[:space:]]*$/, "", header)
                match($0, /^[[:space:]]*/); depth = RLENGTH
                if (header == service) { in_service = 1; svc_depth = depth }
                else if (in_service && depth <= svc_depth) { in_service = 0 }
            }
            in_service && !done && /^[[:space:]]+command:[[:space:]]*$/ {
                print; getline
                # Match the indent of the first list entry so the file stays
                # valid YAML whatever the reference indented with.
                indent = $0; sub(/[^[:space:]].*$/, "", indent)
                print indent "- " flag
                done = 1
                print; next
            }
            { print }
            END { if (!done) print "NOT_APPLIED" > "/dev/stderr" }
        ' "$file" > "$tmp" 2>"$tmp.err"
        if grep -q NOT_APPLIED "$tmp.err" 2>/dev/null; then
            warn "compose: no command: list for service $service in $file — add $flag by hand"
            rm -f "$tmp" "$tmp.err"
            continue
        fi
        if [ "$DRY_RUN" = "1" ]; then
            dim "[dry-run] would add $flag to $service in $file"
        else
            cat "$tmp" > "$file"
            ok "compose: added $flag to $service in $file"
        fi
        rm -f "$tmp" "$tmp.err"
    done
}

# Post-condition for the whole phase. A missed substitution is not cosmetic:
# /opt/unbound/docker-compose.yml kept the reference's `--tls-crt` path on
# cloud2 for a day, and the only reason it did not take DoT down was that the
# container had been started by hand with the right one.
rehost_audit() {
    local file spec leftovers=0
    local files=()
    for file in ${REHOST_FILES[@]+"${REHOST_FILES[@]}"}; do files+=("$file"); done
    for spec in ${COMPOSE_REQUIRED_ARGS[@]+"${COMPOSE_REQUIRED_ARGS[@]}"}; do files+=("${spec%%:*}"); done

    for file in ${files[@]+"${files[@]}"}; do
        [ -f "$file" ] || continue
        if grep -q "\b$REF_HOST\b" "$file"; then
            warn "rehost audit: $file still names $REF_HOST:"
            grep -n "\b$REF_HOST\b" "$file" | sed 's/^/       /' >&2
            leftovers=$((leftovers + 1))
        fi
        # Certificate and key paths are the substitutions that actually break a
        # daemon when they are missed, and a missing file proves the miss.
        local path
        while IFS= read -r path; do
            [ -n "$path" ] || continue
            [ -e "$path" ] || { warn "rehost audit: $file names $path, which does not exist here"; leftovers=$((leftovers + 1)); }
        done < <(grep -oE '/(opt|etc)/[A-Za-z0-9._/-]+\.(crt|key|pem)' "$file" 2>/dev/null | sort -u)
    done

    if [ "$leftovers" = "0" ]; then
        ok "rehost audit clean: nothing still points at $REF_HOST"
    else
        warn "$leftovers rehost problem(s) above — fix them before the services phase starts anything"
    fi
}

phase_rehost() {
    log "phase rehost ($REF_HOST → $HOST)"

    local file
    for file in ${REHOST_FILES[@]+"${REHOST_FILES[@]}"}; do
        rehost_file "$file" "$REF_HOST" "$HOST"
    done

    if [ -f /opt/ocserv/ocserv-run.sh ] && [ -n "$OCSERV_CN" ] && [ -n "$REF_OCSERV_CN" ]; then
        rehost_file /opt/ocserv/ocserv-run.sh \
            "${REF_OCSERV_CN%%.*}" "${OCSERV_CN%%.*}"
    fi

    # The stale update-ocserv.sh from the reference would recreate the container
    # from an image that does not exist here.
    if [ -f /opt/ocserv/ocserv-run.sh ] && [ -f /opt/ocserv/update-ocserv.sh ]; then
        run mv /opt/ocserv/update-ocserv.sh /opt/ocserv/update-ocserv.sh.superseded
    fi

    # A cloned config also carries the reference's cluster identity, and that is
    # not something the install can fix on its own: shard_id must be unique
    # across the mesh, every peer needs the new node in its [cluster] peers, and
    # its address must be allowed on the mesh port fleet-wide.
    if [ -f /etc/outline-ss-rust/config.toml ] \
       && grep -q '^shard_id' /etc/outline-ss-rust/config.toml 2>/dev/null; then
        local shard
        shard="$(sed -n 's/^shard_id *= *\([0-9]*\).*/\1/p' /etc/outline-ss-rust/config.toml | head -1)"
        warn "cluster shard_id=$shard was inherited from $REF_HOST and must be unique — give this node its own, then add it to [cluster] peers and to the mesh allow-list on every peer"
    fi

    if [ -n "$NEW_IPV6_PREFIX" ] && [ -n "$REF_IPV6_PREFIX" ]; then
        for file in ${REHOST_IPV6_FILES[@]+"${REHOST_IPV6_FILES[@]}"}; do
            rehost_prefix_file "$file" "$REF_IPV6_PREFIX" "$NEW_IPV6_PREFIX"
        done
    fi

    # The firewall names the reference by address (its own /32 in the mesh
    # allow-list) and by interface (MASQUERADE, INPUT hook). Both differ here.
    if [ -n "$NEW_IPV4" ] && [ -n "$REF_IPV4" ] && [ "$NEW_IPV4" != "$REF_IPV4" ]; then
        for file in ${REHOST_IPV4_FILES[@]+"${REHOST_IPV4_FILES[@]}"}; do
            rehost_prefix_file "$file" "$REF_IPV4" "$NEW_IPV4"
        done
    fi
    if [ -n "$NEW_WAN_IF" ] && [ -n "$REF_WAN_IF" ] && [ "$NEW_WAN_IF" != "$REF_WAN_IF" ]; then
        for file in ${REHOST_IFACE_FILES[@]+"${REHOST_IFACE_FILES[@]}"}; do
            rehost_file "$file" "$REF_WAN_IF" "$NEW_WAN_IF"
        done
    elif [ -n "$REF_WAN_IF" ]; then
        dim "WAN interface unchanged ($NEW_WAN_IF) — firewall rules need no rewrite"
    fi

    apply_compose_required_args
    rehost_audit
    ok "host-specific references rewritten"
}

# -------------------------------------------------------------------- uplinks
#
# Replace the reference's per-uplink credentials with this node's own. Paths,
# URLs and transport settings stay untouched — only vless_id and password
# inside each [[outline.uplinks]] block (and its fallbacks) change.

phase_uplinks() {
    log "phase uplinks"
    if [ "$REQUIRES_UPLINK_CREDS" != "1" ] && [ -z "$UPLINK_CREDS" ]; then
        dim "profile $PROFILE_NAME does not dial peers — nothing to rewrite"
        return 0
    fi
    if [ -z "$UPLINK_CREDS" ]; then
        warn "keeping $REF_HOST's uplink credentials (--allow-shared-uplink-creds)"
        return 0
    fi

    # Export creds as env vars the awk pass can look up: "beerloga-1.vless_id"
    # becomes UPLK_BEERLOGA_1_VLESS_ID.
    local line name field value norm names=""
    while IFS= read -r line; do
        case "$line" in ''|'#'*) continue ;; esac
        name="${line%%.*}"
        field="${line#*.}"; field="${field%%=*}"
        value="${line#*=}"
        norm="$(normalize_name "$name")"
        case "$field" in
            vless_id) export "UPLK_${norm}_VLESS_ID=$value" ;;
            password) export "UPLK_${norm}_PASSWORD=$value" ;;
            *) warn "ignoring unknown creds field: $field" ;;
        esac
        case " $names " in *" $name "*) ;; *) names="$names $name" ;; esac
    done < "$UPLINK_CREDS"

    # register-uplink-user.sh always writes both fields. A half-filled entry
    # means a hand-edited file, and the missing half would silently leave the
    # reference's credential in place on that wire.
    for name in $names; do
        norm="$(normalize_name "$name")"
        eval "local has_id=\${UPLK_${norm}_VLESS_ID:+yes} has_pw=\${UPLK_${norm}_PASSWORD:+yes}"
        if [ "${has_id:-}" != "yes" ] || [ "${has_pw:-}" != "yes" ]; then
            warn "creds for '$name' define only one of vless_id/password — the other keeps $REF_HOST's value"
        fi
    done

    export UPLK_SHARED="$SHARED_UPLINKS"

    # Checked after the creds file, so a --dry-run on a node that has not been
    # populated yet still validates the credentials it was handed.
    local config=/etc/outline-ws-rust/config.toml
    if [ ! -f "$config" ]; then
        if [ "$DRY_RUN" = "1" ]; then
            dim "[dry-run] $config not installed yet — the secrets phase creates it"
            return 0
        fi
        die "$config missing — run the secrets phase first"
    fi

    local tmpdir tmp
    tmpdir="$(mktemp -d)"
    tmp="$tmpdir/config.toml"
    awk '
        function norm(s,   out) {
            out = toupper(s)
            gsub(/[^A-Z0-9]/, "_", out)
            return out
        }
        # Uplinks the operator marked --shared-uplink keep the reference'"'"'s
        # credentials on purpose: the peer accounts for nodes by alias, not by
        # a separate account per node.
        function is_shared(n,   i, parts, count) {
            count = split(ENVIRON["UPLK_SHARED"], parts, /[ ,]+/)
            for (i = 1; i <= count; i++)
                if (parts[i] == n) return 1
            return 0
        }
        # Any top-level table header ends the current uplink block, except the
        # fallbacks sub-table, which belongs to the uplink above it.
        /^[[:space:]]*\[/ {
            if ($0 ~ /^[[:space:]]*\[\[outline\.uplinks\]\]/) {
                in_uplink = 1; cur = ""
            } else if ($0 ~ /^[[:space:]]*\[\[outline\.uplinks\.fallbacks\]\]/) {
                # keep cur
            } else {
                in_uplink = 0; cur = ""
            }
            print; next
        }
        in_uplink && cur == "" && /^[[:space:]]*name[[:space:]]*=/ {
            match($0, /"[^"]*"/)
            cur = substr($0, RSTART + 1, RLENGTH - 2)
            key = norm(cur)
            if (!(("UPLK_" key "_VLESS_ID") in ENVIRON) &&
                !(("UPLK_" key "_PASSWORD") in ENVIRON)) {
                if (is_shared(cur))
                    print "SHARED:" cur > "/dev/stderr"
                else
                    print "MISSING_CREDS:" cur > "/dev/stderr"
            }
            print; next
        }
        in_uplink && cur != "" && /^[[:space:]]*vless_id[[:space:]]*=/ {
            key = "UPLK_" norm(cur) "_VLESS_ID"
            if (key in ENVIRON) { print "vless_id = \"" ENVIRON[key] "\""; replaced++; next }
        }
        in_uplink && cur != "" && /^[[:space:]]*password[[:space:]]*=/ {
            key = "UPLK_" norm(cur) "_PASSWORD"
            if (key in ENVIRON) { print "password = \"" ENVIRON[key] "\""; replaced++; next }
        }
        { print }
        END { print "REPLACED:" replaced+0 > "/dev/stderr" }
    ' "$config" > "$tmp" 2> "$tmpdir/err"

    local missing shared replaced
    missing="$(sed -n 's/^MISSING_CREDS://p' "$tmpdir/err" | tr '\n' ' ')"
    shared="$(sed -n 's/^SHARED://p' "$tmpdir/err" | tr '\n' ' ')"
    replaced="$(sed -n 's/^REPLACED://p' "$tmpdir/err")"
    if [ -n "$shared" ]; then
        dim "uplink(s) keeping shared credentials by request: $shared"
    fi
    if [ -n "$missing" ]; then
        rm -rf "$tmpdir"
        die "no credentials for uplink(s): $missing — add them to $UPLINK_CREDS, or declare them with --shared-uplink"
    fi
    if [ "${replaced:-0}" -le 0 ]; then
        rm -rf "$tmpdir"
        die "uplink rewrite replaced nothing — check $UPLINK_CREDS"
    fi

    if [ "$DRY_RUN" = "1" ]; then
        dim "[dry-run] would rewrite $replaced credential line(s) in $config"
    else
        cat "$tmp" > "$config"
        chown outline-ws:outline-ws "$config"
        chmod 0640 "$config"
        ok "rewrote $replaced uplink credential line(s)"
    fi
    rm -rf "$tmpdir"
}

# -------------------------------------------------------------------- network
#
# Staging only. Bringing an interface down over ssh on a host with no console
# is how a node gets reinstalled from scratch (2026-07, .104): the reference's
# addresses, tunnels and NDP rules are laid down beside the live files for a
# human to merge, never applied.

phase_network() {
    log "phase network"
    if [ ! -f "$BUNDLE/payload/network.tar.gz" ]; then
        dim "profile $PROFILE_NAME collects no network config"
        return 0
    fi

    local staging="/root/provision-network-$HOST"
    run install -d -m 0700 "$staging"
    run tar xzf "$BUNDLE/payload/network.tar.gz" -C "$staging"

    # Rewrite the reference's identity inside the staged copies so what a human
    # merges is already this node's.
    if [ "$DRY_RUN" != "1" ]; then
        local f
        while IFS= read -r f; do
            sed -i "s/\b$REF_HOST\b/$HOST/g" "$f"
            if [ -n "$NEW_IPV6_PREFIX" ] && [ -n "$REF_IPV6_PREFIX" ]; then
                sed -i "s|$REF_IPV6_PREFIX|$NEW_IPV6_PREFIX|g" "$f"
            fi
        done < <(find "$staging" -type f)
    fi

    warn "network config staged in $staging — NOT applied"
    dim "review and merge by hand; on a remote host do it under a dead-man:"
    dim "  systemd-run --on-active=5min systemctl restart networking  # auto-revert"
    if [ "$IPV6" = "1" ] && [ -z "$NEW_IPV6_PREFIX" ]; then
        warn "staged files still carry $REF_HOST's IPv6 prefix — pass --ipv6-prefix to rewrite them"
    fi
}

# ----------------------------------------------------------------------- ddns

phase_ddns() {
    log "phase ddns"
    case "$DDNS_MODE" in
        venv)
            # The venv is deliberately not carried in the bundle — it embeds
            # absolute interpreter paths and would drift with the host's python.
            if [ ! -x /opt/ddns/venv/bin/python ]; then
                run bash -c 'cd /opt/ddns && virtualenv -q venv && venv/bin/pip install -q -r requirements.txt'
                ok "ddns venv built"
            else
                dim "ddns venv already present"
            fi
            ;;
        docker)
            if [ -n "$DDNS_IMAGE" ] && docker image inspect "$DDNS_IMAGE" >/dev/null 2>&1; then
                # Already present — either built here before, or carried over
                # with `docker save | docker load` because this node cannot
                # reach pypi.org to build it.
                dim "ddns image $DDNS_IMAGE already present — not rebuilding"
            elif [ -n "$DDNS_BUILD" ]; then
                run bash -c "$DDNS_BUILD"
                ok "ddns image built"
            fi
            ;;
        none|"")
            dim "profile $PROFILE_NAME has no ddns component"
            ;;
        *)
            warn "unknown DDNS_MODE '$DDNS_MODE' — skipping"
            ;;
    esac
}

# ---------------------------------------------------------------------- certs

phase_certs() {
    log "phase certs"
    if [ ! -x /opt/beerloga/update-certs.sh ]; then
        dim "no /opt/beerloga/update-certs.sh — skipping"
        return 0
    fi

    # HTTP-01 profiles answer the challenge from the nginx webroot, so the web
    # server has to be up before lego runs — the services phase is too late.
    if [ "$CERT_NEEDS_WEBROOT" = "1" ]; then
        run systemctl enable --now nginx.service
    fi

    local cert="/opt/beerloga/.lego/certificates/$DOMAIN.crt"
    if [ -f "$cert" ]; then
        dim "$DOMAIN certificate already present"
    else
        log "issuing $DOMAIN via lego (this talks to Let's Encrypt)"
        if [ -n "$CERT_ISSUE_CMD" ]; then
            # The reference's update-certs.sh only knows `renew`, which cannot
            # create a certificate that does not exist yet. First issue needs
            # `run`; the profile supplies that command, and the ACME account
            # email is read from the reference's own script rather than pinned
            # in the repository.
            local email issue
            email="$(sed -n 's/^EMAIL=//p' /opt/beerloga/update-certs.sh | head -1)"
            issue="${CERT_ISSUE_CMD//%DOMAIN%/$DOMAIN}"
            issue="${issue//%EMAIL%/$email}"
            run bash -c "$issue"
            if [ "$DRY_RUN" != "1" ] && [ -f "$cert" ]; then
                # update-certs.sh keeps a combined .pem beside each pair.
                run bash -c "cat '$cert' '${cert%.crt}.key' > '${cert%.crt}.pem'"
            fi
        else
            run /opt/beerloga/update-certs.sh
        fi
        if [ "$DRY_RUN" != "1" ] && [ ! -f "$cert" ]; then
            sed -n '1,40p' /opt/beerloga/update-certs.status 2>/dev/null >&2 || true
            die "lego did not produce $cert"
        fi
    fi

    local spec domain
    for spec in ${CERT_DOMAINS[@]+"${CERT_DOMAINS[@]}"}; do
        domain="${spec//%HOST%/$HOST}"
        if [ -f "/opt/beerloga/.lego/certificates/$domain.crt" ]; then
            ok "certificate present: $domain"
        else
            warn "certificate missing: $domain — check /opt/beerloga/update-certs.status"
        fi
    done

    run bash -c '/opt/beerloga/permission-certs.sh || true'
    # ddns serves its API over the host certificate through these symlinks.
    if [ -x /opt/ddns/certs/make_links.sh ]; then
        run bash -c 'cd /opt/ddns/certs && rm -f certificate.pem private_key.pem && ./make_links.sh'
    fi
    ok "certificates in place"
}

# ----------------------------------------------------------------------- cron

phase_cron() {
    log "phase cron"
    local tmp
    tmp="$(mktemp)"
    sed "s/\b$REF_HOST\b/$HOST/g" "$BUNDLE/crontab.root" > "$tmp"

    if [ "$JOIN_SHARED_DNS" != "1" ]; then
        # Joining cloud.beerloga.su is what actually sends client traffic here;
        # keep it a deliberate, separate act.
        # Edits the staged copy, not the live crontab, so it happens even under
        # --dry-run: the preview below is then what would actually be installed.
        sed -i "s|^\(@reboot.*update_domain.py common cloud .*\)$|#\1  # enable to join the shared cloud.beerloga.su record|" "$tmp"
    fi

    if [ "$DRY_RUN" = "1" ]; then
        dim "[dry-run] would install root crontab:"
        grep -vE '^\s*#' "$tmp" | sed 's/^/       /'
    else
        crontab -u root "$tmp"
        ok "root crontab installed"
        if [ "$JOIN_SHARED_DNS" != "1" ]; then
            dim "shared-DNS line left commented out (pass --join-shared-dns to enable)"
        fi
    fi
    rm -f "$tmp"
}

# ------------------------------------------------------------------- services

phase_services() {
    log "phase services"
    run systemctl daemon-reload

    # Access-key files are served by nginx and derived from the SS config, so
    # they are regenerated here rather than copied from the reference.
    if [ "$ACCESS_KEYS_REGEN" = "1" ] && [ -x /opt/outline/outline-ss-rust/save-keys.sh ]; then
        run bash -c '/opt/outline/outline-ss-rust/save-keys.sh > /dev/null || true'
    fi

    local unit
    for unit in ${ENABLE_UNITS[@]+"${ENABLE_UNITS[@]}"}; do
        # A profile may list a unit this particular node does not have (a
        # component replaced by something else, for one). Say so rather than
        # dying halfway through the phase.
        if systemctl cat "$unit" >/dev/null 2>&1; then
            run systemctl enable --now "$unit"
        else
            warn "unit $unit is not installed on this node — skipping"
        fi
    done
    for unit in ${INSTALL_ONLY_UNITS[@]+"${INSTALL_ONLY_UNITS[@]}"}; do
        dim "installed but left disabled by profile: $unit"
    done
    if [ -n "$NGINX_SITE" ]; then
        run systemctl reload nginx
    fi

    log "docker workloads"
    local image
    if [ -s "$BUNDLE/docker-images.list" ]; then
        while IFS= read -r image; do
            case "$image" in ''|'<none>'*) continue ;; esac
            # Pulling is a warm-up, not a requirement: locally built images
            # (the ddns responder, for one) have no registry to pull from and
            # are produced by the ddns phase instead.
            run docker pull -q "$image" || warn "cannot pull $image — expected for locally built images"
        done < "$BUNDLE/docker-images.list"
    else
        warn "bundle has no docker image list — containers will pull on first run"
    fi

    local cmd
    for cmd in ${DOCKER_START[@]+"${DOCKER_START[@]}"}; do
        case "$cmd" in
            /*) if [ ! -x "${cmd%% *}" ]; then
                    if [ "$DRY_RUN" = "1" ]; then
                        dim "[dry-run] ${cmd%% *} arrives with the files phase"
                    else
                        warn "missing start script: $cmd"
                    fi
                    continue
                fi ;;
        esac
        run bash -c "$cmd > /dev/null"
    done
    if [ -n "$DDNS_START" ]; then
        run bash -c "$DDNS_START > /dev/null"
    fi
    ok "services started"
}

# --------------------------------------------------------------------- verify

phase_verify() {
    log "phase verify"
    local failures=0

    local unit
    for unit in ${VERIFY_UNITS[@]+"${VERIFY_UNITS[@]}"}; do
        if systemctl is-active --quiet "$unit"; then
            ok "unit $unit active"
        else
            warn "unit $unit NOT active"
            failures=$((failures + 1))
        fi
    done

    for unit in ${VERIFY_TIMERS[@]+"${VERIFY_TIMERS[@]}"}; do
        if systemctl is-active --quiet "$unit"; then
            ok "timer $unit active"
        else
            warn "timer $unit NOT active"
            failures=$((failures + 1))
        fi
    done

    local ep
    for ep in ${VERIFY_METRICS[@]+"${VERIFY_METRICS[@]}"}; do
        set -- $ep
        if curl -fsS --max-time 5 "http://$1" >/dev/null 2>&1; then
            ok "$2 metrics answer on $1"
        else
            warn "$2 metrics DO NOT answer on $1"
            failures=$((failures + 1))
        fi
    done

    local port
    for port in ${VERIFY_PORTS[@]+"${VERIFY_PORTS[@]}"}; do
        if ss -tulnH "sport = :$port" | grep -q .; then
            ok "port $port listening"
        else
            warn "port $port NOT listening"
            failures=$((failures + 1))
        fi
    done

    # An exporter listening on loopback proves nothing about the scrape, which
    # arrives through nginx on 443. This is the half that was missing on
    # nuxt/nuxt2: everything local looked fine and the metrics never left.
    local spec
    for spec in ${NGINX_LOCATIONS[@]+"${NGINX_LOCATIONS[@]}"}; do
        if grep -qF "location ${spec%%:*}" "/etc/nginx/sites-available/$NGINX_SITE" 2>/dev/null; then
            ok "nginx serves ${spec%%:*}"
        else
            warn "nginx does NOT serve ${spec%%:*} — the scrape through 443 will 404"
            failures=$((failures + 1))
        fi
    done

    # A node whose own resolver misnames it takes down everything that reaches
    # this node by name, while every check above still passes: the daemons are
    # up, the ports listen, and the answer is simply wrong.
    if [ "$VERIFY_SELF_DNS" = "1" ]; then
        if ! command -v dig >/dev/null 2>&1; then
            dim "dig not installed — skipping the resolver self-check"
        else
            local via answer=""
            for via in "$NEW_IPV4" 127.0.0.1; do
                [ -n "$via" ] || continue
                answer="$(dig +short +time=3 +tries=1 "@$via" "$DOMAIN" A 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')" || answer=""
                [ -z "$answer" ] || break
            done
            case "$answer" in
                "")
                    warn "this node's resolver gave no answer for $DOMAIN"
                    failures=$((failures + 1)) ;;
                *127.*)
                    warn "resolver answers $DOMAIN → $answer: a hosts-file entry is leaking into DNS"
                    dim "  every node that dials $DOMAIN then lands on its own loopback instead"
                    dim "  fix: --hosts-file-enabled=false on dnsproxy (assets/unbound/docker-compose.entry.yml), and /etc/hosts"
                    failures=$((failures + 1)) ;;
                *"$NEW_IPV4"*)
                    ok "resolver answers $DOMAIN → $answer" ;;
                *)
                    warn "resolver answers $DOMAIN → $answer but this host is $NEW_IPV4"
                    failures=$((failures + 1)) ;;
            esac
        fi
    fi

    if [ "$IPV6" = "1" ]; then
        if ip -6 route show default | grep -q .; then
            ok "IPv6 default route present"
        else
            warn "no IPv6 default route on a dual-stack profile"
            failures=$((failures + 1))
        fi
        if systemctl is-active --quiet ndppd 2>/dev/null; then
            ok "ndppd active"
        else
            warn "ndppd NOT active — the routed /64 will not answer neighbour solicitations"
            failures=$((failures + 1))
        fi
        if [ -n "$NEW_IPV6_PREFIX" ]; then
            if ip -6 route show table local | grep -q "local ${NEW_IPV6_PREFIX%%/*}"; then
                ok "local route for $NEW_IPV6_PREFIX present"
            else
                warn "no local route for $NEW_IPV6_PREFIX — traffic to addresses in the /64 will not be accepted"
                failures=$((failures + 1))
            fi
        fi
    fi

    # An exit node that does not masquerade forwards nothing.
    if [ ${#NET_BRINGUP_EXEC[@]} -gt 0 ]; then
        if iptables -t nat -S POSTROUTING 2>/dev/null | grep -q -- "-j MASQUERADE"; then
            ok "IPv4 MASQUERADE rule present"
        else
            warn "no IPv4 MASQUERADE rule — check post-up.service and /opt/network/iptables-init.sh"
            failures=$((failures + 1))
        fi
    fi

    local expected running
    # grep -c exits 1 on a zero count, so the fallback goes on the assignment —
    # `|| echo 0` inside the substitution would append a second line instead.
    expected="$(grep -c . "$BUNDLE/docker-images.list")" || expected=0
    running="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -c . )" || running=0
    dim "docker: $running container(s) running (bundle lists $expected image(s))"
    docker ps --format '  {{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null || true

    echo
    if [ "$failures" = "0" ]; then
        ok "verification passed"
    else
        warn "$failures check(s) failed — inspect with: journalctl -u <unit> -n 50"
    fi

    echo
    log "not done automatically:"
    if [ "$JOIN_SHARED_DNS" != "1" ]; then
        dim "• $HOST is NOT in the shared cloud.beerloga.su record — clients still go to $REF_HOST"
    fi
    if [ -f "$BUNDLE/payload/network.tar.gz" ]; then
        dim "• network config staged in /root/provision-network-$HOST, never applied"
    fi
    if [ "$REQUIRES_UPLINK_CREDS" = "1" ]; then
        dim "• peer nodes must know this node's uplink account (register-uplink-user.sh)"
    fi
    if [ ${#NGINX_LOCATIONS[@]} -gt 0 ]; then
        dim "• nothing scrapes $HOST yet — add it to /opt/victoria-metrics/data/scrape.yaml on .102"
        dim "  (one target block per job; see assets/victoria-metrics/ for the unbound-exporter one)"
    fi
    if [ -f /opt/ocserv/conf/ocpasswd ]; then
        dim "• ocserv users live in /opt/ocserv/conf/ocpasswd — copied from $REF_HOST"
    fi
}

# ----------------------------------------------------------------------- main

log "provisioning $HOST ($DOMAIN) from a $REF_HOST bundle, profile $PROFILE_NAME"
if [ "$DRY_RUN" = "1" ]; then
    warn "dry-run: nothing will be changed"
else
    dim "installs packages, unrolls /opt and /usr/local, writes service configs,"
    dim "issues a certificate for $DOMAIN and starts every unit and container."
    if ! confirm "Provision this host as $HOST from the $REF_HOST bundle?"; then
        die "aborted"
    fi
fi

for phase in $ALL_PHASES; do
    if should_run "$phase"; then
        "phase_$phase"
    else
        dim "skipping phase $phase"
    fi
done

# files/secrets lay down the reference's own copies; rehost is what turns them
# into this node's. Running the first without the second silently restores the
# reference's identity — its ndppd prefix, [outbound] ipv6_prefix, certificate
# paths and cert domains — and nothing else complains about it.
if { should_run files || should_run secrets; } && ! should_run rehost; then
    echo
    warn "phases files/secrets ran without rehost: this node now carries $REF_HOST's own values again"
    warn "run: install.sh --bundle $BUNDLE --host $HOST --only rehost"
fi

echo
ok "install.sh finished for $HOST"
