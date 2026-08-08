#!/usr/bin/env bash
#
# Announce a new node to the peers it dials through, and write the credentials
# file that install.sh --uplink-creds consumes.
#
# Two kinds of peer, because the fleet has two conventions:
#
#   --peer        the peer keeps one account per node. The new node gets its own
#                 account, cloned from the reference node's account (same secret
#                 paths and fwmark) with fresh credentials.
#   --alias-peer  the peer serves all cloud nodes through one shared account
#                 (the Russia group's "cloud" user). Nothing is created; the new
#                 node's address is added to that account's [users.aliases] so
#                 its traffic is accounted separately. Credentials stay shared,
#                 so no creds are written for those uplinks.
#
# Both paths refuse to write to a binary that predates the control-API
# persistence fix (b48525b5) — an older build rewrites config.toml on user
# writes and drops the other users with it. Neither path restarts anything.
#
# Usage:
#   ./register-uplink-user.sh --user cloud2 --template cloud1 \
#       --out ./cloud2-uplink-creds \
#       --peer nuxt:sysadm@nuxt.beerloga.su \
#       --peer senko:sysadm@senko.beerloga.su \
#       --peer aeza:sysadm@aeza.beerloga.su \
#       --alias-cidr 87.242.85.181/32 \
#       --alias-peer mmv@198.18.1.104:cloud \
#       --alias-peer mmv@198.18.1.102:cloud
#
# The --peer key is the uplink `name` in the new node's ws-rust config, not a
# hostname. A peer whose account for the reference node goes by another id
# carries its own template as a third segment: --peer foo:sysadm@host:othername
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

USER_ID=""
TEMPLATE_ID=""
OUT=""
PEERS=""
ALIAS_PEERS=""
ALIAS_CIDR=""
FORCE=0
APPEND=0
# Parts of the fleet are not reachable directly from every workstation, so all
# ssh calls can be routed through a jump host.
JUMP=""
SSH_OPTS=( -o BatchMode=yes -o ConnectTimeout=10 )

usage() {
    cat <<'EOF'
Usage: register-uplink-user.sh --user <id> [--template <id>] [--out <file>] \
           [--peer <uplink-name>:<ssh-target>[:<template-id>]] ... \
           [--alias-cidr <cidr> --alias-peer <ssh-target>:<shared-user>] ...

  --user <id>        the new node, e.g. cloud2
  --template <id>    default account to clone on --peer hosts, e.g. cloud1
  --out <file>       credentials file for install.sh --uplink-creds
  --peer <spec>      peer that keeps per-node accounts (repeatable)
  --alias-peer <s>   peer that shares one account across nodes: add the new
                     node to its [users.aliases] instead (repeatable)
  --alias-cidr <c>   the new node's address, e.g. 87.242.85.181/32
  --jump <ssh-target> reach every peer through this host (ssh -J), for peers
                     that are not routable from here
  --append           add to an existing creds file instead of truncating it,
                     so peers can be registered in several passes
  --force            rotate credentials if the account already exists
  --dry-run          show what would be sent, change nothing

The output file contains live credentials — mode 0600, do not commit it.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --user) USER_ID="${2:-}"; shift 2 ;;
        --template) TEMPLATE_ID="${2:-}"; shift 2 ;;
        --out) OUT="${2:-}"; shift 2 ;;
        --peer) PEERS="$PEERS ${2:-}"; shift 2 ;;
        --alias-peer) ALIAS_PEERS="$ALIAS_PEERS ${2:-}"; shift 2 ;;
        --alias-cidr) ALIAS_CIDR="${2:-}"; shift 2 ;;
        --jump) JUMP="${2:-}"; shift 2 ;;
        --append) APPEND=1; shift ;;
        --force) FORCE=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage; die "unknown argument: $1" ;;
    esac
done

[ -n "$USER_ID" ] || { usage; die "--user is required"; }
[ -n "$PEERS$ALIAS_PEERS" ] || { usage; die "at least one --peer or --alias-peer is required"; }
[ -z "$PEERS" ] || [ -n "$OUT" ] || { usage; die "--out is required when --peer is used"; }
[ -z "$ALIAS_PEERS" ] || [ -n "$ALIAS_CIDR" ] || { usage; die "--alias-cidr is required when --alias-peer is used"; }

need_cmd ssh
need_cmd python3

# How to reach the current peer, decided once per peer by peer_connect: some
# are routable from here, some only through the jump host, and jumping through
# the host you are connecting to hangs.
PEER_SSH_ARGS=()
peer_ssh() {
    ssh "${SSH_OPTS[@]}" ${PEER_SSH_ARGS[@]+"${PEER_SSH_ARGS[@]}"} "$@"
}

if [ -n "$PEERS" ] && [ "$DRY_RUN" != "1" ] && [ "$APPEND" != "1" ]; then
    : > "$OUT"
    chmod 600 "$OUT"
    printf '# uplink credentials for %s, generated %s\n' \
        "$USER_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT"
fi

gen_uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }

gen_password() {
    # 32 random bytes, base64 — the key length the 2022-blake3-* ciphers on the
    # fleet's fallback wires expect.
    python3 -c 'import base64, os; print(base64.b64encode(os.urandom(32)).decode())'
}

# peer_connect <ssh-target> — verify access, verify the binary carries the
# control-API persistence fix, and set PEER_LISTEN / PEER_TOKEN for peer_curl.
# Returns 1 when the peer must be skipped.
peer_connect() {
    local target="$1"
    # Direct first, jump host only as a fallback — otherwise a peer that is
    # reachable from here would be dragged through an unnecessary hop.
    if ssh "${SSH_OPTS[@]}" "$target" 'sudo -n true' >/dev/null 2>&1; then
        PEER_SSH_ARGS=()
    elif [ -n "$JUMP" ] && [ "$target" != "$JUMP" ] \
         && ssh "${SSH_OPTS[@]}" -J "$JUMP" "$target" 'sudo -n true' >/dev/null 2>&1; then
        PEER_SSH_ARGS=( -J "$JUMP" )
        dim "reached through $JUMP"
    else
        warn "$target: no ssh access with passwordless sudo (tried directly${JUMP:+ and via $JUMP}) — SKIPPED"
        return 1
    fi

    # Distinguish "old binary" from "cannot read the binary": the first is a
    # real refusal, the second would otherwise masquerade as one.
    if ! peer_ssh "$target" 'sudo test -r /usr/local/bin/outline-ss-rust'; then
        warn "$target: cannot read /usr/local/bin/outline-ss-rust — SKIPPED"
        return 1
    fi
    if ! peer_ssh "$target" 'sudo grep -a -q "failed to serialize user entry as TOML" /usr/local/bin/outline-ss-rust'; then
        warn "$target: outline-ss-rust predates the control-API persistence fix — writing users would corrupt its config.toml"
        warn "$target: SKIPPED. Upgrade the binary there first, then re-run for this peer."
        return 1
    fi

    local control
    control="$(peer_ssh "$target" "sudo sed -n '/^\[control\]/,/^\[/p' /etc/outline-ss-rust/config.toml")"
    PEER_TOKEN="$(printf '%s\n' "$control" | sed -n 's/^token *= *"\(.*\)"/\1/p' | head -1)"
    PEER_LISTEN="$(printf '%s\n' "$control" | sed -n 's/^listen *= *"\(.*\)"/\1/p' | head -1)"
    [ -n "$PEER_TOKEN" ] || die "$target: no control token in /etc/outline-ss-rust/config.toml"
    PEER_LISTEN="${PEER_LISTEN:-127.0.0.1:9190}"
    dim "control API at $PEER_LISTEN"
    return 0
}

# peer_curl <ssh-target> <method> <path> [body] — prints the HTTP status.
# The response body goes to $PEER_BODY_FILE, read it with peer_body: peer_curl
# is called in a command substitution, so a variable set here would not survive.
PEER_BODY_FILE="$(mktemp)"
trap 'rm -f "$PEER_BODY_FILE"' EXIT

peer_curl() {
    local target="$1" method="$2" path="$3" body="${4:-}"
    if [ -n "$body" ]; then
        printf '%s' "$body" | peer_ssh "$target" \
            "curl -sS -o /dev/stderr -w '%{http_code}' -X $method 'http://$PEER_LISTEN$path' \
             -H 'Authorization: Bearer $PEER_TOKEN' -H 'Content-Type: application/json' -d @-" \
            2> "$PEER_BODY_FILE"
    else
        peer_ssh "$target" \
            "curl -sS -o /dev/stderr -w '%{http_code}' -X $method 'http://$PEER_LISTEN$path' \
             -H 'Authorization: Bearer $PEER_TOKEN'" 2> "$PEER_BODY_FILE"
    fi
}

peer_body() { cat "$PEER_BODY_FILE"; }

# ------------------------------------------------- peers with per-node accounts

for peer in $PEERS; do
    name="${peer%%:*}"
    rest="${peer#*:}"
    case "$rest" in
        *:*) target="${rest%%:*}"; template="${rest#*:}" ;;
        *)   target="$rest"; template="$TEMPLATE_ID" ;;
    esac
    [ -n "$name" ] && [ -n "$target" ] || die "malformed --peer (want name:ssh-target[:template]): $peer"
    [ -n "$template" ] || die "no template for peer '$name' — pass --template or name it in the --peer spec"

    echo
    log "peer $name → $target (template: $template)"
    peer_connect "$target" || continue

    code="$(peer_curl "$target" GET "/control/users/$template")" || code=""
    template_json="$(peer_body)"
    [ "$code" = "200" ] || die "$target: template user '$template' not found (HTTP $code)"

    code="$(peer_curl "$target" GET "/control/users/$USER_ID")" || code=""
    if [ "$code" = "200" ] && [ "$FORCE" != "1" ]; then
        warn "$target: user '$USER_ID' already exists — leaving it alone (pass --force to rotate its credentials)"
        warn "$target: no credentials written for uplink '$name'; supply them by hand or re-run with --force"
        continue
    fi

    vless_id="$(gen_uuid)"
    password="$(gen_password)"

    # Copy the routing-visible fields from the template so the new account is
    # reachable on exactly the same wires; only the credentials differ.
    body="$(printf '%s' "$template_json" | python3 -c '
import json, sys
template = json.load(sys.stdin)
out = {"id": sys.argv[1], "password": sys.argv[2], "vless_id": sys.argv[3]}
for key in ("method", "fwmark", "ws_path_tcp", "ws_path_udp", "ws_path_ss",
            "ws_path_vless", "xhttp_path_vless", "xhttp_path_tcp",
            "xhttp_path_udp", "xhttp_path_ss"):
    value = template.get(key)
    if value is not None:
        out[key] = value
json.dump(out, sys.stdout)
' "$USER_ID" "$password" "$vless_id")"

    if [ "$DRY_RUN" = "1" ]; then
        dim "[dry-run] POST /control/users on $target:"
        printf '%s' "$body" | python3 -c '
import json, sys
doc = json.load(sys.stdin)
doc["password"] = "REDACTED"
print("       " + json.dumps(doc, indent=2).replace("\n", "\n       "))
'
        continue
    fi

    if [ "$code" = "200" ]; then
        # PATCH addresses the user through the path; the update payload has no
        # id field, so send the body without it.
        patch_body="$(printf '%s' "$body" | python3 -c '
import json, sys
doc = json.load(sys.stdin)
doc.pop("id", None)
json.dump(doc, sys.stdout)
')"
        code="$(peer_curl "$target" PATCH "/control/users/$USER_ID" "$patch_body")" || code=""
    else
        code="$(peer_curl "$target" POST "/control/users" "$body")" || code=""
    fi
    case "$code" in
        200|201) ok "$target: user '$USER_ID' registered" ;;
        *) die "$target: control API returned HTTP $code: $(peer_body)" ;;
    esac

    {
        printf '%s.vless_id=%s\n' "$name" "$vless_id"
        printf '%s.password=%s\n' "$name" "$password"
    } >> "$OUT"
    dim "credentials for uplink '$name' appended to $OUT"
done

# ------------------------------------------------ peers with one shared account

for peer in $ALIAS_PEERS; do
    target="${peer%%:*}"
    shared_user="${peer#*:}"
    [ -n "$target" ] && [ -n "$shared_user" ] && [ "$target" != "$peer" ] \
        || die "malformed --alias-peer (want ssh-target:shared-user): $peer"

    echo
    log "alias peer $target (shared account: $shared_user)"
    peer_connect "$target" || continue

    code="$(peer_curl "$target" GET "/control/users/$shared_user")" || code=""
    [ "$code" = "200" ] || die "$target: shared user '$shared_user' not found (HTTP $code)"

    # The control API replaces the whole alias map, so merge here and send the
    # union — never just the new entry.
    merged="$(peer_body | python3 -c '
import json, sys
user = json.load(sys.stdin)
name, cidr = sys.argv[1], sys.argv[2]
aliases = dict(user.get("aliases") or {})
if aliases.get(name) == cidr:
    print("UNCHANGED")
    sys.exit(0)
aliases[name] = cidr
json.dump({"aliases": aliases}, sys.stdout)
' "$USER_ID" "$ALIAS_CIDR")"

    if [ "$merged" = "UNCHANGED" ]; then
        ok "$target: alias '$USER_ID' → $ALIAS_CIDR already present"
        continue
    fi

    if [ "$DRY_RUN" = "1" ]; then
        dim "[dry-run] PATCH /control/users/$shared_user on $target:"
        printf '%s' "$merged" | python3 -c '
import json, sys
print("       " + json.dumps(json.load(sys.stdin), indent=2).replace("\n", "\n       "))
'
        continue
    fi

    code="$(peer_curl "$target" PATCH "/control/users/$shared_user" "$merged")" || code=""
    case "$code" in
        200) ok "$target: alias '$USER_ID' → $ALIAS_CIDR added to '$shared_user'" ;;
        *) die "$target: control API returned HTTP $code: $(peer_body)" ;;
    esac
done

echo
if [ "$DRY_RUN" = "1" ]; then
    ok "dry-run finished, nothing was changed"
else
    if [ -n "$PEERS" ]; then
        ok "credentials written to $OUT"
        dim "feed it to the new node: install.sh --uplink-creds $OUT --only uplinks"
    fi
    if [ -n "$ALIAS_PEERS" ]; then
        dim "alias peers keep shared credentials — mark those uplinks with install.sh --shared-uplink <name>"
    fi
    dim "then restart the client there: systemctl restart outline-ws-rust"
fi
