#!/usr/bin/env bash
set -Eeuo pipefail

# Access-key path invariant.
#
# The nodes serve <user>.conf / <user>.json / <user>.txt — files that carry
# every user's Shadowsocks password and vless_id — out of one directory whose
# name is unguessable-by-design. nginx puts no auth in front of it and the
# filenames are plain user ids, so that one path segment is the whole access
# control. It belongs in the node's config.toml (`[access_keys] write_dir`) and
# in nothing that gets committed; ops/access-keys/README.md spells out the rule.
#
# This gate is what keeps the rule from decaying back:
#
#  1. No committed *.pyc / __pycache__. Not hygiene — provenance: the path once
#     survived a history rewrite inside a committed .pyc, because textual
#     rewriting tools skip binary blobs. A secret that can only travel in a
#     compiled artifact is a secret no text search will find.
#  2. No random-looking path segment in a served-directory position: under
#     /var/www/html, in an nginx `location ^/...`, or as the first segment of a
#     URL. "Random-looking" is deliberately narrow — 12+ chars of [A-Za-z0-9_-]
#     mixing upper, lower and digits — so ordinary paths (`access-keys`,
#     `nanopi-r5c-k3s`, `refs/heads/main`) never trip it while a 21-char
#     generated prefix always does.
#  3. No hard-coded output directory back in the generator: the default is the
#     config, and a fallback constant would publish the path in source again.

cd "$(dirname "$0")/../.."

fail=0

# Placeholders that legitimately stand where the real segment would be. A
# placeholder is spelled to be obvious in a diff; keep this list short.
PLACEHOLDERS=(
  __KEYS_PREFIX__
  __HEARTBEAT_TOKEN__
)

is_placeholder() {
  local candidate=$1 known
  for known in "${PLACEHOLDERS[@]}"; do
    [ "$candidate" = "$known" ] && return 0
  done
  return 1
}

# A segment that looks generated rather than written by a human: long, and
# drawing on all three character classes.
looks_generated() {
  local segment=$1
  [ "${#segment}" -ge 12 ] || return 1
  case $segment in
    *[A-Z]*) ;;
    *) return 1 ;;
  esac
  case $segment in
    *[a-z]*) ;;
    *) return 1 ;;
  esac
  case $segment in
    *[0-9]*) ;;
    *) return 1 ;;
  esac
  return 0
}

# ── 1. compiled Python must not be tracked ──────────────────────────────────

compiled=$(git ls-files -- '*.pyc' '*__pycache__/*' || true)
if [ -n "$compiled" ]; then
  echo "::error::compiled Python is tracked; a secret inside it survives textual history rewriting:"
  echo "$compiled"
  fail=1
fi

# ── 2. no generated-looking segment in a served-directory position ──────────

# `grep -o` prints just the match, so the candidate segment is the tail of it.
# -I skips binary files; the pyc gate above is what covers those.
hits=$(grep -rEIno \
  --exclude-dir=.git --exclude-dir=target --exclude-dir=vendor \
  --exclude-dir=node_modules --exclude-dir=build --exclude-dir=__pycache__ \
  -e '/var/www/html/[A-Za-z0-9_-]{12,}' \
  -e 'location[^/]*\^/[A-Za-z0-9_-]{12,}' \
  -e '://[A-Za-z0-9.-]+/[A-Za-z0-9_-]{12,}/' \
  . || true)

while IFS= read -r hit; do
  [ -n "$hit" ] || continue
  match=${hit##*:}
  segment=${match%/}
  segment=${segment##*/}
  is_placeholder "$segment" && continue
  looks_generated "$segment" || continue
  echo "::error::$hit"
  echo "  ↑ looks like the served access-key directory. It lives in the node's"
  echo "    config.toml as [access_keys] write_dir, never in the repository."
  fail=1
done <<EOF
$hits
EOF

# ── 3. the generator keeps taking the directory from the config ─────────────

generator=ops/access-keys/generate_keys.py
if [ -f "$generator" ]; then
  hardcoded=$(grep -nE '^DEFAULT_OUT_DIR|--out-dir.*default *= *"' "$generator" || true)
  if [ -n "$hardcoded" ]; then
    echo "::error::$generator has a hard-coded output directory again:"
    echo "$hardcoded"
    echo "  Resolve it from [access_keys] write_dir instead; --out-dir stays the override."
    fail=1
  fi
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "ok: no served access-key path in the tree, no compiled Python tracked"
