#!/usr/bin/env bash
set -Eeuo pipefail

# Install-script invariants.
#
# The two root installers are delivered as single files over fixed
# raw.githubusercontent.com URLs (curl | bash), so the shared logic
# between install-server.sh and install-client.sh is deliberately
# duplicated instead of factored into a sourced library. This gate is
# what keeps that duplication honest:
#
#  1. Syntax: both bash installers must parse.
#  2. shellcheck must pass for both.
#  3. The shared helper functions listed in SHARED_FUNCS must stay
#     byte-identical between install-server.sh and install-client.sh —
#     a fix applied to one side only fails CI here.

cd "$(dirname "$0")/../.."

bash -n install-server.sh
bash -n install-client.sh

shellcheck install-server.sh install-client.sh

# Print the body of function $2 in file $1: from the `name() {`
# definition line to the first line that is exactly `}`. Single-line
# definitions (`name() { ...; }`) are returned as-is.
extract_function() {
  awk -v fn="$2" '
    $0 ~ "^"fn"\\(\\) \\{" {
      if ($0 ~ /\}[[:space:]]*$/) { print; exit }
      p = 1
    }
    p { print }
    p && /^\}$/ { exit }
  ' "$1"
}

SHARED_FUNCS=(
  github_api_get
  github_api_url
  release_field
  strip_v
  get_nightly_commit_sha
  prune_old_backups
  get_installed_version
)

fail=0
for fn in "${SHARED_FUNCS[@]}"; do
  server_body="$(extract_function install-server.sh "$fn")"
  client_body="$(extract_function install-client.sh "$fn")"
  if [[ -z "$server_body" || -z "$client_body" ]]; then
    echo "FAIL: shared function ${fn}() is missing from one of the installers" >&2
    fail=1
    continue
  fi
  if [[ "$server_body" != "$client_body" ]]; then
    echo "FAIL: shared function ${fn}() drifted between install-server.sh and install-client.sh:" >&2
    diff <(printf '%s\n' "$server_body") <(printf '%s\n' "$client_body") >&2 || true
    fail=1
  fi
done

if (( fail )); then
  echo >&2
  echo "Shared installer helpers must stay byte-identical; apply the fix to both scripts." >&2
  exit 1
fi

echo "install scripts OK: syntax, shellcheck, ${#SHARED_FUNCS[@]} shared helpers identical"
