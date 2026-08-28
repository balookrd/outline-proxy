#!/usr/bin/env bash
# Generate a GitHub release body for one component from Conventional Commits.
#
#   gen-release-notes.sh <component> <tag> <output-file>
#     component : ss | ws | ui | android
#     tag       : ss-v1.9.0 (release) or ss-nightly (rolling)
#     output    : path to write the markdown body to
#
# All per-component knowledge (include-path, tag prefix) lives here so the four
# reusable workflows stay identical. Requires git-cliff on PATH and a checkout
# with full history + tags (fetch-depth: 0, fetch-tags: true).
set -euo pipefail

component="${1:?usage: gen-release-notes.sh <component> <tag> <output-file>}"
tag="${2:?missing tag}"
out="${3:?missing output file}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
config="${repo_root}/cliff.toml"

case "$component" in
  ss)
    prefix="ss"
    paths=(bins/outline-ss-rust crates/outline-net crates/outline-wire crates/outline-transport vendor)
    ;;
  ws)
    prefix="ws"
    paths=(bins/outline-ws-rust crates vendor)
    ;;
  ui)
    prefix="ui"
    paths=(bins/outline-ui)
    ;;
  android)
    prefix="android"
    paths=(android)
    ;;
  *)
    echo "unknown component: $component" >&2
    exit 2
    ;;
esac

# Rolling tag (e.g. ss-nightly) is anything not shaped like <prefix>-vX.Y.Z.
rolling=false
if [[ ! "$tag" =~ ^${prefix}-v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  rolling=true
fi

if [[ "$rolling" == "true" ]]; then
  # Rolling: diff from the newest stable tag of this component up to HEAD.
  prev="$(git tag -l "${prefix}-v*" --sort=-v:refname | head -n1)"
  end_ref="HEAD"
  compare_to="$(git rev-parse HEAD)"
else
  # Release: previous stable tag is the greatest <prefix>-v* strictly LESS than
  # the current one by semver (not just "the greatest other tag"). Insert the
  # tag into the sorted list and take the line before it. bash 3.2-safe: no
  # `mapfile` (macOS ships bash 3.2), plain awk instead.
  prev="$( { git tag -l "${prefix}-v*" | grep -vx "$tag"; printf '%s\n' "$tag"; } \
            | sort -V | awk -v t="$tag" '$0 == t { print p; exit } { p = $0 }')"
  end_ref="$tag"
  compare_to="$tag"
fi

if [[ -n "$prev" ]]; then
  range="${prev}..${end_ref}"
else
  # First release of this component: git-cliff rejects a bare tag as a range, so
  # span from the repo's root commit reachable from end_ref up to it.
  root="$(git rev-list --max-parents=0 "$end_ref" 2>/dev/null | tail -1)"
  range="${root}..${end_ref}"
fi

# Assemble --include-path flags.
include_args=()
for p in "${paths[@]}"; do
  include_args+=(--include-path "${p}/**")
done

# git-cliff exits non-zero when the range has no releasable commits; capture and
# fall through to the fallback body instead of failing the release.
body=""
if body="$(git cliff "$range" \
      --tag-pattern "^${prefix}-v" \
      "${include_args[@]}" \
      --tag "$tag" \
      --config "$config" \
      --strip all 2>/dev/null)"; then
  :
else
  body=""
fi

# Compose the compare-link footer from the exact prev/ref we computed.
server_url="${GITHUB_SERVER_URL:-https://github.com}"
repo="${GITHUB_REPOSITORY:-}"
if [[ -z "$repo" ]]; then
  origin="$(git -C "$repo_root" remote get-url origin 2>/dev/null || echo '')"
  repo="$(printf '%s' "$origin" | sed -E 's#^.*[:/]([^/]+/[^/]+)$#\1#; s#\.git$##')"
fi
footer=""
if [[ -n "$prev" && -n "$repo" ]]; then
  footer="**Full Changelog**: ${server_url}/${repo}/compare/${prev}...${compare_to}"
fi

# Fallback when nothing survived filtering. git-cliff still renders a bare
# "## What's Changed" header for an empty commit set (version comes from --tag),
# so detect emptiness by the absence of list items, not overall blankness.
if ! printf '%s' "$body" | grep -q '^- '; then
  body="## What's Changed in ${tag}

_No user-facing changes in this release; see the full changelog below._"
fi

{
  printf '%s\n' "$body"
  if [[ -n "$footer" ]]; then
    printf '\n%s\n' "$footer"
  fi
} > "$out"

echo "Wrote release notes to $out ($(wc -l < "$out") lines)"
