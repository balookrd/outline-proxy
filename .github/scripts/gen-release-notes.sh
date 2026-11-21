#!/usr/bin/env bash
# Generate a GitHub release body for one component from Conventional Commits.
#
#   gen-release-notes.sh <component> <tag> <output-file> [end-ref]
#     component : all | server | client | ui | android | macos | windows
#     tag       : v26.11.0 (unified release) or <comp>-nightly (rolling)
#     output    : path to write the markdown body to
#     end-ref   : optional upper bound ref for rolling tags (default: HEAD)
#
# All per-component knowledge (include-path, tag prefix) lives here so the
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
  server)
    prefix="server"
    paths=(bins/outline-server crates/outline-net crates/outline-wire crates/outline-transport vendor)
    ;;
  client)
    prefix="client"
    paths=(bins/outline-client crates vendor)
    ;;
  ui)
    prefix="ui"
    paths=(bins/outline-ui)
    ;;
  android)
    prefix="android"
    paths=(android bins/outline-client crates vendor)
    ;;
  macos)
    prefix="macos"
    paths=(macos bins/outline-client crates vendor)
    ;;
  windows)
    prefix="windows"
    paths=(bins/outline-windows bins/outline-client crates vendor)
    ;;
  all)
    prefix=""
    paths=()
    ;;
  *)
    echo "unknown component: $component" >&2
    exit 2
    ;;
esac

if [[ "$component" == "all" ]]; then
  if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "expected CalVer tag vYY.M.PATCH for component 'all', got: $tag" >&2
    exit 2
  fi
  rolling=false
  # Only consider CalVer tags (two+ digit major, e.g. v26.11.0) so historical
  # pre-split v1.0.0..v1.4.4 tags are never treated as the previous release.
  calver_tags="$(git tag -l 'v[0-9][0-9].*' | grep -E '^v[0-9]{2,}\.[0-9]+\.[0-9]+$' || true)"
  prev="$( { printf '%s\n' "$calver_tags" | grep -vx "$tag" || true; printf '%s\n' "$tag"; } \
            | grep -v '^$' | sort -V | awk -v t="$tag" '$0 == t { print p; exit } { p = $0 }')"
  if [[ -z "$prev" ]]; then
    # First CalVer release: anchor at the newest historical per-component stable tag.
    prev="$(git for-each-ref --sort=-creatordate --format='%(refname:short)' refs/tags \
      | grep -E '^(ss|ws|ui|android|macos|windows)-v[0-9]+\.[0-9]+\.[0-9]+$' \
      | head -n1 || true)"
  fi
  end_ref="$tag"
  compare_to="$tag"
  tag_pattern='^v[0-9]{2,}\.'
else
  # Rolling tag (e.g. server-nightly) is anything not shaped like <prefix>-vX.Y.Z.
  rolling=false
  if [[ ! "$tag" =~ ^${prefix}-v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    rolling=true
  fi

  if [[ "$rolling" == "true" ]]; then
    # Rolling: diff from the newest unified CalVer tag reachable from end_ref;
    # fall back to the newest historical per-component stable tag before the
    # first CalVer cut. `--merged` prevents a newer release tag pushed while a
    # nightly build is in flight from yielding an empty range.
    end_ref="${4:-HEAD}"
    prev="$(git tag --merged "$end_ref" -l 'v[0-9][0-9].*' | grep -E '^v[0-9]{2,}\.[0-9]+\.[0-9]+$' | sort -V | tail -n1 || true)"
    if [[ -n "$prev" ]]; then
      tag_pattern='^v[0-9]{2,}\.'
    else
      prev="$(git tag --merged "$end_ref" -l "${prefix}-v*" --sort=-v:refname | head -n1 || true)"
      tag_pattern="^${prefix}-v"
    fi
    compare_to="$(git rev-parse "$end_ref")"
  else
    # Release: previous stable tag is the greatest <prefix>-v* strictly LESS than
    # the current one by semver (not just "the greatest other tag"). Insert the
    # tag into the sorted list and take the line before it. bash 3.2-safe: no
    # `mapfile` (macOS ships bash 3.2), plain awk instead.
    prev="$( { git tag -l "${prefix}-v*" | grep -vx "$tag"; printf '%s\n' "$tag"; } \
              | sort -V | awk -v t="$tag" '$0 == t { print p; exit } { p = $0 }')"
    end_ref="$tag"
    compare_to="$tag"
    tag_pattern="^${prefix}-v"
  fi
fi

if [[ -n "$prev" ]]; then
  range="${prev}..${end_ref}"
elif [[ "${#paths[@]}" -gt 0 ]]; then
  # First release of this component (or rolling before any stable tags exist):
  # in a monorepo, span from the commit introducing this component's primary
  # directory up to end_ref. Using the repo's root commit would erroneously pull
  # in commits to shared paths (crates/**, vendor/**) from before this component existed.
  comp_root="$(git log --reverse --format="%H" "$end_ref" -- "${paths[0]}" 2>/dev/null | head -1)"
  if [[ -n "$comp_root" ]]; then
    base="$(git rev-parse --verify "${comp_root}^" 2>/dev/null || echo "$comp_root")"
    range="${base}..${end_ref}"
  else
    root="$(git rev-list --max-parents=0 "$end_ref" 2>/dev/null | tail -1)"
    range="${root}..${end_ref}"
  fi
else
  root="$(git rev-list --max-parents=0 "$end_ref" 2>/dev/null | tail -1)"
  range="${root}..${end_ref}"
fi

# Assemble --include-path flags (empty for `all`, i.e. whole-repo notes).
include_args=()
for p in "${paths[@]+"${paths[@]}"}"; do
  include_args+=(--include-path "${p}/**")
done

tmpdir=""
cleanup() {
  if [[ -n "$tmpdir" ]]; then
    rm -rf "$tmpdir"
  fi
}
trap cleanup EXIT

has_bullets() {
  grep -q '^- ' <<< "$1"
}

run_cliff() {
  local cfg="$1"
  git cliff "$range" \
    --tag-pattern "$tag_pattern" \
    ${include_args[@]+"${include_args[@]}"} \
    --tag "$tag" \
    --config "$cfg" \
    --strip all 2>/dev/null
}

# git-cliff exits non-zero when the range has no releasable commits; capture and
# fall through to the fallback body instead of failing the release.
body=""
if body="$(run_cliff "$config")"; then
  :
else
  body=""
fi

# Rolling nightlies should still tell users why a build was published when only
# refactor/chore/build/ci commits landed since the last CalVer cut.
if [[ "$rolling" == "true" ]] && ! has_bullets "$body"; then
  tmpdir="$(mktemp -d)"
  maint_config="${tmpdir}/cliff.toml"
  sed -E 's/^([[:space:]]*\{[[:space:]]*message[[:space:]]*=[[:space:]]*"\^(refactor|chore|build|ci)",[[:space:]]*)skip[[:space:]]*=[[:space:]]*true([[:space:]]*\},?)$/\1group = "<!-- 5 -->🔧 Maintenance"\3/' \
    "$config" > "$maint_config"
  if ! grep -q '🔧 Maintenance' "$maint_config"; then
    echo "gen-release-notes.sh: failed to derive Maintenance config from $config" >&2
    exit 1
  fi
  if body="$(run_cliff "$maint_config")"; then
    :
  else
    body=""
  fi
fi

# Compose the compare-link footer from the exact prev/ref we computed.
server_url="${GITHUB_SERVER_URL:-https://github.com}"
repo="${GITHUB_REPOSITORY:-}"
if [[ -z "$repo" ]]; then
  origin="$(git -C "$repo_root" remote get-url origin 2>/dev/null || echo '')"
  repo="$(printf '%s' "$origin" | sed -E 's#^.*[:/]([^/]+/[^/]+)$#\1#; s#\.git$##')"
fi
footer=""
compare_from="${prev:-${base:-}}"
if [[ -n "$compare_from" && -n "$repo" ]]; then
  if [[ -z "$prev" && -n "${base:-}" ]]; then
    compare_from="${base:0:8}"
  fi
  footer="**Full Changelog**: ${server_url}/${repo}/compare/${compare_from}...${compare_to}"
fi

# Fallback when nothing survived filtering. git-cliff still renders a bare
# "## What's Changed" header for an empty commit set (version comes from --tag),
# so detect emptiness by the absence of list items, not overall blankness.
if ! has_bullets "$body"; then
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
