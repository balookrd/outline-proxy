#!/usr/bin/env bash
# RustSec audit that also covers the vendored crates.
#
# Usage: audit-vendored.sh [lockfile...] [-- <cargo audit args>]
#
# `cargo audit` skips packages without a `source` in the lockfile, and the
# crates vendored through `[patch.crates-io]` are path dependencies, so a plain
# run never reports their advisories (quinn-proto 0.11.15 and rustls 0.23.40
# went unnoticed that way). This script copies each lockfile, marks the patched
# packages as crates.io packages of the same version, and audits the copy.
#
# The patched names are read from the root Cargo.toml `[patch.crates-io]`, so a
# newly vendored crate is covered without touching this script. Lockfiles
# default to the root one and android/rust/Cargo.lock. Exits non-zero when any
# lockfile has a vulnerability; warnings (unmaintained, yanked) do not fail.
# sockudo-ws 1.7.5 is gone from the crates.io index, so cargo audit prints
# "couldn't check if the package is yanked" for it; that line is expected and
# does not change the result.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)

lockfiles=()
while [ $# -gt 0 ] && [ "$1" != -- ]; do lockfiles+=("$1"); shift; done
[ "${1:-}" = -- ] && shift
[ ${#lockfiles[@]} -gt 0 ] || lockfiles=("$repo/Cargo.lock" "$repo/android/rust/Cargo.lock")

# `name = { path = "vendor/..." }` lines of the [patch.crates-io] section.
patched=$(awk '
  /^\[/ { in_patch = ($0 == "[patch.crates-io]"); next }
  in_patch && /^[A-Za-z0-9_-]+ *= *\{.*path *=/ { sub(/ *=.*/, ""); print }
' "$repo/Cargo.toml")
[ -n "$patched" ] || { echo "no [patch.crates-io] path entries in $repo/Cargo.toml" >&2; exit 2; }
echo "vendored crates: $(echo "$patched" | tr '\n' ' ')"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

rc=0
for lock in "${lockfiles[@]}"; do
  echo "== $lock"
  # A path package has no `source` line after its `version`; add the crates.io
  # source there for the patched names only.
  # Space-separated: BSD awk rejects a newline inside a -v value.
  awk -v names="$(echo "$patched" | tr '\n' ' ')" '
    BEGIN {
      n = split(names, list, " ")
      for (i = 1; i <= n; i++) want[list[i]] = 1
      src = "source = \"registry+https://github.com/rust-lang/crates.io-index\""
    }
    held != "" {
      print held
      if ($0 !~ /^source = /) print src
      held = ""
    }
    /^\[\[package\]\]$/ { name = "" }
    /^name = "/ { name = $0; sub(/^name = "/, "", name); sub(/"$/, "", name) }
    /^version = "/ && (name in want) { held = $0; next }
    { print }
    END { if (held != "") { print held; print src } }
  ' "$lock" > "$tmp"
  cargo audit --file "$tmp" "$@" || rc=1
done
exit $rc
