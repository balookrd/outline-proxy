#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <target> <profile> <flavor: server|router|router-build-std> <output-dir>" >&2
  exit 1
fi

target="$1"
profile="$2"
flavor="$3"
output_dir="$4"
binary_name="outline-ws-rust"
version="${VERSION:-$(python3 -c 'import re, pathlib; text = pathlib.Path("Cargo.toml").read_text(); match = re.search(r"^version = \"([^\"]+)\"$", text, flags=re.M); print(match.group(1) if match else (_ for _ in ()).throw(SystemExit("failed to read package version from Cargo.toml")))' )}"

case "$flavor" in
  server)
    dest_prefix="$binary_name"
    if [[ "$profile" == "release" ]]; then
      cargo zigbuild --locked --release --target "$target"
    else
      cargo zigbuild --locked --profile "$profile" --target "$target"
    fi
    artifact_dir="$profile"
    ;;
  router)
    dest_prefix="${binary_name}-router"
    cargo zigbuild --locked --profile "$profile" --no-default-features --features router --target "$target"
    artifact_dir="$profile"
    ;;
  router-build-std)
    dest_prefix="${binary_name}-router"
    cargo zigbuild --locked -Z build-std=std,panic_abort --profile "$profile" --no-default-features --features router --target "$target"
    artifact_dir="$profile"
    ;;
  *)
    echo "unknown flavor: $flavor" >&2
    exit 1
    ;;
esac

src_path="target/${target}/${artifact_dir}/${binary_name}"
dest_name="${dest_prefix}-v${version}-${target}"

mkdir -p "$output_dir"
cp "$src_path" "${output_dir}/${dest_name}"
chmod +x "${output_dir}/${dest_name}"
tar -C "$output_dir" -czf "${output_dir}/${dest_name}.tar.gz" "$dest_name"
rm -f "${output_dir:?}/${dest_name}"
