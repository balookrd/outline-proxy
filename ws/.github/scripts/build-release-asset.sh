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

case "$flavor" in
  server)
    if [[ "$profile" == "release" ]]; then
      cargo zigbuild --locked --release --target "$target"
    else
      cargo zigbuild --locked --profile "$profile" --target "$target"
    fi
    artifact_dir="$profile"
    ;;
  router)
    cargo zigbuild --locked --profile "$profile" --no-default-features --features router --target "$target"
    artifact_dir="$profile"
    ;;
  router-build-std)
    cargo zigbuild --locked -Z build-std=std,panic_abort --profile "$profile" --no-default-features --features router --target "$target"
    artifact_dir="$profile"
    ;;
  *)
    echo "unknown flavor: $flavor" >&2
    exit 1
    ;;
esac

src_path="target/${target}/${artifact_dir}/${binary_name}"
dest_name="${binary_name}-${target}"

mkdir -p "$output_dir"
cp "$src_path" "${output_dir}/${dest_name}"
chmod +x "${output_dir}/${dest_name}"
tar -C "$output_dir" -czf "${output_dir}/${dest_name}.tar.gz" "$dest_name"
rm -f "${output_dir:?}/${dest_name}"
