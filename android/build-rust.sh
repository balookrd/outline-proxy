#!/usr/bin/env bash
# Regenerate the Rust artifacts the Android app depends on:
#   1. the native library (jniLibs/<abi>/liboutline_android.so)
#   2. the UniFFI Kotlin bindings (app/src/main/java/uniffi/outline_android/)
#
# Run this after any change under android/rust/ (or in the monorepo crates it
# pulls in), then build the app in Android Studio / with ./gradlew.
#
# Requires: rustup android targets, cargo-ndk, and ANDROID_NDK_HOME pointing at
# an NDK (e.g. /opt/homebrew/share/android-ndk). See README.md.
set -euo pipefail

cd "$(dirname "$0")/rust"

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your NDK path}"

ABI="${1:-arm64-v8a}"
PROFILE_FLAG=""
PROFILE_DIR="debug"
if [ "${2:-}" = "--release" ]; then
    PROFILE_FLAG="--release"
    PROFILE_DIR="release"
fi

echo ">> Building native library for $ABI ($PROFILE_DIR) into jniLibs"
cargo ndk -t "$ABI" --platform 24 -o ../app/src/main/jniLibs -- build --lib $PROFILE_FLAG

# cargo-ndk also copies transitive cdylibs (e.g. tun2proxy's own C-FFI lib),
# which we statically link and do not need shipped. Keep only our library.
find ../app/src/main/jniLibs -name '*.so' ! -name 'liboutline_android.so' -delete

echo ">> Building host cdylib (for binding generation)"
cargo build --lib $PROFILE_FLAG

echo ">> Generating UniFFI Kotlin bindings"
cargo run --bin uniffi-bindgen -- generate \
    --library "target/$PROFILE_DIR/liboutline_android.dylib" \
    --language kotlin \
    --out-dir ../app/src/main/java

echo ">> Done. jniLibs + uniffi bindings refreshed."
