#!/usr/bin/env bash
# Build libtrojan.so for all Android ABIs and copy into the given output
# directory (default: ../igniter/app/src/main/libs).
#
# Prerequisites:
#   - rustup target for the 4 Android ABIs (see README)
#   - cargo-ndk (cargo install cargo-ndk)
#   - ANDROID_NDK_HOME pointing at an NDK (e.g. /disk2vm/Android/Sdk/ndk/27.x)
#
# Usage:
#   ANDROID_NDK_HOME=/path/to/ndk ./android/build.sh [output_dir]
#
# Output layout (standard Android jniLibs):
#   <output>/arm64-v8a/libtrojan.so
#   <output>/armeabi-v7a/libtrojan.so
#   <output>/x86/libtrojan.so
#   <output>/x86_64/libtrojan.so

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ABIS=(arm64-v8a armeabi-v7a x86 x86_64)
RUST_TARGETS=(aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android)

OUT="${1:-$ROOT/../igniter/app/src/main/libs}"

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "error: ANDROID_NDK_HOME is not set" >&2
    exit 1
fi
command -v cargo-ndk >/dev/null || { echo "error: cargo-ndk not installed (cargo install cargo-ndk)" >&2; exit 1; }

echo "building libtrojan.so (4 ABIs) -> $OUT"
for abi in "${ABIS[@]}"; do
    echo "== $abi =="
    case "$abi" in
        arm64-v8a) target=aarch64-linux-android ;;
        armeabi-v7a) target=armv7-linux-androideabi ;;
        x86) target=i686-linux-android ;;
        x86_64) target=x86_64-linux-android ;;
    esac
    rustup target add "$target" >/dev/null 2>&1 || true
    cargo ndk -t "$abi" -o "$OUT" build --release --lib --features server,jni
done

echo "done:"
find "$OUT" -name "*.so" -exec ls -lh {} \;
