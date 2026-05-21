#!/usr/bin/env bash
# Build libboringssl_dart.so from the BoringSSL source bundled in webcrypto pub cache.
#
# Prerequisites:
#   - cmake >= 3.6
#   - C compiler (gcc/clang)
#   - webcrypto in pub cache (dart pub cache add webcrypto --version 0.5.8)
#
# Output: <project_root>/build/libboringssl_dart.so
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Locate the newest webcrypto version in pub cache (any 0.5.x or 0.6.x).
PUB_CACHE="${PUB_CACHE:-$HOME/.pub-cache}"
BORINGSSL_SRC=$(
  find "$PUB_CACHE/hosted/pub.dev" -maxdepth 3 \
    -name "boringssl" -type d 2>/dev/null |
  grep "webcrypto-" |
  sort -V |
  tail -1
)

if [ -z "$BORINGSSL_SRC" ]; then
  echo "Error: webcrypto not found in pub cache ($PUB_CACHE/hosted/pub.dev/webcrypto-*/third_party/boringssl)."
  echo ""
  echo "Add it with:"
  echo "  dart pub cache add webcrypto --version 0.5.8"
  exit 1
fi

echo "Using BoringSSL source: $BORINGSSL_SRC"

BUILD_DIR="$PROJECT_DIR/build/boringssl_build"
OUTPUT_DIR="$PROJECT_DIR/build"

mkdir -p "$BUILD_DIR"
mkdir -p "$OUTPUT_DIR"

# Configure — BORINGSSL_ROOT must have a trailing slash (required by sources.cmake).
cmake \
  -S "$SCRIPT_DIR" \
  -B "$BUILD_DIR" \
  -DBORINGSSL_ROOT="$BORINGSSL_SRC/" \
  -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build "$BUILD_DIR" --parallel

# Copy the result to build/
cp "$BUILD_DIR/libboringssl_dart.so" "$OUTPUT_DIR/libboringssl_dart.so"

echo ""
echo "Done: $OUTPUT_DIR/libboringssl_dart.so"
echo "Run the benchmark with: dart run bin/speedtest.dart 1 10"
