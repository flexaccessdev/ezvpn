#!/usr/bin/env bash
#
# Build libezvpn for a real iOS device (aarch64-apple-ios) and bundle it into
# libezvpn.xcframework in dist/ios, staged with the C header. This is the
# canonical local build output; the CI release workflow zips it into the
# libezvpn-ios.xcframework.zip asset. The sibling Xcode project (../ezvpn-ios)
# links it via its own Swift package (Packages/Ezvpn/Package.swift) — by default
# a pinned release download, or this dist/ios build (reached through a committed
# symlink) when EZVPN_LOCAL_XCFRAMEWORK is set (FFI dev). This script only
# produces dist/ios; it does not write into ../ezvpn-ios.
#
# Device-only by design: a Packet Tunnel Provider does not run in the iOS
# Simulator, so there is no simulator/x86_64 slice — the xcframework carries a
# single aarch64-apple-ios slice. An .xcframework (rather than a bare .a) is used
# so SPM delivers the library and auto-exposes the embedded header to the app's
# bridging header, with no vendored copy and no HEADER_SEARCH_PATHS.
#
# Usage:
#   ./build-ios.sh            # release build (default)
#   ./build-ios.sh debug      # debug build (faster compile, huge .a)
#
set -euo pipefail

PROFILE="${1:-release}"
TARGET="aarch64-apple-ios"
# Minimum iOS version. Must be <= the Xcode project's deployment target, else
# the linker warns that the lib's objects target a newer OS. Override via env.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

case "$PROFILE" in
  release) CARGO_FLAGS="--release"; OUT_SUBDIR="release" ;;
  debug)   CARGO_FLAGS="";          OUT_SUBDIR="debug"   ;;
  *) echo "unknown profile '$PROFILE' (use 'release' or 'debug')" >&2; exit 1 ;;
esac

if ! rustup target list --installed | grep -q "^${TARGET}$"; then
  echo "Installing Rust target ${TARGET}..."
  rustup target add "$TARGET"
fi

echo "Building libezvpn.a [$PROFILE] for $TARGET ..."
cargo build --lib ${CARGO_FLAGS} --target "$TARGET"

DIST="$SCRIPT_DIR/dist/ios"
XCFRAMEWORK="$DIST/libezvpn.xcframework"
mkdir -p "$DIST"
cp "ios/ezvpn.h" "$DIST/ezvpn.h"

echo "Creating libezvpn.xcframework ..."
rm -rf "$XCFRAMEWORK"
xcodebuild -create-xcframework \
  -library "target/${TARGET}/${OUT_SUBDIR}/libezvpn.a" -headers "ios" \
  -output "$XCFRAMEWORK"

echo "Staged: $XCFRAMEWORK"
echo "        $DIST/ezvpn.h"
echo
echo "For local iOS FFI dev, build the app against this xcframework with:"
echo "    cd ../ezvpn-ios"
echo "    EZVPN_LOCAL_XCFRAMEWORK=1 xcodegen generate"
echo "    EZVPN_LOCAL_XCFRAMEWORK=1 xcodebuild -project Ezvpn.xcodeproj \\"
echo "        -scheme EzvpnApp -destination 'generic/platform=iOS' build"
echo "Done."
