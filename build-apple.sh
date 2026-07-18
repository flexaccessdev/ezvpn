#!/usr/bin/env bash
#
# Build libezvpn for iOS (aarch64-apple-ios) and native Apple Silicon macOS
# (aarch64-apple-darwin), then bundle both slices into libezvpn.xcframework in
# dist/apple, staged with the C header. This is the canonical local build output;
# the CI release workflow zips it into libezvpn-apple.xcframework.zip. The sibling
# Xcode project (../ezvpn-apple) links it via its own Swift package — by default a
# pinned release download, or this dist/apple build (reached through a committed
# symlink) when EZVPN_LOCAL_XCFRAMEWORK is exactly 1. This script only produces
# dist/apple; it does not write into ../ezvpn-apple.
#
# A Packet Tunnel Provider does not run in the iOS Simulator, so there is no
# simulator slice. Native macOS uses the app-extension slice. An .xcframework
# (rather than a bare .a) lets SPM deliver both libraries and auto-expose the
# embedded header to the app's bridging header.
#
# Usage:
#   ./build-apple.sh            # release build (default)
#   ./build-apple.sh debug      # debug build (faster compile, huge .a)
#
set -euo pipefail

PROFILE="${1:-release}"
IOS_TARGET="aarch64-apple-ios"
MACOS_TARGET="aarch64-apple-darwin"
# Minimum iOS version. Must be <= the Xcode project's deployment target, else
# the linker warns that the lib's objects target a newer OS. Override via env.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

case "$PROFILE" in
  release) CARGO_FLAGS="--release"; OUT_SUBDIR="release" ;;
  debug)   CARGO_FLAGS="";          OUT_SUBDIR="debug"   ;;
  *) echo "unknown profile '$PROFILE' (use 'release' or 'debug')" >&2; exit 1 ;;
esac

for target in "$IOS_TARGET" "$MACOS_TARGET"; do
  if ! rustup target list --installed | grep -q "^${target}$"; then
    echo "Installing Rust target ${target}..."
    rustup target add "$target"
  fi
done

echo "Building libezvpn.a [$PROFILE] for $IOS_TARGET ..."
cargo build --lib ${CARGO_FLAGS} --target "$IOS_TARGET"
echo "Building libezvpn.a [$PROFILE] for $MACOS_TARGET ..."
cargo build --lib ${CARGO_FLAGS} --target "$MACOS_TARGET"

DIST="$SCRIPT_DIR/dist/apple"
XCFRAMEWORK="$DIST/libezvpn.xcframework"
mkdir -p "$DIST"
cp "ios/ezvpn.h" "$DIST/ezvpn.h"

echo "Creating libezvpn.xcframework ..."
rm -rf "$XCFRAMEWORK"
xcodebuild -create-xcframework \
  -library "target/${IOS_TARGET}/${OUT_SUBDIR}/libezvpn.a" -headers "ios" \
  -library "target/${MACOS_TARGET}/${OUT_SUBDIR}/libezvpn.a" -headers "ios" \
  -output "$XCFRAMEWORK"

echo "Staged: $XCFRAMEWORK"
echo "        $DIST/ezvpn.h"
echo
echo "For local Apple Network Extension FFI dev, build the app against this xcframework with:"
echo "    cd ../ezvpn-apple"
echo "    EZVPN_LOCAL_XCFRAMEWORK=1 xcodegen generate"
echo "    EZVPN_LOCAL_XCFRAMEWORK=1 xcodebuild -project Ezvpn.xcodeproj \\"
echo "        -scheme Ezvpn -destination 'generic/platform=iOS' build"
echo "    EZVPN_LOCAL_XCFRAMEWORK=1 xcodebuild -project Ezvpn.xcodeproj \\"
echo "        -scheme Ezvpn -destination 'platform=macOS,arch=arm64' build"
echo "Done."
