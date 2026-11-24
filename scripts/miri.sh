#!/usr/bin/env bash
# Run the tests in scripts/miri-tests.txt under Miri on this host's target
# (Linux or macOS; scripts/miri.ps1 is the Windows counterpart). Each OS
# compiles different unsafe code (src/ffi.rs and the utun I/O on macOS,
# src/ffi_windows.rs and the IP Helper rows on Windows), so run it on Linux, on
# macvm and on windows-ci-build.
#
# Isolation is off for the real clock and temp files some tests use. Miri
# builds go to target/miri, so the RUSTFLAGS below never touch normal builds.
#
#   scripts/miri.sh            # MIRI_TOOLCHAIN overrides the pinned nightly
set -euo pipefail
cd "$(dirname "$0")/.."

toolchain="${MIRI_TOOLCHAIN:-nightly-2026-10-31}"
rustup toolchain install "$toolchain" --profile minimal --component miri,rust-src >/dev/null
export MIRIFLAGS="${MIRIFLAGS:--Zmiri-disable-isolation}"
# sha2 picks the CPU's SHA instructions at runtime, whose intrinsics Miri does
# not implement on aarch64; its portable backend computes the same digests.
export RUSTFLAGS="${RUSTFLAGS:-} --cfg sha2_backend=\"soft\""

# A read loop rather than mapfile, which macOS' bash 3.2 lacks.
lib=() bin=()
while read -r kind filter; do
    case "$kind" in
        lib) lib+=("$filter") ;;
        bin) bin+=("$filter") ;;
    esac
done <scripts/miri-tests.txt

cargo "+$toolchain" miri test --lib -- "${lib[@]}"
cargo "+$toolchain" miri test --bin ezvpn -- "${bin[@]}"
