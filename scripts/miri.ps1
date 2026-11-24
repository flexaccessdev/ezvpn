# Windows counterpart of scripts/miri.sh: run the `lib` tests in
# scripts/miri-tests.txt under Miri (the `bin` ones are Unix only).
#
# cargo-miri cannot take the argfile cargo falls back to when a rustc command
# line passes Windows' 32 767-character limit, and with cargo's per-crate
# build-dir layout ezvpn's test crate gets one `-L` and two `--extern` paths
# per dependency. To keep it under the limit the build lives under a `subst`
# drive letter, and build-dir points at the drive root itself, which also drops
# the `miri\` segment cargo-miri would add to every path.
#
#   pwsh -File scripts/miri.ps1      # $env:MIRI_TOOLCHAIN overrides the pinned nightly
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repo

$toolchain = if ($env:MIRI_TOOLCHAIN) { $env:MIRI_TOOLCHAIN } else { 'nightly-2026-10-31' }
& rustup component add --toolchain $toolchain miri rust-src *> $null
if ($LASTEXITCODE -ne 0) { throw "rustup could not add miri to $toolchain" }

$lib = Get-Content (Join-Path $PSScriptRoot 'miri-tests.txt') |
    Where-Object { $_ -match '^lib\s+(\S+)' } | ForEach-Object { $Matches[1] }

$build = Join-Path $repo 'target\miri-windows'
New-Item -ItemType Directory -Force -Path $build | Out-Null
$used = (Get-PSDrive -PSProvider FileSystem).Name
$letter = [char[]]'MNOPQRSTUVWXYZ' | Where-Object { "$_" -notin $used } | Select-Object -First 1
if (-not $letter) { throw 'no free drive letter for subst' }
& subst "${letter}:" $build
if ($LASTEXITCODE -ne 0) { throw "subst ${letter}: failed" }
try {
    $env:CARGO_TARGET_DIR = "${letter}:\"
    $env:CARGO_BUILD_BUILD_DIR = "${letter}:\"
    if (-not $env:MIRIFLAGS) { $env:MIRIFLAGS = '-Zmiri-disable-isolation' }
    # As in miri.sh: sha2's portable backend instead of CPU SHA intrinsics.
    $env:RUSTFLAGS = "$env:RUSTFLAGS --cfg sha2_backend=`"soft`"".Trim()
    & cargo "+$toolchain" miri test --lib -- @lib
    $code = $LASTEXITCODE
} finally {
    & subst "${letter}:" /D
}
exit $code
