# The Windows jobs from .github/workflows/ci.yml, in the same order, with the
# same flags: `windows` (clippy, which compiles the Windows-gated
# src/ffi_windows.rs) and `verify-windows-dll` (build-windows.ps1 -Profile
# debug). When this file and that workflow disagree, the workflow is right and
# this is stale — it exists to say what CI will say before CI is asked.
#
# This runs natively on whatever Windows machine it is invoked on: the CI VM
# (see ci\windows\remote.ps1, which hands it a CARGO_TARGET_DIR restored from
# devtools' restic build cache) or a dev box. It installs nothing beyond what
# build-windows.ps1 does (a missing rustup target).
#
# A non-zero exit from a native command is not an error to PowerShell on its
# own, whatever $ErrorActionPreference says, so every step checks
# $LASTEXITCODE by hand.
$ErrorActionPreference = 'Stop'

# Invoked over ssh the working directory is the login user's home, not the
# checkout, so anchor to the repo root this script sits in.
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Invoke-Step([string] $Name, [scriptblock] $Body) {
    Write-Host ''
    Write-Host "== $Name =="
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $global:LASTEXITCODE = 0
    try { & $Body } catch { Write-Host $_.Exception.Message; $global:LASTEXITCODE = 1 }
    Write-Host ("   {0} took {1:n0}s" -f $Name, $clock.Elapsed.TotalSeconds)
    if ($LASTEXITCODE -ne 0) {
        Write-Host ''
        Write-Host "FAILED: $Name (exit $LASTEXITCODE)"
        exit $LASTEXITCODE
    }
}

Write-Host '== toolchain =='
& cmd /c ver
& rustc --version
& cargo --version
& cargo clippy --version
if ($env:CARGO_TARGET_DIR) { Write-Host "   CARGO_TARGET_DIR=$env:CARGO_TARGET_DIR" }

Invoke-Step 'Clippy' { & cargo clippy --all-targets -- -D warnings }
Invoke-Step 'Build ezvpn.dll + header (debug)' { & .\build-windows.ps1 -Profile debug }

Write-Host ''
Write-Host 'all steps passed'
exit 0
