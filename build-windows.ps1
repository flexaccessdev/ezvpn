<#
.SYNOPSIS
  Build ezvpn.dll (the C-ABI cdylib) for Windows and stage it with the C header.

.DESCRIPTION
  Mirrors build-apple.sh: builds the `cdylib` crate-type into ezvpn.dll for the
  requested target(s) and copies it, alongside windows/ezvpn.h, into
  dist/windows. This is the canonical local build output; the sibling .NET
  project (..\ezvpn-windows) links it by copying from here when EZVPN_LOCAL_DLL
  is set, otherwise it uses a pinned release download. The CI release workflow
  zips this into ezvpn-windows.dll.zip.

  wintun.dll (from https://www.wintun.net/) is NOT bundled here — the .NET app /
  MSI installer bundles it next to ezvpn.dll at runtime.

.PARAMETER Profile
  'release' (default) or 'debug'.

.PARAMETER Target
  Rust target triple. Default x86_64-pc-windows-msvc. Pass aarch64-pc-windows-msvc
  for ARM64.

.EXAMPLE
  ./build-windows.ps1
  ./build-windows.ps1 -Profile debug
  ./build-windows.ps1 -Target aarch64-pc-windows-msvc
#>
[CmdletBinding()]
param(
    [ValidateSet('release', 'debug')]
    [string]$Profile = 'release',
    [string]$Target = 'x86_64-pc-windows-msvc'
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Ensure the target toolchain is installed.
$installed = rustup target list --installed
if ($installed -notcontains $Target) {
    Write-Host "Installing Rust target $Target ..."
    rustup target add $Target
}

$cargoFlags = @('--lib', '--target', $Target)
if ($Profile -eq 'release') {
    $cargoFlags += '--release'
    $outSubdir = 'release'
} else {
    $outSubdir = 'debug'
}

Write-Host "Building ezvpn.dll [$Profile] for $Target ..."
& cargo build @cargoFlags
if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }

$dllPath = Join-Path $ScriptDir "target\$Target\$outSubdir\ezvpn.dll"
if (-not (Test-Path $dllPath)) { throw "expected DLL not found: $dllPath" }

$dist = Join-Path $ScriptDir 'dist\windows'
New-Item -ItemType Directory -Force -Path $dist | Out-Null
Copy-Item $dllPath (Join-Path $dist 'ezvpn.dll') -Force
Copy-Item (Join-Path $ScriptDir 'windows\ezvpn.h') (Join-Path $dist 'ezvpn.h') -Force

# The import library and PDB are handy for local linking / debugging (optional).
$implib = Join-Path $ScriptDir "target\$Target\$outSubdir\ezvpn.dll.lib"
if (Test-Path $implib) { Copy-Item $implib (Join-Path $dist 'ezvpn.dll.lib') -Force }

Write-Host ""
Write-Host "Staged: $(Join-Path $dist 'ezvpn.dll')"
Write-Host "        $(Join-Path $dist 'ezvpn.h')"
Write-Host ""
Write-Host "For local FFI dev, build the .NET app against this DLL with:"
Write-Host "    cd ..\ezvpn-windows"
Write-Host "    `$env:EZVPN_LOCAL_DLL = '1'; dotnet build"
Write-Host "Remember: wintun.dll must sit next to ezvpn.dll at runtime."
Write-Host "Done."
