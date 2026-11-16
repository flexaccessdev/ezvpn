# Thin wrapper: the logic lives in the sibling devtools repo, parameterized by
# this repo's .devtools.conf.
param([Parameter(ValueFromRemainingArguments = $true)][string[]] $Rest)
$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$DevTools = if ($env:DEVTOOLS_DIR) { $env:DEVTOOLS_DIR } else { Join-Path (Split-Path -Parent $RepoRoot) 'devtools' }
$SharedScript = Join-Path $DevTools 'ci' 'windows' 'remote.ps1'
if (-not (Test-Path $SharedScript)) {
    throw "devtools not found at $DevTools — git clone git@github.com:andrewtheguy/devtools.git there (or set DEVTOOLS_DIR)"
}
$env:DEVTOOLS_REPO_ROOT = $RepoRoot
# With no arguments -File leaves $Rest $null, and splatting $null passes an
# empty string that fails the driver's ValidateSet — default to no arguments.
if ($null -eq $Rest) { $Rest = @() }
& $SharedScript @Rest
