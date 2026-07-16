#!/usr/bin/env pwsh

# ezvpn installer for Windows
# Downloads latest binary from: https://github.com/flexaccessdev/ezvpn/releases
#
# Usage: .\install.ps1 [RELEASE_TAG] [-PreRelease] [-DownloadOnly]
# Or set $env:RELEASE_TAG environment variable
#
# Installs systemwide to %ProgramData%\ezvpn — run from an elevated (Administrator)
# PowerShell. VPN mode also requires Administrator privileges to run (creates TUN
# devices).
# The wintun.dll driver must be downloaded separately from https://www.wintun.net/ (official WireGuard project)

param(
    [Parameter(Position = 0)]
    [string]$ReleaseTag,

    [Parameter()]
    [switch]$PreRelease,

    [Parameter()]
    [switch]$DownloadOnly
)
# Note: installs systemwide to %ProgramData%\ezvpn; run elevated (Administrator).

$ErrorActionPreference = "Stop"

$REPO_OWNER = "flexaccessdev"
$REPO_NAME = "ezvpn"

# Function to print colored messages
function Print-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Print-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Print-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Fetch the latest stable release tag (non-prerelease)
function Get-LatestReleaseTag {
    $apiUrl = "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest"

    try {
        $release = Invoke-RestMethod -Uri $apiUrl -Method Get
    }
    catch {
        Print-Error "Failed to fetch latest release from GitHub: $_"
        exit 1
    }

    if (-not $release.tag_name) {
        Print-Error "Could not find a latest release on GitHub"
        exit 1
    }

    return $release.tag_name
}

# Fetch the latest prerelease tag
function Get-LatestPrereleaseTag {
    $apiUrl = "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases?per_page=30"

    try {
        $releases = Invoke-RestMethod -Uri $apiUrl -Method Get
    }
    catch {
        Print-Error "Failed to fetch releases from GitHub: $_"
        exit 1
    }

    $latestPrerelease = $releases |
        Where-Object { $_.prerelease -eq $true } |
        Select-Object -First 1 -ExpandProperty tag_name

    if (-not $latestPrerelease) {
        Print-Error "Could not find any prerelease on GitHub"
        exit 1
    }

    return $latestPrerelease
}

# Fetch full release info (including asset checksums) from GitHub API
function Get-ReleaseInfo {
    param([string]$Tag)

    $apiUrl = "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/tags/$Tag"

    try {
        $release = Invoke-RestMethod -Uri $apiUrl -Method Get
        return $release
    }
    catch {
        Print-Warn "Could not fetch release info: $_"
        return $null
    }
}

# Extract SHA-256 checksum from release JSON for a specific binary
function Get-ExpectedChecksum {
    param(
        [object]$ReleaseInfo,
        [string]$BinaryName
    )

    if (-not $ReleaseInfo -or -not $ReleaseInfo.assets) {
        return $null
    }

    # Find the asset matching the binary name
    $asset = $ReleaseInfo.assets | Where-Object { $_.name -eq $BinaryName } | Select-Object -First 1

    if (-not $asset) {
        return $null
    }

    # Extract sha256 hash from digest field
    if ($asset.digest -match 'sha256:([a-f0-9]+)') {
        return $matches[1]
    }

    return $null
}

# Compute SHA-256 checksum of a file
function Get-FileChecksum {
    param([string]$FilePath)

    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256
        return $hash.Hash.ToLower()
    }
    catch {
        Print-Error "Failed to compute checksum: $_"
        return $null
    }
}

# Verify file checksum against expected value
function Test-Checksum {
    param(
        [string]$FilePath,
        [string]$ExpectedChecksum
    )

    Print-Info "Verifying checksum..."
    $actualChecksum = Get-FileChecksum -FilePath $FilePath

    if (-not $actualChecksum) {
        return $false
    }

    if ($ExpectedChecksum -eq $actualChecksum) {
        $shortHash = $actualChecksum.Substring(0, 16)
        Print-Info "Checksum verified: $shortHash..."
        return $true
    }
    else {
        Print-Error "Checksum verification FAILED!"
        Print-Error "Expected: $ExpectedChecksum"
        Print-Error "Actual:   $actualChecksum"
        return $false
    }
}

# Detect architecture
function Get-Architecture {
    $arch = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")

    if ($arch -ne "AMD64") {
        Print-Error "Unsupported architecture: $arch"
        Print-Error "Only AMD64 (x86_64) is supported for Windows"
        exit 1
    }

    return "amd64"
}

# Get binary name based on architecture
function Get-BinaryName {
    param([string]$Arch)

    if ($Arch -ne "amd64") {
        Print-Error "Unsupported architecture: $Arch"
        Print-Error "Only amd64 is supported for Windows"
        exit 1
    }

    return "ezvpn-windows-amd64.exe"
}

# Download binary and verify checksum
function Download-Binary {
    param(
        [string]$Url,
        [string]$OutputPath,
        [string]$ExpectedChecksum
    )

    Print-Info "Downloading from $Url"

    # Download the binary
    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
    }
    catch {
        Print-Error "Failed to download binary: $_"
        exit 1
    }

    # Verify checksum
    if (-not $ExpectedChecksum) {
        Print-Error "No checksum available. Aborting."
        Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue
        exit 1
    }
    if (-not (Test-Checksum -FilePath $OutputPath -ExpectedChecksum $ExpectedChecksum)) {
        Print-Error "Binary integrity check failed. Aborting."
        Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue
        exit 1
    }
}

# Download only - save to current directory
function Download-Only {
    param(
        [string]$BaseUrl,
        [string]$BinaryName,
        [string]$ExpectedChecksum
    )

    $url = "$BaseUrl/$BinaryName"
    $outputFile = Join-Path (Get-Location) $BinaryName

    Download-Binary -Url $url -OutputPath $outputFile -ExpectedChecksum $ExpectedChecksum

    # Test the binary
    Print-Info "Testing downloaded binary..."
    try {
        $versionInfo = & $outputFile --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Binary returned non-zero exit code"
        }
        Print-Info "Binary test successful: $versionInfo"
    }
    catch {
        Print-Error "Binary test failed. The downloaded file may be corrupted or incompatible."
        Print-Error "Output: $_"
        Remove-Item -Path $outputFile -Force -ErrorAction SilentlyContinue
        exit 1
    }

    Print-Info "Binary saved to: $outputFile"
    Print-Warn ""
    Print-Warn "IMPORTANT: Before running, you must manually install the WinTun driver:"
    Print-Warn "  1. Download wintun.zip from https://www.wintun.net/ (official WireGuard project)"
    Print-Warn "  2. Extract the zip file"
    Print-Warn "  3. Copy wintun\bin\amd64\wintun.dll to: $(Get-Location)"
    Print-Warn "     (or any directory in the system PATH)"
    Print-Warn "  4. Run as Administrator"
    Print-Warn ""
    Print-Warn "If you see 'Failed to create TUN device: LoadLibraryExW failed',"
    Print-Warn "the wintun.dll is missing or not in a valid DLL search path."
}

# Download binary to temporary location, test it, and install
function Install-Binary {
    param(
        [string]$BaseUrl,
        [string]$BinaryName,
        [string]$ExpectedChecksum
    )

    $url = "$BaseUrl/$BinaryName"
    $tempDir = Join-Path $env:TEMP "ezvpn-install-$(Get-Random)"
    $tempBinary = Join-Path $tempDir $BinaryName
    # Install systemwide, alongside the config and runtime/lock files the binary
    # reads from %ProgramData%\ezvpn (resolved the same way the app resolves them;
    # fall back to the C:\ProgramData literal only if the env var is unset).
    $programData = if ($env:ProgramData) { $env:ProgramData } else { "C:\ProgramData" }
    $installDir = Join-Path $programData "ezvpn"
    $finalPath = Join-Path $installDir "ezvpn.exe"

    try {
        # Create temp directory
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

        Download-Binary -Url $url -OutputPath $tempBinary -ExpectedChecksum $ExpectedChecksum

        # Test the binary
        Print-Info "Testing downloaded binary..."
        try {
            $versionInfo = & $tempBinary --version 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Binary returned non-zero exit code"
            }
            Print-Info "Binary test successful: $versionInfo"
        }
        catch {
            Print-Error "Binary test failed. The downloaded file may be corrupted or incompatible."
            Print-Error "Output: $_"
            exit 1
        }

        # Create target directory if it doesn't exist
        if (-not (Test-Path $installDir)) {
            New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        }

        # Move the tested binary to final location
        try {
            Move-Item -Path $tempBinary -Destination $finalPath -Force
        }
        catch {
            Print-Error "Failed to move binary to final location: $_"
            exit 1
        }

        Print-Info "Binary installed successfully to $finalPath"

        # Add to the systemwide (Machine) PATH if not already there
        # (case-insensitive exact match). Machine scope matches the systemwide
        # install location and requires the elevation this installer enforces.
        $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
        $normalizedInstallDir = $installDir.TrimEnd('\', '/')
        $currentPaths = @()
        if ($machinePath) {
            $currentPaths = $machinePath -split ';' | ForEach-Object { $_.Trim().TrimEnd('\', '/') } | Where-Object { $_ -ne '' }
        }
        $isInPath = $currentPaths -contains $normalizedInstallDir

        if (-not $isInPath) {
            Print-Warn "$installDir is not in the system PATH"
            Print-Warn "Adding to machine PATH..."

            try {
                $newPath = if ($machinePath) { "$machinePath;$installDir" } else { $installDir }
                [System.Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
                Print-Info "Added to PATH. You may need to restart your terminal for changes to take effect."
            }
            catch {
                Print-Warn "Failed to add to PATH automatically. Please add manually:"
                Print-Warn "$installDir"
            }
        }
        else {
            Print-Info "$installDir is already in the system PATH"
        }

        Print-Warn ""
        Print-Warn "IMPORTANT: Before running, you must manually install the WinTun driver:"
        Print-Warn "  1. Download wintun.zip from https://www.wintun.net/ (official WireGuard project)"
        Print-Warn "  2. Extract the zip file"
        Print-Warn "  3. Copy wintun\bin\amd64\wintun.dll to: $installDir"
        Print-Warn "     (or any directory in the system PATH)"
        Print-Warn "  4. Run as Administrator"
        Print-Warn ""
        Print-Warn "If you see 'Failed to create TUN device: LoadLibraryExW failed',"
        Print-Warn "the wintun.dll is missing or not in a valid DLL search path."
    }
    finally {
        # Clean up temp directory
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Display usage information
function Show-Usage {
    Write-Host @"
Usage: .\install.ps1 [OPTIONS] [RELEASE_TAG]

Download and install ezvpn binary

Installs systemwide to %ProgramData%\ezvpn (run from an elevated PowerShell).

Options:
  -DownloadOnly  Download binary to current directory without installing (no elevation needed)
  -PreRelease    Use latest prerelease instead of latest stable release
  -h, --help     Show this help message

Arguments:
  RELEASE_TAG    GitHub release tag to download (default: latest)

Environment variables:
  `$env:RELEASE_TAG    Alternative way to specify release tag

Examples:
  .\install.ps1                              # Install latest release (run elevated)
  .\install.ps1 20251210172710               # Install specific release
  .\install.ps1 -PreRelease                  # Install latest prerelease
  .\install.ps1 -DownloadOnly                # Download latest to current directory
  .\install.ps1 -DownloadOnly 20251210172710 # Download specific release
  `$env:RELEASE_TAG='latest'; .\install.ps1  # Use environment variable

Supported platforms: Windows (amd64)

Note: installs systemwide to %ProgramData%\ezvpn; VPN mode also requires
Administrator privileges to run (creates TUN devices).

IMPORTANT: You must manually download and install the WinTun driver:
  1. Download wintun.zip from https://www.wintun.net/ (official WireGuard project)
  2. Extract and copy wintun\bin\amd64\wintun.dll to the executable directory
     (or any directory in the system PATH)

If you see 'Failed to create TUN device: LoadLibraryExW failed', wintun.dll is missing or not in a valid DLL search path.
"@
}

# Require administrator privileges. A systemwide install writes the binary to
# %ProgramData%\ezvpn and updates the machine PATH, both of which need elevation
# — and ezvpn itself must run elevated to manage the TUN device.
function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Print-Error "Administrator privileges are required to install systemwide to %ProgramData%\ezvpn."
        Print-Error ""
        Print-Error "Re-run this installer from an elevated (Administrator) PowerShell."
        Print-Error ""
        Print-Error "To download the binary without installing (no elevation needed), use -DownloadOnly."
        exit 1
    }
}

# Main installation function
function Start-Installation {
    param(
        [string]$Tag,
        [bool]$DownloadOnly
    )

    if ($DownloadOnly) {
        Print-Info "ezvpn downloader"
    }
    else {
        Print-Info "ezvpn installer"
    }
    Print-Info "Release: $Tag"
    Print-Info "Repository: $REPO_OWNER/$REPO_NAME"

    $arch = Get-Architecture
    $binaryName = Get-BinaryName -Arch $arch

    Print-Info "Platform detected: windows-$arch"
    Print-Info "Binary name: $binaryName"

    $baseUrl = "https://github.com/$REPO_OWNER/$REPO_NAME/releases/download/$Tag"

    # Fetch release info for checksum verification
    Print-Info "Fetching release information..."
    $releaseInfo = Get-ReleaseInfo -Tag $Tag

    if (-not $releaseInfo) {
        Print-Error "Could not fetch release info from GitHub. Cannot verify binary integrity."
        exit 1
    }

    $expectedChecksum = Get-ExpectedChecksum -ReleaseInfo $releaseInfo -BinaryName $binaryName
    if (-not $expectedChecksum) {
        Print-Error "No checksum found for $binaryName in release. Cannot verify binary integrity."
        exit 1
    }
    $shortHash = $expectedChecksum.Substring(0, 16)
    Print-Info "Expected checksum: $shortHash..."

    if ($DownloadOnly) {
        Download-Only -BaseUrl $baseUrl -BinaryName $binaryName -ExpectedChecksum $expectedChecksum
        Print-Info "Download completed successfully!"
    }
    else {
        Install-Binary -BaseUrl $baseUrl -BinaryName $binaryName -ExpectedChecksum $expectedChecksum
        Print-Info "Installation completed successfully!"
        Print-Info "You can now run 'ezvpn' from an Administrator terminal."
    }
}

# Main execution
function Main {
    # Handle help flags via ReleaseTag parameter
    if ($ReleaseTag -eq "--help" -or $ReleaseTag -eq "-h" -or $ReleaseTag -eq "-?" -or $ReleaseTag -eq "/?" -or $ReleaseTag -eq "/h") {
        Show-Usage
        exit 0
    }

    if ($DownloadOnly) {
        Print-Info "Starting ezvpn download..."
    }
    else {
        Print-Info "Starting ezvpn installation..."
    }

    # Determine release tag
    $tag = $ReleaseTag
    if (-not $tag) {
        $tag = $env:RELEASE_TAG
    }
    if (-not $tag) {
        if ($PreRelease) {
            Print-Info "Fetching latest prerelease tag from GitHub..."
            $tag = Get-LatestPrereleaseTag
        }
        else {
            Print-Info "Fetching latest release tag from GitHub..."
            $tag = Get-LatestReleaseTag
        }
    }

    if (-not $DownloadOnly) {
        Test-AdminPrivileges
    }

    Start-Installation -Tag $tag -DownloadOnly:$DownloadOnly
}

# Run main function
Main
