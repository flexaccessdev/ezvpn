#!/bin/bash

# ezvpn installer for Linux and Mac
# Downloads latest binary from: https://github.com/andrewtheguy/ezvpn/releases
# Installs to /usr/local/bin (requires root/sudo)
#
# Usage: sudo ./install.sh [RELEASE_TAG] [--prerelease]
# Or set RELEASE_TAG environment variable

set -e

REPO_OWNER="andrewtheguy"
REPO_NAME="ezvpn"
DOWNLOAD_ONLY=false
PREFER_PRERELEASE=false

# Color output (defined early for use in release tag helpers)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Fetch the latest stable release tag (non-prerelease)
get_latest_release_tag() {
    local api_url="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"
    local release_json

    if command -v curl >/dev/null 2>&1; then
        release_json=$(curl -s "$api_url")
    elif command -v wget >/dev/null 2>&1; then
        release_json=$(wget -qO- "$api_url")
    else
        print_error "Neither curl nor wget is available. Please install one of them."
        exit 1
    fi

    local tag
    tag=$(echo "$release_json" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')

    if [ -z "$tag" ]; then
        print_error "Could not find a latest release on GitHub"
        exit 1
    fi

    echo "$tag"
}

# Fetch the latest prerelease tag
get_latest_prerelease_tag() {
    local api_url="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases?per_page=30"
    local releases_json

    if command -v curl >/dev/null 2>&1; then
        releases_json=$(curl -s "$api_url")
    elif command -v wget >/dev/null 2>&1; then
        releases_json=$(wget -qO- "$api_url")
    else
        print_error "Neither curl nor wget is available. Please install one of them."
        exit 1
    fi

    # Capture the first prerelease entry and return its tag_name
    local tag
    tag=$(echo "$releases_json" | awk '
        /"tag_name"/ {gsub(/[,"]/, "", $2); tag=$2}
        /"prerelease": *true/ {if(tag!=""){print tag; exit}}
    ')

    if [ -z "$tag" ]; then
        print_error "Could not find any prerelease on GitHub"
        exit 1
    fi

    echo "$tag"
}

# Fetch full release info (including asset checksums) from GitHub API
get_release_info() {
    local tag="$1"
    local api_url="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/tags/${tag}"

    if command -v curl >/dev/null 2>&1; then
        curl -s "$api_url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$api_url"
    else
        print_error "Neither curl nor wget is available."
        return 1
    fi
}

# Extract SHA-256 checksum from release JSON for a specific binary
get_expected_checksum() {
    local release_json="$1"
    local binary_name="$2"

    # Extract sha256 hash for matching asset
    # The digest field appears ~35 lines after the name field due to nested uploader object
    echo "$release_json" | grep -A40 "\"name\": \"${binary_name}\"" | \
        grep '"digest"' | head -1 | grep -o 'sha256:[a-f0-9]*' | cut -d: -f2
}

# Compute SHA-256 checksum of a file (cross-platform)
compute_checksum() {
    local file="$1"

    if command -v sha256sum >/dev/null 2>&1; then
        # Linux
        sha256sum "$file" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        # macOS
        shasum -a 256 "$file" | cut -d' ' -f1
    else
        print_error "No SHA-256 tool available (need sha256sum or shasum)"
        return 1
    fi
}

# Verify file checksum against expected value
verify_checksum() {
    local file="$1"
    local expected="$2"

    print_info "Verifying checksum..."
    local actual
    actual=$(compute_checksum "$file")

    if [ $? -ne 0 ]; then
        return 1
    fi

    if [ "$expected" = "$actual" ]; then
        print_info "Checksum verified: ${actual:0:16}..."
        return 0
    else
        print_error "Checksum verification FAILED!"
        print_error "Expected: $expected"
        print_error "Actual:   $actual"
        return 1
    fi
}

# Parse command-line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --download-only)
                DOWNLOAD_ONLY=true
                shift
                ;;
            --prerelease)
                PREFER_PRERELEASE=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                # Assume it's a release tag
                RELEASE_TAG="$1"
                shift
                ;;
        esac
    done

    # If RELEASE_TAG was not set via args or environment, fetch latest
    if [ -z "$RELEASE_TAG" ]; then
        if [ "$PREFER_PRERELEASE" = true ]; then
            print_info "Fetching latest prerelease tag from GitHub..."
            RELEASE_TAG=$(get_latest_prerelease_tag)
        else
            print_info "Fetching latest release tag from GitHub..."
            RELEASE_TAG=$(get_latest_release_tag)
        fi
    fi
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)
            OS="linux"
            ;;
        Darwin*)
            OS="macos"
            ;;
        *)
            print_error "Unsupported operating system: $(uname -s)"
            print_error "ezvpn only supports Linux and macOS"
            exit 1
            ;;
    esac
}

# Detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            print_error "Supported architectures: x86_64/amd64, aarch64/arm64"
            exit 1
            ;;
    esac
}

# Map OS and architecture to binary name
get_binary_name() {
    case "${OS}-${ARCH}" in
        "linux-amd64")
            BINARY_NAME="ezvpn-linux-amd64"
            ;;
        "linux-arm64")
            BINARY_NAME="ezvpn-linux-arm64"
            ;;
        "macos-arm64")
            BINARY_NAME="ezvpn-macos-arm64"
            ;;
        *)
            print_error "Unsupported platform: ${OS}-${ARCH}"
            print_error "Supported platforms:"
            print_error "  - linux-amd64 (x86_64 Linux)"
            print_error "  - linux-arm64 (aarch64 Linux)"
            print_error "  - macos-arm64 (Apple Silicon Mac)"
            exit 1
            ;;
    esac
}

# Download binary and verify checksum
download_binary() {
    local base_url="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${RELEASE_TAG}"
    local url="${base_url}/${BINARY_NAME}"
    local output_path="$1"

    print_info "Downloading ${BINARY_NAME} from ${url}"

    # Download the binary
    if command -v curl >/dev/null 2>&1; then
        if ! curl -L -o "$output_path" "$url"; then
            print_error "Failed to download binary"
            exit 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -O "$output_path" "$url"; then
            print_error "Failed to download binary"
            exit 1
        fi
    else
        print_error "Neither curl nor wget is available. Please install one of them."
        exit 1
    fi

    # Verify checksum
    if [ -z "$EXPECTED_CHECKSUM" ]; then
        print_error "No checksum available. Aborting."
        rm -f "$output_path"
        exit 1
    fi
    if ! verify_checksum "$output_path" "$EXPECTED_CHECKSUM"; then
        print_error "Binary integrity check failed. Aborting."
        rm -f "$output_path"
        exit 1
    fi
}

# Download only - save to current directory
download_only() {
    local output_file="./${BINARY_NAME}"

    download_binary "$output_file"

    # Make executable
    chmod +x "$output_file"

    # Test the binary
    print_info "Testing downloaded binary..."
    local version_info
    if ! version_info=$("$output_file" --version 2>&1); then
        print_error "Binary test failed. The downloaded file may be corrupted or incompatible."
        print_error "Output: $version_info"
        rm -f "$output_file"
        exit 1
    fi

    print_info "Binary test successful: $version_info"
    print_info "Binary saved to: ${output_file}"
}

# Download binary to temporary location, test it, and install to /usr/local/bin
download_and_install() {
    local temp_dir
    temp_dir=$(mktemp -d)
    local temp_binary="${temp_dir}/${BINARY_NAME}"
    local final_path="/usr/local/bin/ezvpn"

    # Set up trap to clean up temp directory on exit
    trap 'rm -rf "$temp_dir"' EXIT

    download_binary "$temp_binary"

    # Make executable
    chmod +x "$temp_binary"

    # Test the binary
    print_info "Testing downloaded binary..."
    local version_info
    if ! version_info=$("$temp_binary" --version 2>&1); then
        print_error "Binary test failed. The downloaded file may be corrupted or incompatible."
        print_error "Output: $version_info"
        exit 1
    fi

    print_info "Binary test successful: $version_info"

    # Ensure /usr/local/bin exists
    mkdir -p /usr/local/bin

    # Move the tested binary to final location
    if ! mv "$temp_binary" "$final_path"; then
        print_error "Failed to move binary to final location"
        exit 1
    fi

    # Clean up temp directory (trap will also handle this)
    rm -rf "$temp_dir"

    print_info "Binary installed successfully to ${final_path}"
}

# Advise raising the macOS socket buffer limit if it is too small for QUIC.
# macOS clamps SO_RCVBUF/SO_SNDBUF to kern.ipc.maxsockbuf; an undersized limit
# causes UDP drops under load that QUIC answers with congestion backoff.
check_macos_sockbuf() {
    if [ "$OS" != "macos" ]; then
        return 0
    fi

    local recommended=8388608
    local current
    current=$(sysctl -n kern.ipc.maxsockbuf 2>/dev/null) || return 0

    if [ -n "$current" ] && [ "$current" -lt "$recommended" ] 2>/dev/null; then
        print_warn "kern.ipc.maxsockbuf is ${current}, which limits QUIC throughput."
        print_warn "For best performance, raise it with:"
        print_warn "  sudo sysctl -w kern.ipc.maxsockbuf=${recommended}"
        print_warn "Persist across reboots by adding to /etc/sysctl.conf:"
        print_warn "  kern.ipc.maxsockbuf=${recommended}"
    fi
}

# Display usage information
show_usage() {
    echo "Usage: sudo $0 [OPTIONS] [RELEASE_TAG]"
    echo ""
    echo "Download and install ezvpn binary to /usr/local/bin"
    echo ""
    echo "Options:"
    echo "  --download-only  Download binary to current directory without installing"
    echo "  --prerelease     Use latest prerelease instead of latest stable release"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Arguments:"
    echo "  RELEASE_TAG      GitHub release tag to download (default: latest)"
    echo ""
    echo "Examples:"
    echo "  sudo $0                              # Install latest release"
    echo "  sudo $0 20251210172710               # Install specific release"
    echo "  sudo $0 --prerelease                 # Install latest prerelease"
    echo "  $0 --download-only                   # Download latest to current directory"
    echo "  $0 --download-only 20251210172710    # Download specific release"
    echo ""
    echo "Supported platforms: Linux (amd64, arm64), macOS (arm64)"
    echo ""
    echo "Note: VPN mode requires root privileges to run (creates TUN devices)."
}

# Main installation function
install() {
    if [ "$DOWNLOAD_ONLY" = true ]; then
        print_info "ezvpn downloader"
    else
        print_info "ezvpn installer"
    fi
    print_info "Release: ${RELEASE_TAG}"
    print_info "Repository: ${REPO_OWNER}/${REPO_NAME}"

    detect_os
    detect_arch
    get_binary_name

    print_info "Platform detected: ${OS}-${ARCH}"
    print_info "Binary name: ${BINARY_NAME}"

    # Fetch release info for checksum verification
    print_info "Fetching release information..."
    RELEASE_JSON=$(get_release_info "$RELEASE_TAG")

    if [ -z "$RELEASE_JSON" ] || echo "$RELEASE_JSON" | grep -q '"message": "Not Found"'; then
        print_error "Could not fetch release info from GitHub. Cannot verify binary integrity."
        exit 1
    fi

    EXPECTED_CHECKSUM=$(get_expected_checksum "$RELEASE_JSON" "$BINARY_NAME")
    if [ -z "$EXPECTED_CHECKSUM" ]; then
        print_error "No checksum found for ${BINARY_NAME} in release. Cannot verify binary integrity."
        exit 1
    fi
    print_info "Expected checksum: ${EXPECTED_CHECKSUM:0:16}..."

    if [ "$DOWNLOAD_ONLY" = true ]; then
        download_only
        print_info "Download completed successfully!"
    else
        download_and_install
        print_info "Installation completed successfully!"
        print_info "You can now run 'sudo ezvpn' from your terminal."
        check_macos_sockbuf
    fi
}

# Check if running with proper privileges
check_privileges() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This installer must be run as root (use sudo)"
        print_error "Example: curl -sSL ... | sudo bash"
        exit 1
    fi
}

# Main execution
main() {
    parse_args "$@"

    if [ "$DOWNLOAD_ONLY" = true ]; then
        print_info "Starting ezvpn download..."
    else
        print_info "Starting ezvpn installation..."
        check_privileges
    fi

    install
}

# Run main function
main "$@"
