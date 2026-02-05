#!/bin/sh
set -e

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     OS='Linux';;
    Darwin*)    OS='Darwin';;
    *)          echo "Unsupported OS: ${OS}"; exit 1;;
esac

# Detect Architecture
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64)    ARCH='x86_64';;
    aarch64)   ARCH='arm64';;
    arm64)     ARCH='arm64';;
    *)         echo "Unsupported Architecture: ${ARCH}"; exit 1;;
esac

GITHUB_REPO="SKIPPINGpetticoatconvent/go-ssh-mcp"
BINARY_NAME="ssh-mcp"

echo "Detected ${OS} ${ARCH}"

# Get latest release tag
echo "Fetching latest release..."
LATEST_TAG=$(curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
    echo "Failed to fetch latest release tag. Please check your internet connection or GitHub API limits."
    exit 1
fi

echo "Latest release: ${LATEST_TAG}"

# Construct download URL
# Expected naming: go-ssh-mcp_Linux_x86_64.tar.gz
ASSET_NAME="go-ssh-mcp_${OS}_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${LATEST_TAG}/${ASSET_NAME}"

TMP_DIR=$(mktemp -d)
echo "Downloading ${ASSET_NAME} from ${DOWNLOAD_URL}..."
curl -L -o "${TMP_DIR}/${ASSET_NAME}" "${DOWNLOAD_URL}"

echo "Extracting..."
tar -xzf "${TMP_DIR}/${ASSET_NAME}" -C "${TMP_DIR}"

# Install
INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
    echo "Requires sudo to install to ${INSTALL_DIR}"
    sudo mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/"
else
    mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/"
fi

# Cleanup
rm -rf "${TMP_DIR}"

echo "Successfully installed ${BINARY_NAME} to ${INSTALL_DIR}"
"${BINARY_NAME}" --version
