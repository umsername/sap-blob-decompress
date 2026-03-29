#!/usr/bin/env bash

set -euo pipefail

# Installs the latest sapblob release for the current machine.
#
# Optional environment variables:
#   SAPBLOB_REPO        Override the GitHub repository.
#   SAPBLOB_VERSION     Install a specific release tag instead of "latest".
#   SAPBLOB_INSTALL_DIR Override the target directory.

REPO="${SAPBLOB_REPO:-umsername/sap-blob-decompress}"
VERSION="${SAPBLOB_VERSION:-latest}"
INSTALL_DIR="${SAPBLOB_INSTALL_DIR:-/usr/local/bin}"
BIN_NAME="sapblob"

fail() {
  echo "Error: $*" >&2
  exit 1
}

detect_platform() {
  local os arch

  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  case "$os" in
    linux)
      GOOS="linux"
      ;;
    darwin)
      GOOS="darwin"
      ;;
    *)
      fail "unsupported operating system: $os"
      ;;
  esac

  case "$arch" in
    x86_64|amd64)
      GOARCH="amd64"
      ;;
    arm64|aarch64)
      GOARCH="arm64"
      ;;
    *)
      fail "unsupported CPU architecture: $arch"
      ;;
  esac
}

resolve_version() {
  if [[ "$VERSION" != "latest" ]]; then
    return
  fi

  local api_url
  api_url="https://api.github.com/repos/${REPO}/releases/latest"

  VERSION="$(curl -fsSL "$api_url" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"

  [[ -n "$VERSION" ]] || fail "could not determine the latest release tag"
}

install_release() {
  local archive_name download_url temp_dir binary_path

  archive_name="${BIN_NAME}_${VERSION}_${GOOS}-${GOARCH}.tar.gz"
  download_url="https://github.com/${REPO}/releases/download/${VERSION}/${archive_name}"
  temp_dir="$(mktemp -d)"

  trap 'rm -rf "$temp_dir"' EXIT

  curl -fsSL "$download_url" -o "$temp_dir/$archive_name"
  tar -xzf "$temp_dir/$archive_name" -C "$temp_dir"

  binary_path="$(find "$temp_dir" -type f -name "$BIN_NAME" | head -n 1)"
  [[ -n "$binary_path" ]] || fail "release archive did not contain ${BIN_NAME}"

  install -d "$INSTALL_DIR"
  install -m 0755 "$binary_path" "$INSTALL_DIR/$BIN_NAME"

  echo "Installed ${BIN_NAME} ${VERSION} to ${INSTALL_DIR}/${BIN_NAME}"
}

detect_platform
resolve_version
install_release
