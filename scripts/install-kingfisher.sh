#!/usr/bin/env bash
set -euo pipefail

REPO="mongodb/kingfisher"
DEFAULT_INSTALL_DIR="$HOME/.local/bin"
LATEST_DL_BASE="https://github.com/${REPO}/releases/latest/download"

usage() {
  cat <<'USAGE'
Usage: install-kingfisher.sh [INSTALL_DIR]

Downloads the latest Kingfisher release for Linux or macOS and installs the
binary into INSTALL_DIR (default: ~/.local/bin).

Requirements: curl, tar
USAGE
}

if [[ "${1-}" == "-h" || "${1-}" == "--help" ]]; then
  usage
  exit 0
fi

INSTALL_DIR="${1:-$DEFAULT_INSTALL_DIR}"

# deps
command -v curl >/dev/null 2>&1 || { echo "Error: curl is required." >&2; exit 1; }
command -v tar  >/dev/null 2>&1 || { echo "Error: tar is required."  >&2; exit 1; }

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  platform="linux"  ;;
  Darwin) platform="darwin" ;;
  *) echo "Error: Unsupported OS '$OS' (Linux/macOS only)." >&2; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64)  arch_suffix="x64"   ;;
  arm64|aarch64) arch_suffix="arm64" ;;
  *) echo "Error: Unsupported arch '$ARCH' (x86_64/amd64, arm64/aarch64 only)." >&2; exit 1 ;;
esac

asset_name="kingfisher-${platform}-${arch_suffix}.tgz"
: "${asset_name:?internal error: asset_name not set}"  # guard for set -u

download_url="${LATEST_DL_BASE}/${asset_name}"

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

archive_path="$tmpdir/$asset_name"

echo "Downloading latest: ${asset_name} …"
# -f: fail on HTTP errors (e.g., 404 if asset missing)
if ! curl -fLsS "${download_url}" -o "$archive_path"; then
  echo "Error: Failed to download ${download_url}" >&2
  echo "Tip: Ensure the release includes '${asset_name}'." >&2
  exit 1
fi

echo "Extracting archive…"
tar -C "$tmpdir" -xzf "$archive_path"

if [[ ! -f "$tmpdir/kingfisher" ]]; then
  echo "Error: Extracted archive did not contain the 'kingfisher' binary." >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
install -m 0755 "$tmpdir/kingfisher" "$INSTALL_DIR/kingfisher"

printf 'Kingfisher installed to: %s/kingfisher\n\n' "$INSTALL_DIR"
if ! command -v kingfisher >/dev/null 2>&1; then
  printf 'Add this to your shell config if %s is not on PATH:\n  export PATH="%s:$PATH"\n' "$INSTALL_DIR" "$INSTALL_DIR"
fi
