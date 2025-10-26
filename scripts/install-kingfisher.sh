#!/usr/bin/env bash
set -euo pipefail

REPO="mongodb/kingfisher"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"
DEFAULT_INSTALL_DIR="$HOME/.local/bin"

usage() {
  cat <<'USAGE'
Usage: install-kingfisher.sh [INSTALL_DIR]

Downloads the latest Kingfisher release for Linux or macOS and installs the
binary into INSTALL_DIR (default: ~/.local/bin).

The script requires curl, tar, and python3.
USAGE
}

if [[ "${1-}" == "-h" || "${1-}" == "--help" ]]; then
  usage
  exit 0
fi

INSTALL_DIR="${1:-$DEFAULT_INSTALL_DIR}"

if ! command -v curl >/dev/null 2>&1; then
  echo "Error: curl is required to download releases." >&2
  exit 1
fi

if ! command -v tar >/dev/null 2>&1; then
  echo "Error: tar is required to extract the release archive." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is required to process the GitHub API response." >&2
  exit 1
fi

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
  Linux)
    platform="linux"
    ;;
  Darwin)
    platform="darwin"
    ;;
  *)
    echo "Error: Unsupported operating system '$OS'." >&2
    echo "This installer currently supports Linux and macOS." >&2
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64|amd64)
    arch_suffix="x64"
    ;;
  arm64|aarch64)
    arch_suffix="arm64"
    ;;
  *)
    echo "Error: Unsupported architecture '$ARCH'." >&2
    echo "This installer currently supports x86_64/amd64 and arm64/aarch64." >&2
    exit 1
    ;;
esac

asset_name="kingfisher-${platform}-${arch_suffix}.tgz"

echo "Fetching latest release metadata for ${REPO}…"
release_json=$(curl -fsSL "$API_URL")

if [[ -z "$release_json" ]]; then
  echo "Error: Failed to retrieve release information from GitHub." >&2
  exit 1
fi

download_url=$(RELEASE_JSON="$release_json" python3 - "$asset_name" <<'PY'
import json
import sys
import os

asset_name = sys.argv[1]
try:
    release = json.loads(os.environ["RELEASE_JSON"])
except (json.JSONDecodeError, KeyError) as exc:
    sys.stderr.write(f"Error: Failed to parse GitHub response: {exc}\n")
    sys.exit(1)

for asset in release.get("assets", []):
    if asset.get("name") == asset_name:
        print(asset.get("browser_download_url", ""))
        sys.exit(0)

sys.stderr.write(f"Error: Could not find asset '{asset_name}' in the latest release.\n")
sys.exit(1)
PY
)

if [[ -z "$download_url" ]]; then
  exit 1
fi

release_tag=$(RELEASE_JSON="$release_json" python3 - <<'PY'
import json
import sys
import os

try:
    release = json.loads(os.environ["RELEASE_JSON"])
except (json.JSONDecodeError, KeyError) as exc:
    sys.stderr.write(f"Error: Failed to parse GitHub response: {exc}\n")
    sys.exit(1)

print(release.get("tag_name", ""))
PY
)

tmpdir=$(mktemp -d)
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

archive_path="$tmpdir/$asset_name"

if [[ -n "$release_tag" ]]; then
  echo "Latest release: $release_tag"
fi

echo "Downloading $asset_name…"
curl -fsSL "$download_url" -o "$archive_path"

echo "Extracting archive…"
tar -C "$tmpdir" -xzf "$archive_path"

if [[ ! -f "$tmpdir/kingfisher" ]]; then
  echo "Error: Extracted archive did not contain the kingfisher binary." >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
install -m 755 "$tmpdir/kingfisher" "$INSTALL_DIR/kingfisher"

printf 'Kingfisher installed to: %s/kingfisher\n\n' "$INSTALL_DIR"
printf 'Add the following to your shell configuration if the directory is not already in your PATH:\n  export PATH="%s:$PATH"\n' "$INSTALL_DIR"

