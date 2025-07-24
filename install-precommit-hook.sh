#!/usr/bin/env bash
set -euo pipefail

HOOK_DIR="$(git rev-parse --git-dir)/hooks"
HOOK_PATH="$HOOK_DIR/pre-commit"

if [ -e "$HOOK_PATH" ]; then
  echo "Error: $HOOK_PATH already exists. Move or remove the existing hook to continue." >&2
  exit 1
fi

cat > "$HOOK_PATH" <<'HOOK'
#!/usr/bin/env bash
# Pre-commit hook to run Kingfisher scan on staged changes
set -euo pipefail

if ! command -v kingfisher >/dev/null 2>&1; then
  echo "kingfisher not found in PATH" >&2
  exit 1
fi

git diff --cached --name-only -z | \
  xargs -0 --no-run-if-empty kingfisher scan --no-update-check
status=$?
if [ "$status" -ne 0 ]; then
  echo "Kingfisher detected secrets in staged files. Commit aborted." >&2
  exit "$status"
fi
HOOK

chmod +x "$HOOK_PATH"
echo "Pre-commit hook installed to $HOOK_PATH"
