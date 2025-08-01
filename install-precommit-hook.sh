#!/usr/bin/env bash
#
# Install a Git pre‑commit hook that runs `kingfisher scan`.
#
#   --global   → install once for all repos via core.hooksPath
#   --force    → overwrite an existing pre‑commit hook
#
set -euo pipefail

MODE="local"
FORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -g|--global) MODE="global" ;;
    -f|--force)  FORCE=1 ;;
    -h|--help)
      echo "Usage: $0 [--global] [--force]" && exit 0
      ;;
    *) echo "Unknown flag: $1" >&2; exit 1 ;;
  esac
  shift
done

if [[ "$MODE" == "local" ]]; then
  # ensure we're inside a Git repo
  REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) \
    || { echo "Not inside a Git repository" >&2; exit 1; }

  HOOK_DIR="$(git rev-parse --git-dir)/hooks"
else
  # global: honour existing core.hooksPath or default to ~/.git-hooks
  HOOK_DIR=$(git config --global --get core.hooksPath || echo "$HOME/.git-hooks")
  mkdir -p "$HOOK_DIR"

  # if the user hasn’t set core.hooksPath, do it now
  if ! git config --global --get core.hooksPath >/dev/null; then
    git config --global core.hooksPath "$HOOK_DIR"
    echo "Set git config --global core.hooksPath to $HOOK_DIR"
  fi
fi

HOOK_PATH="$HOOK_DIR/pre-commit"

if [[ -e "$HOOK_PATH" && $FORCE -eq 0 ]]; then
  echo "Error: $HOOK_PATH already exists. Use --force to overwrite." >&2
  exit 1
fi

cat >"$HOOK_PATH" <<'HOOK'
#!/usr/bin/env bash
# Git pre‑commit hook to run Kingfisher on staged changes
set -euo pipefail

if ! command -v kingfisher >/dev/null 2>&1; then
  echo "kingfisher not found in PATH" >&2
  exit 1
fi

git diff --cached --name-only -z | \
  xargs -0 --no-run-if-empty kingfisher scan --only-valid --no-update-check
status=$?

# ────────────────────────────────────────────────────────────────
# Treat Kingfisher exit‑code 200 as success (map → 0)
# ────────────────────────────────────────────────────────────────
if [[ $status -eq 200 ]]; then
  status=0
fi

if [[ $status -ne 0 ]]; then
  echo "Kingfisher detected secrets in staged files. Commit aborted." >&2
  exit $status
fi
HOOK

chmod +x "$HOOK_PATH"
echo "Pre‑commit hook installed to $HOOK_PATH ($MODE mode)"
