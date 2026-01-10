#!/usr/bin/env bash
set -euo pipefail

# Lint all bash scripts in this repository.
# - ShellCheck
# - shfmt (diff-only)
# - bash -n syntax check

if ! command -v shellcheck >/dev/null 2>&1; then
  echo "[ERROR] shellcheck not found" >&2
  exit 1
fi
if ! command -v shfmt >/dev/null 2>&1; then
  echo "[ERROR] shfmt not found" >&2
  exit 1
fi

mapfile -d '' -t files < <(find scripts -type f -name '*.sh' -print0)

if ((${#files[@]} == 0)); then
  echo "No bash scripts found under scripts/."
  exit 0
fi

echo "==> Running ShellCheck on ${#files[@]} file(s)..."
shellcheck -x "${files[@]}"

echo "==> Running shfmt (diff-only)..."
shfmt -d -i 2 -ci -sr "${files[@]}"

echo "==> Running bash -n syntax check..."
for f in "${files[@]}"; do
  bash -n "$f"
done

echo "All bash scripts passed lint checks."
