#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "[*] Lint bash scripts with ShellCheck (if installed)"
if command -v shellcheck >/dev/null 2>&1; then
  mapfile -t SH_FILES < <(git ls-files '*.sh')
  if [ "${#SH_FILES[@]}" -gt 0 ]; then
    shellcheck -x "${SH_FILES[@]}"
  fi
else
  echo "[!] shellcheck not found; skip"
fi

echo "[*] Format bash scripts with shfmt (check mode)"
if command -v shfmt >/dev/null 2>&1; then
  shfmt -d $(git ls-files '*.sh')
else
  echo "[!] shfmt not found; skip"
fi

echo "[*] Done"
